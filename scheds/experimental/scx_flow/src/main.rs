// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use log::info;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_flow";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /// Enable stats monitoring with the specified interval.
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler is not launched.
    #[clap(long)]
    monitor: Option<f64>,

    /// Debug mode
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Disable adaptive runtime tuning (no-op, kept for backward compatibility).
    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_autotune: bool,

    /// Generate shell completions for the given shell and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CpuPolicyStateAgg {
    budget_exhaustions: u64,
    runnable_wakeups: u64,
    prio_dispatches: u64,
    normal_dispatches: u64,
    cpu_migrations: u64,
}

impl<'a> Scheduler<'a> {
    fn read_cpu_policy_state(&self) -> CpuPolicyStateAgg {
        let key = 0u32.to_ne_bytes();
        let mut agg = CpuPolicyStateAgg::default();

        let percpu_vals: Vec<Vec<u8>> = match self
            .skel
            .maps
            .cpu_state
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(vals)) => vals,
            _ => return agg,
        };

        for cpu_val in percpu_vals.iter() {
            if cpu_val.len() < std::mem::size_of::<bpf_intf::flow_cpu_state>() {
                continue;
            }

            let state = unsafe {
                std::ptr::read_unaligned(cpu_val.as_ptr() as *const bpf_intf::flow_cpu_state)
            };

            agg.budget_exhaustions = agg
                .budget_exhaustions
                .saturating_add(state.budget_exhaustions);
            agg.runnable_wakeups = agg.runnable_wakeups.saturating_add(state.runnable_wakeups);
            agg.prio_dispatches = agg.prio_dispatches.saturating_add(state.prio_dispatches);
            agg.normal_dispatches = agg
                .normal_dispatches
                .saturating_add(state.normal_dispatches);
            agg.cpu_migrations = agg.cpu_migrations.saturating_add(state.cpu_migrations);
        }

        agg
    }

    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.debug);

        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)?;

        skel.struct_ops.flow_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;

        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;

        // Populate CPU capacity map from sysfs with multi-source fallback.
        // On uniform-core systems all CPUs report the same capacity and
        // has_hybrid_cpus stays 0, making the BPF path a no-op.  On hybrid
        // Intel (Alder Lake / Raptor Lake), cpu_capacity may report 1024
        // for both P-cores and E-cores (seen on some kernel versions), so
        // we fall back to cpufreq/cpuinfo_max_freq which differs (~5.2 GHz
        // P-core vs ~3.9 GHz E-core).  AMD dual-CCD (7950X3D) is detected
        // via preferred-core ranking or CPPC highest_perf.  ARM big.LITTLE
        // reports distinct values via cpu_capacity directly.
        //
        // Detection sources ordered from most precise to least
        // (matching scx_utils::topology::get_capacity_source):
        //   1. cpufreq/amd_pstate_prefcore_ranking  — AMD preferred core ranking
        //   2. cpufreq/amd_pstate_highest_perf       — AMD pstate highest perf
        //   3. acpi_cppc/highest_perf                 — ACPI CPPC highest perf
        //   4. cpu_capacity                           — ARM big.LITTLE, some Intel
        //   5. cpufreq/cpuinfo_max_freq               — Intel hybrid (Raptor Lake)
        {
            let capacity_sources = [
                "cpufreq/amd_pstate_prefcore_ranking",
                "cpufreq/amd_pstate_highest_perf",
                "acpi_cppc/highest_perf",
                "cpu_capacity",
                "cpufreq/cpuinfo_max_freq",
            ];

            let mut chosen_source: Option<&str> = None;
            let mut raw_vals: [u32; 256] = [0; 256];
            let mut nr_online: u32 = 0;

            for source in capacity_sources {
                let mut min_raw = u32::MAX;
                let mut max_raw: u32 = 0;
                let mut any_found = false;

                for cpu in 0..256_usize {
                    let path = format!("/sys/devices/system/cpu/cpu{}/{}", cpu, source);
                    if let Ok(s) = std::fs::read_to_string(&path) {
                        if let Ok(val) = s.trim().parse::<u32>() {
                            any_found = true;
                            raw_vals[cpu] = val;
                            if val < min_raw { min_raw = val; }
                            if val > max_raw { max_raw = val; }
                        }
                    }
                }

                if any_found {
                    nr_online = raw_vals.iter().filter(|&&v| v > 0).count() as u32;
                    if min_raw < max_raw && max_raw > 0 {
                        // Source differentiates cores — hybrid detected
                        chosen_source = Some(source);
                        // Normalize to [0, 1024] for the BPF map
                        for cpu in 0..256_usize {
                            let raw = raw_vals[cpu];
                            let norm = if raw > 0 && max_raw > 0 {
                                ((raw as u64) * 1024 / (max_raw as u64)) as u32
                            } else {
                                0
                            };
                            let key = (cpu as u32).to_ne_bytes();
                            let val = norm.to_ne_bytes();
                            let _ = skel.maps.cpu_capacity_map.update(
                                &key, &val, libbpf_rs::MapFlags::ANY);
                        }
                        let bss = skel.maps.bss_data.as_mut().unwrap();
                        bss.has_hybrid_cpus = 1;
                        info!("CPU topology: hybrid cores detected via {} (raw {}–{}, {} online)",
                              source, min_raw, max_raw, nr_online);
                        break;
                    }
                }
            }

            if chosen_source.is_none() {
                // Uniform or unrecognized topology — write 1024 for all CPUs
                info!("CPU topology: uniform cores ({} online)", nr_online);
                for cpu in 0..256_usize {
                    let key = (cpu as u32).to_ne_bytes();
                    let val = 1024u32.to_ne_bytes();
                    let _ = skel.maps.cpu_capacity_map.update(
                        &key, &val, libbpf_rs::MapFlags::ANY);
                }
            }
        }

        let struct_ops = scx_ops_attach!(skel, flow_ops)?;

        // Expose live metrics for monitor and stats clients.
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        let cpu_policy_state = self.read_cpu_policy_state();
        Metrics {
            nr_running: bss_data.nr_running,
            total_runtime: bss_data.total_runtime,
            prio_dispatches: bss_data.prio_dispatches + cpu_policy_state.prio_dispatches,
            pinned_dispatches: bss_data.pinned_dispatches,
            normal_dispatches: bss_data.normal_dispatches + cpu_policy_state.normal_dispatches,
            budget_refill_events: bss_data.budget_refill_events,
            budget_exhaustions: bss_data.budget_exhaustions + cpu_policy_state.budget_exhaustions,
            runnable_wakeups: bss_data.runnable_wakeups + cpu_policy_state.runnable_wakeups,
            cpu_migrations: bss_data.cpu_migrations + cpu_policy_state.cpu_migrations,
        }
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(250)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
            SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }

    let monitor_only = opts.monitor.is_some();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }

    if !monitor_only {
        simplelog::SimpleLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
        )?;

        info!("{} {}", SCHEDULER_NAME, full_version());
        info!("Starting {} scheduler", SCHEDULER_NAME);
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let monitor_shutdown = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(err) = stats::monitor(Duration::from_secs_f64(intv), monitor_shutdown) {
                log::warn!("stats monitor thread finished with error: {err}");
            }
        });

        if monitor_only {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    sched.run(shutdown)?;

    info!("Scheduler exited");

    Ok(())
}
