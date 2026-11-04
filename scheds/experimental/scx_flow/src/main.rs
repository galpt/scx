// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler front end.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Loads the BPF object, seeds the LLC view, then drives the loop.
//! Observability is four counters through the stats server.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
#[path = "stats.rs"]
mod stats;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::Shell;
use clap_complete::generate;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use stats::Metrics;

/* Binary name used in logs and stats. */
const SCHEDULER_NAME: &str = "scx_flow";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Validated poll interval from float seconds.
/// Rejects NaN plus infinite plus non-positive plus over one hour, so
/// a bad flag fails closed before any timer starts with no panic.
fn poll_interval_secs(v: f64) -> Result<Duration> {
    if !v.is_finite() || v <= 0.0 || v > 3600.0 {
        anyhow::bail!("interval bad {v}");
    }
    Ok(Duration::from_secs_f64(v))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /* Poll interval for the stats printer. */
    #[clap(long)]
    stats: Option<f64>,
    /* Run the stats printer only. */
    #[clap(long)]
    monitor: Option<f64>,
    /* Verbose output with libbpf detail. Logging only. */
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
    /* Exit dump buffer length in bytes. Debug dump only. */
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,
    /* Print version and exit. */
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
    /* Show stat descriptions. */
    #[clap(long)]
    help_stats: bool,
    /* Generate shell completions and exit. */
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/*
 * Scheduler owns the skeleton, the link, and the stats server.
 * It drives the run loop until shutdown or exit.
 */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)
            .context("failed to open BPF object (check dmesg)")?;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        match Self::seed_topology(&mut skel) {
            Ok(text) => info!("Topology: {text}"),
            Err(e) => warn!("topology seed failed, using BPF defaults: {e:#}"),
        }
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
        })
    }

    /// Seed one CPU row per online CPU into the BPF view.
    /// Maps Topology LLC and node ids to contiguous indices for the
    /// fixed BPF bounds. Failures return an error with no trap.
    fn seed_topology(skel: &mut BpfSkel<'_>) -> Result<String> {
        use libbpf_rs::MapCore;
        let topo = Topology::new().context("topology discovery")?;
        let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
        llc_ids.sort_unstable();
        let mut node_ids: Vec<usize> = topo.nodes.keys().copied().collect();
        node_ids.sort_unstable();
        if llc_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_LLCS as usize {
            anyhow::bail!("LLC count over bound");
        }
        if node_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_NODES as usize {
            anyhow::bail!("node count over bound");
        }
        let mut seeded = 0u32;
        let mut cpus: Vec<usize> = topo.all_cpus.keys().copied().collect();
        cpus.sort_unstable();
        for cpu in cpus {
            if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
                continue;
            }
            let entry = match topo.all_cpus.get(&cpu) {
                Some(v) => v,
                None => continue,
            };
            let llc = llc_ids.iter().position(|v| *v == entry.llc_id).unwrap_or(0) as u32;
            let node = node_ids
                .iter()
                .position(|v| *v == entry.node_id)
                .unwrap_or(0) as u32;
            let key = (cpu as u32).to_ne_bytes();
            let mut val = [0u8; 16];
            val[0..4].copy_from_slice(&(cpu as u32).to_ne_bytes());
            val[4..8].copy_from_slice(&llc.to_ne_bytes());
            val[8..12].copy_from_slice(&node.to_ne_bytes());
            skel.maps
                .cpu_ctx_stor
                .update(&key, &val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("cpu seed failed for cpu {cpu}"))?;
            seeded += 1;
        }
        Ok(format!(
            "{} cpus {} llcs {} nodes",
            seeded,
            llc_ids.len(),
            node_ids.len()
        ))
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /// Sum per LLC counters into one view.
    /// A failed map read warns once per poll and keeps zeros.
    fn get_metrics(&self) -> Metrics {
        use libbpf_rs::MapCore;
        let mut out = Metrics::default();
        for llc in 0..crate::bpf_intf::flow_consts_FLOW_MAX_LLCS {
            let key = llc.to_ne_bytes();
            let val = match self
                .skel
                .maps
                .llc_stats_stor
                .lookup(&key, libbpf_rs::MapFlags::ANY)
            {
                Ok(Some(v)) => v,
                Ok(None) => continue,
                Err(e) => {
                    warn!("stats read failed for llc {llc}: {e:#}");
                    continue;
                }
            };
            if val.len() < 32 {
                continue;
            }
            let q = u64::from_ne_bytes(val[0..8].try_into().unwrap_or([0u8; 8]));
            let d = u64::from_ne_bytes(val[8..16].try_into().unwrap_or([0u8; 8]));
            let f = u64::from_ne_bytes(val[16..24].try_into().unwrap_or([0u8; 8]));
            let s = u64::from_ne_bytes(val[24..32].try_into().unwrap_or([0u8; 8]));
            out.queued = out.queued.wrapping_add(q);
            out.dispatched = out.dispatched.wrapping_add(d);
            out.fallback = out.fallback.wrapping_add(f);
            out.steal = out.steal.wrapping_add(s);
            if llc + 1 >= 64 {
                break;
            }
        }
        out
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
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
    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }
    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }
    let loglevel = if opts.verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    info!("{} {}", SCHEDULER_NAME, full_version());
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || {
        sd.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let dur = poll_interval_secs(intv)?;
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(dur, sd) {
                warn!("monitor failed: {e:#}");
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }
    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    info!("Scheduler exited");
    Ok(())
}
