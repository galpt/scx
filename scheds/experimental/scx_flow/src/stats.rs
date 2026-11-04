// SPDX-License-Identifier: GPL-2.0
//! Stats server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports four per LLC counters summed across LLCs.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
/// Minimal counters with pair plus DSQ detail.
pub struct Metrics {
    #[stat(desc = "Tasks now queued in pair plus DSQ")]
    #[serde(default)]
    pub queued: u64,
    #[stat(desc = "Tasks moved to local in dispatch")]
    #[serde(default)]
    pub dispatched: u64,
    #[stat(desc = "Pair full plus duplicate plus stale discards")]
    #[serde(default)]
    pub fallback: u64,
    #[stat(desc = "Pair and LLC queue steals in dispatch")]
    #[serde(default)]
    pub steal: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] queued={} dispatched={} fallback={} steal={}",
            crate::SCHEDULER_NAME,
            self.queued,
            self.dispatched,
            self.fallback,
            self.steal,
        )?;
        Ok(())
    }

    /// Interval delta with queued passing through as a live gauge.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            queued: self.queued,
            dispatched: self.dispatched.wrapping_sub(rhs.dispatched),
            fallback: self.fallback.wrapping_sub(rhs.fallback),
            steal: self.steal.wrapping_sub(rhs.steal),
        }
    }
}

/// Stats printer loop for the monitor flag.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

/// Server data for the stats server.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;
        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}
