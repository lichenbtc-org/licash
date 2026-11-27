//! A standby's deferral ([`Openings::defer_as_standby`]): beside a hub
//! that may well be alive, it does nothing of its own until late in each
//! step's window, and then only on a ledger restored after that point.
//!
//! The hub acts at once, so by a step's midpoint it has acted if it is
//! alive, and a copy of its ledger restored after the midpoint holds what
//! it did. A standby its entrypoint restores ([`RESTORED`]) and whose
//! ledger is older stops (as [`Openings::stale`] says) for the entrypoint
//! to restore the newest replica and start it again. Before its first act
//! of its own it writes [`ACTED`] in its data directory: from then on its
//! ledger is its own, never restored over, and it takes each step at its
//! midpoint without stopping, on that ledger.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::{Context as _, Result};

use super::Openings;

/// The file a standby writes before its first act of its own: its ledger
/// is then its own, which its entrypoint never restores over.
pub const ACTED: &str = "standby-acted";

/// The file a standby's entrypoint writes once it restored its ledger
/// from the hub's replica: it is restored at each start from then on.
pub const RESTORED: &str = "standby-restored";

/// The file a standby's entrypoint writes when a restore failed, saying
/// why: it started on the ledger restored before.
pub const UNRESTORED: &str = "standby-unrestored";

/// A standby's deferral: none unless [`Openings::defer_as_standby`].
#[derive(Default)]
pub(super) struct Deferral {
    deferring: AtomicBool,
    /// The tip when it first played, past the restore it opened on.
    opened: OnceLock<u32>,
    /// Whether it acted, as [`ACTED`] says.
    acted: AtomicBool,
    /// Whether its entrypoint restores it at each start, as [`RESTORED`]
    /// says: else stopping for a newer ledger brings none.
    restored: AtomicBool,
    /// Whether it is to stop, for its ledger to be restored newer.
    stale: AtomicBool,
}

/// What a step of a standby does at a tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// It may act.
    Go,
    /// Not yet: before the step is ripe, or stopping.
    Wait,
    /// Ripe, its ledger restored before then: it stops for a newer one.
    Stale,
}

impl Deferral {
    fn gate(&self, ripe: u32, tip: u32) -> Gate {
        gate(
            self.deferring.load(Ordering::Relaxed),
            self.stale.load(Ordering::Relaxed),
            self.acted.load(Ordering::Relaxed),
            self.restored.load(Ordering::Relaxed),
            self.opened.get().copied(),
            ripe,
            tip,
        )
    }
}

/// A step ripe at `ripe`, at `tip`: any hub's at once; a standby's not
/// before it is ripe, nor while it is stopping, then at once once it has
/// acted or where nothing restores it (not `restored`), else only on a
/// ledger it opened at `ripe` or later (`opened`).
pub(super) fn gate(
    deferring: bool,
    stopping: bool,
    acted: bool,
    restored: bool,
    opened: Option<u32>,
    ripe: u32,
    tip: u32,
) -> Gate {
    if !deferring {
        return Gate::Go;
    }
    if stopping || tip < ripe {
        return Gate::Wait;
    }
    if acted || !restored {
        return Gate::Go;
    }
    match opened {
        Some(opened) if opened >= ripe => Gate::Go,
        Some(_) => Gate::Stale,
        None => Gate::Wait,
    }
}

/// Halfway from `from` to `by`.
pub(super) fn mid(from: u32, by: u32) -> u32 {
    from.saturating_add(by.saturating_sub(from) / 2)
}

/// Write [`ACTED`] in `data`, durably: `tip` and contract `id`.
fn mark(data: &Path, tip: u32, id: &[u8; 32]) -> Result<()> {
    use std::io::Write as _;
    let path = data.join(ACTED);
    let part = data.join(format!("{ACTED}.part"));
    let mut file = std::fs::File::create(&part).with_context(|| format!("{}", part.display()))?;
    writeln!(file, "{tip} {}", crate::hex_id(id))?;
    file.sync_all()?;
    std::fs::rename(&part, &path).with_context(|| format!("{}", path.display()))?;
    std::fs::File::open(data)?.sync_all()?;
    Ok(())
}

impl Openings {
    /// Run as the hub's standby: each step of its own (a fee coin
    /// funded, an answer written to its witnesses, a transaction signed,
    /// posted or proven) deferred to halfway through its window, by when a
    /// live hub has taken it, and taken then only on a ledger opened as
    /// late, else [`Self::stale`], where its entrypoint restores it
    /// ([`RESTORED`]). Set once, before it plays.
    pub fn defer_as_standby(&self) {
        let d = &self.deferral;
        d.deferring.store(true, Ordering::Relaxed);
        let restored = self.data.join(RESTORED).exists();
        d.restored.store(restored, Ordering::Relaxed);
        if let Ok(why) = std::fs::read_to_string(self.data.join(UNRESTORED)) {
            self.alert(&format!(
                "the standby's ledger was not restored from the hub's replica at its start \
                 ({}): it plays on the one restored before, and a contract opened since is not \
                 in it. Check the replica and the private network to the hub.",
                why.trim()
            ));
        }
        if !restored && !self.data.join(ACTED).exists() {
            self.alert(&format!(
                "this standby is not restored by its entrypoint (no {RESTORED} in its data \
                 directory): it takes each step halfway through its window on its copy of \
                 the ledger as it is, never a newer one. Run it with licash-hub-standby."
            ));
        }
        if self.data.join(ACTED).exists() {
            d.acted.store(true, Ordering::Relaxed);
            self.alert(&format!(
                "this standby acted on its own ledger ({} in its data directory): it is no \
                 longer restored from the hub's replica, and the hub must never be restored \
                 from it. Keep it running until the contracts it played have ended.",
                ACTED
            ));
        }
    }

    /// Whether this is a standby, deferring its steps.
    pub(super) fn deferring(&self) -> bool {
        self.deferral.deferring.load(Ordering::Relaxed)
    }

    /// Whether this standby stopped playing, for its ledger to be
    /// restored newer and it started again: the hub's newest replica
    /// restored, it plays on what the hub did since.
    pub fn stale(&self) -> bool {
        self.deferral.stale.load(Ordering::Relaxed)
    }

    /// The tip as it plays a round: kept as the one it opened at, the
    /// first time; a standby not acted stopped once it is [`Self::refresh`]
    /// blocks past it, as a contract opened since is not in its ledger.
    pub(super) fn round_at(&self, tip: u32) {
        let d = &self.deferral;
        let opened = *d.opened.get_or_init(|| tip);
        let refresh = self.refresh();
        if d.deferring.load(Ordering::Relaxed)
            && d.restored.load(Ordering::Relaxed)
            && !d.acted.load(Ordering::Relaxed)
            && tip >= opened.saturating_add(refresh)
            && !d.stale.swap(true, Ordering::Relaxed)
        {
            tracing::info!(
                opened,
                tip,
                "the standby's ledger is {refresh} blocks old: stopping, to be restored newer"
            );
        }
    }

    /// The blocks a standby not acted plays on one restore: a quarter of
    /// the least response window, so a contract opened just after it is
    /// in its ledger before the midpoint of its first request's window.
    pub(super) fn refresh(&self) -> u32 {
        (self.timing().response_window() / 4).max(1)
    }

    /// Whether a step ripe at `ripe` may be looked at, at `tip`: always by
    /// a hub, by a standby once it is ripe and while it is not stopping.
    pub(super) fn due(&self, ripe: u32, tip: u32) -> bool {
        self.deferral.gate(ripe, tip) != Gate::Wait
    }

    /// Whether a step due (ripe at `ripe`) may decide anew at `tip`: a
    /// standby's only on a ledger opened at `ripe` or later, or once it
    /// acted. On an older one it does not, and stops if `stop`, as a step
    /// with a deadline does, to be restored newer at once.
    pub(super) fn fresh(&self, ripe: u32, stop: bool, tip: u32) -> bool {
        match self.deferral.gate(ripe, tip) {
            Gate::Go => true,
            Gate::Wait => false,
            Gate::Stale => {
                if stop && !self.deferral.stale.swap(true, Ordering::Relaxed) {
                    tracing::info!(
                        ripe,
                        tip,
                        "a contract's step is due and the standby's ledger older: stopping, to \
                         be restored newer"
                    );
                }
                false
            }
        }
    }

    /// That this standby, if one, acts now on contract `id` at `tip`: it
    /// writes [`ACTED`] first, once. Any hub's act is its own anyway.
    pub(super) fn acting(&self, id: &[u8; 32], tip: u32) -> Result<()> {
        let d = &self.deferral;
        if !d.deferring.load(Ordering::Relaxed) || d.acted.load(Ordering::Relaxed) {
            return Ok(());
        }
        mark(&self.data, tip, id).context("mark the standby acted")?;
        d.acted.store(true, Ordering::Relaxed);
        self.alert(&format!(
            "the standby acts on contract {} at block {tip}, the hub not having acted by \
             halfway through its window: its ledger is now its own ({ACTED}), never restored \
             from the hub's replica again. Never restore the hub from it; stop the hub if it is \
             alive.",
            crate::hex_id(id)
        ));
        Ok(())
    }

    /// [`Self::due`], [`Self::fresh`] and then [`Self::acting`]: whether
    /// this hub takes now a step of contract `id` ripe at `ripe`.
    pub(super) fn ready(&self, id: &[u8; 32], ripe: u32, stop: bool, tip: u32) -> Result<bool> {
        if !self.due(ripe, tip) || !self.fresh(ripe, stop, tip) {
            return Ok(false);
        }
        self.acting(id, tip)?;
        Ok(true)
    }

    /// Whether this hub plays on a ledger of its own: any but a standby
    /// that has not acted, whose ledger is the hub's copy.
    pub(super) fn own_ledger(&self) -> bool {
        let d = &self.deferral;
        !d.deferring.load(Ordering::Relaxed) || d.acted.load(Ordering::Relaxed)
    }

    /// Fails a standby that has not acted: where only a step through
    /// [`Self::acting`] gets, `what`.
    pub(super) fn unacted(&self, what: &str) -> Result<()> {
        anyhow::ensure!(self.own_ledger(), "the standby {what} before it acted");
        Ok(())
    }

    /// When a proof released at `release`, of an assertion due by
    /// `deadline` from `from`, is started: at once by a hub, by a standby
    /// not before halfway through, as it asserts.
    pub(super) fn proves_from(&self, release: u32, from: u32, deadline: u32) -> u32 {
        match self.deferral.deferring.load(Ordering::Relaxed) {
            true => release.max(mid(from, deadline)),
            false => release,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hub_goes_at_once_and_a_standby_only_when_ripe_and_fresh() {
        use Gate::*;
        // A hub, whatever else.
        assert_eq!(gate(false, true, false, true, None, 100, 0), Go);
        // A standby: not before ripe, nor while stopping.
        assert_eq!(gate(true, false, false, true, Some(100), 100, 99), Wait);
        assert_eq!(gate(true, true, true, true, Some(100), 100, 120), Wait);
        // Ripe: on a ledger opened then or later, or once it acted.
        assert_eq!(gate(true, false, false, true, Some(100), 100, 100), Go);
        assert_eq!(gate(true, false, false, true, Some(99), 100, 100), Stale);
        assert_eq!(gate(true, false, true, true, Some(10), 100, 100), Go);
        // Not yet played a round: it waits for it.
        assert_eq!(gate(true, false, false, true, None, 100, 100), Wait);
        // Nothing restores it: ripe, it goes on the ledger it has, as
        // stopping would bring no newer one.
        assert_eq!(gate(true, false, false, false, Some(10), 100, 99), Wait);
        assert_eq!(gate(true, false, false, false, Some(10), 100, 100), Go);
    }

    #[test]
    fn halfway() {
        assert_eq!(mid(100, 241), 170);
        assert_eq!(mid(100, 100), 100);
        assert_eq!(mid(100, 90), 100);
    }

    #[test]
    fn the_mark_is_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 812, &[7; 32]).unwrap();
        let read = std::fs::read_to_string(dir.path().join(ACTED)).unwrap();
        assert_eq!(read, format!("812 {}\n", crate::hex_id(&[7; 32])));
        assert!(!dir.path().join(format!("{ACTED}.part")).exists());
    }
}
