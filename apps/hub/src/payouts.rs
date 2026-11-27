//! The watch over what the hub pays out of its ledger ([`Guard`]).
//!
//! Whoever else holds the hub's seed makes notes its ledger never issued,
//! and spends them at the hub for what it pays out. The ledger cannot tell
//! such a note from its own, but it counts: once it retired more notes of
//! a denomination than it ever issued ([`licash_hub::Notes::excess`]),
//! some were made outside it. Then the operator is alerted, and the watch
//! stays paused, told of nothing more, until the operator resumes it
//! ([`resume`]). The hub pays nothing out itself: hubs of earlier releases
//! paused their Lightning gateway with it, and what pays out now is the
//! providers', which the operator warns.
//!
//! It tells late: only once such notes outnumber all the hub's outstanding
//! notes of a denomination.
//!
//! A ledger restored from an older copy shows the same: the notes it
//! issued since that copy are retired and, to it, never issued. So does a
//! hub resumed with such notes known, for what it retires beyond those
//! issued is the notes made outside it less those of its own outstanding,
//! and rises again as its holders spend theirs. Only a hub that knows of
//! none is told of nothing but notes made outside its ledger.
//!
//! Kept in `<data>/payouts.json`, read again at every look, so that
//! `licash-hub resume-payouts` reaches the running hub:
//! - no file, as of a hub that never ran this watch: what the ledger shows
//!   then is taken as known, told the operator if any, and nothing pauses;
//! - `baseline`: the notes beyond those issued the operator knows of, as
//!   of the last resume. More than these pause;
//! - `paused`: why payments out are paused, across restarts;
//! - a file that does not read pauses, and is told.

use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use licash_hub::{Excess, Hub, Ledger};
use serde::{Deserialize, Serialize};

/// Between looks at the ledger.
pub const EVERY: Duration = Duration::from_secs(30);

const FILE: &str = "payouts.json";

/// What `payouts.json` keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    /// By keyset then denomination, the notes retired beyond those issued
    /// that the operator knows of.
    pub baseline: Vec<Excess>,
    /// Why payments out are paused, while they are.
    pub paused: Option<String>,
}

/// The watch of the hub of data directory `data`, and whether its
/// payments out are paused.
pub struct Guard {
    data: PathBuf,
    paused: Mutex<Option<String>>,
    /// What the operator was alerted of, once each until payments out
    /// resume.
    told: Mutex<HashSet<String>>,
}

impl Guard {
    /// The watch as `data` keeps it: paused if it was, or if what it kept
    /// does not read. The ledger is not looked at until [`Guard::check`].
    pub fn open(data: &Path) -> Arc<Self> {
        let paused = match kept(data) {
            Ok(kept) => kept.and_then(|kept| kept.paused),
            Err(e) => Some(unreadable(&e)),
        };
        Arc::new(Self {
            data: data.to_owned(),
            paused: Mutex::new(paused),
            told: Mutex::default(),
        })
    }

    /// Whether payments out are paused.
    pub fn paused(&self) -> bool {
        self.paused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Look at the ledger once, and keep what is found: what to alert the
    /// operator of, each thing once until payments out resume. A ledger
    /// that does not read changes nothing.
    pub fn check(&self) -> Vec<String> {
        let before = match kept(&self.data) {
            Ok(before) => before,
            Err(e) => {
                let why = unreadable(&e);
                self.pause(Some(why.clone()));
                return self.once(format!(
                    "The watch over payments out is paused: {why}. Look at the ledger, then \
                     run `licash-hub resume-payouts`."
                ));
            }
        };
        let excess = match excess(&self.data) {
            Ok(excess) => excess,
            Err(e) => {
                tracing::warn!("cannot count the ledger's notes: {e:#}");
                self.pause(before.and_then(|kept| kept.paused));
                return Vec::new();
            }
        };
        let (now, alert) = judge(before.clone(), &excess);
        // Kept before it takes effect; in effect even if it cannot be.
        let mut alerts = Vec::new();
        if before.as_ref() != Some(&now) {
            if let Err(e) = keep(&self.data, &now) {
                tracing::error!("cannot keep {FILE}: {e:#}");
                alerts = self.once(format!(
                    "The watch over payments out cannot keep {FILE}: what it finds \
                     is lost when the hub restarts, and with no such file it takes what the \
                     ledger shows as known and pauses nothing."
                ));
            }
        }
        self.pause(now.paused);
        alerts.extend(alert.map_or_else(Vec::new, |alert| self.once(alert)));
        alerts
    }

    /// Look at the ledger every [`EVERY`], alerting the operator through
    /// `hub`, until the task is dropped.
    pub async fn run(self: Arc<Self>, hub: Arc<Hub>) {
        loop {
            let (guard, notify) = (self.clone(), hub.clone());
            let looked = tokio::task::spawn_blocking(move || {
                for alert in guard.check() {
                    if let Err(e) = notify.alert(&alert) {
                        tracing::error!(error = %e, "cannot alert the operator");
                    }
                }
            });
            if let Err(e) = looked.await {
                tracing::error!("the watch over payments out: {e}");
            }
            tokio::time::sleep(EVERY).await;
        }
    }

    fn pause(&self, why: Option<String>) {
        let mut paused = self.paused.lock().unwrap_or_else(|e| e.into_inner());
        if paused.is_some() && why.is_none() {
            // Resumed: a pause after it is told again, whatever its words.
            self.told.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
        *paused = why;
    }

    fn once(&self, alert: String) -> Vec<String> {
        let mut told = self.told.lock().unwrap_or_else(|e| e.into_inner());
        match told.insert(alert.clone()) {
            true => vec![alert],
            false => Vec::new(),
        }
    }
}

/// What to keep on finding `excess` in the ledger with `before` kept, and
/// what to alert the operator of.
fn judge(before: Option<Kept>, excess: &[Excess]) -> (Kept, Option<String>) {
    let Some(before) = before else {
        // Nothing kept proves nothing: a hub that ran before this watch.
        let alert = (!excess.is_empty()).then(|| {
            format!(
                "The ledger retired notes it never issued ({}), before it was watched for \
                 them: made with the hub's seed outside its ledger, or issued after the copy \
                 a restored ledger was taken at. Taken as known: payments out are not \
                 paused, and pause if more are found.",
                listed(excess)
            )
        });
        let kept = Kept {
            baseline: excess.to_vec(),
            paused: None,
        };
        return (kept, alert);
    };
    let known = |e: &Excess| {
        let same = |b: &&Excess| (b.keyset, b.denom) == (e.keyset, e.denom);
        before.baseline.iter().find(same).map_or(0, |b| b.notes)
    };
    let new: Vec<Excess> = excess
        .iter()
        .filter(|e| e.notes > known(e))
        .copied()
        .collect();
    // What is known stays so until the operator resumes. Lowered as the
    // ledger issues, it would pause as holders spend what it issued them:
    // each note issued takes one from the excess, and spent, gives it back.
    let (paused, alert) = match (before.paused, new.is_empty()) {
        (Some(paused), _) => (Some(paused), None),
        (None, true) => (None, None),
        (None, false) => {
            let why = format!(
                "the ledger retired notes it never issued ({})",
                listed(&new)
            );
            let alert = format!(
                "The watch over payments out is paused: {why}, made with the hub's seed \
                 outside its ledger. Unless the ledger was restored from an older copy, or \
                 notes like these were known when the watch last resumed, treat the seed as \
                 held by someone else: stop the hub, and tell the providers swapping its \
                 notes. Nothing more is told until `licash-hub resume-payouts`."
            );
            (Some(why), Some(alert))
        }
    };
    let baseline = before.baseline;
    (Kept { baseline, paused }, alert)
}

fn listed(excess: &[Excess]) -> String {
    let each = excess
        .iter()
        .map(|e| format!("{} of {} sat of keyset {}", e.notes, e.denom, e.keyset));
    each.collect::<Vec<_>>().join(", ")
}

fn unreadable(e: &anyhow::Error) -> String {
    format!("{FILE} does not read ({e:#})")
}

/// The notes the ledger of `data` retired beyond those it issued.
fn excess(data: &Path) -> Result<Vec<Excess>> {
    let ledger = Ledger::open(&data.join("hub.sqlite")).context("read the hub")?;
    Ok(ledger.notes()?.excess())
}

/// What `data` keeps of the watch: nothing if it never ran there.
pub fn kept(data: &Path) -> Result<Option<Kept>> {
    let bytes = match std::fs::read(data.join(FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Keep `kept` in `data`, whole or not at all, a power cut included.
fn keep(data: &Path, kept: &Kept) -> Result<()> {
    let (file, part) = (data.join(FILE), data.join(format!("{FILE}.part")));
    let mut written = std::fs::File::create(&part)?;
    written.write_all(&serde_json::to_vec_pretty(kept)?)?;
    written.sync_all()?;
    std::fs::rename(&part, &file)?;
    std::fs::File::open(data)?.sync_all()?;
    Ok(())
}

/// Resume the payments out of the hub of `data`, running or not: what its
/// ledger shows now is taken as known. A running hub resumes at its next
/// look, within [`EVERY`]. Why they were paused, if they were, and what
/// is kept now.
pub fn resume(data: &Path) -> Result<(Option<String>, Kept)> {
    let now = Kept {
        baseline: excess(data)?,
        paused: None,
    };
    let paused = match kept(data) {
        Ok(kept) => kept.and_then(|kept| kept.paused),
        Err(e) => Some(unreadable(&e)),
    };
    keep(data, &now).with_context(|| format!("keep {FILE}"))?;
    Ok((paused, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(denom: u64, notes: u64) -> Excess {
        Excess {
            keyset: 0,
            denom,
            notes,
        }
    }

    #[test]
    fn a_hub_never_watched_takes_what_it_finds_as_known_and_pauses_nothing() {
        // Upgraded with nothing to find: kept, nothing told.
        assert_eq!(judge(None, &[]), (Kept::default(), None));
        // With notes beyond those issued already: told, not paused.
        let (kept, alert) = judge(None, &[of(4, 2)]);
        assert_eq!(kept.baseline, [of(4, 2)]);
        assert_eq!(kept.paused, None);
        let alert = alert.unwrap();
        assert!(alert.contains("2 of 4 sat of keyset 0") && alert.contains("not paused"));
        // The same found again: nothing more.
        assert_eq!(judge(Some(kept.clone()), &[of(4, 2)]), (kept, None));
    }

    #[test]
    fn notes_beyond_those_known_pause_until_resumed() {
        let known = Kept {
            baseline: vec![of(4, 2)],
            paused: None,
        };
        // More of a known denomination, or any of another.
        for found in [vec![of(4, 3)], vec![of(4, 2), of(8, 1)]] {
            let (kept, alert) = judge(Some(known.clone()), &found);
            assert_eq!(kept.baseline, known.baseline);
            let why = kept.paused.clone().unwrap();
            assert!(why.contains("never issued"), "{why}");
            assert!(alert.unwrap().contains("resume-payouts"));
            // Paused, it stays so and tells no more, whatever is found.
            assert_eq!(judge(Some(kept.clone()), &found), (kept.clone(), None));
            let (later, alert) = judge(Some(kept.clone()), &[of(4, 9)]);
            assert_eq!((later.paused, alert), (kept.paused, None));
        }
        // A hub watched from its start knows of none: the first pauses.
        let (kept, alert) = judge(Some(Kept::default()), &[of(1, 1)]);
        assert!(kept.paused.is_some() && alert.is_some());
    }

    /// A note the ledger issues takes one from what it retired beyond
    /// those issued, and spent, gives it back: no more than was known.
    #[test]
    fn what_is_known_stays_as_the_ledger_issues_and_its_holders_spend() {
        let known = Kept {
            baseline: vec![of(4, 5), of(8, 1)],
            paused: None,
        };
        for found in [vec![of(4, 3)], vec![], vec![of(4, 5), of(8, 1)]] {
            assert_eq!(judge(Some(known.clone()), &found), (known.clone(), None));
        }
        // One more than was known pauses, whatever was found between.
        let (kept, alert) = judge(Some(known.clone()), &[of(4, 6)]);
        assert_eq!(kept.baseline, known.baseline);
        assert!(kept.paused.is_some() && alert.is_some());
    }

    #[test]
    fn the_watch_keeps_its_file_and_a_file_that_does_not_read_pauses() {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 6).unwrap();
        assert_eq!(kept(dir.path()).unwrap(), None);
        let guard = Guard::open(dir.path());
        assert!(!guard.paused());
        assert_eq!(guard.check(), Vec::<String>::new());
        assert_eq!(kept(dir.path()).unwrap(), Some(Kept::default()));
        assert!(!guard.paused());

        // Paused on file, as by a look before a restart: read at the next
        // look, and by a hub starting.
        let paused = Kept {
            baseline: Vec::new(),
            paused: Some("as told".into()),
        };
        keep(dir.path(), &paused).unwrap();
        assert!(Guard::open(dir.path()).paused());
        assert_eq!(guard.check(), Vec::<String>::new());
        assert!(guard.paused());
        // Resumed beside it: at its next look.
        let (was, now) = resume(dir.path()).unwrap();
        assert_eq!((was, now), (paused.paused, Kept::default()));
        assert!(guard.paused());
        assert_eq!(guard.check(), Vec::<String>::new());
        assert!(!guard.paused());

        // A file that does not read: paused, told once.
        std::fs::write(dir.path().join(FILE), b"{").unwrap();
        let alerts = guard.check();
        assert!(
            alerts.len() == 1 && alerts[0].contains("does not read"),
            "{alerts:?}"
        );
        assert!(guard.paused() && Guard::open(dir.path()).paused());
        assert_eq!(guard.check(), Vec::<String>::new());
        let (was, _) = resume(dir.path()).unwrap();
        assert!(was.unwrap().contains("does not read"));
        guard.check();
        assert!(!guard.paused());
        // Paused again for the same after a resume: told again.
        std::fs::write(dir.path().join(FILE), b"{").unwrap();
        assert_eq!(guard.check().len(), 1);
        assert!(guard.paused());
    }

    #[test]
    fn a_file_that_cannot_be_kept_is_told_once() {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 6).unwrap();
        // Nothing is written over a directory.
        std::fs::create_dir(dir.path().join(format!("{FILE}.part"))).unwrap();
        let guard = Guard::open(dir.path());
        let alerts = guard.check();
        assert!(
            alerts.len() == 1 && alerts[0].contains("cannot keep"),
            "{alerts:?}"
        );
        assert_eq!(guard.check(), Vec::<String>::new());
        assert!(!guard.paused() && kept(dir.path()).unwrap().is_none());
    }
}
