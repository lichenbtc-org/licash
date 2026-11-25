//! What the operator is told of the responder's health: its node's chain
//! stalled, or its rounds failing, for long. Either leaves claims against
//! the hub unanswered, whose timeouts pay what they claim.

use std::time::Duration;

use licash::spend::ChainProfile;
use tokio::time::Instant;

/// Blocks the node's tip may stay unchanged for before the operator is
/// told: two hours of Bitcoin's, about once in decades by chance.
const STALL_BLOCKS: u32 = 12;

/// How long the responder's rounds may fail before the operator is told.
pub(super) const DOWN: Duration = Duration::from_secs(10 * 60);

/// The responder's health, kept across its rounds.
#[derive(Debug)]
pub(super) struct Vigil {
    /// How long the tip may stay unchanged: never on regtest, whose blocks
    /// come only when asked for.
    stall: Option<Duration>,
    /// The tip last seen, and when it was first seen.
    tip: Option<(bitcoin::BlockHash, Instant)>,
    stalled: bool,
    /// Since when rounds fail, and whether the operator was told.
    failing: Option<(Instant, bool)>,
}

impl Vigil {
    pub(super) fn new(profile: ChainProfile) -> Self {
        let stall = match profile {
            ChainProfile::Core30DefaultRegtest => None,
            p => Some(Duration::from_secs(u64::from(
                STALL_BLOCKS * p.block_seconds(),
            ))),
        };
        Self {
            stall,
            tip: None,
            stalled: false,
            failing: None,
        }
    }

    /// A round at `now`, seeing the node's tip `tip` (none if the node
    /// could not tell it) and failing with `failed`, if it did: what to
    /// tell the operator, each once until it changes.
    pub(super) fn round(
        &mut self,
        now: Instant,
        tip: Option<bitcoin::BlockHash>,
        failed: Option<&str>,
    ) -> Vec<String> {
        let mut told = Vec::new();
        if let Some(tip) = tip {
            match self.tip {
                Some((last, _)) if last == tip => {}
                _ => {
                    self.tip = Some((tip, now));
                    if std::mem::take(&mut self.stalled) {
                        told.push(format!("the node's chain advances again, to {tip}"));
                    }
                }
            }
            if let (Some(stall), Some((_, since))) = (self.stall, self.tip) {
                if !self.stalled && now.duration_since(since) >= stall {
                    self.stalled = true;
                    told.push(format!(
                        "the node's chain has not advanced in {} minutes, its tip still \
                         {tip}: is it synced and connected? Claims against the hub go \
                         unanswered while it lags",
                        now.duration_since(since).as_secs() / 60
                    ));
                }
            }
        }
        match (failed, &mut self.failing) {
            (None, failing) => {
                if let Some((_, true)) = failing.take() {
                    told.push("the contract responder works again".into());
                }
            }
            (Some(_), None) => self.failing = Some((now, false)),
            (Some(e), Some((since, told_of))) => {
                if !*told_of && now.duration_since(*since) >= DOWN {
                    *told_of = true;
                    told.push(format!(
                        "the contract responder has failed for {} minutes, claims against \
                         the hub going unanswered: {e}",
                        now.duration_since(*since).as_secs() / 60
                    ));
                }
            }
        }
        told
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::*;

    fn hash(n: u8) -> bitcoin::BlockHash {
        bitcoin::BlockHash::from_byte_array([n; 32])
    }

    #[test]
    fn a_stalled_chain_is_told_once_and_again_once_it_advances() {
        let start = Instant::now();
        let mut vigil = Vigil::new(ChainProfile::Core30Mainnet);
        let at = |minutes: u64| start + Duration::from_secs(minutes * 60);
        assert!(vigil.round(at(0), Some(hash(1)), None).is_empty());
        assert!(vigil.round(at(119), Some(hash(1)), None).is_empty());
        // The node unreachable: its chain not judged.
        assert!(vigil.round(at(119), None, None).is_empty());
        let told = vigil.round(at(120), Some(hash(1)), None);
        assert_eq!(told.len(), 1, "{told:?}");
        assert!(told[0].contains("not advanced in 120 minutes"), "{told:?}");
        assert!(vigil.round(at(500), Some(hash(1)), None).is_empty());
        let told = vigil.round(at(501), Some(hash(2)), None);
        assert_eq!(told.len(), 1, "{told:?}");
        assert!(told[0].contains("advances again"), "{told:?}");
        // Counted anew from the new tip.
        assert!(vigil.round(at(620), Some(hash(2)), None).is_empty());
        assert_eq!(vigil.round(at(621), Some(hash(2)), None).len(), 1);
    }

    #[test]
    fn a_regtest_chain_is_never_stalled() {
        let start = Instant::now();
        let mut vigil = Vigil::new(ChainProfile::Core30DefaultRegtest);
        vigil.round(start, Some(hash(1)), None);
        let later = start + Duration::from_secs(365 * 24 * 3600);
        assert!(vigil.round(later, Some(hash(1)), None).is_empty());
    }

    #[test]
    fn mutinynet_stalls_at_its_own_pace() {
        let start = Instant::now();
        let mut vigil = Vigil::new(ChainProfile::Mutinynet);
        vigil.round(start, Some(hash(1)), None);
        let later = start + Duration::from_secs(6 * 60);
        assert_eq!(vigil.round(later, Some(hash(1)), None).len(), 1);
    }

    #[test]
    fn rounds_failing_for_long_are_told_once_and_again_once_they_work() {
        let start = Instant::now();
        let mut vigil = Vigil::new(ChainProfile::Core30DefaultRegtest);
        // Failing briefly, then working: never told.
        assert!(vigil.round(start, None, Some("down")).is_empty());
        let soon = start + DOWN / 2;
        assert!(vigil.round(soon, Some(hash(1)), None).is_empty());
        // Failing from then for as long as told of.
        let since = soon + Duration::from_secs(1);
        assert!(vigil.round(since, None, Some("down")).is_empty());
        assert!(vigil.round(since + DOWN / 2, None, Some("down")).is_empty());
        let told = vigil.round(since + DOWN, None, Some("rpc refused"));
        assert_eq!(told.len(), 1, "{told:?}");
        assert!(told[0].contains("failed for 10 minutes"), "{told:?}");
        assert!(told[0].contains("rpc refused"), "{told:?}");
        assert!(vigil.round(since + DOWN * 3, None, Some("down")).is_empty());
        let told = vigil.round(since + DOWN * 4, Some(hash(1)), None);
        assert_eq!(told, vec!["the contract responder works again".to_owned()]);
    }
}
