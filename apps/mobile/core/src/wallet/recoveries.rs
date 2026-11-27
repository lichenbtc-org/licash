//! Contracts forced closed when their hub went silent: the notes at the
//! hub, up to the contract's cap, claimed on Bitcoin, paid back on Bitcoin
//! once the hub's window to answer passed. Started only by the holder's
//! explicit choice, carried on with the other contracts as the chain
//! moves. A hub that answers instead says what the claim is owed and must
//! prove it on Bitcoin: the wallet checks the hub's proof, challenges one
//! that does not verify, and is paid what the outcome says. The phone
//! proves nothing.

use std::sync::{Arc, Mutex, PoisonError};

use bitcoin::{BlockHash, FeeRate};
use licash_contracts::holder::recovery::{self, Stage};
use licash_contracts::holder::Chain as _;
use licash_wallet::Blocks as _;

use super::Wallet;
use crate::{chain::Chain, ChainSource, LicashError};

/// The least rate of its fees, in sat/vB, and its rate without one of the
/// chain's. Her publication P starts at it, then is made again to pay more
/// as its window runs out, whatever the chain says; her challenge's fee
/// child is made again at the rate its deadline gives. The timeout's fee
/// coin, sized at twice it, is never bumped.
const RECOVERY_RATE: u64 = 2;

/// The last rate read, of the best chain's block of this hash.
static RATE: Mutex<Option<(BlockHash, FeeRate)>> = Mutex::new(None);

/// Its fees' rate: what the chain's last blocks paid, as the light client
/// reads them (no peer estimates), [`RECOVERY_RATE`] at least. Its blocks
/// are fetched whole: asked for only while a close is under way, once a
/// block.
async fn rate(chain: &Chain) -> FeeRate {
    let floor = FeeRate::from_sat_per_vb(RECOVERY_RATE).expect("a rate");
    let tip = match chain.height().await {
        Ok(height) => chain.hash(height).await,
        Err(e) => Err(e),
    };
    let tip = match tip {
        Ok(tip) => tip,
        Err(e) => {
            tracing::warn!("no fee rate of the chain's blocks: {e}");
            return floor;
        }
    };
    let cached = *RATE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, rate)) = cached.filter(|(hash, _)| *hash == tip) {
        return rate;
    }
    let rate = match chain.fee_rate(6).await {
        Ok(Some(rate)) => rate.max(floor),
        Ok(None) => floor,
        Err(e) => {
            tracing::warn!("no fee rate of the chain's blocks: {e}");
            return floor;
        }
    };
    *RATE.lock().unwrap_or_else(PoisonError::into_inner) = Some((tip, rate));
    rate
}

/// A contract being forced closed, as the wallet last saw it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Recovery {
    /// The contract's id, in hex.
    pub id: String,
    pub stage: RecoveryStage,
    /// Past giving it up: the notes it claimed are gone from the balance
    /// for good, to come back on Bitcoin.
    pub irrevocable: bool,
    /// What the notes it claimed come to, in sat, and how many they are.
    pub claimed: u64,
    pub notes: u32,
    /// Its request on Bitcoin and the transaction publishing its claim,
    /// once signed, their ids in hex.
    pub request: Option<String>,
    pub publication: Option<String>,
    /// The transaction paying the claim back once the hub let its window
    /// pass, and the one sweeping it to the wallet, once built.
    pub timeout: Option<String>,
    pub sweep: Option<String>,
    /// The block its next step waits for, if it waits for one.
    pub next_at: Option<u32>,
    /// What stopped its last step, if anything did.
    pub error: Option<String>,
    /// The hub's answer to its request, its id in hex, and the last block
    /// the hub's proof may be posted in, once known.
    #[uniffi(default = None)]
    pub response: Option<String>,
    #[uniffi(default = None)]
    pub deadline: Option<u32>,
    /// Whether the hub's proof, once posted, verifies.
    #[uniffi(default = false)]
    pub proved: bool,
    /// The hub's proof posted, and the payout after it, their ids in hex.
    #[uniffi(default = None)]
    pub assertion: Option<String>,
    #[uniffi(default = None)]
    pub payout: Option<String>,
    /// What the hub says the claim is owed, distinct from the claim and
    /// from what was received.
    #[uniffi(default = None)]
    pub corrected: Option<u64>,
    #[uniffi(default = None)]
    pub received: Option<u64>,
    /// The last fold of a close on her claim the hub signed, its id in
    /// hex, once it did ([`RecoveryStage::Folding`]).
    #[uniffi(default = None)]
    pub fold: Option<String>,
    /// Its claim held out of blocks by the fee her contract's reserve
    /// pays: on once she allows more ([`Wallet::allow_publication_fee`]).
    #[uniffi(default = false)]
    pub fee_capped: bool,
}

/// Where a forced close, or a close on a fold of her claim, stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RecoveryStage {
    /// Closed with the hub, cooperatively: her claim's notes are out of her
    /// balance, and its fold, which pays them and her reserve on Bitcoin,
    /// awaited. The claim is filed on Bitcoin by a forced close, by itself
    /// should the fold be late; any fold signed may still confirm.
    Folding,
    /// The notes claimed: it may still be given up, until its request may
    /// be in the next block.
    Claimed,
    /// Its request signed, on its way into a block.
    Requesting,
    /// Its request in a block: the hub's window to answer running.
    Requested,
    /// The window passed unanswered: the payback on its way, then its
    /// delay running.
    TimingOut,
    /// The payback swept to the wallet, until in a block.
    Sweeping,
    /// Its value back in the wallet on Bitcoin.
    Done,
    /// The hub answered that the claim is owed less: the wallet checks its
    /// evidence and lets the answer stand, or contests it, and its proof is
    /// awaited.
    Answered,
    /// The contract's collateral went elsewhere.
    Lost,
    /// The hub's proof in a block: checked, then the payout on its way.
    Asserted,
    /// The hub's proof did not verify: the wallet's challenge on its way.
    Challenging,
    /// The challenge in a block: the hub's chance to answer it running,
    /// then the payout on its way.
    Challenged,
    /// The payout after the proof in a block: its delay running.
    Paid,
}

fn stage(s: Stage) -> RecoveryStage {
    match s {
        Stage::Claiming | Stage::Claimed | Stage::GivingUp => RecoveryStage::Claimed,
        Stage::Irrevocable | Stage::Signing | Stage::Published => RecoveryStage::Requesting,
        Stage::Requested => RecoveryStage::Requested,
        Stage::TimingOut | Stage::TimedOut => RecoveryStage::TimingOut,
        Stage::Sweeping => RecoveryStage::Sweeping,
        Stage::Done => RecoveryStage::Done,
        Stage::Answered | Stage::Contesting | Stage::Contested => RecoveryStage::Answered,
        Stage::Asserted | Stage::Succeeding => RecoveryStage::Asserted,
        Stage::Challenging => RecoveryStage::Challenging,
        Stage::Challenged => RecoveryStage::Challenged,
        Stage::Paid => RecoveryStage::Paid,
        Stage::Lost => RecoveryStage::Lost,
        Stage::Folding => RecoveryStage::Folding,
    }
}

fn shown(r: &recovery::Recovery) -> Recovery {
    let txid = |t: Option<bitcoin::Txid>| t.map(|t| t.to_string());
    Recovery {
        id: hex::encode(r.id),
        stage: stage(r.stage),
        irrevocable: r.irrevocable,
        claimed: r.claimed,
        notes: u32::try_from(r.notes).unwrap_or(u32::MAX),
        request: txid(r.request),
        publication: txid(r.publication),
        timeout: txid(r.timeout),
        sweep: txid(r.sweep),
        next_at: r.next_at,
        error: r.error.clone(),
        response: txid(r.response),
        deadline: r.deadline,
        proved: r.proved,
        assertion: txid(r.assertion),
        payout: txid(r.payout),
        corrected: r.corrected,
        received: r.received,
        fold: txid(r.fold),
        fee_capped: r.fee_capped,
    }
}

fn contract_id(id: &str) -> Result<[u8; 32], LicashError> {
    let mut out = [0; 32];
    hex::decode_to_slice(id.trim(), &mut out)
        .map_err(|_| LicashError::invalid(format!("{id} is no contract id")))?;
    Ok(out)
}

fn failed(e: anyhow::Error) -> LicashError {
    LicashError::from_any(e, |reason| LicashError::Failed { reason })
}

/// Forced closes.
#[uniffi::export]
impl Wallet {
    /// Force contract `id` (in hex) closed, its hub silent: the notes at
    /// its hub, up to its cap, leave the balance and are claimed on
    /// Bitcoin through `chain`, carried on as far as the chain lets it.
    /// Irrevocable once its request may be in the next block. Refused for
    /// a contract not protecting yet, or any longer.
    pub fn force_close_contract(
        &self,
        chain: Arc<dyn ChainSource>,
        id: String,
    ) -> Result<Recovery, LicashError> {
        let id = contract_id(&id)?;
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let chain = Chain(chain, self.wallet.network());
        let forced = async {
            let rate = rate(&chain).await;
            recovery::force_close(&self.wallet, &chain, self.wallet.path(), &id, rate).await
        };
        let forced = self.operation(forced).map_err(failed)?;
        tracing::warn!(id = %hex::encode(id), stage = forced.stage.as_str(), "contract forced closed");
        Ok(shown(&forced))
    }

    /// The least, in sat, a coin of hers on Bitcoin besides her others
    /// should hold before she forces a contract closed, if she holds none:
    /// should the hub prove falsely, her challenge's fee comes of it, at
    /// the rate of `chain`'s last blocks. Without it, a challenge pays
    /// what her coins hold, and may come too late.
    pub fn challenge_shortfall(
        &self,
        chain: Arc<dyn ChainSource>,
    ) -> Result<Option<u64>, LicashError> {
        let chain = Chain(chain, self.wallet.network());
        let rate = self.runtime.block_on(rate(&chain));
        let short = recovery::challenge_shortfall(&self.wallet, self.wallet.path(), rate)
            .map_err(failed)?;
        Ok(short.map(|a| a.to_sat()))
    }

    /// Close contract `id` (in hex) early with its hub, cooperatively, and
    /// claim what her notes there come to, up to its cap: they leave her
    /// balance and come to the wallet on Bitcoin with her reserve in the
    /// fold the hub signs, the protection over. The fold's txid; its
    /// recovery follows it (`RecoveryStage::Folding`), and files her claim
    /// on Bitcoin should the hub not fold. Refused for a contract not
    /// protecting yet, forced closed, or past its close, when its reserve
    /// comes back anyway; and for one too near its end to leave time for
    /// that, or whose lock owed to her only a forced close claims.
    pub fn close_contract(
        &self,
        chain: Arc<dyn ChainSource>,
        id: String,
    ) -> Result<String, LicashError> {
        let id = contract_id(&id)?;
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let chain = Chain(chain, self.wallet.network());
        let closed = licash_contracts::holder::close(&self.wallet, &chain, self.wallet.path(), &id);
        let txid = self.operation(closed).map_err(failed)?;
        tracing::info!(id = %hex::encode(id), %txid, "contract closed early");
        Ok(txid.to_string())
    }

    /// The contracts forced closed, the oldest first, as last seen.
    pub fn recoveries(&self) -> Result<Vec<Recovery>, LicashError> {
        let all = recovery::recoveries(self.wallet.path()).map_err(failed)?;
        Ok(all.iter().map(shown).collect())
    }

    /// Give up forcing contract `id` closed, its notes back in the
    /// balance: only while `RecoveryStage::Claimed`.
    pub fn give_up_recovery(&self, id: String) -> Result<(), LicashError> {
        let id = contract_id(&id)?;
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        recovery::give_up(&self.wallet, self.wallet.path(), &id).map_err(failed)
    }

    /// Let forcing contract `id` closed pay up to `sats` in all for
    /// publishing its claim, past its reserve, the rest from her coins on
    /// Bitcoin: refused above what the contract holds.
    pub fn allow_publication_fee(&self, id: String, sats: u64) -> Result<(), LicashError> {
        let id = contract_id(&id)?;
        let _contracting = self
            .contracting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        recovery::allow_publication_fee(self.wallet.path(), &id, sats).map_err(failed)?;
        tracing::info!(id = %hex::encode(id), sats, "publication fee allowed");
        Ok(())
    }
}

/// The least a payout for a forced close's fees asks: swap providers pay
/// out no smaller coin by default (`licash-swaps --payout-min`), and what
/// it holds beyond the fees comes back to her as change.
const FEE_PAYOUT_FLOOR: u64 = 10_000;

impl Wallet {
    /// Pay out of her notes, to her own silent payment address, each coin
    /// her forced closes need of hers on Bitcoin to pay their fees
    /// ([`recovery::fee_needs`]): from her richest hub, through the
    /// provider preferred, recorded as awaited before it is made, else not
    /// made. One not paid out is left
    /// to her coins, as are its fees; nothing else held up.
    pub(super) fn fund_recoveries(&self, chain: &Chain) {
        let active = recovery::recoveries(self.wallet.path())
            .is_ok_and(|all| all.iter().any(|r| !r.stage.over()));
        if !active {
            return;
        }
        let needs = async {
            let rate = rate(chain).await;
            recovery::fee_needs(&self.wallet, chain, self.wallet.path(), rate).await
        };
        let needs = match self.runtime.block_on(needs) {
            Ok(needs) => needs,
            Err(e) => {
                tracing::warn!("forced closes' fees not looked at: {e:#}");
                return;
            }
        };
        let to = self.wallet.silent_keys().address().to_string();
        for need in needs {
            let amount = need.amount.to_sat().max(FEE_PAYOUT_FLOOR);
            // Each payout recorded as awaited before it is made: one made
            // is never asked for again.
            let record = |hash: &str| {
                recovery::expect_fee(self.wallet.path(), &need.id, need.purpose, hash).map_err(
                    |e| LicashError::Unavailable {
                        reason: format!("a fee payout not recorded: {e:#}"),
                    },
                )
            };
            let paid = self
                .payout_quote(to.clone(), Some(amount), None)
                .and_then(|quote| self.pay_out_recorded(quote, Some(amount), &record));
            let id = hex::encode(need.id);
            match paid {
                Ok(paying) => {
                    tracing::info!(%id, hash = %paying.id, amount, "notes paid out for a forced close's fees");
                }
                Err(e) => tracing::warn!(%id, amount, "no payout for a forced close's fees: {e}"),
            }
        }
    }

    /// Carry every forced close on as far as `chain` lets it, the wallet
    /// contracting: one that cannot go on holds up nothing else.
    pub(super) fn advance_recoveries(&self, chain: &Chain) {
        let active = recovery::recoveries(self.wallet.path())
            .is_ok_and(|all| all.iter().any(|r| !r.stage.over()));
        if !active {
            return;
        }
        let advanced = async {
            let rate = rate(chain).await;
            recovery::advance(&self.wallet, chain, self.wallet.path(), rate).await
        };
        if let Err(e) = self.runtime.block_on(advanced) {
            tracing::warn!("forced closes not carried on: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app's stages of a forced close the hub answered: its proof
    /// awaited, posted, challenged, paid.
    #[test]
    fn a_disputed_close_shows_its_own_stages() {
        let cases = [
            (Stage::Answered, RecoveryStage::Answered),
            (Stage::Asserted, RecoveryStage::Asserted),
            (Stage::Succeeding, RecoveryStage::Asserted),
            (Stage::Challenging, RecoveryStage::Challenging),
            (Stage::Challenged, RecoveryStage::Challenged),
            (Stage::Paid, RecoveryStage::Paid),
            (Stage::TimedOut, RecoveryStage::TimingOut),
            (Stage::Folding, RecoveryStage::Folding),
        ];
        for (s, shown) in cases {
            assert_eq!(stage(s), shown, "{}", s.as_str());
        }
    }
}
