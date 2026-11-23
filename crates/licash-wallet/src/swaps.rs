//! Swaps of notes at one hub for notes at another, through a swap provider
//! ([`licash_api::swaps`]).
//!
//! The wallet draws a preimage and records the swap with it before it
//! locks the amount and the provider's fee to the provider at hub `from`,
//! under its hash. It then asks the provider for the swap and, once the
//! provider locked the amount to it at hub `to` under the same hash, checks
//! that lock and claims it, revealing the preimage that pays the provider
//! its own lock in turn. If the provider never locks, the wallet's lock is
//! refunded once expired, as [`Wallet::resume`] follows it.

use licash::spend::{lock_hash, ProposalId};
use licash_api::{
    swaps::{self, State as Theirs},
    Code, Info,
};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Row};

use crate::{
    both, hub_url, locks::Pays, now, sql, unavailable, Error, LockState, Transport, Wallet,
};

/// Blocks the provider's lock leaves the wallet to claim it, beyond the
/// provider's margin: the wallet's lock expires no later, so that its notes
/// return soon if the provider never locks.
pub const SWAP_WINDOW: u32 = 24;

/// Blocks a provider's lock leaves at least before it expires, for the
/// wallet to claim it and the provider to follow it: a swap that leaves
/// fewer is refused before the wallet locks anything.
pub const SWAP_ROOM: u32 = 6;

/// The most a swap may cost: refused before the wallet locks anything if
/// its provider asks more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapLimits {
    /// The provider's fee at most, in sat.
    pub fee: u64,
    /// The provider's margin at most at the hub swapped to, in blocks: how
    /// much longer than [`SWAP_WINDOW`] the wallet's notes stay locked if it
    /// never locks.
    pub margin: u32,
}

impl SwapLimits {
    /// For a swap of `amount`: a fee of 1% and 100 sat, a margin of 200
    /// blocks. That is what a provider other than the hub swapped to needs
    /// there, at a hub of the usual response window of 144 blocks: its lock
    /// outlasts that window, and the refund request that forces the
    /// preimage out of the hub.
    pub fn usual(amount: u64) -> Self {
        let fee = licash_api::Fee {
            base: 100,
            ppm: 10_000,
        };
        Self {
            fee: fee.due(amount),
            margin: 200,
        }
    }
}

/// What a provider asks for a swap ([`Wallet::swap_quote`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuote {
    /// What it said of itself.
    pub info: swaps::Info,
    /// What it swaps: at least what was asked.
    pub amount: u64,
    /// Its fee on the amount, which the wallet's lock pays on top.
    pub fee: u64,
    /// Blocks its lock at the hub swapped to expires before the wallet's,
    /// at least.
    pub margin: u32,
}

/// A swap of notes at hub `from` for notes at hub `to`, and where it
/// stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Swap {
    /// The hash of the wallet's preimage, in hex: the swap's id here.
    pub hash: String,
    pub provider: String,
    pub from: String,
    pub to: String,
    /// What the wallet gets at `to`.
    pub amount: u64,
    /// The provider's fee, which the wallet's lock pays on top.
    pub fee: u64,
    /// The wallet's lock to the provider at `from`, once made.
    pub lock: Option<String>,
    /// The provider's lock to the wallet at `to`, once made.
    pub theirs: Option<String>,
    pub state: SwapState,
    pub created_at: i64,
}

/// Where a swap the wallet asked for stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwapState {
    /// Under way.
    Open,
    /// The provider's lock claimed: the wallet holds its notes.
    Done,
    /// Given up, and why: nothing was claimed, and the wallet's lock, if
    /// made, is refunded once expired.
    Failed(String),
}

/// A swap as recorded, to take it on.
struct Record {
    provider: String,
    preimage: [u8; 32],
    from: (i64, String),
    to: String,
    amount: u64,
    theirs: Option<[u8; 32]>,
    open: bool,
}

/// Swaps.
impl<T: Transport> Wallet<T> {
    /// Swap notes at the hub at `from` for `amount` at the hub at `to`,
    /// both added, through the provider at `provider`: lock the amount and
    /// its fee to the provider at `from`, then claim the provider's lock at
    /// `to`, unless the provider asks more than `limits`. Where the swap
    /// stands; [`Wallet::follow_swap`] takes it on.
    pub async fn swap(
        &self,
        provider: &str,
        from: &str,
        to: &str,
        amount: u64,
        limits: SwapLimits,
    ) -> Result<Swap, Error> {
        self.swap_within(provider, from, to, amount, limits, None)
            .await
    }

    /// [`Wallet::swap`], refused as [`Error::FeeRose`], nothing locked, if
    /// the provider's fee and the hub's at `from` on the lock, as it signs
    /// it, come to more than `costs`: what was quoted in all.
    pub async fn swap_within(
        &self,
        provider: &str,
        from: &str,
        to: &str,
        amount: u64,
        limits: SwapLimits,
        costs: Option<u64>,
    ) -> Result<Swap, Error> {
        // Boxed: a swap's future is deep, and nested in its callers'.
        Box::pin(self.swapping(provider, from, to, amount, limits, costs)).await
    }

    async fn swapping(
        &self,
        provider: &str,
        from: &str,
        to: &str,
        amount: u64,
        limits: SwapLimits,
        costs: Option<u64>,
    ) -> Result<Swap, Error> {
        let provider = hub_url(provider)?;
        let (from, to) = (hub_url(from)?, hub_url(to)?);
        if amount == 0 {
            return Err(Error::Invalid("nothing to swap".into()));
        }
        let (from_hub, to_hub) = (self.hub(&from)?.0, self.hub(&to)?.0);
        if from_hub == to_hub {
            return Err(Error::Invalid("a swap is between two hubs".into()));
        }
        // Asked at once, each a round trip over Tor; failed as when asked
        // in turn, the first's failure first.
        let hubs = both(self.refresh(&from), self.refresh(&to));
        let ((from_said, to_said), offer) =
            both(hubs, self.get(&provider, swaps::SWAPS_INFO)).await;
        let ((_, from_info), (_, to_info)) = (from_said?, to_said?);
        let offer: swaps::Info = offer?;
        let Terms { fee, expiry, .. } = terms(
            &provider,
            &offer,
            (&from, &from_info),
            (&to, &to_info),
            amount,
            limits,
        )?;
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let hash = lock_hash(&preimage);
        let insert = |tx: &rusqlite::Transaction<'_>| -> Result<(), Error> {
            tx.execute(
                "INSERT INTO swaps
                    (hash, provider, preimage, from_hub, to_hub, amount, fee, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    hash,
                    provider,
                    preimage,
                    from_hub,
                    to_hub,
                    sql(amount)?,
                    sql(fee)?,
                    now()
                ],
            )?;
            Ok(())
        };
        let total = amount.saturating_add(fee);
        let at = (from.as_str(), from_hub, &from_info);
        // Its lock prepared first, then the swap, its lock and its notes
        // taken at once: no follower ever sees the swap without its lock.
        let admitted = match self
            .prepare_lock(at, &offer.address, total, hash, Some(expiry), Pays::Nothing)
            .await
        {
            // Its fee as the hub's lock signs it, not as quoted.
            Ok(prepared) if costs.is_some_and(|most| fee.saturating_add(prepared.fee) > most) => {
                let (agreed, asked) = (costs.unwrap_or_default(), fee.saturating_add(prepared.fee));
                Err(Error::FeeRose {
                    who: provider.clone(),
                    agreed,
                    asked,
                    reason: format!(
                        "provider {provider} and hub {from} ask {asked} sat to swap {amount}, more than {agreed}"
                    ),
                })
            }
            Ok(prepared) => self
                .store
                .write(|tx| {
                    insert(tx)?;
                    prepared.record(tx)
                })
                .map(|()| prepared),
            Err(e) => Err(e),
        };
        let prepared = match admitted {
            Ok(prepared) => prepared,
            Err(e) => {
                self.store.write(insert)?;
                self.fail_swap(&hash, &format!("its lock was not made: {e}"))?;
                return Err(e);
            }
        };
        tracing::info!(hash = %hex::encode(hash), %provider, %from, %to, amount, fee, "swapping");
        match self.send_lock(&from, &prepared).await {
            Ok(_) | Err(Error::Pending { .. }) => {}
            Err(e) => {
                self.fail_swap(&hash, &format!("its lock was not made: {e}"))?;
                return Err(e);
            }
        }
        self.advance_swap(&hash).await
    }

    /// Take the swap of `hash` on: have the provider lock to the wallet,
    /// then claim that lock. Where it stands.
    pub async fn follow_swap(&self, hash: &str) -> Result<Swap, Error> {
        let mut bytes = [0; 32];
        hex::decode_to_slice(hash, &mut bytes)
            .map_err(|_| Error::Invalid(format!("not a swap's hash: {hash}")))?;
        self.advance_swap(&bytes).await
    }

    pub(crate) async fn advance_swap(&self, hash: &[u8; 32]) -> Result<Swap, Error> {
        match self.advance_swap_from(hash).await {
            Ok(()) => self.swap_record(hash),
            Err(e @ (Error::Pending { .. } | Error::UnknownPayment(_))) => Err(e),
            Err(e) => Err(Error::Pending {
                id: hex::encode(hash),
                reason: e.to_string(),
            }),
        }
    }

    async fn advance_swap_from(&self, hash: &[u8; 32]) -> Result<(), Error> {
        let record = self.swap_row(hash)?;
        if !record.open {
            return Ok(());
        }
        let from_hub = record.from.0;
        let lock: Option<[u8; 32]> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT id FROM locks WHERE hash = ?1 AND hub = ?2
                 ORDER BY created_at DESC, rowid DESC LIMIT 1",
                params![hash, from_hub],
                |r| r.get(0),
            )
            .optional()?)
        })?;
        // Recorded before its lock, which was never made.
        let Some(lock) = lock else {
            return self.fail_swap(hash, "its lock was not made");
        };
        let id = ProposalId::from_bytes(lock);
        let ours = match self.advance_lock(&id, None).await {
            Ok(ours) => ours,
            Err(Error::Refused { problem, .. }) => {
                return self.fail_swap(hash, &format!("its hub refused its lock: {problem}"));
            }
            Err(Error::Abandoned { reason, .. }) => {
                return self.fail_swap(hash, &format!("its lock was given up: {reason}"));
            }
            Err(e) => return Err(e),
        };
        if ours.state == LockState::Requested {
            return Err(Error::Pending {
                id: hex::encode(hash),
                reason: "its lock is not certified yet".into(),
            });
        }
        let theirs = match record.theirs {
            Some(theirs) => theirs,
            None => {
                if ours.state == LockState::Refunded {
                    return self
                        .fail_swap(hash, "the provider never locked: its lock was refunded");
                }
                match self.ask_swap(hash, &record, &id).await? {
                    Some(theirs) => theirs,
                    None => return Ok(()),
                }
            }
        };
        let theirs = hex::encode(theirs);
        // The chain as the hub of the wallet's lock says it is, too: a
        // provider's hub saying it is behind, to have the preimage of an
        // expired lock revealed, is believed only if both say so. As last
        // said, should it not answer now.
        let from = &record.from.1;
        let info = match self.refresh(from).await {
            Ok((_, info)) => info,
            Err(e) => {
                tracing::warn!(hub = %from, "the chain as the hub says it is, last said: {e}");
                self.hub(from)?.1
            }
        };
        let seen = info.locks.map_or(0, |l| l.height);
        match (self.claim_seen(&record.to, &theirs, &record.preimage, seen)).await {
            Ok(_) | Err(Error::AlreadyReceived) => {}
            Err(e @ (Error::Invalid(_) | Error::PaysNothing)) => {
                return self.fail_swap(hash, &format!("the provider's lock was not claimed: {e}"));
            }
            Err(e) => return Err(e),
        }
        tracing::info!(hash = %hex::encode(hash), "swapped");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE swaps SET done_at = ?2 WHERE hash = ?1 AND done_at IS NULL",
                params![hash, now()],
            )?;
            Ok(())
        })
    }

    /// Ask the provider for the swap of the wallet's lock `id`, and check the
    /// lock it made: its id once it pays the swap, `None` once the swap
    /// failed.
    async fn ask_swap(
        &self,
        hash: &[u8; 32],
        record: &Record,
        id: &ProposalId,
    ) -> Result<Option<[u8; 32]>, Error> {
        let provider = &record.provider;
        // Only who the hubs are: as kept, not asked again, a round trip
        // each over Tor.
        let (_, from_info) = self.hub(&record.from.1)?;
        let (_, to_info) = self.hub(&record.to)?;
        let request = swaps::Request::new(
            &from_info.address,
            id,
            &to_info.address,
            &self.address(),
            record.amount,
        );
        let swap: swaps::Swap = match self.post(provider, swaps::SWAPS, &request).await {
            Ok(swap) => swap,
            // Refused before the provider took it.
            Err(Error::Refused { problem, .. }) => {
                self.fail_swap(hash, &format!("the provider declined: {problem}"))?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if swap.id.0 != id.as_bytes() {
            return Err(unavailable(provider, "it answered with another swap"));
        }
        match swap.state {
            Theirs::Accepted => {
                return Err(Error::Pending {
                    id: hex::encode(hash),
                    reason: "the provider is locking".into(),
                });
            }
            // A later protocol's state: nothing final, asked again later.
            Theirs::Unknown => {
                return Err(Error::Pending {
                    id: hex::encode(hash),
                    reason: "the provider reports a state this wallet does not know".into(),
                });
            }
            Theirs::Failed | Theirs::Refunded => {
                let reason = swap.reason.as_deref().unwrap_or("no reason given");
                self.fail_swap(hash, &format!("the provider gave the swap up: {reason}"))?;
                return Ok(None);
            }
            Theirs::Locked | Theirs::Paid | Theirs::Done => {}
        }
        let theirs = swap
            .lock()
            .map_err(|p| unavailable(provider, p))?
            .ok_or_else(|| unavailable(provider, "a swap locked without its lock"))?;
        let key = hex::encode(theirs.as_bytes());
        let incoming = match self.incoming(&record.to, &key).await {
            Ok(incoming) => incoming,
            Err(Error::PaysNothing) => {
                self.fail_swap(hash, "the provider's lock pays this wallet nothing")?;
                return Ok(None);
            }
            Err(Error::Refused { problem, .. }) if problem.code == Code::UnknownLock => {
                self.fail_swap(hash, "the provider names a lock its hub does not hold")?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if incoming.hash != *hash {
            self.fail_swap(hash, "the provider's lock is under another hash")?;
            return Ok(None);
        }
        if incoming.amount < record.amount {
            let reason = format!(
                "the provider's lock pays {} of {}",
                incoming.amount, record.amount
            );
            self.fail_swap(hash, &reason)?;
            return Ok(None);
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE swaps SET theirs = ?2 WHERE hash = ?1 AND theirs IS NULL",
                params![hash, theirs.as_bytes()],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), lock = %key, "the provider locked");
        Ok(Some(*theirs.as_bytes()))
    }

    fn fail_swap(&self, hash: &[u8; 32], reason: &str) -> Result<(), Error> {
        tracing::warn!(hash = %hex::encode(hash), reason, "swap failed");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE swaps SET failed = ?2
                 WHERE hash = ?1 AND done_at IS NULL AND failed IS NULL",
                params![hash, reason],
            )?;
            Ok(())
        })
    }

    fn swap_row(&self, hash: &[u8; 32]) -> Result<Record, Error> {
        let record = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT s.provider, s.preimage, s.from_hub, f.url, t.url, s.amount, s.theirs,
                    s.done_at IS NULL AND s.failed IS NULL
                 FROM swaps s JOIN reach f ON f.hub = s.from_hub JOIN reach t ON t.hub = s.to_hub
                 WHERE s.hash = ?1",
                [hash],
                |r| {
                    Ok(Record {
                        provider: r.get(0)?,
                        preimage: r.get(1)?,
                        from: (r.get(2)?, r.get(3)?),
                        to: r.get(4)?,
                        amount: r.get::<_, i64>(5)? as u64,
                        theirs: r.get(6)?,
                        open: r.get(7)?,
                    })
                },
            )
            .optional()?)
        })?;
        record.ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))
    }

    /// What the provider at `provider` asks to swap at least `amount`
    /// from hub `from` to hub `to`, both added, as they last said of
    /// themselves: `amount`, or the least it swaps if more. Refused as
    /// [`Error::Invalid`] if it swaps not between them, or not that much
    /// now, or asks more than `limits`. Nothing is recorded or locked:
    /// [`Wallet::swap`] checks it again with what the hubs say then.
    pub async fn swap_quote(
        &self,
        provider: &str,
        from: &str,
        to: &str,
        amount: u64,
        limits: SwapLimits,
    ) -> Result<SwapQuote, Error> {
        let provider = hub_url(provider)?;
        let (from, to) = (hub_url(from)?, hub_url(to)?);
        if amount == 0 {
            return Err(Error::Invalid("nothing to swap".into()));
        }
        let ((from_hub, from_info), (to_hub, to_info)) = (self.hub(&from)?, self.hub(&to)?);
        if from_hub == to_hub {
            return Err(Error::Invalid("a swap is between two hubs".into()));
        }
        let info: swaps::Info = self.get(&provider, swaps::SWAPS_INFO).await?;
        let amount = amount.max(info.min);
        let from_at = (from.as_str(), &from_info);
        let Terms { fee, margin, .. } =
            terms(&provider, &info, from_at, (&to, &to_info), amount, limits)?;
        Ok(SwapQuote {
            info,
            amount,
            fee,
            margin,
        })
    }

    /// What the swap provider at `provider` says of itself and of the swaps
    /// and payouts it makes: nothing kept.
    pub async fn provider_info(&self, provider: &str) -> Result<swaps::Info, Error> {
        self.get(&hub_url(provider)?, swaps::SWAPS_INFO).await
    }

    /// Ask the hub at `url`, added, what it says of itself again, and keep
    /// it. [`Wallet::swap_quote`] judges a lock by the height its hubs last
    /// said they followed, which on quick blocks is soon far behind: a swap
    /// that would go through is refused until they are asked again.
    pub async fn refresh_hub(&self, url: &str) -> Result<(), Error> {
        let url = hub_url(url)?;
        self.hub(&url)?;
        self.refresh(&url).await.map(|_| ())
    }

    /// The swaps made, newest first.
    pub fn swaps(&self) -> Result<Vec<Swap>, Error> {
        self.store.read(|c| {
            let mut stmt =
                c.prepare(&format!("{SWAPS} ORDER BY s.created_at DESC, s.rowid DESC"))?;
            let rows = stmt.query_map([], swap_of)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    fn swap_record(&self, hash: &[u8; 32]) -> Result<Swap, Error> {
        self.store.read(|c| {
            c.query_row(&format!("{SWAPS} WHERE s.hash = ?1"), [hash], swap_of)
                .optional()?
                .ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))
        })
    }

    /// The swaps under way, oldest first.
    pub(crate) fn open_swaps(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash FROM swaps WHERE done_at IS NULL AND failed IS NULL
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}

/// What a swap costs on the terms its provider offers.
struct Terms {
    /// The provider's fee.
    fee: u64,
    /// Blocks its lock at `to` expires before the wallet's, at least.
    margin: u32,
    /// The expiry of the wallet's lock at `from`.
    expiry: u32,
}

/// The terms of a swap of `amount` from hub `from` to hub `to` on what the
/// provider offers, unless it swaps not between them, not that amount now,
/// or more than `limits` allow, or hub `from` admits no lock that expires
/// late enough for the provider to lock its margin earlier.
fn terms(
    provider: &str,
    offer: &swaps::Info,
    (from, from_info): (&str, &Info),
    (to, to_info): (&str, &Info),
    amount: u64,
    limits: SwapLimits,
) -> Result<Terms, Error> {
    if amount == 0 {
        return Err(Error::Invalid("nothing to swap".into()));
    }
    let (Some(_), Some(at_to)) = (offer.hub(&from_info.address), offer.hub(&to_info.address))
    else {
        return Err(Error::Invalid(format!(
            "provider {provider} swaps not between {from} and {to}"
        )));
    };
    let most = offer.max.min(at_to.max);
    if amount < offer.min || amount > most {
        return Err(Error::Invalid(format!(
            "provider {provider} swaps {} to {most} to {to} now",
            offer.min
        )));
    }
    // A lock to a hub's own address is the hub's to settle.
    if offer.address == from_info.address || offer.address == to_info.address {
        return Err(Error::Invalid(format!(
            "provider {provider} names a hub's address as its own"
        )));
    }
    let fee = offer.fee.due(amount);
    if fee > limits.fee {
        return Err(Error::FeeRose {
            who: provider.into(),
            agreed: limits.fee,
            asked: fee,
            reason: format!(
                "provider {provider} asks {fee} sat to swap {amount}, more than {}",
                limits.fee
            ),
        });
    }
    let margin = offer.margin_at(at_to);
    if margin > limits.margin {
        return Err(Error::Invalid(format!(
            "provider {provider} keeps a swap's notes locked {margin} blocks longer, more than {}",
            limits.margin
        )));
    }
    let no_chain =
        |hub: &str| Error::Invalid(format!("hub {hub} follows no chain: it takes no locks"));
    let at_from = from_info.locks.as_ref().ok_or_else(|| no_chain(from))?;
    let height = to_info.locks.as_ref().ok_or_else(|| no_chain(to))?.height;
    let latest = at_from
        .latest_expiry(at_from.min_depth.max(1))
        .map_err(|p| unavailable(from, p))?;
    let expiry = latest.min(
        at_from
            .height
            .saturating_add(margin)
            .saturating_add(SWAP_WINDOW),
    );
    // The provider's lock would expire too soon to claim, or before it is
    // made: it declines once the wallet's lock is made, which then stays
    // locked until it expires.
    let room = height.max(at_from.height).saturating_add(SWAP_ROOM);
    if expiry.saturating_sub(margin) < room {
        return Err(Error::Invalid(format!(
            "provider {provider} locks at {to} {margin} blocks before the wallet's lock \
             expires, and {from} admits none expiring after {latest}"
        )));
    }
    Ok(Terms {
        fee,
        margin,
        expiry,
    })
}

const SWAPS: &str = "SELECT s.hash, s.provider, f.url, t.url, s.amount, s.fee,
    (SELECT l.id FROM locks l WHERE l.hash = s.hash AND l.hub = s.from_hub
        ORDER BY l.created_at DESC, l.rowid DESC LIMIT 1),
    s.theirs, s.done_at IS NOT NULL, s.failed, s.created_at
    FROM swaps s JOIN reach f ON f.hub = s.from_hub JOIN reach t ON t.hub = s.to_hub";

fn swap_of(r: &Row<'_>) -> rusqlite::Result<Swap> {
    let state = match (r.get::<_, bool>(8)?, r.get::<_, Option<String>>(9)?) {
        (_, Some(reason)) => SwapState::Failed(reason),
        (true, None) => SwapState::Done,
        (false, None) => SwapState::Open,
    };
    Ok(Swap {
        hash: hex::encode(r.get::<_, [u8; 32]>(0)?),
        provider: r.get(1)?,
        from: r.get(2)?,
        to: r.get(3)?,
        amount: r.get::<_, i64>(4)? as u64,
        fee: r.get::<_, i64>(5)? as u64,
        lock: r.get::<_, Option<[u8; 32]>>(6)?.map(hex::encode),
        theirs: r.get::<_, Option<[u8; 32]>>(7)?.map(hex::encode),
        state,
        created_at: r.get(10)?,
    })
}
