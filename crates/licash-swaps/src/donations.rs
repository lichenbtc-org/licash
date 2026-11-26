//! Donations taken over Lightning for wallets that are not there: a payer
//! pays a held invoice of the provider's node, and the provider pays the
//! amount, its fee taken, to the wallet of a Licash code in notes, kept at
//! the code's hub for the payee to collect, or mailed. The payee needs to
//! be neither online nor known to the provider: the code is all it takes
//! ([`Provider::donate`], as LNURL-pay asks for it).
//!
//! The provider chooses each invoice's preimage and settles only once its
//! payment of the payee is released: until then the payer's HTLC is
//! canceled whenever the payment cannot be made. Each payment is made
//! under the invoice's hash as its key (`licash_wallet::Wallet::
//! pay_code_keyed`), once, ever: what the wallet recorded under it alone
//! tells what to do with the HTLC, whatever the provider was doing when it
//! stopped. Its point of no return is the payment's release by its hub:
//! - not made, or given up: canceled;
//! - offered, not signed, by the deadline: given up then canceled;
//! - signed, not released, by the deadline: settled all the same, the
//!   donation `owed` until the release, which the provider still follows;
//! - released: settled.
//!
//! The deadline leaves [`SETTLE_MARGIN`] blocks before the HTLC expires, as
//! a hub's gateway does for its receipts: a node's room to settle before
//! its channel is closed on Bitcoin, and the provider's downtime.
//!
//! The hashes of donations are reserved as swaps' are
//! ([`crate::holds_hash`]): a gateway sharing the provider's node never
//! takes a receipt under one, whose notes settling it would pay.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, PoisonError},
};

use bitcoin::hashes::{sha256, Hash};
use licash::spend::lock_hash;
use licash_api::{Fee, Problem};
use licash_lightning::{Description, HeldState, Node};
use licash_wallet::{LicashCode, Sent, State, Transport};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension};

use crate::{declined, now, unavailable, Error, Provider};

/// The blocks the last HTLC paying a donation expires after it arrives,
/// at least.
pub const INVOICE_CLTV: u32 = 40;

/// Seconds a donation's invoice is payable for.
pub const INVOICE_EXPIRY: u64 = 600;

/// Blocks before a donation's HTLC expires by which it is settled or
/// canceled: a gateway's hold delta and downtime.
pub const SETTLE_MARGIN: u32 = 18;

/// Blocks before the deadline the provider needs at least to start paying
/// the payee.
pub const START_ROOM: u32 = 6;

/// Seconds after which a donation recorded but never made an invoice of is
/// given up: the payer never had it.
const UNMADE_AFTER: i64 = 60;

/// What a donation says of itself, as LNURL-pay metadata: the invoices
/// commit to its hash.
pub const METADATA: &str = r#"[["text/plain","A donation to a Licash wallet"]]"#;

/// What the provider takes donations on, as its operator set it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DonationTerms {
    /// Its fee on each donation, taken from it: the hub's fee on paying
    /// the payee comes out of it.
    pub fee: Fee,
    /// The least and the most donated at once, in satoshis.
    pub min: u64,
    pub max: u64,
    /// The most donations whose invoices are open at once.
    pub max_open: u64,
}

impl Default for DonationTerms {
    fn default() -> Self {
        Self {
            fee: Fee {
                base: 2,
                ppm: 5_000,
            },
            min: 100,
            max: 1_000_000,
            max_open: 100,
        }
    }
}

/// Where a donation stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DonationState {
    /// Its invoice not paid yet, or the payee not paid yet.
    Open,
    /// Settled before the payee's payment was released, which is
    /// followed still.
    Owed,
    Settled,
    Canceled,
    /// Paid and not settled, or settled and the payee's payment given up:
    /// the operator was alerted.
    Lost,
}

impl DonationState {
    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Owed => "owed",
            Self::Settled => "settled",
            Self::Canceled => "canceled",
            Self::Lost => "lost",
        }
    }

    fn of(name: &str) -> Self {
        match name {
            "owed" => Self::Owed,
            "settled" => Self::Settled,
            "canceled" => Self::Canceled,
            "lost" => Self::Lost,
            _ => Self::Open,
        }
    }
}

/// A donation as the provider recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Donation {
    pub hash: [u8; 32],
    /// What its invoice asks, in satoshis.
    pub sat: u64,
    /// What it pays the payee: `sat`, the provider's fee taken.
    pub amount: u64,
    /// The payee's code.
    pub code: String,
    /// Its invoice, once made.
    pub request: Option<String>,
    pub state: DonationState,
    pub reason: Option<String>,
    pub created_at: i64,
}

/// What a provider takes donations on, and through which node.
pub(crate) struct Receiver {
    node: Arc<dyn Node>,
    terms: DonationTerms,
    /// The provider's public URL, where payers reach it.
    url: String,
    /// What the operator was alerted of, once each.
    alerted: Mutex<HashSet<String>>,
}

impl Receiver {
    fn first(&self, what: String) -> bool {
        self.alerted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(what)
    }
}

/// Donations taken.
impl<T: Transport> Provider<T> {
    /// Take donations on `terms`, through `node`: the provider takes none
    /// otherwise.
    pub fn take_donations(
        mut self,
        node: Arc<dyn Node>,
        terms: DonationTerms,
        url: &str,
    ) -> Result<Self, Error> {
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(Error::Setup(format!(
                "donations at {url}: an http(s):// URL, payers reach the provider at"
            )));
        }
        if terms.min == 0 || terms.min > terms.max || terms.max_open == 0 {
            return Err(Error::Setup(
                "donations of at least 1 sat, at most the largest, and some open at once".into(),
            ));
        }
        if terms.fee.due(terms.min) >= terms.min {
            return Err(Error::Setup(format!(
                "the donation fee takes all of the least donation of {} sat",
                terms.min
            )));
        }
        self.donations = Some(Receiver {
            node,
            terms,
            url: url.trim_end_matches('/').to_owned(),
            alerted: Mutex::default(),
        });
        Ok(self)
    }

    /// What it takes donations on, if it does.
    pub fn donation_terms(&self) -> Option<&DonationTerms> {
        self.donations.as_ref().map(|r| &r.terms)
    }

    /// The donations it takes, as its info tells wallets: at its public
    /// URL, on its terms. None if it takes none.
    pub fn donations(&self) -> Option<licash_api::swaps::Donations> {
        self.donations
            .as_ref()
            .map(|r| licash_api::swaps::Donations {
                url: r.url.clone(),
                fee: r.terms.fee,
                min: r.terms.min,
                max: r.terms.max,
            })
    }

    /// What a donation to the wallet of `code` may be, in satoshis: the
    /// provider's terms, up to the most it holds at a hub the code names.
    pub fn donation_range(&self, code: &str) -> Result<(u64, u64), Problem> {
        let receiver = self.receiver()?;
        let code = self.payee(code)?;
        let held = self.wallet.balance().map_err(unavailable)?;
        let hubs = self.wallet.hubs().map_err(unavailable)?;
        let most = hubs
            .iter()
            .filter(|(_, info)| code.hubs.contains(&licash_wallet::HubId::of(&info.address)))
            .filter_map(|(url, _)| held.iter().find(|b| &b.hub == url))
            .map(|b| b.available)
            .max()
            .unwrap_or(0);
        let max = receiver.terms.max.min(most);
        if max < receiver.terms.min {
            return Err(declined(
                "the provider takes no donations to this code now: it holds too little at its hubs",
            ));
        }
        Ok((receiver.terms.min, max))
    }

    /// A donation of `msat` to the wallet of `code`: the invoice the payer
    /// pays, recorded before the node makes it, committing to [`METADATA`].
    /// Unavailable past `max_open` open, or past [`crate::PER_SOURCE`] asked
    /// and not paid from `source`, if known.
    pub async fn donate(
        &self,
        code: &str,
        msat: u64,
        source: Option<&[u8]>,
    ) -> Result<String, Problem> {
        let receiver = self.receiver()?;
        if !msat.is_multiple_of(1000) {
            return Err(Problem::invalid("donations are of whole satoshis"));
        }
        let sat = msat / 1000;
        let (min, max) = self.donation_range(code)?;
        if !(min..=max).contains(&sat) {
            return Err(Problem::invalid(format!(
                "a donation of {sat} sat: from {min} to {max} sat"
            )));
        }
        let payee = self.payee(code)?;
        let fee = receiver.terms.fee.due(sat);
        let amount = sat.saturating_sub(fee);
        self.payable(&payee, amount, fee)?;
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let hash = lock_hash(&preimage);
        let at = now();
        let max_open = i64::try_from(receiver.terms.max_open).unwrap_or(i64::MAX);
        self.store
            .write(|tx| {
                let open: i64 = tx.query_row(
                    "SELECT count(*) FROM provider_donations WHERE state = 'open'",
                    [],
                    |r| r.get(0),
                )?;
                if open >= max_open {
                    return Ok(Some("too many donations under way: try again later"));
                }
                if let Some(source) = source {
                    let unpaid: u32 = tx.query_row(
                        "SELECT count(*) FROM provider_donations
                         WHERE state = 'open' AND source = ?1",
                        [source],
                        |r| r.get(0),
                    )?;
                    if unpaid >= crate::PER_SOURCE {
                        return Ok(Some(
                            "too many donations asked from this source and not paid: \
                             try again later",
                        ));
                    }
                }
                tx.execute(
                    "INSERT INTO provider_donations
                        (hash, preimage, code, sat, amount, state, source, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'open', ?6, ?7, ?7)",
                    params![hash, preimage, code, sql(sat)?, sql(amount)?, source, at],
                )?;
                Ok(None)
            })
            .map_err(unavailable)?
            .map_or(Ok(()), |busy| Err(unavailable(busy)))?;
        let description = sha256::Hash::hash(METADATA.as_bytes()).to_byte_array();
        let made = receiver
            .node
            .hold(
                hash,
                msat,
                INVOICE_CLTV,
                INVOICE_EXPIRY,
                Some(Description::Hash(description)),
            )
            .await;
        let request = match made {
            Ok(request) => request,
            Err(e) => {
                tracing::warn!(hash = %hex::encode(hash), error = %e, "no invoice for a donation");
                self.finish(&hash, DonationState::Canceled, "the node made no invoice")
                    .map_err(unavailable)?;
                return Err(unavailable(format!("the Lightning node: {e}")));
            }
        };
        self.store
            .write(|tx| {
                tx.execute(
                    "UPDATE provider_donations SET request = ?2, updated_at = ?3 WHERE hash = ?1",
                    params![hash, request, now()],
                )?;
                Ok(())
            })
            .map_err(unavailable)?;
        tracing::info!(hash = %hex::encode(hash), sat, amount, "donation invoice made");
        Ok(request)
    }

    /// Donations under way: their invoices open or held, or their payees'
    /// payments not released yet. Each needs the node, and the provider
    /// following it.
    pub fn open_donations(&self) -> Result<u64, Error> {
        self.store.read(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM provider_donations WHERE state IN ('open', 'owed')",
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    /// The donation under `hash`, if one is.
    pub fn donation(&self, hash: &[u8; 32]) -> Result<Option<Donation>, Error> {
        self.store.read(|c| {
            Ok(c.query_row(
                "SELECT hash, sat, amount, code, request, state, reason, created_at
                 FROM provider_donations WHERE hash = ?1",
                [hash],
                |r| {
                    Ok(Donation {
                        hash: r.get(0)?,
                        sat: r.get::<_, i64>(1)? as u64,
                        amount: r.get::<_, i64>(2)? as u64,
                        code: r.get(3)?,
                        request: r.get(4)?,
                        state: DonationState::of(&r.get::<_, String>(5)?),
                        reason: r.get(6)?,
                        created_at: r.get(7)?,
                    })
                },
            )
            .optional()?)
        })
    }

    /// Take every donation under way on, as the provider's node and wallet
    /// know it. The donations that could not move now, by hash and why;
    /// `node` if the node did not answer.
    pub async fn follow_donations(&self) -> Result<Vec<(String, String)>, Error> {
        let Some(receiver) = &self.donations else {
            return Ok(Vec::new());
        };
        let open: Vec<([u8; 32], String)> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash, state FROM provider_donations WHERE state IN ('open', 'owed')
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut pending = Vec::new();
        if open.is_empty() {
            return Ok(pending);
        }
        let tip = match receiver.node.info().await {
            Ok(info) => Some(info.height),
            Err(e) => {
                tracing::warn!(error = %e, "the Lightning node does not answer");
                pending.push(("node".to_owned(), e));
                None
            }
        };
        for (hash, state) in open {
            let followed = match (DonationState::of(&state), tip) {
                (DonationState::Owed, _) => self.follow_owed(receiver, &hash),
                (_, Some(tip)) => self.follow_donation(receiver, &hash, tip).await,
                (_, None) => Ok(()),
            };
            if let Err(e) = followed {
                tracing::warn!(hash = %hex::encode(hash), "donation pending: {e}");
                pending.push((hex::encode(hash), e.to_string()));
            }
        }
        Ok(pending)
    }

    /// A donation settled before its payee's payment was released: done
    /// once it is, lost if it is given up.
    fn follow_owed(&self, receiver: &Receiver, hash: &[u8; 32]) -> Result<(), Error> {
        match self.wallet.sent_by_key(hash)?.map(|s| s.state) {
            Some(State::Done) => self.finish(hash, DonationState::Settled, "paid late"),
            Some(State::Abandoned(why)) => {
                self.lost(receiver, hash, &format!("its payment was given up: {why}"))
            }
            _ => Ok(()),
        }
    }

    /// Act on the open donation `hash` at height `tip` of the node.
    async fn follow_donation(
        &self,
        receiver: &Receiver,
        hash: &[u8; 32],
        tip: u32,
    ) -> Result<(), Error> {
        let Some(donation) = self.donation(hash)? else {
            return Ok(());
        };
        let sent = self.wallet.sent_by_key(hash)?;
        let held = receiver
            .node
            .invoice(*hash)
            .await
            .map_err(Error::Lightning)?;
        let age = now() - donation.created_at;
        let Some(held) = held else {
            return match (&donation.request, &sent) {
                (None, None) if age > UNMADE_AFTER => {
                    self.finish(hash, DonationState::Canceled, "no invoice made")
                }
                (Some(_), None) => {
                    self.finish(hash, DonationState::Canceled, "unknown to the node")
                }
                (Some(_), Some(_)) => {
                    let message = format!(
                        "Donation {} was paid on, but the Lightning node knows no invoice of it: \
                         resolve it by hand.",
                        hex::encode(hash)
                    );
                    self.alert_donation(
                        receiver,
                        format!("unknown {}", hex::encode(hash)),
                        &message,
                    )
                }
                _ => Ok(()),
            };
        };
        match held.state {
            HeldState::Open => {
                let unmade = donation.request.is_none() && age > UNMADE_AFTER;
                let expired =
                    age > i64::try_from(INVOICE_EXPIRY).unwrap_or(i64::MAX) + UNMADE_AFTER;
                if unmade || expired {
                    self.cancel(receiver, hash, "not paid in time").await?;
                }
                Ok(())
            }
            HeldState::Accepted => {
                let settle_by = held.min_expiry.unwrap_or(0).saturating_sub(SETTLE_MARGIN);
                self.accepted(receiver, &donation, sent, tip, settle_by)
                    .await
            }
            HeldState::Settled => match sent.map(|s| s.state) {
                Some(State::Done) => self.finish(hash, DonationState::Settled, "paid"),
                _ => self.finish(hash, DonationState::Owed, "settled before its payment"),
            },
            HeldState::Canceled => match sent.map(|s| s.state) {
                None | Some(State::Abandoned(_)) => {
                    self.finish(hash, DonationState::Canceled, "canceled")
                }
                Some(_) => self.lost(receiver, hash, "its invoice was canceled after paying it"),
            },
        }
    }

    /// The donation's HTLCs held, to be settled by `settle_by`: pay its
    /// payee, then settle; or cancel while nothing was paid.
    async fn accepted(
        &self,
        receiver: &Receiver,
        donation: &Donation,
        sent: Option<Sent>,
        tip: u32,
        settle_by: u32,
    ) -> Result<(), Error> {
        let hash = &donation.hash;
        let late = tip >= settle_by;
        let Some(sent) = sent else {
            if tip.saturating_add(START_ROOM) > settle_by {
                return self.cancel(receiver, hash, "too late to pay").await;
            }
            let payee = self.payee(&donation.code).map_err(problem)?;
            let fee = donation.sat - donation.amount;
            let url = match self.payable(&payee, donation.amount, fee) {
                Ok(url) => url,
                Err(why) => return self.cancel(receiver, hash, &why.message).await,
            };
            if let Err(e) = self
                .wallet
                .pay_code_keyed(&url, &payee, donation.amount, *hash)
                .await
            {
                tracing::info!(hash = %hex::encode(hash), "donation payment not done yet: {e}");
            }
            // As the wallet recorded it, whatever the call returned.
            return match self.wallet.sent_by_key(hash)?.map(|s| s.state) {
                Some(State::Done) => {
                    self.settle(receiver, donation, DonationState::Settled)
                        .await
                }
                Some(State::Abandoned(_)) => {
                    self.cancel(receiver, hash, "its payment failed").await
                }
                _ => Ok(()),
            };
        };
        match sent.state {
            State::Done => {
                self.settle(receiver, donation, DonationState::Settled)
                    .await
            }
            State::Abandoned(_) => self.cancel(receiver, hash, "its payment failed").await,
            State::Offered if late => match self.wallet.abandon(&sent.id) {
                Ok(()) => {
                    self.cancel(receiver, hash, "its payment was not made in time")
                        .await
                }
                // As the wallet recorded it since: signed meanwhile, its hub
                // may release it; otherwise looked at again next time.
                Err(e) => match self.wallet.sent_by_key(hash)?.map(|s| s.state) {
                    Some(State::Signed) => {
                        self.settle(receiver, donation, DonationState::Owed).await
                    }
                    Some(State::Done) => {
                        self.settle(receiver, donation, DonationState::Settled)
                            .await
                    }
                    Some(State::Abandoned(_)) => {
                        self.cancel(receiver, hash, "its payment was not made in time")
                            .await
                    }
                    _ => {
                        tracing::warn!(hash = %hex::encode(hash), %e, "a late donation's payment not given up");
                        Ok(())
                    }
                },
            },
            State::Signed if late => self.settle(receiver, donation, DonationState::Owed).await,
            _ => Ok(()),
        }
    }

    /// The hub to pay `amount` at to the payee of `code`: refused if the
    /// provider holds too little at its hubs, or if the hub's fee on it is
    /// more than the provider's, `fee`.
    fn payable(&self, code: &LicashCode, amount: u64, fee: u64) -> Result<String, Problem> {
        if amount == 0 {
            return Err(Problem::invalid(
                "the donation pays nothing once the fee is taken",
            ));
        }
        let url = self
            .wallet
            .hub_to_pay(code, amount)
            .map_err(crate::refused)?
            .ok_or_else(|| declined("the provider holds too little at the hubs of this code"))?;
        let hub_fee = self.wallet.send_fee(&url, amount).map_err(crate::refused)?;
        if hub_fee > fee {
            return Err(declined(format!(
                "the hub's fee of {hub_fee} sat is more than the provider's of {fee} sat"
            )));
        }
        Ok(url)
    }

    /// The Licash code `text`, of the provider's network.
    fn payee(&self, text: &str) -> Result<LicashCode, Problem> {
        let code: LicashCode = text
            .parse()
            .map_err(|_| Problem::invalid("not a Licash code"))?;
        if code.network != self.wallet.network() {
            return Err(Problem::invalid("a Licash code of another network"));
        }
        Ok(code)
    }

    fn receiver(&self) -> Result<&Receiver, Problem> {
        self.donations
            .as_ref()
            .ok_or_else(|| declined("the provider takes no donations"))
    }

    async fn settle(
        &self,
        receiver: &Receiver,
        donation: &Donation,
        to: DonationState,
    ) -> Result<(), Error> {
        let hash = &donation.hash;
        let preimage: [u8; 32] = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT preimage FROM provider_donations WHERE hash = ?1",
                [hash],
                |r| r.get(0),
            )?)
        })?;
        if let Err(e) = receiver.node.settle(preimage).await {
            let held = receiver
                .node
                .invoice(*hash)
                .await
                .map_err(Error::Lightning)?;
            match held.map(|h| h.state) {
                Some(HeldState::Settled) => {}
                Some(HeldState::Canceled) => {
                    return self.lost(receiver, hash, "its invoice was canceled after paying it")
                }
                _ => return Err(Error::Lightning(e)),
            }
        }
        tracing::info!(hash = %hex::encode(hash), sat = donation.sat, "donation settled");
        let why = match to {
            DonationState::Owed => "settled before its payment was released",
            _ => "paid",
        };
        self.finish(hash, to, why)
    }

    async fn cancel(&self, receiver: &Receiver, hash: &[u8; 32], why: &str) -> Result<(), Error> {
        if let Err(e) = receiver.node.cancel(*hash).await {
            let held = receiver
                .node
                .invoice(*hash)
                .await
                .map_err(Error::Lightning)?;
            if held.is_some_and(|h| h.state != HeldState::Canceled) {
                return Err(Error::Lightning(e));
            }
        }
        tracing::info!(hash = %hex::encode(hash), why, "donation canceled");
        self.finish(hash, DonationState::Canceled, why)
    }

    fn lost(&self, receiver: &Receiver, hash: &[u8; 32], why: &str) -> Result<(), Error> {
        let name = hex::encode(hash);
        let message = format!("Donation {name} is lost: {why}. Resolve it by hand.");
        self.alert_donation(receiver, format!("lost {name}"), &message)?;
        self.finish(hash, DonationState::Lost, why)
    }

    fn alert_donation(
        &self,
        receiver: &Receiver,
        what: String,
        message: &str,
    ) -> Result<(), Error> {
        if receiver.first(what) {
            tracing::error!("{message}");
            self.alert(message)?;
        }
        Ok(())
    }

    fn finish(&self, hash: &[u8; 32], state: DonationState, why: &str) -> Result<(), Error> {
        self.store.write(|tx| {
            tx.execute(
                "UPDATE provider_donations SET state = ?2, reason = ?3, updated_at = ?4 WHERE hash = ?1",
                params![hash, state.name(), why, now()],
            )?;
            Ok(())
        })
    }
}

fn sql(amount: u64) -> Result<i64, Error> {
    crate::store::sat(amount)
}

/// A problem with what the provider recorded, as an error of its own.
fn problem(p: Problem) -> Error {
    Error::Setup(p.message)
}
