//! Lightning, through a hub's gateway ([`licash_api::Lightning`]).
//!
//! Paying an invoice locks notes worth it and the gateway's fee to the hub
//! alone, under the invoice's hash, recording the invoice with the lock.
//! Once the lock is certified the wallet asks the hub to pay the invoice:
//! the preimage the payment buys settles the lock, and a failed payment
//! refunds it. Following the lock asks again until one or the other. An
//! invoice of the gateway's own node, a receipt at the same hub, is paid
//! inside the hub, for its amount alone: the lock backs the receipt, and
//! the preimage its payee reveals to claim it settles the lock.
//!
//! Paying through a swap provider instead ([`Wallet::pay_invoice_via`]):
//! the wallet locks the invoice's amount and the provider's fee to the
//! provider, under the invoice's hash, and asks it to pay the invoice from
//! its own node. The preimage the payment buys claims the lock. The lock
//! expires soon after the provider's routes end, so that its notes return
//! soon if the payment fails. When the invoice is a hub's, the payee's
//! wallet chose its preimage: the provider cannot keep it from the payee.
//!
//! Getting paid: the wallet draws a preimage, records it with the receipt
//! it asks for, then asks the hub for an invoice under its hash. Once the
//! invoice is paid, the hub locks notes of its own to the wallet, which
//! claims them with the preimage: that settles the invoice.
//!
//! Or getting paid through a swap provider ([`Wallet::invoice_through`]),
//! at a hub with no gateway: the provider's node makes the invoice under
//! the wallet's hash, asking exactly the amount and its fee, and once it is
//! paid locks notes of its own to the wallet at the hub, which the wallet
//! claims as it claims a hub's. The provider is recorded beside the
//! invoice, in a table made when first used: a wallet's file of an older
//! version holds hub invoices alone, followed as they were.

use licash::{
    address::Ephemeral,
    claim::Branch,
    spend::{lock_hash, ProposalId},
};
use licash_api::{
    swaps::{self, LightningRequest, LightningSwap, ReceiveRequest},
    Lightning, Pay, PayState, Paying, Receive, ReceiveState, ReceiveStatus, Receiving,
};
use lightning_invoice::Bolt11Invoice;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Row};

use crate::{
    hub_url, invalid, locks::Pays, now, sql, unavailable, Address, Error, Lock, LockState,
    Transport, Wallet,
};

/// Blocks a route's timelock may take beyond an invoice's final delta, at
/// least, as hubs require.
const CLTV_MARGIN: u64 = 3;

/// Blocks a swap provider's routes may take beyond an invoice's final delta,
/// its margin and the provider's slack, as a lock paying through it
/// leaves them: one hop of LND's default CLTV delta.
pub const ROUTE_BLOCKS: u32 = 80;

/// A payment asked for over Lightning, and where it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invoice {
    /// Its payment hash, in hex.
    pub hash: String,
    pub hub: String,
    /// What it pays the wallet; the invoice asks the hub's fee on top.
    pub amount: u64,
    /// The BOLT11 invoice to hand the payer, once the hub made it.
    pub request: Option<String>,
    pub state: InvoiceState,
    pub created_at: i64,
    /// The lock of the hub's notes paying it, in hex, once it was paid:
    /// the notes are received under it.
    pub lock: Option<String>,
    /// When its notes were taken, if they were.
    pub received_at: Option<i64>,
    /// Its lock's preimage revealed only with [`crate::PROTECTED_MARGIN`]
    /// blocks left ([`Wallet::invoice_protected`]).
    pub protected: bool,
    /// What it says to its payer, if asked ([`Wallet::invoice_saying`]).
    pub memo: Option<String>,
}

/// Where an invoice the wallet is paid with stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvoiceState {
    /// Waiting for its hub's invoice, its payer or the wallet's claim.
    Open,
    /// Paid, and its notes kept.
    Received,
    /// Refused or canceled unpaid, or its lock unclaimed in time, and why.
    Canceled(String),
}

/// A Lightning invoice to pay, as [`Wallet::read_invoice`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payable {
    /// The BOLT11 invoice, to pay with [`Wallet::pay_invoice`].
    pub request: String,
    /// What it asks, in sat: rounded up from millisatoshis.
    pub amount: u64,
    /// What it says it pays for, if it says.
    pub description: Option<String>,
    /// When it expires, in seconds since the Unix epoch.
    pub expires_at: i64,
}

/// An invoice as the wallet reads it.
fn decode(request: &str) -> Result<Bolt11Invoice, Error> {
    request
        .trim()
        .parse()
        .map_err(|e| Error::Invalid(format!("not a Lightning invoice: {e}")))
}

impl Payable {
    /// The invoice `text` carries, as [`Wallet::read_invoice`] reads it,
    /// whoever can pay it: of any network, expired or not, if it asks an
    /// amount.
    pub fn read(text: &str) -> Result<Self, Error> {
        let invoice = read(text)?;
        let msat = invoice
            .amount_milli_satoshis()
            .ok_or_else(|| Error::Invalid("an invoice without an amount".into()))?;
        Ok(Self::of(&invoice, msat))
    }

    fn of(invoice: &Bolt11Invoice, msat: u64) -> Self {
        let expires_at = invoice.expires_at().map_or(i64::MAX, |at| {
            i64::try_from(at.as_secs()).unwrap_or(i64::MAX)
        });
        Self {
            request: invoice.to_string(),
            amount: msat.div_ceil(1000),
            description: described(invoice),
            expires_at,
        }
    }
}

/// What `invoice` says it pays for, if it says it in words.
fn described(invoice: &Bolt11Invoice) -> Option<String> {
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => Some(d.to_string()),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => None,
    }
    .filter(|d| !d.is_empty())
}

/// The hash of the description `invoice` commits to, if it says none in
/// words.
fn committed(invoice: &Bolt11Invoice) -> Option<[u8; 32]> {
    use bitcoin::hashes::Hash as _;
    match invoice.description() {
        lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => Some(h.0.to_byte_array()),
        lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(_) => None,
    }
}

/// An invoice's exact total, in millisatoshis, and the description hash it
/// commits to ([`Wallet::invoice_exact`]).
#[derive(Clone, Copy)]
struct Exact {
    msat: u64,
    description_hash: Option<[u8; 32]>,
}

/// The invoice `text` carries, decoded.
fn read(text: &str) -> Result<Bolt11Invoice, Error> {
    invoice_in(text)
        .ok_or_else(|| Error::Invalid("no Lightning invoice".into()))
        .and_then(decode)
}

/// The invoice `text` carries: bare, as a `lightning:` URI, or as the
/// `lightning` parameter of a `bitcoin:` URI.
fn invoice_in(text: &str) -> Option<&str> {
    let text = text.trim();
    let scheme = |s: &str| {
        text.get(..s.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(s))
    };
    if scheme("lightning:") {
        return Some(&text["lightning:".len()..]);
    }
    if scheme("bitcoin:") {
        let (_, query) = text.split_once('?')?;
        return query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            key.eq_ignore_ascii_case("lightning").then_some(value)
        });
    }
    Some(text)
}

impl<T: Transport> Wallet<T> {
    /// The invoice `text` asks to pay, if this wallet can: of its network,
    /// with an amount, not expired. `text` is the invoice, bare or as a
    /// `lightning:` URI, or a `bitcoin:` URI naming one.
    pub fn read_invoice(&self, text: &str) -> Result<Payable, Error> {
        let invoice = read(text)?;
        let msat = self.payable(&invoice)?;
        Ok(Payable::of(&invoice, msat))
    }

    /// What `invoice` asks, in msat, if this wallet can pay it.
    fn payable(&self, invoice: &Bolt11Invoice) -> Result<u64, Error> {
        let network = licash_onchain::network(self.network());
        if invoice.currency() != lightning_invoice::Currency::from(network) {
            return Err(Error::Invalid(format!(
                "an invoice of another network than {network}"
            )));
        }
        let msat = invoice
            .amount_milli_satoshis()
            .filter(|msat| *msat > 0)
            .ok_or_else(|| Error::Invalid("an invoice without an amount".into()))?;
        if invoice.is_expired() {
            return Err(Error::Invalid("the invoice expired".into()));
        }
        Ok(msat)
    }

    /// What paying `request` through the hub at `url` costs on top of what
    /// it asks, with the notes held now, as the hub last said: its
    /// gateway's fee, and its fee on a payment to this wallet making notes
    /// worth the lock exactly, if it holds none. Refused as
    /// [`Error::Insufficient`] if it holds not that much at the hub.
    pub fn invoice_fee(&self, url: &str, request: &str) -> Result<u64, Error> {
        let url = hub_url(url)?;
        let invoice = decode(request)?;
        let msat = self.payable(&invoice)?;
        let (hub, info) = self.hub(&url)?;
        let (lock, _) = gateway_lock(&url, &info, &invoice, msat)?;
        self.gateway_fee((&url, hub), lock, msat)
    }

    /// What a lock of `lock` sat at the hub at `url`, paying an invoice of
    /// `msat` through its gateway, costs on top of the invoice: the
    /// gateway's fee in it, and the hub's fee on a payment to this wallet
    /// making notes worth it exactly, if it holds none.
    fn gateway_fee(&self, (url, hub): (&str, i64), lock: u64, msat: u64) -> Result<u64, Error> {
        let exact = match self.exact(hub, lock)? {
            Some(_) => 0,
            None => self.send_fee(url, lock)?,
        };
        Ok(lock - msat.div_ceil(1000) + exact)
    }
}

/// The amount and expiry of a lock paying `invoice`, of `msat`, through
/// the hub at `url` saying `info`. An invoice of its gateway's own node,
/// a receipt there, is paid inside the hub: for its amount alone. Any
/// other, over Lightning: for its amount and the gateway's fee, if the
/// latest expiry the hub admits leaves its gateway room for the invoice's
/// final delta.
fn gateway_lock(
    url: &str,
    info: &licash_api::Info,
    invoice: &Bolt11Invoice,
    msat: u64,
) -> Result<(u64, u32), Error> {
    let lightning = info
        .lightning
        .as_ref()
        .ok_or_else(|| Error::Invalid(format!("hub {url} pays no Lightning invoices")))?;
    let locks = info
        .locks
        .as_ref()
        .ok_or_else(|| Error::Invalid(format!("hub {url} follows no chain: it takes no locks")))?;
    let expiry = locks
        .latest_expiry(locks.min_depth.max(1))
        .map_err(|p| unavailable(url, p))?;
    if pays_inside(lightning, invoice) {
        return Ok((msat.div_ceil(1000), expiry));
    }
    if msat > lightning.max_pay.saturating_mul(1000) {
        return Err(Error::Invalid(format!(
            "hub {url} pays invoices of at most {} sat",
            lightning.max_pay
        )));
    }
    let room = expiry
        .saturating_sub(locks.height)
        .saturating_sub(lightning.pay_slack);
    let delta = invoice.min_final_cltv_expiry_delta();
    if u64::from(room) < delta.saturating_add(CLTV_MARGIN) {
        return Err(Error::Invalid(format!(
            "the invoice's final delta of {delta} blocks outlasts the locks of hub {url}"
        )));
    }
    Ok((lightning.pay_lock(msat), expiry))
}

/// Whether `invoice` is of the node of the gateway `lightning`: a receipt
/// at its hub, which the hub pays inside it.
fn pays_inside(lightning: &Lightning, invoice: &Bolt11Invoice) -> bool {
    hex::encode(invoice.get_payee_pub_key().serialize()) == lightning.node
}

fn hash_id(hash: &str) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(hash, &mut bytes)
        .map_err(|_| Error::Invalid(format!("not a payment hash: {hash}")))?;
    Ok(bytes)
}

/// Paying invoices.
impl<T: Transport> Wallet<T> {
    /// Pay `request`, a BOLT11 invoice, through the hub at `url`: lock
    /// notes worth it and the hub's fee to the hub, until the latest expiry
    /// it admits, for the hub to pay it. Where the lock stands: paid on the
    /// invoice's preimage, refunded once the payment failed, or
    /// [`crate::LockState::Locked`] while it is under way, which
    /// [`Wallet::follow_lock`] follows.
    pub async fn pay_invoice(&self, url: &str, request: &str) -> Result<Lock, Error> {
        self.pay_invoice_within(url, request, None).await
    }

    /// [`Wallet::pay_invoice`], refused as [`Error::FeeRose`] if it costs
    /// more than `max_fee` on top of what the invoice asks
    /// ([`Wallet::invoice_fee`]), as the hub says now: what was quoted.
    pub async fn pay_invoice_within(
        &self,
        url: &str,
        request: &str,
        max_fee: Option<u64>,
    ) -> Result<Lock, Error> {
        let url = hub_url(url)?;
        let invoice = decode(request)?;
        let msat = self.payable(&invoice)?;
        let hash: [u8; 32] = *invoice.payment_hash().as_ref();
        if let Some(lock) = self.live_lock(&hash, |l| l.via.is_some())? {
            return Err(Error::Invalid(format!(
                "the invoice is being paid through a swap provider, by lock {}",
                lock.id
            )));
        }
        // Asked again: the lock made before, live or paid, not another.
        if let Some(lock) = self.live_lock(&hash, |l| l.invoice.is_some())? {
            return self.follow_lock(&lock.id).await;
        }
        let (hub, info) = self.refresh(&url).await?;
        let (amount, expiry) = gateway_lock(&url, &info, &invoice, msat)?;
        if let Some(agreed) = max_fee {
            let asked = self.gateway_fee((&url, hub), amount, msat)?;
            if asked > agreed {
                return Err(Error::FeeRose {
                    who: url.clone(),
                    agreed,
                    asked,
                    reason: format!(
                        "hub {url} asks {asked} sat to pay the invoice, more than {agreed}"
                    ),
                });
            }
            // The exact notes to lock made first, within what is left of
            // the fee once the gateway's: a hub refusing the fee it
            // advertised is paid its new one only that far.
            if self.exact(hub, amount)?.is_none() {
                let gateway = amount - msat.div_ceil(1000);
                let left = Some(agreed.saturating_sub(gateway));
                tracing::info!(%url, amount, "making exact notes to lock");
                let me = self.address();
                match self.send_with(&url, &me, amount, None, None, left).await {
                    Err(Error::FeeRose { asked, .. }) => {
                        let asked = gateway.saturating_add(asked);
                        return Err(Error::FeeRose {
                            who: url.clone(),
                            agreed,
                            asked,
                            reason: format!(
                                "hub {url} asks {asked} sat to pay the invoice, more than {agreed}"
                            ),
                        });
                    }
                    made => made.map(drop)?,
                }
            }
        }
        let request = invoice.to_string();
        tracing::info!(%url, msat, amount, "paying an invoice");
        self.lock_paying(
            (&url, hub, &info),
            &info.address,
            amount,
            hash,
            Some(expiry),
            Pays::Gateway(&request),
        )
        .await
    }

    /// Ask the hub at `url` to pay `invoice` for lock `id`, certified: a
    /// failure or a refusal is recorded, and the lock followed to its
    /// refund. No answer is retried when the lock is followed again.
    pub(crate) async fn ask_payment(
        &self,
        url: &str,
        id: &ProposalId,
        invoice: &str,
    ) -> Result<(), Error> {
        let asked = self
            .post::<Paying>(url, licash_api::LN_PAY, &Pay::new(id, invoice))
            .await;
        let failure = match asked {
            Ok(Paying {
                state: PayState::Failed,
                reason,
                ..
            }) => reason.unwrap_or_else(|| "the payment failed".into()),
            Ok(_) => return Ok(()),
            Err(Error::Refused { problem, .. }) => format!("refused: {problem}"),
            Err(e) => {
                tracing::warn!(id = %hex::encode(id.as_bytes()), error = %e, "cannot ask for a payment");
                return Ok(());
            }
        };
        tracing::warn!(id = %hex::encode(id.as_bytes()), %url, failure, "invoice not paid");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE locks SET failure = ?2 WHERE id = ?1 AND failure IS NULL",
                params![id.as_bytes(), failure],
            )?;
            Ok(())
        })
    }
}

/// The expiry of a lock at the hub at `url` saying `info`, paying `invoice`
/// through a provider of `terms`: the soonest its routes take, those of
/// [`ROUTE_BLOCKS`] beyond its final delta, and the provider's slack, at
/// most the latest the hub admits. Refused unless the hub admits the
/// soonest a provider takes.
fn via_expiry(
    url: &str,
    info: &licash_api::Info,
    terms: &swaps::Lightning,
    invoice: &Bolt11Invoice,
) -> Result<u32, Error> {
    let locks = info
        .locks
        .as_ref()
        .ok_or_else(|| Error::Invalid(format!("hub {url} follows no chain: it takes no locks")))?;
    let latest = locks
        .latest_expiry(locks.min_depth.max(1))
        .map_err(|p| unavailable(url, p))?;
    let delta = invoice
        .min_final_cltv_expiry_delta()
        .saturating_add(CLTV_MARGIN);
    let delta = u32::try_from(delta).unwrap_or(u32::MAX);
    let soonest = locks
        .height
        .saturating_add(terms.slack)
        .saturating_add(delta);
    if soonest >= latest {
        return Err(Error::Invalid(format!(
            "the provider's slack of {} blocks and the invoice's final delta outlast the locks \
             of hub {url}",
            terms.slack
        )));
    }
    Ok(soonest.saturating_add(ROUTE_BLOCKS).min(latest))
}

/// What a lock paying `invoice`, of `msat`, through the provider at
/// `provider` saying `offer` of itself, from notes at the hub at `url`
/// saying `info`, pays the provider, the provider's fee in it, and when it
/// expires ([`via_expiry`]). Refused unless the provider pays invoices that
/// big for locks at that hub, for at most `max_fee`.
fn via_terms(
    provider: &str,
    offer: &swaps::Info,
    (url, info): (&str, &licash_api::Info),
    invoice: &Bolt11Invoice,
    msat: u64,
    max_fee: u64,
) -> Result<(u64, u64, u32), Error> {
    let refuse = |why: String| Err(Error::Invalid(format!("provider {provider} {why}")));
    let Some(terms) = offer.lightning.as_ref() else {
        return refuse("pays no Lightning invoices".into());
    };
    if offer.hub(&info.address).is_none() {
        return refuse(format!("takes no lock at {url}"));
    }
    // A lock to a hub's own address is the hub's to settle.
    if offer.address == info.address {
        return refuse("names a hub's address as its own".into());
    }
    if msat > terms.max.saturating_mul(1000) {
        return refuse(format!("pays invoices of at most {} sat", terms.max));
    }
    let amount = terms.pays(msat);
    let fee = amount - msat.div_ceil(1000);
    if fee > max_fee {
        return Err(Error::FeeRose {
            who: provider.into(),
            agreed: max_fee,
            asked: fee,
            reason: format!("provider {provider} asks a fee of {fee} sat, more than {max_fee}"),
        });
    }
    let expiry = via_expiry(url, info, terms, invoice)?;
    Ok((amount, fee, expiry))
}

/// Blocks from the tip of the hub saying `info`, as it last said, until a
/// lock there expiring at `expiry` returns its notes: once that deep. None
/// if it follows no chain.
pub fn refund_blocks(info: &licash_api::Info, expiry: u32) -> u32 {
    info.locks.as_ref().map_or(0, |l| {
        expiry.saturating_sub(l.height).saturating_add(l.min_depth)
    })
}

/// What paying an invoice through a swap provider costs, from notes at a
/// hub ([`Wallet::invoice_quote_via`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViaQuote {
    /// What the provider said of itself, with what it pays over Lightning.
    pub info: swaps::Info,
    /// What the invoice asks, in sat rounded up.
    pub amount: u64,
    /// The provider's fee, routing fees included: the lock pays it on top.
    pub fee: u64,
    /// The hub's fee on the wallet's lock, as it charges now.
    pub lock_fee: u64,
    /// The height the lock would expire at: should the payment fail, its
    /// notes return once it is that deep.
    pub expiry: u32,
    /// Blocks from the hub's tip until they do.
    pub refund_blocks: u32,
}

impl ViaQuote {
    /// What paying it costs on top of what the invoice asks.
    pub fn costs(&self) -> u64 {
        self.fee.saturating_add(self.lock_fee)
    }
}

/// Paying invoices through a swap provider.
impl<T: Transport> Wallet<T> {
    /// What paying `request`, a BOLT11 invoice, through the swap provider
    /// at `provider` costs from the notes held now at the hub at `url`, as
    /// it last said of itself. Refused as [`Error::Invalid`] if the
    /// provider pays no such invoice for a lock there, or asks more than
    /// `max_fee`, and as [`Error::Insufficient`] if the notes there pay
    /// not the lock. Nothing is recorded or locked:
    /// [`Wallet::pay_invoice_via`] checks it again.
    pub async fn invoice_quote_via(
        &self,
        provider: &str,
        url: &str,
        request: &str,
        max_fee: u64,
    ) -> Result<ViaQuote, Error> {
        let provider = hub_url(provider)?;
        let url = hub_url(url)?;
        let invoice = decode(request)?;
        let msat = self.payable(&invoice)?;
        let (hub, info) = self.hub(&url)?;
        let offer: swaps::Info = self.get(&provider, swaps::SWAPS_INFO).await?;
        let at = (url.as_str(), &info);
        let (locked, fee, expiry) = via_terms(&provider, &offer, at, &invoice, msat, max_fee)?;
        let fees = self.agreed_fees(hub, &url, &info)?;
        let (_, selection) = self.select(hub, locked, &fees.locking())?;
        Ok(ViaQuote {
            info: offer,
            amount: msat.div_ceil(1000),
            fee,
            lock_fee: selection.fee,
            expiry,
            refund_blocks: refund_blocks(&info, expiry),
        })
    }

    /// Pay `request`, a BOLT11 invoice, through the swap provider at
    /// `provider`, from notes at the hub at `url`: lock the invoice's amount
    /// and the provider's fee to the provider under the invoice's hash,
    /// unless the fee is above `max_fee`, expiring soon after the routes
    /// the provider takes end ([`ROUTE_BLOCKS`]), then ask it to pay. A
    /// lock made before for the same invoice, live or paid, is asked for
    /// again instead. Where the lock stands, [`Wallet::follow_lock`]
    /// following it: paid on the invoice's preimage once the provider
    /// claimed it, or left to be refunded once expired if the payment
    /// failed, why recorded as its `failure`.
    pub async fn pay_invoice_via(
        &self,
        provider: &str,
        url: &str,
        request: &str,
        max_fee: u64,
    ) -> Result<Lock, Error> {
        self.pay_invoice_via_within(provider, url, request, max_fee, None)
            .await
    }

    /// [`Wallet::pay_invoice_via`], refused as [`Error::FeeRose`], nothing
    /// locked, if the provider's fee and the hub's on the lock, as it signs
    /// it, come to more than `costs`: what was quoted in all
    /// ([`ViaQuote::costs`]).
    pub async fn pay_invoice_via_within(
        &self,
        provider: &str,
        url: &str,
        request: &str,
        max_fee: u64,
        costs: Option<u64>,
    ) -> Result<Lock, Error> {
        // Boxed: a lock's future is deep, and nested in its callers'.
        Box::pin(self.paying_via(provider, url, request, max_fee, costs)).await
    }

    async fn paying_via(
        &self,
        provider: &str,
        url: &str,
        request: &str,
        max_fee: u64,
        costs: Option<u64>,
    ) -> Result<Lock, Error> {
        let provider = hub_url(provider)?;
        let url = hub_url(url)?;
        let invoice = decode(request)?;
        let msat = self.payable(&invoice)?;
        let (hub, info) = self.refresh(&url).await?;
        let offer: swaps::Info = self.get(&provider, swaps::SWAPS_INFO).await?;
        let hash: [u8; 32] = *invoice.payment_hash().as_ref();
        let request = invoice.to_string();
        let lock = match self.lock_via(&url, &offer.address, &hash)? {
            Some(lock) => self.follow_lock(&lock.id).await?,
            None => {
                if let Some(lock) = self.live_lock(&hash, |l| l.invoice.is_some())? {
                    return Err(Error::Invalid(format!(
                        "the invoice is being paid through hub {}, by lock {}",
                        lock.hub, lock.id
                    )));
                }
                let at = (url.as_str(), &info);
                let (amount, fee, expiry) =
                    via_terms(&provider, &offer, at, &invoice, msat, max_fee)?;
                tracing::info!(%url, %provider, msat, amount, expiry, "paying an invoice through a provider");
                let at = (url.as_str(), hub, &info);
                let pays = Pays::Via {
                    provider: &provider,
                    invoice: &request,
                };
                let prepared = self
                    .prepare_lock(at, &offer.address, amount, hash, Some(expiry), pays)
                    .await?;
                // Its fee as the hub's lock signs it, not as quoted.
                let asked = fee.saturating_add(prepared.fee);
                if let Some(agreed) = costs.filter(|most| asked > *most) {
                    return Err(Error::FeeRose {
                        who: provider.clone(),
                        agreed,
                        asked,
                        reason: format!(
                            "provider {provider} and hub {url} ask {asked} sat to pay the invoice, more than {agreed}"
                        ),
                    });
                }
                self.store.write(|tx| prepared.record(tx))?;
                self.send_lock(&url, &prepared).await?
            }
        };
        match lock.state {
            LockState::Requested => Err(Error::Pending {
                id: lock.id,
                reason: "its lock is not certified yet".into(),
            }),
            _ => Ok(lock),
        }
    }

    /// The latest lock at the hub at `url` to `payee` under `hash`, unless
    /// refunded or given up.
    fn lock_via(&self, url: &str, payee: &Address, hash: &[u8; 32]) -> Result<Option<Lock>, Error> {
        let locks = self.locks()?;
        Ok(locks.into_iter().find(|l| {
            l.hub == url
                && l.payee == *payee
                && l.hash == *hash
                && l.invoice.is_none()
                && !matches!(l.state, LockState::Refunded | LockState::Abandoned(_))
        }))
    }

    /// The latest lock under `hash`, unless refunded or given up, that
    /// `paying` says pays its invoice.
    fn live_lock(
        &self,
        hash: &[u8; 32],
        paying: impl Fn(&Lock) -> bool,
    ) -> Result<Option<Lock>, Error> {
        let locks = self.locks()?;
        Ok(locks.into_iter().find(|l| {
            l.hash == *hash
                && paying(l)
                && !matches!(l.state, LockState::Refunded | LockState::Abandoned(_))
        }))
    }

    /// Ask the provider at `provider` to pay `invoice` for lock `id`,
    /// certified at the hub at `url`: asked again each time the lock is
    /// followed, the provider answering where its payment stands. A payment
    /// it gave up or declined is recorded as the lock's failure, which ends
    /// the asking: the lock is refunded once expired. No answer is asked
    /// again.
    pub(crate) async fn ask_provider(
        &self,
        url: &str,
        provider: &str,
        id: &ProposalId,
        invoice: &str,
    ) -> Result<(), Error> {
        let key = hex::encode(id.as_bytes());
        let (_, info) = self.hub(url)?;
        let asked = LightningRequest::new(&info.address, id, invoice);
        let asked = self
            .post::<LightningSwap>(provider, swaps::LIGHTNING_SWAPS, &asked)
            .await;
        let failure = match asked {
            Ok(LightningSwap {
                state: swaps::State::Failed,
                reason,
                ..
            }) => reason.unwrap_or_else(|| "the payment failed".into()),
            Ok(answer) => {
                tracing::debug!(id = %key, %provider, state = ?answer.state, "the provider pays");
                return Ok(());
            }
            Err(Error::Refused { problem, .. }) => format!("the provider declined: {problem}"),
            Err(e) => {
                tracing::warn!(id = %key, %provider, error = %e, "cannot ask the provider to pay");
                return Ok(());
            }
        };
        tracing::warn!(id = %key, %provider, failure, "invoice not paid");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE locks SET failure = ?2 WHERE id = ?1 AND failure IS NULL",
                params![id.as_bytes(), failure],
            )?;
            Ok(())
        })
    }
}

/// The component of the providers of invoices ([`Wallet::invoice_through`]),
/// and its version.
const VIA_COMPONENT: &str = "invoice_providers";
const VIA_VERSION: i64 = 1;
const VIA_SCHEMA: &str = "
-- The swap provider asked for an invoice in place of its hub, by the
-- invoice's hash: `asks`, what its invoice asks exactly, in sat.
CREATE TABLE invoice_providers (
    hash BLOB PRIMARY KEY REFERENCES invoices (hash),
    provider TEXT NOT NULL,
    asks INTEGER NOT NULL CHECK (asks > 0)
) STRICT;
";

/// The provider asked for the invoice of `hash`, and what it asks, if one
/// was: none in a file whose wallet never asked one.
fn via(c: &rusqlite::Connection, hash: &[u8; 32]) -> Result<Option<(String, u64)>, Error> {
    let kept = licash_store::component_version(c, VIA_COMPONENT)
        .map_err(|e| Error::Setup(e.to_string()))?;
    if kept.is_none() {
        return Ok(None);
    }
    Ok(c.query_row(
        "SELECT provider, asks FROM invoice_providers WHERE hash = ?1",
        [hash],
        |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
    )
    .optional()?)
}

/// What a swap provider takes to have the wallet paid over Lightning at a
/// hub ([`Wallet::receive_offer`]).
#[derive(Clone, Debug)]
pub struct ReceiveOffer {
    pub info: swaps::Info,
    pub terms: swaps::Receives,
    /// The most it takes there now: its terms, and what it holds there.
    pub max: u64,
}

/// Getting paid over Lightning through a swap provider.
impl<T: Transport> Wallet<T> {
    /// What the provider at `provider` takes to have the wallet paid over
    /// Lightning at the hub at `hub`, trusted: refused if it takes no such
    /// payments, or none there now.
    pub async fn receive_offer(&self, provider: &str, hub: &str) -> Result<ReceiveOffer, Error> {
        let provider = hub_url(provider)?;
        let url = hub_url(hub)?;
        let (_, hub_info) = self.hub(&url)?;
        let info: swaps::Info = self.get(&provider, swaps::SWAPS_INFO).await?;
        let terms = info.receive.ok_or_else(|| {
            Error::Invalid(format!(
                "provider {provider} takes no payments over Lightning"
            ))
        })?;
        let max = match info.hub(&hub_info.address) {
            Some(at) => terms.max.min(at.max),
            None => 0,
        };
        if max < terms.min {
            return Err(Error::Invalid(format!(
                "provider {provider} takes no payments over Lightning at hub {url} now"
            )));
        }
        Ok(ReceiveOffer { info, terms, max })
    }

    /// Ask the provider at `provider` for an invoice paying this wallet
    /// `amount` at the hub at `url`, its fee on top, saying `memo` to its
    /// payer, if given: in its description, which the provider and its
    /// node see too, as they see each payment's amount and the wallet's
    /// address. [`Wallet::follow_invoice`] claims the payment once made.
    pub async fn invoice_through(
        &self,
        provider: &str,
        url: &str,
        amount: u64,
        memo: Option<&str>,
    ) -> Result<Invoice, Error> {
        let memo = memo
            .map(licash_api::memo)
            .transpose()
            .map_err(|p| Error::Invalid(p.message))?;
        let provider = hub_url(provider)?;
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let offer = self.receive_offer(&provider, &url).await?;
        if amount < offer.terms.min || amount > offer.max {
            return Err(Error::Invalid(format!(
                "provider {provider} takes {} to {} over Lightning at hub {url}",
                offer.terms.min, offer.max
            )));
        }
        let asks = offer.terms.asks(amount);
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let hash = lock_hash(&preimage);
        let body = ReceiveRequest {
            hub: info.address,
            address: self.address(),
            amount,
            hash: licash_api::Hex(hash.to_vec()),
            memo,
        };
        let body = serde_json::to_string(&body).map_err(invalid)?;
        self.store.write(|tx| {
            licash_store::component_in(tx, VIA_COMPONENT, VIA_VERSION, VIA_SCHEMA)
                .map_err(|e| Error::Setup(e.to_string()))?;
            tx.execute(
                "INSERT INTO invoices (hash, hub, preimage, amount, body, created_at, protected)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                params![hash, hub, preimage, sql(amount)?, body, now()],
            )?;
            tx.execute(
                "INSERT INTO invoice_providers (hash, provider, asks) VALUES (?1, ?2, ?3)",
                params![hash, provider, sql(asks)?],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, %provider, amount, "asking a provider for an invoice");
        self.advance_invoice(&hash).await
    }
}

/// Getting paid over Lightning.
impl<T: Transport> Wallet<T> {
    /// Ask the hub at `url` for an invoice paying this wallet `amount`, its
    /// fee on top, to hand the payer. [`Wallet::follow_invoice`] claims the
    /// payment once made.
    pub async fn invoice(&self, url: &str, amount: u64) -> Result<Invoice, Error> {
        self.invoice_with(url, amount, false, None).await
    }

    /// [`Wallet::invoice`], or [`Wallet::invoice_protected`] if
    /// `protected`, saying `memo` to its payer, if given: in its
    /// description, which the hub and its Lightning node see too. Refused
    /// at a hub not naming [`licash_api::FEATURE_MEMO`], which would leave
    /// it out, and checked in the invoice it answers.
    pub async fn invoice_saying(
        &self,
        url: &str,
        amount: u64,
        memo: Option<&str>,
        protected: bool,
    ) -> Result<Invoice, Error> {
        if protected {
            self.chain_known_to_protect()?;
        }
        self.invoice_with(url, amount, protected, memo).await
    }

    /// An invoice from the hub at `url` asking exactly `msat`, the hub's
    /// fee taken from it: this wallet is paid the most whole notes the rest
    /// comes to, and the hub keeps the under 2 sat beyond. Committing to
    /// `description_hash`, if given, instead of saying a memo, as LNURL-pay
    /// and Nostr zaps want. Refused at a hub not naming
    /// [`licash_api::FEATURE_LNURL`], and checked in the invoice it
    /// answers.
    pub async fn invoice_exact(
        &self,
        url: &str,
        msat: u64,
        description_hash: Option<[u8; 32]>,
    ) -> Result<Invoice, Error> {
        let exact = Exact {
            msat,
            description_hash,
        };
        self.invoice_asking(url, None, false, None, Some(exact))
            .await
    }

    /// [`Wallet::invoice`], its lock's preimage revealed only with
    /// [`crate::PROTECTED_MARGIN`] blocks left at the higher of its hub's
    /// height and the chain's as the wallet knows it of itself
    /// ([`Wallet::tip`]): should the hub keep the notes, the wallet
    /// activates the lock on Bitcoin in time for a contract's recovery at
    /// the hub to claim them; a lock shown later is left to expire, the
    /// payment failing back to its payer. Only worth asking with such a
    /// contract, and a coin to activate with: without, a protected invoice
    /// only fails more often. Refused of a wallet that does not know the
    /// chain's height of itself, whose hub's word for it protects nothing:
    /// its payment waits, unclaimed, while it does not.
    pub async fn invoice_protected(&self, url: &str, amount: u64) -> Result<Invoice, Error> {
        self.chain_known_to_protect()?;
        self.invoice_with(url, amount, true, None).await
    }

    fn chain_known_to_protect(&self) -> Result<(), Error> {
        match self.tip()? {
            Some(_) => Ok(()),
            None => Err(Error::Chain(
                "the chain's height is not known to the wallet itself, to protect an \
                 invoice by: tell it, or scan"
                    .into(),
            )),
        }
    }

    async fn invoice_with(
        &self,
        url: &str,
        amount: u64,
        protected: bool,
        memo: Option<&str>,
    ) -> Result<Invoice, Error> {
        self.invoice_asking(url, Some(amount), protected, memo, None)
            .await
    }

    /// An invoice for `amount`, or for what `exact` leaves of its total.
    async fn invoice_asking(
        &self,
        url: &str,
        amount: Option<u64>,
        protected: bool,
        memo: Option<&str>,
        exact: Option<Exact>,
    ) -> Result<Invoice, Error> {
        let memo = memo
            .map(licash_api::memo)
            .transpose()
            .map_err(|p| Error::Invalid(p.message))?;
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let lightning = info
            .lightning
            .as_ref()
            .ok_or_else(|| Error::Invalid(format!("hub {url} takes no Lightning payments")))?;
        if memo.is_some() && !info.features.iter().any(|f| f == licash_api::FEATURE_MEMO) {
            return Err(Error::Invalid(format!(
                "hub {url} puts no memo in its invoices"
            )));
        }
        let amount = match (amount, exact) {
            (Some(amount), _) => amount,
            (None, Some(exact)) => {
                if !info.features.iter().any(|f| f == licash_api::FEATURE_LNURL) {
                    return Err(Error::Invalid(format!(
                        "hub {url} makes no invoices of an exact amount"
                    )));
                }
                licash_api::receivable(exact.msat, &lightning.receive).ok_or_else(|| {
                    Error::Invalid(format!(
                        "hub {url} takes all of {} msat in fees",
                        exact.msat
                    ))
                })?
            }
            (None, None) => return Err(Error::Invalid("an invoice of no amount".into())),
        };
        if amount < lightning.min_receive || amount > lightning.max_receive {
            return Err(Error::Invalid(format!(
                "hub {url} takes {} to {} over Lightning",
                lightning.min_receive, lightning.max_receive
            )));
        }
        let keysets = info.keysets().map_err(|p| unavailable(&url, p))?;
        let (ephemeral, me) = (Ephemeral::random(), self.address());
        let (keyset, outputs) = keysets
            .iter()
            .find_map(|k| {
                let outputs = crate::outputs(k, &ephemeral, Branch::Pay, &[(&me, amount)]);
                Some((k, outputs.ok()?))
            })
            .ok_or_else(|| Error::Invalid(format!("hub {url} has no keyset making {amount}")))?;
        let mut preimage = [0; 32];
        OsRng.fill_bytes(&mut preimage);
        let hash = lock_hash(&preimage);
        let body = Receive::new(keyset.id(), &ephemeral.public(), &outputs, &hash)
            .with_memo(memo)
            .with_lnurl(
                exact.map(|e| e.msat),
                exact.and_then(|e| e.description_hash),
            );
        let body = serde_json::to_string(&body).map_err(invalid)?;
        self.store.write(|tx| {
            tx.execute(
                "INSERT INTO invoices (hash, hub, preimage, amount, body, created_at, protected)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![hash, hub, preimage, sql(amount)?, body, now(), protected],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, amount, protected, "asking for an invoice");
        self.advance_invoice(&hash).await
    }

    /// Take the invoice of `hash` on: have its hub make it, then claim the
    /// notes its hub locks to the wallet once it is paid. Where it stands.
    pub async fn follow_invoice(&self, hash: &str) -> Result<Invoice, Error> {
        self.advance_invoice(&hash_id(hash)?).await
    }

    /// One caller at a time for each invoice: asked, followed and resumed
    /// alongside, two would each send its request and update it.
    pub(crate) async fn advance_invoice(&self, hash: &[u8; 32]) -> Result<Invoice, Error> {
        let lock = {
            let mut advancing = self.advancing.lock().unwrap_or_else(|e| e.into_inner());
            advancing.entry(*hash).or_default().clone()
        };
        let held = lock.lock().await;
        let advanced = self.advance_invoice_alone(hash).await;
        drop(held);
        let mut advancing = self.advancing.lock().unwrap_or_else(|e| e.into_inner());
        // Kept only while another waits for it.
        if std::sync::Arc::strong_count(&lock) == 2 {
            advancing.remove(hash);
        }
        advanced
    }

    async fn advance_invoice_alone(&self, hash: &[u8; 32]) -> Result<Invoice, Error> {
        let pending = |e: Error| match e {
            Error::Pending { .. } | Error::UnknownPayment(_) => e,
            e => Error::Pending {
                id: hex::encode(hash),
                reason: e.to_string(),
            },
        };
        self.advance_invoice_from(hash).await.map_err(pending)?;
        self.invoice_record(hash)
    }

    async fn advance_invoice_from(&self, hash: &[u8; 32]) -> Result<(), Error> {
        type Row = (String, [u8; 32], i64, String, Option<String>, bool, bool);
        let row: Option<Row> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT r.url, i.preimage, i.amount, i.body, i.request,
                    i.done_at IS NULL AND i.canceled IS NULL, i.protected
                 FROM invoices i JOIN reach r ON r.hub = i.hub WHERE i.hash = ?1",
                [hash],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?)
        })?;
        let (url, preimage, amount, body, request, open, protected) =
            row.ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))?;
        if !open {
            return Ok(());
        }
        let via = self.store.read(|c| via(c, hash))?;
        if let Some((provider, asks)) = via {
            return self
                .advance_invoice_via(
                    hash,
                    (&url, &provider),
                    (preimage, amount as u64, asks),
                    &body,
                    request,
                )
                .await;
        }
        if request.is_none() {
            let body: Receive = serde_json::from_str(&body).map_err(invalid)?;
            let asked = self
                .post::<Receiving>(&url, licash_api::LN_RECEIVE, &body)
                .await;
            let receiving = match asked {
                Ok(receiving) => receiving,
                // Refused before the hub made an invoice.
                Err(Error::Refused { problem, .. }) => {
                    return self.cancel_invoice(hash, &format!("refused: {problem}"));
                }
                Err(e) => return Err(e),
            };
            let invoice = decode(&receiving.request).map_err(|e| unavailable(&url, e))?;
            let of: [u8; 32] = *invoice.payment_hash().as_ref();
            let least = (amount as u64).saturating_mul(1000);
            if of != *hash
                || invoice
                    .amount_milli_satoshis()
                    .is_none_or(|msat| msat < least)
            {
                return Err(unavailable(
                    &url,
                    "it answered an invoice of another payment",
                ));
            }
            if let Some(memo) = &body.memo {
                // Never handed out: the payer would not read what it was asked to.
                if described(&invoice).as_ref() != Some(memo) {
                    return self.cancel_invoice(hash, "its hub left the memo out of the invoice");
                }
            }
            // Never handed out: its payer, an LNURL service, would refuse it.
            if body
                .msat
                .is_some_and(|msat| invoice.amount_milli_satoshis() != Some(msat))
            {
                return self.cancel_invoice(hash, "its hub's invoice asks another amount");
            }
            if body
                .description_hash
                .as_ref()
                .is_some_and(|asked| committed(&invoice).map(Vec::from) != Some(asked.0.clone()))
            {
                return self
                    .cancel_invoice(hash, "its hub's invoice commits to another description");
            }
            self.store.write(|tx| {
                tx.execute(
                    "UPDATE invoices SET request = ?2 WHERE hash = ?1",
                    params![hash, invoice.to_string()],
                )?;
                Ok(())
            })?;
            tracing::info!(hash = %hex::encode(hash), %url, "invoice made");
        }
        let status: ReceiveStatus = self.get(&url, &licash_api::ln_receive_state(hash)).await?;
        let lock = status.lock().map_err(|p| unavailable(&url, p))?;
        let lock = match (status.state, lock) {
            (ReceiveState::Open, _) => return Ok(()),
            (ReceiveState::Canceled, _) => return self.cancel_invoice(hash, "canceled by its hub"),
            (_, None) => return Err(unavailable(&url, "a payment locked to no lock")),
            (_, Some(lock)) => lock,
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE invoices SET lock = ?2 WHERE hash = ?1",
                params![hash, lock.as_bytes()],
            )?;
            Ok(())
        })?;
        let (lock, least) = (hex::encode(lock.as_bytes()), amount as u64);
        let claimed = match protected {
            true => self.claim_protected(&url, &lock, &preimage, least).await,
            false => self.claim_paying(&url, &lock, &preimage, least).await,
        };
        match claimed {
            Ok(_) | Err(Error::AlreadyReceived) => {}
            // Refunded, too late to claim, or not a lock to this wallet.
            Err(Error::Invalid(reason)) => return self.cancel_invoice(hash, &reason),
            Err(Error::PaysNothing) => {
                return self.cancel_invoice(hash, "its lock pays this wallet nothing");
            }
            Err(e) => return Err(e),
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE invoices SET done_at = ?2 WHERE hash = ?1 AND done_at IS NULL",
                params![hash, now()],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, amount, "invoice paid");
        Ok(())
    }

    /// [`Wallet::advance_invoice_from`], of an invoice asked of `provider`
    /// paying at the hub at `url`, its invoice asking `asks` exactly.
    async fn advance_invoice_via(
        &self,
        hash: &[u8; 32],
        (url, provider): (&str, &str),
        (preimage, amount, asks): ([u8; 32], u64, u64),
        body: &str,
        request: Option<String>,
    ) -> Result<(), Error> {
        if request.is_none() {
            let body: ReceiveRequest = serde_json::from_str(body).map_err(invalid)?;
            let asked = self
                .post::<Receiving>(provider, swaps::RECEIVES, &body)
                .await;
            let receiving = match asked {
                Ok(receiving) => receiving,
                Err(Error::Refused { problem, .. }) => {
                    return self.cancel_invoice(hash, &format!("refused: {problem}"));
                }
                Err(e) => return Err(e),
            };
            let invoice = decode(&receiving.request).map_err(|e| unavailable(provider, e))?;
            let of: [u8; 32] = *invoice.payment_hash().as_ref();
            // Exactly as offered: the payer pays no more than it was told.
            if of != *hash || invoice.amount_milli_satoshis() != Some(asks.saturating_mul(1000)) {
                return self
                    .cancel_invoice(hash, "its provider answered an invoice of another payment");
            }
            if let Some(memo) = &body.memo {
                if described(&invoice).as_ref() != Some(memo) {
                    return self
                        .cancel_invoice(hash, "its provider left the memo out of the invoice");
                }
            }
            self.store.write(|tx| {
                tx.execute(
                    "UPDATE invoices SET request = ?2 WHERE hash = ?1",
                    params![hash, invoice.to_string()],
                )?;
                Ok(())
            })?;
            tracing::info!(hash = %hex::encode(hash), %provider, "invoice made");
        }
        let status: ReceiveStatus = self.get(provider, &swaps::receive_state(hash)).await?;
        let lock = status.lock().map_err(|p| unavailable(provider, p))?;
        let lock = match (status.state, lock) {
            (ReceiveState::Open, _) => return Ok(()),
            (ReceiveState::Canceled, _) => {
                return self.cancel_invoice(hash, "canceled by its provider");
            }
            (_, None) => return Err(unavailable(provider, "a payment locked to no lock")),
            (_, Some(lock)) => lock,
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE invoices SET lock = ?2 WHERE hash = ?1",
                params![hash, lock.as_bytes()],
            )?;
            Ok(())
        })?;
        // The provider's lock at the hub, claimed as the hub's own would be.
        let lock = hex::encode(lock.as_bytes());
        match self.claim_paying(url, &lock, &preimage, amount).await {
            Ok(_) | Err(Error::AlreadyReceived) => {}
            Err(Error::Invalid(reason)) => return self.cancel_invoice(hash, &reason),
            Err(Error::PaysNothing) => {
                return self.cancel_invoice(hash, "its lock pays this wallet nothing");
            }
            Err(e) => return Err(e),
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE invoices SET done_at = ?2 WHERE hash = ?1 AND done_at IS NULL",
                params![hash, now()],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, %provider, amount, "invoice paid");
        Ok(())
    }

    fn cancel_invoice(&self, hash: &[u8; 32], reason: &str) -> Result<(), Error> {
        tracing::warn!(hash = %hex::encode(hash), reason, "invoice canceled");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE invoices SET canceled = ?2
                 WHERE hash = ?1 AND done_at IS NULL AND canceled IS NULL",
                params![hash, reason],
            )?;
            Ok(())
        })
    }

    /// The invoices asked for, newest first.
    pub fn invoices(&self) -> Result<Vec<Invoice>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "{INVOICES} ORDER BY i.created_at DESC, i.rowid DESC"
            ))?;
            let rows = stmt.query_map([], invoice_of)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    fn invoice_record(&self, hash: &[u8; 32]) -> Result<Invoice, Error> {
        self.store.read(|c| {
            c.query_row(&format!("{INVOICES} WHERE i.hash = ?1"), [hash], invoice_of)
                .optional()?
                .ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))
        })
    }

    /// The invoices under way, oldest first.
    pub(crate) fn open_invoices(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash FROM invoices WHERE done_at IS NULL AND canceled IS NULL
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}

const INVOICES: &str = "SELECT i.hash, r.url, i.amount, i.request, i.done_at IS NOT NULL,
    i.canceled, i.created_at, i.lock, i.done_at, i.protected, i.body
    FROM invoices i JOIN reach r ON r.hub = i.hub";

fn invoice_of(r: &Row<'_>) -> rusqlite::Result<Invoice> {
    let state = match (r.get::<_, bool>(4)?, r.get::<_, Option<String>>(5)?) {
        (_, Some(reason)) => InvoiceState::Canceled(reason),
        (true, None) => InvoiceState::Received,
        (false, None) => InvoiceState::Open,
    };
    Ok(Invoice {
        hash: hex::encode(r.get::<_, [u8; 32]>(0)?),
        hub: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        request: r.get(3)?,
        state,
        created_at: r.get(6)?,
        lock: r.get::<_, Option<[u8; 32]>>(7)?.map(hex::encode),
        received_at: r.get(8)?,
        protected: r.get(9)?,
        // As asked of a hub or a provider: an older wallet's asked none.
        memo: {
            let body = r.get::<_, String>(10)?;
            match serde_json::from_str::<Receive>(&body) {
                Ok(asked) => asked.memo,
                Err(_) => serde_json::from_str::<ReceiveRequest>(&body)
                    .ok()
                    .and_then(|asked| asked.memo),
            }
        },
    })
}
