//! Lightning invoices paid through swap providers announced on Nostr: the
//! provider pays an invoice from its own node for a lock of the wallet's
//! notes at a hub, and claims the lock with the preimage the payment buys.
//! The app pays the cheapest; hubs pay no invoices. A payment through a
//! provider that fails returns its notes only once its lock expires, which
//! the quote tells.
//!
//! And invoices the wallet is paid with through providers taking them, at
//! a hub trusted: the provider's node makes the invoice, and once paid
//! locks its notes to the wallet.

use licash_nostr::wallet::{
    deposit_providers_with, hub_relays, invoice_providers_with, receive_providers_with,
    DepositProvider, ReceiveProvider,
};
use licash_wallet::{Payable, SwapLimits};

use super::Wallet;
use crate::{Activity, InvoiceQuote, LicashError, LnurlPay, ViaProvider};

/// LNURL-pay codes and Lightning Addresses: an invoice asked of the
/// payee's service, then paid as any.
#[uniffi::export]
impl Wallet {
    /// What the payee of the LNURL-pay code or Lightning Address `text`
    /// takes, its service asked, over Tor if the wallet is.
    pub fn lnurl_pay(&self, text: String) -> Result<LnurlPay, LicashError> {
        let _timed = crate::log::timed("lnurl_pay");
        let asked = self.wallet.lnurl_pay_request(&text);
        Ok(LnurlPay::of(self.runtime.block_on(asked)?))
    }

    /// An invoice of `amount` from the service of `pay`, checked to ask
    /// exactly that, of the wallet's network, for what it showed: to pay
    /// as any ([`Wallet::invoice_quote`]).
    pub fn lnurl_invoice(&self, pay: LnurlPay, amount: u64) -> Result<String, LicashError> {
        let _timed = crate::log::timed("lnurl_invoice");
        let pay = pay.request();
        let asked = self.wallet.lnurl_invoice(&pay, amount);
        Ok(self.runtime.block_on(asked)?)
    }
}

/// Lightning invoices through providers.
#[uniffi::export]
impl Wallet {
    /// The ways to pay the Lightning invoice `text` with the notes held
    /// now, the cheapest first: through each swap provider announced on
    /// the relays the hubs name that pays it for a lock at a hub holding
    /// enough. Refused if none can: hubs pay no invoices.
    pub fn invoice_offers(&self, text: String) -> Result<Vec<InvoiceQuote>, LicashError> {
        let _timed = crate::log::timed("invoice_offers");
        let invoice = self.wallet.read_invoice(&text)?;
        let mut offers = self.provider_offers(&invoice)?;
        offers.sort_by_key(|o| o.fee);
        if offers.is_empty() {
            return Err(LicashError::invalid(super::NO_PAYER));
        }
        Ok(offers)
    }

    /// Pay the Lightning invoice `text` through the swap provider at
    /// `provider`, from notes at `hub`, its fee at most `max_fee` and the
    /// hub's on the lock at most `lock_fee` more in all, as
    /// [`Wallet::invoice_offers`] quoted them ([`crate::ViaProvider`]):
    /// under way until [`Wallet::resume`] finds its lock paid, or refunded
    /// once expired if the payment failed. Should it fail before any lock
    /// is made, the other ways to pay it costing no more in all are tried,
    /// the cheapest first, as quoted from the providers' terms kept: its
    /// fee risen is the owner's to accept instead.
    pub fn pay_invoice_via(
        &self,
        text: String,
        hub: String,
        provider: String,
        max_fee: u64,
        lock_fee: u64,
    ) -> Result<Activity, LicashError> {
        let _timed = crate::log::timed("pay_invoice_via");
        let invoice = self.wallet.read_invoice(&text)?;
        let most = max_fee.saturating_add(lock_fee);
        let locked = || -> Result<Vec<String>, LicashError> {
            Ok(self.wallet.locks()?.into_iter().map(|l| l.id).collect())
        };
        let before = locked()?;
        let pay = |provider: &str, hub: &str, max_fee| {
            let request = &invoice.request;
            let pay =
                (self.wallet).pay_invoice_via_within(provider, hub, request, max_fee, Some(most));
            self.operation(pay)
        };
        let e = match pay(&provider, &hub, max_fee) {
            Ok(lock) => return Ok(super::lightning_activity(&lock, &invoice.request)),
            Err(e) => e,
        };
        if matches!(e, licash_wallet::Error::FeeRose { .. }) || locked()? != before {
            return Err(e.into());
        }
        tracing::info!(%provider, "paying the invoice failed, nothing locked: {e}");
        let others = self.invoice_offers(text).unwrap_or_default();
        let others = others
            .into_iter()
            .filter(|o| o.fee <= most && (o.provider.url != provider || o.hub != hub));
        for other in others {
            match pay(&other.provider.url, &other.hub, other.provider.fee) {
                Ok(lock) => return Ok(super::lightning_activity(&lock, &invoice.request)),
                Err(again) if locked()? != before => return Err(again.into()),
                Err(again) => {
                    let through = &other.provider.url;
                    tracing::info!(%through, "paying the invoice failed, nothing locked: {again}");
                }
            }
        }
        Err(e.into())
    }
}

impl Wallet {
    /// What paying `invoice` costs through each swap provider announced
    /// that pays it, from each hub trusted holding at least what it asks:
    /// none if no hub names relays, or none answers.
    fn provider_offers(&self, invoice: &Payable) -> Result<Vec<InvoiceQuote>, LicashError> {
        let relays = hub_relays(&self.wallet)?;
        if relays.is_empty() {
            return Ok(Vec::new());
        }
        let max_fee = SwapLimits::usual(invoice.amount).fee;
        let mut offers = Vec::new();
        for balance in self.wallet.balance()? {
            if balance.available <= invoice.amount {
                continue;
            }
            let found = invoice_providers_with(
                &self.wallet,
                &self.announced,
                (&relays, &self.route),
                &balance.hub,
                &invoice.request,
                max_fee,
            );
            let found = match self.operation(found) {
                Ok(found) => found,
                Err(e) => {
                    tracing::info!(hub = %balance.hub, "no provider pays the invoice: {e:#}");
                    continue;
                }
            };
            offers.extend(found.into_iter().map(|p| InvoiceQuote {
                hub: balance.hub.clone(),
                amount: invoice.amount,
                fee: p.quote.costs(),
                description: invoice.description.clone(),
                provider: ViaProvider {
                    url: p.url,
                    name: p.name,
                    fee: p.quote.fee,
                    lock_fee: p.quote.lock_fee,
                    refund_blocks: p.quote.refund_blocks,
                },
            }));
        }
        Ok(offers)
    }
}

/// Getting paid through providers.
#[uniffi::export]
impl Wallet {
    /// Whether a swap provider announced has the wallet paid over Lightning
    /// at a hub trusted now ([`Wallet::ask_invoice`]): asked of the relays
    /// the hubs name, and each provider.
    pub fn provider_takes_lightning(&self) -> Result<bool, LicashError> {
        let _timed = crate::log::timed("provider_takes_lightning");
        Ok(!self.receive_offers()?.is_empty())
    }
}

impl Wallet {
    /// Each swap provider announced that has the wallet paid over Lightning
    /// now, at each hub trusted: none if no hub names relays.
    fn receive_offers(&self) -> Result<Vec<(String, ReceiveProvider)>, LicashError> {
        let relays = hub_relays(&self.wallet)?;
        let mut offers = Vec::new();
        if relays.is_empty() {
            return Ok(offers);
        }
        for (hub, _) in self.wallet.hubs()? {
            let found =
                receive_providers_with(&self.wallet, &self.announced, (&relays, &self.route), &hub);
            match self.operation(found) {
                Ok(found) => offers.extend(found.into_iter().map(|p| (hub.clone(), p))),
                Err(e) => {
                    tracing::info!(%hub, "no provider takes payments over Lightning: {e:#}");
                }
            }
        }
        Ok(offers)
    }

    /// The swap providers announced on the relays the hubs name that take
    /// deposits on Bitcoin for notes at each hub trusted, with the hub: none
    /// if the hubs name no relays.
    pub(super) fn deposit_offers(&self) -> Result<Vec<(String, DepositProvider)>, LicashError> {
        let relays = hub_relays(&self.wallet)?;
        let mut offers = Vec::new();
        if relays.is_empty() {
            return Ok(offers);
        }
        for (hub, _) in self.wallet.hubs()? {
            let found =
                deposit_providers_with(&self.wallet, &self.announced, (&relays, &self.route), &hub);
            match self.operation(found) {
                Ok(found) => offers.extend(found.into_iter().map(|p| (hub.clone(), p))),
                Err(e) => {
                    tracing::info!(%hub, "no provider takes deposits on Bitcoin: {e:#}");
                }
            }
        }
        Ok(offers)
    }

    /// Ask the swap provider announced that has the wallet paid over
    /// Lightning at a hub trusted for least for an invoice paying the wallet
    /// `amount`, or, `invoiced`, asking the payer `amount`, its fee in it:
    /// None if no provider takes it.
    pub(super) fn provider_invoice(
        &self,
        amount: u64,
        invoiced: bool,
        memo: Option<&str>,
    ) -> Result<Option<Result<licash_wallet::Invoice, licash_wallet::Error>>, LicashError> {
        // Its fee, what it pays the wallet, at which hub, through which.
        let mut best: Option<(u64, u64, String, String)> = None;
        for (hub, provider) in self.receive_offers()? {
            let (terms, max) = (&provider.offer.terms, provider.offer.max);
            let paid = match invoiced {
                true => super::before_fee(&terms.fee, amount),
                false => amount,
            };
            if paid == 0 || !(terms.min..=max).contains(&paid) {
                continue;
            }
            let fee = terms.fee.due(paid);
            if best.as_ref().is_none_or(|(least, ..)| fee < *least) {
                best = Some((fee, paid, hub, provider.url));
            }
        }
        let Some((_, paid, hub, provider)) = best else {
            return Ok(None);
        };
        let asked = self.wallet.invoice_through(&provider, &hub, paid, memo);
        Ok(Some(self.operation(asked)))
    }
}
