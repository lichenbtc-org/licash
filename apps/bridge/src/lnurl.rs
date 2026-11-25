//! Lightning Addresses (LUD-16) of the accounts naming one, paid over
//! LNURL-pay (LUD-06), verified (LUD-21), and zapped (NIP-57): an invoice
//! committing to the address's metadata, or to the zap request it pays,
//! whose receipt the bridge publishes once paid. Served where the bridge's
//! public URL says, if it does ([`crate::Config::public_url`]).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use licash_api::bridge::State as Settled;
use licash_wallet::Transport;
use nostr::prelude::{Event, EventBuilder, FinalizeEvent, Kind, RelayUrl, Tag, Timestamp};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{key_hex, sha256, Bridge, Error};

/// The most characters of a comment a payer may send (LUD-12).
const COMMENT: usize = 255;

/// The most relays a zap receipt is published to, of those its request
/// names.
const ZAP_RELAYS: usize = 8;

/// The host, and port if any, of `url`: what its Lightning Addresses are
/// at.
pub(crate) fn domain(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split('/').next().filter(|h| !h.is_empty())?;
    Some(host.to_ascii_lowercase())
}

/// `name` as a Lightning Address's, or why not.
pub(crate) fn username(name: &str) -> Result<String, Error> {
    let name = name.trim().to_ascii_lowercase();
    let fits = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
    if !fits {
        return Err(Error::Invalid(
            "a name of 1 to 64 of a-z, 0-9, '-', '_' and '.'".into(),
        ));
    }
    Ok(name)
}

/// The metadata of `name@domain`, as served and as its invoices commit to.
fn metadata(address: &str) -> String {
    json!([
        ["text/plain", format!("Pay {address}")],
        ["text/identifier", address],
    ])
    .to_string()
}

/// The zap request `nostr` pays, if one, for `amount` msat: valid as
/// NIP-57 has it, or why not.
fn zap_request(nostr: &str, amount: u64) -> Result<Event, Error> {
    let invalid = |why: &str| Error::Invalid(format!("not a zap request: {why}"));
    let event = Event::from_json(nostr).map_err(|_| invalid("no event"))?;
    if event.kind != Kind::ZapRequest {
        return Err(invalid("not of kind 9734"));
    }
    event
        .verify()
        .map_err(|_| invalid("not signed by its key"))?;
    let tags = |kind: &str| {
        event
            .tags
            .iter()
            .filter(|t| t.as_slice().first().is_some_and(|k| k == kind))
            .count()
    };
    if tags("p") != 1 {
        return Err(invalid("not of one recipient"));
    }
    if tags("e") > 1 {
        return Err(invalid("of several events"));
    }
    if tags("relays") == 0 {
        return Err(invalid("naming no relays"));
    }
    let asked = event
        .tags
        .iter()
        .find(|t| t.as_slice().first().is_some_and(|k| k == "amount"))
        .and_then(|t| t.as_slice().get(1).cloned());
    if let Some(asked) = asked {
        if asked.parse::<u64>().ok() != Some(amount) {
            return Err(invalid("of another amount"));
        }
    }
    Ok(event)
}

/// The relays the zap request `event` names, at most [`ZAP_RELAYS`].
fn zap_relays(event: &Event) -> Vec<RelayUrl> {
    event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().is_some_and(|k| k == "relays"))
        .flat_map(|t| t.as_slice().iter().skip(1).cloned().collect::<Vec<_>>())
        .filter_map(|r| RelayUrl::parse(&r).ok())
        .take(ZAP_RELAYS)
        .collect()
}

/// A zap receipt to publish: its event, the relays to publish it to, and
/// the invoice it is of.
pub struct ZapReceipt {
    pub event: Event,
    pub relays: Vec<RelayUrl>,
    pub hash: [u8; 32],
    /// When its invoice was paid.
    pub settled_at: i64,
}

impl<T: Transport> Bridge<T> {
    /// The domain of its Lightning Addresses, if it serves them.
    pub fn lightning_domain(&self) -> Option<String> {
        self.config.public_url.as_deref().and_then(domain)
    }

    /// Name the Lightning Address of `key`'s account `username`, or none.
    pub fn set_username(
        &self,
        key: &[u8; 32],
        name: Option<&str>,
    ) -> Result<licash_api::bridge::Account, Error> {
        if self.lightning_domain().is_none() {
            return Err(Error::Restricted(
                "this bridge serves no Lightning Address".into(),
            ));
        }
        let id = self.account_id(key)?;
        let name = name.map(username).transpose()?;
        self.store
            .write(|tx| crate::store::set_username(tx, id, name.as_deref()))?;
        self.account(key)
    }

    /// The account of `name`, and its address.
    fn addressed(&self, name: &str) -> Result<(i64, String), Error> {
        let domain = self
            .lightning_domain()
            .ok_or_else(|| Error::NotFound("no Lightning Address here".into()))?;
        let name = username(name)?;
        let account = self
            .store
            .read(|c| crate::store::account_named(c, &name))?
            .ok_or_else(|| Error::NotFound(format!("no {name}@{domain}")))?;
        Ok((account.id, format!("{name}@{domain}")))
    }

    /// What an invoice of its hub may ask, in msat: at least and at most.
    fn sendable(&self) -> Result<(u64, u64), Error> {
        let hub = &self.config.hub;
        let urls = self.wallet.hub_urls(hub).map_err(crate::wallet_error)?;
        let hubs = self.wallet.hubs().map_err(crate::wallet_error)?;
        let terms = hubs
            .into_iter()
            .find(|(url, _)| urls.contains(url))
            .and_then(|(_, info)| info.lightning)
            .ok_or_else(|| Error::Unavailable(format!("hub {hub} takes no Lightning payments")))?;
        let asks = |notes: u64| (notes + terms.receive.due(notes)).saturating_mul(1000);
        let mut most = asks(terms.max_receive);
        if let Some(max) = self.config.max_balance {
            most = most.min(max);
        }
        Ok((asks(terms.min_receive.max(1)), most))
    }

    /// The LNURL-pay request of the address of `name` (LUD-06).
    pub fn pay_request(&self, name: &str) -> Result<Value, Error> {
        let (_, address) = self.addressed(name)?;
        let (least, most) = self.sendable()?;
        let base = self.config.public_url.as_deref().unwrap_or_default();
        let name = username(name)?;
        Ok(json!({
            "tag": "payRequest",
            "callback": format!("{}/lnurlp/{name}/callback", base.trim_end_matches('/')),
            "minSendable": least,
            "maxSendable": most.max(least),
            "metadata": metadata(&address),
            "commentAllowed": COMMENT,
            "allowsNostr": true,
            "nostrPubkey": self.keys.public_key().to_hex(),
        }))
    }

    /// An invoice of `amount` msat paying the address of `name`, for the
    /// zap request `nostr` if given, saying `comment` if given (LUD-12).
    pub async fn pay_address(
        &self,
        name: &str,
        amount: u64,
        nostr: Option<&str>,
        comment: Option<&str>,
    ) -> Result<Value, Error> {
        let (id, address) = self.addressed(name)?;
        let (least, most) = self.sendable()?;
        if amount < least || amount > most {
            return Err(Error::Invalid(format!(
                "{amount} msat: {least} to {most} msat are taken"
            )));
        }
        let comment = comment
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(|c| c.chars().take(COMMENT).collect::<String>());
        let (hash, zap) = match nostr {
            Some(nostr) => {
                zap_request(nostr, amount)?;
                (sha256(nostr.as_bytes()), Some(nostr.to_owned()))
            }
            None => (sha256(metadata(&address).as_bytes()), None),
        };
        let receipt = self
            .receive(id, None, amount, comment.as_deref(), Some(hash), zap)
            .await?;
        let base = self.config.public_url.as_deref().unwrap_or_default();
        let name = username(name)?;
        Ok(json!({
            "pr": receipt.invoice,
            "routes": [],
            "verify": format!(
                "{}/lnurlp/{name}/verify/{}",
                base.trim_end_matches('/'),
                hex::encode(receipt.hash)
            ),
        }))
    }

    /// Whether the invoice of `hash`, paying the address of `name`, was
    /// paid (LUD-21).
    pub fn verify_address(&self, name: &str, hash: &str) -> Result<Value, Error> {
        let (id, _) = self.addressed(name)?;
        let hash = key_hex(hash)?;
        let receipt = self
            .store
            .read(|c| crate::store::receipt(c, &hash))?
            .filter(|r| r.account == id)
            .ok_or_else(|| Error::NotFound("no such invoice".into()))?;
        Ok(json!({
            "status": "OK",
            "settled": receipt.state == Settled::Settled,
            "preimage": null,
            "pr": receipt.invoice,
        }))
    }

    /// The receipts of the zaps paid that are not published yet (NIP-57),
    /// signed by the bridge's Nostr key.
    pub fn zap_receipts(&self) -> Result<Vec<ZapReceipt>, Error> {
        let due = self.store.read(crate::store::zaps_due)?;
        let mut receipts = Vec::new();
        for receipt in due {
            let Some(zap) = &receipt.zap else { continue };
            let settled_at = receipt.settled_at.unwrap_or(receipt.created_at);
            let request = match Event::from_json(zap) {
                Ok(request) => request,
                Err(_) => {
                    self.zap_published(&receipt.hash)?;
                    continue;
                }
            };
            // The description as the request came, which the invoice
            // commits to, not as parsed and written again.
            let mut tags = vec![
                Tag::custom("bolt11", [receipt.invoice.clone()]),
                Tag::custom("description", [zap.clone()]),
            ];
            for kind in ["e", "a", "p"] {
                let found = request
                    .tags
                    .iter()
                    .find(|t| t.as_slice().first().is_some_and(|k| k == kind));
                if let Some(tag) = found {
                    tags.push(tag.clone());
                }
            }
            tags.push(Tag::custom("P", [request.pubkey.to_hex()]));
            let event = EventBuilder::new(Kind::ZapReceipt, "")
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(settled_at.max(0) as u64))
                .finalize(&self.keys)
                .map_err(|e| Error::Unavailable(format!("signing a zap receipt: {e}")))?;
            let mut relays = zap_relays(&request);
            if relays.is_empty() {
                relays = self
                    .config
                    .relays
                    .iter()
                    .filter_map(|r| RelayUrl::parse(r).ok())
                    .collect();
            }
            receipts.push(ZapReceipt {
                event,
                relays,
                hash: receipt.hash,
                settled_at,
            });
        }
        Ok(receipts)
    }

    /// The receipt of the zap paying the invoice of `hash` published, or
    /// given up on: not published again.
    pub fn zap_published(&self, hash: &[u8; 32]) -> Result<(), Error> {
        self.store.write(|tx| crate::store::zap_sent(tx, hash))
    }
}

/// An LNURL answer: its body, or `{"status": "ERROR", "reason"}`.
fn lnurl(answer: Result<Value, Error>) -> Response {
    match answer {
        Ok(body) => Json(body).into_response(),
        Err(e) => Json(json!({ "status": "ERROR", "reason": e.to_string() })).into_response(),
    }
}

#[derive(Deserialize)]
struct Callback {
    amount: u64,
    nostr: Option<String>,
    comment: Option<String>,
}

/// The routes of its Lightning Addresses: none unless it serves them.
pub(crate) fn router<T: Transport + 'static>(bridge: Arc<Bridge<T>>) -> Router {
    if bridge.lightning_domain().is_none() {
        return Router::new();
    }
    Router::new()
        .route(
            "/.well-known/lnurlp/{name}",
            get(
                |State(b): State<Arc<Bridge<T>>>, Path(name): Path<String>| async move {
                    lnurl(b.pay_request(&name))
                },
            ),
        )
        .route(
            "/lnurlp/{name}/callback",
            get(
                |State(b): State<Arc<Bridge<T>>>,
                 Path(name): Path<String>,
                 Query(q): Query<Callback>| async move {
                    let paid = b.pay_address(&name, q.amount, q.nostr.as_deref(), q.comment.as_deref());
                    lnurl(paid.await)
                },
            ),
        )
        .route(
            "/lnurlp/{name}/verify/{hash}",
            get(
                |State(b): State<Arc<Bridge<T>>>, Path((name, hash)): Path<(String, String)>| async move {
                    lnurl(b.verify_address(&name, &hash))
                },
            ),
        )
        .with_state(bridge)
}
