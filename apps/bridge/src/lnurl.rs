//! Lightning Addresses (LUD-16) of the accounts naming one, paid over
//! LNURL-pay (LUD-06), verified (LUD-21), and zapped (NIP-57): an invoice
//! committing to the address's metadata, or to the zap request it pays,
//! whose receipt the bridge publishes once paid. Served where the bridge's
//! public URL says, if it does ([`crate::Config::public_url`]).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{Extensions, HeaderMap},
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

/// The most invoices of an account's address unpaid and unexpired: past
/// them its callback refuses, so that anyone asking for many fills only
/// that address, not the bridge's room at its hub.
pub(crate) const MAX_UNPAID: u32 = 64;

/// The most addresses of an `X-Forwarded-For` the bridge passes on, its
/// caller's own added: as many as a hub reads.
const MAX_FORWARDED: usize = 16;

/// The `X-Forwarded-For` the bridge sends its hub for a caller at `peer`:
/// those `headers` forward for (if each is a bare IP address, and but a
/// few), then `peer`, as a proxy appends its client. A hub that trusts the
/// bridge (and any proxy before it) counts each caller apart; one that
/// does not reads no forwarded address of the bridge's.
fn forwarded_for(headers: &HeaderMap, peer: IpAddr) -> String {
    let mut chain = Vec::new();
    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            chain.clear();
            break;
        };
        chain.extend(value.split(',').map(|hop| hop.trim().parse::<IpAddr>()));
    }
    // A hop that does not parse makes none of them trusted.
    let mut chain: Vec<IpAddr> = chain
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    if chain.len() >= MAX_FORWARDED {
        chain.clear();
    }
    chain.push(peer.to_canonical());
    let chain: Vec<String> = chain.iter().map(IpAddr::to_string).collect();
    chain.join(", ")
}

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

/// The relays the zap request `event` names, at most [`ZAP_RELAYS`]: those
/// a payer may have the bridge connect to ([`public_relay`]) alone.
fn zap_relays(event: &Event) -> Vec<RelayUrl> {
    event
        .tags
        .iter()
        .filter(|t| t.as_slice().first().is_some_and(|k| k == "relays"))
        .flat_map(|t| t.as_slice().iter().skip(1).cloned().collect::<Vec<_>>())
        .filter_map(|r| RelayUrl::parse(&r).ok())
        .filter(public_relay)
        .take(ZAP_RELAYS)
        .collect()
}

/// Whether `relay`, which anyone paying an address may name, is one the
/// bridge publishes to: over TLS (`wss://`), at a public address or a
/// domain of the public DNS, so that no payer has it reach a service of
/// its own network, or an onion service, which it would reach in the
/// clear. A domain is not resolved: one of the public DNS pointing at a
/// private address is still reached, over TLS to that domain.
fn public_relay(relay: &RelayUrl) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use nostr::types::url::Host;
    fn public_v4(ip: Ipv4Addr) -> bool {
        let [a, b, ..] = ip.octets();
        !(ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || ip.is_multicast()
            || ip.is_documentation()
            || a == 0
            // Shared (carrier-grade NAT), 100.64.0.0/10.
            || (a == 100 && (b & 0xc0) == 64)
            // Reserved, 240.0.0.0/4.
            || a >= 240)
    }
    fn public_v6(ip: Ipv6Addr) -> bool {
        if let IpAddr::V4(v4) = IpAddr::V6(ip).to_canonical() {
            return public_v4(v4);
        }
        let first = ip.segments()[0];
        !(ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            // Unique local, fc00::/7, and link-local, fe80::/10.
            || (first & 0xfe00) == 0xfc00
            || (first & 0xffc0) == 0xfe80)
    }
    if relay.scheme() != nostr::types::url::RelayUrlScheme::Wss {
        return false;
    }
    match relay.host() {
        Some(Host::Ipv4(ip)) => public_v4(ip),
        Some(Host::Ipv6(ip)) => public_v6(ip),
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            let local = [".localhost", ".onion", ".local", ".internal", ".home.arpa"];
            domain.contains('.')
                && domain != "home.arpa"
                && !local.iter().any(|suffix| domain.ends_with(suffix))
        }
        None => false,
    }
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

    /// What an invoice of its provider may ask, in msat:
    /// at least and at most.
    fn sendable(&self) -> Result<(u64, u64), Error> {
        let terms = self.receiving()?;
        let asks = |notes: u64| (notes + terms.fee.due(notes)).saturating_mul(1000);
        let mut most = asks(terms.max);
        if let Some(max) = self.config.max_balance {
            most = most.min(max);
        }
        Ok((asks(terms.min.max(1)), most))
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
        let unpaid = (self.store).read(|c| crate::store::unpaid_addressed(c, id, crate::now()))?;
        if unpaid >= MAX_UNPAID {
            return Err(Error::Quota(format!(
                "{MAX_UNPAID} invoices of this address are unpaid: later"
            )));
        }
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
                 Query(q): Query<Callback>,
                 headers: HeaderMap,
                 extensions: Extensions| async move {
                    let paid = b.pay_address(&name, q.amount, q.nostr.as_deref(), q.comment.as_deref());
                    // Its invoice asked of the hub for the caller, served
                    // over TCP: counted as theirs by a hub trusting the
                    // bridge as its proxy.
                    let lnurl_ = match extensions.get::<ConnectInfo<SocketAddr>>() {
                        Some(ConnectInfo(peer)) => {
                            let chain = forwarded_for(&headers, peer.ip());
                            licash_transport::forwarding_for(chain, paid).await
                        }
                        None => paid.await,
                    };
                    lnurl(lnurl_)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        headers
    }

    /// A zap request names relays the bridge connects to: those of its own
    /// network, the bridge's host, or onion services are dropped, and
    /// those unencrypted, so that a payer reaches no service of the
    /// bridge's through it.
    #[test]
    fn a_zap_publishes_to_public_relays_alone() {
        let public = |url: &str| public_relay(&RelayUrl::parse(url).unwrap());
        for url in [
            "wss://relay.example.com",
            "wss://relay.example.com:7777/path",
            "wss://8.8.8.8",
            "wss://[2001:4860::8888]",
            "wss://100.128.0.1",
            "wss://RELAY.Example.COM.",
        ] {
            assert!(public(url), "{url}");
        }
        for url in [
            "ws://relay.example.com",
            "wss://localhost:8080",
            "wss://LocalHost.",
            "wss://relay.localhost",
            "wss://127.0.0.1",
            "wss://10.0.0.1",
            "wss://172.16.5.4",
            "wss://192.168.1.1:4869",
            "wss://169.254.169.254",
            "wss://100.64.0.1",
            "wss://0.0.0.0",
            "wss://255.255.255.255",
            "wss://[::1]",
            "wss://[::]",
            "wss://[::ffff:127.0.0.1]",
            "wss://[::ffff:10.0.0.1]",
            "wss://[fd00::1]",
            "wss://[fe80::1]",
            "wss://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
            "wss://printer.local",
            "wss://metadata.google.internal",
            "wss://relay",
        ] {
            assert!(!public(url), "{url}");
        }
    }

    /// A zap request's relays, the private ones dropped, and at most so
    /// many: none left, the bridge's own are used (as the receipt says).
    #[test]
    fn a_zap_requests_relays_are_its_public_ones_at_most_so_many() {
        use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
        let request = |relays: &[&str]| {
            EventBuilder::new(Kind::ZapRequest, "")
                .tag(Tag::custom("relays", relays.iter().copied()))
                .finalize(&Keys::generate())
                .unwrap()
        };
        let named = zap_relays(&request(&[
            "wss://127.0.0.1:9735",
            "wss://one.example",
            "ws://two.example",
            "not a url",
            "wss://two.example",
        ]));
        let named: Vec<_> = named.iter().map(RelayUrl::as_str).collect();
        assert_eq!(named, ["wss://one.example", "wss://two.example"]);
        assert!(zap_relays(&request(&["wss://localhost"])).is_empty());
        let many: Vec<_> = (0..ZAP_RELAYS + 3)
            .map(|n| format!("wss://r{n}.example"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(zap_relays(&request(&many)).len(), ZAP_RELAYS);
    }

    /// The caller is always last, as its proxy appends it: a hub walking
    /// from the right stops at it unless it trusts it, so no caller names
    /// another.
    #[test]
    fn a_caller_is_forwarded_for_after_those_it_forwards_for() {
        let peer: IpAddr = "198.51.100.2".parse().unwrap();
        assert_eq!(forwarded_for(&headers(&[]), peer), "198.51.100.2");
        assert_eq!(
            forwarded_for(&headers(&["203.0.113.7", "192.0.2.1, 192.0.2.9"]), peer),
            "203.0.113.7, 192.0.2.1, 192.0.2.9, 198.51.100.2"
        );
        // An IPv4 peer over IPv6 is that IPv4 address.
        let mapped: IpAddr = "::ffff:198.51.100.2".parse().unwrap();
        assert_eq!(forwarded_for(&headers(&[]), mapped), "198.51.100.2");
        // Malformed, or too long, what it forwards for is dropped.
        for odd in ["203.0.113.7:80", "unknown", &["192.0.2.1"; 16].join(",")] {
            assert_eq!(
                forwarded_for(&headers(&[odd]), peer),
                "198.51.100.2",
                "{odd}"
            );
        }
    }
}
