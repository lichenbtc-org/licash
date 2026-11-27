//! Paying an LNURL-pay code (LUD-06) or a Lightning Address (LUD-16): the
//! payee's service is asked what it takes ([`Wallet::lnurl_pay_request`]),
//! then for an invoice of the amount chosen ([`Wallet::lnurl_invoice`]),
//! which is paid as any ([`Wallet::read_invoice`]). The invoice is checked
//! before it is handed back: of the wallet's network, asking exactly the
//! amount asked, and committing to the metadata the service showed, so the
//! service can't swap what is paid for.
//!
//! Only over HTTPS, or HTTP to an onion service, which Tor authenticates
//! (or on regtest), as the wallet reaches anyone else.

use bitcoin::hashes::{sha256, Hash};
use lightning_invoice::Bolt11InvoiceDescriptionRef;
use serde::Deserialize;

use crate::{Error, Transport, Wallet};
use licash::spend::ChainProfile;

/// What an LNURL-pay service takes, as it answered: in millisatoshis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayRequest {
    /// Where its invoices are asked for.
    pub callback: String,
    pub min_msat: u64,
    pub max_msat: u64,
    /// Its metadata, as it sent it: an invoice commits to its hash.
    pub metadata: String,
    /// What it says is paid for, in words, if it says.
    pub description: Option<String>,
    /// Whom it pays: the Lightning Address, or the service's host.
    pub payee: String,
}

impl PayRequest {
    /// The least whole satoshis it takes.
    pub fn min_sat(&self) -> u64 {
        self.min_msat.div_ceil(1000)
    }

    /// The most whole satoshis it takes.
    pub fn max_sat(&self) -> u64 {
        self.max_msat / 1000
    }
}

/// Where the LNURL-pay code or Lightning Address `text` says to ask what
/// it takes, and whom it names: none if it is neither. Read as a payer
/// pastes or scans it: a bech32 `lnurl1…`, as is or after `lightning:`,
/// an `lnurlp://` URL (LUD-17), or `name@domain`. On regtest, a service
/// of `network` is asked over HTTP, at any host.
pub fn pay_target(text: &str, network: ChainProfile) -> Option<(String, String)> {
    let local = network == ChainProfile::Core30DefaultRegtest;
    let scheme = |host: &str| {
        if onion(host) || local {
            "http"
        } else {
            "https"
        }
    };
    let text = text.trim();
    let text = strip_prefix_ci(text, "lightning:").unwrap_or(text);
    if strip_prefix_ci(text, "lnurl1").is_some() {
        let (hrp, data) = bitcoin::bech32::decode(text).ok()?;
        if !hrp.as_str().eq_ignore_ascii_case("lnurl") {
            return None;
        }
        let url = String::from_utf8(data).ok()?;
        let host = host_of(&url)?.to_owned();
        return Some((url, host));
    }
    if let Some(rest) = strip_prefix_ci(text, "lnurlp://") {
        let host = rest.split(['/', '?']).next()?;
        return Some((format!("{}://{rest}", scheme(host)), host.to_owned()));
    }
    let (name, domain) = text.split_once('@')?;
    let name = name.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    let named = !name.is_empty()
        && (name.bytes()).all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b));
    let host = domain.split(':').next().unwrap_or(&domain);
    let reachable = (host.contains('.') || local)
        && !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && (domain.bytes()).all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b));
    if !named || !reachable {
        return None;
    }
    let url = format!("{}://{domain}/.well-known/lnurlp/{name}", scheme(host));
    Some((url, format!("{name}@{domain}")))
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// The host of `url`, without its port: none if it names none.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then_some(host)
}

fn onion(host: &str) -> bool {
    host.to_ascii_lowercase().ends_with(".onion")
}

/// `url`, if the wallet asks it: over HTTPS, or HTTP to an onion service
/// or on regtest.
fn reachable(url: &str, network: ChainProfile) -> Result<(), Error> {
    let lower = url.to_ascii_lowercase();
    let host = host_of(url).ok_or_else(|| Error::Invalid(format!("not a URL: {url}")))?;
    let plain = lower.starts_with("http://");
    if lower.starts_with("https://")
        || (plain && (onion(host) || network == ChainProfile::Core30DefaultRegtest))
    {
        return Ok(());
    }
    Err(Error::Invalid(format!(
        "an LNURL must be asked over HTTPS, or HTTP to an onion service: not {url}"
    )))
}

/// An LNURL answer: what was asked, or why not.
#[derive(Deserialize)]
#[serde(untagged)]
enum Answer<A> {
    Refused { status: String, reason: String },
    Answered(A),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PayRequestJson {
    tag: String,
    callback: String,
    min_sendable: u64,
    max_sendable: u64,
    metadata: String,
}

#[derive(Deserialize)]
struct InvoiceJson {
    pr: String,
}

/// LNURL-pay.
impl<T: Transport> Wallet<T> {
    /// What the payee of the LNURL-pay code or Lightning Address `text`
    /// takes, its service asked: refused if `text` is neither, or its
    /// service isn't one paid with.
    pub async fn lnurl_pay_request(&self, text: &str) -> Result<PayRequest, Error> {
        let (url, payee) = pay_target(text, self.network())
            .ok_or_else(|| Error::Invalid("neither an LNURL nor a Lightning Address".into()))?;
        let asked: PayRequestJson = self.lnurl_get(&url).await?;
        if asked.tag != "payRequest" {
            return Err(Error::Invalid(format!(
                "an LNURL of another kind than a payment: {}",
                asked.tag
            )));
        }
        if asked.min_sendable > asked.max_sendable || asked.max_sendable < 1000 {
            return Err(Error::Invalid(format!(
                "{payee} takes no amount: {} to {} msat",
                asked.min_sendable, asked.max_sendable
            )));
        }
        reachable(&asked.callback, self.network())?;
        Ok(PayRequest {
            description: described(&asked.metadata),
            callback: asked.callback,
            min_msat: asked.min_sendable,
            max_msat: asked.max_sendable,
            metadata: asked.metadata,
            payee,
        })
    }

    /// An invoice of `sat` from the service of `pay`, checked: of the
    /// wallet's network, unexpired, asking exactly `sat`, and committing
    /// to the metadata it showed. The invoice, as text.
    pub async fn lnurl_invoice(&self, pay: &PayRequest, sat: u64) -> Result<String, Error> {
        let msat = sat
            .checked_mul(1000)
            .ok_or_else(|| Error::Invalid("too much".into()))?;
        if !(pay.min_msat..=pay.max_msat).contains(&msat) {
            return Err(Error::Invalid(format!(
                "{} takes {} to {} sat",
                pay.payee,
                pay.min_sat(),
                pay.max_sat()
            )));
        }
        let joint = if pay.callback.contains('?') { '&' } else { '?' };
        let url = format!("{}{joint}amount={msat}", pay.callback);
        let answered: InvoiceJson = self.lnurl_get(&url).await?;
        let invoice = crate::lightning::decode(&answered.pr)?;
        let asked = self.payable(&invoice)?;
        if asked != msat {
            return Err(Error::Invalid(format!(
                "{} answered an invoice of {asked} msat, not the {msat} asked",
                pay.payee
            )));
        }
        let hash = sha256::Hash::hash(pay.metadata.as_bytes());
        let committed = match invoice.description() {
            Bolt11InvoiceDescriptionRef::Hash(h) => h.0 == hash,
            Bolt11InvoiceDescriptionRef::Direct(_) => false,
        };
        if !committed {
            return Err(Error::Invalid(format!(
                "{} answered an invoice not for what it showed",
                pay.payee
            )));
        }
        Ok(invoice.to_string())
    }

    /// The LNURL answer at `url`: refused if the service refuses.
    async fn lnurl_get<A: serde::de::DeserializeOwned>(&self, url: &str) -> Result<A, Error> {
        reachable(url, self.network())?;
        let host = host_of(url).unwrap_or(url).to_owned();
        let response = (self.transport.request(url, None).await)
            .map_err(|reason| crate::unavailable(&host, reason))?;
        let answer = serde_json::from_slice::<Answer<A>>(&response.body);
        match answer {
            Ok(Answer::Refused { status, reason }) if status.eq_ignore_ascii_case("ERROR") => {
                Err(Error::Invalid(format!("{host} refused: {reason}")))
            }
            Ok(Answer::Answered(a)) if (200..300).contains(&response.status) => Ok(a),
            _ => Err(Error::Invalid(format!(
                "{host} answered no LNURL payment (HTTP {})",
                response.status
            ))),
        }
    }
}

/// What LNURL metadata says is paid for, in words: its `text/plain`.
fn described(metadata: &str) -> Option<String> {
    let entries: Vec<(String, serde_json::Value)> = serde_json::from_str(metadata).ok()?;
    entries
        .into_iter()
        .find(|(kind, _)| kind == "text/plain")
        .and_then(|(_, v)| v.as_str().map(str::to_owned))
        .filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lnurl(url: &str) -> String {
        let hrp = bitcoin::bech32::Hrp::parse("lnurl").unwrap();
        bitcoin::bech32::encode_upper::<bitcoin::bech32::Bech32>(hrp, url.as_bytes()).unwrap()
    }

    #[test]
    fn an_lnurl_or_a_lightning_address_says_where_to_ask() {
        let url = "https://pay.example/lnurlp/alice";
        let code = lnurl(url);
        let main = ChainProfile::Core30Mainnet;
        let at = |t: &str| pay_target(t, main);
        let expected = Some((url.to_owned(), "pay.example".to_owned()));
        assert_eq!(at(&code), expected);
        assert_eq!(at(&code.to_lowercase()), expected);
        assert_eq!(at(&format!("lightning:{code}")), expected);
        assert_eq!(at(&format!("LIGHTNING:{code}")), expected);
        assert_eq!(at(&format!("  {code}\n")), expected);
        assert_eq!(
            at("Alice@Pay.Example"),
            Some((
                "https://pay.example/.well-known/lnurlp/alice".into(),
                "alice@pay.example".into()
            ))
        );
        assert_eq!(
            at("lightning:bob.smith+tips@pay.example:8443"),
            Some((
                "https://pay.example:8443/.well-known/lnurlp/bob.smith+tips".into(),
                "bob.smith+tips@pay.example:8443".into()
            ))
        );
        // An onion service, over HTTP: Tor authenticates it.
        assert_eq!(
            at("alice@abc.onion").map(|(u, _)| u),
            Some("http://abc.onion/.well-known/lnurlp/alice".into())
        );
        assert_eq!(
            at("lnurlp://pay.example/lnurlp/alice?x=1").map(|(u, _)| u),
            Some("https://pay.example/lnurlp/alice?x=1".into())
        );
        // Neither.
        for text in [
            "",
            "alice",
            "@pay.example",
            "alice@",
            "alice@localhost",
            "alice@pay.example/x",
            "al ice@pay.example",
            "lnurl1notbech32",
            "lnbc1qqqq",
            "https://pay.example",
            "lnürl1",
            "é@pay.example",
        ] {
            assert_eq!(pay_target(text, main), None, "{text}");
        }
        // On regtest, over HTTP, at any host.
        assert_eq!(
            pay_target("alice@swaps:8080", ChainProfile::Core30DefaultRegtest).map(|(u, _)| u),
            Some("http://swaps:8080/.well-known/lnurlp/alice".into())
        );
    }

    #[test]
    fn an_lnurl_is_asked_over_https_or_to_an_onion_service() {
        let main = ChainProfile::Core30Mainnet;
        assert!(reachable("https://pay.example/x", main).is_ok());
        assert!(reachable("http://abc.onion/x", main).is_ok());
        assert!(reachable("http://pay.example/x", main).is_err());
        assert!(reachable("ftp://pay.example/x", main).is_err());
        assert!(reachable("http://bridge:8080/x", ChainProfile::Core30DefaultRegtest).is_ok());
    }

    #[test]
    fn what_is_paid_for_is_the_metadatas_plain_text() {
        let metadata =
            r#"[["text/plain","Tips for Alice"],["text/identifier","alice@pay.example"]]"#;
        assert_eq!(described(metadata), Some("Tips for Alice".into()));
        assert_eq!(described(r#"[["text/identifier","a@b.c"]]"#), None);
        assert_eq!(described("not json"), None);
    }
}
