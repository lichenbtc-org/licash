//! Who asks the hub for an unpaid deposit or Lightning receipt, as its
//! ingress tells: the source each is counted against ([`PER_SOURCE`]).
//!
//! Resolved once per request, by [`resolve`] in the router, before any
//! handler: an onion service's circuit first (every stream of one
//! rendezvous is one source, another circuit another), else the address
//! of the TCP peer, its port left out, or, where that peer is a proxy the
//! operator trusts ([`Ingress`]), the client its `X-Forwarded-For` names.
//! An address is one source however many connections it opens, so a NAT's
//! users share one; one with many addresses (a botnet, an IPv6 block) is
//! bounded by the gateways' global caps alone.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{request::Parts, HeaderMap},
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use licash_api::Problem;

use crate::Failure;

/// The deposits, and apart the Lightning receipts, asked and not paid from
/// one [`AdmissionSource`] that the hub takes at most.
pub const PER_SOURCE: u32 = 8;

/// The most addresses an `X-Forwarded-For` from a trusted proxy may name:
/// more is refused as malformed, not read.
pub const MAX_FORWARDED: usize = 16;

/// The header a trusted proxy names its clients in, as Traefik writes it.
pub const FORWARDED_FOR: &str = "x-forwarded-for";

/// Where a request for a deposit or a receipt comes from, as stored with
/// it: `onion ` and its circuit's 16 bytes, or `ip ` and the client's
/// address (IPv4, or exact IPv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionSource(Vec<u8>);

impl AdmissionSource {
    pub fn of_circuit(circuit: &licash_tor::Circuit) -> Self {
        Self([b"onion ".as_slice(), &circuit.0].concat())
    }

    /// The client at `ip`: an IPv4 address mapped into IPv6 is that IPv4
    /// address.
    pub fn of_ip(ip: IpAddr) -> Self {
        Self(format!("ip {}", ip.to_canonical()).into_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// What releases before this one stored for this source: `tcp `, the
    /// peer's address and its port, `[::ffff:a.b.c.d]` for an IPv4 peer
    /// over an IPv6 socket. A stored value starting with one of these was
    /// asked from this address, and counts against it. None but for an
    /// address.
    pub(crate) fn legacy_prefixes(&self) -> [Option<Vec<u8>>; 2] {
        let Some(ip) = self.0.strip_prefix(b"ip ") else {
            return [None, None];
        };
        let Some(ip) = std::str::from_utf8(ip).ok().and_then(|s| s.parse().ok()) else {
            return [None, None];
        };
        let prefix = |s: String| Some(s.into_bytes());
        match ip {
            IpAddr::V4(v4) => [
                prefix(format!("tcp {v4}:")),
                prefix(format!("tcp [{}]:", v4.to_ipv6_mapped())),
            ],
            IpAddr::V6(v6) => [prefix(format!("tcp [{v6}]:")), None],
        }
    }
}

/// The proxies in front of the hub it believes, by address or block:
/// `X-Forwarded-For` is read only from a peer among them.
#[derive(Clone, Debug, Default)]
pub struct Ingress {
    trusted: Vec<IpNet>,
}

impl Ingress {
    pub fn new(trusted: Vec<IpNet>) -> Self {
        Self { trusted }
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The source of a request with these `parts`: none served in process;
    /// an error, said to the client, for a trusted proxy's malformed
    /// `X-Forwarded-For`.
    pub fn source(&self, parts: &Parts) -> Result<Option<AdmissionSource>, String> {
        if let Some(circuit) = parts.extensions.get::<licash_tor::Circuit>() {
            return Ok(Some(AdmissionSource::of_circuit(circuit)));
        }
        let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
            return Ok(None);
        };
        Ok(Some(AdmissionSource::of_ip(
            self.client(peer.ip(), &parts.headers)?,
        )))
    }

    /// The client behind the TCP peer `peer`: the peer itself unless it is
    /// trusted; else, from the right of the addresses `headers` forward
    /// for, the first not trusted (the leftmost if every one is). A trusted
    /// peer forwarding for none is the client.
    fn client(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, String> {
        let peer = peer.to_canonical();
        if !self.trusts(peer) {
            return Ok(peer);
        }
        let mut client = peer;
        for hop in forwarded(headers)?.into_iter().rev() {
            client = hop;
            if !self.trusts(hop) {
                break;
            }
        }
        Ok(client)
    }
}

/// The addresses of every `X-Forwarded-For` of `headers`, in order: each
/// an IP address alone (no port, no brackets), [`MAX_FORWARDED`] at most.
fn forwarded(headers: &HeaderMap) -> Result<Vec<IpAddr>, String> {
    let mut hops = Vec::new();
    for value in headers.get_all(FORWARDED_FOR) {
        let value = value
            .to_str()
            .map_err(|_| "X-Forwarded-For: not text".to_owned())?;
        for hop in value.split(',') {
            let hop = hop.trim();
            let ip: IpAddr = hop
                .parse()
                .map_err(|_| format!("X-Forwarded-For: {hop:?} is not an IP address"))?;
            hops.push(ip.to_canonical());
            if hops.len() > MAX_FORWARDED {
                return Err(format!(
                    "X-Forwarded-For: more than {MAX_FORWARDED} addresses"
                ));
            }
        }
    }
    Ok(hops)
}

/// What [`resolve`] found of a request's source.
#[derive(Clone, Debug)]
struct Resolved(Result<Option<AdmissionSource>, String>);

/// Middleware: the request's source, resolved once by `ingress` for the
/// handlers that admit by it ([`Admission`]).
pub async fn resolve(
    State(ingress): State<Arc<Ingress>>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let resolved = Resolved(ingress.source(&parts));
    parts.extensions.insert(resolved);
    next.run(Request::from_parts(parts, body)).await
}

/// The source a deposit or receipt is asked from, as [`resolve`] found it:
/// refused (invalid) where a trusted proxy forwarded a malformed chain.
/// Without [`resolve`] in front, as served in process, none.
pub struct Admission(pub Option<AdmissionSource>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Admission {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Failure> {
        match parts.extensions.get::<Resolved>() {
            None => Ok(Self(None)),
            Some(Resolved(Ok(source))) => Ok(Self(source.clone())),
            Some(Resolved(Err(why))) => Err(Failure(Problem::invalid(why.clone()))),
        }
    }
}

/// `s` as a proxy to trust: an address, or a block of them (CIDR).
pub fn trusted_proxy(s: &str) -> Result<IpNet, String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(IpNet::from(ip.to_canonical()));
    }
    s.parse::<IpNet>()
        .map_err(|_| format!("{s:?}: not an IP address or a CIDR block"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn parts(circuit: Option<[u8; 16]>, peer: Option<&str>, xff: &[&str]) -> Parts {
        let mut request = axum::http::Request::builder();
        if let Some(id) = circuit {
            request = request.extension(licash_tor::Circuit(id));
        }
        if let Some(peer) = peer {
            request = request.extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        for value in xff {
            request = request.header(FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        request.body(()).unwrap().into_parts().0
    }

    fn ingress(trusted: &[&str]) -> Ingress {
        Ingress::new(trusted.iter().map(|s| trusted_proxy(s).unwrap()).collect())
    }

    fn ip(s: &str) -> Option<AdmissionSource> {
        Some(AdmissionSource::of_ip(s.parse().unwrap()))
    }

    /// One address, however many ports it asks from, is one source; an
    /// IPv4 address over IPv6 is that address; IPv6 exact.
    #[test]
    fn a_clearnet_source_is_its_address_without_its_port() {
        let none = Ingress::default();
        let source = |peer| none.source(&parts(None, Some(peer), &[])).unwrap();
        assert_eq!(none.source(&parts(None, None, &[])).unwrap(), None);
        assert_eq!(source("127.0.0.1:1"), ip("127.0.0.1"));
        assert_eq!(source("127.0.0.1:1"), source("127.0.0.1:2"));
        assert_ne!(source("127.0.0.1:1"), source("127.0.0.2:1"));
        assert_eq!(source("[::ffff:10.0.0.1]:9"), ip("10.0.0.1"));
        assert_eq!(source("[2001:db8::1]:9"), ip("2001:db8::1"));
        assert_ne!(source("[2001:db8::1]:9"), source("[2001:db8::2]:9"));
    }

    /// A circuit before its connection: every stream of one rendezvous is
    /// one source, another circuit another, whatever it forwards for.
    #[test]
    fn an_onion_circuit_comes_before_its_connection() {
        let ingress = ingress(&["127.0.0.1"]);
        let circuit = AdmissionSource::of_circuit(&licash_tor::Circuit([7; 16]));
        let source = |c, xff: &[&str]| ingress.source(&parts(c, Some("127.0.0.1:1"), xff));
        assert_eq!(source(Some([7; 16]), &[]).unwrap(), Some(circuit.clone()));
        assert_eq!(source(Some([7; 16]), &["garbage"]).unwrap(), Some(circuit));
        assert_ne!(
            source(Some([7; 16]), &[]).unwrap(),
            source(Some([8; 16]), &[]).unwrap()
        );
    }

    /// An untrusted peer is its own client, whatever it says it forwards
    /// for, even a malformed header.
    #[test]
    fn an_untrusted_peers_forwarding_is_ignored() {
        let ingress = ingress(&["10.0.0.0/8"]);
        let source = |xff: &[&str]| ingress.source(&parts(None, Some("192.0.2.1:5"), xff));
        assert_eq!(source(&["198.51.100.7"]).unwrap(), ip("192.0.2.1"));
        assert_eq!(source(&["not an address"]).unwrap(), ip("192.0.2.1"));
    }

    /// From a trusted proxy, the first address from the right it does not
    /// trust: what a client wrote to the left of that is not believed.
    #[test]
    fn a_trusted_chain_is_walked_from_the_right() {
        let ingress = ingress(&["10.0.0.0/8", "2001:db8:ffff::/48"]);
        let source = |peer, xff: &[&str]| ingress.source(&parts(None, Some(peer), xff)).unwrap();
        // Traefik: the client it saw.
        assert_eq!(source("10.0.0.2:80", &["198.51.100.7"]), ip("198.51.100.7"));
        // A spoofed address left of it is the client's own claim.
        assert_eq!(
            source("10.0.0.2:80", &["1.1.1.1, 198.51.100.7"]),
            ip("198.51.100.7")
        );
        // Proxies in a row, in one header or several.
        assert_eq!(
            source("10.0.0.2:80", &["1.1.1.1, 198.51.100.7, 10.0.0.9"]),
            ip("198.51.100.7")
        );
        assert_eq!(
            source("10.0.0.2:80", &["1.1.1.1, 198.51.100.7", "10.0.0.9"]),
            ip("198.51.100.7")
        );
        // Every hop trusted: the leftmost; none forwarded: the proxy.
        assert_eq!(source("10.0.0.2:80", &["10.0.0.3"]), ip("10.0.0.3"));
        assert_eq!(source("10.0.0.2:80", &[]), ip("10.0.0.2"));
        // Mapped IPv4, for the peer and in the chain.
        assert_eq!(
            source("[::ffff:10.0.0.2]:80", &["::ffff:198.51.100.7"]),
            ip("198.51.100.7")
        );
        assert_eq!(
            source("[2001:db8:ffff::1]:80", &["2001:db8::7"]),
            ip("2001:db8::7")
        );
    }

    /// A trusted proxy's chain that does not parse, or is too long, is
    /// refused rather than read as some address.
    #[test]
    fn a_trusted_proxys_malformed_chain_is_refused() {
        let ingress = ingress(&["10.0.0.2"]);
        let source = |xff: &[&str]| ingress.source(&parts(None, Some("10.0.0.2:80"), xff));
        for bad in [
            "198.51.100.7:443",
            "[2001:db8::1]",
            "unknown",
            "",
            "1.1.1.1,,2.2.2.2",
        ] {
            assert!(source(&[bad]).is_err(), "{bad:?}");
        }
        let long = vec!["198.51.100.7"; MAX_FORWARDED + 1].join(",");
        assert!(source(&[&long]).is_err());
        let most = vec!["198.51.100.7"; MAX_FORWARDED].join(",");
        assert_eq!(source(&[&most]).unwrap(), ip("198.51.100.7"));
    }

    #[test]
    fn a_proxy_is_trusted_by_address_or_block() {
        assert_eq!(
            trusted_proxy("10.0.0.1").unwrap().to_string(),
            "10.0.0.1/32"
        );
        assert_eq!(
            trusted_proxy("::ffff:10.0.0.1").unwrap().to_string(),
            "10.0.0.1/32"
        );
        assert_eq!(
            trusted_proxy("10.1.2.3/8").unwrap().to_string(),
            "10.1.2.3/8"
        );
        assert!(ingress(&["10.1.2.3/8"]).trusts("10.200.0.1".parse().unwrap()));
        assert!(trusted_proxy("10.0.0.0/33").is_err());
        assert!(trusted_proxy("proxy").is_err());
    }

    /// An address counts the rows older releases stored for it, by peer
    /// and port, and no other address's.
    #[test]
    fn an_address_knows_what_older_releases_stored_for_it() {
        let prefixes = |s: &str| {
            AdmissionSource::of_ip(s.parse().unwrap())
                .legacy_prefixes()
                .map(|p| p.map(|p| String::from_utf8(p).unwrap()))
        };
        assert_eq!(
            prefixes("1.2.3.4"),
            [
                Some("tcp 1.2.3.4:".into()),
                Some("tcp [::ffff:1.2.3.4]:".into())
            ]
        );
        assert_eq!(
            prefixes("2001:db8::1"),
            [Some("tcp [2001:db8::1]:".into()), None]
        );
        let circuit = AdmissionSource::of_circuit(&licash_tor::Circuit([1; 16]));
        assert_eq!(circuit.legacy_prefixes(), [None, None]);
        // "tcp 1.2.3.4:" is no prefix of 1.2.3.45's.
        let legacy = format!("tcp {}", "1.2.3.45:80".parse::<SocketAddr>().unwrap());
        assert!(!legacy.starts_with(prefixes("1.2.3.4")[0].as_deref().unwrap()));
    }
}
