//! How the applications reach hubs and swap providers: HTTP(S), directly,
//! through a proxy such as Tor's SOCKS port, or, with the `tor` feature,
//! through a Tor client of their own.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::Context;
use licash_wallet::{Response, Transport};

/// How long an onion service standing in for a hub has to open a stream
/// before the hub's own URL is asked instead, still over Tor.
#[cfg(feature = "tor")]
const ONION_OPEN: Duration = Duration::from_secs(30);

/// How long an onion service whose stream did not open is passed over.
const ONION_RESTS: Duration = Duration::from_secs(10 * 60);

/// How long a host that did not answer is passed over in the background
/// ([`licash_wallet::in_background`]), by how many times in a row: the
/// last for every time after. Asked by someone waiting, it is asked still.
const RESTS: [Duration; 4] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
];

/// How long the fastest answer of a host stands for how fast it answers:
/// one taking longer replaces it after.
const FASTEST_FOR: Duration = Duration::from_secs(5 * 60);

/// The most an answer may hold: far above any grant.
const MAX_ANSWER: usize = 4 << 20;

/// How long a [`Transport::download`] may take: its answer is large.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(900);

/// How long an answer may take, but for sending a large body.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// A body larger than this is given time to be sent ([`sending`]).
const LARGE_BODY: usize = 1 << 20;

/// The slowest a large body is sent, in bytes a second: Tor's slowest
/// circuits, from a phone.
const SLOWEST_SEND: usize = 32 << 10;

/// How long POSTing `bytes` and its answer may take, if that is longer
/// than a client's own: an instance of a contract's opening, 25 MB, has
/// 15 minutes.
fn sending(bytes: usize) -> Option<Duration> {
    let secs = (bytes / SLOWEST_SEND) as u64;
    (bytes > LARGE_BODY).then(|| ANSWER_TIMEOUT + Duration::from_secs(secs))
}

/// A wallet's [`Transport`] over HTTP(S).
pub struct Http {
    route: Route,
    onions: Onions,
    hosts: Hosts,
}

/// How each host answered, by origin.
#[derive(Default)]
struct Hosts(Mutex<HashMap<String, Host>>);

#[derive(Default)]
struct Host {
    /// How many requests in a row got no answer, and when the last.
    unanswered: Option<(usize, Instant)>,
    /// The fastest answer lately, and when.
    fastest: Option<(Duration, Instant)>,
}

impl Hosts {
    /// How much longer `origin` rests at `now`, if it does: passed over
    /// in the background since it did not answer.
    fn left(&self, origin: &str, now: Instant) -> Option<Duration> {
        let hosts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (times, since) = hosts.get(origin)?.unanswered?;
        let rest = RESTS[(times - 1).min(RESTS.len() - 1)];
        (since + rest)
            .checked_duration_since(now)
            .filter(|left| !left.is_zero())
    }

    /// That `origin` answered at `now` in `took`, or did not (None): then
    /// it rests longer.
    fn answered(&self, origin: &str, took: Option<Duration>, now: Instant) {
        let mut hosts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let host = hosts.entry(origin.to_owned()).or_default();
        let Some(took) = took else {
            let times = host.unanswered.map_or(0, |(times, _)| times);
            host.unanswered = Some((times + 1, now));
            return;
        };
        host.unanswered = None;
        let faster = host.fastest.is_none_or(|(fastest, at)| {
            took <= fastest || now.saturating_duration_since(at) >= FASTEST_FOR
        });
        if faster {
            host.fastest = Some((took, now));
        }
    }

    /// The fastest `origin` answered within [`FASTEST_FOR`] of `now`.
    fn fastest(&self, origin: &str, now: Instant) -> Option<Duration> {
        let hosts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (took, at) = hosts.get(origin)?.fastest?;
        (now.saturating_duration_since(at) < FASTEST_FOR).then_some(took)
    }
}

/// The scheme, host and port of `url`, as hosts rest by.
fn origin(url: &str) -> &str {
    let after = url.find("://").map_or(0, |i| i + 3);
    let end = url[after..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after + i);
    &url[..end]
}

/// Onion services standing in for hubs' own URLs, over Tor only: by the
/// hub's URL, the onion service's and when a stream to it last did not
/// open.
#[derive(Default)]
struct Onions(Mutex<HashMap<String, (String, Option<Instant>)>>);

impl Onions {
    /// `onion` for the hub at `base`, if both are as [`Http::set_onion`]
    /// takes them, the one known kept otherwise; none if None: whether
    /// taken. The same again keeps resting if it rests.
    fn set(&self, base: &str, onion: Option<&str>) -> bool {
        let base = base.trim_end_matches('/');
        let mut onions = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(onion) = onion else {
            onions.remove(base);
            return false;
        };
        // Not for a hub over plain HTTP: what it says of itself crosses a
        // Tor exit unauthenticated, and its URLs are not in its proof.
        let usable = !base.contains(char::is_whitespace)
            && base.starts_with("https://")
            && !onion_host(base);
        let Some(onion) = onion_url(onion).filter(|_| usable) else {
            return false;
        };
        if onions.get(base).is_none_or(|(known, _)| *known != onion) {
            onions.insert(base.to_owned(), (onion, None));
        }
        true
    }

    /// For `url`, the hub's URL it is under, the longest, and `url` at the
    /// onion service standing in for it, unless that one rests since it
    /// did not open.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    fn route(&self, url: &str, now: Instant) -> Option<(String, String)> {
        let onions = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (base, (onion, unopened), rest) = onions
            .iter()
            .filter_map(|(base, known)| {
                let rest = url.strip_prefix(base.as_str())?;
                rest.starts_with('/').then_some((base, known, rest))
            })
            .max_by_key(|(base, _, _)| base.len())?;
        let resting = unopened.is_some_and(|at| now.saturating_duration_since(at) < ONION_RESTS);
        (!resting).then(|| (base.clone(), format!("{onion}{rest}")))
    }

    /// That a stream to the onion service for `base` did not open at `now`.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    fn unopened(&self, base: &str, now: Instant) {
        let mut onions = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, unopened)) = onions.get_mut(base) {
            *unopened = Some(now);
        }
    }
}

/// `url` if that of an onion service as a hub names its own: `http://`, a
/// v3 address and a port at most, no path; in lower case, without a
/// trailing `/`.
fn onion_url(url: &str) -> Option<String> {
    let url = url.trim().to_ascii_lowercase();
    let rest = url.strip_prefix("http://")?.trim_end_matches('/');
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let address = host.strip_suffix(".onion")?;
    let v3 = address.len() == 56
        && address
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    let port = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p > 0));
    (v3 && port).then(|| format!("http://{rest}"))
}

/// Whether the host of `url` is an onion service.
fn onion_host(url: &str) -> bool {
    let host = url.split("://").nth(1).unwrap_or(url);
    let host = host.split(['/', ':', '?', '#']).next().unwrap_or(host);
    host.to_ascii_lowercase().ends_with(".onion")
}

enum Route {
    Direct(reqwest::Client),
    #[cfg(feature = "tor")]
    Tor(licash_tor::Tor),
}

impl Http {
    /// Through `proxy` if given, e.g. `socks5h://127.0.0.1:9050`, else
    /// directly: never through a proxy the environment names unasked.
    pub fn new(proxy: Option<&str>) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(90))
            .user_agent(concat!("licash/", env!("CARGO_PKG_VERSION")));
        client = match proxy {
            Some(proxy) => client.proxy(reqwest::Proxy::all(proxy).context("the proxy URL")?),
            None => client.no_proxy(),
        };
        // Android's verifier needs the application's Java side: Mozilla's
        // roots instead, as for Tor.
        #[cfg(target_os = "android")]
        {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client = client.tls_backend_preconfigured(tls);
        }
        Ok(Self {
            route: Route::Direct(client.build()?),
            onions: Onions::default(),
            hosts: Hosts::default(),
        })
    }

    /// Through `tor`, a Tor client of the application's own, to onion
    /// services and to the clear web alike.
    #[cfg(feature = "tor")]
    pub fn tor(tor: licash_tor::Tor) -> Self {
        Self {
            route: Route::Tor(tor),
            onions: Onions::default(),
            hosts: Hosts::default(),
        }
    }

    /// Reach the hub at `base` at `onion` instead, an onion service it
    /// names as its own, while over Tor: back at `base`, still over Tor,
    /// when a stream to `onion` does not open, and for a while after. None
    /// forgets the one known. Whether taken, the one known kept if not:
    /// never directly, nor for a `base` that is an onion service itself,
    /// nor an `onion` but `http://`, a v3 address and a port at most, nor
    /// a `base` but `https://`. Only for a hub the caller trusts, of what
    /// it said of itself: an onion service named by anyone else could
    /// stand in for the hub. One that opens but is not the hub's stays
    /// until set otherwise, its answers going to the caller.
    pub fn set_onion(&self, base: &str, onion: Option<&str>) -> bool {
        !matches!(self.route, Route::Direct(_)) && self.onions.set(base, onion)
    }

    /// How much longer the host of `url` is passed over in the background,
    /// since it did not answer, if it is.
    pub fn resting(&self, url: &str) -> Option<Duration> {
        self.hosts.left(origin(url), Instant::now())
    }

    /// How fast the host of `url` answers: its fastest answer of the last
    /// minutes, a round trip on a connection or circuit already open
    /// rather than one opened for it. None if it answered none lately.
    pub fn answers_in(&self, url: &str) -> Option<Duration> {
        self.hosts.fastest(origin(url), Instant::now())
    }
}

impl Transport for Http {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        // A large body on circuits of its own, as a download: sent beside
        // others to the same host.
        let timeout = body.as_ref().and_then(|b| sending(b.len()));
        let origin = origin(url).to_owned();
        let exchange = self.exchange(url, body, MAX_ANSWER, timeout, timeout.is_some());
        // A host not answering lately: passed over in the background, not
        // waited on again for minutes, each answer or none told.
        async move {
            if licash_wallet::in_background_now() {
                if let Some(left) = self.hosts.left(&origin, Instant::now()) {
                    return Err(format!(
                        "{origin} did not answer lately, asked again in {} s",
                        left.as_millis().div_ceil(1000)
                    ));
                }
            }
            let asked = Instant::now();
            let answer = exchange.await;
            let took = answer.is_ok().then(|| asked.elapsed());
            self.hosts.answered(&origin, took, Instant::now());
            answer
        }
    }

    fn download(
        &self,
        url: &str,
        max: usize,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        // Over Tor on circuits of its own: one carries only so much, and
        // downloads run beside each other.
        self.exchange(url, None, max, Some(DOWNLOAD_TIMEOUT), true)
    }

    /// As if it did not answer: passed over in the background a while.
    fn gave_up(&self, url: &str) {
        self.hosts.answered(origin(url), None, Instant::now());
    }
}

/// What went wrong of a request, with why, which reqwest tells apart: a
/// timeout, a connection refused or reset ("error sending request" alone
/// says none of it). Without its URL, which the caller names.
fn failed(e: reqwest::Error) -> String {
    let e = e.without_url();
    let mut said = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(why) = source {
        let told = why.to_string();
        if !said.contains(&told) {
            said = format!("{said}: {told}");
        }
        source = why.source();
    }
    said
}

impl Http {
    /// `body` POSTed to `url`, or a GET: an answer of at most `max` bytes,
    /// in `timeout` if given rather than the client's own. Over Tor on
    /// circuits of its own if `apart` ([`licash_tor::Tor::apart`]).
    #[cfg_attr(not(feature = "tor"), allow(clippy::infallible_destructuring_match))]
    #[cfg_attr(not(feature = "tor"), allow(unused_variables))]
    fn exchange(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        max: usize,
        timeout: Option<Duration>,
        apart: bool,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send + '_ {
        let client = match &self.route {
            Route::Direct(client) => client,
            #[cfg(feature = "tor")]
            Route::Tor(tor) => {
                let tor = if apart { tor.apart() } else { tor.clone() };
                let url = url.to_owned();
                let downloading = apart;
                let timeout = timeout.unwrap_or(licash_tor::TIMEOUT);
                let onion = self.onions.route(&url, Instant::now());
                // Boxed: Arti's futures are too deep a type to nest in the
                // callers'.
                let tor: futures_util::future::BoxFuture<'_, _> = Box::pin(async move {
                    // In the wallet's lane as it is first polled
                    // ([`licash_wallet::in_lane`]): a download on circuits
                    // of its own already.
                    let lane = licash_wallet::current_lane().filter(|_| !downloading);
                    let tor = tor.in_lane(lane);
                    if let Some((base, at)) = onion {
                        let opened =
                            tor.request_opened(&at, body.clone(), max, ONION_OPEN, timeout);
                        match opened.await {
                            Ok((status, body)) => return Ok(Response { status, body }),
                            // Its onion service may have had it: not again.
                            Err(licash_tor::Failed::Sent(why)) => return Err(why),
                            Err(licash_tor::Failed::Unsent(why)) => {
                                tracing::info!(%base, %why, "its onion service did not open, asking its own URL");
                                self.onions.unopened(&base, Instant::now());
                            }
                        }
                    }
                    let (status, body) = tor.request_for(&url, body, max, timeout).await?;
                    Ok(Response { status, body })
                });
                return futures_util::future::Either::Left(tor);
            }
        };
        let mut request = match body {
            Some(body) => client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body),
            None => client.get(url),
        };
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let direct = async move {
            let mut response = request.send().await.map_err(failed)?;
            let status = response.status().as_u16();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(failed)? {
                if body.len() + chunk.len() > max {
                    return Err(format!("an answer over {max} bytes"));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Response { status, body })
        };
        #[cfg(feature = "tor")]
        let direct = futures_util::future::Either::Right(direct);
        direct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v3() -> String {
        format!("{}.onion", "a2".repeat(28))
    }

    #[test]
    fn only_a_v3_onion_services_http_url_with_a_port_at_most_stands_in() {
        let host = v3();
        assert_eq!(
            onion_url(&format!("http://{host}")),
            Some(format!("http://{host}"))
        );
        assert_eq!(
            onion_url(&format!(" HTTP://{}:8338/ ", host.to_uppercase())),
            Some(format!("http://{host}:8338"))
        );
        for refused in [
            format!("https://{host}"),
            format!("http://{host}/v1"),
            format!("http://{host}:0"),
            format!("http://{host}:99999"),
            format!("http://user@{host}"),
            format!("http://{}.onion", "a".repeat(16)),
            format!("http://{}.onion", "1".repeat(56)),
            "http://hub.example".into(),
            "https://hub.example/x.onion".into(),
        ] {
            assert_eq!(onion_url(&refused), None, "{refused}");
        }
        assert!(onion_host(&format!("http://{host}:80/v1")));
        assert!(!onion_host("https://onion.example/a.onion"));
    }

    #[test]
    fn a_hubs_requests_go_to_its_onion_service_but_while_it_rests() {
        let onions = Onions::default();
        let (base, onion) = ("https://hub.example", format!("http://{}", v3()));
        // An onion service stands in for none of an onion service.
        assert!(!onions.set(
            &onion,
            Some(&format!("http://{}", "b".repeat(56) + ".onion"))
        ));
        assert!(!onions.set(base, Some("https://hub.example")));
        let now = Instant::now();
        assert_eq!(onions.route(&format!("{base}/v1/info"), now), None);

        assert!(onions.set(&format!("{base}/"), Some(&onion)));
        let routed = onions.route(&format!("{base}/v1/info"), now);
        assert_eq!(routed, Some((base.to_owned(), format!("{onion}/v1/info"))));
        // A hub over plain HTTP: none.
        assert!(!onions.set("http://plain.example", Some(&onion)));
        assert_eq!(onions.route("http://plain.example/v1/info", now), None);
        // Only under its URL exactly.
        assert_eq!(onions.route("https://hub.example.evil/v1/info", now), None);
        assert_eq!(onions.route("https://hub.example:8443/v1/info", now), None);
        assert_eq!(onions.route(base, now), None);

        // Not opened: its own URL for a while, though set again.
        onions.unopened(base, now);
        assert_eq!(onions.route(&format!("{base}/v1/info"), now), None);
        assert!(onions.set(base, Some(&onion)));
        let later = now + ONION_RESTS - Duration::from_secs(1);
        assert_eq!(onions.route(&format!("{base}/v1/info"), later), None);
        let rested = now + ONION_RESTS;
        assert!(onions.route(&format!("{base}/v1/info"), rested).is_some());

        // One not taken keeps the one known; none forgets it.
        assert!(!onions.set(base, Some("http://hub.example")));
        assert!(onions.route(&format!("{base}/v1"), rested).is_some());
        assert!(!onions.set(base, None));
        assert_eq!(onions.route(&format!("{base}/v1"), rested), None);
    }

    #[test]
    fn a_hub_under_another_hubs_url_goes_to_its_own_onion_service() {
        let onions = Onions::default();
        let (outer, inner) = (
            format!("http://{}", v3()),
            format!("http://{}", "b".repeat(56)),
        );
        let inner = format!("{inner}.onion");
        assert!(onions.set("https://hub.example", Some(&outer)));
        assert!(onions.set("https://hub.example/b", Some(&inner)));
        let now = Instant::now();
        for _ in 0..8 {
            let routed = onions.route("https://hub.example/b/v1/info", now);
            assert_eq!(
                routed,
                Some(("https://hub.example/b".into(), format!("{inner}/v1/info")))
            );
        }
        // Its own resting, the other's is not taken instead.
        onions.unopened("https://hub.example/b", now);
        assert_eq!(onions.route("https://hub.example/b/v1/info", now), None);
        let routed = onions.route("https://hub.example/v1/info", now);
        assert_eq!(
            routed,
            Some(("https://hub.example".into(), format!("{outer}/v1/info")))
        );
    }

    #[test]
    fn a_large_body_has_the_time_to_be_sent_over_tor() {
        assert_eq!(sending(0), None);
        assert_eq!(sending(LARGE_BODY), None);
        let instance = sending(25_024_328).unwrap();
        assert_eq!(instance, ANSWER_TIMEOUT + Duration::from_secs(763));
        assert!(sending(LARGE_BODY + 1).unwrap() > ANSWER_TIMEOUT);
    }

    /// A server at a local port answering every request with `len` bytes,
    /// as fast as they are read.
    fn answering(len: usize) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let _ = stream.read(&mut [0; 4096]);
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&vec![b'0'; len]);
            }
        });
        url
    }

    /// Whatever a hub, or anyone on the path to it, answers, a wallet holds
    /// at most [`MAX_ANSWER`] bytes of it, and a download at most its own.
    #[tokio::test]
    async fn an_answer_too_large_is_refused_before_it_is_held() {
        let http = Http::new(None).unwrap();
        let url = answering(MAX_ANSWER);
        let answer = http.request(&url, None).await.unwrap();
        assert_eq!(answer.body.len(), MAX_ANSWER);
        let url = answering(MAX_ANSWER + 1);
        let refused = http.request(&url, None).await.unwrap_err();
        assert!(refused.contains("an answer over"), "{refused}");
        let refused = http.request(&url, Some(b"{}".to_vec())).await.unwrap_err();
        assert!(refused.contains("an answer over"), "{refused}");
        let url = answering(1001);
        let refused = http.download(&url, 1000).await.unwrap_err();
        assert!(refused.contains("an answer over 1000 bytes"), "{refused}");
    }

    #[test]
    fn a_host_not_answering_rests_longer_each_time_until_it_answers() {
        assert_eq!(
            origin("https://hub.example:8443/v1/info?x=1"),
            "https://hub.example:8443"
        );
        assert_eq!(origin("http://abc.onion"), "http://abc.onion");
        let hosts = Hosts::default();
        let (hub, now) = ("https://hub.example", Instant::now());
        assert_eq!(hosts.left(hub, now), None);
        for (times, rest) in RESTS.iter().chain([&RESTS[3]]).enumerate() {
            let at = now + Duration::from_secs(1000 * times as u64);
            hosts.answered(hub, None, at);
            assert_eq!(hosts.left(hub, at), Some(*rest));
            assert_eq!(
                hosts.left(hub, at + *rest - Duration::from_secs(1)),
                Some(Duration::from_secs(1))
            );
            assert_eq!(hosts.left(hub, at + *rest), None);
            assert_eq!(hosts.left("https://other.example", at), None);
        }
        hosts.answered(hub, Some(Duration::from_secs(2)), now);
        assert_eq!(hosts.left(hub, now), None);
        hosts.answered(hub, None, now);
        assert_eq!(hosts.left(hub, now), Some(RESTS[0]));
    }

    #[test]
    fn a_host_answers_as_fast_as_its_fastest_answer_lately() {
        let hosts = Hosts::default();
        let (hub, now) = ("https://hub.example", Instant::now());
        let ms = Duration::from_millis;
        assert_eq!(hosts.fastest(hub, now), None);
        // A circuit opened for the first: the next, on it, is the round trip.
        hosts.answered(hub, Some(ms(30_000)), now);
        hosts.answered(hub, Some(ms(900)), now);
        hosts.answered(hub, Some(ms(4_000)), now + ms(1_000));
        assert_eq!(hosts.fastest(hub, now + ms(1_000)), Some(ms(900)));
        // Not answering keeps it; minutes later, a slower one replaces it.
        hosts.answered(hub, None, now + ms(2_000));
        assert_eq!(hosts.fastest(hub, now + ms(2_000)), Some(ms(900)));
        let later = now + FASTEST_FOR;
        assert_eq!(hosts.fastest(hub, later), None);
        hosts.answered(hub, Some(ms(1_500)), later);
        assert_eq!(hosts.fastest(hub, later), Some(ms(1_500)));
    }

    /// Asked in the background, a host that did not answer is passed over
    /// at once while it rests; asked by someone waiting, it is asked still.
    #[tokio::test]
    async fn a_host_not_answering_is_passed_over_in_the_background_only() {
        let http = Http::new(None).unwrap();
        // A port nothing listens at.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/info", closed.local_addr().unwrap());
        drop(closed);
        let refused = http.request(&url, None).await.unwrap_err();
        assert!(!refused.contains("did not answer lately"), "{refused}");
        let passed = licash_wallet::in_background(http.request(&url, None))
            .await
            .unwrap_err();
        assert!(
            passed.contains("did not answer lately, asked again in 30 s"),
            "{passed}"
        );
        assert!(http.resting(&url).is_some());
        let asked = http.request(&url, None).await.unwrap_err();
        assert!(!asked.contains("did not answer lately"), "{asked}");
        // Answering again: asked in the background at once.
        let host = answering(2);
        http.hosts.answered(&host, None, Instant::now());
        let answer = http
            .request(&format!("{host}/v1/info"), None)
            .await
            .unwrap();
        assert_eq!(answer.status, 200);
        assert!(http.answers_in(&format!("{host}/")).is_some());
        assert_eq!(http.answers_in(&url), None);
        assert!(licash_wallet::in_background(http.request(&host, None))
            .await
            .is_ok());
    }

    /// One the wallet stopped waiting on rests as one that did not answer.
    #[tokio::test]
    async fn a_host_given_up_on_rests_as_one_not_answering() {
        let http = Http::new(None).unwrap();
        let host = answering(1);
        let url = format!("{host}/v1/chain/tweaks?from=1&count=144");
        http.gave_up(&url);
        let resting = http.resting(&format!("{host}/v1/info")).unwrap();
        assert!(resting > RESTS[0] - Duration::from_secs(5), "{resting:?}");
        let passed = licash_wallet::in_background(http.request(&url, None))
            .await
            .unwrap_err();
        assert!(passed.contains("did not answer lately"), "{passed}");
        assert_eq!(http.request(&url, None).await.unwrap().status, 200);
        assert_eq!(http.resting(&url), None);
    }

    #[test]
    fn a_direct_transport_takes_no_onion_service() {
        let http = Http::new(None).unwrap();
        let onion = format!("http://{}", v3());
        assert!(!http.set_onion("https://hub.example", Some(&onion)));
    }
}
