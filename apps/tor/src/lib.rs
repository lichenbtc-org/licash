//! Tor for the applications, through a Tor client of their own (Arti):
//! HTTP(S) requests and streams over it, to onion services and to the
//! clear web alike, and an axum router served as an onion service of their
//! own, each request carrying its [`licash_serve::Circuit`].
//!
//! Arti may end the process if the Tor network's consensus declares its
//! version obsolete.

mod serve;
mod socks;

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use arti_client::{config::TorClientConfigBuilder, IsolationToken, StreamPrefs, TorClient};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Bytes,
    client::conn::http1,
    header::{CONTENT_TYPE, HOST, USER_AGENT},
    Method, Request, Uri,
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{rustls, TlsConnector};
use tor_rtcompat::PreferredRuntime;

pub use serve::Onion;
pub use socks::Socks;

/// How long a request may take, its circuit included.
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// The most hosts kept apart at once: past it, they start over apart from
/// those before, as from a fresh client.
const MAX_ISOLATED: usize = 1024;

/// How long a connection to a host stays open, idle, for the next request
/// to it: a payment's few requests, one after the other, share one, and
/// so do the app's rounds, 20 s apart and more, and the steps an owner
/// takes a minute apart. A new one costs a stream and a TLS handshake over
/// Tor, a second or two, and to an onion service several.
const KEPT_FOR: Duration = Duration::from_secs(5 * 60);

/// How long a connection is used at all, since it opened: as long as Tor
/// gives a circuit new streams (its MaxCircuitDirtiness), so that a
/// connection kept links no more requests than its circuit would.
const OLDEST: Duration = Duration::from_secs(10 * 60);

/// The most idle connections kept open at once.
const MOST_KEPT: usize = 16;

/// How long an operation's connection stays open, idle: its next request
/// comes at once, if at all. Its operation over, it goes first.
const LANE_KEPT_FOR: Duration = Duration::from_secs(60);

/// The most operations' lanes told apart at once: past it, the least
/// lately used is forgotten.
const MOST_LANES: usize = 4096;

/// How long a spare lane of a host's is handed out, since it was made:
/// short of [`OLDEST`] and Tor's 10 min for an onion service's circuit
/// unused, so that the operation taking it finds it still open.
const SPARE_FOR: Duration = Duration::from_secs(8 * 60);

/// The most hosts kept a spare lane at once.
const MOST_SPARES: usize = 8;

/// Of each predicted port (443, the hubs' own), at least so many exit
/// circuits are built ahead, unused, for a wallet's operations to take
/// ([`Tor::for_wallet`]): Arti's default is 2.
const SPARE_CIRCUITS: usize = 3;

/// Past so many circuits open, the wallet's included, none are built
/// ahead: Arti's default of 12 is soon reached by operations' lanes, each
/// circuit used for up to 10 min.
const CIRCUITS_AHEAD_UP_TO: usize = 32;

/// How long a connection kept may take to be ready for the next request:
/// its own task taking in the last answer's end, not the network.
const READY: Duration = Duration::from_secs(1);

/// How long an answer may come with nothing more of it: then its circuit
/// is taken for gone, rather than waited on for the whole of a long
/// download's time (on signet one hung 15 min).
const STALLED: Duration = Duration::from_secs(60);

/// A Tor client, shared by its clones.
#[derive(Clone)]
pub struct Tor {
    client: Arc<TorClient<PreferredRuntime>>,
    tls: TlsConnector,
    isolation: Arc<Isolation>,
    kept: Arc<Kept>,
    spares: Arc<Spares>,
    /// The runtime it was made in, which spare lanes are made on: not
    /// whichever runtime a request happens to run on.
    runtime: Option<tokio::runtime::Handle>,
    /// Whether a [`Tor::bootstrap`] is under way.
    connecting: Arc<AtomicBool>,
    /// The operation whose lane this clone's streams keep to, if any
    /// ([`Tor::in_lane`]).
    lane: Option<u64>,
}

/// Which circuits streams may share: those to the same host only, so that
/// no exit or onion service sees two of them on one circuit, and no host
/// learns which others the application reaches; and of those, those of
/// the same operation's lane only, if in one ([`Tor::in_lane`]).
#[derive(Default)]
struct Isolation(Mutex<HashMap<String, IsolationToken>>, Lanes);

/// The tokens of operations' lanes, by [`Target::isolated`], and when each
/// was last used: apart from the hosts', so that many operations never
/// start the hosts' over.
#[derive(Default)]
struct Lanes(Mutex<HashMap<String, (IsolationToken, Instant)>>);

impl Lanes {
    /// The token of the lane `key`, made if new: the least lately used
    /// forgotten past [`MOST_LANES`], and those unused for [`OLDEST`].
    fn of(&self, key: &str) -> IsolationToken {
        let mut lanes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if !lanes.contains_key(key) {
            lanes.retain(|_, (_, used)| now.duration_since(*used) < OLDEST);
            if lanes.len() >= MOST_LANES {
                let least = lanes.iter().min_by_key(|(_, (_, used))| *used);
                if let Some(least) = least.map(|(key, _)| key.clone()) {
                    lanes.remove(&least);
                }
            }
        }
        let (token, used) = lanes
            .entry(key.to_owned())
            .or_insert_with(|| (IsolationToken::new(), now));
        *used = now;
        *token
    }

    /// Whether the lane `key` has a token yet.
    fn has(&self, key: &str) -> bool {
        let lanes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        lanes.contains_key(key)
    }

    /// The lane `key` on the circuits of `token` from now on.
    fn set(&self, key: &str, token: IsolationToken) {
        let mut lanes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        lanes.insert(key.to_owned(), (token, Instant::now()));
    }

    fn renew(&self, key: &str) {
        let mut lanes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((token, _)) = lanes.get_mut(key) {
            *token = IsolationToken::new();
        }
    }
}

impl Isolation {
    /// What streams to `target` share their circuits with.
    fn token(&self, target: &Target) -> IsolationToken {
        match target.lane {
            Some(_) => self.1.of(&target.isolated()),
            None => self.of(&target.isolated()),
        }
    }

    /// Streams to `target` on new circuits from now on ([`Isolation::renew`]).
    fn renew_target(&self, target: &Target) {
        match target.lane {
            Some(_) => self.1.renew(&target.isolated()),
            None => self.renew(&target.isolated()),
        }
    }

    /// What streams to `host` share their circuits with.
    fn of(&self, host: &str) -> IsolationToken {
        let mut hosts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if hosts.len() >= MAX_ISOLATED && !hosts.contains_key(&host.to_ascii_lowercase()) {
            hosts.clear();
        }
        *hosts
            .entry(host.to_ascii_lowercase())
            .or_insert_with(IsolationToken::new)
    }

    /// Streams to `host` on new circuits from now on: those it had failed
    /// one, an exit timing out or failing to look its name up, say. Arti
    /// would use them again, and a host's streams fail one after the other.
    fn renew(&self, host: &str) {
        let mut hosts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(token) = hosts.get_mut(&host.to_ascii_lowercase()) {
            *token = IsolationToken::new();
        }
    }

    /// Stream preferences keeping streams to `host` to their own circuits.
    fn prefs(&self, host: &str) -> StreamPrefs {
        prefs(self.of(host))
    }
}

/// Stream preferences keeping streams to the circuits of `token`.
fn prefs(token: IsolationToken) -> StreamPrefs {
    let mut prefs = StreamPrefs::new();
    prefs.set_isolation(token);
    prefs
}

/// For each host operations reach, a lane made ahead: its circuit built,
/// through to an onion service too, and a connection open over it, for
/// the next operation's first request to take rather than wait for. Made
/// again once taken.
#[derive(Default)]
struct Spares(Mutex<HashMap<Target, Spare>>);

struct Spare {
    /// None while it is made.
    token: Option<IsolationToken>,
    open: Option<Open>,
    made: Instant,
}

impl Tor {
    /// A Tor client keeping its state, onion service keys included, in
    /// `dir/state` and its directory cache in `dir/cache`. It connects to
    /// the Tor network once first used. Within a Tokio runtime.
    pub fn new(dir: &Path) -> anyhow::Result<Self> {
        Self::configured(dir, |_| {})
    }

    /// [`Tor::new`], for a wallet: more exit circuits built ahead, for its
    /// operations' lanes to take at once ([`Tor::in_lane`]).
    pub fn for_wallet(dir: &Path) -> anyhow::Result<Self> {
        Self::configured(dir, |config| {
            config
                .preemptive_circuits()
                .min_exit_circs_for_port(SPARE_CIRCUITS)
                .disable_at_threshold(CIRCUITS_AHEAD_UP_TO);
        })
    }

    fn configured(
        dir: &Path,
        set: impl FnOnce(&mut TorClientConfigBuilder),
    ) -> anyhow::Result<Self> {
        // Arti's TLS needs a process-wide provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config =
            TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"));
        set(&mut config);
        let config = config.build()?;
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()?;
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            client,
            tls: TlsConnector::from(Arc::new(tls)),
            isolation: Arc::default(),
            kept: Arc::new(Kept::new(KEPT_FOR, OLDEST)),
            spares: Arc::default(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            connecting: Arc::default(),
            lane: None,
        })
    }

    /// How far the client is in connecting to the Tor network.
    pub fn status(&self) -> Status {
        let s = self.client.bootstrap_status();
        Status {
            percent: (s.as_frac().clamp(0.0, 1.0) * 100.0).round() as u8,
            ready: s.ready_for_traffic(),
            summary: s.to_string(),
            blocked: s.blocked().map(|b| b.to_string()),
        }
    }

    /// Connect to the Tor network now rather than at the first stream:
    /// done at once if connected, else when it is. Done at once too if
    /// another call is already connecting, so that asking again and again
    /// starts one attempt at a time.
    pub async fn bootstrap(&self) -> Result<(), String> {
        struct Connecting<'a>(&'a AtomicBool);
        impl Drop for Connecting<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        if self.connecting.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        // Cleared however it ends, dropped half way included.
        let _connecting = Connecting(&self.connecting);
        self.client.bootstrap().await.map_err(|e| e.to_string())
    }

    /// This client, its streams on circuits of their own, shared with no
    /// stream of another clone: for a large download, one circuit carrying
    /// only so much (on the order of 100 KB/s), to run beside others to
    /// the same host. It keeps no connection of another.
    pub fn apart(&self) -> Self {
        Self {
            client: self.client.clone(),
            tls: self.tls.clone(),
            isolation: Arc::default(),
            kept: Arc::new(Kept::new(KEPT_FOR, OLDEST)),
            spares: Arc::default(),
            runtime: self.runtime.clone(),
            connecting: self.connecting.clone(),
            lane: None,
        }
    }

    /// This client, its streams in the lane of operation `lane`, if any:
    /// to each host on circuits and connections of the lane's own, shared
    /// with no other lane's, nor with streams in none. A lane's first
    /// request to a host takes the host's spare lane, made ahead, if any,
    /// and has the next made: an operation waits for no circuit, nor for
    /// an onion service's rendezvous.
    pub fn in_lane(&self, lane: Option<u64>) -> Self {
        Self {
            lane,
            ..self.clone()
        }
    }

    /// Where a stream to `uri` goes, in this clone's lane.
    fn target(&self, uri: &Uri) -> Result<Target, String> {
        Ok(Target {
            lane: self.lane,
            ..Target::of(uri)?
        })
    }

    /// The request for `url`, and where it goes, in this clone's lane.
    fn prepare(&self, url: &str, body: Option<Vec<u8>>) -> Result<(Target, Asked), String> {
        let (target, request) = prepare(url, body)?;
        Ok((
            Target {
                lane: self.lane,
                ..target
            },
            request,
        ))
    }

    /// GET `url`, or POST `body` to it as JSON, over Tor: its status and
    /// body, of at most `max` bytes.
    pub async fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        max: usize,
    ) -> Result<(u16, Vec<u8>), String> {
        self.request_for(url, body, max, TIMEOUT).await
    }

    /// [`Tor::request`], given `timeout` rather than its own: for a large
    /// answer.
    pub async fn request_for(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        max: usize,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>), String> {
        let answer = tokio::time::timeout(timeout, self.exchange(url, body, max)).await;
        answer.unwrap_or_else(|_| {
            self.renew(url);
            Err(format!("no answer over Tor in {} s", timeout.as_secs()))
        })
    }

    /// Requests to the host of `url` on new circuits: one timed out.
    fn renew(&self, url: &str) {
        if let Ok((target, _)) = self.prepare(url, None) {
            self.isolation.renew_target(&target);
        }
    }

    /// [`Tor::request_for`], its stream to open within `open` once the
    /// client is bootstrapped: told whether it failed before any of it was
    /// sent, to try another way safely.
    pub async fn request_opened(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        max: usize,
        open: Duration,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>), Failed> {
        let deadline = tokio::time::Instant::now() + timeout;
        let (target, request) = self.prepare(url, body).map_err(Failed::Unsent)?;
        let get = request.method() == Method::GET;
        let reused = tokio::time::timeout_at(deadline, self.reuse(&target, request, max));
        let request = match reused.await {
            Err(_) => {
                let why = format!("no answer over Tor in {} s", timeout.as_secs());
                return Err(Failed::Sent(why));
            }
            Ok(Ok(Ok(answer))) => return Ok(answer),
            // The connection kept may have closed as it was asked: a GET is
            // asked again.
            Ok(Ok(Err(_))) if get => prepare(url, None).map_err(Failed::Unsent)?.1,
            Ok(Ok(Err(why))) => return Err(Failed::Sent(why)),
            Ok(Err(request)) => *request,
        };
        // A cold start is not the host's slowness: `open` counts after it.
        tokio::time::timeout_at(deadline, self.client.bootstrap())
            .await
            .map_err(|_| Failed::Unsent(format!("no Tor in {} s", timeout.as_secs())))?
            .map_err(|e| Failed::Unsent(format!("bootstrapping Tor: {e}")))?;
        let open_by = deadline.min(tokio::time::Instant::now() + open);
        let opening = tokio::time::timeout_at(open_by, self.stream(target.clone()));
        let stream = opening
            .await
            .map_err(|_| {
                self.isolation.renew_target(&target);
                Failed::Unsent(format!("no stream over Tor in {} s", open.as_secs()))
            })?
            .map_err(Failed::Unsent)?;
        let renewed = target.clone();
        tokio::time::timeout_at(deadline, self.kept.first(target, stream, request, max))
            .await
            .map_err(|_| {
                self.isolation.renew_target(&renewed);
                Failed::Sent(format!("no answer over Tor in {} s", timeout.as_secs()))
            })?
            .map_err(Failed::Sent)
    }

    async fn exchange(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
        max: usize,
    ) -> Result<(u16, Vec<u8>), String> {
        let (target, request) = self.prepare(url, body)?;
        let get = request.method() == Method::GET;
        let request = match self.reuse(&target, request, max).await {
            Ok(Ok(answer)) => return Ok(answer),
            // The connection kept may have closed as it was asked: a GET is
            // asked again.
            Ok(Err(_)) if get => prepare(url, None)?.1,
            Ok(Err(why)) => return Err(why),
            Err(request) => *request,
        };
        let stream = self.stream(target.clone()).await?;
        self.kept.first(target, stream, request, max).await
    }

    /// A SOCKS5 proxy at a loopback address through this client, served on
    /// the current Tokio runtime until dropped: for code bringing its own
    /// sockets, such as a light client. It takes CONNECT, and Tor's
    /// RESOLVE, only with its random username and password, each
    /// destination host on circuits apart from the others' as this
    /// client's own streams.
    pub async fn socks(&self) -> std::io::Result<Socks> {
        socks::serve(self.clone()).await
    }

    /// A stream over Tor to the host and port of `url`, an `http[s]://` or
    /// `ws[s]://` URL, within TLS for `https://` and `wss://`.
    pub async fn connect(&self, url: &str) -> Result<Box<dyn Stream>, String> {
        let uri: Uri = url.parse().map_err(|e| format!("not a URL: {e}"))?;
        let target = self.target(&uri)?;
        // A lane's first stream to the host on its spare's circuits.
        if let Some(open) = self.claim(&target) {
            drop(open);
        }
        self.stream(target).await
    }

    /// `request` on a connection kept to `target`, else on its lane's
    /// spare ([`Kept::reuse`]).
    async fn reuse(
        &self,
        target: &Target,
        request: Asked,
        max: usize,
    ) -> Result<Result<Answer, String>, Box<Asked>> {
        let request = match self.kept.reuse(target, request, max).await {
            Err(request) => request,
            done => return done,
        };
        match self.claim(target) {
            Some(open) => self.kept.on(target.clone(), open, *request, max).await,
            None => Err(request),
        }
    }

    /// For the first stream of a lane to `target`'s host: its spare lane's
    /// circuits, and its connection, if still open; another spare made
    /// next. None in no lane, nor once the lane has circuits of its own.
    fn claim(&self, target: &Target) -> Option<Open> {
        target.lane?;
        let key = target.isolated();
        if self.isolation.1.has(&key) {
            return None;
        }
        let base = target.base();
        let spare = {
            let mut spares = self.spares.0.lock().unwrap_or_else(|e| e.into_inner());
            let ready = spares
                .get(&base)
                .is_some_and(|s| s.token.is_some() && s.made.elapsed() < SPARE_FOR);
            match ready {
                true => spares.remove(&base),
                false => None,
            }
        };
        self.make_spare(base);
        let spare = spare?;
        self.isolation.1.set(&key, spare.token?);
        tracing::debug!(host = %target.host, "a lane takes its spare");
        spare.open.filter(|open| !open.sender.is_closed())
    }

    /// A spare lane to the host of `base` made, in the background, unless
    /// one is or is being made: the least lately made let go past
    /// [`MOST_SPARES`].
    fn make_spare(&self, base: Target) {
        {
            let mut spares = self.spares.0.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = |s: &Spare| s.token.is_none() || s.made.elapsed() < SPARE_FOR;
            if spares.get(&base).is_some_and(fresh) {
                return;
            }
            spares.remove(&base);
            if spares.len() >= MOST_SPARES {
                let oldest = spares.iter().min_by_key(|(_, s)| s.made);
                if let Some(oldest) = oldest.map(|(t, _)| t.clone()) {
                    spares.remove(&oldest);
                }
            }
            let made = Instant::now();
            spares.insert(
                base.clone(),
                Spare {
                    token: None,
                    open: None,
                    made,
                },
            );
        }
        let tor = self.in_lane(None);
        let making = async move {
            let token = IsolationToken::new();
            let made = match tor.open_with(&base, token).await {
                Ok(stream) => Open::over(stream).await.ok().map(|open| (token, open)),
                Err(e) => {
                    tracing::debug!(host = %base.host, "no spare lane: {e}");
                    None
                }
            };
            let mut spares = tor.spares.0.lock().unwrap_or_else(|e| e.into_inner());
            match made {
                Some((token, open)) => {
                    let spare = Spare {
                        token: Some(token),
                        open: Some(open),
                        made: Instant::now(),
                    };
                    spares.insert(base, spare);
                }
                None => {
                    spares.remove(&base);
                }
            }
        };
        match &self.runtime {
            Some(runtime) => drop(runtime.spawn(making)),
            None => drop(tokio::spawn(making)),
        }
    }

    /// A stream to `target`, within TLS if it asks: on new circuits once
    /// more should one fail, and next time should that one fail too.
    async fn stream(&self, target: Target) -> Result<Box<dyn Stream>, String> {
        let renew = || self.isolation.renew_target(&target);
        twice(|| self.open(&target), renew).await
    }

    async fn open(&self, target: &Target) -> Result<Box<dyn Stream>, String> {
        self.open_with(target, self.isolation.token(target)).await
    }

    /// A stream to `target` on the circuits of `token`.
    async fn open_with(
        &self,
        target: &Target,
        token: IsolationToken,
    ) -> Result<Box<dyn Stream>, String> {
        let prefs = prefs(token);
        let host = &target.host;
        let started = Instant::now();
        let stream = self
            .client
            .connect_with_prefs((host.as_str(), target.port), &prefs)
            .await
            .map_err(|e| {
                tracing::debug!(%host, ms = ms(started), "no stream over Tor: {e}");
                format!("over Tor: {e}")
            })?;
        let circuit = ms(started);
        if !target.tls {
            tracing::debug!(%host, circuit_ms = circuit, "stream over Tor opened");
            return Ok(Box::new(stream));
        }
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(|e| format!("not a TLS name: {e}"))?;
        let stream = self
            .tls
            .connect(name, stream)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        let tls_ms = ms(started) - circuit;
        tracing::debug!(%host, circuit_ms = circuit, tls_ms, "stream over Tor opened");
        Ok(Box::new(stream))
    }
}

/// The milliseconds since `started`, for the log.
fn ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// How far a client is in connecting to the Tor network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// Of the way, 0 to 100.
    pub percent: u8,
    /// Whether it can carry streams.
    pub ready: bool,
    /// What it is doing, as Arti says.
    pub summary: String,
    /// Why it seems stuck, if it does: a clock wrong, the network blocked.
    pub blocked: Option<String>,
}

/// What `open` opened, tried once more on new circuits (`renew`) should
/// it fail: an exit refusing, a name not looked up, a TLS handshake cut
/// short, a circuit's to blame more often than its host. Nothing was sent
/// yet: safe to try again. On new circuits again next time, should the
/// second fail too.
async fn twice<T, F, O>(mut open: O, renew: impl Fn()) -> Result<T, String>
where
    O: FnMut() -> F,
    F: std::future::Future<Output = Result<T, String>>,
{
    let first = match open().await {
        Ok(opened) => return Ok(opened),
        Err(first) => first,
    };
    renew();
    tracing::info!(%first, "no stream over Tor: once more, on new circuits");
    let again = open().await;
    if again.is_err() {
        renew();
    }
    again
}

/// How a request over Tor failed ([`Tor::request_opened`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failed {
    /// Before any of it was sent: no stream to its host opened in time, or
    /// at all, or it was not a URL to ask.
    Unsent(String),
    /// Once its stream opened: its host may have had it.
    Sent(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsent(why) | Self::Sent(why) => f.write_str(why),
        }
    }
}

impl socks::Exit for Tor {
    async fn connect(
        &self,
        host: String,
        port: u16,
        lane: Option<u8>,
    ) -> Result<Box<dyn Stream>, String> {
        let tls = false;
        self.stream(Target {
            host,
            port,
            tls,
            socks: lane,
            lane: None,
        })
        .await
    }

    async fn resolve(&self, host: String) -> Result<Vec<std::net::IpAddr>, String> {
        let prefs = self.isolation.prefs(&host);
        let resolved = self.client.resolve_with_prefs(&host, &prefs).await;
        resolved.map_err(|e| {
            self.isolation.renew(&host);
            format!("over Tor: {e}")
        })
    }
}

/// A byte stream over Tor.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// Where a stream goes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Target {
    host: String,
    port: u16,
    tls: bool,
    /// The circuits of a lane of the host's, apart from its others, for a
    /// download of the light client's.
    socks: Option<u8>,
    /// The circuits of an operation's lane ([`Tor::in_lane`]).
    lane: Option<u64>,
}

impl Target {
    /// The host of `uri`, and its port or its scheme's, within TLS for
    /// `https://` and `wss://`.
    fn of(uri: &Uri) -> Result<Self, String> {
        let tls = match uri.scheme_str() {
            Some("https" | "wss") => true,
            Some("http" | "ws") => false,
            _ => return Err(format!("not an http[s]:// or ws[s]:// URL: {uri}")),
        };
        let authority = uri.authority().ok_or("a URL without a host")?;
        Ok(Self {
            host: authority.host().to_owned(),
            port: authority.port_u16().unwrap_or(if tls { 443 } else { 80 }),
            tls,
            socks: None,
            lane: None,
        })
    }

    /// Which streams share its circuits: those to its host, in its lane.
    fn isolated(&self) -> String {
        let mut key = self.host.to_ascii_lowercase();
        if let Some(socks) = self.socks {
            key.push_str(&format!("#{socks}"));
        }
        if let Some(lane) = self.lane {
            key.push_str(&format!("@{lane}"));
        }
        key
    }

    /// Where it goes, in no operation's lane: what a spare lane is made
    /// for ([`Tor::claim`]).
    fn base(&self) -> Self {
        Self {
            lane: None,
            ..self.clone()
        }
    }
}

/// Where the request for `url` goes, and the request: a POST of `body` as
/// JSON if given, else a GET.
fn prepare(url: &str, body: Option<Vec<u8>>) -> Result<(Target, Request<Full<Bytes>>), String> {
    let uri: Uri = url.parse().map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(format!("not an http:// or https:// URL: {url}"));
    }
    let target = Target::of(&uri)?;
    let authority = uri.authority().ok_or("a URL without a host")?;
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let request = Request::builder()
        .uri(path)
        .header(HOST, authority.as_str())
        .header(USER_AGENT, concat!("licash/", env!("CARGO_PKG_VERSION")));
    let request = match body {
        Some(body) => request
            .method(Method::POST)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body))),
        None => request.method(Method::GET).body(Full::default()),
    };
    let request = request.map_err(|e| e.to_string())?;
    Ok((target, request))
}

/// An HTTP/1.1 request as sent over Tor.
type Asked = Request<Full<Bytes>>;

/// An answer: its status and body.
type Answer = (u16, Vec<u8>);

/// HTTP/1.1 connections kept open once answered, idle, each for the next
/// request to the same host and port: no stream to open nor TLS handshake
/// to make for it, a second or two over Tor. Streams to a host share their
/// circuits already, and a host can tell they are one client's (TLS
/// resumes its sessions; an onion service sees one circuit), so keeping a
/// connection open links no more requests than before.
struct Kept {
    open: Mutex<Vec<(Target, Instant, Open)>>,
    /// How long a connection is kept, idle.
    keep: Duration,
    /// How long a connection is used, since it opened.
    oldest: Duration,
}

/// An HTTP/1.1 connection, its task ended as it is dropped.
struct Open {
    sender: http1::SendRequest<Full<Bytes>>,
    task: tokio::task::AbortHandle,
    opened: Instant,
}

impl Drop for Open {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `e` and what caused it, as hyper's "connection error" says nothing of
/// why: a circuit closed, a stream reset.
fn why(e: &(dyn std::error::Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

/// How a request on a connection failed.
enum Lost {
    /// Not sent: the connection had closed. The request back.
    Unsent(Box<Asked>),
    /// Sent, in part or whole: its host may have had it.
    Sent(String),
}

impl Open {
    /// An HTTP/1.1 connection over `stream`, served by a task of its own.
    async fn over(stream: Box<dyn Stream>) -> Result<Self, String> {
        let (sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| e.to_string())?;
        let task = tokio::spawn(connection).abort_handle();
        Ok(Self {
            sender,
            task,
            opened: Instant::now(),
        })
    }

    /// `request` on this connection: its answer, with a body of at most
    /// `max` bytes.
    async fn ask(&mut self, request: Asked, max: usize) -> Result<Answer, Lost> {
        let response = match self.sender.try_send_request(request).await {
            Ok(response) => response,
            Err(mut e) => {
                return Err(match e.take_message() {
                    Some(request) => Lost::Unsent(Box::new(request)),
                    None => Lost::Sent(why(&e.into_error())),
                })
            }
        };
        let status = response.status().as_u16();
        let mut body = Limited::new(response.into_body(), max);
        let mut bytes = Vec::new();
        loop {
            let frame = tokio::time::timeout(STALLED, body.frame()).await;
            let stalled = || format!("the answer stalled for {} s", STALLED.as_secs());
            match frame.map_err(|_| Lost::Sent(stalled()))? {
                None => return Ok((status, bytes)),
                Some(Err(e)) => return Err(Lost::Sent(format!("the answer: {}", why(&*e)))),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        bytes.extend_from_slice(&data);
                    }
                }
            }
        }
    }
}

impl Kept {
    fn new(keep: Duration, oldest: Duration) -> Self {
        Self {
            open: Mutex::default(),
            keep,
            oldest,
        }
    }

    /// The connections kept, those expired, too old or closed let go.
    fn kept(&self) -> std::sync::MutexGuard<'_, Vec<(Target, Instant, Open)>> {
        let mut kept = self.open.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        kept.retain(|(to, at, open)| {
            let keep = match to.lane {
                Some(_) => self.keep.min(LANE_KEPT_FOR),
                None => self.keep,
            };
            now.duration_since(*at) < keep
                && now.duration_since(open.opened) < self.oldest
                && !open.sender.is_closed()
        });
        kept
    }

    /// A connection to `target` kept and ready for a request, the latest
    /// kept first, if any.
    async fn take(&self, target: &Target) -> Option<Open> {
        loop {
            let mut open = {
                let mut kept = self.kept();
                let at = kept.iter().rposition(|(to, ..)| to == target)?;
                kept.remove(at).2
            };
            if let Ok(Ok(())) = tokio::time::timeout(READY, open.sender.ready()).await {
                return Some(open);
            }
        }
    }

    /// `open`, its last answer read whole, kept for the next request to
    /// `target`: the oldest kept let go past [`MOST_KEPT`].
    fn put(&self, target: Target, open: Open) {
        if open.sender.is_closed() {
            return;
        }
        let mut kept = self.kept();
        if kept.len() >= MOST_KEPT {
            // An operation's first, likely over.
            let at = kept.iter().position(|(to, ..)| to.lane.is_some());
            kept.remove(at.unwrap_or(0));
        }
        kept.push((target, Instant::now(), open));
    }

    /// `request` on a connection kept to `target`: its answer, or how it
    /// failed once sent; or, none kept taking it, the request back.
    async fn reuse(
        &self,
        target: &Target,
        mut request: Asked,
        max: usize,
    ) -> Result<Result<Answer, String>, Box<Asked>> {
        while let Some(mut open) = self.take(target).await {
            let started = Instant::now();
            match open.ask(request, max).await {
                Ok(answer) => {
                    tracing::debug!(host = %target.host, ms = ms(started), "asked on a connection kept");
                    self.put(target.clone(), open);
                    return Ok(Ok(answer));
                }
                // Closed: the next kept, or a new one.
                Err(Lost::Unsent(back)) => request = *back,
                Err(Lost::Sent(why)) => return Ok(Err(why)),
            }
        }
        Err(Box::new(request))
    }

    /// `request` on a new connection over `stream` to `target`: its
    /// answer, the connection kept once it is read whole.
    async fn first(
        &self,
        target: Target,
        stream: Box<dyn Stream>,
        request: Asked,
        max: usize,
    ) -> Result<Answer, String> {
        let started = Instant::now();
        let open = Open::over(stream).await?;
        let answer = self.asked(&target, open, request, max).await;
        tracing::debug!(host = %target.host, ms = ms(started), "asked on a new connection");
        answer
    }

    /// `request` on `open`, a connection to `target` made ahead: its
    /// answer, or how it failed once sent; or, the connection closed, the
    /// request back.
    async fn on(
        &self,
        target: Target,
        mut open: Open,
        request: Asked,
        max: usize,
    ) -> Result<Result<Answer, String>, Box<Asked>> {
        if !matches!(
            tokio::time::timeout(READY, open.sender.ready()).await,
            Ok(Ok(()))
        ) {
            return Err(Box::new(request));
        }
        match open.ask(request, max).await {
            Ok(answer) => {
                self.put(target, open);
                Ok(Ok(answer))
            }
            Err(Lost::Unsent(back)) => Err(back),
            Err(Lost::Sent(why)) => Ok(Err(why)),
        }
    }

    /// `request` on `open`, new, to `target`: kept once read whole.
    async fn asked(
        &self,
        target: &Target,
        mut open: Open,
        request: Asked,
        max: usize,
    ) -> Result<Answer, String> {
        let answer = open.ask(request, max).await.map_err(|lost| match lost {
            Lost::Unsent(_) => "the connection closed".to_owned(),
            Lost::Sent(why) => why,
        })?;
        self.put(target.clone(), open);
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_says_what_caused_it() {
        #[derive(Debug)]
        struct Connection(std::io::Error);
        impl std::fmt::Display for Connection {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("connection error")
            }
        }
        impl std::error::Error for Connection {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let reset = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "circuit closed");
        assert_eq!(why(&Connection(reset)), "connection error: circuit closed");
        assert_eq!(why(&std::io::Error::other("no stream")), "no stream");
    }

    fn target(host: &str, port: u16, tls: bool) -> Target {
        Target {
            host: host.into(),
            port,
            tls,
            socks: None,
            lane: None,
        }
    }

    #[test]
    fn requests_go_to_the_host_and_port_of_their_url() {
        let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        let (to, request) = prepare(&format!("http://{onion}/v1/info"), None).unwrap();
        assert_eq!(to, target(onion, 80, false));
        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri(), "/v1/info");
        assert_eq!(request.headers()[HOST], onion);

        let url = "https://hub.example:8443/v1/swaps?x=1";
        let (to, request) = prepare(url, Some(b"{}".to_vec())).unwrap();
        assert_eq!(to, target("hub.example", 8443, true));
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri(), "/v1/swaps?x=1");
        assert_eq!(request.headers()[HOST], "hub.example:8443");
        assert_eq!(request.headers()[CONTENT_TYPE], "application/json");

        let (to, request) = prepare("https://hub.example", None).unwrap();
        assert_eq!(to, target("hub.example", 443, true));
        assert_eq!(request.uri(), "/");
    }

    #[test]
    fn only_http_and_https_urls_are_requested() {
        for url in [
            "ftp://hub.example/",
            "ws://hub.example/",
            "socks5h://127.0.0.1:9050",
            "/v1/info",
            "hub",
        ] {
            assert!(prepare(url, None).is_err(), "{url}");
        }
    }

    #[test]
    fn streams_go_to_the_host_and_port_of_their_url() {
        let at = |url: &str| Target::of(&url.parse().unwrap());
        let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
        assert_eq!(at(&format!("ws://{onion}")), Ok(target(onion, 80, false)));
        let relay = "relay.example";
        assert_eq!(at("wss://relay.example/"), Ok(target(relay, 443, true)));
        assert_eq!(
            at("wss://relay.example:7777"),
            Ok(target(relay, 7777, true))
        );
        assert_eq!(at("https://relay.example"), Ok(target(relay, 443, true)));
        assert!(at("ftp://relay.example").is_err());
        assert!(at("/v1/info").is_err());
    }

    #[test]
    fn streams_share_circuits_only_with_those_to_the_same_host() {
        let isolation = Isolation::default();
        let hub = isolation.of("hub.example");
        assert_eq!(isolation.of("HUB.example"), hub);
        assert_ne!(isolation.of("relay.example"), hub);
        assert_ne!(isolation.of("relay.example"), isolation.of("other.example"));
        assert_eq!(isolation.of("hub.example"), hub);
    }

    #[test]
    fn an_operations_lane_keeps_to_circuits_of_its_own_and_many_leave_the_hosts_alone() {
        let isolation = Isolation::default();
        let to = |lane| Target {
            lane,
            ..target("hub.example", 443, true)
        };
        let host = isolation.token(&to(None));
        let first = isolation.token(&to(Some(1)));
        assert_ne!(first, host);
        assert_ne!(isolation.token(&to(Some(2))), first);
        assert_eq!(isolation.token(&to(Some(1))), first);
        // A lane's request timing out renews its lane alone.
        isolation.renew_target(&to(Some(1)));
        let renewed = isolation.token(&to(Some(1)));
        assert_ne!(renewed, first);
        assert_eq!(isolation.token(&to(None)), host);
        // Ever more lanes: the least lately used forgotten, the hosts' kept.
        for lane in 3..(MOST_LANES as u64 + 10) {
            isolation.token(&to(Some(lane)));
        }
        assert!(isolation.1 .0.lock().unwrap().len() <= MOST_LANES);
        assert_eq!(isolation.token(&to(None)), host);
        assert_ne!(isolation.token(&to(Some(1))), renewed, "forgotten");
    }

    #[tokio::test]
    async fn a_lanes_first_request_takes_its_hosts_spare_made_lately_and_once() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::new(dir.path()).unwrap();
        let to = |lane| Target {
            lane,
            ..target("hub.example", 443, true)
        };
        let spare = |token, made| Spare {
            token: Some(token),
            open: None,
            made,
        };
        let token = IsolationToken::new();
        tor.spares
            .0
            .lock()
            .unwrap()
            .insert(to(None), spare(token, Instant::now()));
        // In no lane: no spare taken.
        assert!(tor.claim(&to(None)).is_none());
        assert!(tor.spares.0.lock().unwrap()[&to(None)].token == Some(token));
        // A lane's first: on the spare's circuits; another made.
        let lane = tor.in_lane(Some(7));
        assert!(
            lane.claim(&to(Some(7))).is_none(),
            "no connection kept open"
        );
        assert_eq!(tor.isolation.token(&to(Some(7))), token);
        assert!(
            tor.spares.0.lock().unwrap()[&to(None)].token.is_none(),
            "being made"
        );
        // Once the lane has its own, no other spare is taken.
        let next = IsolationToken::new();
        tor.spares
            .0
            .lock()
            .unwrap()
            .insert(to(None), spare(next, Instant::now()));
        lane.claim(&to(Some(7)));
        assert_eq!(tor.isolation.token(&to(Some(7))), token);
        // A spare made too long ago is not handed out.
        let stale = Instant::now()
            .checked_sub(SPARE_FOR + Duration::from_secs(1))
            .unwrap();
        tor.spares
            .0
            .lock()
            .unwrap()
            .insert(to(None), spare(next, stale));
        tor.claim(&to(Some(8)));
        assert_ne!(tor.isolation.token(&to(Some(8))), next);
    }

    #[test]
    fn each_lane_of_a_host_keeps_to_circuits_of_its_own() {
        let isolation = Isolation::default();
        let lane = |socks| Target {
            socks,
            ..target("cdn.example", 443, false)
        };
        let host = isolation.of(&lane(None).isolated());
        let (first, second) = (
            isolation.of(&lane(Some(1)).isolated()),
            isolation.of(&lane(Some(2)).isolated()),
        );
        assert_ne!(first, host);
        assert_ne!(first, second);
        assert_eq!(isolation.of(&lane(Some(1)).isolated()), first);
        // A lane's stream failing renews its lane alone.
        isolation.renew(&lane(Some(1)).isolated());
        assert_ne!(isolation.of(&lane(Some(1)).isolated()), first);
        assert_eq!(isolation.of(&lane(Some(2)).isolated()), second);
        assert_eq!(isolation.of(&lane(None).isolated()), host);
    }

    #[test]
    fn a_host_whose_stream_failed_goes_on_new_circuits() {
        let isolation = Isolation::default();
        let hub = isolation.of("hub.example");
        let relay = isolation.of("relay.example");
        isolation.renew("HUB.example");
        let renewed = isolation.of("hub.example");
        assert_ne!(renewed, hub);
        assert_ne!(renewed, relay);
        assert_eq!(isolation.of("hub.example"), renewed);
        assert_eq!(isolation.of("relay.example"), relay);
        // A host never reached keeps none: its first stream takes one.
        isolation.renew("other.example");
        assert_eq!(isolation.0.lock().unwrap().len(), 2);
    }

    /// A connection to a host that answers `head`, then `body` and then
    /// nothing more, never closing.
    async fn answering(head: &'static str, body: &'static [u8]) -> Open {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (ours, mut theirs) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut asked = [0; 1024];
            let _ = theirs.read(&mut asked).await;
            theirs.write_all(head.as_bytes()).await.unwrap();
            theirs.write_all(body).await.unwrap();
            std::future::pending::<()>().await;
            drop(theirs);
        });
        Open::over(Box::new(ours)).await.unwrap()
    }

    fn info() -> Asked {
        let request = hyper::Request::get("/v1/info").header("host", "hub.example");
        request.body(Full::new(Bytes::new())).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_stalled_fails_its_request() {
        let head = "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n";
        let mut open = answering(head, b"abc").await;
        let started = tokio::time::Instant::now();
        let Err(Lost::Sent(why)) = open.ask(info(), 100).await else {
            panic!("an answer");
        };
        assert!(why.contains("stalled"), "{why}");
        assert_eq!(started.elapsed(), STALLED);
        // Whole: taken.
        let mut open = answering(head, b"0123456789").await;
        let answer = open.ask(info(), 100).await.ok().unwrap();
        assert_eq!(answer, (200, b"0123456789".to_vec()));
    }

    #[tokio::test]
    async fn a_client_apart_shares_no_circuit_with_the_one_it_is_of() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::new(dir.path()).unwrap();
        let hub = tor.isolation.of("hub.example");
        let (one, other) = (tor.apart(), tor.apart());
        let apart = one.isolation.of("hub.example");
        assert_ne!(apart, hub);
        assert_ne!(other.isolation.of("hub.example"), apart);
        // Each its own from then on, the one it is of unchanged.
        assert_eq!(one.isolation.of("hub.example"), apart);
        assert_eq!(tor.isolation.of("hub.example"), hub);
        assert!(!Arc::ptr_eq(&one.kept, &tor.kept));
        assert!(Arc::ptr_eq(&one.client, &tor.client));
    }

    #[tokio::test]
    async fn a_client_never_used_is_not_connected() {
        let dir = tempfile::tempdir().unwrap();
        let status = Tor::new(dir.path()).unwrap().status();
        assert!(!status.ready, "{status:?}");
        assert!(status.percent < 100, "{status:?}");
        assert!(!status.summary.is_empty());
    }

    #[tokio::test]
    async fn a_stream_failing_is_opened_once_more_on_new_circuits() {
        use std::cell::Cell;
        let (opened, renewed) = (Cell::new(0), Cell::new(0));
        let renew = || renewed.set(renewed.get() + 1);
        // Failing once: opened the second time, on new circuits.
        let open = || {
            opened.set(opened.get() + 1);
            let n = opened.get();
            async move {
                if n == 1 {
                    Err(format!("failed {n}"))
                } else {
                    Ok(n)
                }
            }
        };
        assert_eq!(twice(open, renew).await, Ok(2));
        assert_eq!((opened.get(), renewed.get()), (2, 1));
        // Failing twice: the second failure said, on new circuits next time.
        let (opened, renewed) = (Cell::new(0), Cell::new(0));
        let renew = || renewed.set(renewed.get() + 1);
        let open = || {
            opened.set(opened.get() + 1);
            let n = opened.get();
            async move { Err::<usize, _>(format!("failed {n}")) }
        };
        assert_eq!(twice(open, renew).await, Err("failed 2".into()));
        assert_eq!((opened.get(), renewed.get()), (2, 2));
        // Opened at once: as it was.
        let renewed = Cell::new(0);
        let open = || async { Ok::<_, String>(1) };
        assert_eq!(twice(open, || renewed.set(1)).await, Ok(1));
        assert_eq!(renewed.get(), 0);
    }

    #[test]
    fn hosts_past_the_most_kept_start_over_apart() {
        let isolation = Isolation::default();
        let first = isolation.of("host0.example");
        for i in 1..MAX_ISOLATED {
            isolation.of(&format!("host{i}.example"));
        }
        assert_eq!(isolation.of("host0.example"), first);
        let next = isolation.of("one-more.example");
        assert_eq!(isolation.0.lock().unwrap().len(), 1);
        assert_eq!(isolation.of("one-more.example"), next);
        assert_ne!(isolation.of("host0.example"), first);
    }

    /// An HTTP/1.1 server on a loopback port answering `ok`, closing the
    /// connection if the path asks it (`/close`): its address, and how many
    /// connections it took.
    async fn server() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        let taken = Arc::new(AtomicUsize::new(0));
        let counted = taken.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let service = hyper::service::service_fn(
                    |request: Request<hyper::body::Incoming>| async move {
                        let mut answer = hyper::Response::builder();
                        if request.uri().path() == "/close" {
                            answer = answer.header(hyper::header::CONNECTION, "close");
                        }
                        answer.body(Full::new(Bytes::from_static(b"ok")))
                    },
                );
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });
        (at, taken)
    }

    /// GET `path` from the server at `at` as host `to`: on a connection
    /// kept, or a new one.
    async fn get(kept: &Kept, at: std::net::SocketAddr, to: &Target, path: &str) -> Answer {
        let url = format!("http://{}:{}{path}", to.host, to.port);
        let (_, request) = prepare(&url, None).unwrap();
        match kept.reuse(to, request, 1 << 10).await {
            Ok(answer) => answer.unwrap(),
            Err(request) => {
                let stream = tokio::net::TcpStream::connect(at).await.unwrap();
                kept.first(to.clone(), Box::new(stream), *request, 1 << 10)
                    .await
                    .unwrap()
            }
        }
    }

    fn taken(count: &std::sync::atomic::AtomicUsize) -> usize {
        count.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_hosts_requests_share_a_connection_kept_open() {
        let (at, count) = server().await;
        let kept = Kept::new(KEPT_FOR, OLDEST);
        let hub = target("hub.example", at.port(), false);
        for _ in 0..3 {
            assert_eq!(
                get(&kept, at, &hub, "/v1/info").await,
                (200, b"ok".to_vec())
            );
        }
        assert_eq!(taken(&count), 1);
        // Another host: a connection of its own, as on its own circuits.
        let relay = target("relay.example", at.port(), false);
        assert_eq!(get(&kept, at, &relay, "/").await.0, 200);
        assert_eq!(taken(&count), 2);
        assert_eq!(get(&kept, at, &hub, "/v1/info").await.0, 200);
        assert_eq!(taken(&count), 2);
    }

    #[tokio::test]
    async fn a_connection_idle_too_long_or_closed_is_not_used_again() {
        let (at, count) = server().await;
        let hub = target("hub.example", at.port(), false);
        let expired = Kept::new(Duration::ZERO, OLDEST);
        get(&expired, at, &hub, "/").await;
        get(&expired, at, &hub, "/").await;
        assert_eq!(taken(&count), 2);
        // Used as long as Tor gives its circuit new streams, no longer.
        let old = Kept::new(KEPT_FOR, Duration::ZERO);
        get(&old, at, &hub, "/").await;
        get(&old, at, &hub, "/").await;
        assert_eq!(taken(&count), 4);

        let kept = Kept::new(KEPT_FOR, OLDEST);
        get(&kept, at, &hub, "/close").await;
        get(&kept, at, &hub, "/").await;
        assert_eq!(taken(&count), 6);
        get(&kept, at, &hub, "/").await;
        assert_eq!(taken(&count), 6);
    }

    #[tokio::test]
    async fn at_most_so_many_connections_are_kept() {
        let (at, count) = server().await;
        let kept = Kept::new(KEPT_FOR, OLDEST);
        for i in 0..=MOST_KEPT {
            get(
                &kept,
                at,
                &target(&format!("host{i}.example"), at.port(), false),
                "/",
            )
            .await;
        }
        assert_eq!(kept.kept().len(), MOST_KEPT);
        // The oldest let go: asked again, it connects anew.
        get(&kept, at, &target("host0.example", at.port(), false), "/").await;
        assert_eq!(taken(&count), MOST_KEPT + 2);
    }

    /// The Tor Project's check that a request came over Tor.
    #[tokio::test]
    #[ignore = "reaches the Tor network"]
    async fn requests_reach_the_clear_web_over_tor() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::new(dir.path()).unwrap();
        let url = "https://check.torproject.org/api/ip";
        let (status, body) = tor.request(url, None, 1 << 16).await.unwrap();
        assert_eq!(status, 200);
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains("\"IsTor\":true"), "{body}");
    }
}
