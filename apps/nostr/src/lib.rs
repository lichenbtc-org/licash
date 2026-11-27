//! Hubs and swap providers announce themselves on Nostr relays, and wallets
//! discover them there.
//!
//! An announcement is an addressable event (NIP-01) of kind [`KIND`]. Its
//! `d` tag names the [`Role`], so that a key keeps one announcement per
//! role; its `t` tag, `licash-hub` or `licash-swaps`, lets clients ask
//! relays for one role; and its NIP-40 `expiration` drops it [`LIFETIME`]
//! after it was signed, unless renewed, as [`Announcer::run`] does every
//! [`EVERY`]. Its content is an [`Announcement`] in JSON.
//!
//! Anyone may announce any URL: a client uses one only once the service
//! there names the key that announced it ([`Found::named_by`]), as a hub
//! does in its `/v1/info`.
//!
//! Wallets are paid at their [`mailbox`] on Nostr too: with the `wallet`
//! feature, [`wallet`] pays payment codes and takes what a mailbox holds.
//!
//! Relays are reached directly, through a SOCKS5 proxy, or, with the `tor`
//! feature, through a Tor client of the application's own ([`Route`]).

pub mod mailbox;
#[cfg(feature = "tor")]
mod tor;
#[cfg(feature = "wallet")]
pub mod wallet;

pub mod watch;

use std::{collections::HashMap, future::Future, net::SocketAddr, time::Duration};

use anyhow::{ensure, Context};
use nostr_sdk::prelude::{
    Client, ClientBuilder, Event, EventBuilder, Filter, FinalizeEvent, Keys, Kind, Proxy,
    PublicKey, Relay, RelayUrl, SecretKey, SignerAuthenticator, Tag, Timestamp,
};
use serde::{Deserialize, Serialize};

/// The kind of announcements: addressable.
pub const KIND: u16 = 38338;

/// How often a service renews its announcement.
pub const EVERY: Duration = Duration::from_secs(30 * 60);

/// How long an announcement lasts unless renewed.
pub const LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

/// How long to wait for relays to connect, take an event or answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The same through Tor, whose circuits take longer, as may its first
/// connection.
const TOR_TIMEOUT: Duration = Duration::from_secs(60);

/// How soon to try again after no relay took an announcement.
const RETRY: Duration = Duration::from_secs(60);

/// The largest content read: an announcement is far smaller.
const MAX_CONTENT: usize = 8 * 1024;

/// The most URLs read from one announcement, and the longest.
const MAX_URLS: usize = 4;
const MAX_URL: usize = 256;

/// The most announcements asked of each relay.
const MAX_EVENTS: usize = 500;

/// How far ahead of the clock an announcement may say it was signed: a
/// service's clock off by a little.
const MAX_AHEAD: Duration = Duration::from_secs(15 * 60);

/// Relays to look for hubs and providers on besides those a wallet's hubs
/// name: the signet hubs and provider announce there. They were chosen for
/// serving readers over Tor without NIP-42 and keeping addressable events,
/// unlike many relays, which refuse Tor's exits or ask for AUTH; one may
/// still be slow at times (on 2026-11-15 the oxtr.dev pair timed out over
/// Tor while the others answered). The last two are onion services,
/// reached only through Tor.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.primal.net",
    "wss://relay.snort.social",
    "wss://relay.ditto.pub",
    "wss://nostr.azzamo.net",
    "wss://relay.angor.io",
    "wss://nostr.oxtr.dev",
    "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion",
    "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion",
];

/// The relays of [`DEFAULT_RELAYS`] to look on for services of `network`,
/// the onion services among them only if reached `over_tor`. None on
/// regtest, whose services are local.
pub fn default_relays(network: &str, over_tor: bool) -> Vec<String> {
    if network == "regtest" {
        return Vec::new();
    }
    DEFAULT_RELAYS
        .iter()
        .filter(|relay| over_tor || !onion(relay))
        .map(|relay| (*relay).to_owned())
        .collect()
}

/// Whether `url` is that of an onion service.
pub fn onion(url: &str) -> bool {
    let host = url.split("://").nth(1).unwrap_or(url);
    let host = host.split(['/', ':', '?']).next().unwrap_or(host);
    host.to_ascii_lowercase().ends_with(".onion")
}

/// What announces itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Hub,
    Swaps,
    /// An NWC bridge keeping accounts for anyone ([`Announcement::urls`]
    /// answering its info, naming the key that announced it).
    Bridge,
}

impl Role {
    /// Its `d` tag.
    fn id(self) -> &'static str {
        match self {
            Role::Hub => "hub",
            Role::Swaps => "swaps",
            Role::Bridge => "bridge",
        }
    }

    /// Its `t` tag.
    fn topic(self) -> &'static str {
        match self {
            Role::Hub => "licash-hub",
            Role::Swaps => "licash-swaps",
            Role::Bridge => "licash-bridge",
        }
    }
}

/// The content of an announcement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announcement {
    /// Where the service answers: `https://` URLs, or `http://` ones of
    /// onion services.
    pub urls: Vec<String>,
    /// The Bitcoin network of its locks: `bitcoin`, `testnet4`, `signet` or
    /// `regtest`.
    pub network: String,
    /// A name to show.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Announcement {
    /// Fails unless it names 1 to 4 URLs, each `http[s]://` and at most 256
    /// bytes long: clients skip the others.
    pub fn check(&self) -> anyhow::Result<()> {
        ensure!(
            (1..=MAX_URLS).contains(&self.urls.len()),
            "an announcement names 1 to {MAX_URLS} URLs"
        );
        for url in &self.urls {
            ensure!(
                usable(url),
                "{url}: not an http:// or https:// URL of at most {MAX_URL} bytes"
            );
        }
        Ok(())
    }
}

/// An announcement found on the relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The key that announced it: x-only, in hex.
    pub key: String,
    pub announcement: Announcement,
    /// When it was signed, in seconds since the epoch.
    pub at: u64,
}

impl Found {
    /// Whether a service that names `nostr` as its key, in hex, made this
    /// announcement: only then may its URL be used.
    pub fn named_by(&self, nostr: Option<&str>) -> bool {
        nostr.is_some_and(|key| key.eq_ignore_ascii_case(&self.key))
    }
}

/// The x-only public key of `secret`, in hex, as services name it.
pub fn public_key(secret: &[u8; 32]) -> anyhow::Result<String> {
    Ok(keys(secret)?.public_key().to_hex())
}

fn keys(secret: &[u8; 32]) -> anyhow::Result<Keys> {
    let secret = SecretKey::from_slice(secret).context("a Nostr secret key")?;
    Ok(Keys::new(secret))
}

/// How a client reaches the relays.
#[derive(Clone, Default)]
pub enum Route {
    #[default]
    Direct,
    /// Through a SOCKS5 proxy, such as Tor's.
    Socks(SocketAddr),
    /// Through a Tor client of the application's own.
    #[cfg(feature = "tor")]
    Tor(licash_tor::Tor),
}

impl Route {
    /// A client to build reaching relays this way.
    pub fn builder(&self) -> ClientBuilder {
        match self {
            Self::Direct => Client::builder(),
            Self::Socks(proxy) => Client::builder().proxy(Proxy::all(*proxy)),
            #[cfg(feature = "tor")]
            Self::Tor(tor) => Client::builder().websocket_transport(tor::OverTor(tor.clone())),
        }
    }

    /// Through the `socks5[h]://host:port` proxy `url`.
    pub fn socks(url: &str) -> anyhow::Result<Self> {
        let at = url
            .strip_prefix("socks5h://")
            .or_else(|| url.strip_prefix("socks5://"))
            .context("Nostr relays are reached through a socks5h:// proxy only")?;
        let address = std::net::ToSocketAddrs::to_socket_addrs(at.trim_end_matches('/'))
            .with_context(|| format!("the proxy {at}"))?
            .next()
            .with_context(|| format!("the proxy {at}: no address"))?;
        Ok(Self::Socks(address))
    }

    /// How long to wait for relays to connect, take an event or answer.
    fn timeout(&self) -> Duration {
        match self {
            Self::Direct => TIMEOUT,
            _ => TOR_TIMEOUT,
        }
    }
}

/// A client of `relays`, through `route`, authenticating as `auth` to
/// relays that ask (NIP-42), not connected yet.
async fn client(relays: &[String], route: &Route, auth: Option<Keys>) -> anyhow::Result<Client> {
    ensure!(!relays.is_empty(), "no Nostr relay");
    let mut builder = route.builder();
    if let Some(keys) = auth {
        builder = builder.authenticator(SignerAuthenticator::new(keys));
    }
    let client = builder.build();
    for relay in relays {
        client
            .add_relay(relay.as_str())
            .await
            .with_context(|| format!("Nostr relay {relay}"))?;
    }
    Ok(client)
}

/// Announces a service on Nostr relays.
pub struct Announcer {
    client: Client,
    keys: Keys,
    role: Role,
}

impl Announcer {
    /// An announcer of `role` on `relays`, reached through `route`,
    /// signing with `secret`. It keeps connecting to the relays down.
    pub async fn new(
        secret: &[u8; 32],
        role: Role,
        relays: &[String],
        route: &Route,
    ) -> anyhow::Result<Self> {
        let keys = keys(secret)?;
        let client = client(relays, route, None).await?;
        client.connect().and_wait(route.timeout()).await;
        Ok(Self { client, keys, role })
    }

    /// Its public key, x-only in hex.
    pub fn key(&self) -> String {
        self.keys.public_key().to_hex()
    }

    /// Sign `announcement` and send it to the relays: how many took it, at
    /// least one.
    pub async fn announce(&self, announcement: &Announcement) -> anyhow::Result<usize> {
        announcement.check()?;
        let event = self.event(announcement, Timestamp::now())?;
        let sent = self.client.send_event(&event).await?;
        if sent.success.is_empty() {
            let failed: Vec<String> = sent
                .failed
                .iter()
                .map(|(relay, e)| format!("{relay}: {e}"))
                .collect();
            anyhow::bail!("no relay took the announcement: {}", failed.join("; "));
        }
        Ok(sent.success.len())
    }

    /// The event announcing `announcement`, signed at `at`.
    pub fn event(&self, announcement: &Announcement, at: Timestamp) -> anyhow::Result<Event> {
        let tags = [
            Tag::identifier(self.role.id()),
            Tag::hashtag(self.role.topic()),
            Tag::expiration(at + LIFETIME),
        ];
        let content = serde_json::to_string(announcement)?;
        Ok(EventBuilder::new(Kind::Custom(KIND), content)
            .tags(tags)
            .custom_created_at(at)
            .finalize(&self.keys)?)
    }

    /// Announce `announcement` now and every [`EVERY`], for good.
    pub async fn run(self, announcement: Announcement) {
        let mut announced = false;
        loop {
            let wait = match self.announce(&announcement).await {
                Ok(relays) => {
                    if !announced {
                        tracing::info!(relays, key = %self.key(), "announced on Nostr");
                    }
                    announced = true;
                    EVERY
                }
                Err(e) => {
                    tracing::warn!("announcing on Nostr: {e:#}");
                    announced = false;
                    RETRY
                }
            };
            tokio::time::sleep(wait).await;
        }
    }
}

/// The announcements of `role` for `network` on `relays`, asked through
/// `route`: the newest of each key, newest first, unexpired and
/// well formed. Relays that do not answer in time are skipped; fails only
/// if none answered.
pub async fn discover(
    relays: &[String],
    route: &Route,
    role: Role,
    network: &str,
) -> anyhow::Result<Vec<Found>> {
    discover_known(relays, route, role, network, &[]).await
}

/// The most keys asked for by name ([`discover_known`]), the first named.
pub const MAX_KNOWN: usize = 500;

/// [`discover`], the announcements of the `known` keys (x-only, in hex),
/// up to [`MAX_KNOWN`], asked for apart as well: a flood of newer
/// announcements of other keys, filling all a relay answers, hides none of
/// theirs. Keys not in hex are passed over.
pub async fn discover_known(
    relays: &[String],
    route: &Route,
    role: Role,
    network: &str,
    known: &[String],
) -> anyhow::Result<Vec<Found>> {
    let started = std::time::Instant::now();
    let client = client(relays, route, None).await?;
    let filter = Filter::new()
        .kind(Kind::Custom(KIND))
        .identifier(role.id())
        .hashtag(role.topic());
    let known: Vec<PublicKey> = (known.iter())
        .filter_map(|k| PublicKey::from_hex(k).ok())
        .take(MAX_KNOWN)
        .collect();
    let named = (!known.is_empty()).then(|| {
        let limit = known.len();
        filter.clone().authors(known).limit(limit)
    });
    let filter = filter.limit(MAX_EVENTS);
    let timeout = route.timeout();
    let fetched = ask_each(client.relays().await, route, MIN_GRACE, |relay| {
        let (filter, named) = (filter.clone(), named.clone());
        async move {
            let mut events: Vec<Event> = relay
                .fetch_events(filter)
                .timeout(timeout)
                .await?
                .into_iter()
                .collect();
            if let Some(named) = named {
                events.extend(relay.fetch_events(named).timeout(timeout).await?);
            }
            Ok(events)
        }
    })
    .await;
    client.shutdown().await;
    let mut newest: HashMap<String, Found> = HashMap::new();
    for event in fetched?.into_iter().flatten() {
        let Some(found) = read(&event, role, network) else {
            continue;
        };
        if newest.get(&found.key).is_none_or(|old| old.at < found.at) {
            newest.insert(found.key.clone(), found);
        }
    }
    let mut found: Vec<Found> = newest.into_values().collect();
    found.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.key.cmp(&b.key)));
    tracing::info!(role = role.id(), found = found.len(), took = ?started.elapsed(), "announcements looked for");
    Ok(found)
}

/// How long the other relays have to answer once one did, at most: those
/// slower are left out, rather than hold up whoever waits (a payment being
/// sent, providers being looked for, or the wallet, as it looks in its
/// mailbox). One that never answers would take the route's whole timeout,
/// and over Tor some often do not (an onion service gone, a relay blocking
/// Tor).
const GRACE: Duration = Duration::from_secs(4);

/// How long the other relays have to answer once one did, at least, when
/// asked for events: as long again as the first took otherwise, as relays
/// reached the same way answer in comparable times, one connected already
/// within a second. Asked again soon, those left out are not missed for
/// long; an event sent is given every relay [`GRACE`] can reach.
const MIN_GRACE: Duration = Duration::from_secs(1);

/// Each of `relays` asked through `ask` as soon as it connects, not
/// once the others did or gave up: the answers of those that answered in
/// time, the first within the route's timeout to connect and as long again
/// to answer, the others within as long again as the first took, `least`
/// to [`GRACE`]. Fails if none answered, saying why each did not. Those
/// still connecting carry on, for a client kept to ask again
/// ([`mailbox::Mailbox`]).
async fn ask_each<T, F, A>(
    relays: impl IntoIterator<Item = (RelayUrl, Relay)>,
    route: &Route,
    least: Duration,
    ask: F,
) -> anyhow::Result<Vec<T>>
where
    F: Fn(Relay) -> A,
    A: Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let timeout = route.timeout();
    let started = tokio::time::Instant::now();
    let mut trying = tokio::task::JoinSet::new();
    for (url, relay) in relays {
        let asked = ask(relay.clone());
        trying.spawn(async move {
            let answer = async {
                relay.try_connect().timeout(timeout).await?;
                let connected = started.elapsed();
                match tokio::time::timeout(timeout, asked).await {
                    Ok(answer) => answer.map(|answer| (answer, connected)),
                    Err(_) => anyhow::bail!("no answer in {} s", timeout.as_secs()),
                }
            };
            (url, answer.await)
        });
    }
    let mut until = None;
    let (mut answers, mut failed) = (Vec::new(), Vec::new());
    loop {
        let tried = match until {
            None => trying.join_next().await,
            Some(until) => match tokio::time::timeout_at(until, trying.join_next()).await {
                Ok(tried) => tried,
                Err(_) => break,
            },
        };
        match tried {
            None => break,
            Some(Ok((url, Ok((answer, connected))))) => {
                tracing::debug!(%url, ?connected, took = ?started.elapsed(), "a relay answered");
                until.get_or_insert_with(|| {
                    let now = tokio::time::Instant::now();
                    now + (now - started).clamp(least, GRACE)
                });
                answers.push(answer);
            }
            Some(Ok((url, Err(e)))) => {
                tracing::debug!(%url, took = ?started.elapsed(), "a relay failed: {e:#}");
                failed.push(format!("{url}: {e:#}"));
            }
            Some(Err(e)) => failed.push(format!("a relay: {e}")),
        }
    }
    // Left to finish: a connection cut short would stay connecting for
    // good, never tried again.
    tracing::debug!(
        answered = answers.len(),
        left_out = trying.len(),
        took = ?started.elapsed(),
        failed = ?failed,
        "relays asked"
    );
    trying.detach_all();
    if answers.is_empty() {
        if failed.is_empty() {
            failed.push(format!("none in {} s", timeout.as_secs()));
        }
        anyhow::bail!("no Nostr relay answered: {}", failed.join("; "));
    }
    Ok(answers)
}

/// `event`, if a valid, unexpired announcement of `role` for `network`,
/// signed no later than [`MAX_AHEAD`] from now: one dated later would
/// outlast and stand in for those its key makes in time.
fn read(event: &Event, role: Role, network: &str) -> Option<Found> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let valid = event.kind == Kind::Custom(KIND)
        && event.tags.identifier().as_deref() == Some(role.id())
        && !event.is_expired()
        && event.created_at.as_secs() <= now.saturating_add(MAX_AHEAD.as_secs())
        && event.content.len() <= MAX_CONTENT
        && event.verify().is_ok();
    if !valid {
        return None;
    }
    let mut announcement: Announcement = serde_json::from_str(&event.content).ok()?;
    if announcement.network != network {
        return None;
    }
    announcement.urls.retain(|url| usable(url));
    announcement.urls.truncate(MAX_URLS);
    if announcement.urls.is_empty() {
        return None;
    }
    Some(Found {
        key: event.pubkey.to_hex(),
        announcement,
        at: event.created_at.as_secs(),
    })
}

/// Whether `url` is an `http[s]://` URL of reasonable length.
fn usable(url: &str) -> bool {
    url.len() <= MAX_URL
        && (url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_relays_are_onion_services_only_over_tor_and_none_on_regtest() {
        let clear = default_relays("signet", false);
        assert!(!clear.is_empty());
        assert!(clear.iter().all(|r| r.starts_with("wss://") && !onion(r)));
        let all = default_relays("bitcoin", true);
        assert_eq!(all.len(), DEFAULT_RELAYS.len());
        assert_eq!(all.iter().filter(|r| onion(r)).count(), 2);
        assert!(clear.iter().all(|r| all.contains(r)));
        assert!(default_relays("regtest", true).is_empty());
        assert!(default_relays("regtest", false).is_empty());
    }

    #[tokio::test]
    async fn an_announcement_signed_well_ahead_of_the_clock_is_not_read() {
        let announcer = Announcer {
            client: Client::default(),
            keys: keys(&[3; 32]).unwrap(),
            role: Role::Hub,
        };
        let announcement = Announcement {
            urls: vec!["https://hub.example".into()],
            network: "regtest".into(),
            name: None,
        };
        let at = |ahead: u64| {
            let at = Timestamp::now() + Duration::from_secs(ahead);
            let event = announcer.event(&announcement, at);
            read(&event.unwrap(), Role::Hub, "regtest")
        };
        assert!(at(0).is_some());
        assert!(at(60).is_some(), "a clock a little off");
        assert!(at(MAX_AHEAD.as_secs() + 60).is_none());
        assert!(at(365 * 24 * 3600).is_none());
    }

    #[test]
    fn onion_urls_are_told_by_their_host() {
        let v3 = "gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion";
        assert!(onion(&format!("ws://{v3}")));
        assert!(onion(&format!("http://{}:8080/v1", v3.to_uppercase())));
        assert!(onion(v3));
        assert!(!onion("wss://relay.example"));
        assert!(!onion("wss://onion.example/x.onion"));
        assert!(!onion("https://relay.example?h=a.onion"));
    }
}
