//! Watching without money: services found on Nostr (and those configured),
//! each probed at its URLs every few minutes, at a random moment of each
//! round, and its terms kept as they change.

use std::{collections::HashSet, sync::Arc, time::Duration};

use licash_nostr::Route;
use rand_core::{OsRng, RngCore};

use crate::{
    probe::{self, Dialer},
    store::{self, Probe, Role, Service, Store},
};

/// How long a service no longer announced is still probed: its downtime
/// counts against it, rather than vanishing with its announcement.
pub const KEPT: Duration = Duration::from_secs(7 * 24 * 3600);

/// How long probes are kept.
pub const HISTORY: Duration = Duration::from_secs(90 * 24 * 3600);

/// The most probes under way at once of services that answered as
/// themselves lately ([`Store::answered_since`]), or were configured.
const AT_ONCE: usize = 8;

/// The most probes under way at once of the others: announcing is free, so
/// a flood of them waits on itself, never on those above.
const AT_ONCE_UNPROVEN: usize = 4;

/// The most services of a role announced and seen in the last [`KEPT`]
/// that did not answer as themselves in it: past it, an announcement of a
/// key not stored already is passed over. Announcing is free, and each is
/// stored and probed.
pub const MAX_UNPROVEN: usize = 2_000;

/// What the observer watches, and how.
#[derive(Clone)]
pub struct Watching {
    /// The network's name: `bitcoin`, `signet`, `mutinynet` or `regtest`.
    pub network: String,
    pub relays: Vec<String>,
    pub route: Route,
    pub dialer: Dialer,
    /// Services to watch besides those announced, by URL.
    pub hubs: Vec<String>,
    pub providers: Vec<String>,
    pub probe_every: Duration,
    pub discover_every: Duration,
    /// How long a probe may take, all of it.
    pub timeout: Duration,
}

/// Look for services, and probe them, until dropped.
pub async fn run(store: Arc<Store>, watching: Watching) {
    let discovering = {
        let (store, watching) = (store.clone(), watching.clone());
        async move {
            loop {
                if let Err(e) = discover(&store, &watching).await {
                    tracing::warn!("looking for services: {e:#}");
                }
                tokio::time::sleep(watching.discover_every).await;
            }
        }
    };
    let probing = async move {
        // The first round once the first discovery had a moment.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let round = tokio::spawn(round(store.clone(), watching.clone()));
            tokio::time::sleep(watching.probe_every).await;
            round.abort();
            if let Err(e) = store.prune(store::now() - millis(HISTORY)) {
                tracing::warn!("forgetting old probes: {e:#}");
            }
        }
    };
    tokio::join!(discovering, probing);
}

/// Record the services announced now, and those configured.
pub async fn discover(store: &Store, watching: &Watching) -> anyhow::Result<()> {
    let now = store::now();
    for url in &watching.hubs {
        store.seen(&configured(url, Role::Hub, now))?;
    }
    for url in &watching.providers {
        store.seen(&configured(url, Role::Provider, now))?;
    }
    if watching.relays.is_empty() {
        return Ok(());
    }
    // Gone a while and never answering: forgotten, making room for others.
    let since = now - millis(KEPT);
    let forgotten = store.forget_unanswered(since)?;
    if forgotten > 0 {
        tracing::info!(forgotten, "services announced that never answered");
    }
    // Those that answered as themselves asked for by key too: a flood of
    // newer announcements, filling what relays answer, hides none of them.
    let services = store.services()?;
    let answered = store.answered_since(since)?;
    let stored: HashSet<&str> = services.iter().map(|s| s.id.as_str()).collect();
    for (role, announced) in [
        (Role::Hub, licash_nostr::Role::Hub),
        (Role::Provider, licash_nostr::Role::Swaps),
    ] {
        let mut known: Vec<(i64, String)> = (services.iter())
            .filter(|s| s.role == role)
            .filter_map(|s| Some((*answered.get(&s.id)?, s.key.clone()?)))
            .collect();
        // The latest to answer first, should there be more than are asked.
        known.sort_by(|a, b| b.cmp(a));
        let known: Vec<String> = known.into_iter().map(|(_, key)| key).collect();
        let found = licash_nostr::discover_known(
            &watching.relays,
            &watching.route,
            announced,
            &watching.network,
            &known,
        )
        .await?;
        tracing::debug!(role = role.name(), found = found.len(), "announcements");
        let mut unproven = (services.iter())
            .filter(|s| s.role == role && s.key.is_some() && s.last_seen >= since)
            .filter(|s| !answered.contains_key(&s.id))
            .count();
        let mut passed_over = 0;
        for found in found {
            if !stored.contains(found.key.as_str()) {
                if unproven >= MAX_UNPROVEN {
                    passed_over += 1;
                    continue;
                }
                unproven += 1;
            }
            store.seen(&Service {
                id: found.key.clone(),
                role,
                key: Some(found.key),
                name: found.announcement.name,
                urls: found.announcement.urls,
                first_seen: now,
                last_seen: now,
            })?;
        }
        if passed_over > 0 {
            tracing::warn!(
                role = role.name(),
                passed_over,
                unproven,
                "announcements of new keys passed over: as many services never answering are kept"
            );
        }
    }
    Ok(())
}

fn configured(url: &str, role: Role, now: i64) -> Service {
    let url = url.trim_end_matches('/').to_owned();
    Service {
        id: url.clone(),
        role,
        key: None,
        name: None,
        urls: vec![url],
        first_seen: now,
        last_seen: now,
    }
}

/// Probe every service's URLs once, each at a random moment of the round.
pub async fn round(store: Arc<Store>, watching: Watching) {
    let services = match store.services() {
        Ok(services) => services,
        Err(e) => return tracing::warn!("reading the services: {e:#}"),
    };
    let since = store::now() - millis(KEPT);
    let answered = match store.answered_since(since) {
        Ok(answered) => answered,
        Err(e) => return tracing::warn!("reading the services answering: {e:#}"),
    };
    let at_once = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
    let at_once_unproven = Arc::new(tokio::sync::Semaphore::new(AT_ONCE_UNPROVEN));
    let mut probes = tokio::task::JoinSet::new();
    let spread = millis(watching.probe_every) as u64 / 2;
    for service in services.into_iter().filter(|s| s.last_seen >= since) {
        let lane = match service.key.is_none() || answered.contains_key(&service.id) {
            true => &at_once,
            false => &at_once_unproven,
        };
        for url in service.urls.iter().filter(|u| watching.dialer.reaches(u)) {
            let (store, dialer, at_once) = (store.clone(), watching.dialer.clone(), lane.clone());
            let (service, url, timeout) = (service.clone(), url.clone(), watching.timeout);
            let delay = OsRng.next_u64() % spread.max(1);
            probes.spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _turn = at_once.acquire_owned().await;
                let probe = check(&dialer, &service, &url, timeout).await;
                if let Err(e) = store.probed(&probe.0) {
                    tracing::warn!("recording a probe: {e:#}");
                }
                if let Some(info) = probe.1 {
                    if let Err(e) = store.terms_seen(&service.id, probe.0.at, &info) {
                        tracing::warn!("recording terms: {e:#}");
                    }
                }
            });
        }
    }
    while probes.join_next().await.is_some() {}
}

/// Probe `url` of `service`: the probe, and the info it answered,
/// normalized, if it is that of the service that announced the URL. A
/// service configured, announced by no key, may be local.
pub async fn check(
    dialer: &Dialer,
    service: &Service,
    url: &str,
    timeout: Duration,
) -> (Probe, Option<String>) {
    let at = store::now();
    let path = match service.role {
        Role::Hub => licash_api::INFO,
        Role::Provider => licash_api::swaps::SWAPS_INFO,
    };
    let dialer = match service.key {
        None => dialer.trusting(),
        Some(_) => dialer.clone(),
    };
    let probed = probe::probe(&dialer, url, path, timeout).await;
    let info = probed
        .info
        .and_then(|body| verified(service, &body).map_err(|e| format!("info: {e}")));
    let (ok, info, error) = match info {
        Ok(info) => (true, Some(info), None),
        Err(e) => (false, None, Some(e)),
    };
    if let Some(e) = &error {
        tracing::debug!(%url, "probe failed: {e}");
    }
    let probe = Probe {
        at,
        service: service.id.clone(),
        url: url.to_owned(),
        ok,
        open_ms: probed.times.open,
        rtt_ms: probed.times.rtt,
        info_ms: probed.times.info,
        error,
    };
    (probe, info)
}

/// The info in `body`, as JSON again, if it is of the service's role and
/// names the key that announced it. Only its shape and key are checked
/// here: its terms are read part by part when shown.
fn verified(service: &Service, body: &[u8]) -> Result<String, String> {
    let info: serde_json::Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
    let nostr = crate::terms::nostr(&info, service.role == Role::Hub)?;
    if let Some(key) = &service.key {
        if !nostr.is_some_and(|n| n.eq_ignore_ascii_case(key)) {
            return Err("not the service that announced it".into());
        }
    }
    Ok(info.to_string())
}

pub fn millis(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}
