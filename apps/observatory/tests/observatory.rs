//! The observatory against a fake hub and provider on loopback: probed,
//! their terms kept, and shown on the page and in the JSON API.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{body::Body, http::Request, routing::get, Json, Router};
use http_body_util::BodyExt;
use licash_nostr::Route;
use licash_observatory::{
    budget::{self, Budget, Kind},
    mover::{Mover, Moving, Skipped},
    observer::{self, Watching},
    probe::Dialer,
    store::{self, Action, Outcome, Role, Service, Store},
    view::{self, Range, Records},
    web::{self, App},
};
use serde_json::{json, Value};
use tower::ServiceExt;

/// A valid point: the generator, compressed.
const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const HUB_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const PROVIDER_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn address() -> String {
    format!("{G}{G}{G}")
}

fn hub_info() -> Value {
    json!({
        "keysets": [],
        "address": address(),
        "fees": {
            "spend": {"base": 1, "ppm": 100},
            "lock": {"base": 1, "ppm": 100},
            "refund": {"base": 1, "ppm": 0},
            "output_msat": 100
        },
        "locks": null,
        "lightning": {
            "node": "02aa", "pay": {"base": 2, "ppm": 1000}, "receive": {"base": 1, "ppm": 100},
            "pay_slack": 40, "max_pay": 1000000, "min_receive": 100, "max_receive": 500000
        },
        "deposits": {
            "fee": {"base": 300, "ppm": 0}, "min": 10000, "max": 1000000,
            "depth": 1, "window": 144, "timeout": 1008
        },
        "nostr": HUB_KEY
    })
}

fn provider_info() -> Value {
    json!({
        "address": address(),
        "fee": {"base": 10, "ppm": 1000},
        "min": 1000,
        "max": 1000000,
        "margin": 200,
        "hubs": [{"address": address(), "max": 250000}],
        "nostr": PROVIDER_KEY,
        "chain": {"fee": {"base": 100, "ppm": 1000}, "miner": 400, "rate": 2000,
                  "min": 10000, "max": 500000, "margin": 72}
    })
}

/// A service on loopback answering `/health` and its info at `path`.
async fn serve(path: &'static str, info: Value) -> String {
    let router = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(path, get(move || async move { Json(info) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{at}")
}

/// An address nothing answers at.
async fn closed() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{at}")
}

fn announced(id: &str, role: Role, urls: Vec<String>) -> Service {
    let now = store::now();
    Service {
        id: id.into(),
        role,
        key: Some(id.into()),
        name: None,
        urls,
        first_seen: now,
        last_seen: now,
    }
}

struct World {
    _dir: tempfile::TempDir,
    store: Arc<Store>,
    hub: String,
    provider: String,
}

async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("observatory.sqlite")).unwrap());
    let hub = serve(licash_api::INFO, hub_info()).await;
    let provider = serve(licash_api::swaps::SWAPS_INFO, provider_info()).await;
    let down = closed().await;
    store
        .seen(&announced(HUB_KEY, Role::Hub, vec![hub.clone(), down]))
        .unwrap();
    store
        .seen(&announced(
            PROVIDER_KEY,
            Role::Provider,
            vec![provider.clone()],
        ))
        .unwrap();
    World {
        _dir: dir,
        store,
        hub,
        provider,
    }
}

fn watching() -> Watching {
    Watching {
        network: "regtest".into(),
        relays: Vec::new(),
        route: Route::Direct,
        dialer: Dialer::direct_reaching(true),
        hubs: Vec::new(),
        providers: Vec::new(),
        probe_every: Duration::from_millis(20),
        discover_every: Duration::from_secs(600),
        timeout: Duration::from_secs(5),
    }
}

fn view(store: &Store, budget: Option<Budget>) -> view::View {
    let now = store::now();
    let records = Records::read(store, now - Range::Week.millis()).unwrap();
    view::compute(
        records,
        view::Context {
            network: "regtest".into(),
            tor: false,
            now,
            range: Range::Week,
            fresh: 60_000,
            budget,
        },
    )
}

#[tokio::test]
async fn a_round_probes_every_url_and_keeps_the_terms() {
    let w = world().await;
    for _ in 0..3 {
        observer::round(w.store.clone(), watching()).await;
    }
    let probes = w.store.probes_since(0).unwrap();
    assert_eq!(
        probes.len(),
        9,
        "two URLs of the hub and one of the provider, 3 times"
    );
    let answered = probes.iter().filter(|p| p.ok).count();
    assert_eq!(answered, 6);
    let failed = probes.iter().find(|p| !p.ok).unwrap();
    assert!(failed.open_ms.is_none() && failed.error.is_some());
    let ok = probes.iter().find(|p| p.ok).unwrap();
    assert!(ok.open_ms.is_some() && ok.rtt_ms.is_some() && ok.info_ms.is_some());
    // Terms are kept once while unchanged.
    assert_eq!(w.store.latest_terms().unwrap().len(), 2);

    let view = view(&w.store, None);
    let hub = &view.hubs[0];
    assert_eq!(hub.health.up, Some(true), "one URL answers");
    assert_eq!(hub.health.uptime, Some(0.5));
    assert_eq!(hub.health.probes, 6);
    assert_eq!(hub.health.urls.len(), 2);
    assert_eq!(hub.inbound, 250_000, "the provider moves into it");
    let provider = &view.providers[0];
    assert_eq!(provider.health.uptime, Some(1.0));
    assert_eq!(provider.hubs, vec![(HUB_KEY.to_owned(), 250_000)]);

    // Ranked: the provider first by uptime.
    assert_eq!(view.boards.uptime[0].id, PROVIDER_KEY);
    assert_eq!(view.boards.uptime.len(), 2);
    assert_eq!(view.boards.latency.len(), 2);

    let fee = |what: &str| view.fees.iter().find(|f| f.what == what).unwrap().clone();
    // 1 sat + 100 ppm of 10,000 sat.
    assert_eq!(fee("Pay in Licash").median, Some(2));
    // 100 sat + 1,000 ppm of 10,000, and 400 for miners.
    assert_eq!(fee("Pay on Bitcoin").median, Some(510));
    assert_eq!(fee("Protection, opening").offered, 0);
    let _ = (&w.hub, &w.provider);
}

#[tokio::test]
async fn a_url_answering_for_another_key_is_not_the_service() {
    let w = world().await;
    let impostor = announced(
        "3333333333333333333333333333333333333333333333333333333333333333",
        Role::Hub,
        vec![w.hub.clone()],
    );
    let (probe, info) = observer::check(
        &Dialer::direct_reaching(true),
        &impostor,
        &w.hub,
        Duration::from_secs(5),
    )
    .await;
    assert!(!probe.ok);
    assert!(info.is_none());
    assert_eq!(
        probe.error.as_deref(),
        Some("info: not the service that announced it")
    );
}

/// An info larger than any service's is not taken as one, nor stored.
#[tokio::test]
async fn an_info_too_large_is_not_the_services() {
    let mut info = hub_info();
    info["padding"] = json!("x".repeat(observer::MAX_INFO));
    let url = serve(licash_api::INFO, info).await;
    let service = announced(HUB_KEY, Role::Hub, vec![url.clone()]);
    let dialer = Dialer::direct_reaching(true);
    let (probe, info) = observer::check(&dialer, &service, &url, Duration::from_secs(5)).await;
    assert!(!probe.ok && info.is_none());
    let error = probe.error.unwrap_or_default();
    assert!(error.contains("more than"), "{error}");
    // Its info as served, under the bound: the service's.
    let url = serve(licash_api::INFO, hub_info()).await;
    let (probe, _) = observer::check(&dialer, &service, &url, Duration::from_secs(5)).await;
    assert!(probe.ok, "{:?}", probe.error);
}

#[tokio::test]
async fn a_configured_service_is_watched_by_its_url() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let mut watching = watching();
    watching.hubs = vec!["http://hub.example/".into()];
    observer::discover(&store, &watching).await.unwrap();
    let services = store.services().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].id, "http://hub.example");
    assert_eq!(services[0].key, None);
}

async fn get_page(app: Router, path: &str) -> (u16, String) {
    let response = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn action(kind: Kind, source: &str, outcome: Outcome, cost: u64) -> Action {
    Action {
        id: 0,
        kind: kind.key().into(),
        started: store::now() - 5_000,
        ended: None,
        source: Some(source.into()),
        target: Some(source.into()),
        via: None,
        amount: 1_000,
        quoted: Some(cost),
        cost: None,
        outcome,
        detail: None,
        swapped: None,
    }
}

#[tokio::test]
async fn the_pages_show_what_was_seen() {
    let w = world().await;
    observer::round(w.store.clone(), watching()).await;
    let started = action(Kind::Hub, HUB_KEY, Outcome::Running, 2);
    let id = w.store.action_started(&started).unwrap();
    w.store
        .action_ended(id, store::now(), Outcome::Done, Some(2), None, None)
        .unwrap();
    let id = w.store.action_started(&started).unwrap();
    w.store
        .action_ended(
            id,
            store::now(),
            Outcome::Failed,
            Some(1),
            Some("the hub refused"),
            None,
        )
        .unwrap();
    let month = w.store.actions_since(0).unwrap();
    let budget = Budget::new(
        10_000,
        &month,
        Some(5_000),
        &[(Kind::Hub, true, Some(store::now() + 600_000))],
    );
    assert_eq!(budget.spent, 3);
    assert_eq!(budget::spent(&month, Some(Kind::Hub)), 3);
    let app = Arc::new(App::new(
        w.store.clone(),
        "signet".into(),
        true,
        Duration::from_secs(60),
        Arc::new(Mutex::new(Some(budget))),
    ));
    let router = web::router(vec![app]);

    let (status, page) = get_page(router.clone(), "/signet").await;
    assert_eq!(status, 200);
    assert!(page.contains("Test network"), "a test network is said");
    assert!(page.contains("Leaderboards"));
    assert!(page.contains("Fees on 10,000 sat"));
    assert!(page.contains("1 of 1"), "the provider is up");
    assert!(page.contains("50%"), "half the moves succeeded");

    let (status, page) = get_page(router.clone(), "/signet/hubs?range=24h").await;
    assert_eq!(status, 200);
    assert!(page.contains("127.0.0.1"));
    assert!(page.contains("1 sat + 0.01%"), "the hub's fee, as terms");
    assert!(page.contains("up to 250,000 sat"));

    let (status, page) = get_page(router.clone(), "/signet/providers").await;
    assert_eq!(status, 200);
    assert!(page.contains("10 sat + 0.10%"));

    let (status, page) = get_page(router.clone(), &format!("/signet/service?id={HUB_KEY}")).await;
    assert_eq!(status, 200);
    assert!(page.contains("Receive on Bitcoin"));
    assert!(page.contains("the hub refused"));
    assert!(page.contains("<svg"));

    let (status, _) = get_page(router.clone(), "/signet/service?id=nobody").await;
    assert_eq!(status, 404);

    let (status, page) = get_page(router.clone(), "/signet/moves").await;
    assert_eq!(status, 200);
    assert!(page.contains("Pay in Licash"));
    assert!(page.contains("5,000 sat"));

    let (status, body) = get_page(router.clone(), "/signet/api/v1/view?range=30d").await;
    assert_eq!(status, 200);
    let json: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["range"], "30d");
    assert_eq!(json["hubs"][0]["id"], HUB_KEY);
    assert_eq!(json["budget"]["spent"], 3);

    let (status, body) = get_page(router, "/health").await;
    assert_eq!((status, body.as_str()), (200, "ok"));
}

#[test]
fn a_later_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("o.sqlite");
    drop(Store::open(&path).unwrap());
    assert!(Store::open(&path).is_ok(), "its own version opens again");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.pragma_update(None, "user_version", 2).unwrap();
    drop(db);
    let refused = Store::open(&path).err().unwrap().to_string();
    assert!(refused.contains("later version"), "{refused}");
}

#[tokio::test]
async fn an_unfunded_mover_moves_nothing_and_says_so() {
    let w = world().await;
    observer::round(w.store.clone(), watching()).await;
    let mut seed = [7; 32];
    seed[0] = 1;
    let wallet = licash_wallet::Wallet::create(
        &w._dir.path().join("wallet.sqlite"),
        &seed,
        licash::spend::ChainProfile::Core30DefaultRegtest,
        licash_transport::Http::new(None).unwrap(),
    )
    .unwrap();
    let shown = Arc::new(Mutex::new(None));
    let moving = Moving {
        store: w.store.clone(),
        monthly: 10_000,
        amount: 1_000,
        fresh: 60_000,
        shown: shown.clone(),
        chain: None,
        block_secs: 600,
    };
    let mut mover = Mover::new(wallet, moving).unwrap();
    for kind in [Kind::Hub, Kind::Swap, Kind::Lightning] {
        let skipped = mover.move_now(kind).await.unwrap_err();
        assert!(
            matches!(skipped, Skipped::NoRoute(_)),
            "{kind:?}: {skipped:?}"
        );
    }
    assert!(
        w.store.actions_since(0).unwrap().is_empty(),
        "nothing recorded"
    );
    let budget = shown.lock().unwrap().clone().unwrap();
    assert_eq!(budget.balance, Some(0));
    assert!(
        budget.notes.iter().any(|n| n.contains("fund it")),
        "{:?}",
        budget.notes
    );
    // The fake hub's info is not a hub the wallet can use.
    assert!(
        budget.notes.iter().any(|n| n.contains("can't use")),
        "{:?}",
        budget.notes
    );
    let hub = budget.kinds.iter().find(|k| k.kind == Kind::Hub).unwrap();
    let why = hub.waiting.as_deref().unwrap();
    assert!(
        why.starts_with("No route:"),
        "a kind waiting says why: {why}"
    );
    let chain = budget.kinds.iter().find(|k| k.kind == Kind::Chain).unwrap();
    assert!(!chain.enabled);
}

#[tokio::test]
async fn several_networks_are_served_each_under_its_name() {
    let w = world().await;
    observer::round(w.store.clone(), watching()).await;
    let other = tempfile::tempdir().unwrap();
    let empty = Arc::new(Store::open(&other.path().join("o.sqlite")).unwrap());
    let app = |store: &Arc<Store>, network: &str| {
        Arc::new(App::new(
            store.clone(),
            network.into(),
            false,
            Duration::from_secs(60),
            Arc::new(Mutex::new(None)),
        ))
    };
    let router = web::router(vec![app(&w.store, "mutinynet"), app(&empty, "bitcoin")]);

    let response = router
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 307);
    assert_eq!(response.headers()["location"], "/mutinynet");

    let (status, page) = get_page(router.clone(), "/mutinynet/hubs").await;
    assert_eq!(status, 200);
    assert!(page.contains("127.0.0.1"), "its own records");
    assert!(
        page.contains("href=\"/bitcoin/hubs?range=7d\""),
        "a switch to the other"
    );
    assert!(
        page.contains("href=\"/mutinynet/service?id="),
        "links stay in its network"
    );

    let (status, page) = get_page(router.clone(), "/bitcoin/hubs/").await;
    assert_eq!(status, 404, "no such page");
    let (status, page_bitcoin) = get_page(router.clone(), "/bitcoin").await;
    assert_eq!(status, 200);
    assert!(!page_bitcoin.contains("Test network"), "{page}");
    assert!(
        !page_bitcoin.contains("127.0.0.1"),
        "not the other's records"
    );
    let (status, _) = get_page(router.clone(), "/nowhere").await;
    assert_eq!(status, 404);
    let (status, _) = get_page(router, "/bitcoin/").await;
    assert_eq!(status, 200);
}

/// The first layout of `actions`, as the image first deployed wrote it.
const FIRST_LAYOUT: &str = "
CREATE TABLE services (
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    -- The Nostr key that announced it, in hex; none for one configured.
    key TEXT,
    name TEXT,
    -- Its URLs, a JSON array, in the order announced.
    urls TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE TABLE probes (
    at INTEGER NOT NULL,
    service TEXT NOT NULL,
    url TEXT NOT NULL,
    ok INTEGER NOT NULL,
    open_ms INTEGER,
    rtt_ms INTEGER,
    info_ms INTEGER,
    error TEXT
);
CREATE INDEX probes_at ON probes (at);
CREATE TABLE terms (
    service TEXT NOT NULL,
    at INTEGER NOT NULL,
    info TEXT NOT NULL,
    PRIMARY KEY (service, at)
);
CREATE TABLE actions (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    started INTEGER NOT NULL,
    ended INTEGER,
    source TEXT,
    target TEXT,
    via TEXT,
    amount INTEGER NOT NULL,
    quoted INTEGER,
    cost INTEGER,
    outcome TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX actions_started ON actions (started);
";

#[test]
fn a_file_of_the_first_layout_gains_its_column_and_keeps_its_moves() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("o.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(FIRST_LAYOUT).unwrap();
    db.execute(
        "INSERT INTO actions (kind, started, ended, amount, quoted, cost, outcome)
         VALUES ('chain', 1000, 142000, 10000, 1338, 1328, 'done')",
        [],
    )
    .unwrap();
    db.pragma_update(None, "user_version", 1).unwrap();
    drop(db);

    for _ in 0..2 {
        let store = Store::open(&path).unwrap();
        let moves = store.actions_since(0).unwrap();
        assert_eq!(moves.len(), 1, "its move is kept");
        assert_eq!(moves[0].cost, Some(1328));
        assert_eq!(moves[0].swapped, None, "never timed: unknown");
        assert_eq!(
            budget::took(&moves[0]),
            None,
            "not the waits for blocks in its stead"
        );
    }
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1, "the version is the one an older image reads");
}

#[test]
fn a_move_on_bitcoin_is_timed_by_its_swap_and_others_by_all_of_them() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let mut chain = action(Kind::Chain, HUB_KEY, Outcome::Running, 1_338);
    chain.started = store::now() - 150_000;
    let id = store.action_started(&chain).unwrap();
    store
        .action_ended(
            id,
            store::now(),
            Outcome::Done,
            Some(1_328),
            None,
            Some(38_000),
        )
        .unwrap();
    let hub = action(Kind::Hub, HUB_KEY, Outcome::Running, 3);
    let id = store.action_started(&hub).unwrap();
    store
        .action_ended(id, store::now(), Outcome::Done, Some(3), None, None)
        .unwrap();
    let moves = store.actions_since(0).unwrap();
    let by = |kind: Kind| moves.iter().find(|a| a.kind == kind.key()).unwrap();
    assert_eq!(
        budget::took(by(Kind::Chain)),
        Some(38_000),
        "the swap, not the 150 s"
    );
    assert!(
        budget::took(by(Kind::Hub)).unwrap() >= 5_000,
        "the whole of it"
    );

    let records = Records::read(&store, 0).unwrap();
    let view = view::compute(
        records,
        view::Context {
            network: "regtest".into(),
            tor: false,
            now: store::now(),
            range: Range::Week,
            fresh: 60_000,
            budget: None,
        },
    );
    let kind = view
        .moves
        .iter()
        .find(|k| k.kind == Kind::Chain.key())
        .unwrap();
    assert_eq!(kind.duration, Some(38_000));
}

#[tokio::test]
async fn a_young_services_chart_covers_what_there_is_of_the_range() {
    let w = world().await;
    observer::round(w.store.clone(), watching()).await;
    let view = view(&w.store, None);
    let chart = &view.hubs[0].health.chart;
    assert_eq!(chart.len(), 48);
    let week = Range::Week.millis();
    // From a twelfth of the week at most, not all seven days of empty cells.
    assert!(
        view.at - chart[0].at <= week / 12 + 1_000,
        "{}",
        view.at - chart[0].at
    );
    assert!(chart.iter().any(|b| b.total > 0), "its probes are in it");
    let full = view::compute(
        Records::read(&w.store, 0).unwrap(),
        view::Context {
            network: "regtest".into(),
            tor: false,
            now: store::now(),
            range: Range::Day,
            fresh: 60_000,
            budget: None,
        },
    );
    assert!(
        full.hubs[0].health.chart.last().unwrap().total > 0,
        "the newest cell has the probe"
    );
}

/// The services answering as themselves lately are told apart from those
/// that never did, or not since: those a flood of announcements cannot
/// crowd out, asked for by key and probed apart.
#[test]
fn the_services_answering_lately_are_those_with_a_probe_ok_since() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let probe = |at, service: &str, ok| store::Probe {
        at,
        service: service.into(),
        url: format!("https://{service}.example"),
        ok,
        open_ms: None,
        rtt_ms: None,
        info_ms: None,
        error: None,
    };
    for p in [
        probe(10, "honest", true),
        probe(20, "honest", true),
        probe(30, "honest", false),
        probe(20, "sybil", false),
        probe(5, "gone", true),
    ] {
        store.probed(&p).unwrap();
    }
    let answered = store.answered_since(10).unwrap();
    assert_eq!(answered.len(), 1, "{answered:?}");
    assert_eq!(answered["honest"], 20);
}

/// Answering as the key that announced is as free as announcing: while as
/// many services of a role as are watched answered so, an announcement of
/// a new key is passed over all the same.
#[tokio::test]
async fn announcements_of_new_keys_wait_while_as_many_answering_are_watched() {
    use licash_nostr::{Announcement, Announcer};
    let relay = nostr_sdk::prelude::MockRelay::run().await.unwrap();
    let relays = vec![relay.url().await.to_string()];
    let new = Announcer::new(&[23; 32], licash_nostr::Role::Hub, &relays, &Route::Direct);
    let new = new.await.unwrap();
    let announcement = Announcement {
        urls: vec!["https://new.example".into()],
        network: "regtest".into(),
        name: None,
    };
    new.announce(&announcement).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let at = store::now();
    for i in 0..observer::MAX_ANNOUNCED {
        let id = format!("{i:064x}");
        let url = format!("https://sybil{i}.example");
        store
            .seen(&announced(&id, Role::Hub, vec![url.clone()]))
            .unwrap();
        let answered = store::Probe {
            at,
            service: id,
            url,
            ok: true,
            open_ms: Some(1),
            rtt_ms: Some(1),
            info_ms: Some(1),
            error: None,
        };
        store.probed(&answered).unwrap();
    }
    let watching = Watching {
        relays,
        ..watching()
    };
    observer::discover(&store, &watching).await.unwrap();
    let services = store.services().unwrap();
    assert_eq!(services.len(), observer::MAX_ANNOUNCED);
    assert!(!services.iter().any(|s| s.id == new.key()));
}

/// Announcements pile up no longer than the history: a service announced
/// and gone that long is forgotten with its terms, even one that answered
/// as itself, which is free too, unlike one configured or one seen since.
#[test]
fn announced_services_never_answering_are_forgotten_with_the_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let service = |id: &str, key: Option<&str>, last_seen| Service {
        id: id.into(),
        role: Role::Hub,
        key: key.map(Into::into),
        name: None,
        urls: vec![format!("https://{id}.example")],
        first_seen: 1,
        last_seen,
    };
    for s in [
        service("sybil", Some("sybil"), 10),
        service("answered", Some("answered"), 10),
        service("recent", Some("recent"), 200),
        service("https://configured.example", None, 10),
    ] {
        store.seen(&s).unwrap();
    }
    store.terms_seen("answered", 5, "{}").unwrap();
    store.prune(100).unwrap();
    let mut kept: Vec<String> = store
        .services()
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    kept.sort();
    assert_eq!(kept, ["https://configured.example", "recent"]);
    assert!(store.latest_terms().unwrap().is_empty());
}

/// Each service's terms are kept as they change, the latest few of them:
/// only the latest is read, however often a service changes its own.
#[test]
fn a_service_keeps_its_latest_terms_however_often_they_change() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
    let now = store::now();
    store
        .seen(&announced(
            HUB_KEY,
            Role::Hub,
            vec!["https://a.example".into()],
        ))
        .unwrap();
    let versions = store::TERMS_KEPT + 10;
    for n in 0..versions {
        store
            .terms_seen(HUB_KEY, now - versions + n, &format!("{{\"n\":{n}}}"))
            .unwrap();
    }
    store
        .prune(now - observer::millis(observer::HISTORY))
        .unwrap();
    let db = rusqlite::Connection::open(dir.path().join("o.sqlite")).unwrap();
    let kept: i64 = db
        .query_row("SELECT count(*) FROM terms", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, store::TERMS_KEPT);
    let latest = store.latest_terms().unwrap();
    assert_eq!(latest[0].2, format!("{{\"n\":{}}}", versions - 1));
}

/// Of the services announced that answered as themselves, those first
/// seen are probed apart from the rest, so a flood of new keys answering
/// for themselves does not delay them: at most so many of each role.
#[test]
fn the_services_known_longest_are_probed_apart_from_newer_ones() {
    let mut services = Vec::new();
    let mut answered = std::collections::HashMap::new();
    for i in 0..observer::SENIOR + 10 {
        let id = format!("{i:064x}");
        services.push(Service {
            first_seen: 1_000 + i as i64,
            ..announced(&id, Role::Provider, vec![format!("https://p{i}.example")])
        });
        answered.insert(id, 5_000);
    }
    // One known longer that never answered lately: not among them.
    services.push(Service {
        first_seen: 1,
        ..announced(
            &"ff".repeat(32),
            Role::Provider,
            vec!["https://q.example".into()],
        )
    });
    let senior = observer::senior(&services, &answered);
    assert_eq!(senior.len(), observer::SENIOR);
    assert!(senior.contains(&format!("{:064x}", 0)));
    assert!(!senior.contains(&format!("{:064x}", observer::SENIOR)));
    assert!(!senior.contains(&"ff".repeat(32)));
}

/// While as many services of a role as are kept never answered, an
/// announcement of a new key is passed over, and a known key's still
/// updates it. Those gone a week without ever answering are forgotten
/// with their probes, making room again.
#[tokio::test]
async fn announcements_of_new_keys_wait_while_as_many_never_answering_are_kept() {
    use licash_nostr::{Announcement, Announcer};
    let relay = nostr_sdk::prelude::MockRelay::run().await.unwrap();
    let relays = vec![relay.url().await.to_string()];
    let hub = licash_nostr::Role::Hub;
    let known = Announcer::new(&[21; 32], hub, &relays, &Route::Direct);
    let new = Announcer::new(&[22; 32], hub, &relays, &Route::Direct);
    let (known, new) = (known.await.unwrap(), new.await.unwrap());
    let announcement = |url: &str| Announcement {
        urls: vec![url.into()],
        network: "regtest".into(),
        name: None,
    };
    known
        .announce(&announcement("https://known.example"))
        .await
        .unwrap();
    new.announce(&announcement("https://new.example"))
        .await
        .unwrap();
    let watching = Watching {
        relays,
        ..watching()
    };
    let gone = observer::millis(observer::KEPT) + 60_000;
    for (age, admitted) in [(0, false), (gone, true)] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("o.sqlite")).unwrap();
        let at = store::now() - age;
        for i in 0..observer::MAX_ANNOUNCED {
            let id = format!("{i:064x}");
            let urls = vec![format!("https://sybil{i}.example")];
            let sybil = Service {
                last_seen: at,
                first_seen: at,
                ..announced(&id, Role::Hub, urls)
            };
            store.seen(&sybil).unwrap();
            let failed = store::Probe {
                at,
                service: id,
                url: format!("https://sybil{i}.example"),
                ok: false,
                open_ms: None,
                rtt_ms: None,
                info_ms: None,
                error: Some("refused".into()),
            };
            store.probed(&failed).unwrap();
        }
        let before = announced(&known.key(), Role::Hub, vec!["https://old.example".into()]);
        store.seen(&before).unwrap();
        observer::discover(&store, &watching).await.unwrap();
        let services = store.services().unwrap();
        let of = |key: String| services.iter().find(|s| s.id == key).cloned();
        let kept = of(known.key()).expect("known");
        assert_eq!(kept.urls, ["https://known.example"], "{age}");
        assert_eq!(of(new.key()).is_some(), admitted, "{age}");
        let sybils = match admitted {
            false => observer::MAX_ANNOUNCED,
            true => 0,
        };
        assert_eq!(services.len(), sybils + 1 + usize::from(admitted), "{age}");
        let probes = store.probes_since(0).unwrap();
        assert_eq!(probes.len(), sybils, "forgotten with their probes: {age}");
    }
}
