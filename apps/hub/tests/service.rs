//! The service over its router, in process: each endpoint's body, status
//! and problem code.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, SignedProposal},
    claim::Branch,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{lock_hash, ChainProfile, Output, Proposal, TimedLock, TimedTerms},
    unlink::{Nonce, Session},
};
use licash_api::{
    Code, Evidenced, Hex, Info, Inquire, Issued, Lock, LockState, Locked, Locks, Offer, Offered,
    Problem, Refund, Release, Released, Settle, Settled, Unlink, Unlinked,
};
use licash_hub::{Fee, Hub, Policy};
use licash_hub_service::notify::Notifier;
use licash_notify::Timing;
use serde::de::DeserializeOwned;
use tower::ServiceExt;

const MAX_POW: u32 = 6;

struct Service {
    dir: tempfile::TempDir,
    hub: Arc<Hub>,
    app: Router,
    keys: IssuerKeys,
    keyset: Keyset,
}

fn service(fee: u64) -> Service {
    service_with(Policy {
        spend: Fee { base: fee, ppm: 0 },
        ..Policy::default()
    })
}

fn service_with(policy: Policy) -> Service {
    let dir = tempfile::tempdir().unwrap();
    let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
    Hub::init(&seed, &db, MAX_POW).unwrap();
    let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
    let mut secret = [0; 32];
    hex::decode_to_slice(std::fs::read_to_string(&seed).unwrap().trim(), &mut secret).unwrap();
    let keys = IssuerKeys::from_seed(&secret, 0, MAX_POW).unwrap();
    let keyset = keys.keyset().unwrap();
    Service {
        dir,
        app: licash_hub_service::router(hub.clone(), Default::default()),
        hub,
        keys,
        keyset,
    }
}

impl Service {
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
    ) -> (StatusCode, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(path);
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let request = request
            .body(body.map_or_else(Body::empty, Body::from))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body.to_vec())
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &impl serde::Serialize) -> T {
        let (status, body) = self
            .call(
                Method::POST,
                path,
                Some(serde_json::to_string(body).unwrap()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    /// The problem a request is answered with, checked against its status.
    async fn problem(&self, path: &str, body: String) -> Problem {
        let (status, body) = self.call(Method::POST, path, Some(body)).await;
        let problem: Problem = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.as_u16(), problem.code.status(), "{problem:?}");
        problem
    }

    async fn info(&self) -> Info {
        let (status, body) = self.call(Method::GET, licash_api::INFO, None).await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice(&body).unwrap()
    }

    fn mint(&self, to: &OwnerKeys, denom: u64) -> Coin {
        mint_under(&self.keys, &self.keyset, to, denom)
    }
}

fn mint_under(keys: &IssuerKeys, keyset: &Keyset, to: &OwnerKeys, denom: u64) -> Coin {
    let d = Ephemeral::random()
        .derive(&to.address(), denom, Branch::Pay, 0)
        .unwrap();
    let output = Output::from_derivation(&d).unwrap();
    let proof = keys.prove_blinded(denom, output.blinded()).unwrap();
    let note = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: Nonce::new(keyset, &output).unwrap().commit().unwrap(),
        },
    )
    .unwrap();
    Coin {
        note,
        derivation: d,
        owner: to.clone(),
    }
}

struct Coin {
    note: Note,
    derivation: Derivation,
    owner: OwnerKeys,
}

/// A spend of `coin` to `outputs`, with the derivations of its outputs.
fn spend(keyset: &Keyset, coin: &Coin, outputs: &[(Address, u64)]) -> (Proposal, Vec<Derivation>) {
    spend_with(&Ephemeral::random(), keyset, coin, outputs)
}

/// [`spend`], under the ephemeral key `e`.
fn spend_with(
    e: &Ephemeral,
    keyset: &Keyset,
    coin: &Coin,
    outputs: &[(Address, u64)],
) -> (Proposal, Vec<Derivation>) {
    let outputs: Vec<_> = outputs
        .iter()
        .enumerate()
        .map(|(i, (to, denom))| e.derive(to, *denom, Branch::Pay, i).unwrap())
        .collect();
    let proposal = Proposal::new(
        keyset,
        std::slice::from_ref(&coin.note),
        e.public(),
        outputs
            .iter()
            .map(|d| Output::from_derivation(d).unwrap())
            .collect(),
        None,
    )
    .unwrap();
    (proposal, outputs)
}

fn sign(
    keyset: &Keyset,
    coin: &Coin,
    proposal: &Proposal,
    authorization: Authorization,
) -> SignedProposal {
    let secret = coin
        .derivation
        .ownership()
        .owner_secret(coin.owner.spend_secret())
        .unwrap();
    SignedProposal::sign(
        keyset,
        proposal.clone(),
        std::slice::from_ref(&coin.note),
        authorization,
        &[secret],
    )
    .unwrap()
}

fn owner(seed: u8) -> OwnerKeys {
    OwnerKeys::from_seed(&[seed; 32]).unwrap()
}

fn json(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).unwrap()
}

#[tokio::test]
async fn a_wallet_spends_and_unlinks_through_the_api() {
    let service = service(2);
    let (status, body) = service
        .call(Method::GET, licash_hub_service::HEALTH, None)
        .await;
    assert_eq!((status, &body[..]), (StatusCode::OK, &b"ok"[..]));
    let info = service.info().await;
    assert_eq!(info.keysets().unwrap(), vec![service.keyset.clone()]);
    assert_eq!(info.fees.spend, licash_api::Fee { base: 2, ppm: 0 });
    let keyset = &service.keyset;
    let (alice, bob) = (owner(1), owner(2));
    let coin = service.mint(&alice, 8);
    let (proposal, outputs) = spend(
        keyset,
        &coin,
        &[(bob.address(), 4), (alice.address(), 2), (info.address, 2)],
    );
    let notes = vec![coin.note.clone()];

    let offered: Offered = service
        .post(licash_api::OFFER, &Offer::new(&proposal, &notes))
        .await;
    let grant = offered.decode().unwrap();
    grant.verify(keyset, &proposal).unwrap();
    let signed = sign(
        keyset,
        &coin,
        &proposal,
        Authorization::Granted(Box::new(grant)),
    );
    let released: Released = service
        .post(licash_api::RELEASE, &Release::new(&signed, &notes))
        .await;
    let unlock = released.decode().unwrap();
    let paid = signed
        .open_granted_output(keyset, &notes, 0, &outputs[0], &unlock)
        .unwrap();
    // The hub proves the spend to the holder who signs for the note: the
    // spent coin shows its spend, the new note nothing; a signature of
    // another's note shows nothing, and is refused.
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let asked = |note: &Note, derivation: &Derivation, at: u64| {
        let message = note.message();
        let key = derivation.hold_key(alice.hold_root()).unwrap();
        let signature = licash::inquiry::sign(keyset.id(), at, message, &key).unwrap();
        Inquire::new(keyset.id(), at, &[(message.clone(), signature)])
    };
    let evidenced: Evidenced = service
        .post(
            licash_api::INQUIRE,
            &asked(&coin.note, &coin.derivation, at),
        )
        .await;
    let evidence = evidenced.decode(keyset, 1).unwrap();
    assert!(
        matches!(&evidence[0][..], [licash::recovery::Evidence::Spend { .. }]),
        "the spend shows"
    );
    let proven = licash::recovery::voids_note(keyset, coin.note.message(), &evidence[0][0]);
    assert!(proven.unwrap());
    let late = service
        .problem(
            licash_api::INQUIRE,
            json(&asked(&coin.note, &coin.derivation, at - 3600)),
        )
        .await;
    assert_eq!(late.code, Code::Invalid);

    let session = Session::start(keyset, &paid, &outputs[0]).unwrap();
    let unlinked: Unlinked = service
        .post(licash_api::UNLINK, &Unlink::new(session.request()))
        .await;
    let unlinked = session.finish(keyset, &unlinked.decode().unwrap()).unwrap();
    assert!(matches!(unlinked.evidence(), Evidence::Unlinked(_)));
}

#[tokio::test]
async fn refusals_are_problems_with_their_codes() {
    let service = service(1);
    let keyset = &service.keyset;
    let address = service.info().await.address;
    let (alice, bob) = (owner(1), owner(2));
    let problem = |path, body| service.problem(path, body);

    let coin = service.mint(&alice, 8);
    let notes = vec![coin.note.clone()];
    let (unpaid, _) = spend(keyset, &coin, &[(bob.address(), 8)]);
    let offer = json(&Offer::new(&unpaid, &notes));
    assert_eq!(problem(licash_api::OFFER, offer).await.code, Code::Fee);

    let (paid, _) = spend(
        keyset,
        &coin,
        &[(bob.address(), 4), (bob.address(), 2), (address, 2)],
    );
    // Signed for a grant the hub never offered.
    let foreign = licash::authorization::PreparedGrant::new(&service.keys, &paid)
        .unwrap()
        .offer();
    let signed = sign(
        keyset,
        &coin,
        &paid,
        Authorization::Granted(Box::new(foreign)),
    );
    let release = json(&Release::new(&signed, &notes));
    assert_eq!(
        problem(licash_api::RELEASE, release).await.code,
        Code::UnknownOffer
    );

    // Two spends of one coin: the second is refused as spent.
    let (rival, _) = spend(
        keyset,
        &coin,
        &[(alice.address(), 4), (alice.address(), 2), (address, 2)],
    );
    let mut signed = Vec::new();
    for proposal in [&paid, &rival] {
        let offered: Offered = service
            .post(licash_api::OFFER, &Offer::new(proposal, &notes))
            .await;
        let grant = offered.decode().unwrap();
        signed.push(sign(
            keyset,
            &coin,
            proposal,
            Authorization::Granted(Box::new(grant)),
        ));
    }
    let _: Released = service
        .post(licash_api::RELEASE, &Release::new(&signed[0], &notes))
        .await;
    let release = json(&Release::new(&signed[1], &notes));
    let refused = problem(licash_api::RELEASE, release).await;
    assert_eq!(
        refused,
        Problem::new(Code::Spent, "refused: an input is already spent")
    );

    let other = IssuerKeys::random(MAX_POW).unwrap();
    let other_keyset = other.keyset().unwrap();
    let elsewhere = mint_under(&other, &other_keyset, &alice, 8);
    let (proposal, _) = spend(&other_keyset, &elsewhere, &[(bob.address(), 8)]);
    let offer = json(&Offer::new(
        &proposal,
        std::slice::from_ref(&elsewhere.note),
    ));
    assert_eq!(
        problem(licash_api::OFFER, offer).await.code,
        Code::UnknownKeyset
    );

    let never = service.mint(&bob, 4);
    let session = Session::start(keyset, &never.note, &never.derivation).unwrap();
    let unlink = json(&Unlink::new(session.request()));
    assert_eq!(
        problem(licash_api::UNLINK, unlink).await.code,
        Code::NotIssued
    );
}

#[tokio::test]
async fn malformed_bodies_are_invalid() {
    let service = service(0);
    for body in [
        "not json".to_owned(),
        r#"{"request":"0g"}"#.to_owned(),
        r#"{"request":"00"}"#.to_owned(),
        format!(
            r#"{{"request":"{}"}}"#,
            "00".repeat(licash_hub_service::BODY_LIMIT)
        ),
    ] {
        let problem = service.problem(licash_api::UNLINK, body).await;
        assert_eq!(problem.code, Code::Invalid, "{problem:?}");
    }
    let (status, body) = service.call(Method::POST, licash_api::OFFER, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let problem: Problem = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.code, Code::Invalid);
}

#[tokio::test]
async fn a_halted_hub_is_unhealthy_and_serves_nothing() {
    let service = service(0);
    let alice = owner(1);
    let coin = service.mint(&alice, 8);
    let (proposal, _) = spend(&service.keyset, &coin, &[(alice.address(), 8)]);
    let offer = json(&Offer::new(&proposal, std::slice::from_ref(&coin.note)));
    // The database changed under the hub, as a restored backup would.
    rusqlite::Connection::open(service.dir.path().join("hub.sqlite"))
        .unwrap()
        .execute("UPDATE meta SET seq = seq + 7", [])
        .unwrap();
    let problem = service.problem(licash_api::OFFER, offer).await;
    assert_eq!(
        problem,
        Problem::new(Code::Unavailable, "the hub cannot serve now")
    );
    let (status, body) = service
        .call(Method::GET, licash_hub_service::HEALTH, None)
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let problem: Problem = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.code, Code::Unavailable);
}

/// A copy of the hub responding only serves its health and nothing a
/// wallet asks: no spend, info or lock, so it forks no ledger.
#[tokio::test]
async fn a_hub_responding_only_serves_its_health_alone() {
    let mut service = service(0);
    service.app = licash_hub_service::responding(service.hub.clone());
    let (status, _) = service
        .call(Method::GET, licash_hub_service::HEALTH, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let alice = owner(1);
    let coin = service.mint(&alice, 8);
    let (proposal, _) = spend(&service.keyset, &coin, &[(alice.address(), 8)]);
    let offer = json(&Offer::new(&proposal, std::slice::from_ref(&coin.note)));
    let (status, _) = service
        .call(Method::POST, licash_api::OFFER, Some(offer))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for path in [licash_api::INFO, licash_api::LOCK_STATE] {
        let (status, _) = service.call(Method::GET, path, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// A JSON webhook, and the titles it took.
async fn hook() -> (licash_notify::Target, Arc<Mutex<Vec<String>>>) {
    let titles = Arc::new(Mutex::new(Vec::new()));
    let took = titles.clone();
    let app = Router::new().fallback(move |body: axum::body::Bytes| {
        let took = took.clone();
        async move {
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            took.lock()
                .unwrap()
                .push(body["title"].as_str().unwrap().to_owned());
            StatusCode::OK
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("json://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (target.parse().unwrap(), titles)
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn the_operator_hears_of_spends_a_halt_and_the_stop() {
    let service = service(0);
    let (target, titles) = hook().await;
    let dir = service.dir.path();
    let fast = Timing {
        poll: Duration::from_millis(10),
        retry: Duration::from_millis(10),
        max_retry: Duration::from_millis(40),
    };
    let notifier = Notifier::new(
        &dir.join("hub.sqlite"),
        "north",
        vec![target],
        &dir.join("notify.json"),
        vec![],
    )
    .unwrap()
    .timing(fast);
    let running = tokio::spawn(notifier.clone().run(service.hub.clone()));

    let alice = owner(1);
    let coin = service.mint(&alice, 8);
    let (proposal, _) = spend(&service.keyset, &coin, &[(owner(2).address(), 8)]);
    let notes = vec![coin.note.clone()];
    let offered: Offered = service
        .post(licash_api::OFFER, &Offer::new(&proposal, &notes))
        .await;
    let grant = Authorization::Granted(Box::new(offered.decode().unwrap()));
    let signed = sign(&service.keyset, &coin, &proposal, grant);
    let _: Released = service
        .post(licash_api::RELEASE, &Release::new(&signed, &notes))
        .await;
    until("released", || titles.lock().unwrap().len() == 1).await;
    assert_eq!(titles.lock().unwrap()[0], "north: Spend released");

    // The database changed under the hub.
    rusqlite::Connection::open(dir.join("hub.sqlite"))
        .unwrap()
        .execute("UPDATE meta SET seq = seq + 7", [])
        .unwrap();
    let (proposal, _) = spend(&service.keyset, &coin, &[(alice.address(), 8)]);
    service
        .problem(licash_api::OFFER, json(&Offer::new(&proposal, &notes)))
        .await;
    until("halted", || titles.lock().unwrap().len() == 2).await;
    assert_eq!(titles.lock().unwrap()[1], "north: Hub halted");

    running.abort();
    notifier.stopped().await;
    assert_eq!(titles.lock().unwrap()[2..], ["north: Hub stopped"]);
}

mod chain;

const SECRET: [u8; 32] = [7; 32];

impl Service {
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Problem> {
        let (status, body) = self.call(Method::GET, path, None).await;
        if status == StatusCode::OK {
            return Ok(serde_json::from_slice(&body).unwrap());
        }
        let problem: Problem = serde_json::from_slice(&body).unwrap();
        assert_eq!(status.as_u16(), problem.code.status(), "{problem:?}");
        Err(problem)
    }

    /// Follow `chain` from genesis, mined to `height` and scanned.
    fn follow(&self, chain: &mut chain::Chain, height: u32) {
        if self.hub.checkpoint().is_none() {
            self.hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        }
        while chain.height() < height {
            let block = chain.mine(None).clone();
            self.hub.observe(chain.height(), &block).unwrap();
        }
        assert!(self.hub.synced(chain.height(), &chain.tip()).unwrap());
    }
}

/// A timed lock of `coin`: `pay` on the preimage of `SECRET`'s hash, else
/// `refund`, each with the derivations of its outputs.
struct Locking {
    signed: SignedProposal,
    notes: Vec<Note>,
    pay: Vec<Derivation>,
    refund: Vec<Derivation>,
}

fn locking(
    keyset: &Keyset,
    coin: &Coin,
    pay: &[(Address, u64)],
    refund: &[(Address, u64)],
    terms: TimedTerms,
) -> Locking {
    let e = Ephemeral::random();
    let derive = |outputs: &[(Address, u64)], branch| -> Vec<Derivation> {
        (0..)
            .zip(outputs)
            .map(|(i, (to, denom))| e.derive(to, *denom, branch, i).unwrap())
            .collect()
    };
    let (pay, refund) = (derive(pay, Branch::Pay), derive(refund, Branch::Refund));
    let outputs = |ds: &[Derivation]| -> Vec<Output> {
        ds.iter()
            .map(|d| Output::from_derivation(d).unwrap())
            .collect()
    };
    let lock = TimedLock::new(terms, outputs(&refund)).unwrap();
    let notes = vec![coin.note.clone()];
    let proposal = Proposal::new(keyset, &notes, e.public(), outputs(&pay), Some(lock)).unwrap();
    let signed = sign(keyset, coin, &proposal, Authorization::Plain);
    Locking {
        signed,
        notes,
        pay,
        refund,
    }
}

fn terms(locks: &Locks, expiry: u32, depth: u32) -> TimedTerms {
    let checkpoint = locks.checkpoint().unwrap().commitment();
    let hash = lock_hash(&SECRET);
    TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        checkpoint,
        expiry,
        depth,
        hash,
    )
    .unwrap()
}

#[tokio::test]
async fn a_lock_is_paid_or_refunded_through_the_api() {
    let service = service_with(Policy {
        lock: Fee { base: 1, ppm: 0 },
        timing: licash_hub::Timing {
            window: 20,
            reaction: 2,
            min_depth: 1,
            ..licash_hub::Timing::default()
        },
        ..Policy::default()
    });
    let keyset = &service.keyset;
    // Its operator hears of the locks once they paid or refunded.
    let (target, titles) = hook().await;
    let dir = service.dir.path();
    let notifier = Notifier::new(
        &dir.join("hub.sqlite"),
        "north",
        vec![target],
        &dir.join("notify.json"),
        vec![],
    )
    .unwrap()
    .timing(Timing {
        poll: Duration::from_millis(10),
        ..Timing::default()
    });
    let _notifying = tokio::spawn(notifier.run(service.hub.clone()));
    let info = service.info().await;
    assert_eq!(info.fees.lock, licash_api::Fee { base: 1, ppm: 0 });
    assert!(info.locks.is_none());
    let mut chain = chain::Chain::new();
    service.follow(&mut chain, 3);
    let info = service.info().await;
    let locks = info.locks.clone().unwrap();
    let checkpoint = locks.checkpoint().unwrap();
    assert_eq!((checkpoint.height(), locks.height), (0, 3));
    assert_eq!((locks.window, locks.reaction, locks.min_depth), (20, 2, 1));

    let (alice, bob) = (owner(1), owner(2));
    let pay = [(bob.address(), 4), (bob.address(), 2), (info.address, 2)];
    let refund = [(alice.address(), 8)];
    let coin = service.mint(&alice, 8);
    let l = locking(keyset, &coin, &pay, &refund, terms(&locks, 6, 1));
    let id = l.signed.proposal().id();
    let locked: Locked = service
        .post(licash_api::LOCK, &Lock::new(&l.signed, &l.notes))
        .await;
    locked.decode(keyset, &l.signed, &l.notes).unwrap();
    let path = licash_api::lock_state(&id);
    let state: LockState = service.get(&path).await.unwrap();
    let view = state
        .decode(|k| (k == keyset.id()).then_some(keyset))
        .unwrap();
    assert_eq!(
        (view.proposal.id(), view.settled, view.preimage),
        (id, None, None)
    );

    // A lock is not offered, a plain spend not locked.
    let offer = json(&Offer::new(l.signed.proposal(), &l.notes));
    assert_eq!(
        service.problem(licash_api::OFFER, offer).await.code,
        Code::Timed
    );
    let other = service.mint(&alice, 4);
    let (plain, _) = spend(keyset, &other, &[(bob.address(), 4)]);
    let plain = sign(keyset, &other, &plain, Authorization::Plain);
    let body = json(&Lock::new(&plain, std::slice::from_ref(&other.note)));
    assert_eq!(
        service.problem(licash_api::LOCK, body).await.code,
        Code::NotALock
    );

    let wrong = json(&Settle::new(&id, &[8; 32]));
    assert_eq!(
        service.problem(licash_api::SETTLE, wrong).await.code,
        Code::Preimage
    );
    let early = json(&Refund::new(&id));
    assert_eq!(
        service.problem(licash_api::REFUND, early).await.code,
        Code::Unexpired
    );
    let paid: Issued = service
        .post(licash_api::SETTLE, &Settle::new(&id, &SECRET))
        .await;
    let paid = paid.decode(keyset).unwrap();
    for (issued, d) in paid.iter().zip(&l.pay[..2]) {
        issued.open(keyset, d).unwrap();
    }
    let late = json(&Refund::new(&id));
    assert_eq!(
        service.problem(licash_api::REFUND, late).await.code,
        Code::Settled
    );
    let state: LockState = service.get(&path).await.unwrap();
    assert_eq!(state.settled, Some(Settled::Pay));
    assert_eq!(state.preimage.unwrap().0, SECRET);

    // Another expires at depth and is refunded.
    let coin = service.mint(&alice, 8);
    let l = locking(keyset, &coin, &pay, &refund, terms(&locks, 5, 1));
    let id = l.signed.proposal().id();
    let _: Locked = service
        .post(licash_api::LOCK, &Lock::new(&l.signed, &l.notes))
        .await;
    service.follow(&mut chain, 6);
    let expired = json(&Settle::new(&id, &SECRET));
    assert_eq!(
        service.problem(licash_api::SETTLE, expired).await.code,
        Code::LockExpired
    );
    let refunded: Issued = service.post(licash_api::REFUND, &Refund::new(&id)).await;
    refunded.decode(keyset).unwrap()[0]
        .open(keyset, &l.refund[0])
        .unwrap();
    let state: LockState = service.get(&licash_api::lock_state(&id)).await.unwrap();
    assert_eq!(
        (state.settled, state.preimage),
        (Some(Settled::Refund), None)
    );
    until("refunded", || titles.lock().unwrap().len() == 2).await;
    assert_eq!(
        *titles.lock().unwrap(),
        ["north: Lock paid", "north: Lock refunded"]
    );
}

#[tokio::test]
async fn locks_out_of_the_hubs_terms_or_view_are_problems() {
    let service = service_with(Policy {
        timing: licash_hub::Timing {
            window: 20,
            reaction: 2,
            min_depth: 1,
            ..licash_hub::Timing::default()
        },
        ..Policy::default()
    });
    let keyset = &service.keyset;
    let alice = owner(1);
    let pay = [(owner(2).address(), 8)];
    let refund = [(alice.address(), 8)];
    let lock = |terms| {
        let l = locking(keyset, &service.mint(&alice, 8), &pay, &refund, terms);
        json(&Lock::new(&l.signed, &l.notes))
    };
    let unknown = licash_api::lock_state(&licash::spend::ProposalId::from_bytes([1; 32]));
    assert_eq!(
        service.get::<LockState>(&unknown).await.unwrap_err().code,
        Code::UnknownLock
    );
    let bad = service.get::<LockState>("/v1/lock/zz").await.unwrap_err();
    assert_eq!(bad.code, Code::Invalid);

    let mut chain = chain::Chain::new();
    service.follow(&mut chain, 3);
    let locks = service.info().await.locks.unwrap();
    let elsewhere = Locks {
        checkpoint: licash_api::Hex(chain.checkpoint(2).to_bytes()),
        ..locks.clone()
    };
    let code = |p: Problem| p.code;
    let problem = service
        .problem(licash_api::LOCK, lock(terms(&elsewhere, 6, 1)))
        .await;
    assert_eq!(code(problem), Code::Checkpoint);
    let problem = service
        .problem(licash_api::LOCK, lock(terms(&locks, 30, 1)))
        .await;
    assert_eq!(code(problem), Code::Timing);
    // The backend's tip is one the hub has not scanned.
    assert!(!service.hub.synced(4, &[0; 32]).unwrap());
    let problem = service
        .problem(licash_api::LOCK, lock(terms(&locks, 6, 1)))
        .await;
    assert_eq!(code(problem), Code::Unavailable);
}

#[tokio::test]
async fn its_info_names_the_urls_it_is_reached_at_once_known() {
    let mut service = service(0);
    assert!(service.info().await.urls.is_empty());
    let urls = Arc::new(std::sync::RwLock::new(vec![
        "https://hub.example".to_owned()
    ]));
    let services = licash_hub_service::Services {
        urls: urls.clone(),
        ..Default::default()
    };
    service.app = licash_hub_service::router(service.hub.clone(), services);
    assert_eq!(service.info().await.urls, ["https://hub.example"]);
    // Its onion service's, once it runs.
    let onion = format!("http://{}.onion", "a".repeat(56));
    urls.write().unwrap().push(onion.clone());
    let info = service.info().await;
    assert_eq!(info.urls, ["https://hub.example".to_owned(), onion]);
    // Not part of what it proves.
    let mut without = info.clone();
    without.urls.clear();
    let signet = ChainProfile::Core30Signet;
    assert_eq!(info.identity(signet), without.identity(signet));
}

#[tokio::test]
async fn a_payment_kept_for_its_payee_is_taken_and_acknowledged_through_the_api() {
    use licash_api::inbox::{self, Acknowledge, Acknowledgment, AskAcks, Keep, Kept, Take};

    let mut service = service(1);
    let path = service.dir.path().join("hub.sqlite");
    let kept = Arc::new(licash_hub_service::inbox::Inbox::open(&path).unwrap());
    let services = licash_hub_service::Services {
        inbox: Some(kept),
        ..Default::default()
    };
    service.app = licash_hub_service::router(service.hub.clone(), services);
    let info = service.info().await;
    assert!(info.features.iter().any(|f| f == inbox::FEATURE_NOTE));
    let keyset = &service.keyset;
    let (alice, bob) = (owner(1), owner(2));
    let coin = service.mint(&alice, 8);
    let e = Ephemeral::random();
    let (proposal, outputs) = spend_with(
        &e,
        keyset,
        &coin,
        &[(bob.address(), 4), (alice.address(), 2), (info.address, 2)],
    );
    let notes = vec![coin.note.clone()];
    let offered: Offered = service
        .post(licash_api::OFFER, &Offer::new(&proposal, &notes))
        .await;
    let grant = offered.decode().unwrap();
    let signed = sign(
        keyset,
        &coin,
        &proposal,
        Authorization::Granted(Box::new(grant)),
    );
    let shared = e.shared(&bob.address()).unwrap();
    let (keep, ack) = Keep::new(&shared, &proposal.id());
    // A note of another size is refused, before anything is released.
    let odd = inbox::Release {
        release: Release::new(&signed, &notes),
        keep: Some(keep.clone().with_note(Some(vec![9; 16]))),
    };
    let problem = service.problem(licash_api::RELEASE, json(&odd)).await;
    assert_eq!(problem.code, Code::Invalid);
    let note = vec![9; inbox::NOTE_SEALED];
    let keep = keep.with_note(Some(note.clone()));
    let release = inbox::Release {
        release: Release::new(&signed, &notes),
        keep: Some(keep.clone()),
    };
    let released: inbox::Released = service.post(licash_api::RELEASE, &release).await;
    assert!(released.kept);
    // Asked again, as a payer does that missed the answer: kept once.
    let again: inbox::Released = service.post(licash_api::RELEASE, &release).await;
    assert!(again.kept);
    assert_eq!(again.released.unlock, released.released.unlock);

    // Bob finds it by its tag, of the secret he shares with Alice.
    let (status, body) = service.call(Method::GET, &inbox::feed(0), None).await;
    assert_eq!(status, StatusCode::OK);
    let feed: inbox::Feed = serde_json::from_slice(&body).unwrap();
    assert_eq!(feed.entries.len(), 1, "{feed:?}");
    let entry = &feed.entries[0];
    let (ephemeral, tag) = entry.decode().unwrap();
    let found = bob
        .scan_key()
        .shared(&licash::crypto::Point(ephemeral))
        .unwrap();
    assert_eq!(tag, inbox::tag(&found));

    // And takes it with its key, only.
    let ask = |key: [u8; 32]| Take {
        payments: vec![Kept {
            seq: entry.seq,
            key: Hex(key.to_vec()),
        }],
    };
    let none: inbox::Taken = service.post(inbox::TAKE, &ask([0; 32])).await;
    assert!(none.payments[0].is_none());
    let taken: inbox::Taken = service.post(inbox::TAKE, &ask(inbox::key(&found))).await;
    let payment = taken.payments[0].clone().unwrap().at("http://hub.example");
    assert_eq!(payment.note, Some(Hex(note)), "the note kept with it");
    let lookup = |id: &[u8; 32]| (id == keyset.id()).then_some(keyset);
    let (paid, paid_notes, unlock) = payment.decode(lookup).unwrap();
    paid.open_granted_output(keyset, &paid_notes, 0, &outputs[0], &unlock)
        .unwrap();

    // Alice hears of it only once Bob tells his ack.
    let key = Hex(inbox::key(&shared).to_vec());
    let asking = AskAcks {
        keys: vec![key.clone()],
    };
    let acks: inbox::Acks = service.post(inbox::ACKS, &asking).await;
    assert_eq!(acks.acks, [None]);
    let told = |ack: [u8; 32]| Acknowledge {
        acks: vec![Acknowledgment {
            key: key.clone(),
            ack: Hex(ack.to_vec()),
        }],
    };
    let wrong: inbox::Acknowledged = service.post(inbox::ACK, &told([3; 32])).await;
    assert_eq!(wrong.acked, [false]);
    let acks: inbox::Acks = service.post(inbox::ACKS, &asking).await;
    assert_eq!(acks.acks, [None], "not by an ack the hub could make");
    let right: inbox::Acknowledged = service
        .post(inbox::ACK, &told(inbox::ack(&found, &proposal.id())))
        .await;
    assert_eq!(right.acked, [true]);
    let acks: inbox::Acks = service.post(inbox::ACKS, &asking).await;
    assert_eq!(acks.acks, [Some(Hex(ack.to_vec()))]);

    let many = AskAcks {
        keys: vec![key; inbox::MAX_ASKED + 1],
    };
    let problem = service.problem(inbox::ACKS, json(&many)).await;
    assert_eq!(problem.code, Code::Invalid);
}

#[tokio::test]
async fn a_hub_keeping_no_payments_releases_without_keeping() {
    use licash_api::inbox::{self, Keep};

    let service = service(1);
    let info = service.info().await;
    assert!(!info.features.iter().any(|f| f == inbox::FEATURE_NOTE));
    let keyset = &service.keyset;
    let (alice, bob) = (owner(1), owner(2));
    let coin = service.mint(&alice, 8);
    let e = Ephemeral::random();
    let (proposal, _) = spend_with(
        &e,
        keyset,
        &coin,
        &[(bob.address(), 4), (alice.address(), 2), (info.address, 2)],
    );
    let notes = vec![coin.note.clone()];
    let offered: Offered = service
        .post(licash_api::OFFER, &Offer::new(&proposal, &notes))
        .await;
    let signed = sign(
        keyset,
        &coin,
        &proposal,
        Authorization::Granted(Box::new(offered.decode().unwrap())),
    );
    let shared = e.shared(&bob.address()).unwrap();
    let release = inbox::Release {
        release: Release::new(&signed, &notes),
        keep: Some(Keep::new(&shared, &proposal.id()).0),
    };
    let (status, body) = service
        .call(Method::POST, licash_api::RELEASE, Some(json(&release)))
        .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body).unwrap();
    assert!(!text.contains("kept"), "{text}");
    let released: inbox::Released = serde_json::from_str(&text).unwrap();
    assert!(!released.kept);
    let (status, _) = service.call(Method::GET, &inbox::feed(0), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
