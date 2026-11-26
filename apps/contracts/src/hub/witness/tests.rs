use std::{path::Path, sync::Arc};

use bitcoin::Transaction;
use licash_witness::{server, store::Store as WitnessStore};
use tempfile::TempDir;

use super::*;
use crate::hub::{responses::Responses, store::Store};

const SECRET: [u8; 32] = [7; 32];
const SET: [u8; 32] = [3; 32];
const ID: [u8; 32] = [1; 32];

/// A witness served on a local port, from its directory: kept while the
/// test runs.
struct Served {
    dir: TempDir,
    url: String,
    pin: [u8; 32],
}

impl Served {
    fn client(&self) -> Client {
        Client::new(&self.url, self.pin).unwrap()
    }
}

/// Serve the witness in `dir` on a new port.
async fn serve_dir(dir: TempDir) -> Served {
    let (cert, _) = server::identity(dir.path()).unwrap();
    let pin = server::pin_of(&cert);
    let store = Arc::new(WitnessStore::open(&dir.path().join("witness.sqlite")).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let path = dir.path().to_owned();
    tokio::spawn(async move {
        server::serve(listener, &path, store, std::future::pending())
            .await
            .unwrap()
    });
    Served { dir, url, pin }
}

/// A new witness of `set` for the hub of `secret`.
async fn witness_of(set: [u8; 32], secret: [u8; 32]) -> Served {
    let dir = tempfile::tempdir().unwrap();
    let key = licash_witness::public_key(&secret).unwrap();
    WitnessStore::create(&dir.path().join("witness.sqlite"), &set, &key).unwrap();
    server::make_identity(dir.path()).unwrap();
    serve_dir(dir).await
}

async fn witness() -> Served {
    witness_of(SET, SECRET).await
}

fn set(members: &[&Served]) -> Witnesses {
    let clients = members.iter().map(|m| m.client()).collect();
    Witnesses::of(SET, clients, SECRET).unwrap()
}

/// A hub's data directory, its database made.
fn hub_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    crate::testing::hub_data(dir.path());
    dir
}

/// A copy of the hub's database in `from`: as restored from a backup.
fn restored(from: &Path) -> TempDir {
    let to = tempfile::tempdir().unwrap();
    let c = Connection::open(crate::hub_db(from)).unwrap();
    c.execute(
        "VACUUM INTO ?1",
        [crate::hub_db(to.path()).to_str().unwrap()],
    )
    .unwrap();
    to
}

fn respond(owed: u32) -> Decision {
    Decision::Respond {
        request: [5; 32],
        b: 100,
        e: [6; 32],
        owed,
        evidence: vec![owed as u8; 3],
    }
}

/// A witness written to as the hub writes, bypassing it.
async fn write_raw(w: &Served, contract: &[u8; 32], slot: &str, decision: &Decision) {
    let write = licash_witness::signed(&SECRET, &SET, contract, slot, decision.to_body()).unwrap();
    w.client().write(&write).await.unwrap();
}

/// What one hub decides first is what any copy of it signs, even one
/// restored older than its decision: its witnesses keep it.
#[tokio::test]
async fn the_first_decision_kept_is_the_one_every_copy_of_the_hub_signs() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    let witnesses = set(&[&a, &b]);
    witnesses
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .unwrap();
    assert_eq!(bound(hub.path()).unwrap(), Some(SET));
    let older = restored(hub.path());
    let first = witnesses
        .authorize(hub.path(), &ID, slot::RESPOND, &respond(40))
        .await
        .unwrap();
    assert_eq!(first, respond(40));
    // Again, of the same hub: the same.
    let again = witnesses
        .authorize(hub.path(), &ID, slot::RESPOND, &respond(40))
        .await
        .unwrap();
    assert_eq!(again, first);
    // A copy restored older decides otherwise: it is given the first.
    let copy = set(&[&a, &b]);
    let replayed = copy
        .authorize(older.path(), &ID, slot::RESPOND, &respond(60))
        .await
        .unwrap();
    assert_eq!(replayed, respond(40));
    let recovered = copy
        .recover(older.path(), &ID, slot::RESPOND)
        .await
        .unwrap();
    assert_eq!(recovered, Some(respond(40)));
    // Its assertion is a slot of its own, none kept yet.
    let none = copy.recover(older.path(), &ID, slot::ASSERT).await.unwrap();
    assert_eq!(none, None);
}

/// A contract never enrolled has no decision kept, so none signed.
#[tokio::test]
async fn a_contract_never_enrolled_is_never_decided() {
    let a = witness().await;
    let hub = hub_dir();
    let witnesses = set(&[&a]);
    witnesses
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .unwrap();
    let other = [2; 32];
    let refused = witnesses
        .authorize(hub.path(), &other, slot::RESPOND, &respond(1))
        .await
        .unwrap_err();
    assert!(
        format!("{refused:#}").contains("not enrolled"),
        "{refused:#}"
    );
    assert_eq!(
        witnesses
            .recover(hub.path(), &other, slot::RESPOND)
            .await
            .unwrap(),
        None
    );
}

/// Witnesses holding two decisions sign none, now or later, and burn
/// nothing: the operator is to look.
#[tokio::test]
async fn witnesses_that_disagree_sign_nothing() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    let witnesses = set(&[&a, &b]);
    witnesses
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .unwrap();
    // The witness written last holds another already.
    let last = if a.pin > b.pin { &a } else { &b };
    write_raw(last, &ID, slot::RESPOND, &respond(9)).await;
    for _ in 0..2 {
        let refused = witnesses
            .authorize(hub.path(), &ID, slot::RESPOND, &respond(40))
            .await
            .unwrap_err();
        assert!(format!("{refused:#}").contains("disagree"), "{refused:#}");
        assert!(disagreed(&refused));
    }
    let refused = witnesses
        .recover(hub.path(), &ID, slot::RESPOND)
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("disagree"));
    assert!(disagreed(&refused));
    // A witness unreachable is not of witnesses that disagree.
    let gone = Client::new("https://127.0.0.1:1", [0; 32]).unwrap();
    let refused = Witnesses::of(SET, vec![a.client(), gone], SECRET)
        .unwrap()
        .recover(hub.path(), &ID, slot::RESPOND)
        .await
        .unwrap_err();
    assert!(!disagreed(&refused));
}

/// A witness restored older, or made anew, is refused; one cloned from a
/// witness that survives holds all it did, and is taken.
#[tokio::test]
async fn a_witness_rolled_back_or_made_anew_is_refused_and_a_clone_taken() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    set(&[&a, &b])
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .unwrap();
    // `b` as it is now, kept aside with its identity.
    let old = tempfile::tempdir().unwrap();
    for file in ["tls.crt", "tls.key"] {
        std::fs::copy(b.dir.path().join(file), old.path().join(file)).unwrap();
    }
    WitnessStore::open(&b.dir.path().join("witness.sqlite"))
        .unwrap()
        .backup(&old.path().join("witness.sqlite"))
        .unwrap();
    set(&[&a, &b])
        .authorize(hub.path(), &ID, slot::RESPOND, &respond(40))
        .await
        .unwrap();
    // Restored to that: of its pin, fewer entries than the hub saw.
    let rolled = serve_dir(old).await;
    assert_eq!(rolled.pin, b.pin);
    let refused = set(&[&a, &rolled])
        .authorize(hub.path(), &ID, slot::RESPOND, &respond(60))
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("fewer than"), "{refused:#}");
    // Made anew: unsealed.
    let fresh = witness().await;
    let refused = set(&[&a, &fresh])
        .recover(hub.path(), &ID, slot::RESPOND)
        .await
        .unwrap_err();
    assert!(
        format!("{refused:#}").contains("not sealed alike"),
        "{refused:#}"
    );
    // Cloned from `a`, under an identity of its own.
    let clone = tempfile::tempdir().unwrap();
    WitnessStore::copy(
        &a.dir.path().join("witness.sqlite"),
        &clone.path().join("witness.sqlite"),
    )
    .unwrap();
    server::make_identity(clone.path()).unwrap();
    let clone = serve_dir(clone).await;
    let kept = set(&[&a, &clone])
        .authorize(hub.path(), &ID, slot::RESPOND, &respond(60))
        .await
        .unwrap();
    assert_eq!(kept, respond(40));
}

/// Only witnesses of the set configured, keeping this hub's entries, are
/// spoken to; one unreachable stops all.
#[tokio::test]
async fn a_witness_of_another_set_or_hub_or_unreachable_is_refused() {
    let a = witness().await;
    for (other, says) in [
        (witness_of([4; 32], SECRET).await, "of the set"),
        (witness_of(SET, [8; 32]).await, "another hub's"),
    ] {
        let hub = hub_dir();
        let refused = set(&[&a, &other])
            .enroll(hub.path(), &ID, || Ok(true))
            .await
            .unwrap_err();
        assert!(format!("{refused:#}").contains(says), "{refused:#}");
        assert_eq!(bound(hub.path()).unwrap(), None);
    }
    let hub = hub_dir();
    let gone = Client::new("https://127.0.0.1:1", [0; 32]).unwrap();
    let witnesses = Witnesses::of(SET, vec![a.client(), gone], SECRET).unwrap();
    assert!(witnesses
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .is_err());
    // Two of one pin are one witness.
    assert!(Witnesses::of(SET, vec![a.client(), a.client()], SECRET).is_err());
}

/// A set unsealed is sealed only for a hub that never signed: one that
/// did must import what it signed first.
#[tokio::test]
async fn a_hub_that_signed_before_its_witnesses_must_import_first() {
    let a = witness().await;
    let hub = hub_dir();
    let refused = set(&[&a])
        .enroll(hub.path(), &ID, || Ok(false))
        .await
        .unwrap_err();
    assert!(format!("{refused:#}").contains("import"), "{refused:#}");
    assert!(a.client().status().await.unwrap().seal.is_none());
}

/// No witnesses on mainnet, fewer than two there, or none once a hub's
/// contracts are witnessed: refused.
#[tokio::test]
async fn none_is_refused_on_mainnet_and_once_witnessed() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    let mainnet = ChainProfile::Core30Mainnet;
    let regtest = ChainProfile::Core30DefaultRegtest;
    assert!(Witnesses::none().admit(mainnet, hub.path()).is_err());
    assert!(set(&[&a]).admit(mainnet, hub.path()).is_err());
    set(&[&a, &b]).admit(mainnet, hub.path()).unwrap();
    Witnesses::none().admit(regtest, hub.path()).unwrap();
    set(&[&a])
        .enroll(hub.path(), &ID, || Ok(true))
        .await
        .unwrap();
    let refused = Witnesses::none().admit(regtest, hub.path()).unwrap_err();
    assert!(refused.to_string().contains("witnessed"), "{refused}");
    let other = Witnesses::of([4; 32], vec![a.client()], SECRET).unwrap();
    assert!(other.admit(regtest, hub.path()).is_err());
    set(&[&a]).admit(regtest, hub.path()).unwrap();
}

/// An entry of a newer version is never read as this one.
#[test]
fn an_entry_of_another_version_is_refused() {
    assert_eq!(
        Decision::from_body(&respond(3).to_body()).unwrap(),
        respond(3)
    );
    assert_eq!(
        Decision::from_body(&Decision::Burnt.to_body()).unwrap(),
        Decision::Burnt
    );
    let newer = br#"{"v":2,"kind":"respond"}"#;
    let refused = Decision::from_body(newer).unwrap_err();
    assert!(refused.to_string().contains("version 2"), "{refused}");
    assert!(Decision::from_body(br#"{"v":1,"kind":"other"}"#).is_err());
}

/// A real request of the shared mock opening claiming `b`, and the hub's
/// response to it of `owed`.
fn real_answer(b: u32, owed: u32) -> (Transaction, Transaction) {
    use licash_contract::{
        keys::HolderKeys,
        opening::{Context, Holder, Hub, Trust},
    };
    let saved = crate::testing::opened();
    let ctx = Context {
        tip: 0,
        trust: Trust::mock(),
    };
    let holder = Holder::load(&saved.holder, &saved.seed, &ctx).unwrap();
    let keys = HolderKeys::derive(&saved.seed, &holder.id());
    let request = holder
        .signed()
        .unwrap()
        .request(&keys, b, &[0xff; 32])
        .unwrap();
    let hub = Hub::load(&saved.hub, &ctx).unwrap();
    let response = hub.signed().unwrap().respond(hub.keys(), owed).unwrap();
    (request, response)
}

/// An import gives the witnesses each contract, each answer as it was
/// signed, and each that may have been signed with what is lost to be
/// signed never; it is not run twice, and a hub restored older than it
/// finds what it gave.
#[tokio::test]
async fn an_import_gives_what_the_hub_signed_once() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    let (signed, burnt, untouched, pinned) = ([1; 32], [2; 32], [3; 32], [4; 32]);
    {
        let store = Store::open(hub.path()).unwrap();
        // Each a real hub's state: its answers' words read by its payout.
        let state = &crate::testing::opened().hub;
        for (n, id) in [signed, burnt, untouched, pinned].iter().enumerate() {
            let deposit = bitcoin::OutPoint {
                txid: bitcoin::hashes::Hash::from_byte_array([9; 32]),
                vout: n as u32,
            };
            assert!(store
                .insert(id, 0, true, &deposit, &[0; 32], state)
                .unwrap());
            store.save(id, 0, true, &[0; 32], state).unwrap();
        }
        store.begin_signing(&burnt, "respond").unwrap();
        store.begin_signing(&pinned, "respond").unwrap();
        let pins = Responses::open(hub.path()).unwrap();
        let (request, response) = real_answer(3072, 1024);
        pins.pin(&signed, &request, b"evidence").unwrap();
        pins.answer(&signed, &request, || Ok(response.clone()))
            .unwrap();
        // Pinned, not signed: written as any once the hub runs.
        pins.pin(&pinned, &request, b"pinned").unwrap();
        assert!(!store.never_signed().unwrap());
    }
    let older = restored(hub.path());
    let witnesses = set(&[&a, &b]);
    let imported = witnesses.import(hub.path()).await.unwrap();
    assert_eq!(
        imported,
        Imported {
            enrolled: 4,
            answers: 1,
            burnt: 1
        }
    );
    assert_eq!(bound(hub.path()).unwrap(), Some(SET));
    // Imported: a hub of regtest or signet, never of mainnet.
    assert!(witnesses
        .admit(ChainProfile::Core30Mainnet, hub.path())
        .is_err());
    witnesses
        .admit(ChainProfile::Core30DefaultRegtest, hub.path())
        .unwrap();
    let kept = witnesses
        .recover(hub.path(), &signed, slot::RESPOND)
        .await
        .unwrap();
    let Some(Decision::Respond {
        b,
        owed,
        evidence,
        e,
        ..
    }) = kept
    else {
        panic!("{kept:?}");
    };
    assert_eq!((b, owed, e), (3072, 1024, [0xff; 32]));
    assert_eq!(evidence, b"evidence");
    let kept = witnesses
        .recover(hub.path(), &burnt, slot::RESPOND)
        .await
        .unwrap();
    assert_eq!(kept, Some(Decision::Burnt));
    for id in [untouched, pinned] {
        assert_eq!(
            witnesses
                .recover(hub.path(), &id, slot::RESPOND)
                .await
                .unwrap(),
            None
        );
    }
    // Enrolled, each: decided as any.
    witnesses
        .authorize(hub.path(), &untouched, slot::RESPOND, &respond(5))
        .await
        .unwrap();
    // Not again.
    assert!(witnesses.import(hub.path()).await.is_err());
    assert!(witnesses.import(older.path()).await.is_err());
    // Restored to before the import, the hub finds it: bound as sealed.
    let kept = witnesses
        .authorize(older.path(), &burnt, slot::RESPOND, &respond(5))
        .await
        .unwrap();
    assert_eq!(kept, Decision::Burnt);
    assert_eq!(bound(older.path()).unwrap(), Some(SET));
}

/// An import that failed before its seal is run again; one into a set
/// sealed is refused.
#[tokio::test]
async fn an_import_is_run_again_until_sealed() {
    let a = witness().await;
    let hub = hub_dir();
    {
        let store = Store::open(hub.path()).unwrap();
        let deposit = bitcoin::OutPoint::null();
        assert!(store
            .insert(&ID, 0, true, &deposit, &[0; 32], b"state")
            .unwrap());
        store.begin_signing(&ID, "respond").unwrap();
    }
    // Its first run stopped short of its seal: the witness unreachable.
    let gone = Client::new("https://127.0.0.1:1", [0; 32]).unwrap();
    let partial = Witnesses::of(SET, vec![a.client(), gone], SECRET).unwrap();
    assert!(partial.import(hub.path()).await.is_err());
    let imported = set(&[&a]).import(hub.path()).await.unwrap();
    assert_eq!(imported.burnt, 1);
    // A hub of another database, its set sealed: refused.
    let other = hub_dir();
    assert!(set(&[&a]).import(other.path()).await.is_err());
}

/// An import that stopped as it sealed, some witnesses sealed and some
/// not, is run again: the rest sealed as the first were.
#[tokio::test]
async fn an_import_sealed_in_part_is_run_again() {
    let (a, b) = (witness().await, witness().await);
    let hub = hub_dir();
    {
        let store = Store::open(hub.path()).unwrap();
        let deposit = bitcoin::OutPoint::null();
        assert!(store
            .insert(&ID, 0, true, &deposit, &[0; 32], b"state")
            .unwrap());
        store.begin_signing(&ID, "respond").unwrap();
    }
    // As the hub's database was before its import bound it.
    let before = restored(hub.path());
    set(&[&a]).import(hub.path()).await.unwrap();
    assert!(b.client().status().await.unwrap().seal.is_none());
    let imported = set(&[&a, &b]).import(before.path()).await.unwrap();
    assert_eq!(imported.burnt, 1);
    let (sa, sb) = (
        a.client().status().await.unwrap().seal.unwrap(),
        b.client().status().await.unwrap().seal.unwrap(),
    );
    assert_eq!(sa.body, sb.body);
    assert_eq!(
        set(&[&a, &b])
            .recover(before.path(), &ID, slot::RESPOND)
            .await
            .unwrap(),
        Some(Decision::Burnt)
    );
}

/// A copy of the hub taking the contracts over supersedes the others: they
/// open nothing, their enrollment refused, and answer the contracts open
/// as ever, each decision as first kept. The superseded copy may take them
/// back the same way.
#[tokio::test]
async fn a_copy_superseded_opens_nothing_and_answers_as_ever() {
    let (a, b) = (witness().await, witness().await);
    let master = hub_dir();
    let witnesses = set(&[&a, &b]);
    assert_eq!(
        witnesses.leadership(master.path()).await.unwrap(),
        Leadership::Unfenced
    );
    witnesses
        .enroll(master.path(), &ID, || Ok(true))
        .await
        .unwrap();
    // Restored elsewhere, from a copy that holds no instance id.
    let replica = restored(master.path());
    let replicas = set(&[&a, &b]);
    assert_eq!(replicas.take_over(replica.path()).await.unwrap(), 1);
    assert!(replica.path().join(INSTANCE_FILE).is_file());
    assert_eq!(
        replicas.leadership(replica.path()).await.unwrap(),
        Leadership::Leads(1)
    );
    assert_eq!(
        witnesses.leadership(master.path()).await.unwrap(),
        Leadership::Superseded(1)
    );
    // Kept, for a start its witnesses cannot be asked at.
    assert_eq!(superseded(master.path()).unwrap(), Some(1));
    assert_eq!(superseded(replica.path()).unwrap(), None);
    let refused = witnesses
        .enroll(master.path(), &[2; 32], || Ok(false))
        .await
        .unwrap_err();
    assert!(
        format!("{refused:#}").contains("took the contracts over"),
        "{refused:#}"
    );
    // Even unchecked by the hub: its witnesses refuse it.
    let mut stale = licash_witness::signed(&SECRET, &SET, &[2; 32], slot::ENROLL, vec![]).unwrap();
    stale.epoch = 0;
    let refused = a.client().write(&stale).await.unwrap_err();
    assert!(format!("{refused:#}").contains("superseded"), "{refused:#}");
    replicas
        .enroll(replica.path(), &[2; 32], || Ok(false))
        .await
        .unwrap();
    // Both answer the contract open: one decision, the first.
    let first = witnesses
        .authorize(master.path(), &ID, slot::RESPOND, &respond(40))
        .await
        .unwrap();
    let theirs = replicas
        .authorize(replica.path(), &ID, slot::RESPOND, &respond(60))
        .await
        .unwrap();
    assert_eq!((first, theirs), (respond(40), respond(40)));
    // Taken back: the next epoch.
    assert_eq!(witnesses.take_over(master.path()).await.unwrap(), 2);
    assert_eq!(
        witnesses.leadership(master.path()).await.unwrap(),
        Leadership::Leads(2)
    );
    assert_eq!(
        replicas.leadership(replica.path()).await.unwrap(),
        Leadership::Superseded(2)
    );
    assert_eq!(superseded(master.path()).unwrap(), None);
    assert_eq!(superseded(replica.path()).unwrap(), Some(2));
}

/// A takeover that reached only its first witness (and stopped there)
/// fences the other copies all the same, as that witness enrolls nothing
/// for them; taken again by the same copy, it is finished, never the next
/// epoch's, so that the copy never supersedes itself. One that cannot
/// reach every witness at first takes nothing, nor does one of a hub
/// bound to no set.
#[tokio::test]
async fn a_takeover_half_written_fences_all_the_same_and_is_taken_again() {
    let (a, b) = (witness().await, witness().await);
    let master = hub_dir();
    let masters = set(&[&a, &b]);
    masters
        .enroll(master.path(), &ID, || Ok(true))
        .await
        .unwrap();
    let replica = restored(master.path());
    let unbound = hub_dir();
    assert!(masters.take_over(unbound.path()).await.is_err());
    assert!(!unbound.path().join(INSTANCE_FILE).exists());
    let gone = Client::new("https://127.0.0.1:1", [0xff; 32]).unwrap();
    let unreachable = Witnesses::of(SET, vec![a.client(), gone], SECRET).unwrap();
    assert!(unreachable.take_over(replica.path()).await.is_err());
    assert_eq!(
        masters.leadership(master.path()).await.unwrap(),
        Leadership::Unfenced
    );
    // Stopped after its first witness: kept there alone.
    keep_instance(replica.path(), &[9; 32]).unwrap();
    let mut leader =
        licash_witness::signed(&SECRET, &SET, &leader_id(1), slot::LEADER, vec![9; 32]).unwrap();
    leader.epoch = 1;
    let first = if a.pin < b.pin { &a } else { &b };
    first.client().write(&leader).await.unwrap();
    assert_eq!(
        masters.leadership(master.path()).await.unwrap(),
        Leadership::Superseded(1)
    );
    assert!(masters
        .enroll(master.path(), &[2; 32], || Ok(false))
        .await
        .is_err());
    let replicas = set(&[&a, &b]);
    assert_eq!(
        replicas.leadership(replica.path()).await.unwrap(),
        Leadership::Leads(1)
    );
    assert_eq!(replicas.take_over(replica.path()).await.unwrap(), 1);
    let other = if a.pin < b.pin { &b } else { &a };
    let kept = other.client().status().await.unwrap().leader.unwrap();
    assert_eq!((kept.epoch, kept.entry.body), (1, vec![9; 32]));
    assert_eq!(
        replicas.leadership(replica.path()).await.unwrap(),
        Leadership::Leads(1)
    );
    // Another copy's takeover is the next epoch's.
    assert_eq!(masters.take_over(master.path()).await.unwrap(), 2);
}

/// Without witnesses no copy is fenced, and none can take over.
#[tokio::test]
async fn without_witnesses_every_copy_leads_and_none_takes_over() {
    let hub = hub_dir();
    let none = Witnesses::none();
    assert_eq!(
        none.leadership(hub.path()).await.unwrap(),
        Leadership::Unfenced
    );
    assert!(none.take_over(hub.path()).await.is_err());
    assert!(!hub.path().join(INSTANCE_FILE).exists());
}
