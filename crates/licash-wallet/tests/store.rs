//! The wallet's file: what it says it is, what it refuses, and what its
//! tables hold to.

#[allow(dead_code)]
mod net;

use licash::spend::{lock_hash, ChainProfile};
use licash_api::Fee;
use licash_store::Kind;
use licash_wallet::Wallet;
use net::{Link, Net, HUB};
use rusqlite::Connection;

const REGTEST: ChainProfile = ChainProfile::Core30DefaultRegtest;

fn path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("wallet.sqlite")
}

#[test]
fn a_wallet_file_says_what_it_is_and_is_whole() {
    let dir = tempfile::tempdir().unwrap();
    drop(Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(Net::new())).unwrap());
    let db = Connection::open(path(&dir)).unwrap();
    let id: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .unwrap();
    assert_eq!(id, 0x4C57_4C54);
    let version: i64 = db
        .query_row(
            "SELECT version FROM schema_versions WHERE component = 'wallet'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, 6);
    let broken: Option<String> = db
        .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
        .ok()
        .filter(|ok| ok != "ok");
    assert_eq!(broken, None);
    let mut check = db.prepare("PRAGMA foreign_key_check").unwrap();
    assert!(check.query([]).unwrap().next().unwrap().is_none());
}

#[test]
fn a_file_of_an_earlier_layout_is_refused_and_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    {
        let db = Connection::open(path(&dir)).unwrap();
        db.execute_batch("CREATE TABLE meta (one INTEGER); PRAGMA user_version = 16;")
            .unwrap();
    }
    let before = std::fs::read(path(&dir)).unwrap();
    let refused = Wallet::open(&path(&dir), Link(Net::new())).err().unwrap();
    assert!(refused.to_string().contains("earlier"), "{refused}");
    assert!(Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(Net::new())).is_err());
    assert_eq!(std::fs::read(path(&dir)).unwrap(), before);
}

/// A wallet of the version before (schema 5) holds notes of the note
/// format v4, which this version does not read: it is refused, said
/// to be another version's, and left for that version.
#[test]
fn a_wallet_of_the_version_before_is_refused_and_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    drop(Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(Net::new())).unwrap());
    Connection::open(path(&dir))
        .unwrap()
        .execute(
            "UPDATE schema_versions SET version = 5 WHERE component = 'wallet'",
            [],
        )
        .unwrap();
    let before = std::fs::read(path(&dir)).unwrap();
    let refused = Wallet::open(&path(&dir), Link(Net::new())).err().unwrap();
    let why = refused.to_string();
    assert!(
        why.contains("earlier version") && why.contains("schema 5"),
        "{why}"
    );
    assert_eq!(std::fs::read(path(&dir)).unwrap(), before);
}

#[test]
fn a_file_of_another_actor_or_without_a_wallet_in_it_is_no_wallet() {
    let dir = tempfile::tempdir().unwrap();
    drop(licash_store::create(&path(&dir), Kind::Hub).unwrap());
    let refused = Wallet::open(&path(&dir), Link(Net::new())).err().unwrap();
    assert!(refused.to_string().contains("hub database"), "{refused}");

    let other = dir.path().join("other.sqlite");
    drop(licash_store::create(&other, Kind::Wallet).unwrap());
    let refused = Wallet::open(&other, Link(Net::new())).err().unwrap();
    assert!(refused.to_string().contains("no wallet in"), "{refused}");
}

#[tokio::test]
async fn a_note_is_spent_by_a_kind_of_payment_or_by_none() {
    let net = Net::new();
    net.start(HUB, Fee { base: 0, ppm: 0 });
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(net.clone())).unwrap();
    wallet.add_hub(HUB).await.unwrap();
    wallet
        .receive(&net.pay(HUB, &wallet.address(), 100))
        .unwrap();
    let db = Connection::open(path(&dir)).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    let take = |set: &str| db.execute(&format!("UPDATE notes SET {set} WHERE denom = 4"), []);
    assert!(take("spent_by = x'01'").is_err());
    assert!(take("spent_kind = 'send'").is_err());
    assert!(take("spent_by = x'01', spent_kind = 'refund'").is_err());
    assert_eq!(take("spent_by = x'01', spent_kind = 'lock'").unwrap(), 1);
    assert!(take("spent_by = NULL").is_err());
    assert_eq!(take("spent_by = NULL, spent_kind = NULL").unwrap(), 1);
}

#[tokio::test]
async fn a_lock_settles_once_on_a_branch_and_a_pay_names_its_preimage() {
    let net = Net::new();
    net.start(HUB, Fee { base: 0, ppm: 0 });
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(net.clone())).unwrap();
    wallet.add_hub(HUB).await.unwrap();
    wallet
        .receive(&net.pay(HUB, &wallet.address(), 100))
        .unwrap();
    let lock = wallet
        .lock(HUB, &wallet.address(), 40, lock_hash(&[9; 32]), None)
        .await
        .unwrap();
    let id = hex::decode(&lock.id).unwrap();
    let db = Connection::open(path(&dir)).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    let settle = |branch: &str, preimage: Option<&[u8]>| {
        db.execute(
            "INSERT INTO lock_settlements (id, branch, preimage, settled_at)
             VALUES (?1, ?2, ?3, 1)",
            rusqlite::params![id, branch, preimage],
        )
    };
    assert!(settle("pay", None).is_err());
    assert!(settle("paid", Some(&[9; 32])).is_err());
    assert!(settle("pay", Some(&[9; 5])).is_err());
    assert_eq!(settle("refund", None).unwrap(), 1);
    assert!(settle("refund", None).is_err());
    // No lock settles that was never made.
    let unknown = db.execute(
        "INSERT INTO lock_settlements (id, branch, settled_at) VALUES (x'00', 'refund', 1)",
        [],
    );
    assert!(unknown.is_err());
}

#[test]
fn one_backup_holds_the_tables_of_every_component_in_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(&path(&dir), &[7; 32], REGTEST, Link(Net::new())).unwrap();
    // Another module of the process, with a connection of its own.
    let mut other = licash_store::open(&path(&dir), Kind::Wallet).unwrap();
    licash_store::component(
        &mut other,
        "elsewhere",
        1,
        "CREATE TABLE elsewhere_things (n INTEGER) STRICT;",
    )
    .unwrap();
    licash_store::write(&mut other, |tx| {
        tx.execute("INSERT INTO elsewhere_things VALUES (42)", [])?;
        Ok::<_, licash_store::Error>(())
    })
    .unwrap();
    let to = dir.path().join("copy.sqlite");
    wallet.backup_to(&to).unwrap();
    let copy = licash_store::open(&to, Kind::Wallet).unwrap();
    let n: i64 = copy
        .query_row("SELECT n FROM elsewhere_things", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 42);
    assert_eq!(
        licash_store::component_version(&copy, "wallet").unwrap(),
        Some(6)
    );
}
