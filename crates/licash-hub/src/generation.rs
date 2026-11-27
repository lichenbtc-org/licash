//! Which copy of the ledger serves wallets.
//!
//! A ledger restored from a backup, or copied, is older than the one its
//! hub last served from, or a second one beside it: serving wallets, it
//! would take again the notes they spent since, and issue for them. So the
//! hub's first start serving wallets binds the ledger to its data
//! directory: a random generation, kept in the ledger and in the file
//! [`FILE`] beside it, which is never backed up or synced. A ledger found
//! with its own generation and not the file's, or the file without one,
//! is a copy, and serves no wallet ([`serving`]) until its operator,
//! sure that no other copy serves, makes it the one that does
//! ([`promote`]).
//!
//! What each state proves:
//! - neither: a ledger never served from, or by a release before this
//!   one; this directory is where it was, as nothing says otherwise. It
//!   serves, and is bound then ([`Hub::bind`]).
//! - both, the same: the ledger this directory last served from, or an
//!   older copy of it restored in place, which nothing here tells apart.
//! - the ledger's alone, the file's alone, or two that differ: a copy,
//!   held. So is a file that cannot be read.
//!
//! The ledger is bound before the file is written: a crash between the
//! two leaves a ledger held, which its operator promotes.

use std::{io::Write, path::Path};

use licash_store::Kind;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension, Transaction};

use crate::{
    derived, keyset_rows_in, read_seed,
    store::{self, setup},
    Error, Hub,
};

/// The file beside the ledger that names the generation this data
/// directory serves: local to it, never backed up or synced.
pub const FILE: &str = "ledger-generation";

const COMPONENT: &str = "generation";
const VERSION: i64 = 1;
const SCHEMA: &str = "
CREATE TABLE generation (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    id BLOB NOT NULL CHECK (length(id) = 32),
    created_at INTEGER NOT NULL
) STRICT;
";

/// Whether the ledger serves wallets from this data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Serving {
    /// Never bound: it serves, and is bound as it starts to.
    Unbound,
    /// Bound to this data directory: it serves.
    Bound,
    /// A copy: it serves no wallet, for this reason, until promoted.
    Held(String),
}

/// Whether the ledger at `db` serves wallets, as it and the file beside it
/// ([`FILE`]) say: [`Serving::Unbound`] if there is no ledger. Read only,
/// beside a running hub or not.
pub fn serving(db: &Path) -> Result<Serving, Error> {
    if !db.try_exists()? {
        return Ok(Serving::Unbound);
    }
    let conn = store::inspect(db)?;
    let ledger = stamp(&conn)?;
    Ok(judge(ledger, token(&file(db))))
}

/// Make the ledger at `db` the copy that serves wallets from its data
/// directory: a new generation, in the ledger, then in the file beside it.
/// With the hub stopped, and its seed, which must be the ledger's: for its
/// operator alone to run once sure no other copy serves.
pub fn promote(seed: &Path, db: &Path) -> Result<(), Error> {
    if !db.is_file() {
        return Err(Error::Setup(format!("no hub database at {}", db.display())));
    }
    let _stopped = store::lock(db)?;
    let secret = read_seed(seed)?;
    derived(&secret, &keyset_rows_in(&store::inspect(db)?)?)?;
    let mut conn = licash_store::open(db, Kind::Hub).map_err(setup)?;
    let id = drawn();
    licash_store::write(&mut conn, |tx| {
        licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA)?;
        put(tx, &id).map_err(licash_store::Error::from)
    })
    .map_err(setup)?;
    keep(&file(db), &id)
}

impl Hub {
    /// Bind the ledger at `db`, which this hub runs on, to its data
    /// directory, if neither is yet: refused if it is held ([`serving`]),
    /// or the hub is a standby.
    pub fn bind(&self, db: &Path) -> Result<(), Error> {
        self.secrets()?;
        let path = file(db);
        let found = token(&path);
        let made = self.store.write(|tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(setup)?;
            match judge(stamp(tx)?, found) {
                Serving::Unbound => {
                    let id = drawn();
                    put(tx, &id)?;
                    Ok(Some(id))
                }
                Serving::Bound => Ok(None),
                Serving::Held(why) => Err(Error::Setup(why)),
            }
        })?;
        match made {
            Some(id) => keep(&path, &id),
            None => Ok(()),
        }
    }
}

fn file(db: &Path) -> std::path::PathBuf {
    db.with_file_name(FILE)
}

fn drawn() -> [u8; 32] {
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    id
}

/// What the ledger and the file say, the file read or why it was not.
fn judge(ledger: Option<[u8; 32]>, file: Result<Option<[u8; 32]>, String>) -> Serving {
    const PROMOTE: &str = "it serves no wallet until licash-hub ledger-promote, run with the hub \
                           stopped and its seed, makes it the copy that does, once no other \
                           does (docs/hub.md, Restoring the hub)";
    let held = |what: &str| Serving::Held(format!("{what}: {PROMOTE}"));
    match (ledger, file) {
        (None, Ok(None)) => Serving::Unbound,
        (Some(l), Ok(Some(f))) if l == f => Serving::Bound,
        (Some(_), Ok(Some(_))) => held(
            "the ledger is of another generation than this data directory served from: a \
             restored or copied ledger",
        ),
        (Some(_), Ok(None)) => held(&format!(
            "the ledger served from another data directory, or this one lost its {FILE}: a \
             restored or copied ledger"
        )),
        (None, Ok(Some(_))) => held(
            "this data directory served from a ledger, and this one was never served from: a \
             ledger replaced",
        ),
        (_, Err(e)) => held(&format!("{FILE} cannot be read ({e})")),
    }
}

/// The generation the ledger keeps: none if never bound.
fn stamp(conn: &Connection) -> Result<Option<[u8; 32]>, Error> {
    match licash_store::component_version(conn, COMPONENT).map_err(setup)? {
        None => Ok(None),
        Some(VERSION) => Ok(conn
            .query_row("SELECT id FROM generation WHERE one = 1", [], |r| r.get(0))
            .optional()?),
        Some(v) => Err(Error::Setup(format!(
            "{COMPONENT} is of version {v}, this build reads {VERSION}"
        ))),
    }
}

fn put(tx: &Transaction<'_>, id: &[u8; 32]) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT OR REPLACE INTO generation (one, id, created_at) VALUES (1, ?1, ?2)",
        rusqlite::params![id, store::now()],
    )?;
    Ok(())
}

/// The generation the file at `path` names: none if there is no file.
fn token(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let mut id = [0; 32];
    hex::decode_to_slice(text.trim(), &mut id).map_err(|_| "not 32 hex bytes".to_owned())?;
    Ok(Some(id))
}

/// `id` in the file at `path`, replaced whole and synced with its directory.
fn keep(path: &Path, id: &[u8; 32]) -> Result<(), Error> {
    let new = path.with_extension("new");
    let mut file = std::fs::File::create(&new)?;
    file.write_all(format!("{}\n", hex::encode(id)).as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&new, path)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Policy;

    fn made() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, 4).unwrap();
        (dir, seed, db)
    }

    fn held(db: &Path) -> String {
        match serving(db).unwrap() {
            Serving::Held(why) => why,
            other => panic!("{other:?}"),
        }
    }

    /// Without a ledger, or a new one, nothing holds the hub; its first
    /// start binds it, and it is bound from then on.
    #[test]
    fn a_ledger_is_bound_on_its_first_start_and_serves_from_then_on() {
        let (dir, seed, db) = made();
        assert_eq!(
            serving(&dir.path().join("none.sqlite")).unwrap(),
            Serving::Unbound
        );
        assert_eq!(serving(&db).unwrap(), Serving::Unbound);
        let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
        hub.bind(&db).unwrap();
        assert_eq!(serving(&db).unwrap(), Serving::Bound);
        let kept = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert_eq!(kept.trim().len(), 64);
        // Bound again on every start, unchanged.
        hub.bind(&db).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(FILE)).unwrap(),
            kept
        );
    }

    /// A copy of a bound ledger elsewhere, the file lost, replaced, or
    /// unreadable, or a ledger never bound where one was: each is held,
    /// and refused binding, until promoted.
    #[test]
    fn a_copy_of_the_ledger_is_held_until_promoted() {
        let (dir, seed, db) = made();
        let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
        hub.bind(&db).unwrap();
        drop(hub);
        let path = dir.path().join(FILE);
        let kept = std::fs::read(&path).unwrap();

        // Restored elsewhere: the ledger without its file.
        std::fs::remove_file(&path).unwrap();
        assert!(held(&db).contains("another data directory"));
        let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
        assert!(matches!(hub.bind(&db), Err(Error::Setup(_))));
        // Refused, the file is not written.
        assert!(!path.exists());
        drop(hub);

        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        assert!(held(&db).contains("another generation"));
        std::fs::write(&path, "garbage").unwrap();
        assert!(held(&db).contains("cannot be read"));

        // The directory served from a ledger; a new one is not it.
        std::fs::write(&path, &kept).unwrap();
        let (other, other_seed, other_db) = made();
        std::fs::copy(&path, other.path().join(FILE)).unwrap();
        assert!(held(&other_db).contains("never served from"));
        let fresh = Hub::open(&other_seed, &other_db, Policy::default()).unwrap();
        assert!(fresh.bind(&other_db).is_err());
        drop(fresh);

        // Promoted, the copy serves, as the file it had no longer does.
        std::fs::remove_file(&path).unwrap();
        promote(&seed, &db).unwrap();
        assert_eq!(serving(&db).unwrap(), Serving::Bound);
        assert_ne!(std::fs::read(&path).unwrap(), kept);
        let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
        hub.bind(&db).unwrap();
        drop(hub);
        promote(&other_seed, &other_db).unwrap();
        assert_eq!(serving(&other_db).unwrap(), Serving::Bound);
    }

    /// Promotion needs the ledger's own seed, and the hub stopped.
    #[test]
    fn a_ledger_is_promoted_with_its_seed_and_the_hub_stopped() {
        let (dir, seed, db) = made();
        let (_other, other_seed, _) = made();
        let refused = promote(&other_seed, &db).unwrap_err().to_string();
        assert!(refused.contains("does not match"), "{refused}");
        assert!(!dir.path().join(FILE).exists());
        let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
        let refused = promote(&seed, &db).unwrap_err().to_string();
        assert!(refused.contains("another hub is running"), "{refused}");
        drop(hub);
        assert!(promote(&seed, &dir.path().join("none.sqlite")).is_err());
        promote(&seed, &db).unwrap();
        assert_eq!(serving(&db).unwrap(), Serving::Bound);
    }

    /// A standby, without the seed, never binds the ledger.
    #[test]
    fn a_standby_never_binds_the_ledger() {
        let (dir, seed, db) = made();
        let keys = dir.path().join("standby.json");
        crate::write_standby_keys(&seed, &db, &keys).unwrap();
        let standby = Hub::open_standby(&keys, &db, Policy::default()).unwrap();
        assert!(standby.bind(&db).is_err());
        drop(standby);
        assert_eq!(serving(&db).unwrap(), Serving::Unbound);
        assert!(!dir.path().join(FILE).exists());
    }
}
