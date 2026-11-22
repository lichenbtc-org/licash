//! The hub's ledger, the component `ledger` of `hub.sqlite`: one SQLite
//! connection, one IMMEDIATE transaction per operation, and a write counter
//! that halts the hub if its database is replaced while it runs. Other
//! modules of the hub keep their tables in the same file, as components of
//! their own, through connections of their own.
//!
//! The file is of one layout: a version other than [`VERSION`] is refused,
//! and nothing is migrated.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, MutexGuard, PoisonError,
    },
};

use licash_store::Kind;
use rusqlite::{Connection, Transaction};

use crate::Error;

pub(crate) use licash_store::now;

/// The component the ledger's tables are, and its version. 4 issues notes
/// of the note format v5 (a message without a nonce), each blinded point
/// once whatever its keyset; a ledger of 3 holds v4 notes, one of 2 v3
/// notes and grants, one of 1 v2 notes, keysets and proofs: each is
/// refused rather than read under the other rule.
pub(crate) const COMPONENT: &str = "ledger";
pub(crate) const VERSION: i64 = 4;

const SCHEMA: &str = "
CREATE TABLE meta (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    -- Bumped by every write, and checked against the running hub's count.
    seq INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE keysets (
    id BLOB PRIMARY KEY,
    idx INTEGER NOT NULL UNIQUE,
    max_pow INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
-- Every proposal the hub served: a grant or a lock.
CREATE TABLE proposals (
    id BLOB PRIMARY KEY,
    keyset BLOB NOT NULL REFERENCES keysets (id),
    created_at INTEGER NOT NULL,
    -- When a spend of its inputs by another proposal was first refused.
    double_spent_at INTEGER
) STRICT;
-- Offered grants. The unlock derives from the seed and the salt, the
-- unlink nonces from the boot that made the offer. Released once signed:
-- both or neither.
CREATE TABLE grants (
    id BLOB PRIMARY KEY REFERENCES proposals (id),
    offer BLOB NOT NULL,
    salt BLOB NOT NULL,
    boot BLOB NOT NULL,
    signed BLOB,
    released_at INTEGER,
    CHECK ((signed IS NULL) = (released_at IS NULL))
) STRICT;
-- Checkpoints the terms of a lock may name.
CREATE TABLE checkpoints (
    commitment BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    added_at INTEGER NOT NULL
) STRICT;
-- The best chain as scanned, each block linked to the one before, from
-- the first checkpoint's.
CREATE TABLE blocks (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    prev BLOB NOT NULL
) STRICT;
-- Every activation ever scanned, in the best chain or not: a holder may
-- prove one on any chain from a checkpoint. Never deleted. Its block has no
-- row of `blocks` to refer to: one of a chain no longer the best has none.
CREATE TABLE activations (
    block BLOB NOT NULL,
    txid BLOB NOT NULL,
    output INTEGER NOT NULL,
    hash BLOB NOT NULL,
    secret BLOB NOT NULL,
    height INTEGER NOT NULL,
    PRIMARY KEY (block, txid, output)
) STRICT;
CREATE INDEX activations_hash ON activations (hash);
-- Timed locks: their pay branch is issued on the preimage, their refund
-- branch once they expired unactivated. `own` locks spend notes the hub
-- issued itself, backed by what the caller holds (an HTLC). Settled on one
-- branch, with the time: both or neither, and a pay with its preimage.
CREATE TABLE locks (
    id BLOB PRIMARY KEY REFERENCES proposals (id),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    checkpoint BLOB NOT NULL REFERENCES checkpoints (commitment),
    expiry_height INTEGER NOT NULL,
    depth INTEGER NOT NULL,
    -- Height by which the hub answers a refund request: expiry, depth and
    -- its reaction at the time it was admitted.
    decide_by_height INTEGER NOT NULL,
    proposal BLOB NOT NULL,
    signed BLOB NOT NULL,
    certificate BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    own INTEGER NOT NULL CHECK (own IN (0, 1)),
    preimage BLOB,
    settled TEXT CHECK (settled IN ('pay', 'refund')),
    settled_at INTEGER,
    CHECK ((settled IS NULL) = (settled_at IS NULL)),
    CHECK (settled IS NOT 'pay' OR preimage IS NOT NULL)
) STRICT;
CREATE INDEX locks_hash ON locks (hash);
CREATE UNIQUE INDEX own_locks ON locks (hash) WHERE own = 1;
-- The own locks not settled yet, by expiry: those the hub may yet pay.
CREATE INDEX live_own_locks ON locks (expiry_height, id) WHERE own = 1 AND settled IS NULL;
-- Each retired input, by its identifier, with the note that spent it.
CREATE TABLE spent (
    y BLOB PRIMARY KEY,
    proposal BLOB NOT NULL REFERENCES proposals (id),
    position INTEGER NOT NULL,
    note BLOB NOT NULL
) STRICT;
CREATE INDEX spent_proposal ON spent (proposal, position);
-- Each output the hub issued or, without a boot, reserved for a lock's
-- branch; a lock's with its issuance, and once answered, its unlink
-- record. A reserved output is issued to nobody else. A blinded point is
-- issued once under any keyset: one made again, as by an ephemeral key
-- used twice, is the same note, whose identifier does not name its keyset
-- and would be spent once.
CREATE TABLE issued (
    keyset BLOB NOT NULL REFERENCES keysets (id),
    denom INTEGER NOT NULL,
    blinded BLOB NOT NULL,
    commitment BLOB NOT NULL,
    proposal BLOB NOT NULL REFERENCES proposals (id),
    position INTEGER NOT NULL,
    boot BLOB,
    issuance BLOB CHECK (issuance IS NULL OR boot IS NOT NULL),
    answered BLOB CHECK (answered IS NULL OR boot IS NOT NULL),
    PRIMARY KEY (blinded)
) STRICT;
-- Notes paid to the hub, a lock's refund branch from `REFUND_INDEX`.
CREATE TABLE income (
    proposal BLOB NOT NULL REFERENCES proposals (id),
    position INTEGER NOT NULL,
    denom INTEGER NOT NULL,
    note BLOB NOT NULL,
    PRIMARY KEY (proposal, position)
) STRICT;
-- Payments the hub makes outside its ledger, such as over Lightning, for a
-- lock that pays it only, settled by the preimage they buy. A pending one
-- keeps its lock from a refund; a failed one refunded it. One live
-- payment per hash, which a lock's own hash is: its expiry is its lock's.
CREATE TABLE forwards (
    lock BLOB PRIMARY KEY REFERENCES locks (id),
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    request TEXT NOT NULL,
    node TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'paid', 'failed')),
    preimage BLOB,
    reason TEXT,
    created_at INTEGER NOT NULL,
    resolved_at INTEGER,
    CHECK (state <> 'pending' OR (preimage IS NULL AND reason IS NULL AND resolved_at IS NULL)),
    CHECK (state <> 'paid' OR (preimage IS NOT NULL AND resolved_at IS NOT NULL)),
    CHECK (state <> 'failed' OR (reason IS NOT NULL AND resolved_at IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX live_forwards ON forwards (hash) WHERE state IN ('pending', 'paid');
-- The notification outbox.
CREATE TABLE events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    json TEXT NOT NULL
) STRICT;
-- Each note a holder's claim on Bitcoin names, by contract, with its hold
-- key's signature of the claim: retired, spent by nothing else, and cited
-- against any other claim of it. Never deleted.
CREATE TABLE claimed (
    contract BLOB NOT NULL,
    y BLOB NOT NULL,
    context BLOB NOT NULL,
    message BLOB NOT NULL,
    sig BLOB NOT NULL,
    at INTEGER NOT NULL,
    PRIMARY KEY (contract, y)
) STRICT;
CREATE INDEX claimed_y ON claimed (y);
";

/// The locks holders' claims showed the hub, a component of their own
/// beside the ledger's: a hub's file of before it has none, which says
/// that none was shown it since, and nothing of the claims read before.
/// Made empty the first time such a file is opened, and no work with it.
pub(crate) const SHOWN: &str = "shown";
pub(crate) const SHOWN_VERSION: i64 = 1;

const SHOWN_SCHEMA: &str = "
-- Each lock of her own notes that the hub never served and a holder's
-- claim on Bitcoin took the refund of, as its filing showed it, signed by
-- the owners of the notes it spends: the evidence of that spend, as cited
-- against any other claim of them. Never deleted, never settled.
CREATE TABLE shown_locks (
    id BLOB PRIMARY KEY,
    keyset BLOB NOT NULL,
    contract BLOB NOT NULL,
    evidence BLOB NOT NULL,
    at INTEGER NOT NULL
) STRICT;
-- Each note such a claim gave up by its lock alone, its hold key having
-- signed nothing: retired, spent by nothing else, with the first lock
-- shown of it.
CREATE TABLE shown_inputs (
    y BLOB PRIMARY KEY,
    lock BLOB NOT NULL REFERENCES shown_locks (id)
) STRICT;
";

pub(crate) struct Store {
    inner: Mutex<Inner>,
    halted: AtomicBool,
    /// Held for the life of the hub: one hub per database.
    _lock: File,
}

struct Inner {
    conn: Connection,
    seq: i64,
}

impl Store {
    /// A new ledger in a new file at `path`, filled by `init` in the
    /// transaction that creates the schema. On an error nothing is left
    /// behind.
    pub(crate) fn create(
        path: &Path,
        init: impl FnOnce(&Transaction<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut conn = licash_store::create(path, Kind::Hub).map_err(setup)?;
        let created = licash_store::write(&mut conn, |tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(setup)?;
            licash_store::component_in(tx, SHOWN, SHOWN_VERSION, SHOWN_SCHEMA).map_err(setup)?;
            tx.execute(
                "INSERT INTO meta (one, seq, created_at) VALUES (1, 0, ?1)",
                [now()],
            )?;
            init(tx)
        });
        if created.is_err() {
            drop(conn);
            for file in [
                path.to_owned(),
                suffixed(path, "-wal"),
                suffixed(path, "-shm"),
            ] {
                let _ = std::fs::remove_file(file);
            }
        }
        created
    }

    /// The ledger at `path`, as [`Store::create`] made it.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        if !path.is_file() {
            return Err(Error::Setup(format!(
                "no hub database at {}",
                path.display()
            )));
        }
        // One lock per file, by whatever path the hub is given.
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(suffixed(&path.canonicalize()?, ".lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::Setup(format!(
                    "another hub is running on {}",
                    path.display()
                )))
            }
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        let mut conn = licash_store::open(path, Kind::Hub).map_err(setup)?;
        check_version(&conn)?;
        // A file of before claims showed locks: the tables, empty.
        licash_store::component(&mut conn, SHOWN, SHOWN_VERSION, SHOWN_SCHEMA).map_err(setup)?;
        let seq = conn.query_row("SELECT seq FROM meta", [], |r| r.get(0))?;
        Ok(Self {
            inner: Mutex::new(Inner { conn, seq }),
            halted: AtomicBool::new(false),
            _lock: lock,
        })
    }

    /// Run `op` in one IMMEDIATE transaction and commit it if `op`
    /// succeeds. An [`Error::Halted`] from `op`, or a database whose write
    /// count is not this hub's, halts the hub.
    pub(crate) fn write<T>(
        &self,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut inner = self.lock()?;
        let Inner { conn, seq } = &mut *inner;
        let tx = licash_store::begin(conn)?;
        if tx.execute("UPDATE meta SET seq = seq + 1 WHERE seq = ?1", [*seq])? != 1 {
            return Err(self.halt("the database changed under the running hub"));
        }
        let value = match op(&tx) {
            Err(Error::Halted) => return Err(self.halt("the ledger contradicts itself")),
            result => result?,
        };
        tx.commit()?;
        *seq += 1;
        Ok(value)
    }

    pub(crate) fn read<T>(
        &self,
        op: impl FnOnce(&Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        op(&self.lock()?.conn)
    }

    /// [`Self::read`], halting the hub as [`Self::write`] would should the
    /// database's write count not be this hub's: for a refusal made on a
    /// read alone, which must not answer from a database changed under it.
    pub(crate) fn read_current<T>(
        &self,
        op: impl FnOnce(&Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let inner = self.lock()?;
        let seq: i64 = inner
            .conn
            .query_row("SELECT seq FROM meta", [], |r| r.get(0))?;
        if seq != inner.seq {
            return Err(self.halt("the database changed under the running hub"));
        }
        op(&inner.conn)
    }

    pub(crate) fn halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, Error> {
        if self.halted.load(Ordering::SeqCst) {
            return Err(Error::Halted);
        }
        // A panic in an operation rolled its transaction back.
        Ok(self.inner.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn halt(&self, why: &str) -> Error {
        self.halted.store(true, Ordering::SeqCst);
        tracing::error!("{why}: the hub serves nothing more");
        Error::Halted
    }
}

/// A connection to the ledger at `path` that cannot write it.
pub(crate) fn inspect(path: &Path) -> Result<Connection, Error> {
    let conn = licash_store::inspect(path, Kind::Hub)
        .map_err(setup)?
        .ok_or_else(|| Error::Setup(format!("no hub database at {}", path.display())))?;
    check_version(&conn)?;
    Ok(conn)
}

fn check_version(conn: &Connection) -> Result<(), Error> {
    match licash_store::component_version(conn, COMPONENT).map_err(setup)? {
        Some(VERSION) => Ok(()),
        Some(v) if v < VERSION => Err(Error::Setup(format!(
            "database schema {v}, this hub reads {VERSION}: a ledger of an earlier release, \
             left as it is. Run the release that wrote it until its contracts close, then \
             make a hub anew with init in a new data directory (docs/hub.md, Upgrading)"
        ))),
        Some(v) => Err(Error::Setup(format!(
            "database schema {v}, this hub reads {VERSION}"
        ))),
        None => Err(Error::Setup("no ledger in the hub's database".into())),
    }
}

fn setup(e: licash_store::Error) -> Error {
    match e {
        licash_store::Error::Sqlite(e) => e.into(),
        e => Error::Setup(e.to_string()),
    }
}

pub(crate) fn setup_io(path: &Path, e: std::io::Error) -> Error {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        Error::Setup(format!("{} exists", path.display()))
    } else {
        e.into()
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}
