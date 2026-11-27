//! The Lightning receipts' table as the gateway of an earlier release made
//! it in `hub.sqlite` (component `lightning`, version 2): what this release
//! reads, and never writes.

use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE lightning_receipts (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    body TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    msat INTEGER NOT NULL CHECK (msat >= 0),
    request TEXT,
    lock BLOB,
    state TEXT NOT NULL CHECK (state IN ('open', 'locked', 'settled', 'canceled')),
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    source BLOB,
    CHECK ((state IN ('settled', 'canceled')) = (done_at IS NOT NULL))
) STRICT;
CREATE INDEX live_receipts ON lightning_receipts (state) WHERE state IN ('open', 'locked');
CREATE INDEX receipt_sources ON lightning_receipts (source) WHERE state = 'open';
";

/// The table made in the hub's database at `db`, as the gateway made it on
/// its first start: a connection to write receipts with.
pub fn made(db: &Path) -> rusqlite::Connection {
    let mut conn = licash_store::open(db, licash_store::Kind::Hub).unwrap();
    licash_store::component(&mut conn, "lightning", 2, SCHEMA).unwrap();
    conn
}

/// A receipt under `hash`, in `state`, backing `lock` if any.
pub fn record(conn: &rusqlite::Connection, hash: [u8; 32], state: &str, lock: Option<&[u8]>) {
    let done = matches!(state, "settled" | "canceled").then_some(1);
    conn.execute(
        "INSERT INTO lightning_receipts (hash, body, amount, msat, lock, state, created_at, done_at)
         VALUES (?1, '{}', 5, 5000, ?2, ?3, 0, ?4)",
        rusqlite::params![hash, lock, state, done],
    )
    .unwrap();
}
