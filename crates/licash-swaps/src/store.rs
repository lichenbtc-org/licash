//! The provider's tables, the component `provider` of its wallet's file:
//! its swaps and its events, written in IMMEDIATE transactions through a
//! connection of their own. The wallet is the provider's, so the file is
//! too: one copy of it is the provider whole.
//!
//! The file is of one layout: a version other than [`VERSION`] is refused,
//! and nothing is migrated.

use std::{
    path::Path,
    sync::{Mutex, MutexGuard, PoisonError},
};

use licash_store::Kind;
use rusqlite::{Connection, Transaction};

use crate::Error;

pub(crate) use licash_store::now;

/// `value` as a database integer: an error beyond it, not a lesser amount.
pub(crate) fn sat(value: u64) -> Result<i64, crate::Error> {
    Ok(licash_store::sat(value)?)
}

/// The component the provider's tables are, and its version.
pub(crate) const COMPONENT: &str = "provider";
pub(crate) const VERSION: i64 = 2;

const SCHEMA: &str = "
-- The provider's identity.
CREATE TABLE provider_meta (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    -- The secret key the provider announces itself under on Nostr.
    nostr BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Swaps by the client's lock at `from_url`, which pays the provider `paid`
-- under `hash` until `expiry_from_height`: recorded before the provider's lock of
-- `amount` to the client's `address` at `to_url` is made, then that lock,
-- then the preimage the client revealed claiming it. `state` is accepted,
-- locked, paid, done, refunded, failed or lost (paid at `to_url` but not
-- claimed at `from_url`).
--
-- `kind` is `notes`, a swap of notes at one hub for notes at another;
-- `own`, into the provider's own hub, which the provider is, whose lock
-- notes it issues itself (`licash_hub::Hub::lock_own`) rather than notes
-- its wallet holds there (it has an `issues` row); `chain`, a payout: its
-- `to_url` is `bitcoin:<network>`, `address` the output script of the
-- provider's coin, `amount` its value and `expiry_height` its timeout, a block
-- height (it has a `payouts` row); or `lightning`, an invoice paid from the
-- provider's node: its `to_url` is `lightning:<network>`, `address` the
-- invoice's payee, a public key, `amount` the invoice's satoshis, rounded
-- up, and `expiry_height` the height its routes' timelock ends by at the latest
-- (it has an `invoices` row).
CREATE TABLE provider_swaps (
    id BLOB PRIMARY KEY,
    hash BLOB NOT NULL UNIQUE CHECK (length(hash) = 32),
    from_url TEXT NOT NULL,
    to_url TEXT NOT NULL,
    address BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    fee INTEGER NOT NULL CHECK (fee >= 0),
    paid INTEGER NOT NULL CHECK (paid >= 0),
    expiry_from_height INTEGER NOT NULL,
    expiry_height INTEGER NOT NULL,
    lock BLOB,
    preimage BLOB CHECK (preimage IS NULL OR length(preimage) = 32),
    state TEXT NOT NULL
        CHECK (state IN ('accepted', 'locked', 'paid', 'done', 'refunded', 'failed', 'lost')),
    reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'notes' CHECK (kind IN ('notes', 'own', 'chain', 'lightning'))
) STRICT;
CREATE INDEX provider_swaps_state ON provider_swaps (state);

-- What the operator is told of, in order. `kind` is the notice's, free: a
-- notice of a kind this version does not know is read as stored.
CREATE TABLE provider_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    json TEXT NOT NULL
) STRICT;

-- The own swaps' locks, by their swaps' ids: their notes pay the client's
-- address as derived from the ephemeral secret, recorded with the swap,
-- before the hub locks.
CREATE TABLE provider_issues (
    id BLOB PRIMARY KEY REFERENCES provider_swaps (id),
    ephemeral BLOB NOT NULL
) STRICT;

-- The invoices, by their swaps' ids, recorded before the node pays them:
-- `node` is the public key of the provider's node that pays it, which
-- alone knows how its payment ends.
CREATE TABLE provider_invoices (
    id BLOB PRIMARY KEY REFERENCES provider_swaps (id),
    request TEXT NOT NULL,
    node BLOB NOT NULL
) STRICT;

-- The payouts' coins, by their swaps' ids: claimed with the client's key
-- claim_key and the preimage, taken back after the timeout with the
-- provider's refund_key, a secret key, recorded before the coin is made.
-- refund_tx is the provider's taking it back once timed out unclaimed.
CREATE TABLE provider_payouts (
    id BLOB PRIMARY KEY REFERENCES provider_swaps (id),
    claim_key BLOB NOT NULL,
    refund_key BLOB NOT NULL,
    refund_tx BLOB
) STRICT;
-- The wallet's transaction paying the coin, at output `vout`, once made.
CREATE TABLE provider_payout_fundings (
    id BLOB PRIMARY KEY REFERENCES provider_payouts (id),
    tx BLOB NOT NULL,
    vout INTEGER NOT NULL
) STRICT;
-- The block a payout's coin was looked through to, by its height: while
-- the chain still has the block of `hash` there, so are the blocks before,
-- and what they held stands. A refund buried deep clears the hash: the
-- height alone then tells REORG blocks less.
CREATE TABLE provider_payout_scans (
    id BLOB PRIMARY KEY REFERENCES provider_payouts (id),
    height INTEGER NOT NULL,
    hash BLOB CHECK (hash IS NULL OR length(hash) = 32)
) STRICT;

-- Donations taken over Lightning (`crate::donations`). Each is a held
-- invoice of the provider's node under `hash`, whose `preimage` the provider
-- chose, asking `sat`, recorded before the node makes it, then its
-- `request`. Once paid, the provider pays `amount` to the wallet of the
-- Licash code `code` under the key `hash` (`licash_wallet::Wallet::
-- pay_code_keyed`), then settles. `state` is open, owed (settled before that
-- payment was released, which the provider still follows), settled, canceled
-- or lost (paid and not settled, or settled and the payment given up).
-- `source` is where it was asked from, as the service tells it, if known.
CREATE TABLE provider_donations (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    code TEXT NOT NULL,
    sat INTEGER NOT NULL CHECK (sat >= 0),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    request TEXT,
    state TEXT NOT NULL CHECK (state IN ('open', 'owed', 'settled', 'canceled', 'lost')),
    reason TEXT,
    source BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX provider_donations_state ON provider_donations (state);
";

pub(crate) struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub(crate) fn set_lock(&self, id: &[u8; 32], lock: &[u8; 32]) -> Result<(), Error> {
        self.write(|tx| {
            tx.execute(
                "UPDATE provider_swaps SET lock = ?2, updated_at = ?3
                 WHERE id = ?1 AND lock IS NULL",
                rusqlite::params![id, lock, now()],
            )?;
            Ok(())
        })
    }

    /// The provider's tables, new in the wallet's file at `path`: refused
    /// where it holds them already.
    pub(crate) fn create(path: &Path, nostr: &[u8; 32]) -> Result<Self, Error> {
        let mut conn = licash_store::open(path, Kind::Wallet).map_err(setup)?;
        if licash_store::component_version(&conn, COMPONENT)
            .map_err(setup)?
            .is_some()
        {
            return Err(Error::Setup(format!(
                "{} holds a swap provider already",
                path.display()
            )));
        }
        licash_store::write(&mut conn, |tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA)
                .map_err(|e| Error::Setup(e.to_string()))?;
            tx.execute(
                "INSERT INTO provider_meta (one, nostr, created_at) VALUES (1, ?1, ?2)",
                rusqlite::params![nostr, now()],
            )?;
            Ok::<_, Error>(())
        })?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The provider's tables in the wallet's file at `path`.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let conn = licash_store::open(path, Kind::Wallet).map_err(setup)?;
        match licash_store::component_version(&conn, COMPONENT).map_err(setup)? {
            Some(VERSION) => Ok(Self {
                conn: Mutex::new(conn),
            }),
            Some(v) => Err(Error::Setup(format!(
                "swaps schema {v}, this version reads {VERSION}"
            ))),
            None => Err(Error::Setup(format!(
                "no swap provider in {}",
                path.display()
            ))),
        }
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn read<T>(
        &self,
        op: impl FnOnce(&Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        op(&self.conn())
    }

    /// `op` whole or not at all.
    pub(crate) fn write<T>(
        &self,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        licash_store::write(&mut self.conn(), op)
    }
}

pub(crate) fn setup(e: licash_store::Error) -> Error {
    match e {
        licash_store::Error::Sqlite(e) => Error::Storage(e),
        e => Error::Setup(e.to_string()),
    }
}
