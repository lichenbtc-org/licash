//! The wallet's tables, the component `wallet` of its file: one SQLite
//! database, written in IMMEDIATE transactions, so that processes sharing
//! it see each step whole. Modules of other crates keep their tables in the
//! same file as components of their own (`contracts`, `provider`).
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

/// The component the wallet's tables are, and its version. 6 holds notes
/// of the note format v5 (a message without a nonce); a file of 5 holds
/// v4 notes, one of 4 v3 notes and grants, one of 3 v2 notes, which this
/// version cannot spend.
const COMPONENT: &str = "wallet";
const VERSION: i64 = 6;

/// A stage of an operation is a table of its own where its columns are
/// known together (the terms of a deposit, the claim of a payout, a lock's
/// settlement): a row of it is the fact that the stage was reached, and
/// none that it was not. One optional value written alone is a nullable
/// column.
const SCHEMA: &str = "
CREATE TABLE meta (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    -- The owner's seed, unless the application keeps it elsewhere.
    seed BLOB CHECK (seed IS NULL OR length(seed) = 32),
    -- The owner's address, which the seed opening the wallet must derive.
    address BLOB NOT NULL,
    -- The network of the hubs it trusts, by name: bitcoin, regtest, signet
    -- or mutinynet.
    network TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- Hubs, and what each last said of itself (an Info body). Whether the owner
-- trusts the hub, having added it (1), or the wallet only visited it to pay
-- a payee there (0), the hub proving it is the one the payee's code names.
-- inbox_after is the last entry of the hub's inbox the wallet looked
-- through for payments kept for it: none before it first did. deposit_next
-- is the next number of a deposit's secret derived from the seed at this
-- hub: none at a hub added since, until its deposits are looked for there.
CREATE TABLE hubs (
    id INTEGER PRIMARY KEY,
    info TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    trusted INTEGER NOT NULL DEFAULT 1 CHECK (trusted IN (0, 1)),
    inbox_after INTEGER,
    deposit_next INTEGER CHECK (deposit_next IS NULL OR deposit_next >= 0)
) STRICT;
-- The URLs each hub is reached at.
CREATE TABLE hub_urls (
    url TEXT PRIMARY KEY,
    hub INTEGER NOT NULL REFERENCES hubs (id)
) STRICT;
CREATE INDEX hub_urls_hub ON hub_urls (hub);
-- Each hub with the URL the wallet reaches it at.
CREATE VIEW reach (hub, url) AS
    SELECT hub, url FROM hub_urls
    WHERE rowid IN (SELECT MIN(rowid) FROM hub_urls GROUP BY hub);
-- A keyset belongs to the one hub that first advertised it.
CREATE TABLE keysets (
    id BLOB PRIMARY KEY,
    hub INTEGER NOT NULL REFERENCES hubs (id),
    bytes BLOB NOT NULL
) STRICT;

-- Payments made, each step recorded before the hub is asked for the next:
-- the offer asked for, then the release once signed. A signed send is
-- given up only once its hub proves an input spent otherwise, or refuses
-- again an offer it forgot: its release is kept with it, as its hub may
-- have kept it too.
-- renewal is 1 for a payment of the wallet's notes to itself renewing
-- them, which Wallet::unlink finishes. A payment made under a key of its
-- payer's, at most one each, is found again by it.
CREATE TABLE sends (
    id BLOB PRIMARY KEY,
    hub INTEGER NOT NULL REFERENCES hubs (id),
    payee BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    fee INTEGER NOT NULL CHECK (fee >= 0),
    offer TEXT NOT NULL,
    release TEXT,
    unlock BLOB,
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    abandoned TEXT,
    renewal INTEGER NOT NULL DEFAULT 0 CHECK (renewal IN (0, 1)),
    key BLOB
) STRICT;
CREATE UNIQUE INDEX sends_key ON sends (key) WHERE key IS NOT NULL;

-- The owner's notes. Each was made at `position` of `branch` of the
-- proposal with ephemeral key `ephemeral`, where the scan key derives it
-- again.
CREATE TABLE notes (
    y BLOB PRIMARY KEY,
    keyset BLOB NOT NULL REFERENCES keysets (id),
    denom INTEGER NOT NULL CHECK (denom > 0),
    note BLOB NOT NULL,
    proposal BLOB NOT NULL,
    ephemeral BLOB NOT NULL,
    branch INTEGER NOT NULL,
    position INTEGER NOT NULL,
    -- What spends it, from when it chose it: the id of a send, of a lock,
    -- or of the recovery of a contract that claims it, as `spent_kind`
    -- says: both or neither.
    spent_by BLOB,
    spent_kind TEXT CHECK (spent_kind IN ('send', 'lock', 'recovery')),
    -- 1 unlinked, 0 linked, -1 linked for good: its hub unlinks it no more.
    unlinked INTEGER NOT NULL DEFAULT 0 CHECK (unlinked IN (-1, 0, 1)),
    -- An unlink under way: its session, to ask the hub again.
    session TEXT,
    -- When its hub showed it spent by a payment this file never made, by a
    -- copy of the wallet: it is never spent here.
    gone_at INTEGER,
    added_at INTEGER NOT NULL,
    -- Why a note stays linked (unlinked = -1): the code its hub refused to
    -- unlink it with ('expired' while the wallet may renew it), or
    -- 'renewal_refused' once its hub refused to renew it.
    stays_linked TEXT,
    -- When it finished unlinking: its privacy rest starts then.
    unlinked_at INTEGER,
    CHECK ((spent_by IS NULL) = (spent_kind IS NULL))
) STRICT;
CREATE INDEX notes_spent_by ON notes (spent_by);

-- Notes locked to a payee on the preimage of `hash` until `expiry_height`, else
-- refunded: the lock asked for (a Lock body), then the hub's certificate,
-- then its settlement, once the wallet kept its notes of the branch its hub
-- settled. An uncertified lock is given up only once its hub refused it,
-- which proves the hub never recorded it. A lock to the hub may pay a
-- Lightning `invoice` through it, and record why the hub failed or refused
-- to. claimed_by is the recovery of a contract claiming its refund on
-- Bitcoin.
CREATE TABLE locks (
    id BLOB PRIMARY KEY,
    hub INTEGER NOT NULL REFERENCES hubs (id),
    payee BLOB NOT NULL,
    hash BLOB NOT NULL CHECK (length(hash) = 32),
    expiry_height INTEGER NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    fee INTEGER NOT NULL CHECK (fee >= 0),
    request TEXT NOT NULL,
    certificate BLOB,
    invoice TEXT,
    failure TEXT,
    created_at INTEGER NOT NULL,
    abandoned TEXT,
    claimed_by BLOB
) STRICT;
-- The branch settled, with the preimage it was paid on: none of a refund
-- the hub settled without it. A lock is done once it has this row.
CREATE TABLE lock_settlements (
    id BLOB PRIMARY KEY REFERENCES locks (id),
    branch TEXT NOT NULL CHECK (branch IN ('pay', 'refund')),
    preimage BLOB CHECK (preimage IS NULL OR length(preimage) = 32),
    settled_at INTEGER NOT NULL,
    CHECK (branch <> 'pay' OR preimage IS NOT NULL)
) STRICT;
-- The swap provider a lock pays a Lightning invoice through, and the
-- invoice it asks it to pay. Its lock's own `invoice` stays NULL, which
-- names one its hub's gateway pays.
CREATE TABLE lock_routes (
    id BLOB PRIMARY KEY REFERENCES locks (id),
    provider TEXT NOT NULL,
    invoice TEXT NOT NULL
) STRICT;

-- Payments asked for over Lightning, by their hash: the preimage only the
-- wallet knows and the receipt asked for (a Receive body), recorded before
-- the hub hears of them, then the hub's invoice and, once it was paid, the
-- lock of the hub's notes the wallet claims. Done once claimed; canceled
-- once the hub refused it or canceled the invoice. protected marks one
-- whose lock's preimage is revealed with PROTECTED_MARGIN blocks left.
CREATE TABLE invoices (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    hub INTEGER NOT NULL REFERENCES hubs (id),
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    body TEXT NOT NULL,
    request TEXT,
    lock BLOB,
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    canceled TEXT,
    protected INTEGER NOT NULL DEFAULT 0 CHECK (protected IN (0, 1))
) STRICT;

-- Deposits on Bitcoin asked for, by their hash: the preimage and the
-- refund key only the wallet knows and the deposit asked for (a Deposit
-- body), recorded before the hub hears of them; then the hub's terms, the
-- payment once the hub saw it confirm, and the lock of the hub's notes the
-- wallet claims. Done once claimed; canceled once the hub refused or
-- canceled it; a refund, once the wallet made one, takes the coins back.
CREATE TABLE deposits (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    hub INTEGER NOT NULL REFERENCES hubs (id),
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    refund_key BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    -- What its payment is to be, as asked: the hub's terms are held to it.
    pays INTEGER NOT NULL CHECK (pays >= 0),
    body TEXT NOT NULL,
    lock BLOB,
    refund BLOB,
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    canceled TEXT
) STRICT;
-- The hub's terms: its claim key, the block it times out at, the address
-- to pay and by which block.
CREATE TABLE deposit_terms (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    claim_key BLOB NOT NULL,
    timeout_height INTEGER NOT NULL,
    address TEXT NOT NULL,
    fund_by_height INTEGER NOT NULL
) STRICT;
-- The payment, once the hub saw it confirm.
CREATE TABLE deposit_fundings (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    height INTEGER NOT NULL
) STRICT;

-- Swaps of notes at one hub for notes at another through a provider, by
-- the hash of a preimage only the wallet knows, recorded before the lock to
-- the provider (in locks, under that hash) is made; then the provider's
-- lock to the wallet at the other hub, which the wallet claims with the
-- preimage. Done once claimed; failed once the provider did not lock.
CREATE TABLE swaps (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    provider TEXT NOT NULL,
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    from_hub INTEGER NOT NULL REFERENCES hubs (id),
    to_hub INTEGER NOT NULL REFERENCES hubs (id),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    fee INTEGER NOT NULL CHECK (fee >= 0),
    theirs BLOB,
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    failed TEXT
) STRICT;

-- Payments taken, and locks claimed.
CREATE TABLE receipts (
    id BLOB PRIMARY KEY,
    keyset BLOB NOT NULL REFERENCES keysets (id),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    received_at INTEGER NOT NULL
) STRICT;

-- Payouts by the hash of a preimage only the wallet knows, recorded with
-- it, the key that claims the coin and the payee before the lock to the
-- provider (in locks, under that hash) is made at from_hub. The provider
-- locks a coin on chain under the same hash, which the wallet claims
-- paying `script` (`address`, as shown) exactly `amount`, its fee the rest
-- of the coin, `budget` at most. `fee` is the provider's, its miners'
-- included. `blind` is the secret the payee's scan key of a silent payment
-- address is blinded by before the provider is asked its share of it.
CREATE TABLE payouts (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    provider TEXT NOT NULL,
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    claim_key BLOB NOT NULL,
    from_hub INTEGER NOT NULL REFERENCES hubs (id),
    address TEXT NOT NULL,
    script BLOB NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    budget INTEGER NOT NULL CHECK (budget >= 0),
    fee INTEGER NOT NULL CHECK (fee >= 0),
    blind BLOB,
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    failed TEXT
) STRICT;
-- The provider's terms once it took the payout: its refund key and
-- timeout, and its share of a silent payee's scan key, 33 bytes, kept as
-- first proven: none for a payout to an address.
CREATE TABLE payout_terms (
    hash BLOB PRIMARY KEY REFERENCES payouts (hash),
    refund_key BLOB NOT NULL,
    timeout_height INTEGER NOT NULL,
    share BLOB CHECK (share IS NULL OR length(share) = 33)
) STRICT;
-- The coin once found where the provider says, worth `value`, and the
-- claim once made, broadcast until it confirms: the preimage is public from
-- revealed_at on. scanned_height is the last block looked in for the coin's
-- spend, spent_height the block of the claim.
CREATE TABLE payout_claims (
    hash BLOB PRIMARY KEY REFERENCES payouts (hash),
    funding_txid BLOB NOT NULL,
    funding_vout INTEGER NOT NULL,
    funding_height INTEGER NOT NULL,
    value INTEGER NOT NULL CHECK (value >= 0),
    claim_tx BLOB NOT NULL,
    revealed_at INTEGER NOT NULL,
    scanned_height INTEGER NOT NULL,
    spent_height INTEGER
) STRICT;

-- How each payment to a payment code reaches its payee: its hub asked to
-- keep it under the inbox tag and key of the receipt secret, the payee
-- telling ack through the hub once it has it; mailed to the payee's
-- mailbox (an x-only Nostr key), if the code names one, from mail_at on
-- unless acked by then. kept_at is when its hub answered that it keeps
-- it, and mail_at set once released: an hour on if kept, else then. tries
-- counts the mailings failed, the last for error. A payment neither acked
-- nor mailed in the days a hub keeps it is given up.
CREATE TABLE deliveries (
    send BLOB PRIMARY KEY REFERENCES sends (id),
    mailbox BLOB,
    tag BLOB NOT NULL,
    key BLOB NOT NULL,
    ack BLOB NOT NULL,
    kept_at INTEGER,
    mail_at INTEGER,
    acked_at INTEGER,
    mailed_at INTEGER,
    tries INTEGER NOT NULL DEFAULT 0 CHECK (tries >= 0),
    error TEXT,
    given_up_at INTEGER
) STRICT;

-- The locks paying the wallet whose preimage it revealed to their hub,
-- with what proves them on Bitcoin should the hub not issue them
-- (crate::OwedLock): recorded before revealing it. `anchor` is the
-- checkpoint its terms name, once known: its hub's, as it was revealed, or
-- found on the chain. claimed_by is the recovery claiming it on Bitcoin.
CREATE TABLE owed_locks (
    id BLOB PRIMARY KEY,
    hub INTEGER NOT NULL REFERENCES hubs (id),
    keyset BLOB NOT NULL,
    proposal BLOB NOT NULL,
    certificate BLOB NOT NULL,
    -- Its payer's owner signatures, 64 bytes each.
    signatures BLOB NOT NULL,
    preimage BLOB NOT NULL CHECK (length(preimage) = 32),
    expiry_height INTEGER NOT NULL,
    depth INTEGER NOT NULL,
    anchor BLOB,
    claimed_by BLOB,
    created_at INTEGER NOT NULL
) STRICT;
-- Its activation on Bitcoin, as JSON, and its block's height: deleted
-- when a reorganization takes the block.
CREATE TABLE owed_lock_activations (
    id BLOB PRIMARY KEY REFERENCES owed_locks (id),
    activation TEXT NOT NULL,
    height INTEGER NOT NULL
) STRICT;

-- The next block to look in for silent payments (`next_height`), from a
-- first block the owner chose: none until it chose one. The blocks from
-- `untweaked_height` up to `untweaked_until`, or up to the next if none, were
-- looked in without tweaks, to look in again for silent payments once a hub
-- serves them: none if none was.
CREATE TABLE silent_scan (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    next_height INTEGER NOT NULL,
    untweaked_height INTEGER,
    untweaked_until INTEGER,
    CHECK (untweaked_until IS NULL OR untweaked_until > untweaked_height)
) STRICT;
-- The blocks looked in lately, by height, to notice a reorganization.
CREATE TABLE silent_blocks (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL
) STRICT;
-- Outputs paying the silent payment address, in a block of the best chain,
-- with what spends each (its key's tweak and label); spent_by names the
-- transaction spending it, the wallet's own or seen, and spent_height the
-- block it is in, once in one.
CREATE TABLE silent_coins (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    value INTEGER NOT NULL CHECK (value >= 0),
    output BLOB NOT NULL,
    tweak BLOB NOT NULL,
    label INTEGER,
    height INTEGER NOT NULL,
    spent_by BLOB,
    spent_height INTEGER,
    PRIMARY KEY (txid, vout)
) STRICT;
-- The transactions the wallet made of its coins, to broadcast.
CREATE TABLE silent_spends (
    txid BLOB PRIMARY KEY,
    tx BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
-- The highest index of a fallback address handed out in a payment code:
-- none until one is. Those up to it, and a few after, are watched.
CREATE TABLE silent_fallback (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    shown INTEGER NOT NULL
) STRICT;

-- Cold storage (crate::Wallet::set_cold), at most one: the external
-- wallet's extended public key as given, the kind of its addresses, the
-- rules of withdrawing to it, the block looked for its coins from and the
-- last looked in; and the coins found at its addresses, by the index of
-- each.
CREATE TABLE cold (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key TEXT NOT NULL,
    script TEXT NOT NULL,
    threshold INTEGER NOT NULL CHECK (threshold >= 0),
    keep INTEGER NOT NULL CHECK (keep >= 0),
    max_fee_percent REAL NOT NULL CHECK (max_fee_percent >= 0),
    birthday_height INTEGER NOT NULL,
    scanned_height INTEGER
) STRICT;
CREATE TABLE cold_coins (
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    value INTEGER NOT NULL CHECK (value >= 0),
    height INTEGER NOT NULL,
    spent_height INTEGER,
    PRIMARY KEY (txid, vout)
) STRICT;
";

/// What a wallet file holds of its owner.
pub(crate) struct Owner {
    /// Unless the application keeps it.
    pub(crate) seed: Option<[u8; 32]>,
    pub(crate) address: Vec<u8>,
    pub(crate) network: String,
}

pub(crate) struct Store {
    conn: Mutex<Connection>,
    path: std::path::PathBuf,
}

impl Store {
    /// A new wallet file at `path` of the owner at `address`, on `network`,
    /// holding its `seed` if given, readable by its owner only. Never over
    /// an existing file.
    pub(crate) fn create(
        path: &Path,
        seed: Option<&[u8; 32]>,
        address: &[u8],
        network: &str,
    ) -> Result<Self, Error> {
        let mut conn = licash_store::create(path, Kind::Wallet).map_err(setup)?;
        let made = licash_store::write(&mut conn, |tx| {
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA)
                .map_err(|e| Error::Setup(e.to_string()))?;
            tx.execute(
                "INSERT INTO meta (one, seed, address, network, created_at)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                rusqlite::params![seed, address, network, now()],
            )?;
            Ok::<_, Error>(())
        });
        if let Err(e) = made {
            drop(conn);
            for file in [
                path.to_owned(),
                suffixed(path, "-wal"),
                suffixed(path, "-shm"),
            ] {
                let _ = std::fs::remove_file(file);
            }
            return Err(e);
        }
        Ok(Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        })
    }

    /// The wallet file at `path`, and what it holds of its owner.
    pub(crate) fn open(path: &Path) -> Result<(Self, Owner), Error> {
        if !path.exists() {
            return Err(Error::Setup(format!("no wallet at {}", path.display())));
        }
        let conn = licash_store::open(path, Kind::Wallet).map_err(setup)?;
        match licash_store::component_version(&conn, COMPONENT).map_err(setup)? {
            Some(VERSION) => {}
            Some(v) if v < VERSION => {
                return Err(Error::Setup(format!(
                    "a wallet of an earlier version (schema {v}, this version reads {VERSION}), \
                     left as it is: spend or pay out its notes with that version"
                )))
            }
            Some(v) => {
                return Err(Error::Setup(format!(
                    "wallet schema {v}, this version reads {VERSION}"
                )))
            }
            None => {
                return Err(Error::Setup(format!(
                    "no wallet in {}: it holds another's tables only",
                    path.display()
                )))
            }
        }
        let store = Self {
            conn: Mutex::new(conn),
            path: path.to_path_buf(),
        };
        let owner = store.read(|c| {
            Ok(
                c.query_row("SELECT seed, address, network FROM meta", [], |r| {
                    Ok(Owner {
                        seed: r.get(0)?,
                        address: r.get(1)?,
                        network: r.get(2)?,
                    })
                })?,
            )
        })?;
        Ok((store, owner))
    }

    /// The file the wallet is kept in.
    pub(crate) fn path(&self) -> &Path {
        &self.path
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

fn setup(e: licash_store::Error) -> Error {
    match e {
        licash_store::Error::Sqlite(e) => Error::Storage(e),
        e => Error::Setup(e.to_string()),
    }
}

fn suffixed(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

/// A u64 as SQLite's i64: an error beyond it, not a lesser amount.
pub(crate) fn sql(value: u64) -> Result<i64, Error> {
    Ok(licash_store::sat(value)?)
}
