//! The bridge's records, in its wallet's file as a component of their own:
//! its accounts, their connections, and the payments in and out of them.
//! Amounts are in millisatoshis.

use std::{
    path::Path,
    sync::{Mutex, MutexGuard, PoisonError},
};

use licash_api::bridge::{Budget, Period, State};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::Error;

pub(crate) const COMPONENT: &str = "bridge";
pub(crate) const VERSION: i64 = 1;

const SCHEMA: &str = "
-- The bridge itself: one row.
CREATE TABLE bridge_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- The secret key its NWC service answers as.
    nostr BLOB NOT NULL CHECK (length(nostr) = 32),
    -- What its owner registers with, until registered: none once used.
    pairing TEXT,
    -- Once its notes were exported to be claimed elsewhere: it pays
    -- nothing out until unfrozen.
    frozen_at INTEGER,
    created_at INTEGER NOT NULL
);
-- An account: a key managing it, and what it holds, payments under way
-- taken out.
CREATE TABLE bridge_accounts (
    id INTEGER PRIMARY KEY,
    key BLOB NOT NULL UNIQUE CHECK (length(key) = 32),
    balance INTEGER NOT NULL CHECK (balance >= 0),
    -- The name of its Lightning Address, if it has one.
    username TEXT UNIQUE,
    -- A Licash code it is swept to, keeping `keep` at most.
    sweep_to TEXT,
    keep INTEGER CHECK (keep >= 0),
    created_at INTEGER NOT NULL
);
-- An NWC connection: its client's key, and what it may do.
CREATE TABLE bridge_connections (
    key BLOB PRIMARY KEY CHECK (length(key) = 32),
    account INTEGER NOT NULL REFERENCES bridge_accounts (id),
    name TEXT NOT NULL,
    pay INTEGER NOT NULL CHECK (pay IN (0, 1)),
    receive INTEGER NOT NULL CHECK (receive IN (0, 1)),
    max_payment INTEGER CHECK (max_payment >= 0),
    budget INTEGER CHECK (budget >= 0),
    period TEXT CHECK (period IN ('daily', 'weekly', 'monthly', 'yearly', 'never')),
    expires_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK ((budget IS NULL) = (period IS NULL))
);
-- An invoice paid out of an account: `reserved` is taken from its
-- balance while under way, and is what it cost once decided.
CREATE TABLE bridge_payments (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    account INTEGER NOT NULL REFERENCES bridge_accounts (id),
    connection BLOB REFERENCES bridge_connections (key),
    invoice TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    reserved INTEGER NOT NULL CHECK (reserved >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'failed')),
    preimage BLOB CHECK (length(preimage) = 32),
    failure TEXT,
    -- Of its latest attempt: a lock made before it is not its.
    started_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    settled_at INTEGER
);
CREATE INDEX bridge_payments_pending ON bridge_payments (state) WHERE state = 'pending';
-- An invoice paying into an account `credits` once paid.
CREATE TABLE bridge_invoices (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    account INTEGER NOT NULL REFERENCES bridge_accounts (id),
    connection BLOB REFERENCES bridge_connections (key),
    invoice TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    credits INTEGER NOT NULL CHECK (credits >= 0),
    description TEXT,
    description_hash BLOB CHECK (length(description_hash) = 32),
    -- The Nostr zap request it pays, as JSON, for its receipt, and when
    -- the receipt was published, or given up on.
    zap TEXT,
    zap_sent_at INTEGER,
    state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'expired')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    settled_at INTEGER
);
CREATE INDEX bridge_invoices_pending ON bridge_invoices (state) WHERE state = 'pending';
";

/// The bridge's records, one connection at a time.
pub(crate) struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Add the bridge's records to the wallet's file at `path`, with its
    /// Nostr key and its owner's pairing code.
    pub(crate) fn create(path: &Path, nostr: &[u8; 32], pairing: &str) -> Result<Self, Error> {
        let mut conn = licash_store::open(path, licash_store::Kind::Wallet).map_err(setup)?;
        licash_store::write(&mut conn, |tx| {
            if licash_store::component_version(tx, COMPONENT)
                .map_err(setup)?
                .is_some()
            {
                return Err(Error::Invalid("this wallet is a bridge already".into()));
            }
            licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(setup)?;
            tx.execute(
                "INSERT INTO bridge_meta (id, nostr, pairing, created_at) VALUES (1, ?1, ?2, ?3)",
                params![nostr, pairing, licash_store::now()],
            )?;
            Ok(())
        })?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The bridge's records in the wallet's file at `path`: refused unless
    /// they are of this version.
    pub(crate) fn open(path: &Path) -> Result<Self, Error> {
        let conn = licash_store::open(path, licash_store::Kind::Wallet).map_err(setup)?;
        match licash_store::component_version(&conn, COMPONENT).map_err(setup)? {
            Some(VERSION) => Ok(Self {
                conn: Mutex::new(conn),
            }),
            Some(v) => Err(Error::Unavailable(format!(
                "bridge records of version {v}, not {VERSION}: use the release that wrote them"
            ))),
            None => Err(Error::Invalid(
                "this wallet is no bridge: run `licash-bridge init` first".into(),
            )),
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

fn setup(e: licash_store::Error) -> Error {
    Error::Unavailable(format!("the bridge's records: {e}"))
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Unavailable(format!("the bridge's records: {e}"))
    }
}

/// A count of millisatoshis as SQLite keeps it.
pub(crate) fn sql(msat: u64) -> Result<i64, Error> {
    i64::try_from(msat).map_err(|_| Error::Invalid("an amount out of range".into()))
}

pub(crate) struct Meta {
    pub nostr: [u8; 32],
    pub pairing: Option<String>,
    pub frozen_at: Option<i64>,
}

pub(crate) fn meta(c: &Connection) -> Result<Meta, Error> {
    Ok(c.query_row(
        "SELECT nostr, pairing, frozen_at FROM bridge_meta WHERE id = 1",
        [],
        |r| {
            Ok(Meta {
                nostr: r.get(0)?,
                pairing: r.get(1)?,
                frozen_at: r.get(2)?,
            })
        },
    )?)
}

#[derive(Clone, Debug)]
pub(crate) struct Account {
    pub id: i64,
    pub balance: u64,
    pub username: Option<String>,
}

const ACCOUNT: &str = "SELECT id, balance, username FROM bridge_accounts";

fn account_row(r: &Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get(0)?,
        balance: r.get::<_, i64>(1)? as u64,
        username: r.get(2)?,
    })
}

pub(crate) fn account_of(c: &Connection, key: &[u8; 32]) -> Result<Option<Account>, Error> {
    Ok(
        c.query_row(&format!("{ACCOUNT} WHERE key = ?1"), [key], account_row)
            .optional()?,
    )
}

/// The account of the Lightning Address `username`.
pub(crate) fn account_named(c: &Connection, username: &str) -> Result<Option<Account>, Error> {
    Ok(c.query_row(
        &format!("{ACCOUNT} WHERE username = ?1"),
        [username],
        account_row,
    )
    .optional()?)
}

/// Name the Lightning Address of account `id` `username`, or none: refused
/// if another account's.
pub(crate) fn set_username(
    tx: &Transaction<'_>,
    id: i64,
    username: Option<&str>,
) -> Result<(), Error> {
    if let Some(name) = username {
        if account_named(tx, name)?.is_some_and(|a| a.id != id) {
            return Err(Error::Invalid(format!("{name} is taken")));
        }
    }
    tx.execute(
        "UPDATE bridge_accounts SET username = ?2 WHERE id = ?1",
        params![id, username],
    )?;
    Ok(())
}

pub(crate) fn account(c: &Connection, id: i64) -> Result<Account, Error> {
    Ok(c.query_row(&format!("{ACCOUNT} WHERE id = ?1"), [id], account_row)?)
}

pub(crate) fn accounts(c: &Connection) -> Result<Vec<Account>, Error> {
    let mut stmt = c.prepare(&format!("{ACCOUNT} ORDER BY id"))?;
    let rows = stmt.query_map([], account_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Add `delta` to the balance of account `id`: refused, as
/// [`Error::Insufficient`], below none.
pub(crate) fn credit(tx: &Transaction<'_>, id: i64, delta: i64) -> Result<(), Error> {
    let balance: i64 = tx.query_row(
        "SELECT balance FROM bridge_accounts WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    let after = balance
        .checked_add(delta)
        .ok_or_else(|| Error::Invalid("an amount out of range".into()))?;
    if after < 0 {
        return Err(Error::Insufficient(format!(
            "{} msat asked, {balance} held",
            -delta
        )));
    }
    tx.execute(
        "UPDATE bridge_accounts SET balance = ?2 WHERE id = ?1",
        params![id, after],
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct Link {
    pub key: [u8; 32],
    pub account: i64,
    pub name: String,
    pub pay: bool,
    pub receive: bool,
    pub max_payment: Option<u64>,
    pub budget: Option<Budget>,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
}

impl Link {
    /// Whether it may be used at `now`.
    pub(crate) fn live(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|at| now < at)
    }

    /// When its budget's current period started, as of `now`.
    pub(crate) fn period_start(&self, now: i64) -> i64 {
        match self.budget.and_then(|b| b.period.seconds()) {
            Some(length) => {
                let elapsed = (now - self.created_at).max(0);
                self.created_at + elapsed / length * length
            }
            None => self.created_at,
        }
    }
}

const LINK: &str = "SELECT key, account, name, pay, receive, max_payment, budget, period,
    expires_at, revoked_at, created_at FROM bridge_connections";

fn link_row(r: &Row<'_>) -> rusqlite::Result<Link> {
    let budget: Option<i64> = r.get(6)?;
    let period: Option<String> = r.get(7)?;
    let budget = match (budget, period.as_deref()) {
        (Some(amount), Some(period)) => Some(Budget {
            amount: amount as u64,
            period: match period {
                "daily" => Period::Daily,
                "weekly" => Period::Weekly,
                "monthly" => Period::Monthly,
                "yearly" => Period::Yearly,
                _ => Period::Never,
            },
        }),
        _ => None,
    };
    Ok(Link {
        key: r.get(0)?,
        account: r.get(1)?,
        name: r.get(2)?,
        pay: r.get(3)?,
        receive: r.get(4)?,
        max_payment: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        budget,
        expires_at: r.get(8)?,
        revoked_at: r.get(9)?,
        created_at: r.get(10)?,
    })
}

pub(crate) fn period_name(period: Period) -> &'static str {
    match period {
        Period::Daily => "daily",
        Period::Weekly => "weekly",
        Period::Monthly => "monthly",
        Period::Yearly => "yearly",
        Period::Never => "never",
    }
}

pub(crate) fn link(c: &Connection, key: &[u8; 32]) -> Result<Option<Link>, Error> {
    Ok(
        c.query_row(&format!("{LINK} WHERE key = ?1"), [key], link_row)
            .optional()?,
    )
}

pub(crate) fn links_of(c: &Connection, account: i64) -> Result<Vec<Link>, Error> {
    let mut stmt = c.prepare(&format!(
        "{LINK} WHERE account = ?1 ORDER BY created_at, key"
    ))?;
    let rows = stmt.query_map([account], link_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(crate) fn insert_link(tx: &Transaction<'_>, link: &Link) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO bridge_connections (key, account, name, pay, receive, max_payment,
            budget, period, expires_at, revoked_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
        params![
            link.key,
            link.account,
            link.name,
            link.pay,
            link.receive,
            link.max_payment.map(sql).transpose()?,
            link.budget.map(|b| sql(b.amount)).transpose()?,
            link.budget.map(|b| period_name(b.period)),
            link.expires_at,
            link.created_at,
        ],
    )?;
    Ok(())
}

/// What the connection of `key` paid since `since`: what its payments
/// under way hold, and what those decided cost.
pub(crate) fn spent(c: &Connection, key: &[u8; 32], since: i64) -> Result<u64, Error> {
    let spent: i64 = c.query_row(
        "SELECT COALESCE(SUM(reserved), 0) FROM bridge_payments
         WHERE connection = ?1 AND started_at >= ?2",
        params![key, since],
        |r| r.get(0),
    )?;
    Ok(spent as u64)
}

/// What the payments under way of account `id` hold.
pub(crate) fn reserved(c: &Connection, id: i64) -> Result<u64, Error> {
    let reserved: i64 = c.query_row(
        "SELECT COALESCE(SUM(reserved), 0) FROM bridge_payments
         WHERE account = ?1 AND state = 'pending'",
        [id],
        |r| r.get(0),
    )?;
    Ok(reserved as u64)
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Pending => "pending",
        State::Settled => "settled",
        State::Failed => "failed",
        State::Expired => "expired",
    }
}

fn state_of(name: &str) -> State {
    match name {
        "settled" => State::Settled,
        "failed" => State::Failed,
        "expired" => State::Expired,
        _ => State::Pending,
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Payment {
    pub hash: [u8; 32],
    pub account: i64,
    pub connection: Option<[u8; 32]>,
    pub invoice: String,
    pub amount: u64,
    pub reserved: u64,
    pub state: State,
    pub preimage: Option<[u8; 32]>,
    pub failure: Option<String>,
    pub started_at: i64,
    pub created_at: i64,
    pub settled_at: Option<i64>,
}

impl Payment {
    /// What it paid on top of its invoice, once settled.
    pub(crate) fn fee(&self) -> u64 {
        match self.state {
            State::Settled => self.reserved.saturating_sub(self.amount),
            _ => 0,
        }
    }
}

const PAYMENT: &str = "SELECT hash, account, connection, invoice, amount, reserved, state,
    preimage, failure, started_at, created_at, settled_at FROM bridge_payments";

fn payment_row(r: &Row<'_>) -> rusqlite::Result<Payment> {
    Ok(Payment {
        hash: r.get(0)?,
        account: r.get(1)?,
        connection: r.get(2)?,
        invoice: r.get(3)?,
        amount: r.get::<_, i64>(4)? as u64,
        reserved: r.get::<_, i64>(5)? as u64,
        state: state_of(&r.get::<_, String>(6)?),
        preimage: r.get(7)?,
        failure: r.get(8)?,
        started_at: r.get(9)?,
        created_at: r.get(10)?,
        settled_at: r.get(11)?,
    })
}

pub(crate) fn payment(c: &Connection, hash: &[u8; 32]) -> Result<Option<Payment>, Error> {
    Ok(
        c.query_row(&format!("{PAYMENT} WHERE hash = ?1"), [hash], payment_row)
            .optional()?,
    )
}

pub(crate) fn pending_payments(c: &Connection) -> Result<Vec<Payment>, Error> {
    let mut stmt = c.prepare(&format!(
        "{PAYMENT} WHERE state = 'pending' ORDER BY started_at"
    ))?;
    let rows = stmt.query_map([], payment_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(crate) fn payments_of(c: &Connection, account: i64, limit: u32) -> Result<Vec<Payment>, Error> {
    let mut stmt = c.prepare(&format!(
        "{PAYMENT} WHERE account = ?1 ORDER BY created_at DESC, hash LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![account, limit], payment_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Record `payment`, under way, or start it again after it failed.
pub(crate) fn put_payment(tx: &Transaction<'_>, payment: &Payment) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO bridge_payments (hash, account, connection, invoice, amount, reserved,
            state, preimage, failure, started_at, created_at, settled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', NULL, NULL, ?7, ?8, NULL)
         ON CONFLICT (hash) DO UPDATE SET account = ?2, connection = ?3, reserved = ?6,
            state = 'pending', preimage = NULL, failure = NULL, started_at = ?7,
            settled_at = NULL",
        params![
            payment.hash,
            payment.account,
            payment.connection,
            payment.invoice,
            sql(payment.amount)?,
            sql(payment.reserved)?,
            payment.started_at,
            payment.created_at,
        ],
    )?;
    Ok(())
}

/// Decide the payment of `hash`, under way, as `state`, at a cost of
/// `cost`: what it held beyond goes back to its account. False if it was
/// decided already.
pub(crate) fn decide_payment(
    tx: &Transaction<'_>,
    hash: &[u8; 32],
    state: State,
    cost: u64,
    preimage: Option<[u8; 32]>,
    failure: Option<&str>,
) -> Result<bool, Error> {
    let Some(payment) = payment(tx, hash)? else {
        return Ok(false);
    };
    if payment.state != State::Pending {
        return Ok(false);
    }
    let cost = cost.min(payment.reserved);
    let back = payment.reserved - cost;
    credit(tx, payment.account, sql(back)?)?;
    tx.execute(
        "UPDATE bridge_payments SET state = ?2, reserved = ?3, preimage = ?4, failure = ?5,
            settled_at = ?6 WHERE hash = ?1",
        params![
            hash,
            state_name(state),
            sql(cost)?,
            preimage,
            failure,
            licash_store::now()
        ],
    )?;
    Ok(true)
}

#[derive(Clone, Debug)]
pub(crate) struct Receipt {
    pub hash: [u8; 32],
    pub account: i64,
    pub connection: Option<[u8; 32]>,
    pub invoice: String,
    pub amount: u64,
    pub credits: u64,
    pub description: Option<String>,
    pub description_hash: Option<[u8; 32]>,
    pub zap: Option<String>,
    pub state: State,
    pub created_at: i64,
    pub expires_at: i64,
    pub settled_at: Option<i64>,
}

const RECEIPT: &str = "SELECT hash, account, connection, invoice, amount, credits,
    description, description_hash, zap, state, created_at, expires_at, settled_at
    FROM bridge_invoices";

fn receipt_row(r: &Row<'_>) -> rusqlite::Result<Receipt> {
    Ok(Receipt {
        hash: r.get(0)?,
        account: r.get(1)?,
        connection: r.get(2)?,
        invoice: r.get(3)?,
        amount: r.get::<_, i64>(4)? as u64,
        credits: r.get::<_, i64>(5)? as u64,
        description: r.get(6)?,
        description_hash: r.get(7)?,
        zap: r.get(8)?,
        state: state_of(&r.get::<_, String>(9)?),
        created_at: r.get(10)?,
        expires_at: r.get(11)?,
        settled_at: r.get(12)?,
    })
}

pub(crate) fn receipt(c: &Connection, hash: &[u8; 32]) -> Result<Option<Receipt>, Error> {
    Ok(
        c.query_row(&format!("{RECEIPT} WHERE hash = ?1"), [hash], receipt_row)
            .optional()?,
    )
}

pub(crate) fn pending_receipts(c: &Connection) -> Result<Vec<Receipt>, Error> {
    let mut stmt = c.prepare(&format!(
        "{RECEIPT} WHERE state = 'pending' ORDER BY created_at"
    ))?;
    let rows = stmt.query_map([], receipt_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub(crate) fn receipts_of(c: &Connection, account: i64, limit: u32) -> Result<Vec<Receipt>, Error> {
    let mut stmt = c.prepare(&format!(
        "{RECEIPT} WHERE account = ?1 ORDER BY created_at DESC, hash LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![account, limit], receipt_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The invoices paid by a zap request whose receipt is not published yet.
pub(crate) fn zaps_due(c: &Connection) -> Result<Vec<Receipt>, Error> {
    let mut stmt = c.prepare(&format!(
        "{RECEIPT} WHERE state = 'settled' AND zap IS NOT NULL AND zap_sent_at IS NULL
         ORDER BY settled_at"
    ))?;
    let rows = stmt.query_map([], receipt_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The receipt of the zap paying the invoice of `hash` published, or
/// given up on.
pub(crate) fn zap_sent(tx: &Transaction<'_>, hash: &[u8; 32]) -> Result<(), Error> {
    tx.execute(
        "UPDATE bridge_invoices SET zap_sent_at = ?2 WHERE hash = ?1",
        params![hash, licash_store::now()],
    )?;
    Ok(())
}

/// What the invoices of account `id` still open would credit it.
pub(crate) fn incoming(c: &Connection, id: i64) -> Result<u64, Error> {
    let incoming: i64 = c.query_row(
        "SELECT COALESCE(SUM(credits), 0) FROM bridge_invoices
         WHERE account = ?1 AND state = 'pending'",
        [id],
        |r| r.get(0),
    )?;
    Ok(incoming as u64)
}

pub(crate) fn insert_receipt(tx: &Transaction<'_>, receipt: &Receipt) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO bridge_invoices (hash, account, connection, invoice, amount, credits,
            description, description_hash, zap, state, created_at, expires_at, settled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10, ?11, NULL)",
        params![
            receipt.hash,
            receipt.account,
            receipt.connection,
            receipt.invoice,
            sql(receipt.amount)?,
            sql(receipt.credits)?,
            receipt.description,
            receipt.description_hash,
            receipt.zap,
            receipt.created_at,
            receipt.expires_at,
        ],
    )?;
    Ok(())
}

/// Decide the invoice of `hash`, open: settled, crediting its account
/// `credits`, or expired. False if it was decided already.
pub(crate) fn decide_receipt(
    tx: &Transaction<'_>,
    hash: &[u8; 32],
    settled: Option<u64>,
) -> Result<bool, Error> {
    let Some(receipt) = receipt(tx, hash)? else {
        return Ok(false);
    };
    if receipt.state != State::Pending {
        return Ok(false);
    }
    let state = match settled {
        Some(credits) => {
            credit(tx, receipt.account, sql(credits)?)?;
            tx.execute(
                "UPDATE bridge_invoices SET credits = ?2 WHERE hash = ?1",
                params![hash, sql(credits)?],
            )?;
            State::Settled
        }
        None => State::Expired,
    };
    tx.execute(
        "UPDATE bridge_invoices SET state = ?2, settled_at = ?3 WHERE hash = ?1",
        params![hash, state_name(state), licash_store::now()],
    )?;
    Ok(true)
}
