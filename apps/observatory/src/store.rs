//! What the observatory saw, in `observatory.sqlite`: the services it
//! watches, each probe of them, the terms they advertised as they changed,
//! and the actions its wallet took between them.
//!
//! The wallet's own tables are in another file (`wallet.sqlite`), owned by
//! the wallet SDK: this one holds only measurements, and losing it loses
//! history, never money.

use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{bail, Context};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

/// The schema this version writes. A file of a later one is refused. It is
/// bumped only when an older binary could misread or miswrite a file: a
/// nullable column added at the end is invisible to one that names its
/// columns, so it is ensured at open instead (see `ensure_columns`), and an
/// older image still opens the file after a rollback.
const VERSION: i64 = 1;

/// The most versions of a service's terms kept ([`Store::prune`]).
pub const TERMS_KEPT: i64 = 16;

const SCHEMA: &str = "
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
    detail TEXT,
    -- How long its swap took, in ms, where that is less than all of it:
    -- a move on Bitcoin leaves out the waits for blocks.
    swapped INTEGER
);
CREATE INDEX actions_started ON actions (started);
";

/// What a service is to the observatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Hub,
    Provider,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Hub => "hub",
            Role::Provider => "provider",
        }
    }

    fn parse(s: &str) -> Self {
        if s == "provider" {
            Role::Provider
        } else {
            Role::Hub
        }
    }
}

/// A service watched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    /// Its Nostr key if announced, else its URL.
    pub id: String,
    pub role: Role,
    pub key: Option<String>,
    pub name: Option<String>,
    pub urls: Vec<String>,
    /// Milliseconds since the epoch.
    pub first_seen: i64,
    pub last_seen: i64,
}

/// One probe of one of a service's URLs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub at: i64,
    pub service: String,
    pub url: String,
    pub ok: bool,
    /// Opening a connection: over Tor, a circuit, the stream and TLS.
    pub open_ms: Option<u32>,
    /// A round trip on the open connection: its `/health`.
    pub rtt_ms: Option<u32>,
    /// Its info, on the same connection.
    pub info_ms: Option<u32>,
    pub error: Option<String>,
}

/// How an action ended, or that it has not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Running,
    Done,
    Failed,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Running => "running",
            Outcome::Done => "done",
            Outcome::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "done" => Outcome::Done,
            "failed" => Outcome::Failed,
            _ => Outcome::Running,
        }
    }
}

/// An action of the wallet's, measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    pub id: i64,
    /// What was done: see `mover::Kind`.
    pub kind: String,
    pub started: i64,
    pub ended: Option<i64>,
    /// The service ids it went from, to and through.
    pub source: Option<String>,
    pub target: Option<String>,
    pub via: Option<String>,
    pub amount: u64,
    /// What it was quoted to cost, before.
    pub quoted: Option<u64>,
    /// What it cost: what the wallet held less after it.
    pub cost: Option<u64>,
    pub outcome: Outcome,
    /// Why it failed, in a line.
    pub detail: Option<String>,
    /// How long its swap took in ms, where that is not all of it: a move on
    /// Bitcoin counts its provider's part, not the waits for blocks. None
    /// where it was not timed, as in a move made before this was recorded.
    pub swapped: Option<u64>,
}

/// The observatory's file, one connection shared.
pub struct Store {
    db: Mutex<Connection>,
}

impl Store {
    /// The file at `path`, created if missing. A file of a later version
    /// is refused rather than read.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Connection::open(path).with_context(|| format!("{}", path.display()))?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match version {
            0 => {
                let tx = db.unchecked_transaction()?;
                tx.execute_batch(SCHEMA)?;
                tx.pragma_update(None, "user_version", VERSION)?;
                tx.commit()?;
            }
            VERSION => {}
            later => bail!(
                "{}: written by a later version of the observatory ({later})",
                path.display()
            ),
        }
        ensure_columns(&db)?;
        Ok(Self { db: Mutex::new(db) })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record `service` as seen at `at`: its name, key and URLs replaced,
    /// first seen kept.
    pub fn seen(&self, service: &Service) -> anyhow::Result<()> {
        let urls = serde_json::to_string(&service.urls)?;
        self.db().execute(
            "INSERT INTO services (id, role, key, name, urls, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT (id) DO UPDATE SET role = ?2, key = ?3, name = ?4, urls = ?5,
                 last_seen = max(last_seen, ?6)",
            params![
                service.id,
                service.role.name(),
                service.key,
                service.name,
                urls,
                service.last_seen
            ],
        )?;
        Ok(())
    }

    /// Every service ever seen.
    pub fn services(&self) -> anyhow::Result<Vec<Service>> {
        let db = self.db();
        let mut query = db.prepare(
            "SELECT id, role, key, name, urls, first_seen, last_seen FROM services ORDER BY id",
        )?;
        let rows = query.query_map([], |r| {
            let urls: String = r.get(4)?;
            Ok(Service {
                id: r.get(0)?,
                role: Role::parse(&r.get::<_, String>(1)?),
                key: r.get(2)?,
                name: r.get(3)?,
                urls: serde_json::from_str(&urls).unwrap_or_default(),
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn probed(&self, probe: &Probe) -> anyhow::Result<()> {
        self.db().execute(
            "INSERT INTO probes (at, service, url, ok, open_ms, rtt_ms, info_ms, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                probe.at,
                probe.service,
                probe.url,
                probe.ok,
                probe.open_ms,
                probe.rtt_ms,
                probe.info_ms,
                probe.error
            ],
        )?;
        Ok(())
    }

    /// The services a probe found answering as themselves since `since`,
    /// by id: when one last did.
    pub fn answered_since(
        &self,
        since: i64,
    ) -> anyhow::Result<std::collections::HashMap<String, i64>> {
        let db = self.db();
        let mut query = db.prepare(
            "SELECT service, max(at) FROM probes WHERE at >= ?1 AND ok GROUP BY service",
        )?;
        let rows = query.query_map([since], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Forget the services announced, last seen before `before`, that
    /// never answered as themselves: how many.
    pub fn forget_unanswered(&self, before: i64) -> anyhow::Result<usize> {
        forget_unanswered(&self.db(), before)
    }

    /// The probes since `since`, oldest first.
    pub fn probes_since(&self, since: i64) -> anyhow::Result<Vec<Probe>> {
        let db = self.db();
        let mut query = db.prepare(
            "SELECT at, service, url, ok, open_ms, rtt_ms, info_ms, error
             FROM probes WHERE at >= ?1 ORDER BY at",
        )?;
        let rows = query.query_map([since], |r| {
            Ok(Probe {
                at: r.get(0)?,
                service: r.get(1)?,
                url: r.get(2)?,
                ok: r.get(3)?,
                open_ms: r.get(4)?,
                rtt_ms: r.get(5)?,
                info_ms: r.get(6)?,
                error: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Record the info `service` answered at `at`, unless it is what it
    /// answered last.
    pub fn terms_seen(&self, service: &str, at: i64, info: &str) -> anyhow::Result<()> {
        let db = self.db();
        let last: Option<String> = db
            .query_row(
                "SELECT info FROM terms WHERE service = ?1 ORDER BY at DESC LIMIT 1",
                [service],
                |r| r.get(0),
            )
            .optional()?;
        if last.as_deref() != Some(info) {
            db.execute(
                "INSERT OR REPLACE INTO terms (service, at, info) VALUES (?1, ?2, ?3)",
                params![service, at, info],
            )?;
        }
        Ok(())
    }

    /// The last info of each service that answered one: its id, when, and
    /// the info's JSON.
    pub fn latest_terms(&self) -> anyhow::Result<Vec<(String, i64, String)>> {
        let db = self.db();
        let mut query = db.prepare(
            "SELECT t.service, t.at, t.info FROM terms t
             JOIN (SELECT service, max(at) AS at FROM terms GROUP BY service) l
             ON t.service = l.service AND t.at = l.at",
        )?;
        let rows = query.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Record an action starting: its id.
    pub fn action_started(&self, action: &Action) -> anyhow::Result<i64> {
        let db = self.db();
        db.execute(
            "INSERT INTO actions (kind, started, source, target, via, amount, quoted, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'running')",
            params![
                action.kind,
                action.started,
                action.source,
                action.target,
                action.via,
                sql(action.amount),
                action.quoted.map(sql)
            ],
        )?;
        Ok(db.last_insert_rowid())
    }

    /// Record how the action `id` ended.
    pub fn action_ended(
        &self,
        id: i64,
        ended: i64,
        outcome: Outcome,
        cost: Option<u64>,
        detail: Option<&str>,
        swapped: Option<u64>,
    ) -> anyhow::Result<()> {
        self.db().execute(
            "UPDATE actions SET ended = ?2, outcome = ?3, cost = ?4, detail = ?5, swapped = ?6
             WHERE id = ?1",
            params![
                id,
                ended,
                outcome.name(),
                cost.map(sql),
                detail,
                swapped.map(sql)
            ],
        )?;
        Ok(())
    }

    /// Actions left running by a process that stopped: failed, as
    /// interrupted. Their cost is not known.
    pub fn interrupted(&self, now: i64) -> anyhow::Result<usize> {
        Ok(self.db().execute(
            "UPDATE actions SET ended = ?1, outcome = 'failed', detail = 'interrupted'
             WHERE outcome = 'running'",
            [now],
        )?)
    }

    /// The actions started since `since`, oldest first.
    pub fn actions_since(&self, since: i64) -> anyhow::Result<Vec<Action>> {
        let db = self.db();
        let mut query = db.prepare(
            "SELECT id, kind, started, ended, source, target, via, amount, quoted, cost,
                    outcome, detail, swapped
             FROM actions WHERE started >= ?1 ORDER BY started",
        )?;
        let rows = query.query_map([since], |r| {
            Ok(Action {
                id: r.get(0)?,
                kind: r.get(1)?,
                started: r.get(2)?,
                ended: r.get(3)?,
                source: r.get(4)?,
                target: r.get(5)?,
                via: r.get(6)?,
                amount: nat(r.get(7)?),
                quoted: r.get::<_, Option<i64>>(8)?.map(nat),
                cost: r.get::<_, Option<i64>>(9)?.map(nat),
                outcome: Outcome::parse(&r.get::<_, String>(10)?),
                detail: r.get(11)?,
                swapped: r.get::<_, Option<i64>>(12)?.map(nat),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Forget probes, and terms other than each service's last, older than
    /// `before`, but the last [`TERMS_KEPT`] of each, and the services
    /// announced, last seen before it, with their probes and terms, whether
    /// they answered or not: announcing is free, and so is answering as the
    /// key that announced, so they would only pile up. Those configured are
    /// kept. Actions are kept: they are few, and the budget reads them.
    pub fn prune(&self, before: i64) -> anyhow::Result<()> {
        let db = self.db();
        db.execute("DELETE FROM probes WHERE at < ?1", [before])?;
        const GONE: &str = "SELECT id FROM services WHERE key IS NOT NULL AND last_seen < ?1";
        let tx = db.unchecked_transaction()?;
        for table in ["probes WHERE service", "terms WHERE service"] {
            tx.execute(&format!("DELETE FROM {table} IN ({GONE})"), [before])?;
        }
        tx.execute(
            &format!("DELETE FROM services WHERE id IN ({GONE})"),
            [before],
        )?;
        tx.commit()?;
        db.execute(
            "DELETE FROM terms WHERE at < ?1 AND at < (
                 SELECT max(at) FROM terms t WHERE t.service = terms.service)",
            [before],
        )?;
        // Each service's latest terms alone are read: a few more kept,
        // however often they change.
        db.execute(
            "DELETE FROM terms WHERE rowid IN (
                 SELECT rowid FROM (
                     SELECT rowid, row_number() OVER (PARTITION BY service ORDER BY at DESC) AS n
                     FROM terms)
                 WHERE n > ?1)",
            [TERMS_KEPT],
        )?;
        Ok(())
    }
}

/// [`Store::forget_unanswered`], on `db`: their failed probes with them.
fn forget_unanswered(db: &Connection, before: i64) -> anyhow::Result<usize> {
    const FORGOTTEN: &str = "SELECT id FROM services WHERE key IS NOT NULL
        AND last_seen < ?1 AND id NOT IN (SELECT service FROM terms)";
    let tx = db.unchecked_transaction()?;
    let probes = format!("DELETE FROM probes WHERE service IN ({FORGOTTEN})");
    tx.execute(&probes, [before])?;
    let services = format!("DELETE FROM services WHERE id IN ({FORGOTTEN})");
    let forgotten = tx.execute(&services, [before])?;
    tx.commit()?;
    Ok(forgotten)
}

/// Columns added since the first version, each nullable and at the end of
/// its table: added to a file written before it, once. Taking the write
/// lock first means that of two processes opening the file, the second finds
/// the column made, rather than failing to make it again.
fn ensure_columns(db: &Connection) -> anyhow::Result<()> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let has: i64 = tx.query_row(
        "SELECT count(*) FROM pragma_table_info('actions') WHERE name = 'swapped'",
        [],
        |r| r.get(0),
    )?;
    if has == 0 {
        tx.execute_batch("ALTER TABLE actions ADD COLUMN swapped INTEGER")?;
    }
    tx.commit()?;
    Ok(())
}

fn sql(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn nat(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

/// Milliseconds since the epoch, now.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}
