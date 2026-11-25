//! The hub's openings, the component `openings` of `hub.sqlite`: each as
//! its machine stored itself at its last step, the digest of the holder's
//! message that step took, and the hub's own coins F spends, which its node
//! keeps locked while the opening lives.
//!
//! The tables are made with the first opening; reading finds none before.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{OutPoint, Transaction, TxOut};
use licash_api::Fees;
use licash_store::Kind;
use rusqlite::{params, Connection, OptionalExtension};

/// The format of the rows: a machine's stored bytes, of
/// `licash_contract`'s format 3. Older rows are retained, not reinterpreted:
/// no exit of theirs is played.
pub(super) const FORMAT: i64 = 4;

/// The component the openings' tables are, and its version.
const COMPONENT: &str = "openings";
const VERSION: i64 = 1;

/// A stage an opening reaches is a table of its own, one row of it a fact.
const SCHEMA: &str = "
-- Each opening. `fees` is what the hub charged as it started, as JSON, the
-- most its holder agreed to pay: for the operator to know whom fees raised
-- since leave to agree again. Nothing is done by it. None where the hub was
-- told not to charge.
CREATE TABLE openings (
    id BLOB PRIMARY KEY,
    format INTEGER NOT NULL,
    phase INTEGER NOT NULL,
    mock INTEGER NOT NULL CHECK (mock IN (0, 1)),
    irrevocable INTEGER NOT NULL CHECK (irrevocable IN (0, 1)),
    deposit BLOB NOT NULL,
    coins BLOB NOT NULL,
    last BLOB NOT NULL,
    state BLOB NOT NULL,
    abandoned INTEGER NOT NULL DEFAULT 0 CHECK (abandoned IN (0, 1)),
    fees TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX openings_deposit ON openings (deposit) WHERE abandoned = 0;

-- Each coin its wallet funded to pay a terminal's fee (opening, terminal),
-- made once: another made after a restart would be lost to the hub, as only
-- that terminal spends it.
CREATE TABLE opening_fee_coins (
    id BLOB NOT NULL REFERENCES openings (id),
    name TEXT NOT NULL,
    outpoint BLOB NOT NULL,
    output BLOB NOT NULL,
    PRIMARY KEY (id, name)
) STRICT;
-- The fee child of each link last made, kept before it is broadcast.
CREATE TABLE opening_children (
    id BLOB NOT NULL REFERENCES openings (id),
    name TEXT NOT NULL,
    tx BLOB NOT NULL,
    PRIMARY KEY (id, name)
) STRICT;
-- The contracts whose exit or default left nothing of the hub's to play,
-- deep enough not to look again.
CREATE TABLE opening_ended (
    id BLOB PRIMARY KEY REFERENCES openings (id),
    height INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
-- The signed openings whose F the responder saw in no block, and the block
-- it first did: given up once F can never confirm, and made so by the hub
-- some blocks after.
CREATE TABLE opening_unfunded (
    id BLOB PRIMARY KEY REFERENCES openings (id),
    height INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
-- Each answer of a one-time key (opening, `respond` or `assert`) the hub
-- was about to sign, or had signed: kept once what it answers on is pinned
-- in `response_pins`, and before it signs ([`Store::begin_signing`]). One
-- with nothing pinned there any more tells those rows were lost, or
-- restored older than these: an answer decided anew could differ from the
-- one signed.
CREATE TABLE opening_signing (
    id BLOB NOT NULL REFERENCES openings (id),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (id, name)
) STRICT;
";

/// The hub's connection to the openings' tables, read only, in the hub's
/// data directory `data`: none if the hub has no database there or never
/// stored an opening.
fn reader(data: &Path) -> Result<Option<Connection>> {
    let Some(c) = licash_store::inspect(&crate::hub_db(data), Kind::Hub)? else {
        return Ok(None);
    };
    match licash_store::component_version(&c, COMPONENT)? {
        Some(VERSION) => Ok(Some(c)),
        Some(v) => bail!("the openings are of version {v}, newer than this hub knows"),
        None => Ok(None),
    }
}

/// The name of extra fee coin `n` of transaction `name`, beside the first
/// kept under `name` itself.
fn extra_coin(name: &str, n: &str) -> String {
    format!("{name}/{n}")
}

/// An opening as stored.
pub(super) struct Row {
    pub state: Vec<u8>,
    /// The digest of the holder's message its last step took.
    pub last: [u8; 32],
    pub abandoned: bool,
}

/// An opening as stored, for the hub's operator ([`Store::listed`]).
pub(super) struct Listed {
    pub id: [u8; 32],
    pub format: i64,
    pub phase: u8,
    pub mock: bool,
    pub irrevocable: bool,
    pub abandoned: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub state: Vec<u8>,
}

/// The openings, and what the hub charges, if told
/// ([`Store::charging`]): kept with each that starts.
pub(super) struct Store(Connection, Option<Fees>, PathBuf);

/// Every opening, as [`Store::listed`] reads them: unsorted, as sorting
/// their states in SQLite spills them to a temporary file, past what a
/// small `/tmp` holds ("database or disk is full").
const LISTED: &str =
    "SELECT id, format, phase, mock, irrevocable, abandoned, created_at, updated_at, state, rowid
     FROM openings";

impl Store {
    /// How many openings in `dir` the hub signed and did not give up,
    /// read only: none if no opening was ever stored there.
    pub fn signed(dir: &Path) -> Result<u64> {
        let Some(c) = reader(dir)? else {
            return Ok(0);
        };
        let n: i64 = c.query_row(
            "SELECT count(*) FROM openings WHERE irrevocable = 1 AND abandoned = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    /// Every opening in `dir`, oldest first, read only: none if no
    /// opening was ever stored there.
    pub fn listed(dir: &Path) -> Result<Vec<Listed>> {
        let Some(c) = reader(dir)? else {
            return Ok(Vec::new());
        };
        let mut stmt = c.prepare(LISTED)?;
        let rows = stmt.query_map([], |r| {
            let at: (i64, i64) = (r.get(6)?, r.get(9)?);
            let listed = Listed {
                id: r.get(0)?,
                format: r.get(1)?,
                phase: r.get(2)?,
                mock: r.get(3)?,
                irrevocable: r.get(4)?,
                abandoned: r.get(5)?,
                created_at: r.get(6)?,
                updated_at: r.get(7)?,
                state: r.get(8)?,
            };
            Ok((at, listed))
        })?;
        let mut rows = rows.collect::<Result<Vec<_>, _>>()?;
        // Oldest first, sorted here, in memory with them all.
        rows.sort_by_key(|(at, _)| *at);
        Ok(rows.into_iter().map(|(_, listed)| listed).collect())
    }

    /// The openings in the hub's data directory `dir`, made if none were.
    pub fn open(dir: &Path) -> Result<Self> {
        let mut c = licash_store::open(&crate::hub_db(dir), Kind::Hub)?;
        licash_store::component(&mut c, COMPONENT, VERSION, SCHEMA)?;
        Ok(Self(c, None, dir.to_path_buf()))
    }

    /// Persist an already-validated kept instance before saving the machine
    /// state that names it. No artifact is removed automatically.
    pub fn keep(&self, id: &[u8; 32], i: u32, bytes: &[u8]) -> Result<()> {
        ensure!(i > 0, "instances are numbered from one");
        let root = self.2.join("opening-instances");
        let dir = root.join(crate::hex_id(id));
        for directory in [&root, &dir] {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            match builder.create(directory) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
                Err(e) => return Err(e).with_context(|| directory.display().to_string()),
            }
            // A retry may have created this directory before interruption.
            std::fs::File::open(directory.parent().context("artifact parent")?)?.sync_all()?;
        }
        let path = dir.join(i.to_string());
        if path.exists() {
            ensure!(
                std::fs::read(&path)? == bytes,
                "a different instance is already stored"
            );
            std::fs::File::open(&path)?.sync_all()?;
            std::fs::File::open(&dir)?.sync_all()?;
            return Ok(());
        }
        let aside = dir.join(format!(
            ".{i}.{}.new",
            hex::encode(licash::base::Base::fresh_nonce())
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&aside)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&aside, &path)?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    }

    pub fn kept_instance(&self, id: &[u8; 32], i: u32) -> Result<Vec<u8>> {
        ensure!(i > 0, "instances are numbered from one");
        let path = self.instance_path(id, i);
        std::fs::read(&path).with_context(|| path.display().to_string())
    }

    /// Of the kept instances `kept` of opening `id`, those whose files are
    /// not in the data directory, as of one restored without them: the
    /// hub answers no challenge of its assertion with those.
    pub fn missing_instances(&self, id: &[u8; 32], kept: &[u32]) -> Vec<u32> {
        (kept.iter().copied())
            .filter(|&i| i == 0 || !self.instance_path(id, i).is_file())
            .collect()
    }

    fn instance_path(&self, id: &[u8; 32], i: u32) -> PathBuf {
        (self.2.join("opening-instances"))
            .join(crate::hex_id(id))
            .join(i.to_string())
    }

    /// Keep `fees`, what the hub charges, with each opening that starts
    /// from now on.
    pub fn charging(&mut self, fees: Fees) {
        self.1 = Some(fees);
    }

    /// What the hub charged as each opening in `dir` it signed and did
    /// not give up started, read only: none of one that started with the
    /// hub told not to charge, nor of one whose own cannot be read.
    pub fn charged(dir: &Path) -> Result<Vec<Fees>> {
        let Some(c) = reader(dir)? else {
            return Ok(Vec::new());
        };
        let mut stmt = c.prepare(
            "SELECT fees FROM openings
             WHERE fees IS NOT NULL AND irrevocable = 1 AND abandoned = 0",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut all = Vec::new();
        for text in rows {
            if let Ok(fees) = serde_json::from_str(&text?) {
                all.push(fees);
            }
        }
        Ok(all)
    }

    pub fn row(&self, id: &[u8; 32]) -> Result<Option<Row>> {
        row(&self.0, id)
    }

    /// The signed openings not given up nor ended, of this format: those
    /// whose exit the hub plays.
    pub fn signed_ids(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.0.prepare(
            "SELECT id FROM openings WHERE irrevocable = 1 AND abandoned = 0 AND format = ?1
             AND id NOT IN (SELECT id FROM opening_ended) ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([FORMAT], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The states of the openings but `except` the hub committed to and
    /// may yet have to prove an exit of: funded or signed, of this format,
    /// not the mock authority's, not given up nor ended.
    pub fn committed(&self, except: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self.0.prepare(
            "SELECT state FROM openings
             WHERE (irrevocable = 1 OR length(coins) > 0) AND abandoned = 0 AND mock = 0
               AND format = ?1 AND id != ?2 AND id NOT IN (SELECT id FROM opening_ended)",
        )?;
        let rows = stmt.query_map(params![FORMAT, except], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Opening `id`'s contract ended at block `height`: nothing of the
    /// hub's left in it to play.
    pub fn end(&self, id: &[u8; 32], height: u32) -> Result<()> {
        self.0.execute(
            "INSERT INTO opening_ended (id, height, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![id, height, crate::now()],
        )?;
        Ok(())
    }

    /// The fee coin kept for terminal `name` of opening `id`, if one was.
    pub fn fee_coin(&self, id: &[u8; 32], name: &str) -> Result<Option<(OutPoint, TxOut)>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .0
            .query_row(
                "SELECT outpoint, output FROM opening_fee_coins WHERE id = ?1 AND name = ?2",
                params![id, name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(op, out)| Ok((deserialize(&op)?, deserialize(&out)?)))
            .transpose()
    }

    /// Keep `coin` as terminal `name`'s fee coin of opening `id`, unless
    /// one was kept: the one kept.
    pub fn keep_fee_coin(
        &self,
        id: &[u8; 32],
        name: &str,
        coin: &(OutPoint, TxOut),
    ) -> Result<(OutPoint, TxOut)> {
        self.0.execute(
            "INSERT INTO opening_fee_coins (id, name, outpoint, output) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO NOTHING",
            params![id, name, serialize(&coin.0), serialize(&coin.1)],
        )?;
        self.fee_coin(id, name)?.context("no fee coin kept")
    }

    /// Keep `new` as terminal `name`'s fee coin of opening `id` in place of
    /// `old`, gone from the chain and the mempool: the one kept, `old`'s
    /// unless that was replaced already. `old` is kept on as an extra coin
    /// ([`Store::extra_coins`]), in one transaction: should its funding
    /// confirm after all, it is the hub's still.
    pub fn replace_fee_coin(
        &self,
        id: &[u8; 32],
        name: &str,
        old: &(OutPoint, TxOut),
        new: &(OutPoint, TxOut),
    ) -> Result<(OutPoint, TxOut)> {
        let tx = self.0.unchecked_transaction()?;
        let replaced = tx.execute(
            "UPDATE opening_fee_coins SET outpoint = ?3, output = ?4
             WHERE id = ?1 AND name = ?2 AND outpoint = ?5",
            params![
                id,
                name,
                serialize(&new.0),
                serialize(&new.1),
                serialize(&old.0)
            ],
        )?;
        if replaced == 1 {
            self.keep_extra_coin(id, name, old)?;
        }
        tx.commit()?;
        self.fee_coin(id, name)?.context("no fee coin kept")
    }

    /// How many fee coins are kept for transaction `name` of opening `id`:
    /// its first and its extra ones. Each kept adds one, so that each
    /// funded is of a count of its own ([`super::Openings`]'s tags).
    pub fn fee_coins_kept(&self, id: &[u8; 32], name: &str) -> Result<usize> {
        let first = self.fee_coin(id, name)?.is_some();
        Ok(usize::from(first) + self.extra_coins(id, name)?.len())
    }

    /// The extra fee coins kept for transaction `name` of opening `id`, in
    /// the order kept ([`Store::keep_extra_coin`]): a link's child's, or a
    /// terminal's larger ones.
    pub fn extra_coins(&self, id: &[u8; 32], name: &str) -> Result<Vec<(OutPoint, TxOut)>> {
        let mut stmt = self.0.prepare(
            "SELECT outpoint, output FROM opening_fee_coins
             WHERE id = ?1 AND substr(name, 1, length(?2)) = ?2 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![id, extra_coin(name, "")], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (op, out) = row?;
            Ok((deserialize(&op)?, deserialize(&out)?))
        })
        .collect()
    }

    /// Keep `coin` as one more extra fee coin of transaction `name`: the
    /// extra coins kept for it, `coin` last.
    pub fn keep_extra_coin(
        &self,
        id: &[u8; 32],
        name: &str,
        coin: &(OutPoint, TxOut),
    ) -> Result<Vec<(OutPoint, TxOut)>> {
        let n = self.extra_coins(id, name)?.len();
        self.keep_fee_coin(id, &extra_coin(name, &n.to_string()), coin)?;
        self.extra_coins(id, name)
    }

    /// The fee child of link `name` of opening `id` last made, if any.
    pub fn child(&self, id: &[u8; 32], name: &str) -> Result<Option<Transaction>> {
        let tx: Option<Vec<u8>> = self
            .0
            .query_row(
                "SELECT tx FROM opening_children WHERE id = ?1 AND name = ?2",
                params![id, name],
                |r| r.get(0),
            )
            .optional()?;
        Ok(tx.map(|tx| deserialize(&tx)).transpose()?)
    }

    /// Keep `tx` as link `name`'s fee child, in place of the one before:
    /// kept before it is broadcast.
    pub fn keep_child(&self, id: &[u8; 32], name: &str, tx: &Transaction) -> Result<()> {
        self.0.execute(
            "INSERT INTO opening_children (id, name, tx) VALUES (?1, ?2, ?3)
             ON CONFLICT (id, name) DO UPDATE SET tx = excluded.tx",
            params![id, name, serialize(tx)],
        )?;
        Ok(())
    }

    /// The hub is about to sign answer `name` of opening `id` with its
    /// one-time key, or has: kept before it signs, once what it answers
    /// on is pinned in `response_pins`.
    pub fn begin_signing(&self, id: &[u8; 32], name: &str) -> Result<()> {
        self.0.execute(
            "INSERT INTO opening_signing (id, name, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![id, name, crate::now()],
        )?;
        Ok(())
    }

    /// Whether the hub never signed a contract's funding, nor began to sign
    /// an answer of a one-time key, of any format: what it may seal a new
    /// witness set on as its first ([`super::witness`]).
    pub fn never_signed(&self) -> Result<bool> {
        let signed: i64 = self.0.query_row(
            "SELECT (SELECT count(*) FROM openings WHERE irrevocable = 1)
                  + (SELECT count(*) FROM opening_signing)",
            [],
            |r| r.get(0),
        )?;
        Ok(signed == 0)
    }

    /// Every opening's id, of any format or phase, oldest first.
    pub fn all_ids(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .0
            .prepare("SELECT id FROM openings ORDER BY created_at, rowid")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Whether the hub was about to sign answer `name` of opening `id`, or
    /// had ([`Store::begin_signing`]).
    pub fn began_signing(&self, id: &[u8; 32], name: &str) -> Result<bool> {
        Ok(self
            .0
            .query_row(
                "SELECT 1 FROM opening_signing WHERE id = ?1 AND name = ?2",
                params![id, name],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// The block opening `id`'s F was first seen in no block at: `tip`,
    /// if it was not before. Its holder may refresh `updated_at` at will,
    /// by sending a message again: not this.
    pub fn unfunded(&self, id: &[u8; 32], tip: u32) -> Result<u32> {
        self.0.execute(
            "INSERT INTO opening_unfunded (id, height, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![id, tip, crate::now()],
        )?;
        Ok(self.0.query_row(
            "SELECT height FROM opening_unfunded WHERE id = ?1",
            [id],
            |r| r.get(0),
        )?)
    }

    /// Whether opening `id`'s F was seen in no block, and not since in one.
    pub fn was_unfunded(&self, id: &[u8; 32]) -> Result<bool> {
        Ok(self
            .0
            .query_row("SELECT 1 FROM opening_unfunded WHERE id = ?1", [id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .is_some())
    }

    /// Opening `id`'s F is in a block: its count of blocks unfunded over.
    pub fn funded(&self, id: &[u8; 32]) -> Result<()> {
        self.0
            .execute("DELETE FROM opening_unfunded WHERE id = ?1", [id])?;
        Ok(())
    }

    /// How many signed openings not given up have their F in no block, as
    /// the responder last saw.
    pub fn unfunded_count(&self) -> Result<usize> {
        Ok(self.0.query_row(
            "SELECT count(*) FROM opening_unfunded u JOIN openings o ON o.id = u.id
             WHERE o.abandoned = 0",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize)
    }

    /// Give up signed opening `id`, whose F can never confirm: its coins,
    /// to unlock, if it was not given up before. Its deposit is free for
    /// another opening. Never by [`Store::abandon`], which gives up only
    /// what the hub never signed.
    pub fn give_up_unfunded(&self, id: &[u8; 32]) -> Result<Option<Vec<OutPoint>>> {
        let coins: Option<Vec<u8>> = self
            .0
            .query_row(
                "UPDATE openings SET abandoned = 1, updated_at = ?2
                 WHERE id = ?1 AND abandoned = 0 AND irrevocable = 1
                 RETURNING coins",
                params![id, crate::now()],
                |r| r.get(0),
            )
            .optional()?;
        coins.map(|coins| outpoints(&coins)).transpose()
    }

    /// The signed openings not given up stored in another format, which
    /// this build neither reads nor plays.
    pub fn unreadable_signed(&self) -> Result<Vec<([u8; 32], i64)>> {
        let mut stmt = self.0.prepare(
            "SELECT id, format FROM openings WHERE irrevocable = 1 AND abandoned = 0 AND format != ?1
             ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([FORMAT], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// A new opening, of the holder's deposit `deposit`: false if another
    /// opening not given up spends it. What the hub charges, if told, is
    /// kept with it.
    pub fn insert(
        &self,
        id: &[u8; 32],
        phase: u8,
        mock: bool,
        deposit: &OutPoint,
        last: &[u8; 32],
        state: &[u8],
    ) -> Result<bool> {
        let now = crate::now();
        let fees = (self.1.as_ref().map(serde_json::to_string)).transpose()?;
        let inserted = self.0.execute(
            "INSERT INTO openings (id, format, phase, mock, irrevocable, deposit, coins, last,
                                   state, fees, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, x'', ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT DO NOTHING",
            params![
                id,
                FORMAT,
                phase,
                mock,
                serialize(deposit),
                last,
                state,
                fees,
                now
            ],
        )?;
        Ok(inserted == 1)
    }

    /// The opening `id` after a step taking the message of digest `last`:
    /// `irrevocable` once the hub signed F.
    pub fn save(
        &self,
        id: &[u8; 32],
        phase: u8,
        irrevocable: bool,
        last: &[u8; 32],
        state: &[u8],
    ) -> Result<()> {
        self.0.execute(
            "UPDATE openings SET phase = ?2, irrevocable = ?3, last = ?4, state = ?5,
                                 updated_at = ?6
             WHERE id = ?1",
            params![id, phase, irrevocable, last, state, crate::now()],
        )?;
        Ok(())
    }

    /// The hub's own coins the F of opening `id` spends.
    pub fn set_coins(&self, id: &[u8; 32], coins: &[OutPoint]) -> Result<()> {
        let bytes: Vec<u8> = coins.iter().flat_map(serialize).collect();
        self.0.execute(
            "UPDATE openings SET coins = ?2 WHERE id = ?1",
            params![id, bytes],
        )?;
        Ok(())
    }

    /// How many openings are under way: not given up, the hub's
    /// signatures not given.
    pub fn under_way(&self) -> Result<usize> {
        Ok(self.0.query_row(
            "SELECT count(*) FROM openings WHERE abandoned = 0 AND irrevocable = 0",
            [],
            |r| r.get::<_, i64>(0),
        )? as usize)
    }

    /// Candidate openings untouched since `before`. Recheck when abandoning.
    pub fn stale(&self, before: i64) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.0.prepare(
            "SELECT id FROM openings
             WHERE abandoned = 0 AND irrevocable = 0 AND updated_at < ?1",
        )?;
        let rows = stmt.query_map([before], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Give up a still-idle, unsigned opening and return only its current
    /// coins. A stale selection never authorizes unlocking a signed row.
    pub fn abandon(&self, id: &[u8; 32], before: i64) -> Result<Option<Vec<OutPoint>>> {
        let coins: Option<Vec<u8>> = self
            .0
            .query_row(
                "UPDATE openings SET abandoned = 1, updated_at = ?2
             WHERE id = ?1 AND abandoned = 0 AND irrevocable = 0 AND updated_at < ?3
             RETURNING coins",
                params![id, crate::now(), before],
                |r| r.get(0),
            )
            .optional()?;
        coins.map(|coins| outpoints(&coins)).transpose()
    }

    /// The coins of the openings not given up: locked in the hub's node.
    pub fn locked(&self) -> Result<Vec<OutPoint>> {
        let mut stmt = self
            .0
            .prepare("SELECT coins FROM openings WHERE abandoned = 0")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut all = Vec::new();
        for coins in rows {
            all.extend(outpoints(&coins?)?);
        }
        Ok(all)
    }
}

fn row(c: &Connection, id: &[u8; 32]) -> Result<Option<Row>> {
    let row = c
        .query_row(
            "SELECT format, state, last, abandoned FROM openings WHERE id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    Row {
                        state: r.get(1)?,
                        last: r.get(2)?,
                        abandoned: r.get(3)?,
                    },
                ))
            },
        )
        .optional()?;
    match row {
        Some((FORMAT, row)) => Ok(Some(row)),
        Some((format, _)) => bail!("an opening stored in format {format}, unknown"),
        None => Ok(None),
    }
}

fn outpoints(bytes: &[u8]) -> Result<Vec<OutPoint>> {
    bytes.chunks(36).map(|c| Ok(deserialize(c)?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fee_coin_is_kept_once_and_an_ended_contract_is_played_no_more() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        let deposit = |n| OutPoint {
            txid: bitcoin::hashes::Hash::from_byte_array([n; 32]),
            vout: 0,
        };
        for n in [1, 2] {
            ensure!(store.insert(&[n; 32], 0, true, &deposit(n), &[0; 32], b"state")?);
            store.save(&[n; 32], 0, true, &[0; 32], b"state")?;
        }
        let coin = |n| {
            (
                deposit(n),
                TxOut {
                    value: bitcoin::Amount::from_sat(330),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x20, n]),
                },
            )
        };
        ensure!(store.fee_coin(&[1; 32], "default")?.is_none());
        ensure!(store.keep_fee_coin(&[1; 32], "default", &coin(7))? == coin(7));
        // Another made after a restart: the first one kept is paid with.
        ensure!(store.keep_fee_coin(&[1; 32], "default", &coin(8))? == coin(7));
        ensure!(store.keep_fee_coin(&[1; 32], "success", &coin(8))? == coin(8));
        // One gone, replaced: once, in place of the one gone only.
        ensure!(store.replace_fee_coin(&[1; 32], "success", &coin(7), &coin(9))? == coin(8));
        ensure!(store.replace_fee_coin(&[1; 32], "success", &coin(8), &coin(9))? == coin(9));
        ensure!(store.replace_fee_coin(&[1; 32], "success", &coin(8), &coin(10))? == coin(9));
        // The one gone kept on beside it, once: should it confirm after all.
        ensure!(store.extra_coins(&[1; 32], "success")? == vec![coin(8)]);
        ensure!(store.fee_coins_kept(&[1; 32], "success")? == 2);
        ensure!(store.fee_coins_kept(&[1; 32], "default")? == 1);
        ensure!(store.fee_coins_kept(&[1; 32], "reclaim")? == 0);
        ensure!(store.fee_coin(&[1; 32], "default")? == Some(coin(7)));
        store.end(&[1; 32], 100)?;
        store.end(&[1; 32], 101)?;
        drop(store);
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        ensure!(store.fee_coin(&[1; 32], "default")? == Some(coin(7)));
        ensure!(store.fee_coin(&[1; 32], "success")? == Some(coin(9)));
        ensure!(store.extra_coins(&[1; 32], "success")? == vec![coin(8)]);
        ensure!(store.signed_ids()? == vec![[2; 32]]);
        Ok(())
    }

    #[test]
    fn a_signed_opening_unfunded_counts_its_blocks_from_first_seen_and_is_given_up_once(
    ) -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        let outpoint = |n| OutPoint {
            txid: bitcoin::hashes::Hash::from_byte_array([n; 32]),
            vout: 0,
        };
        for n in [1, 2] {
            ensure!(store.insert(&[n; 32], 0, true, &outpoint(n), &[0; 32], b"state")?);
            store.save(&[n; 32], 0, true, &[0; 32], b"state")?;
            store.set_coins(&[n; 32], &[outpoint(10 + n)])?;
        }
        // Rows from before the table: nothing unfunded, nothing proved.
        ensure!(!store.was_unfunded(&[1; 32])? && store.unfunded_count()? == 0);
        store.funded(&[1; 32])?;
        ensure!(store.unfunded(&[1; 32], 100)? == 100);
        // Seen again later, or its holder's messages refreshing it: the
        // first block stays.
        store.save(&[1; 32], 0, true, &[1; 32], b"state")?;
        ensure!(store.unfunded(&[1; 32], 150)? == 100);
        ensure!(store.unfunded(&[2; 32], 120)? == 120);
        ensure!(store.unfunded_count()? == 2 && store.was_unfunded(&[2; 32])?);
        // Funded since: counted no more.
        store.funded(&[2; 32])?;
        ensure!(store.unfunded_count()? == 1 && !store.was_unfunded(&[2; 32])?);
        // Given up once, its coins unlocked once, played no more, and its
        // deposit free for another opening.
        ensure!(store.give_up_unfunded(&[1; 32])? == Some(vec![outpoint(11)]));
        ensure!(store.give_up_unfunded(&[1; 32])?.is_none());
        ensure!(store.unfunded_count()? == 0);
        ensure!(store.signed_ids()? == vec![[2; 32]]);
        ensure!(store.locked()? == vec![outpoint(12)]);
        ensure!(store.insert(&[3; 32], 0, true, &outpoint(1), &[0; 32], b"state")?);
        // Never what the idle sweep gives up.
        ensure!(store.abandon(&[2; 32], i64::MAX)?.is_none());
        Ok(())
    }

    #[test]
    fn extra_fee_coins_add_up_and_a_links_child_is_the_last_made() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        let id = [1; 32];
        let coin = |n: u8| {
            (
                OutPoint {
                    txid: bitcoin::hashes::Hash::from_byte_array([n; 32]),
                    vout: 1,
                },
                TxOut {
                    value: bitcoin::Amount::from_sat(1_000 * u64::from(n)),
                    script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51, 0x20, n]),
                },
            )
        };
        ensure!(store.insert(&id, 0, true, &coin(9).0, &[0; 32], b"state")?);
        ensure!(
            store.extra_coins(&id, "assert")?.is_empty() && store.child(&id, "assert")?.is_none()
        );
        // A terminal's coin is none of a link's.
        store.keep_fee_coin(&id, "assert_timeout", &coin(5))?;
        ensure!(store.keep_extra_coin(&id, "assert", &coin(1))? == vec![coin(1)]);
        ensure!(store.keep_extra_coin(&id, "assert", &coin(2))? == vec![coin(1), coin(2)]);
        ensure!(store.keep_extra_coin(&id, "respond", &coin(3))? == vec![coin(3)]);
        let tx = |n: u32| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(n),
            input: vec![],
            output: vec![],
        };
        store.keep_child(&id, "assert", &tx(1))?;
        store.keep_child(&id, "assert", &tx(2))?;
        drop(store);
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        ensure!(store.child(&id, "assert")? == Some(tx(2)));
        ensure!(store.child(&id, "respond")?.is_none());
        ensure!(store.extra_coins(&id, "assert")? == vec![coin(1), coin(2)]);
        ensure!(store.fee_coin(&id, "assert_timeout")? == Some(coin(5)));
        Ok(())
    }

    /// Each one-time answer the hub began signing is kept, apart from the
    /// other of its opening and across a restart.
    #[test]
    fn answers_begun_are_kept_apart_per_opening_and_across_a_restart() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        let deposit = |n| OutPoint {
            txid: bitcoin::hashes::Hash::from_byte_array([n; 32]),
            vout: 0,
        };
        let (id, other) = ([1; 32], [2; 32]);
        for id in [id, other] {
            ensure!(store.insert(&id, 0, true, &deposit(id[0]), &[0; 32], b"state")?);
        }
        store.end(&other, 100)?;
        ensure!(!store.began_signing(&id, "respond")?);

        store.begin_signing(&id, "respond")?;
        store.begin_signing(&id, "respond")?;
        ensure!(store.began_signing(&id, "respond")?);
        ensure!(!store.began_signing(&id, "assert")?);
        ensure!(!store.began_signing(&other, "respond")?);
        store.begin_signing(&id, "assert")?;
        drop(store);
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        ensure!(store.began_signing(&id, "respond")? && store.began_signing(&id, "assert")?);
        ensure!(!store.began_signing(&other, "assert")?);
        Ok(())
    }

    #[test]
    fn openings_are_listed_oldest_first_without_sorting_their_states_on_disk() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        let deposit = |n| OutPoint {
            txid: bitcoin::hashes::Hash::from_byte_array([n; 32]),
            vout: 0,
        };
        for n in [3, 1, 2] {
            ensure!(store.insert(&[n; 32], 0, true, &deposit(n), &[0; 32], b"state")?);
        }
        // The second made first, the first last; the third as made.
        let at = |n: u8, t: i64| {
            store.0.execute(
                "UPDATE openings SET created_at = ?2 WHERE id = ?1",
                params![[n; 32], t],
            )
        };
        at(1, 30)?;
        at(2, 10)?;
        at(3, 10)?;
        let listed = Store::listed(data.path())?;
        let ids: Vec<[u8; 32]> = listed.iter().map(|l| l.id).collect();
        ensure!(ids == [[3; 32], [2; 32], [1; 32]], "{ids:?}");
        // SQLite sorts none of it: no temporary B-tree, which large states
        // spill to a file in /tmp.
        let plan: Vec<String> = store
            .0
            .prepare(&format!("EXPLAIN QUERY PLAN {LISTED}"))?
            .query_map([], |r| r.get(3))?
            .collect::<rusqlite::Result<_>>()?;
        ensure!(plan.iter().all(|p| !p.contains("TEMP B-TREE")), "{plan:?}");
        Ok(())
    }

    #[test]
    fn uploaded_instances_are_durable_private_and_isolated() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        store.keep(&[1; 32], 1, b"first")?;
        store.keep(&[1; 32], 2, b"second")?;
        store.keep(&[2; 32], 1, b"another opening")?;
        store.keep(&[1; 32], 1, b"first")?;
        assert!(store.keep(&[1; 32], 1, b"different").is_err());
        assert!(store.keep(&[1; 32], 0, b"zero").is_err());
        drop(store);
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        assert_eq!(store.kept_instance(&[1; 32], 1)?, b"first");
        assert_eq!(store.kept_instance(&[1; 32], 2)?, b"second");
        assert_eq!(store.kept_instance(&[2; 32], 1)?, b"another opening");
        assert!(store.kept_instance(&[1; 32], 3).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let root = data.path().join("opening-instances");
            let dir = root.join(crate::hex_id(&[1; 32]));
            assert_eq!(
                std::fs::metadata(&root)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(std::fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
            assert_eq!(
                std::fs::metadata(dir.join("1"))?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn partial_artifacts_are_not_state_and_are_not_removed() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        store.keep(&[1; 32], 1, b"complete")?;
        let dir = data
            .path()
            .join("opening-instances")
            .join(crate::hex_id(&[1; 32]));
        let partial = dir.join(".2.interrupted.new");
        std::fs::write(&partial, b"partial")?;
        assert!(store.kept_instance(&[1; 32], 2).is_err());
        store.keep(&[1; 32], 2, b"whole")?;
        assert_eq!(store.kept_instance(&[1; 32], 2)?, b"whole");
        assert_eq!(std::fs::read(partial)?, b"partial");
        let blocked = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(blocked.path()))?;
        std::fs::write(blocked.path().join("opening-instances"), b"not a directory")?;
        assert!(store.keep(&[1; 32], 1, b"cannot save").is_err());
        assert!(store.row(&[1; 32])?.is_none());
        Ok(())
    }

    /// A data directory restored without an opening's kept instances, or
    /// with some, tells which are missing; a partial upload is not one.
    #[test]
    fn instances_missing_from_a_restored_directory_are_told() -> Result<()> {
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        store.keep(&[1; 32], 1, b"first")?;
        store.keep(&[1; 32], 3, b"third")?;
        assert!(store.missing_instances(&[1; 32], &[1, 3]).is_empty());
        assert_eq!(store.missing_instances(&[1; 32], &[1, 2, 3]), [2]);
        let dir = data
            .path()
            .join("opening-instances")
            .join(crate::hex_id(&[1; 32]));
        std::fs::write(dir.join(".2.interrupted.new"), b"partial")?;
        assert_eq!(store.missing_instances(&[1; 32], &[1, 2, 3]), [2]);
        std::fs::remove_dir_all(data.path().join("opening-instances"))?;
        assert_eq!(store.missing_instances(&[1; 32], &[1, 3]), [1, 3]);
        assert_eq!(store.missing_instances(&[2; 32], &[0]), [0]);
        Ok(())
    }

    /// A signed opening of an older format is kept and reported, but its
    /// exit is never played: this build can't read it.
    #[test]
    fn signed_openings_of_another_format_are_kept_but_not_played() -> Result<()> {
        use bitcoin::hashes::Hash as _;
        let data = tempfile::tempdir()?;
        let store = Store::open(&crate::testing::hub_data(data.path()))?;
        for (n, id) in [[1; 32], [2; 32], [3; 32]].iter().enumerate() {
            let deposit = OutPoint {
                txid: bitcoin::Txid::from_byte_array([n as u8 + 1; 32]),
                vout: 0,
            };
            assert!(store.insert(id, 0, true, &deposit, &[0; 32], b"state")?);
        }
        store.save(&[1; 32], 0, true, &[0; 32], b"state")?;
        store.save(&[2; 32], 0, true, &[0; 32], b"state")?;
        store.0.execute(
            "UPDATE openings SET format = ?2 WHERE id = ?1",
            params![[2u8; 32], FORMAT - 1],
        )?;
        assert_eq!(store.signed_ids()?, vec![[1; 32]]);
        assert_eq!(store.unreadable_signed()?, vec![([2; 32], FORMAT - 1)]);
        assert!(store
            .row(&[2; 32])
            .err()
            .is_some_and(|e| e.to_string().contains(&format!("format {}", FORMAT - 1))));
        Ok(())
    }
}
