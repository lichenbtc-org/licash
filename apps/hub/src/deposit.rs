//! The hub's deposits on Bitcoin: its notes for coins.
//!
//! A wallet asks for a deposit as for a receipt over Lightning, notes to
//! lock to it on the preimage of a hash only it knows, and names a key to
//! take its coins back with. The hub answers the address of a taproot
//! output ([`Htlc`]) that it claims with the preimage and a key of its own
//! for the deposit, and that the payer takes back after a timeout. Once a
//! payment of exactly the amount asked confirms at depth in time, the hub
//! locks its own notes to the wallet, early enough to claim the coins
//! before the timeout with the preimage the wallet reveals to claim the
//! notes. A lock refunded unclaimed leaves the coins to their payer.
//!
//! The deposits, and the blocks the gateway scanned for their payments and
//! claims, are kept in the hub's database, the component `deposits`.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::Secp256k1,
    secp256k1::{SecretKey, XOnlyPublicKey},
    Amount, Block, BlockHash, FeeRate, OutPoint, ScriptBuf, Transaction, Txid,
};
use licash::spend::{ChainProfile, ProposalId, TimedTerms};
use licash_api::{
    Code, Deposit, DepositStatus, Depositing, Deposits, Fee, Funding, Hex, Problem, Receive,
    ReceiveState, ReceiveStatus, XOnly,
};
use licash_chain_client::{Follow, Source};
use licash_hub::{Error, Hub, Refusal, Settled, Timing};
use licash_onchain::{
    deadline,
    deposit::{self, close_claim_key, close_claim_secret, Htlc, CLOSE_WAIT},
};
use licash_store::Kind;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::{
    peer::{self, Peer, Recorded},
    Failure,
};

/// What deposits cost, the amounts taken and their timing, in satoshis
/// and blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// On top of the notes a deposit locks.
    pub fee: Fee,
    /// The notes a deposit locks: at least and at most.
    pub min: u64,
    pub max: u64,
    /// Confirmations a payment needs.
    pub depth: u32,
    /// Blocks from the request within which its payment must confirm.
    pub window: u32,
    /// Blocks a deposit's lock lasts.
    pub lock_blocks: u32,
    /// Blocks the gateway may be down while a deposit is locked.
    pub downtime: u32,
    /// Blocks the hub's claim has to confirm in before the timeout.
    pub sweep_blocks: u32,
    /// The fee rate of claims, at least, and when the chain estimates none.
    pub min_fee_rate: FeeRate,
    /// Where claims pay.
    pub sweep_to: ScriptBuf,
    /// Between rounds of scanning and following deposits.
    pub poll: Duration,
    /// Deposits asked and not yet paid at once, from which new ones are
    /// refused as unavailable: each is scanned for in every block of its
    /// window, at no cost to whoever asked.
    pub max_open: u32,
}

impl Config {
    /// Deposits that claims pay `sweep_to`, otherwise as by default.
    pub fn new(sweep_to: ScriptBuf) -> Self {
        Self {
            fee: Fee {
                base: 1_000,
                ppm: 0,
            },
            min: 10_000,
            max: 5_000_000,
            depth: 3,
            // Half a day: a slot asked and never paid is freed by then.
            window: 72,
            lock_blocks: 36,
            downtime: 6,
            sweep_blocks: 36,
            min_fee_rate: FeeRate::from_sat_per_vb_u32(2),
            sweep_to,
            poll: Duration::from_secs(5),
            max_open: 1024,
        }
    }

    /// Whether the hub, of `timing`, admits the locks of deposits.
    pub fn check(&self, timing: &Timing) -> Result<(), String> {
        let lock = [self.lock_blocks, timing.min_depth, timing.reaction]
            .iter()
            .try_fold(0u32, |sum, b| sum.checked_add(*b));
        if self.lock_blocks == 0 || lock.is_none_or(|l| l > timing.window) {
            return Err(format!(
                "deposit lock blocks must be positive and, with the depth and reaction of the \
                 hub's locks, within their window of {}",
                timing.window
            ));
        }
        if self.depth == 0 || self.window == 0 || self.sweep_blocks == 0 {
            return Err("the deposit depth, window and sweep blocks must be positive".into());
        }
        if self.min == 0 || self.min > self.max {
            return Err("the least deposit must be positive and at most the largest".into());
        }
        if self.max_open == 0 {
            return Err("the limit of deposits asked must be positive".into());
        }
        if self.timeout_blocks(timing.min_depth).is_none() {
            return Err("the deposit timing overflows".into());
        }
        Ok(())
    }

    /// Blocks from a request to its timeout: its window and depth, then a
    /// lock's life and depth, the gateway's downtime and a claim's time to
    /// confirm.
    fn timeout_blocks(&self, lock_depth: u32) -> Option<u32> {
        [
            self.depth,
            self.lock_blocks,
            lock_depth,
            self.downtime,
            self.sweep_blocks,
        ]
        .iter()
        .try_fold(self.window, |sum, b| sum.checked_add(*b))
    }

    /// Whether a lock expiring at `expiry` at `lock_depth` leaves the hub
    /// time to claim the coins before `timeout`, down a while.
    fn claims_in_time(&self, expiry: u32, lock_depth: u32, timeout: u32) -> bool {
        [lock_depth, self.downtime, self.sweep_blocks]
            .iter()
            .try_fold(expiry, |at, b| at.checked_add(*b))
            .is_some_and(|latest| latest <= timeout)
    }
}

/// The component the deposits' tables are, and its version.
pub(crate) const COMPONENT: &str = "deposits";
pub(crate) const VERSION: i64 = 3;

/// A stage a deposit reaches is a table of its own, one row of it a fact.
const SCHEMA: &str = "
-- Deposits asked for, recorded before their address is answered: paid
-- once a payment confirms, locked, then settled and claimed, or canceled.
-- Live until done. `lock` is the proposal of the hub's lock to the wallet,
-- `preimage` the one the wallet revealed claiming its notes. One under a
-- refund key, which its wallet asks after it by.
CREATE TABLE deposits (
    hash BLOB PRIMARY KEY CHECK (length(hash) = 32),
    -- The deposit asked for, as JSON.
    body TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount >= 0),
    pays INTEGER NOT NULL CHECK (pays >= 0),
    claim_key BLOB NOT NULL,
    refund_key BLOB NOT NULL UNIQUE,
    timeout_height INTEGER NOT NULL,
    fund_by_height INTEGER NOT NULL,
    script BLOB NOT NULL,
    lock BLOB,
    preimage BLOB,
    state TEXT NOT NULL CHECK (state IN ('open', 'locked', 'settled', 'canceled')),
    created_at INTEGER NOT NULL,
    done_at INTEGER,
    -- Where it was asked from (crate::AdmissionSource), if known.
    source BLOB
) STRICT;
CREATE INDEX live_deposits ON deposits (state) WHERE done_at IS NULL;
CREATE INDEX deposit_sources ON deposits (source) WHERE done_at IS NULL;
-- Its payment, once confirmed: forgotten again if its block leaves the best
-- chain before the hub's claim of it confirms, to be found again in the
-- block it confirms in next, perhaps another transaction.
CREATE TABLE deposit_fundings (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    txid BLOB NOT NULL,
    vout INTEGER NOT NULL,
    height INTEGER NOT NULL
) STRICT;
-- The hub's claim of the payment, once made, before it is broadcast, and its
-- id: made again at a higher fee as the timeout nears.
CREATE TABLE deposit_sweeps (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    tx BLOB NOT NULL,
    txid BLOB NOT NULL
) STRICT;
-- The spend of the payment, once confirmed, by the hub's claim or by its
-- payer taking it back: forgotten again if its block leaves the best chain.
CREATE TABLE deposit_spends (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    txid BLOB NOT NULL,
    height INTEGER NOT NULL
) STRICT;
-- The blocks of the best chain scanned, of late.
CREATE TABLE deposit_blocks (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL
) STRICT;
";

/// The deposits that return a contract's reserve, a component of their own
/// so that a file made before them takes it as a table not yet made, and its
/// deposits as the ordinary ones they were.
const CLOSES: &str = "deposit_closes";
const CLOSES_VERSION: i64 = 1;

const CLOSES_SCHEMA: &str = "
-- A deposit that a contract's default close pays her reserve to
-- (`licash_api::CloseTerms`), one row each: its contract once the hub's
-- contracts bound it (until then the hub keeps it for a window only), and
-- when its wallet asked for the lock, which no payment starts.
CREATE TABLE deposit_closes (
    hash BLOB PRIMARY KEY REFERENCES deposits (hash),
    contract BLOB UNIQUE CHECK (length(contract) = 32),
    asked_at INTEGER
) STRICT;
";

/// Scanned blocks kept below the newest, to find where a reorganization
/// forked.
const KEPT_BLOCKS: u32 = 1_000;

/// The most blocks ahead of the hub's tip the timeout of a deposit that
/// returns a contract's reserve may be: some two years.
const MAX_CLOSE_BLOCKS: u32 = 105_120;

/// The gateway's deposits, in the hub's database.
struct Store(Mutex<Connection>);

/// A deposit as recorded.
#[derive(Clone, Debug)]
struct Record {
    hash: [u8; 32],
    body: String,
    amount: u64,
    pays: u64,
    htlc: Htlc,
    /// The `timeout_height` column: its refund's height, or for a deposit
    /// that returns a contract's reserve, the block it is watched for until.
    until: u32,
    fund_by: u32,
    funding: Option<(OutPoint, u32)>,
    lock: Option<ProposalId>,
    preimage: Option<[u8; 32]>,
    sweep: Option<Vec<u8>>,
    spent_by: Option<Txid>,
    state: ReceiveState,
    /// Set if it returns a contract's reserve.
    close: Option<CloseState>,
}

impl Record {
    /// The height after which its payer may take the coins back: its
    /// timeout, or for a deposit that returns a contract's reserve a wait
    /// after its payment confirmed, none until it did.
    fn refund_height(&self) -> Option<u32> {
        match self.htlc.wait {
            None => Some(self.htlc.timeout),
            Some(_) => self
                .funding
                .map(|(_, height)| self.htlc.refund_height(height)),
        }
    }
}

/// A deposit asked for, to record.
struct New<'a> {
    body: &'a str,
    amount: u64,
    pays: u64,
    htlc: &'a Htlc,
    /// What its `timeout_height` is: its refund's height, or the block a
    /// deposit that returns a contract's reserve is watched for until.
    until: u32,
    /// The last block its payment may confirm in.
    fund_by: u32,
    /// Whether it returns a contract's reserve.
    close: bool,
    /// Where it is asked from, if known.
    source: Option<&'a crate::AdmissionSource>,
}

/// Where a deposit that returns a contract's reserve stands.
#[derive(Clone, Debug)]
struct CloseState {
    /// The contract that names it, once the hub's contracts bound it.
    contract: Option<[u8; 32]>,
    /// Whether its wallet asked for the lock.
    asked: bool,
}

const RECORDS: &str = "SELECT d.hash, d.body, d.amount, d.pays, d.claim_key, d.refund_key,
    d.timeout_height, d.fund_by_height, f.txid, f.vout, f.height, d.lock, d.preimage, w.tx,
    p.txid, d.state, c.hash, c.contract, c.asked_at
    FROM deposits d
    LEFT JOIN deposit_fundings f ON f.hash = d.hash
    LEFT JOIN deposit_sweeps w ON w.hash = d.hash
    LEFT JOIN deposit_spends p ON p.hash = d.hash
    LEFT JOIN deposit_closes c ON c.hash = d.hash";

/// What became of a deposit to record.
enum Kept {
    Recorded,
    /// Recorded before, under its hash.
    Known,
    /// Its refund key is another deposit's.
    RefundTaken,
    /// As many as the hub takes are asked and not paid.
    Full,
    /// As many as the hub takes from one source are asked from its own
    /// and not paid.
    SourceFull,
}

/// The deposits asked and not paid, as many as `--deposit-max-open`
/// bounds: from `source` alone, if any, those an older release stored
/// under its address and a port too. Those bound to a contract are paid
/// for by it.
fn unpaid(conn: &Connection, source: Option<&crate::AdmissionSource>) -> rusqlite::Result<u32> {
    let [v4, v6] = source.map_or([None, None], crate::AdmissionSource::legacy_prefixes);
    conn.query_row(
        "SELECT count(*) FROM deposits d
         WHERE d.state = 'open' AND d.done_at IS NULL
           AND (?1 IS NULL OR d.source = ?1
                OR substr(d.source, 1, length(?2)) = ?2
                OR substr(d.source, 1, length(?3)) = ?3)
           AND NOT EXISTS (SELECT 1 FROM deposit_closes c
                           WHERE c.hash = d.hash AND c.contract IS NOT NULL)",
        params![source.map(crate::AdmissionSource::as_bytes), v4, v6],
        |r| r.get(0),
    )
}

/// Why a new deposit asked from `source` is refused, if as one too many:
/// past `most` asked and not paid, or past [`crate::PER_SOURCE`] from
/// `source`.
fn full(
    conn: &Connection,
    most: u32,
    source: Option<&crate::AdmissionSource>,
) -> rusqlite::Result<Option<Kept>> {
    if unpaid(conn, None)? >= most {
        return Ok(Some(Kept::Full));
    }
    if source.is_some() && unpaid(conn, source)? >= crate::PER_SOURCE {
        return Ok(Some(Kept::SourceFull));
    }
    Ok(None)
}

/// The key in column `i` of `r`.
fn x_only(r: &Row<'_>, i: usize) -> rusqlite::Result<XOnlyPublicKey> {
    let bytes: [u8; 32] = r.get(i)?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Blob, e.into())
    })
}

fn record(r: &Row<'_>) -> rusqlite::Result<Record> {
    let key = |i| x_only(r, i);
    let hash: [u8; 32] = r.get(0)?;
    let funding = match (r.get::<_, Option<[u8; 32]>>(8)?, r.get(9)?, r.get(10)?) {
        (Some(txid), Some(vout), Some(height)) => Some((
            OutPoint {
                txid: Txid::from_byte_array(txid),
                vout,
            },
            height,
        )),
        _ => None,
    };
    let state = match r.get::<_, String>(15)?.as_str() {
        "open" => ReceiveState::Open,
        "locked" => ReceiveState::Locked,
        "settled" => ReceiveState::Settled,
        _ => ReceiveState::Canceled,
    };
    let close = match r.get::<_, Option<[u8; 32]>>(16)? {
        None => None,
        Some(_) => Some(CloseState {
            contract: r.get(17)?,
            asked: r.get::<_, Option<i64>>(18)?.is_some(),
        }),
    };
    Ok(Record {
        hash,
        body: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        pays: r.get::<_, i64>(3)? as u64,
        htlc: Htlc {
            hash,
            claim: key(4)?,
            refund: key(5)?,
            // A deposit that returns a contract's reserve is taken back
            // a wait after its payment, whatever the height.
            timeout: if close.is_some() { 0 } else { r.get(6)? },
            wait: close.as_ref().map(|_| CLOSE_WAIT),
            sized: false,
        },
        until: r.get(6)?,
        fund_by: r.get(7)?,
        funding,
        lock: r
            .get::<_, Option<[u8; 32]>>(11)?
            .map(ProposalId::from_bytes),
        preimage: r.get(12)?,
        sweep: r.get(13)?,
        spent_by: r.get::<_, Option<[u8; 32]>>(14)?.map(Txid::from_byte_array),
        state,
        close,
    })
}

/// `n` as a database integer: an amount beyond it is an error, not a lesser one.
fn sql(n: u64) -> rusqlite::Result<i64> {
    licash_store::sat(n)
}

impl Store {
    /// The deposits in the hub's database at `path`, made if the gateway
    /// never ran there.
    fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = licash_store::open(path, Kind::Hub)?;
        licash_store::component(&mut conn, COMPONENT, VERSION, SCHEMA)?;
        licash_store::component(&mut conn, CLOSES, CLOSES_VERSION, CLOSES_SCHEMA)?;
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get(&self, hash: &[u8; 32]) -> rusqlite::Result<Option<Record>> {
        let conn = self.conn();
        conn.query_row(&format!("{RECORDS} WHERE d.hash = ?1"), [hash], record)
            .optional()
    }

    /// The deposits not done, oldest first.
    fn live(&self) -> rusqlite::Result<Vec<Record>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "{RECORDS} WHERE d.done_at IS NULL ORDER BY d.created_at, d.rowid"
        ))?;
        let live = stmt.query_map([], record)?.collect();
        live
    }

    /// The hash of the deposit whose refund key is `refund`.
    fn hash_of(&self, refund: &[u8; 32]) -> rusqlite::Result<Option<[u8; 32]>> {
        let conn = self.conn();
        conn.query_row(
            "SELECT hash FROM deposits WHERE refund_key = ?1",
            [refund],
            |r| r.get(0),
        )
        .optional()
    }

    /// Record a deposit unless one under its hash or its refund key is, or
    /// `most` are asked and not paid. Those bound to a contract are not
    /// counted: a contract limits them. One that returns a contract's
    /// reserve (`new.close`) is recorded as such, in the same write.
    fn insert(&self, new: &New, most: u32) -> rusqlite::Result<Kept> {
        let New {
            body,
            amount,
            pays,
            htlc,
            until,
            fund_by,
            close,
            source,
        } = *new;
        let mut conn = self.conn();
        let tx = licash_store::begin(&mut conn)?;
        let taken: Option<[u8; 32]> = tx
            .query_row(
                "SELECT hash FROM deposits WHERE hash = ?1 OR refund_key = ?2
                 ORDER BY hash = ?1 DESC LIMIT 1",
                params![htlc.hash, htlc.refund.serialize()],
                |r| r.get(0),
            )
            .optional()?;
        match taken {
            Some(hash) if hash == htlc.hash => return Ok(Kept::Known),
            Some(_) => return Ok(Kept::RefundTaken),
            None => {}
        }
        if let Some(full) = full(&tx, most, source)? {
            return Ok(full);
        }
        tx.execute(
            "INSERT INTO deposits (hash, body, amount, pays, claim_key, refund_key,
                 timeout_height, fund_by_height, script, state, created_at, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', ?10, ?11)",
            params![
                htlc.hash,
                body,
                sql(amount)?,
                sql(pays)?,
                htlc.claim.serialize(),
                htlc.refund.serialize(),
                until,
                fund_by,
                htlc.script_pubkey().as_bytes(),
                sql(now())?,
                source.map(crate::AdmissionSource::as_bytes),
            ],
        )?;
        if close {
            tx.execute(
                "INSERT INTO deposit_closes (hash) VALUES (?1)",
                params![htlc.hash],
            )?;
        }
        tx.commit()?;
        Ok(Kept::Recorded)
    }

    /// Whether a new deposit asked from `source` would be refused as one
    /// too many: checked again as it is recorded.
    fn full(
        &self,
        most: u32,
        source: Option<&crate::AdmissionSource>,
    ) -> rusqlite::Result<Option<Kept>> {
        full(&self.conn(), most, source)
    }

    /// The deposit paid to `script`, live.
    fn by_script(&self, script: &[u8]) -> rusqlite::Result<Option<Record>> {
        let conn = self.conn();
        conn.query_row(
            &format!("{RECORDS} WHERE d.script = ?1 AND d.done_at IS NULL"),
            [script],
            record,
        )
        .optional()
    }

    /// Bind the deposit under `hash` that returns a contract's reserve to
    /// `contract`, and keep it till its timeout, a payment being its
    /// default's: false if it is not one, or another contract's.
    fn bind(&self, hash: &[u8; 32], contract: &[u8; 32]) -> rusqlite::Result<bool> {
        let mut conn = self.conn();
        let tx = licash_store::begin(&mut conn)?;
        // Of a deposit still open, in the same write: one given up in between
        // is bound to nothing.
        let bound = tx.execute(
            "UPDATE deposit_closes SET contract = ?2
             WHERE hash = ?1 AND (contract IS NULL OR contract = ?2)
               AND EXISTS (SELECT 1 FROM deposits d
                           WHERE d.hash = ?1 AND d.state = 'open' AND d.done_at IS NULL)",
            params![hash, contract],
        )?;
        if bound == 1 {
            tx.execute(
                "UPDATE deposits SET fund_by_height = timeout_height WHERE hash = ?1",
                params![hash],
            )?;
        }
        tx.commit()?;
        Ok(bound == 1)
    }

    /// Record that the wallet of the deposit under `hash` that returns a
    /// contract's reserve asked for the lock: false if it is none, not
    /// bound, or its payment not seen yet. The lock is made once, and lasts
    /// a few blocks: asked before the payment, it would run out before the
    /// wallet came back.
    fn ask(&self, hash: &[u8; 32]) -> rusqlite::Result<bool> {
        let asked = self.conn().execute(
            "UPDATE deposit_closes SET asked_at = coalesce(asked_at, ?2)
             WHERE hash = ?1 AND contract IS NOT NULL
               AND EXISTS (SELECT 1 FROM deposit_fundings f WHERE f.hash = ?1)",
            params![hash, sql(now())?],
        )?;
        Ok(asked == 1)
    }

    /// Give up the deposits bound to `contract` that no payment was seen
    /// for: its opening was given up, and none will pay them.
    fn release(&self, contract: &[u8; 32]) -> rusqlite::Result<usize> {
        self.conn().execute(
            "UPDATE deposits SET state = 'canceled', done_at = ?2
             WHERE state = 'open' AND done_at IS NULL
               AND hash IN (SELECT hash FROM deposit_closes WHERE contract = ?1)
               AND NOT EXISTS (SELECT 1 FROM deposit_fundings f WHERE f.hash = deposits.hash)",
            params![contract, sql(now())?],
        )
    }

    fn set(
        &self,
        hash: &[u8; 32],
        column: &str,
        value: &dyn rusqlite::ToSql,
    ) -> rusqlite::Result<()> {
        self.conn().execute(
            &format!("UPDATE deposits SET {column} = ?2 WHERE hash = ?1"),
            params![hash, value],
        )?;
        Ok(())
    }

    /// Move a deposit to `state`, done unless it is to be claimed.
    fn finish(&self, hash: &[u8; 32], state: &str) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE deposits SET state = ?2,
                 done_at = CASE WHEN ?2 IN ('locked', 'settled') THEN NULL ELSE ?3 END
             WHERE hash = ?1",
            params![hash, state, sql(now())?],
        )?;
        Ok(())
    }

    /// Done with a deposit as it stands.
    fn done(&self, hash: &[u8; 32]) -> rusqlite::Result<()> {
        self.set(hash, "done_at", &sql(now())?)
    }

    /// The newest block scanned.
    fn top(&self) -> rusqlite::Result<Option<(u32, BlockHash)>> {
        let conn = self.conn();
        let top = conn
            .query_row(
                "SELECT height, hash FROM deposit_blocks ORDER BY height DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get::<_, [u8; 32]>(1)?)),
            )
            .optional()?;
        Ok(top.map(|(height, hash)| (height, BlockHash::from_byte_array(hash))))
    }

    fn hash_at(&self, height: u32) -> rusqlite::Result<Option<BlockHash>> {
        let conn = self.conn();
        let hash = conn
            .query_row(
                "SELECT hash FROM deposit_blocks WHERE height = ?1",
                [height],
                |r| r.get::<_, [u8; 32]>(0),
            )
            .optional()?;
        Ok(hash.map(BlockHash::from_byte_array))
    }
}

impl Store {
    /// Record `block`, at `height` on the best chain, with the payments of
    /// deposits in it and the spends of those paid.
    fn scanned(&self, height: u32, block: &Block) -> rusqlite::Result<()> {
        let mut conn = self.conn();
        let tx = licash_store::begin(&mut conn)?;
        let mut unpaid: HashMap<Vec<u8>, ([u8; 32], u64, u32)> = tx
            .prepare(
                "SELECT script, hash, pays, fund_by_height FROM deposits d
                 WHERE d.done_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM deposit_fundings f WHERE f.hash = d.hash)",
            )?
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    (r.get(1)?, r.get::<_, i64>(2)? as u64, r.get(3)?),
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut paid: HashMap<OutPoint, Htlc> = tx
            .prepare(
                "SELECT f.txid, f.vout, d.hash, d.claim_key, d.refund_key, d.timeout_height
                 FROM deposits d JOIN deposit_fundings f ON f.hash = d.hash
                 WHERE d.done_at IS NULL
                   AND NOT EXISTS (SELECT 1 FROM deposit_spends s WHERE s.hash = d.hash)",
            )?
            .query_map([], |r| {
                let txid = Txid::from_byte_array(r.get(0)?);
                Ok((
                    OutPoint {
                        txid,
                        vout: r.get(1)?,
                    },
                    Htlc {
                        hash: r.get(2)?,
                        claim: x_only(r, 3)?,
                        refund: x_only(r, 4)?,
                        timeout: r.get(5)?,
                        wait: None,
                        sized: false,
                    },
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        for t in &block.txdata {
            let txid = t.compute_txid();
            for input in &t.input {
                let Some(htlc) = paid.remove(&input.previous_output) else {
                    continue;
                };
                let hash = htlc.hash;
                // Claimed by the hub, by whichever of its claims, done;
                // else the payer took it back.
                let ours = htlc.claimed_by(t, input.previous_output);
                tx.execute(
                    "INSERT INTO deposit_spends (hash, txid, height) VALUES (?1, ?2, ?3)
                     ON CONFLICT (hash) DO UPDATE SET txid = excluded.txid,
                        height = excluded.height",
                    params![hash, txid.to_byte_array(), height],
                )?;
                tx.execute(
                    "UPDATE deposits SET done_at = CASE WHEN ?2 THEN ?3 ELSE done_at END
                     WHERE hash = ?1",
                    params![hash, ours, sql(now())?],
                )?;
                let hash = hex::encode(hash);
                tracing::info!(%hash, %txid, height, ours, "a deposit's payment spent");
            }
            for (vout, output) in (0u32..).zip(&t.output) {
                let script = output.script_pubkey.as_bytes();
                let Some(&(hash, pays, fund_by)) = unpaid.get(script) else {
                    continue;
                };
                let name = hex::encode(hash);
                if output.value.to_sat() != pays || height > fund_by {
                    let value = output.value.to_sat();
                    tracing::warn!(hash = %name, %txid, value, pays, height, fund_by, "a payment to a deposit not as asked: its payer takes it back");
                    continue;
                }
                unpaid.remove(script);
                tx.execute(
                    "INSERT INTO deposit_fundings (hash, txid, vout, height)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (hash) DO UPDATE SET txid = excluded.txid,
                        vout = excluded.vout, height = excluded.height",
                    params![hash, txid.to_byte_array(), vout, height],
                )?;
                tracing::info!(hash = %name, %txid, vout, height, "deposit paid");
            }
        }
        tx.execute(
            "INSERT INTO deposit_blocks (height, hash) VALUES (?1, ?2)",
            params![height, block.block_hash().to_byte_array()],
        )?;
        tx.execute(
            "DELETE FROM deposit_blocks WHERE height < ?1",
            [height.saturating_sub(KEPT_BLOCKS)],
        )?;
        tx.commit()
    }

    /// The oldest block kept.
    fn oldest(&self) -> rusqlite::Result<Option<u32>> {
        self.conn()
            .query_row("SELECT MIN(height) FROM deposit_blocks", [], |r| r.get(0))
    }

    /// Forget the blocks from `height` up, which left the best chain, and
    /// what was found in them: the payments of deposits not locked yet,
    /// and spends. Those locked keep theirs: the hub's notes are out.
    /// `below`, the best chain's block before `height`, is kept as scanned
    /// should none older be: the scan goes on from `height`.
    fn rewind(&self, height: u32, below: Option<BlockHash>) -> rusqlite::Result<Vec<[u8; 32]>> {
        let mut conn = self.conn();
        let tx = licash_store::begin(&mut conn)?;
        tx.execute("DELETE FROM deposit_blocks WHERE height >= ?1", [height])?;
        if let (Some(hash), Some(at)) = (below, height.checked_sub(1)) {
            tx.execute(
                "INSERT INTO deposit_blocks (height, hash) VALUES (?1, ?2)
                 ON CONFLICT (height) DO UPDATE SET hash = excluded.hash",
                params![at, hash.to_byte_array()],
            )?;
        }
        tx.execute(
            "UPDATE deposits SET done_at = NULL
             WHERE state = 'settled'
               AND hash IN (SELECT hash FROM deposit_spends WHERE height >= ?1)",
            [height],
        )?;
        tx.execute("DELETE FROM deposit_spends WHERE height >= ?1", [height])?;
        let unbacked = tx
            .prepare(
                "SELECT d.hash FROM deposits d JOIN deposit_fundings f ON f.hash = d.hash
                 WHERE f.height >= ?1 AND d.state IN ('locked', 'settled')
                   AND NOT EXISTS (SELECT 1 FROM deposit_spends s WHERE s.hash = d.hash)",
            )?
            .query_map([height], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        // Payments that left the best chain, of deposits not done: found
        // again wherever they confirm next, the hub's claims of them made
        // anew, those made spending a coin perhaps gone.
        let gone = "SELECT f.hash FROM deposit_fundings f JOIN deposits d ON d.hash = f.hash
                    WHERE f.height >= ?1 AND d.done_at IS NULL";
        tx.execute(
            &format!("DELETE FROM deposit_sweeps WHERE hash IN ({gone})"),
            [height],
        )?;
        tx.execute(
            &format!("DELETE FROM deposit_fundings WHERE hash IN ({gone})"),
            [height],
        )?;
        tx.commit()?;
        Ok(unbacked)
    }
}

/// The current Unix time, in seconds.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn store_down(e: rusqlite::Error) -> Failure {
    tracing::error!(error = %e, "the deposits cannot be read or written");
    Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
}

fn store_gone() -> Failure {
    tracing::error!("a deposit does not read as written");
    Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
}

/// The refusal of a deposit `kept` as one too many.
fn unkept(kept: Kept) -> Failure {
    let detail = match kept {
        Kept::SourceFull => "too many deposits asked from this source and not paid: retry later",
        _ => "too many deposits asked and not paid: retry later",
    };
    Failure(Problem::new(Code::Unavailable, detail))
}

fn refused(detail: &str) -> Failure {
    Failure(Problem::new(Code::Forward, detail))
}

impl Store {
    /// Record the hub's claim of a deposit, before it is broadcast.
    fn set_sweep(&self, hash: &[u8; 32], tx: &Transaction) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO deposit_sweeps (hash, tx, txid) VALUES (?1, ?2, ?3)
             ON CONFLICT (hash) DO UPDATE SET tx = excluded.tx, txid = excluded.txid",
            params![hash, serialize(tx), tx.compute_txid().to_byte_array()],
        )?;
        Ok(())
    }
}

/// The hub's deposits on Bitcoin.
pub struct Gateway {
    hub: Arc<Hub>,
    source: Source,
    profile: ChainProfile,
    config: Config,
    store: Store,
    /// What the operator was alerted of, once each.
    alerted: Mutex<HashSet<String>>,
    /// The Lightning gateway, if the hub runs one.
    pub(crate) peer: Peer,
}

impl Gateway {
    /// The deposits of `hub` on the chain of `source`, of `profile`, kept
    /// at `path`.
    pub fn open(
        hub: Arc<Hub>,
        source: Source,
        profile: ChainProfile,
        config: Config,
        path: &Path,
    ) -> anyhow::Result<Self> {
        config
            .check(&hub.info().policy.timing)
            .map_err(anyhow::Error::msg)?;
        Ok(Self {
            store: Store::open(path)?,
            hub,
            source,
            profile,
            config,
            alerted: Mutex::default(),
            peer: Peer::default(),
        })
    }

    fn lock_depth(&self) -> u32 {
        self.hub.info().policy.timing.min_depth
    }

    /// What the hub's info says of its deposits.
    pub fn advertise(&self) -> Deposits {
        let c = &self.config;
        Deposits {
            fee: c.fee,
            min: c.min,
            max: c.max,
            depth: c.depth,
            window: c.window,
            timeout: c.timeout_blocks(self.lock_depth()).unwrap_or(u32::MAX),
            close_root: self.root().ok().map(|root| XOnly(root.serialize())),
        }
    }

    /// The address and amount whose payment locks the hub's notes to the
    /// outputs of `body`: the same again for the same deposit.
    pub async fn deposit(
        &self,
        body: &Deposit,
        source: Option<&crate::AdmissionSource>,
    ) -> Result<Depositing, Failure> {
        let outputs = body.receive.outputs()?;
        let (keyset, ephemeral, hash) = body.receive.terms()?;
        if self.hub.keyset(&keyset).is_none() {
            return Err(Failure(Problem::new(Code::UnknownKeyset, "unknown keyset")));
        }
        let amount = outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.denomination()))
            .ok_or_else(|| Failure(Problem::invalid("the outputs overflow")))?;
        let c = &self.config;
        if outputs.is_empty() || amount < c.min || amount > c.max {
            return Err(refused("outside the amounts the hub takes in deposits"));
        }
        let pays = match &body.close {
            None => amount
                .checked_add(c.fee.due(amount))
                .filter(|pays| Amount::from_sat(*pays) <= Amount::MAX_MONEY)
                .ok_or_else(|| Failure(Problem::invalid("the amount overflows")))?,
            // The reserve exactly, the notes the most it covers: the rest
            // is the hub's, which she agreed to in her contract.
            Some(close) => {
                if self.advertise().most_for(close.pays) != Some(amount) {
                    return Err(refused("not the most notes this payment covers"));
                }
                close.pays
            }
        };
        let refund = XOnlyPublicKey::from_slice(&body.refund.0)
            .map_err(|_| Failure(Problem::invalid("refund: not an x-only public key")))?;
        let canonical = Deposit {
            receive: Receive::new(&keyset, &ephemeral, &outputs, &hash),
            refund: Hex(refund.serialize().to_vec()),
            close: body.close,
        };
        let canonical = serde_json::to_string(&canonical).expect("a deposit serializes");
        let turn = self.peer.turn().await;
        if self.store.get(&hash).map_err(store_down)?.is_none() {
            // Refused before any work, if it would be at the end.
            if let Some(kept) = self.store.full(c.max_open, source).map_err(store_down)? {
                return Err(unkept(kept));
            }
            if self.peer.recorded(&hash)?.is_some() || self.peer.holds_swap(&hash)? {
                return Err(refused("the hub holds this hash for another payment"));
            }
            if self
                .on_hub(move |hub| hub.own_lock_of(&hash))
                .await?
                .is_some()
            {
                return Err(refused("the hub locked notes under this hash before"));
            }
            let (from, _) = self.on_hub(|hub| hub.scanned()).await?.ok_or_else(|| {
                Failure(Problem::new(
                    Code::Unavailable,
                    "the hub follows no chain yet",
                ))
            })?;
            // A deposit that returns a contract's reserve is claimed with a key
            // anyone derives from the hub's root: so a wallet restored from its
            // seed rebuilds its address.
            let claim = match &body.close {
                None => {
                    self.claim_key(&hash)?
                        .x_only_public_key(&Secp256k1::new())
                        .0
                }
                Some(_) => close_claim_key(&self.root()?, &hash, &refund),
            };
            let until = match &body.close {
                None => c
                    .timeout_blocks(self.lock_depth())
                    .and_then(|blocks| from.checked_add(blocks))
                    .ok_or_else(|| Failure(Problem::invalid("the deposit's timeout overflows")))?,
                // Where her contract's Base puts it: beyond the window the
                // hub gives it to be bound, and not so far as to be kept
                // for years.
                Some(close) => {
                    let first = from
                        .checked_add(c.window)
                        .ok_or_else(|| Failure(Problem::invalid("the timeout overflows")))?;
                    let last = from.saturating_add(MAX_CLOSE_BLOCKS);
                    if close.until <= first || close.until > last {
                        return Err(refused(
                            "a block to watch until outside what the hub keeps a deposit for",
                        ));
                    }
                    close.until
                }
            };
            let htlc = Htlc {
                hash,
                claim,
                refund,
                timeout: if body.close.is_some() { 0 } else { until },
                wait: body.close.as_ref().map(|_| CLOSE_WAIT),
                sized: false,
            };
            // Its window from now, not from where the scan is: a scan behind
            // the node would leave it a part of it, or none once caught up.
            let now = match self.source.tip().await {
                Ok(tip) => tip.height.max(from),
                Err(_) => from,
            };
            let fund_by = now.saturating_add(c.window);
            let new = New {
                body: &canonical,
                amount,
                pays,
                htlc: &htlc,
                until,
                fund_by,
                close: body.close.is_some(),
                source,
            };
            match self.store.insert(&new, c.max_open).map_err(store_down)? {
                Kept::Recorded => {
                    tracing::info!(hash = %hex::encode(hash), amount, pays, fund_by, until, "deposit asked");
                }
                Kept::Known => {}
                // Its wallet asks after a deposit by its refund key: under
                // one, a second would hide the first from it.
                Kept::RefundTaken => {
                    return Err(refused("another deposit under this refund key"));
                }
                kept @ (Kept::Full | Kept::SourceFull) => return Err(unkept(kept)),
            }
        }
        drop(turn);
        let record = self
            .store
            .get(&hash)
            .map_err(store_down)?
            .ok_or_else(store_gone)?;
        if record.body != canonical {
            return Err(refused("another deposit under this hash"));
        }
        Ok(self.terms(&record))
    }

    /// The terms answered for the deposit `record`.
    fn terms(&self, record: &Record) -> Depositing {
        Depositing {
            address: record
                .htlc
                .address(licash_chain_client::network(self.profile))
                .to_string(),
            amount: record.pays,
            claim: Hex(record.htlc.claim.serialize().to_vec()),
            timeout: record.until,
            fund_by: record.fund_by,
        }
    }

    /// Where the deposit under `hash` stands, with what was asked and the
    /// terms answered: whoever knows its hash, its wallet, finds it again.
    /// The hash of the deposit whose refund key, x-only, is `refund`: how
    /// its wallet names it, which derives the key from its seed before it
    /// knows the hash.
    pub fn deposit_of(&self, refund: &[u8; 32]) -> Result<[u8; 32], Failure> {
        self.store
            .hash_of(refund)
            .map_err(store_down)?
            .ok_or_else(|| {
                Failure(Problem::new(
                    Code::UnknownLock,
                    "no deposit under this refund key",
                ))
            })
    }

    pub fn deposit_status(&self, hash: &[u8; 32]) -> Result<DepositStatus, Failure> {
        let record = self.store.get(hash).map_err(store_down)?.ok_or_else(|| {
            Failure(Problem::new(
                Code::UnknownLock,
                "no deposit under this hash",
            ))
        })?;
        Ok(DepositStatus {
            status: ReceiveStatus {
                state: record.state,
                lock: record.lock.map(|id| Hex(id.as_bytes().to_vec())),
            },
            funding: record.funding.map(|(outpoint, height)| Funding {
                txid: outpoint.txid.to_string(),
                vout: outpoint.vout,
                height,
            }),
            request: serde_json::from_str(&record.body).ok(),
            terms: Some(self.terms(&record)),
        })
    }

    /// Bind the deposit paid to `script` to the contract `contract`, whose
    /// default pays it `pays` (the reserve) at `timeout`, the hub keeping
    /// `fee` of it: refused unless it is a deposit that returns a contract's
    /// reserve, asked for just so, still open within its window, and not
    /// another contract's. The same again for the same contract.
    pub fn bind_close(
        &self,
        script: &[u8],
        contract: [u8; 32],
        pays: u64,
        fee: u64,
        timeout: u32,
    ) -> Result<(), String> {
        let store_err = |e: rusqlite::Error| e.to_string();
        let record = self
            .store
            .by_script(script)
            .map_err(store_err)?
            .ok_or("no such deposit of the hub's")?;
        let Some(close) = &record.close else {
            return Err("the hub's deposit is no contract's close".into());
        };
        if close.contract.is_some_and(|bound| bound != contract) {
            return Err("the deposit is another contract's".into());
        }
        if record.pays != pays
            || record.until != timeout
            || record.amount.checked_add(fee) != Some(pays)
        {
            return Err("the deposit is not as the contract's close names it".into());
        }
        let scanned = self
            .store
            .top()
            .map_err(store_err)?
            .map(|(height, _)| height);
        if record.state != ReceiveState::Open
            || scanned.is_none_or(|height| height > record.fund_by)
        {
            return Err("the deposit was kept for its window only, which is over".into());
        }
        match self
            .store
            .bind(&record.hash, &contract)
            .map_err(store_err)?
        {
            true => Ok(()),
            false => Err("the deposit is another contract's".into()),
        }
    }

    /// Give up the deposit bound to `contract`, whose opening was given up,
    /// unless a payment was seen for it.
    pub fn release_close(&self, contract: &[u8; 32]) {
        match self.store.release(contract) {
            Ok(0) => {}
            Ok(_) => {
                tracing::info!(contract = %hex::encode(contract), "a contract's close deposit given up")
            }
            Err(e) => {
                tracing::warn!(contract = %hex::encode(contract), "cannot give up a close deposit: {e}")
            }
        }
    }

    /// Ask for the lock of the deposit under `hash` that returns a contract's
    /// reserve, bound to its contract: once its payment is buried, the hub
    /// locks its notes to its wallet, if that leaves it time to claim the
    /// coins before the timeout. The same again for the same.
    pub fn ask_lock(&self, hash: &[u8; 32]) -> Result<DepositStatus, Failure> {
        let record = self.store.get(hash).map_err(store_down)?.ok_or_else(|| {
            Failure(Problem::new(
                Code::UnknownLock,
                "no deposit under this hash",
            ))
        })?;
        if record.close.is_none() {
            return Err(refused("a deposit that returns no contract's reserve"));
        }
        if !self.store.ask(hash).map_err(store_down)? {
            return Err(refused("a deposit no contract of the hub's names"));
        }
        self.deposit_status(hash)
    }

    /// The secret of the hub's deposit root, which it claims the deposits that
    /// return a contract's reserve with, each under the root tweaked.
    fn root_secret(&self) -> Result<SecretKey, Failure> {
        SecretKey::from_slice(&self.hub.deposit_root_secret()).map_err(|_| {
            tracing::error!("no deposit root");
            Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
        })
    }

    /// The hub's deposit root, as it publishes it.
    fn root(&self) -> Result<XOnlyPublicKey, Failure> {
        Ok(self.root_secret()?.x_only_public_key(&Secp256k1::new()).0)
    }

    /// The secret the hub claims `record`'s deposit with.
    fn claim_secret(&self, record: &Record) -> Result<SecretKey, Failure> {
        match record.close {
            None => self.claim_key(&record.hash),
            Some(_) => Ok(close_claim_secret(
                &self.root_secret()?,
                &record.hash,
                &record.htlc.refund,
            )),
        }
    }

    /// The key the hub claims the deposit under `hash` with.
    fn claim_key(&self, hash: &[u8; 32]) -> Result<SecretKey, Failure> {
        SecretKey::from_slice(&self.hub.deposit_secret(hash)).map_err(|_| {
            tracing::error!(hash = %hex::encode(hash), "no deposit key under this hash");
            Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
        })
    }
}

impl Gateway {
    /// Whether a deposit is under `hash`, which no other lock of the hub's
    /// own notes may take.
    pub fn holds(&self, hash: &[u8; 32]) -> Result<bool, String> {
        Ok(self.recorded(hash)?.is_some())
    }

    /// Which of `hashes` the deposits file at `path` holds, if there is one.
    pub fn holding(db: &Path, hashes: &[[u8; 32]]) -> anyhow::Result<HashSet<[u8; 32]>> {
        peer::recorded_in(
            db,
            COMPONENT,
            "SELECT 1 FROM deposits WHERE hash = ?1",
            hashes,
        )
    }

    /// The deposit under `hash`, if any, and the lock it backs once
    /// locked.
    pub fn recorded(&self, hash: &[u8; 32]) -> Result<Recorded, String> {
        let record = self.store.get(hash).map_err(|e| e.to_string())?;
        Ok(record.map(|record| record.lock))
    }

    /// Follow the chain and the deposits until the task is dropped, once
    /// the chain is of the hub's network.
    pub async fn run(self: Arc<Self>) {
        let profile = loop {
            match self.source.profile().await {
                Ok(profile) => break profile,
                Err(e) => tracing::debug!(chain = %self.source, "deposits: {e:#}"),
            }
            tokio::time::sleep(self.config.poll).await;
        };
        if profile != self.profile {
            // The hub's own scan alerts of it.
            let (chain, network) = (&self.source, self.profile);
            return tracing::error!(%chain, %profile, %network, "taking no deposits on another network");
        }
        loop {
            self.round().await;
            tokio::time::sleep(self.config.poll).await;
        }
    }

    /// One round: scan the blocks beyond those scanned, then lock the
    /// deposits paid at depth, settle or cancel those decided, and claim
    /// the coins of those settled.
    pub async fn round(&self) {
        if let Err(e) = self.scan().await {
            tracing::warn!(chain = %self.source, "scanning for deposits: {e:#}");
        }
        if let Err(e) = self.follow().await {
            tracing::warn!(error = %e.0.message, "cannot follow deposits");
        }
    }

    /// Scan the best chain from the newest block scanned, or the tip.
    async fn scan(&self) -> anyhow::Result<()> {
        loop {
            let top = self.store.top()?;
            let first = match top {
                Some(_) => 0,
                None => self.source.tip().await?.height,
            };
            let ours = |height| Ok(self.store.hash_at(height)?);
            match self.source.follow(top, first, ours).await? {
                Follow::Next(height, block) => self.store.scanned(height, &block)?,
                Follow::Rewind(height) => {
                    // None kept below: rather than from the tip, on from
                    // there, the best chain's block before it as scanned.
                    let below = match (self.store.oldest()?, height.checked_sub(1)) {
                        (Some(oldest), Some(at)) if oldest >= height => {
                            tracing::warn!(chain = %self.source, height, "deposits: the chain left the oldest block scanned; scanning again from it");
                            Some(self.source.hash(at).await?)
                        }
                        _ => None,
                    };
                    for hash in self.store.rewind(height, below)? {
                        let name = hex::encode(hash);
                        let message = format!(
                            "The payment of deposit {name}, whose notes the hub locked, left the \
                             best chain."
                        );
                        self.alert(format!("unbacked {name}"), message).await;
                    }
                }
                Follow::AtTip => return Ok(()),
            }
        }
    }

    async fn follow(&self) -> Result<(), Failure> {
        let Some((scanned, _)) = self.store.top().map_err(store_down)? else {
            return Ok(());
        };
        for record in self.store.live().map_err(store_down)? {
            let followed = match record.state {
                ReceiveState::Open => self.accept(&record, scanned).await,
                ReceiveState::Locked => self.decide(&record).await,
                ReceiveState::Settled => self.claim(&record, scanned).await,
                ReceiveState::Canceled => Ok(()),
            };
            if let Err(e) = followed {
                let hash = hex::encode(record.hash);
                tracing::warn!(%hash, error = %e.0.message, "cannot follow a deposit");
            }
        }
        Ok(())
    }

    /// Lock the hub's notes for `record` once its payment is at depth, if
    /// the lock leaves time to claim the coins before the timeout; give it
    /// up unpaid once its window passed.
    async fn accept(&self, record: &Record, scanned: u32) -> Result<(), Failure> {
        let hash = record.hash;
        let name = hex::encode(hash);
        let Some((_, height)) = record.funding else {
            if scanned > record.fund_by {
                tracing::info!(hash = %name, "deposit unpaid in time");
                return self.finish(record, "canceled");
            }
            return Ok(());
        };
        if scanned.saturating_sub(height).saturating_add(1) < self.config.depth {
            return Ok(());
        }
        // A contract's close waits for its wallet, which comes back after the
        // close: no lock is made for it, nor is it given up, till it asks.
        if record.close.as_ref().is_some_and(|close| !close.asked) {
            if record.spent_by.is_some() || record.refund_height().is_some_and(|h| scanned > h) {
                tracing::info!(hash = %name, "a contract's close never asked for: its payer takes the coins back");
                return self.finish(record, "canceled");
            }
            return Ok(());
        }
        let body: Deposit = serde_json::from_str(&record.body).map_err(|_| store_gone())?;
        let ((keyset, ephemeral, _), outputs) = (body.receive.terms()?, body.receive.outputs()?);
        let (lock_depth, timeout) = (
            self.lock_depth(),
            record.refund_height().ok_or_else(store_gone)?,
        );
        // Until the lock under the hash is recorded.
        let _turn = self.peer.turn().await;
        // A lock made before the gateway stopped, or for a receipt under
        // the same hash, which backs it once the Lightning gateway recorded
        // it: one payment per lock.
        if let Some(lock) = self.on_hub(move |hub| hub.own_lock_of(&hash)).await? {
            let receipt = self.peer.recorded(&hash)? == Some(Some(lock.proposal.id()));
            if receipt || self.peer.swap_owns(&hash, &lock.proposal.id())? {
                let owner = if receipt {
                    "a Lightning receipt"
                } else {
                    "a swap"
                };
                let message = format!(
                    "The hash of deposit {name} is locked for {owner}: its payer \
                     takes its coins back."
                );
                self.alert(format!("taken {name}"), message).await;
                return self.finish(record, "canceled");
            }
            let expiry = lock
                .proposal
                .lock()
                .ok_or_else(store_gone)?
                .terms()
                .expiry();
            if lock.proposal.outputs() != outputs.as_slice()
                || !self.config.claims_in_time(expiry, lock_depth, timeout)
            {
                let message = format!(
                    "The hash of deposit {name} is locked to other notes or for too long: its \
                     payer takes its coins back."
                );
                self.alert(format!("taken {name}"), message).await;
                return self.finish(record, "canceled");
            }
            self.store
                .set(&hash, "lock", &lock.proposal.id().as_bytes())
                .map_err(store_down)?;
            return self.finish(record, "locked");
        }
        let (tip, checkpoint) = self
            .on_hub(|hub| Ok((hub.scanned()?, hub.checkpoint())))
            .await?;
        let (Some((tip, _)), Some(checkpoint)) = (tip, checkpoint) else {
            return Ok(());
        };
        let expiry = tip.saturating_add(self.config.lock_blocks);
        if !self.config.claims_in_time(expiry, lock_depth, timeout) {
            tracing::warn!(hash = %name, expiry, timeout, "deposit paid too late to lock: its payer takes its coins back");
            return self.finish(record, "canceled");
        }
        let terms = TimedTerms::new(
            checkpoint.profile(),
            checkpoint.commitment(),
            expiry,
            lock_depth,
            hash,
        )
        .map_err(|e| Failure(Problem::invalid(e.to_string())))?;
        let locked = self
            .on_hub(move |hub| hub.lock_own(&keyset, ephemeral, outputs, terms))
            .await;
        match locked {
            Ok(lock) => {
                let id = lock.proposal.id();
                self.store
                    .set(&hash, "lock", &id.as_bytes())
                    .map_err(store_down)?;
                self.finish(record, "locked")?;
                tracing::info!(hash = %name, lock = %hex::encode(id.as_bytes()), expiry, "deposit locked");
                Ok(())
            }
            // Retried: the hub catches up, or adopts its lock above.
            Err(Error::Refused(Refusal::Unsynced | Refusal::NoChain | Refusal::Exists)) => Ok(()),
            Err(Error::Refused(refusal)) => {
                tracing::warn!(hash = %name, %refusal, "the hub refuses to lock a deposit");
                self.finish(record, "canceled")
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl Gateway {
    /// Settle `record` once its lock paid, learning the preimage that
    /// claims its coins, or cancel it once its lock is refunded, which the
    /// gateway asks for once the lock expired at depth.
    async fn decide(&self, record: &Record) -> Result<(), Failure> {
        let id = record.lock.ok_or_else(store_gone)?;
        let lock = self.on_hub(move |hub| hub.locked(&id)).await?;
        let terms = lock.proposal.lock().ok_or_else(store_gone)?.terms().clone();
        match (lock.settled, lock.preimage) {
            (Some(Settled::Refund), _) => {
                let hash = hex::encode(record.hash);
                tracing::info!(%hash, "deposit refunded unclaimed: its payer takes its coins back");
                self.finish(record, "canceled")
            }
            (Some(Settled::Pay), Some(preimage)) => self.settle(record, preimage),
            // Activated on Bitcoin: the lock pays.
            (None, Some(preimage)) => {
                self.on_hub(move |hub| hub.settle(&id, &preimage)).await?;
                self.settle(record, preimage)
            }
            (None, None) => {
                let tip = self
                    .on_hub(|hub| hub.scanned())
                    .await?
                    .map_or(0, |(h, _)| h);
                if tip < terms.expiry().saturating_add(terms.depth()) {
                    return Ok(());
                }
                match self.on_hub(move |hub| hub.refund(&id)).await {
                    Ok(_) => self.finish(record, "canceled"),
                    Err(Error::Refused(Refusal::Unexpired | Refusal::Activated)) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
            (Some(Settled::Pay), None) => Err(store_gone()),
        }
    }

    fn settle(&self, record: &Record, preimage: [u8; 32]) -> Result<(), Failure> {
        self.store
            .set(&record.hash, "preimage", &preimage)
            .map_err(store_down)?;
        tracing::info!(hash = %hex::encode(record.hash), amount = record.amount, "deposit settled");
        self.finish(record, "settled")
    }

    /// Claim the coins of settled `record` to the sweep address, broadcast
    /// each round until a block spends them, and made again in place of
    /// the one before as the rate its timeout calls for rises; alert the
    /// operator if another spend did, or once the timeout nears.
    async fn claim(&self, record: &Record, scanned: u32) -> Result<(), Failure> {
        let name = hex::encode(record.hash);
        // Its payment left the best chain: claimed once found again.
        if record.funding.is_none() {
            return Ok(());
        }
        if let Some(by) = record.spent_by {
            let message = format!(
                "The payment of deposit {name} was spent by {by}, not by the hub's claim, after \
                 its notes were issued: the hub lost {}.",
                licash_notify::sat(record.pays)
            );
            self.alert(format!("lost {name}"), message).await;
            return self.store.done(&record.hash).map_err(store_down);
        }
        let old = match &record.sweep {
            Some(raw) => Some(deserialize::<Transaction>(raw).map_err(|_| store_gone())?),
            None => None,
        };
        let left = record
            .refund_height()
            .ok_or_else(store_gone)?
            .saturating_sub(scanned);
        let tx = match self.make_claim(record, old.as_ref(), left).await? {
            Some(tx) => {
                self.store
                    .set_sweep(&record.hash, &tx)
                    .map_err(store_down)?;
                let txid = tx.compute_txid();
                tracing::info!(hash = %name, %txid, left, "deposit claim made");
                tx
            }
            None => match old {
                Some(old) => old,
                None => return Ok(()),
            },
        };
        if let Err(e) = self.source.broadcast(&tx).await {
            tracing::warn!(hash = %name, "cannot broadcast a deposit's claim: {e:#}");
        }
        if left <= self.config.sweep_blocks / 2 {
            let message = format!(
                "The claim {} of deposit {name} is unconfirmed {left} blocks before its payer may \
                 take the coins back.",
                tx.compute_txid()
            );
            self.alert(format!("unclaimed {name}"), message).await;
        }
        Ok(())
    }

    /// The claim of `record` to broadcast in place of `old`, the one made
    /// before if any, `left` blocks before its timeout: at the fee rate the
    /// chain estimates confirms well within the sweep blocks or half of
    /// those left, whichever is sooner, rising as they run out
    /// ([`deadline::rate`]), all of its coins but dust at most. None while
    /// `old` pays that rate already, or if its coins cannot pay a claim.
    async fn make_claim(
        &self,
        record: &Record,
        old: Option<&Transaction>,
        left: u32,
    ) -> Result<Option<Transaction>, Failure> {
        let c = &self.config;
        let (outpoint, _) = record.funding.ok_or_else(store_gone)?;
        let preimage = record.preimage.ok_or_else(store_gone)?;
        // Well within the sweep blocks, sooner as the timeout nears.
        let sweep = u16::try_from(c.sweep_blocks / 3).unwrap_or(u16::MAX).max(1);
        let target = deadline::target(left).min(sweep);
        let estimated = self.source.fee_rate(target).await.unwrap_or_else(|e| {
            tracing::warn!(chain = %self.source, "cannot estimate a fee rate: {e:#}");
            None
        });
        let rate = deadline::rate(estimated, c.min_fee_rate, left);
        let secret = self.claim_secret(record)?;
        let value = Amount::from_sat(record.pays);
        let build = |rate| {
            record.htlc.claim_capped(
                outpoint,
                value,
                c.sweep_to.clone(),
                rate,
                &secret,
                &preimage,
            )
        };
        match deadline::remake(old, value, rate, build) {
            Ok(tx) => Ok(tx),
            Err(e @ deposit::Error::TooSmall { .. }) => {
                let name = hex::encode(record.hash);
                let message = format!("Deposit {name} cannot be claimed: {e}.");
                self.alert(format!("unclaimable {name}"), message).await;
                Ok(None)
            }
            Err(e) => {
                tracing::error!(hash = %hex::encode(record.hash), "cannot claim a deposit: {e}");
                Err(store_gone())
            }
        }
    }

    fn finish(&self, record: &Record, state: &str) -> Result<(), Failure> {
        self.store.finish(&record.hash, state).map_err(store_down)
    }

    /// Run `op` on the hub off the async workers.
    async fn on_hub<T: Send + 'static>(
        &self,
        op: impl FnOnce(&Hub) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let hub = self.hub.clone();
        tokio::task::spawn_blocking(move || op(&hub))
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?
    }

    /// Tell the operator `message` once for `key`.
    async fn alert(&self, key: String, message: String) {
        let new = self
            .alerted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key);
        if new {
            tracing::warn!("{message}");
            if let Err(e) = self.on_hub(move |hub| hub.alert(&message)).await {
                tracing::error!(error = %e, "cannot alert the operator");
            }
        }
    }
}
