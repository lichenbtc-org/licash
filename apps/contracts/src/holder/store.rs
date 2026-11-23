//! The holder's contracts, the component `contracts` of the wallet's file,
//! and the instances each keeps, in `contracts/` beside it: each opening as
//! its machine stored itself at its last step, with what a list shows of
//! it. The tables are made with the first contract opened; the directory
//! when one first keeps an instance. A wallet that never opened one holds
//! neither, and reading them finds none.
//!
//! The wallet's own connection and this one are two of one file: a backup
//! of the wallet's file is a backup of its contracts too, but for the
//! instances, which the caller copies while the holder driver is frozen.

use std::collections::HashMap;
#[cfg(test)]
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context as _, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{BlockHash, OutPoint, Txid};
use licash_api::Fees;
use licash_contract::opening::{Fate, Phase};
use licash_store::Kind;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

/// The format of the rows: a machine's stored bytes, of
/// `licash_contract`'s format 3.
const FORMAT: i64 = 3;

/// The component the holder's tables are, and its version.
const COMPONENT: &str = "contracts";
const VERSION: i64 = 1;

/// A stage a contract reaches is a table of its own, one row of it a fact:
/// its recovery, its claim terms, its fold, the block its F was buried in,
/// what she funded of it, the instances its hub answered. A contract of no
/// such row never reached it.
const SCHEMA: &str = "
-- Each opening as its machine stored itself, with what a list shows of it:
-- `phase` its machine's, `fate` where F stands once she signed it (live,
-- dead, or open again), `abandoned` why she gave it up short of that. Her
-- `ceiling_fees`, as JSON, are the most its hub may charge her: its fees as
-- the contract opened, raised since by her only.
CREATE TABLE contracts (
    id BLOB PRIMARY KEY,
    hub TEXT NOT NULL,
    format INTEGER NOT NULL,
    phase INTEGER NOT NULL,
    mock INTEGER NOT NULL CHECK (mock IN (0, 1)),
    irrevocable INTEGER NOT NULL CHECK (irrevocable IN (0, 1)),
    deposit BLOB NOT NULL,
    value INTEGER NOT NULL CHECK (value >= 0),
    price INTEGER NOT NULL CHECK (price >= 0),
    cap INTEGER NOT NULL,
    assert_height INTEGER NOT NULL,
    close_height INTEGER NOT NULL,
    funding BLOB,
    since_height INTEGER NOT NULL,
    fate TEXT CHECK (fate IN ('live', 'dead', 'open')),
    abandoned TEXT,
    ceiling_fees TEXT NOT NULL,
    ceiling_updated_at INTEGER NOT NULL,
    state BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX contracts_deposit ON contracts (deposit)
    WHERE abandoned IS NULL AND (fate IS NULL OR fate != 'dead');

-- Contracts she forced closed, each a recovery's stage and state in a
-- format of `recovery`'s. Dropped only while revocable.
CREATE TABLE contract_recoveries (
    id BLOB PRIMARY KEY REFERENCES contracts (id),
    format INTEGER NOT NULL,
    stage TEXT NOT NULL,
    irrevocable INTEGER NOT NULL CHECK (irrevocable IN (0, 1)),
    state BLOB NOT NULL,
    error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Of each contract, the keyset whose notes its claim holds, the most
-- authorizations it may and the holder program it opened under: read from
-- its state, kept so as not to read it whole again. No row tells nothing:
-- its state tells.
CREATE TABLE contract_claim_terms (
    id BLOB PRIMARY KEY REFERENCES contracts (id),
    keyset BLOB NOT NULL,
    authorizations INTEGER NOT NULL,
    program BLOB NOT NULL
) STRICT;

-- Her consent to exit contracts ending ([`super::exit`]), a row at most,
-- and the payouts the exit made, by ticket, before each was paid, from the
-- hub at `hub` (a URL it may be reached at) at block `height`.
CREATE TABLE contract_exit_consent (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    address TEXT NOT NULL,
    exit_margin INTEGER NOT NULL,
    given_at INTEGER NOT NULL
) STRICT;
CREATE TABLE contract_exit_payouts (
    ticket TEXT PRIMARY KEY,
    contract BLOB NOT NULL REFERENCES contracts (id),
    hub TEXT NOT NULL,
    height INTEGER NOT NULL
) STRICT;

-- The contracts she closed early with their hub, each by its last fold's
-- txid: kept before the hub can sign it, and never dropped: whatever the
-- hub answers, it may have signed.
CREATE TABLE contract_folds (
    id BLOB PRIMARY KEY REFERENCES contracts (id),
    txid BLOB NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- The tips each recovery saw from her publication on: a height and hash
-- each, thinned to about one per power of two blocks back, the newest and
-- the first kept. One whose block the chain no longer has tells what it saw
-- since may be gone ([`Store::recovery_tips`]).
CREATE TABLE contract_recovery_tips (
    id BLOB NOT NULL REFERENCES contracts (id),
    height INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (id, height)
) STRICT;

-- The block each contract's F was found buried in, its height and hash, for
-- as long as the contract lasts: once the chain no longer has it there,
-- F's fate is to be found again. A contract live without one was buried six
-- deep under one that stopped following it there: trusted as it stands.
CREATE TABLE contract_fate_blocks (
    id BLOB PRIMARY KEY REFERENCES contracts (id),
    height INTEGER NOT NULL,
    hash BLOB NOT NULL
) STRICT;

-- What she funded of each contract herself, in sat, of those funding some,
-- and once her wallet received the notes its hub issues her for it
-- ([`super::funded`]).
CREATE TABLE contract_funded (
    id BLOB PRIMARY KEY REFERENCES contracts (id),
    amount INTEGER NOT NULL CHECK (amount > 0),
    received_at INTEGER
) STRICT;

-- The instances of each opening its hub answered as had, by the index of
-- each: not sent again when the opening resumes.
CREATE TABLE contract_served (
    id BLOB NOT NULL REFERENCES contracts (id),
    i INTEGER NOT NULL,
    PRIMARY KEY (id, i)
) STRICT;
";

/// A contract's claim terms as kept ([`CLAIM_TERMS`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct KeptTerms {
    pub keyset: [u8; 32],
    pub authorizations: u32,
    pub program: [u8; 32],
}

/// A recovery as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecoveryRow {
    pub id: [u8; 32],
    pub format: i64,
    pub stage: String,
    /// Past giving it up: her request signed, or about to be.
    pub irrevocable: bool,
    pub state: Vec<u8>,
    /// What stopped its last step, if anything did.
    pub error: Option<String>,
    pub created_at: i64,
}

/// Where beside the wallet's file the instances each opening keeps are, in
/// a directory of its id each.
const KEPT_DIR: &str = "contracts";

/// Beside a contract's kept instances, her statement's input once she
/// forced it closed and the hub answered: what her proof is of.
const STATEMENT: &str = "statement.input";

/// Of the instances opening `id` of the wallet at `wallet_file` keeps, how
/// many are on disk: those `Store::keep` finished writing. None if it keeps
/// none there.
pub fn kept(wallet_file: &Path, id: &[u8; 32]) -> usize {
    let dir = wallet_file.parent().unwrap_or_else(|| Path::new(""));
    let Ok(entries) = std::fs::read_dir(dir.join(KEPT_DIR).join(crate::hex_id(id))) else {
        return 0;
    };
    let written = |e: &std::fs::DirEntry| {
        let name = e.file_name().to_string_lossy().into_owned();
        !name.ends_with(".new") && name != STATEMENT
    };
    entries.filter_map(Result::ok).filter(written).count()
}

/// A contract as a list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub id: [u8; 32],
    /// The hub's URL.
    pub hub: String,
    pub phase: Phase,
    /// Under the mock authority, for regtest only.
    pub mock: bool,
    /// Her coin F spends, and what it holds.
    pub deposit: OutPoint,
    pub value: u64,
    /// What opening it cost her, from her deposit: her reserve and the
    /// hub's fee.
    pub price: u64,
    /// The most it protects, in sat.
    pub cap: u32,
    /// The last block a recovery can assert in: it protects until then.
    pub assert_height: u32,
    /// The block its collateral returns to the hub from.
    pub close_height: u32,
    /// The chain's height as she started opening it.
    pub since: u32,
    /// F's id, once she knows F.
    pub funding: Option<Txid>,
    /// Where F stands, as last seen once she signed it.
    pub fate: Option<Fate>,
    /// Why it was given up, short of her signing F.
    pub abandoned: Option<String>,
    pub created_at: i64,
    /// Its fold's txid, once she closed it early with its hub.
    pub folded: Option<Txid>,
    /// What she funded of it herself, in sat: notes its hub issues her
    /// once F is buried, else her recovery claims.
    pub funded: u64,
    /// Whether her wallet received those notes.
    pub funded_received: bool,
}

impl Contract {
    /// Whether it protects notes now: F buried, its assertion deadline
    /// ahead of `tip`, not closed early.
    pub fn live(&self, tip: u32) -> bool {
        self.fate == Some(Fate::Live) && tip < self.assert_height && self.folded.is_none()
    }

    /// Whether it is at the hub reached at any of `urls`.
    pub fn at(&self, urls: &[String]) -> bool {
        let hub = self.hub.trim_end_matches('/');
        urls.iter().any(|url| url.trim_end_matches('/') == hub)
    }

    /// Whether nothing is left to do for it: given up, F never to
    /// confirm, closed early, or past its close.
    pub fn over(&self, tip: u32) -> bool {
        self.abandoned.is_some()
            || self.fate == Some(Fate::Dead)
            || self.folded.is_some()
            || tip >= self.close_height
    }
}

/// The new contract's row.
pub(super) struct New<'a> {
    pub id: [u8; 32],
    pub hub: &'a str,
    pub mock: bool,
    pub deposit: OutPoint,
    pub value: u64,
    pub price: u64,
    pub cap: u32,
    pub assert_height: u32,
    pub close_height: u32,
    /// The chain's height as she started: no spend of F's inputs that
    /// matters is in a block before.
    pub since: u32,
    pub state: &'a [u8],
}

/// The component of her openings paid for with notes ([`super::paid`]),
/// and its version: made with the first. A file without it holds none.
const PAID_COMPONENT: &str = "contract_paid";
const PAID_VERSION: i64 = 1;
const PAID_SCHEMA: &str = "
-- Each opening she pays for with notes, by its payout's ticket, kept before
-- the payout is made: the hub, what she asked of it, the coin's value, how
-- many times an opening on the coin failed, and once over, why.
CREATE TABLE contract_paid (
    ticket TEXT PRIMARY KEY,
    hub TEXT NOT NULL,
    blocks INTEGER NOT NULL,
    max_price INTEGER NOT NULL CHECK (max_price >= 0),
    cap INTEGER,
    value INTEGER NOT NULL CHECK (value > 0),
    tries INTEGER NOT NULL DEFAULT 0,
    ended TEXT,
    created_at INTEGER NOT NULL
) STRICT;
";

/// An opening paid for with notes, as kept (`Store::paid`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaidRow {
    pub ticket: String,
    pub hub: String,
    pub blocks: u32,
    pub max_price: u64,
    pub cap: Option<u32>,
    pub value: u64,
    pub tries: u32,
    pub ended: Option<String>,
    pub created_at: i64,
}

pub(super) struct Store {
    c: Connection,
    kept: PathBuf,
}

impl Store {
    /// The contracts in the wallet's file `wallet_file`, if any were ever
    /// opened there: none in a wallet that never opened one, which this
    /// leaves as it is.
    pub fn existing(wallet_file: &Path) -> Result<Option<Self>> {
        if !wallet_file.is_file() {
            return Ok(None);
        }
        let Some(c) = licash_store::inspect(wallet_file, Kind::Wallet)? else {
            return Ok(None);
        };
        if licash_store::component_version(&c, COMPONENT)?.is_none() {
            return Ok(None);
        }
        drop(c);
        Self::open(wallet_file).map(Some)
    }

    /// The contracts in the wallet's file `wallet_file`, made if none were.
    pub fn open(wallet_file: &Path) -> Result<Self> {
        let mut c = licash_store::open(wallet_file, Kind::Wallet)?;
        licash_store::component(&mut c, COMPONENT, VERSION, SCHEMA)?;
        let kept = wallet_file
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(KEPT_DIR);
        Ok(Self { c, kept })
    }

    /// Keep the opening at `hub` paid for by the payout `ticket`, of a coin
    /// worth `value`, before the payout is made.
    pub fn insert_paid(
        &self,
        ticket: &str,
        hub: &str,
        (blocks, max_price, cap): (u32, u64, Option<u32>),
        value: u64,
    ) -> Result<()> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        licash_store::component_in(&t, PAID_COMPONENT, PAID_VERSION, PAID_SCHEMA)?;
        t.execute(
            "INSERT INTO contract_paid (ticket, hub, blocks, max_price, cap, value, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ticket,
                hub,
                blocks,
                i64::try_from(max_price)?,
                cap,
                i64::try_from(value)?,
                crate::now()
            ],
        )?;
        t.commit()?;
        Ok(())
    }

    /// The openings paid for with notes, the oldest first: none in a file
    /// that never kept one.
    pub fn paid(&self) -> Result<Vec<PaidRow>> {
        match licash_store::component_version(&self.c, PAID_COMPONENT)? {
            None => return Ok(Vec::new()),
            Some(PAID_VERSION) => {}
            Some(v) => bail!("{PAID_COMPONENT} of version {v}, this build reads {PAID_VERSION}"),
        }
        let mut stmt = self.c.prepare(
            "SELECT ticket, hub, blocks, max_price, cap, value, tries, ended, created_at
             FROM contract_paid ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PaidRow {
                ticket: r.get(0)?,
                hub: r.get(1)?,
                blocks: r.get(2)?,
                max_price: r.get::<_, i64>(3)? as u64,
                cap: r.get(4)?,
                value: r.get::<_, i64>(5)? as u64,
                tries: r.get(6)?,
                ended: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// One more opening on the coin of `ticket` failed: how many have.
    pub fn paid_tried(&self, ticket: &str) -> Result<u32> {
        Ok(self.c.query_row(
            "UPDATE contract_paid SET tries = tries + 1 WHERE ticket = ?1 RETURNING tries",
            [ticket],
            |r| r.get(0),
        )?)
    }

    /// The opening paid for by `ticket` over, and `why`.
    pub fn end_paid(&self, ticket: &str, why: &str) -> Result<()> {
        self.c.execute(
            "UPDATE contract_paid SET ended = ?2 WHERE ticket = ?1 AND ended IS NULL",
            params![ticket, why],
        )?;
        Ok(())
    }

    /// [`Store::insert_under`] of a hub that charges nothing, for tests.
    #[cfg(test)]
    pub fn insert(&self, new: &New<'_>) -> Result<()> {
        self.insert_under(new, &Fees::default(), 0)
    }

    /// Insert a contract with the ceilings of its hub's `fees`, the most it
    /// may charge her, and the sat she `funded` of it herself, if any, in
    /// the same write.
    pub fn insert_under(&self, new: &New<'_>, fees: &Fees, funded: u64) -> Result<()> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        insert(&t, new, fees)?;
        if funded > 0 {
            t.execute(
                "INSERT INTO contract_funded (id, amount) VALUES (?1, ?2)",
                params![new.id, i64::try_from(funded)?],
            )?;
        }
        t.commit()?;
        Ok(())
    }

    /// The contracts whose funded notes her wallet has not received yet.
    pub fn funded_unreceived(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .c
            .prepare("SELECT id FROM contract_funded WHERE received_at IS NULL")?;
        let ids = stmt.query_map([], |r| r.get(0))?;
        Ok(ids.collect::<rusqlite::Result<_>>()?)
    }

    /// The funded notes of contract `id`, all received by her wallet.
    pub fn funded_received(&self, id: &[u8; 32]) -> Result<()> {
        self.c.execute(
            "UPDATE contract_funded SET received_at = ?2 WHERE id = ?1 AND received_at IS NULL",
            params![id, crate::now()],
        )?;
        Ok(())
    }

    /// Opening `id`'s instance `i`, answered by its hub as had.
    pub fn served(&self, id: &[u8; 32], i: u32) -> Result<()> {
        self.c.execute(
            "INSERT INTO contract_served (id, i) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![id, i],
        )?;
        Ok(())
    }

    /// The instances of opening `id` its hub answered as had: none if
    /// none was.
    pub fn served_of(&self, id: &[u8; 32]) -> Result<std::collections::BTreeSet<u32>> {
        let mut stmt = self
            .c
            .prepare("SELECT i FROM contract_served WHERE id = ?1")?;
        let rows = stmt.query_map([id], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Opening `id`'s instances to be sent again, all of them.
    pub fn unserve(&self, id: &[u8; 32]) -> Result<()> {
        self.c
            .execute("DELETE FROM contract_served WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Her consent to exit, if given: where to pay out, and the exit
    /// margin she gave with it. None if never given or revoked.
    pub fn exit_consent(&self) -> Result<Option<(String, u32, i64)>> {
        Ok(self
            .c
            .query_row(
                "SELECT address, exit_margin, given_at FROM contract_exit_consent WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Her consent to exit, paying out to `address`, with `exit_margin`:
    /// in place of any given before.
    pub fn consent_to_exit(&self, address: &str, exit_margin: u32) -> Result<()> {
        self.c.execute(
            "INSERT INTO contract_exit_consent (id, address, exit_margin, given_at)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET address = ?1, exit_margin = ?2, given_at = ?3",
            params![address, exit_margin, crate::now()],
        )?;
        Ok(())
    }

    /// Her consent to exit revoked, if given.
    pub fn revoke_exit_consent(&self) -> Result<()> {
        self.c.execute("DELETE FROM contract_exit_consent", [])?;
        Ok(())
    }

    /// The exit's payout `ticket`, for contract `id` from the hub at `hub`,
    /// at block `at`: kept before it is paid.
    pub fn exit_payout(&self, ticket: &str, id: &[u8; 32], hub: &str, at: u32) -> Result<()> {
        self.c.execute(
            "INSERT INTO contract_exit_payouts (ticket, contract, hub, height)
             VALUES (?1, ?2, ?3, ?4)",
            params![ticket, id, hub, at],
        )?;
        Ok(())
    }

    /// The tickets of the payouts the exit made for contract `id`.
    pub fn exit_payouts(&self, id: &[u8; 32]) -> Result<Vec<String>> {
        let mut stmt = self.c.prepare(
            "SELECT ticket FROM contract_exit_payouts WHERE contract = ?1 ORDER BY height",
        )?;
        let tickets = stmt.query_map([id], |r| r.get(0))?;
        Ok(tickets.collect::<rusqlite::Result<_>>()?)
    }

    /// Contract `id` closed early by the fold `txid`, before the hub can
    /// sign it.
    pub fn fold(&self, id: &[u8; 32], txid: &Txid) -> Result<()> {
        self.c.execute(
            "INSERT INTO contract_folds (id, txid, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET txid = ?2, created_at = ?3",
            params![id, serialize(txid), crate::now()],
        )?;
        Ok(())
    }

    /// The most the hub of each contract may charge her: none of one whose
    /// own cannot be read.
    pub fn ceilings(&self) -> Result<HashMap<[u8; 32], Fees>> {
        let mut stmt = self.c.prepare("SELECT id, ceiling_fees FROM contracts")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut all = HashMap::new();
        for row in rows {
            let (id, text) = row?;
            match serde_json::from_str(&text) {
                Ok(fees) => {
                    all.insert(id, fees);
                }
                Err(e) => tracing::warn!(
                    id = %crate::hex_id(&id),
                    "a contract's fee ceilings cannot be read, as if it kept none: {e}"
                ),
            }
        }
        Ok(all)
    }

    /// Raise the ceilings of each of `ids` to `fees`, fee by fee: none
    /// lowered. How many were raised.
    pub fn raise_ceilings(&self, ids: &[[u8; 32]], fees: &Fees) -> Result<usize> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        let mut raised = 0;
        for id in ids {
            let kept: Option<String> = t
                .query_row(
                    "SELECT ceiling_fees FROM contracts WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(was) = kept.and_then(|text| serde_json::from_str::<Fees>(&text).ok()) else {
                continue;
            };
            let now = was.most(fees);
            if now == was {
                continue;
            }
            let (from, to) = (serde_json::to_string(&was)?, serde_json::to_string(&now)?);
            t.execute(
                "UPDATE contracts SET ceiling_fees = ?2, ceiling_updated_at = ?3 WHERE id = ?1",
                params![id, to, crate::now()],
            )?;
            tracing::info!(id = %crate::hex_id(id), %from, %to, "a contract's fee ceilings raised");
            raised += 1;
        }
        t.commit()?;
        Ok(raised)
    }

    /// Each contract's claim terms kept, by id.
    pub(super) fn claim_terms(&self) -> Result<HashMap<[u8; 32], KeptTerms>> {
        let mut stmt = (self.c)
            .prepare("SELECT id, keyset, authorizations, program FROM contract_claim_terms")?;
        let rows = stmt.query_map([], |r| {
            let terms = KeptTerms {
                keyset: r.get(1)?,
                authorizations: r.get(2)?,
                program: r.get(3)?,
            };
            Ok((r.get(0)?, terms))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Keep the claim terms of `id`, as its state has them: of a contract
    /// it keeps only, once.
    pub(super) fn keep_claim_terms(&self, id: &[u8; 32], terms: &KeptTerms) -> Result<()> {
        self.c.execute(
            "INSERT OR IGNORE INTO contract_claim_terms (id, keyset, authorizations, program)
             SELECT ?1, ?2, ?3, ?4 WHERE EXISTS (SELECT 1 FROM contracts WHERE id = ?1)",
            params![id, terms.keyset, terms.authorizations, terms.program],
        )?;
        Ok(())
    }

    /// Opening `id` after a step: its phase, F once known, its state.
    /// Irrevocable from [`Phase::Funded`] on, in the same write: her
    /// signature of F leaves only after.
    pub fn save(
        &self,
        id: &[u8; 32],
        phase: Phase,
        funding: Option<Txid>,
        state: &[u8],
    ) -> Result<()> {
        self.c.execute(
            "UPDATE contracts SET phase = ?2, funding = ?3, state = ?4, updated_at = ?5,
                                  irrevocable = max(irrevocable, ?6)
             WHERE id = ?1",
            params![
                id,
                phase as u8,
                funding.map(|t| serialize(&t)),
                state,
                crate::now(),
                phase == Phase::Funded
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn set_fate(&self, id: &[u8; 32], fate: Fate) -> Result<()> {
        self.settle_fate(id, fate, None)
    }

    /// F of contract `id` found to be `fate`: if live, in `block`, its
    /// height and hash, followed from then on ([`SCHEMA`]'s `contract_fate_blocks`).
    pub fn settle_fate(
        &self,
        id: &[u8; 32],
        fate: Fate,
        block: Option<(u32, BlockHash)>,
    ) -> Result<()> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        t.execute(
            "UPDATE contracts SET fate = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, fate_text(fate), crate::now()],
        )?;
        match block.filter(|_| fate == Fate::Live) {
            Some((height, hash)) => {
                t.execute(
                    "INSERT INTO contract_fate_blocks (id, height, hash) VALUES (?1, ?2, ?3)
                     ON CONFLICT (id) DO UPDATE SET height = ?2, hash = ?3",
                    params![id, height, bitcoin::hashes::Hash::as_byte_array(&hash)],
                )?;
            }
            None => unfollow(&t, id)?,
        }
        t.commit()?;
        Ok(())
    }

    /// The block F of contract `id` was found buried in, its height and
    /// hash, while followed.
    pub fn fate_block(&self, id: &[u8; 32]) -> Result<Option<(u32, BlockHash)>> {
        let row: Option<(u32, [u8; 32])> = self
            .c
            .query_row(
                "SELECT height, hash FROM contract_fate_blocks WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map(|(height, hash)| {
            (
                height,
                <BlockHash as bitcoin::hashes::Hash>::from_byte_array(hash),
            )
        }))
    }

    /// The block F of contract `id` was found buried in left the chain:
    /// its fate open again, to be found anew.
    pub fn unbury(&self, id: &[u8; 32]) -> Result<()> {
        self.settle_fate(id, Fate::Open, None)
    }

    /// Give up opening `id` short of her signing F, and why: never one
    /// irrevocable. Its kept instances go: no contract can need them.
    pub fn abandon(&self, id: &[u8; 32], reason: &str) -> Result<()> {
        let given_up = self.c.execute(
            "UPDATE contracts SET abandoned = ?2, updated_at = ?3
             WHERE id = ?1 AND abandoned IS NULL AND irrevocable = 0",
            params![id, reason, crate::now()],
        )?;
        if given_up == 1 {
            self.forget(id)?;
        }
        Ok(())
    }

    /// Remove the instances opening `id` kept, once it can never be a
    /// contract: given up, or its F never to confirm.
    pub fn forget(&self, id: &[u8; 32]) -> Result<()> {
        let dir = self.kept.join(crate::hex_id(id));
        match std::fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("{}", dir.display()))
            }
            _ => Ok(()),
        }
    }

    /// The stored state of opening `id`, and the height she started at.
    pub fn state(&self, id: &[u8; 32]) -> Result<(Vec<u8>, u32)> {
        let row = self
            .c
            .query_row(
                "SELECT format, state, since_height FROM contracts WHERE id = ?1",
                [id],
                |r| Ok((r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            Some((FORMAT, state, since)) => Ok((state, since)),
            Some((format, ..)) => bail!("a contract stored in format {format}, unknown"),
            None => bail!("no contract {}", crate::hex_id(id)),
        }
    }

    /// Every contract, the newest first.
    pub fn list(&self) -> Result<Vec<Contract>> {
        let mut stmt = self.c.prepare(
            "SELECT id, hub, phase, mock, deposit, value, price, cap, assert_height,
                    close_height, funding, fate, abandoned, created_at, since_height,
                    (SELECT txid FROM contract_folds WHERE contract_folds.id = contracts.id),
                    (SELECT amount FROM contract_funded WHERE contract_funded.id = contracts.id),
                    (SELECT received_at IS NOT NULL FROM contract_funded
                     WHERE contract_funded.id = contracts.id)
             FROM contracts ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, [u8; 32]>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u8>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                (
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, u32>(7)?,
                ),
                (r.get::<_, u32>(8)?, r.get::<_, u32>(9)?),
                r.get::<_, Option<Vec<u8>>>(10)?,
                r.get::<_, Option<String>>(11)?,
                r.get::<_, Option<String>>(12)?,
                r.get::<_, i64>(13)?,
                (r.get::<_, u32>(14)?, r.get::<_, Option<Vec<u8>>>(15)?),
                (r.get::<_, Option<i64>>(16)?, r.get::<_, Option<bool>>(17)?),
            ))
        })?;
        let mut all = Vec::new();
        for row in rows {
            let (
                id,
                hub,
                phase,
                mock,
                deposit,
                (value, price, cap),
                heights,
                funding,
                fate,
                abandoned,
                created_at,
                (since, folded),
                (funded, received),
            ) = row?;
            let phase = *Phase::ALL
                .get(usize::from(phase))
                .with_context(|| format!("a contract of phase {phase}, unknown"))?;
            all.push(Contract {
                id,
                hub,
                phase,
                mock,
                deposit: deserialize(&deposit)?,
                value: value as u64,
                price: price as u64,
                cap,
                assert_height: heights.0,
                close_height: heights.1,
                since,
                funding: funding.map(|t| deserialize(&t)).transpose()?,
                fate: fate.as_deref().map(text_fate).transpose()?,
                abandoned,
                created_at,
                folded: folded.map(|t| deserialize(&t)).transpose()?,
                funded: funded.map_or(0, |f| f as u64),
                funded_received: received.unwrap_or(false),
            });
        }
        Ok(all)
    }

    /// Keep instance `index` of assertion `stage` of opening `id`, on disk
    /// before her state names it. Openings keep none now: what older ones
    /// kept goes with them.
    #[cfg(test)]
    pub fn keep(&self, id: &[u8; 32], stage: usize, index: usize, bytes: &[u8]) -> Result<()> {
        let dir = self.kept.join(crate::hex_id(id));
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&dir)
            .with_context(|| format!("{}", dir.display()))?;
        let path = dir.join(format!("{stage}-{index}"));
        let aside = dir.join(format!("{stage}-{index}.new"));
        let mut file = std::fs::File::create(&aside)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&aside, &path)?;
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    }

    /// Start recovering contract `id`, at `stage` with `state`, made
    /// revocable: false if it is recovering already.
    pub fn start_recovery(
        &self,
        id: &[u8; 32],
        format: i64,
        stage: &str,
        state: &[u8],
    ) -> Result<bool> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        let known: Option<i64> = t
            .query_row("SELECT 1 FROM contracts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        ensure!(known.is_some(), "no contract {}", crate::hex_id(id));
        let now = crate::now();
        let started = t.execute(
            "INSERT OR IGNORE INTO contract_recoveries (id, format, stage, irrevocable, state, created_at,
                                               updated_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5, ?5)",
            params![id, format, stage, state, now],
        )?;
        t.commit()?;
        Ok(started == 1)
    }

    /// Recovery `id` at stage `to` with `state`, from stage `from` and
    /// state `was` only; irrevocable from then on if `irrevocable`, in the
    /// same write. False if another step moved it on meanwhile, or it was
    /// given up (and started again) since `was` was read.
    pub fn save_recovery(
        &self,
        id: &[u8; 32],
        (from, was): (&str, &[u8]),
        to: &str,
        irrevocable: bool,
        state: &[u8],
    ) -> Result<bool> {
        let saved = self.c.execute(
            "UPDATE contract_recoveries SET stage = ?4, state = ?5, irrevocable = max(irrevocable, ?6),
                                   error = NULL, updated_at = ?7
             WHERE id = ?1 AND stage = ?2 AND state = ?3",
            params![id, from, was, to, state, irrevocable, crate::now()],
        )?;
        Ok(saved == 1)
    }

    /// Recovery `id` at stage `to` whatever its stage, `error` why, only
    /// while revocable: giving it up, before its notes are given back.
    /// False if it is irrevocable, or none is.
    pub fn revoke_recovery(&self, id: &[u8; 32], to: &str, error: Option<&str>) -> Result<bool> {
        let revoked = self.c.execute(
            "UPDATE contract_recoveries SET stage = ?2, error = ?3, updated_at = ?4
             WHERE id = ?1 AND irrevocable = 0",
            params![id, to, error, crate::now()],
        )?;
        Ok(revoked == 1)
    }

    /// What stopped recovery `id`'s last step, or none.
    pub fn recovery_error(&self, id: &[u8; 32], error: Option<&str>) -> Result<()> {
        self.c.execute(
            "UPDATE contract_recoveries SET error = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, error, crate::now()],
        )?;
        Ok(())
    }

    /// Forget recovery `id`, given up: never one irrevocable. False if it
    /// is, or none was.
    pub fn drop_recovery(&self, id: &[u8; 32]) -> Result<bool> {
        let dropped = self.c.execute(
            "DELETE FROM contract_recoveries WHERE id = ?1 AND irrevocable = 0",
            [id],
        )?;
        Ok(dropped == 1)
    }

    /// The tips recovery `id` saw, each its height and hash, the newest
    /// first ([`RECOVERY_TIPS`]).
    pub fn recovery_tips(&self, id: &[u8; 32]) -> Result<Vec<(u32, BlockHash)>> {
        let mut q = self.c.prepare(
            "SELECT height, hash FROM contract_recovery_tips WHERE id = ?1 ORDER BY height DESC",
        )?;
        let rows = q.query_map([id], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, [u8; 32]>(1)?))
        })?;
        rows.map(|row| {
            let (height, hash) = row?;
            Ok((
                height,
                <BlockHash as bitcoin::hashes::Hash>::from_byte_array(hash),
            ))
        })
        .collect()
    }

    /// Recovery `id` saw `hash` at the tip, `height`: kept, those below
    /// thinned out to the lowest of each power of two blocks back, so that
    /// the first stays. Not kept should one at or above it be: what that
    /// one shows of the chain stays to be looked at.
    pub fn see_recovery_tip(&self, id: &[u8; 32], height: u32, hash: BlockHash) -> Result<()> {
        let t = rusqlite::Transaction::new_unchecked(&self.c, TransactionBehavior::Immediate)?;
        let higher: Option<i64> = t
            .query_row(
                "SELECT 1 FROM contract_recovery_tips WHERE id = ?1 AND height >= ?2",
                params![id, height],
                |r| r.get(0),
            )
            .optional()?;
        if higher.is_some() {
            return Ok(());
        }
        t.execute(
            "INSERT INTO contract_recovery_tips (id, height, hash) VALUES (?1, ?2, ?3)",
            params![
                id,
                height,
                <BlockHash as bitcoin::hashes::Hash>::to_byte_array(hash)
            ],
        )?;
        let heights: Vec<u32> = t
            .prepare("SELECT height FROM contract_recovery_tips WHERE id = ?1 ORDER BY height")?
            .query_map([id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut last = None;
        for h in heights {
            let back = u64::from(height - h) + 1;
            let band = u64::BITS - back.leading_zeros();
            if last == Some(band) {
                t.execute(
                    "DELETE FROM contract_recovery_tips WHERE id = ?1 AND height = ?2",
                    params![id, h],
                )?;
            }
            last = Some(band);
        }
        t.commit()?;
        Ok(())
    }

    /// The tips recovery `id` saw above `height` forgotten: of a chain
    /// replaced since.
    pub fn forget_recovery_tips(&self, id: &[u8; 32], height: u32) -> Result<()> {
        self.c.execute(
            "DELETE FROM contract_recovery_tips WHERE id = ?1 AND height > ?2",
            params![id, height],
        )?;
        Ok(())
    }

    /// Recovery `id`, if she forced it closed.
    pub fn recovery(&self, id: &[u8; 32]) -> Result<Option<RecoveryRow>> {
        Ok(self.recoveries()?.into_iter().find(|r| &r.id == id))
    }

    /// Every recovery, the oldest first.
    pub fn recoveries(&self) -> Result<Vec<RecoveryRow>> {
        let mut stmt = self.c.prepare(
            "SELECT id, format, stage, irrevocable, state, error, created_at
             FROM contract_recoveries ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RecoveryRow {
                id: r.get(0)?,
                format: r.get(1)?,
                stage: r.get(2)?,
                irrevocable: r.get(3)?,
                state: r.get(4)?,
                error: r.get(5)?,
                created_at: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

fn insert(c: &Connection, new: &New<'_>, fees: &Fees) -> Result<()> {
    let now = crate::now();
    c.execute(
        "INSERT INTO contracts (id, hub, format, phase, mock, irrevocable, deposit, value, price, cap,
                                assert_height, close_height, since_height, state, created_at,
                                updated_at, ceiling_fees, ceiling_updated_at)
         VALUES (?1, ?2, ?3, 0, ?4, 0, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, ?14, ?13)",
        params![
            new.id,
            new.hub,
            FORMAT,
            new.mock,
            serialize(&new.deposit),
            i64::try_from(new.value)?,
            i64::try_from(new.price)?,
            new.cap,
            new.assert_height,
            new.close_height,
            new.since,
            new.state,
            now,
            serde_json::to_string(fees)?
        ],
    )?;
    Ok(())
}

/// The block of contract `id`'s F no longer followed, if it was.
fn unfollow(c: &Connection, id: &[u8; 32]) -> Result<()> {
    c.execute("DELETE FROM contract_fate_blocks WHERE id = ?1", [id])?;
    Ok(())
}

fn fate_text(fate: Fate) -> &'static str {
    match fate {
        Fate::Live => "live",
        Fate::Dead => "dead",
        Fate::Open => "open",
    }
}

fn text_fate(text: &str) -> Result<Fate> {
    Ok(match text {
        "live" => Fate::Live,
        "dead" => Fate::Dead,
        "open" => Fate::Open,
        other => bail!("a fate {other}, unknown"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new(id: u8, deposit: OutPoint) -> New<'static> {
        New {
            id: [id; 32],
            hub: "http://hub.example",
            mock: true,
            deposit,
            value: 60_000,
            price: 23_000,
            cap: 4_096,
            assert_height: 360,
            close_height: 500,
            since: 200,
            state: b"state",
        }
    }

    fn coin(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout,
        }
    }

    use bitcoin::hashes::Hash as _;

    #[test]
    fn nothing_is_made_until_a_contract_opens() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Store::existing(&crate::testing::wallet_file(dir.path()))
            .unwrap()
            .is_none());
        assert!(!dir.path().join("contracts.sqlite").exists());
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(Store::existing(&crate::testing::wallet_file(dir.path()))
            .unwrap()
            .is_some());
    }

    #[test]
    fn contracts_list_as_stored_the_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store.insert(&new(2, coin(1))).unwrap();
        let f = Txid::from_byte_array([5; 32]);
        store
            .save(&[1; 32], Phase::Funded, Some(f), b"funded")
            .unwrap();
        store.set_fate(&[1; 32], Fate::Live).unwrap();
        let all = store.list().unwrap();
        assert_eq!(all.len(), 2);
        let first = all.iter().find(|c| c.id == [1; 32]).unwrap();
        assert_eq!(first.phase, Phase::Funded);
        assert_eq!((first.funding, first.fate), (Some(f), Some(Fate::Live)));
        assert_eq!(
            (first.deposit, first.value, first.price),
            (coin(0), 60_000, 23_000)
        );
        assert_eq!(
            (first.assert_height, first.close_height, first.since),
            (360, 500, 200)
        );
        assert!(first.live(359) && !first.live(360) && !first.over(499) && first.over(500));
        assert_eq!(store.state(&[1; 32]).unwrap(), (b"funded".to_vec(), 200));
        let second = all.iter().find(|c| c.id == [2; 32]).unwrap();
        assert_eq!((second.phase, second.fate), (Phase::Started, None));
    }

    #[test]
    fn a_contract_folded_protects_nothing_and_is_over_by_its_last_fold() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store.set_fate(&[1; 32], Fate::Live).unwrap();
        // None folded.
        assert_eq!(store.list().unwrap()[0].folded, None);
        let fold = Txid::from_byte_array([7; 32]);
        store.fold(&[1; 32], &fold).unwrap();
        let folded = &store.list().unwrap()[0];
        assert_eq!(folded.folded, Some(fold));
        assert!(!folded.live(300) && folded.over(300));
        // Asked again: the last.
        let again = Txid::from_byte_array([8; 32]);
        store.fold(&[1; 32], &again).unwrap();
        assert_eq!(store.list().unwrap()[0].folded, Some(again));
        assert!(!store.list().unwrap()[0].live(300));
    }

    /// Openings paid for with notes are kept in a component of their own,
    /// made with the first: a file without it holds none.
    #[test]
    fn openings_paid_for_with_notes_are_kept_until_over() {
        let dir = tempfile::tempdir().unwrap();
        let file = crate::testing::wallet_file(dir.path());
        let store = Store::open(&file).unwrap();
        assert_eq!(store.paid().unwrap(), Vec::new());
        let c = licash_store::inspect(&file, Kind::Wallet).unwrap().unwrap();
        assert_eq!(
            licash_store::component_version(&c, PAID_COMPONENT).unwrap(),
            None
        );
        store
            .insert_paid("ab", "http://a.test", (1_000, 30_000, None), 21_001)
            .unwrap();
        assert!(store
            .insert_paid("ab", "http://a.test", (1_000, 30_000, None), 21_001)
            .is_err());
        assert_eq!(store.paid_tried("ab").unwrap(), 1);
        assert_eq!(store.paid_tried("ab").unwrap(), 2);
        store.end_paid("ab", "opened").unwrap();
        // Over once: why stays.
        store.end_paid("ab", "again").unwrap();
        let rows = store.paid().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            (
                row.hub.as_str(),
                row.blocks,
                row.max_price,
                row.cap,
                row.value
            ),
            ("http://a.test", 1_000, 30_000, None, 21_001)
        );
        assert_eq!((row.tries, row.ended.as_deref()), (2, Some("opened")));
    }

    #[test]
    fn a_coin_is_the_deposit_of_one_live_contract_at_most() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        assert!(store.insert(&new(2, coin(0))).is_err());
        store.abandon(&[1; 32], "refused").unwrap();
        store.insert(&new(2, coin(0))).unwrap();
        store
            .save(&[2; 32], Phase::Funded, None, b"funded")
            .unwrap();
        store.set_fate(&[2; 32], Fate::Dead).unwrap();
        store.insert(&new(3, coin(0))).unwrap();
    }

    #[test]
    fn a_contract_she_signed_is_never_given_up() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store.keep(&[1; 32], 0, 2, b"instance").unwrap();
        store
            .save(&[1; 32], Phase::Funded, None, b"funded")
            .unwrap();
        // A later step never takes it back.
        store
            .save(&[1; 32], Phase::Signing, None, b"signing")
            .unwrap();
        store.abandon(&[1; 32], "refused").unwrap();
        assert_eq!(store.list().unwrap()[0].abandoned, None);
        let kept = dir.path().join("contracts").join(crate::hex_id(&[1; 32]));
        assert_eq!(std::fs::read(kept.join("0-2")).unwrap(), b"instance");
    }

    #[test]
    fn what_a_contract_given_up_kept_goes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store.keep(&[1; 32], 1, 3, b"instance").unwrap();
        let kept = dir.path().join("contracts").join(crate::hex_id(&[1; 32]));
        assert!(kept.join("1-3").exists() && !kept.join("1-3.new").exists());
        store.abandon(&[1; 32], "refused").unwrap();
        assert_eq!(
            store.list().unwrap()[0].abandoned.as_deref(),
            Some("refused")
        );
        assert!(!kept.exists());
        // Again, or with nothing kept: no error.
        store.forget(&[1; 32]).unwrap();
    }

    #[test]
    fn nothing_is_made_by_reading_and_a_recovery_starts_once_for_a_known_contract() {
        let dir = tempfile::tempdir().unwrap();
        let file = crate::testing::wallet_file(dir.path());
        // A wallet's file that never opened a contract holds none, and
        // reading it makes none.
        assert!(Store::existing(&file).unwrap().is_none());
        let c = licash_store::open(&file, Kind::Wallet).unwrap();
        assert_eq!(
            licash_store::component_version(&c, COMPONENT).unwrap(),
            None
        );
        drop(c);

        let store = Store::open(&file).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store
            .save(&[1; 32], Phase::Funded, None, b"funded")
            .unwrap();
        store.set_fate(&[1; 32], Fate::Live).unwrap();
        let before = store.list().unwrap();
        drop(store);
        // Opened, listed, read: as it was.
        let store = Store::existing(&file).unwrap().unwrap();
        assert!(store.recoveries().unwrap().is_empty());
        assert!(store.recovery(&[1; 32]).unwrap().is_none());
        assert!(!store.drop_recovery(&[1; 32]).unwrap());

        assert!(store.start_recovery(&[1; 32], 1, "claiming", b"s").unwrap());
        assert_eq!(store.list().unwrap(), before);
        assert_eq!(store.state(&[1; 32]).unwrap(), (b"funded".to_vec(), 200));
        let row = store.recovery(&[1; 32]).unwrap().unwrap();
        assert_eq!((row.format, row.stage.as_str()), (1, "claiming"));
        assert!(!row.irrevocable && row.state == b"s" && row.error.is_none());
        // Again: refused, as it was.
        assert!(!store.start_recovery(&[1; 32], 1, "claiming", b"t").unwrap());
        assert_eq!(store.recovery(&[1; 32]).unwrap().unwrap().state, b"s");
        drop(store);

        // Reopened.
        let store = Store::open(&file).unwrap();
        assert_eq!(store.recoveries().unwrap().len(), 1);
        // Of a contract it does not know: refused.
        assert!(store.start_recovery(&[2; 32], 1, "claiming", b"s").is_err());
    }

    fn fees(base: u64, ppm: u64, output_msat: u64) -> Fees {
        let fee = licash_api::Fee { base, ppm };
        Fees {
            spend: fee,
            lock: fee,
            refund: fee,
            output_msat,
        }
    }

    #[test]
    fn ceilings_are_kept_with_a_contract_and_a_refused_one_keeps_neither() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        let agreed = fees(1, 100, 100);
        store.insert_under(&new(2, coin(1)), &agreed, 0).unwrap();
        assert_eq!(
            store.ceilings().unwrap(),
            HashMap::from([([2; 32], agreed)])
        );
        // Neither its deposit taken nor its ceilings kept, if it is refused.
        assert!(store
            .insert_under(&new(3, coin(1)), &fees(0, 0, 0), 0)
            .is_err());
        assert_eq!(store.list().unwrap().len(), 1);
        assert_eq!(store.ceilings().unwrap().len(), 1);
        assert_eq!(store.ceilings().unwrap()[&[2; 32]], agreed);
        store.insert_under(&new(4, coin(2)), &agreed, 0).unwrap();
        assert_eq!(store.ceilings().unwrap().len(), 2);
    }

    #[test]
    fn claim_terms_are_kept_once_for_a_contract_it_knows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        // None kept.
        assert!(store.claim_terms().unwrap().is_empty());
        let terms = |keyset, authorizations, program| KeptTerms {
            keyset,
            authorizations,
            program,
        };
        store
            .keep_claim_terms(&[1; 32], &terms([7; 32], 128, [5; 32]))
            .unwrap();
        // Kept once: never changed after.
        store
            .keep_claim_terms(&[1; 32], &terms([8; 32], 2, [6; 32]))
            .unwrap();
        let kept = HashMap::from([([1; 32], terms([7; 32], 128, [5; 32]))]);
        assert_eq!(store.claim_terms().unwrap(), kept);
        // Of a contract it does not know: not kept.
        store
            .keep_claim_terms(&[2; 32], &terms([7; 32], 1, [5; 32]))
            .unwrap();
        assert_eq!(store.claim_terms().unwrap(), kept);
        drop(store);
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        assert_eq!(store.claim_terms().unwrap(), kept);
    }

    #[test]
    fn ceilings_are_raised_fee_by_fee_and_never_lowered() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store
            .insert_under(&new(1, coin(0)), &fees(2, 80, 100), 0)
            .unwrap();
        store
            .insert_under(&new(2, coin(1)), &fees(1, 100, 100), 0)
            .unwrap();
        store
            .insert_under(&new(3, coin(2)), &fees(5, 50, 0), 0)
            .unwrap();
        store
            .insert_under(&new(4, coin(3)), &fees(0, 0, 0), 0)
            .unwrap();
        // Of those named only, and only those it raises: the first holds
        // as much already.
        let all = [[1; 32], [2; 32], [3; 32]];
        assert_eq!(store.raise_ceilings(&all, &fees(2, 80, 100)).unwrap(), 2);
        let kept = store.ceilings().unwrap();
        assert_eq!(kept.len(), 4);
        assert_eq!(kept[&[1; 32]], fees(2, 80, 100));
        assert_eq!(kept[&[2; 32]], fees(2, 100, 100));
        assert_eq!(kept[&[3; 32]], fees(5, 80, 100));
        assert_eq!(kept[&[4; 32]], fees(0, 0, 0));
        assert_eq!(store.raise_ceilings(&all, &fees(2, 80, 100)).unwrap(), 0);
        assert_eq!(store.raise_ceilings(&all, &fees(0, 0, 0)).unwrap(), 0);
        assert_eq!(store.ceilings().unwrap(), kept);
    }

    #[test]
    fn ceilings_that_cannot_be_read_are_as_none_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store
            .insert_under(&new(1, coin(0)), &fees(1, 100, 100), 0)
            .unwrap();
        store
            .insert_under(&new(2, coin(1)), &fees(1, 100, 100), 0)
            .unwrap();
        store
            .c
            .execute(
                "UPDATE contracts SET ceiling_fees = 'not fees' WHERE id = ?1",
                [[1u8; 32]],
            )
            .unwrap();
        let kept = store.ceilings().unwrap();
        assert_eq!(kept.len(), 1);
        assert!(kept.contains_key(&[2; 32]));
        // Nor made up by her agreeing to more.
        let both = [[1; 32], [2; 32]];
        assert_eq!(store.raise_ceilings(&both, &fees(2, 100, 100)).unwrap(), 1);
        assert_eq!(store.ceilings().unwrap().len(), 1);
    }

    #[test]
    fn contracts_of_a_version_newer_than_it_knows_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = crate::testing::wallet_file(dir.path());
        drop(Store::open(&file).unwrap());
        let c = Connection::open(&file).unwrap();
        c.execute(
            "UPDATE schema_versions SET version = 3 WHERE component = 'contracts'",
            [],
        )
        .unwrap();
        drop(c);
        let refused = Store::open(&file).err().unwrap();
        assert!(format!("{refused:#}").contains("version 3"), "{refused:#}");
        // The file is not the holder's to make again.
        assert!(Store::existing(&file).is_err());
    }

    #[test]
    fn a_recovery_keeps_the_tips_it_saw_thinned_out_and_none_past_one_higher() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        let id = [1; 32];
        // None kept, nothing forgotten.
        assert!(store.recovery_tips(&id).unwrap().is_empty());
        store.forget_recovery_tips(&id, 0).unwrap();
        let hash = |h: u32| <BlockHash as bitcoin::hashes::Hash>::hash(&h.to_le_bytes());
        for h in 100..=200 {
            store.see_recovery_tip(&id, h, hash(h)).unwrap();
        }
        let heights: Vec<u32> = (store.recovery_tips(&id).unwrap().iter())
            .map(|&(h, _)| h)
            .collect();
        assert_eq!(heights, [200, 198, 196, 188, 180, 164, 100]);
        assert!(store
            .recovery_tips(&id)
            .unwrap()
            .iter()
            .all(|&(h, b)| b == hash(h)));
        // The tip seen again, of another block, or one lower: the one kept
        // stays, to tell the chain was replaced.
        store.see_recovery_tip(&id, 200, hash(0)).unwrap();
        store.see_recovery_tip(&id, 199, hash(0)).unwrap();
        assert_eq!(
            store.recovery_tips(&id).unwrap()[..2],
            [(200, hash(200)), (198, hash(198))]
        );
        store.forget_recovery_tips(&id, 190).unwrap();
        let heights: Vec<u32> = (store.recovery_tips(&id).unwrap().iter())
            .map(|&(h, _)| h)
            .collect();
        assert_eq!(heights, [188, 180, 164, 100]);
        store.see_recovery_tip(&id, 191, hash(191)).unwrap();
        // Of another recovery: none of its.
        assert!(store.recovery_tips(&[2; 32]).unwrap().is_empty());
    }

    #[test]
    fn a_recovery_moves_on_one_stage_at_a_time_and_is_dropped_only_while_revocable() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        store.start_recovery(&[1; 32], 1, "a", b"0").unwrap();
        store.recovery_error(&[1; 32], Some("offline")).unwrap();
        let save = |from: (&str, &[u8]), to: &str, irrevocable: bool, state: &[u8]| {
            store
                .save_recovery(&[1; 32], from, to, irrevocable, state)
                .unwrap()
        };
        assert!(save(("a", b"0"), "b", false, b"1"));
        // From a stage it left, or a state it no longer has: not saved.
        assert!(!save(("a", b"0"), "c", false, b"2"));
        assert!(!save(("b", b"0"), "c", false, b"2"));
        let row = store.recovery(&[1; 32]).unwrap().unwrap();
        assert_eq!((row.stage.as_str(), row.state.as_slice()), ("b", &b"1"[..]));
        assert_eq!(row.error, None);

        assert!(save(("b", b"1"), "c", true, b"2"));
        // Never revocable again.
        assert!(save(("c", b"2"), "d", false, b"3"));
        assert!(store.recovery(&[1; 32]).unwrap().unwrap().irrevocable);
        assert!(!store.revoke_recovery(&[1; 32], "x", None).unwrap());
        assert!(!store.drop_recovery(&[1; 32]).unwrap());
        assert_eq!(store.recovery(&[1; 32]).unwrap().unwrap().stage, "d");

        store.insert(&new(2, coin(1))).unwrap();
        store.start_recovery(&[2; 32], 1, "a", b"0").unwrap();
        let why = Some("why");
        assert!(store.revoke_recovery(&[2; 32], "giving-up", why).unwrap());
        let row = store.recovery(&[2; 32]).unwrap().unwrap();
        assert_eq!(
            (row.stage.as_str(), row.error.as_deref()),
            ("giving-up", why)
        );
        // A step that read it before: not saved.
        assert!(!store
            .save_recovery(&[2; 32], ("a", b"0"), "b", false, b"1")
            .unwrap());
        assert!(store.drop_recovery(&[2; 32]).unwrap());
        assert!(store.recovery(&[2; 32]).unwrap().is_none());
        // And started again.
        assert!(store.start_recovery(&[2; 32], 1, "a", b"0").unwrap());
    }

    #[test]
    fn a_snapshot_of_the_wallets_file_preserves_the_selected_mode_pinned_proof_and_irrevocable_row()
    {
        let dir = tempfile::tempdir().unwrap();
        let copy = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        let state = br#"{"amount":4096,"reduced":0}"#;
        store.start_recovery(&[1; 32], 2, "signing", state).unwrap();
        assert!(store
            .save_recovery(&[1; 32], ("signing", state), "signing", true, state)
            .unwrap());
        super::super::recovery::validate_backup(&store).unwrap();
        // One snapshot of the wallet's file is the contracts' too.
        let to = copy.path().join("snapshot.sqlite");
        licash_store::backup(&store.c, &to).unwrap();
        let copied = Store::existing(&to).unwrap().unwrap();
        let row = copied.recovery(&[1; 32]).unwrap().unwrap();
        assert_eq!(row.state, state);
        assert!(row.irrevocable);
        assert_eq!(row.stage, "signing");
        assert!(!copied.drop_recovery(&[1; 32]).unwrap());
        assert!(licash_store::backup(&store.c, &to).is_err());
        store
            .c
            .execute(
                "UPDATE contract_recoveries SET state = ?1",
                [br#"{"future_field":1}"#.as_slice()],
            )
            .unwrap();
        assert!(super::super::recovery::validate_backup(&store).is_err());
        super::super::recovery::validate_backup(&copied).unwrap();
    }

    #[test]
    fn the_instances_an_opening_kept_are_counted_once_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        store.insert(&new(1, coin(0))).unwrap();
        assert_eq!(kept(&crate::testing::wallet_file(dir.path()), &[1; 32]), 0);
        store.keep(&[1; 32], 0, 1, b"instance").unwrap();
        store.keep(&[1; 32], 1, 3, b"instance").unwrap();
        // One being written, as a stop leaves it: not yet.
        let aside = dir.path().join("contracts").join(crate::hex_id(&[1; 32]));
        std::fs::write(aside.join("1-0.new"), b"inst").unwrap();
        assert_eq!(kept(&crate::testing::wallet_file(dir.path()), &[1; 32]), 2);
        assert_eq!(kept(&crate::testing::wallet_file(dir.path()), &[2; 32]), 0);
        store.forget(&[1; 32]).unwrap();
        assert_eq!(kept(&crate::testing::wallet_file(dir.path()), &[1; 32]), 0);
    }
}
