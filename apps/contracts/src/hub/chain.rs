//! The hub's header chain: the Bitcoin headers its contracts of graph id
//! [`licash::recovery::CHAINED_FROM`] on are decided on, kept from the
//! checkpoint of the first such contract, extended as blocks arrive and proven
//! in batches in the background by the chain program (`licash-chain`), so
//! that a dispute proves what it contests and not the contract's age.
//!
//! **What is kept** (a component of `hub.sqlite`, and a file a receipt): the
//! chain's start, every header after it, and the receipts of the chain
//! program, each a succinct proof of the chain through its last block. The
//! rest ([`Lineage`]) is made of those on start, and a receipt that its chain
//! does not commit is not kept.
//!
//! **When a batch is proven.** A batch costs a segment or two of fixed
//! cycles, so one is made for a day of blocks, and for the blocks a dispute
//! needs at once ([`HubChain::demand`]): the hub's prover makes it when no
//! dispute's proof can run, and stops it, to carry on after, when one can.
//! Nothing is proven for the blocks no dispute asks for until a day of them
//! is behind.
//!
//! **Whose chain.** One for each chain program, of every contract the hub
//! opens under the statements that verify its receipts: the checkpoint of a
//! contract is a block of it ([`HubChain::covers`]), which the hub checks
//! before it quotes one.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use anyhow::{anyhow, bail, ensure, Context, Result};
use licash::chain::{sha256d, Checkpoint};
use licash::spend::ChainProfile;
use licash_chain::{Batch, Builder, Journal, Lineage, Origin, Tree};
use licash_statement::codec::{R, W};
use licash_store::Kind;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

/// The component the chain is, and its version.
const COMPONENT: &str = "header_chain";
const VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE chains (
    program BLOB PRIMARY KEY,
    start BLOB NOT NULL
) STRICT;
CREATE TABLE chain_headers (
    program BLOB NOT NULL,
    height INTEGER NOT NULL,
    header BLOB NOT NULL,
    PRIMARY KEY (program, height)
) STRICT, WITHOUT ROWID;
CREATE TABLE chain_receipts (
    program BLOB NOT NULL,
    count INTEGER NOT NULL,
    journal BLOB NOT NULL,
    tip BLOB NOT NULL,
    tree BLOB NOT NULL,
    digest BLOB NOT NULL,
    PRIMARY KEY (program, count)
) STRICT, WITHOUT ROWID;
";

/// The receipts kept besides the newest: a chain cut back by a reorg
/// resumes the newest of them its blocks still hold.
const KEPT: usize = 3;

/// How far below the chain's tip the newest receipt kept that is that deep
/// is: receipts made for disputes are a few blocks apart, so those kept alone
/// could all be taken back by a reorg, and the chain proven again from its
/// start.
const DEEP: u32 = 100;

/// The most blocks a reorg may take back before the chain is given up.
const REORG: u32 = 1_000;

/// The headers of the chain being followed: a node's, or a test's.
#[allow(async_fn_in_trait)]
pub(super) trait Headers {
    /// The height of the chain's tip.
    async fn tip(&self) -> Result<u32>;
    /// The hash (internal order) of the block at `height`.
    async fn hash(&self, height: u32) -> Result<[u8; 32]>;
    /// The header of the block `hash`.
    async fn header(&self, hash: &[u8; 32]) -> Result<[u8; 80]>;
}

#[cfg(feature = "node")]
impl Headers for licash_chain_client::Source {
    async fn tip(&self) -> Result<u32> {
        Ok(licash_chain_client::Source::tip(self).await?.height)
    }

    async fn hash(&self, height: u32) -> Result<[u8; 32]> {
        use bitcoin::hashes::Hash;
        Ok(licash_chain_client::Source::hash(self, height)
            .await?
            .to_byte_array())
    }

    async fn header(&self, hash: &[u8; 32]) -> Result<[u8; 80]> {
        use bitcoin::hashes::Hash;
        let hash = bitcoin::BlockHash::from_byte_array(*hash);
        let header = licash_chain_client::Source::header(self, &hash).await?;
        ensure!(header.block_hash() == hash, "header {hash}");
        bitcoin::consensus::serialize(&header)
            .try_into()
            .map_err(|_| anyhow!("a header of 80 bytes"))
    }
}

/// A receipt as `chain_receipts` has it.
struct Row {
    count: u32,
    journal: Vec<u8>,
    tip: Vec<u8>,
    tree: Vec<u8>,
    digest: Vec<u8>,
}

/// A receipt of the chain program that is kept: what its journal commits and
/// where its succinct receipt is.
#[derive(Clone)]
pub(super) struct Receipt {
    pub journal: Journal,
    /// The state of the chain's last block.
    pub tip: Checkpoint,
    tree: Tree,
    /// Its receipt, which a proof that verifies it is given (`--assume`).
    pub file: PathBuf,
}

/// A batch to prove: its input, where its receipt is to be made and the
/// receipt it resumes.
pub(super) struct Pending {
    /// The height of the last block it adds.
    pub through: u32,
    pub input: PathBuf,
    pub work: PathBuf,
    pub assume: Option<PathBuf>,
    /// A dispute waits for it: not stopped for another's proof.
    pub demanded: bool,
    receipt: Receipt,
}

struct State {
    conn: Connection,
    lineage: Option<Lineage>,
    /// Oldest first.
    receipts: Vec<Receipt>,
    /// The highest block a dispute needs a receipt of.
    demand: u32,
}

pub(super) struct HubChain {
    dir: PathBuf,
    program: [u8; 32],
    /// The blocks that make a day, which a batch is proven for.
    batch: u32,
    state: Mutex<State>,
}

fn tip_height(journal: &Journal) -> u32 {
    journal.tip_height()
}

impl HubChain {
    /// The chain of the chain program `program` kept in `data`'s
    /// `hub.sqlite`, on `profile`: made if there is none, not started until a
    /// contract's checkpoint is ([`HubChain::begin`]). A receipt that the
    /// headers kept do not commit to is left out, and why is the error of the
    /// second result.
    pub fn open(
        data: &Path,
        program: [u8; 32],
        profile: ChainProfile,
    ) -> Result<(Self, Option<String>)> {
        let mut conn = licash_store::open(&crate::hub_db(data), Kind::Hub)?;
        licash_store::component(&mut conn, COMPONENT, VERSION, SCHEMA)?;
        let dir = data.join("header-chain").join(hex::encode(program));
        std::fs::create_dir_all(&dir)?;
        let lineage = Self::load(&conn, &program)?;
        let mut told = None;
        let mut receipts = Vec::new();
        if let Some(lineage) = &lineage {
            let mut rows = conn.prepare(
                "SELECT count, journal, tip, tree, digest FROM chain_receipts WHERE program = ?1
                 ORDER BY count",
            )?;
            let rows: Vec<Row> = rows
                .query_map([&program[..]], |r| {
                    Ok(Row {
                        count: r.get(0)?,
                        journal: r.get(1)?,
                        tip: r.get(2)?,
                        tree: r.get(3)?,
                        digest: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            for row in rows {
                let count = row.count;
                let file = dir.join(format!("receipt-{count}"));
                match Self::kept(lineage, &program, row, file) {
                    Ok(receipt) => receipts.push(receipt),
                    Err(e) => told = Some(format!("the receipt of {count} blocks: {e:#}")),
                }
            }
        }
        let chain = Self {
            dir,
            program,
            batch: profile.blocks_a_day(),
            state: Mutex::new(State {
                conn,
                lineage,
                receipts,
                demand: 0,
            }),
        };
        Ok((chain, told))
    }

    fn load(conn: &Connection, program: &[u8; 32]) -> Result<Option<Lineage>> {
        let start: Option<Vec<u8>> = conn
            .query_row(
                "SELECT start FROM chains WHERE program = ?1",
                [&program[..]],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                e => Err(e),
            })?;
        let Some(start) = start else { return Ok(None) };
        let start =
            Checkpoint::from_bytes(&start).map_err(|e| anyhow!("the chain's start: {e}"))?;
        let mut lineage = Lineage::new(start).map_err(|e| anyhow!("{e}"))?;
        let mut rows = conn.prepare(
            "SELECT height, header FROM chain_headers WHERE program = ?1 ORDER BY height",
        )?;
        let rows = rows.query_map([&program[..]], |r| {
            Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (height, header) = row?;
            ensure!(
                height == lineage.tip_height() + 1,
                "the chain's headers are not in order at {height}"
            );
            let header = header
                .try_into()
                .map_err(|_| anyhow!("a header of 80 bytes"))?;
            lineage
                .push(header)
                .map_err(|e| anyhow!("the chain's header {height}: {e}"))?;
        }
        Ok(Some(lineage))
    }

    /// A receipt as a row has it, if the chain `lineage` commits it.
    fn kept(lineage: &Lineage, program: &[u8; 32], row: Row, file: PathBuf) -> Result<Receipt> {
        let bytes = std::fs::read(&file).map_err(|e| anyhow!("its file: {e}"))?;
        ensure!(
            Sha256::digest(&bytes)[..] == row.digest[..],
            "its file is not the one that was made"
        );
        let journal = Journal::from_bytes(&row.journal).context("its journal")?;
        let tip = Checkpoint::from_bytes(&row.tip).map_err(|e| anyhow!("its tip: {e}"))?;
        let tree = Tree::read(&mut R(&row.tree)).map_err(|e| anyhow!("its tree: {e}"))?;
        // as the chain was when the receipt was made
        let (expected, _) = lineage
            .through(*program, tip_height(&journal))
            .map_err(|e| anyhow!("{e}"))?;
        ensure!(expected == journal, "the chain does not commit it");
        Ok(Receipt {
            journal,
            tip,
            tree,
            file,
        })
    }

    /// A chain proven in batches of `blocks`, for tests of when one is due.
    #[cfg(test)]
    pub(super) fn with_batch(mut self, blocks: u32) -> Self {
        self.batch = blocks;
        self
    }

    /// The blocks a batch is proven for, a day's.
    pub fn batch_blocks(&self) -> u32 {
        self.batch
    }

    /// The chain program this chain is proven by.
    pub fn program(&self) -> [u8; 32] {
        self.program
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Start the chain at `start`, a checkpoint a contract is quoted on, if it
    /// has none.
    pub fn begin(&self, start: &Checkpoint) -> Result<()> {
        let mut s = self.state();
        if s.lineage.is_some() {
            return Ok(());
        }
        s.conn.execute(
            "INSERT INTO chains (program, start) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![&self.program[..], start.to_bytes()],
        )?;
        s.lineage = Some(Lineage::new(start.clone()).map_err(|e| anyhow!("{e}"))?);
        Ok(())
    }

    /// Whether `checkpoint` is a block of the chain, in the state the chain
    /// has it: what a contract quoted on it needs, for its statement opens
    /// the chain's leaf there and requires it to commit what its Base does.
    /// Why not, if not.
    pub fn covers(&self, checkpoint: &Checkpoint) -> Result<(), String> {
        let s = self.state();
        let Some(lineage) = &s.lineage else {
            return Err("the hub's header chain has not started".into());
        };
        let Some(leaf) = lineage.leaf(checkpoint.height()) else {
            return Err(format!(
                "block {} is not in the hub's header chain, which is of {} to {}",
                checkpoint.height(),
                lineage.start().height(),
                lineage.tip_height()
            ));
        };
        match leaf.state == checkpoint.commitment() {
            true => Ok(()),
            false => Err(format!(
                "the hub's header chain has block {} in another state than the checkpoint's",
                checkpoint.height()
            )),
        }
    }

    /// The chain's last block, if it has started.
    pub fn tip(&self) -> Option<u32> {
        self.state().lineage.as_ref().map(Lineage::tip_height)
    }

    /// Follow `source` through height `to` (or as far as it goes): the headers
    /// after the chain's tip, each on the last; after a reorg, from where the
    /// chain and the source still agree. Nothing if the chain has not
    /// started.
    pub async fn follow(&self, source: &impl Headers, to: u32) -> Result<()> {
        let Some((tip, hash)) = self.state().lineage.as_ref().map(|l| {
            let tip = l.tip_height();
            (tip, sha256d(l.header(tip).expect("its own tip")))
        }) else {
            return Ok(());
        };
        // A failure to ask is no reorg: the chain is cut back only on what the
        // node says of its blocks, never on what it fails to say.
        let node = source.tip().await?;
        let tip = match tip <= node && source.hash(tip).await? == hash {
            true => tip,
            false => self.reorg(source, tip, node).await?,
        };
        if to <= tip {
            return Ok(());
        }
        let mut have = source.hash(to).await?;
        let mut fetched = Vec::with_capacity((to - tip) as usize);
        for _ in tip..to {
            let header = source.header(&have).await?;
            have = header[4..36].try_into().expect("32 bytes");
            fetched.push(header);
        }
        fetched.reverse();
        let mut s = self.state();
        let Some(lineage) = s.lineage.as_mut() else {
            return Ok(());
        };
        // another follow got there first
        if lineage.tip_height() != tip {
            return Ok(());
        }
        let mut next = lineage.clone();
        for header in &fetched {
            next.push(*header)
                .map_err(|e| anyhow!("the node's header at {}: {e}", next.tip_height() + 1))?;
        }
        let tx = s.conn.transaction()?;
        for (i, header) in fetched.iter().enumerate() {
            tx.execute(
                "INSERT INTO chain_headers (program, height, header) VALUES (?1, ?2, ?3)",
                params![&self.program[..], tip + 1 + i as u32, &header[..]],
            )?;
        }
        tx.commit()?;
        s.lineage = Some(next);
        Ok(())
    }

    /// The chain's tip is no longer the source's block at its height: cut it
    /// back to the last block they agree on, and the receipts with it that
    /// went beyond. The height it is cut back to.
    async fn reorg(&self, source: &impl Headers, tip: u32, node: u32) -> Result<u32> {
        let start = self.state().lineage.as_ref().map(|l| l.start().height());
        let start = start.context("no chain")?;
        // from the node's tip down if it is lower than the chain's: it has no
        // block above it to agree on
        let mut at = tip.min(node.saturating_add(1));
        let agreed = loop {
            ensure!(
                at > start && tip - at < REORG,
                "the hub's header chain is {} blocks off the node's",
                tip - at
            );
            at -= 1;
            let hash = source.hash(at).await?;
            let ours = {
                let s = self.state();
                s.lineage
                    .as_ref()
                    .and_then(|l| l.header(at).map(|h| sha256d(h)))
            };
            if ours == Some(hash) {
                break at;
            }
        };
        let mut s = self.state();
        let cut = s
            .lineage
            .as_ref()
            .context("no chain")?
            .truncated(agreed)
            .map_err(|e| anyhow!("{e}"))?;
        let gone: Vec<u32> = s
            .receipts
            .iter()
            .filter(|r| tip_height(&r.journal) > agreed)
            .map(|r| r.journal.count)
            .collect();
        let tx = s.conn.transaction()?;
        tx.execute(
            "DELETE FROM chain_headers WHERE program = ?1 AND height > ?2",
            params![&self.program[..], agreed],
        )?;
        for count in &gone {
            tx.execute(
                "DELETE FROM chain_receipts WHERE program = ?1 AND count = ?2",
                params![&self.program[..], count],
            )?;
        }
        tx.commit()?;
        for count in &gone {
            let _ = std::fs::remove_file(self.dir.join(format!("receipt-{count}")));
        }
        // the work kept of batches the blocks taken back were in
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("batch-") {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }
        s.receipts.retain(|r| tip_height(&r.journal) <= agreed);
        s.lineage = Some(cut);
        tracing::warn!(
            from = tip,
            to = agreed,
            "the hub's header chain was reorganized: cut back"
        );
        Ok(agreed)
    }

    /// A dispute needs a receipt through block `height`.
    pub fn demand(&self, height: u32) {
        let mut s = self.state();
        s.demand = s.demand.max(height);
    }

    /// The block the disputes need a receipt through, the most asked for
    /// ([`Self::demand`]): 0 until one asks.
    pub fn demanded(&self) -> u32 {
        self.state().demand
    }

    /// The batch to prove next, if one is due: for the blocks a dispute
    /// asked for, else for a day of them since the last receipt. At most a
    /// day's blocks of it, the next after it is made.
    pub fn next_batch(&self) -> Result<Option<Pending>> {
        let s = self.state();
        let Some(lineage) = &s.lineage else {
            return Ok(None);
        };
        let tip = lineage.tip_height();
        let last = s.receipts.last();
        let proven = last.map(|r| tip_height(&r.journal));
        let behind = tip.saturating_sub(proven.unwrap_or(lineage.start().height()));
        let asked = s.demand.min(tip);
        let due = match proven {
            Some(p) => asked > p || behind >= self.batch,
            None => asked >= lineage.start().height() && s.demand > 0 || behind >= self.batch,
        };
        if !due {
            return Ok(None);
        }
        let from = proven.map_or(lineage.start().height() + 1, |p| p + 1);
        // No block followed past it yet: nothing to prove.
        if from > tip {
            return Ok(None);
        }
        let through = tip.min(from + self.batch - 1).max(from);
        let through = if asked >= from {
            through.min(asked.max(from))
        } else {
            through
        };
        let headers = lineage.headers(from, through).to_vec();
        let (origin, mut builder) = match last {
            None => (
                Origin::Start(lineage.start().clone()),
                Builder::start(lineage.start().clone()).map_err(|e| anyhow!("{e}"))?,
            ),
            Some(last) => (
                Origin::Resume {
                    journal: last.journal.clone(),
                    tip: last.tip.clone(),
                    tree: last.tree.clone(),
                },
                Builder::resume(&last.journal, last.tip.clone(), last.tree.clone())
                    .map_err(|e| anyhow!("{e}"))?,
            ),
        };
        for header in &headers {
            builder.push(*header).map_err(|e| anyhow!("{e}"))?;
        }
        let work = self.dir.join(format!("batch-{through}"));
        let batch = Batch {
            chain: self.program,
            from: origin,
            headers,
        };
        // The work kept of a batch stopped is of this input alone: a reorg may
        // have made another of the same height.
        let input = work.join("batch.bin");
        let bytes = batch.to_bytes();
        if std::fs::read(&input).ok().as_deref() != Some(&bytes[..]) {
            let _ = std::fs::remove_dir_all(&work);
            std::fs::create_dir_all(&work)?;
            let part = work.join("batch.part");
            std::fs::write(&part, &bytes)?;
            std::fs::rename(&part, &input)?;
        }
        let journal = builder.journal(self.program);
        Ok(Some(Pending {
            through,
            input,
            work,
            assume: last.map(|r| r.file.clone()),
            demanded: asked >= from,
            receipt: Receipt {
                journal,
                tip: builder.tip().clone(),
                tree: builder.tree().clone(),
                file: self.dir.join(format!("receipt-{}", builder.tree().count())),
            },
        }))
    }

    /// The batch `pending` was proven: its receipt kept, those before it
    /// beyond [`KEPT`] not.
    pub fn done(&self, pending: &Pending) -> Result<()> {
        let made = pending.work.join("receipt");
        let receipt = pending.receipt.clone();
        let count = receipt.journal.count;
        let mut s = self.state();
        // A reorg while it was proven may have taken its blocks back: a
        // receipt the chain does not commit is none.
        let committed = s
            .lineage
            .as_ref()
            .and_then(|l| l.through(self.program, pending.through).ok())
            .is_some_and(|(journal, _)| journal == receipt.journal);
        if !committed {
            let _ = std::fs::remove_dir_all(&pending.work);
            bail!("the chain was reorganized while the batch was proven: its receipt is not kept");
        }
        ensure!(made.exists(), "the prover left no receipt");
        // the file before the row: a row is of a receipt that is there
        let bytes = std::fs::read(&made)?;
        std::fs::rename(&made, &receipt.file)?;
        let digest = Sha256::digest(&bytes);
        s.conn.execute(
            "INSERT OR REPLACE INTO chain_receipts (program, count, journal, tip, tree, digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &self.program[..],
                count,
                receipt.journal.to_bytes(),
                receipt.tip.to_bytes(),
                {
                    let mut w = W::default();
                    receipt.tree.write(&mut w);
                    w.0
                },
                &digest[..]
            ],
        )?;
        s.receipts.retain(|r| r.journal.count != count);
        s.receipts.push(receipt);
        s.receipts.sort_by_key(|r| r.journal.count);
        // the newest KEPT, and the newest that is DEEP: a reorg that takes the
        // others back leaves that
        let tip = s.lineage.as_ref().map_or(0, Lineage::tip_height);
        let deep = s
            .receipts
            .iter()
            .rposition(|r| tip_height(&r.journal) + DEEP <= tip);
        let newest = s.receipts.len().saturating_sub(KEPT + 1);
        let mut old = Vec::new();
        let mut at = 0;
        s.receipts.retain(|r| {
            let keep = at >= newest || Some(at) == deep;
            at += 1;
            if !keep {
                old.push(r.clone());
            }
            keep
        });
        for r in &old {
            s.conn.execute(
                "DELETE FROM chain_receipts WHERE program = ?1 AND count = ?2",
                params![&self.program[..], r.journal.count],
            )?;
        }
        drop_files(&old);
        let _ = std::fs::remove_dir_all(&pending.work);
        Ok(())
    }

    /// Of a mock chain program (regtest's, which no prover runs): the
    /// batches through block `height` made at once, each receipt's journal
    /// the chain's own and its file empty, which a mock proof binds alone.
    pub fn mock_through(&self, height: u32) -> Result<()> {
        self.demand(height);
        while self.receipt_through(height).is_none() {
            let Some(pending) = self.next_batch()? else {
                bail!("no batch to prove through block {height}");
            };
            std::fs::write(pending.work.join("receipt"), [])?;
            self.done(&pending)?;
        }
        Ok(())
    }

    /// The newest receipt through block `height`, if there is one.
    pub fn receipt_through(&self, height: u32) -> Option<Receipt> {
        let s = self.state();
        s.receipts
            .last()
            .filter(|r| tip_height(&r.journal) >= height)
            .cloned()
    }

    /// Work with the chain kept: its blocks, for the openings of a dispute.
    pub fn with<T>(&self, f: impl FnOnce(&Lineage) -> T) -> Option<T> {
        self.state().lineage.as_ref().map(f)
    }

    /// The headers after `receipt`'s last block that a statement needs to
    /// count `work` on top of block `last`: as few as there are to reach it
    /// (all there are, if they do not).
    pub fn tail(&self, receipt: &Receipt, last: u32, work: u128) -> Vec<[u8; 80]> {
        let tip = tip_height(&receipt.journal);
        self.with(|lineage| {
            let Some(leaf) = lineage.leaf(last) else {
                return Vec::new();
            };
            let mut have = receipt.journal.work.saturating_sub(leaf.work);
            let mut tail = Vec::new();
            let mut at = tip + 1;
            while have < work {
                let Some(header) = lineage.header(at) else {
                    break;
                };
                let bits = u32::from_le_bytes(header[72..76].try_into().expect("four bytes"));
                have = have.saturating_add(licash_statement::btc::work(bits));
                tail.push(*header);
                at += 1;
            }
            tail
        })
        .unwrap_or_default()
    }
}

fn drop_files(old: &[Receipt]) {
    for r in old {
        let _ = std::fs::remove_file(&r.file);
    }
}

/// A node and a genesis, for this module's tests and the prover's.
#[cfg(test)]
pub(super) mod fixtures {
    use super::*;
    use licash_statement::testing::headers_on;

    pub fn genesis() -> Checkpoint {
        Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap()
    }

    /// A node's chain of `n` blocks on the genesis (or on what it says the
    /// block at height 0 is: a node on another chain).
    pub struct Node(pub Vec<[u8; 80]>, pub Option<[u8; 32]>);

    impl Node {
        pub fn new(n: usize) -> Self {
            Self(headers_on(&sha256d(genesis().header()), n), None)
        }

        /// Its blocks after `height` replaced by `n` others.
        pub fn fork(&mut self, height: usize, n: usize) {
            let from = match height {
                0 => sha256d(genesis().header()),
                h => sha256d(&self.0[h - 1]),
            };
            self.0.truncate(height);
            self.0.extend(headers_on(&from, n));
        }
    }

    impl Headers for Node {
        async fn tip(&self) -> Result<u32> {
            Ok(self.0.len() as u32)
        }

        async fn hash(&self, height: u32) -> Result<[u8; 32]> {
            match height {
                0 => Ok(self.1.unwrap_or_else(|| sha256d(genesis().header()))),
                h => self
                    .0
                    .get(h as usize - 1)
                    .map(|h| sha256d(h))
                    .context("beyond the node's tip"),
            }
        }

        async fn header(&self, hash: &[u8; 32]) -> Result<[u8; 80]> {
            self.0
                .iter()
                .find(|h| sha256d(*h) == *hash)
                .copied()
                .context("no such block")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{genesis, Node};
    use super::*;

    const PROGRAM: [u8; 32] = [0xc1; 32];

    fn chain(dir: &Path) -> HubChain {
        HubChain::open(
            &crate::testing::hub_data(dir),
            PROGRAM,
            ChainProfile::Core30DefaultRegtest,
        )
        .unwrap()
        .0
    }

    #[tokio::test]
    async fn a_chain_follows_the_node_from_a_contracts_checkpoint_and_is_kept() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(30);
        let chain = chain(data.path());
        // nothing is followed before a contract's checkpoint starts it
        chain.follow(&node, 10).await.unwrap();
        assert_eq!(chain.tip(), None);
        assert!(chain.covers(&genesis()).is_err());
        chain.begin(&genesis()).unwrap();
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 12).await.unwrap();
        assert_eq!(chain.tip(), Some(12));
        chain.follow(&node, 9).await.unwrap();
        chain.follow(&node, 25).await.unwrap();
        assert_eq!(chain.tip(), Some(25));
        // it is as a chain of those headers is
        let at = chain.with(|l| l.builder().journal(PROGRAM)).unwrap();
        let mut dense = Lineage::new(genesis()).unwrap();
        node.0[..25].iter().for_each(|h| dense.push(*h).unwrap());
        assert_eq!(at, dense.builder().journal(PROGRAM));
        // what is kept is the chain again, on a restart
        drop(chain);
        let again = self::chain(data.path());
        assert_eq!(again.tip(), Some(25));
        assert_eq!(again.with(|l| l.builder().journal(PROGRAM)).unwrap(), at);
    }

    #[tokio::test]
    async fn a_checkpoint_is_covered_only_in_the_state_the_chain_has_it() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(20);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 20).await.unwrap();
        // a block of the chain, as its contract's Base binds it
        let mut state = genesis();
        for h in &node.0[..7] {
            state.push(*h).unwrap();
        }
        assert_eq!(chain.covers(&state), Ok(()));
        assert!(chain.covers(&genesis()).is_ok());
        // another state of the same height: the median's times, or the period's start
        let other = Checkpoint::new(
            ChainProfile::Core30DefaultRegtest,
            7,
            *state.header(),
            vec![
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                u32::from_le_bytes(state.header()[68..72].try_into().unwrap()),
            ],
            None,
        )
        .unwrap();
        assert!(chain.covers(&other).unwrap_err().contains("another state"));
        // beyond its tip
        state.push(node.0[7]).unwrap();
        let mut later = state;
        for h in &node.0[8..20] {
            later.push(*h).unwrap();
        }
        node.0.get(20).is_none().then_some(()).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let chain2 = self::chain(elsewhere.path());
        chain2.begin(&genesis()).unwrap();
        chain2.follow(&node, 5).await.unwrap();
        assert!(chain2.covers(&later).unwrap_err().contains("not in"));
    }

    #[tokio::test]
    async fn a_reorg_cuts_the_chain_and_its_receipts_back_to_the_block_they_agree_on() {
        let data = tempfile::tempdir().unwrap();
        let mut node = Node::new(20);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 20).await.unwrap();
        // a receipt through 15 and one through 20
        for through in [15, 20] {
            chain.demand(through);
            let pending = chain.next_batch().unwrap().unwrap();
            assert_eq!(pending.through, through);
            std::fs::write(pending.work.join("receipt"), format!("receipt {through}")).unwrap();
            chain.done(&pending).unwrap();
        }
        assert!(chain.receipt_through(20).is_some());
        // the node's last four blocks are replaced by five others
        node.fork(16, 6);
        chain.follow(&node, 22).await.unwrap();
        assert_eq!(chain.tip(), Some(22));
        // the receipt through 20 went with the blocks, and the one through 15 stays
        assert!(chain.receipt_through(20).is_none());
        let kept = chain.receipt_through(15).unwrap();
        assert_eq!(tip_height(&kept.journal), 15);
        assert!(kept.file.exists());
        assert!(!data
            .path()
            .join("header-chain")
            .join(hex::encode(PROGRAM))
            .join("receipt-21")
            .exists());
        // and it is the chain of the node's, as kept
        drop(chain);
        let again = self::chain(data.path());
        assert_eq!(again.tip(), Some(22));
        // a chain that does not reach back to its start is given up
        let mut node = Node::new(30);
        node.1 = Some([9; 32]);
        let e = again.follow(&node, 30).await.unwrap_err();
        assert!(format!("{e:#}").contains("off the node's"), "{e:#}");
    }

    #[tokio::test]
    async fn a_batch_is_proven_for_a_day_of_blocks_or_the_blocks_a_dispute_needs() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(40);
        let chain = chain(data.path());
        // regtest's day is 144 blocks: nothing is due by itself
        assert_eq!(chain.batch, 144);
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 40).await.unwrap();
        assert!(chain.next_batch().unwrap().is_none());
        // asked before a block past its start is followed: none to prove
        let empty = tempfile::tempdir().unwrap();
        let unfollowed = self::chain(empty.path());
        unfollowed.begin(&genesis()).unwrap();
        unfollowed.demand(12);
        assert!(unfollowed.next_batch().unwrap().is_none());
        // a dispute needs the blocks through 12: a batch from the start
        chain.demand(12);
        let first = chain.next_batch().unwrap().unwrap();
        assert_eq!((first.through, first.assume.is_none()), (12, true));
        let batch = Batch::from_bytes(&std::fs::read(&first.input).unwrap()).unwrap();
        assert_eq!(batch.headers.len(), 12);
        assert!(matches!(batch.from, Origin::Start(_)));
        // what the batch proves is what the chain commits through its block
        let journal = licash_chain::extend(&batch, &|_, _| {}).unwrap();
        assert_eq!(
            journal,
            chain.with(|l| l.through(PROGRAM, 12).unwrap().0).unwrap()
        );
        assert_eq!(journal, first.receipt.journal);
        // not kept until it is proven
        assert!(chain.receipt_through(12).is_none());
        assert!(chain.done(&first).is_err());
        std::fs::write(first.work.join("receipt"), b"the receipt").unwrap();
        chain.done(&first).unwrap();
        assert!(!first.work.exists());
        let kept = chain.receipt_through(12).unwrap();
        assert_eq!((kept.journal.count, tip_height(&kept.journal)), (13, 12));
        assert_eq!(std::fs::read(&kept.file).unwrap(), b"the receipt");
        assert!(chain.receipt_through(13).is_none());
        // met: nothing more is due, until another dispute needs more
        assert!(chain.next_batch().unwrap().is_none());
        chain.demand(30);
        let second = chain.next_batch().unwrap().unwrap();
        assert_eq!(
            (second.through, second.assume.as_ref()),
            (30, Some(&kept.file))
        );
        let batch = Batch::from_bytes(&std::fs::read(&second.input).unwrap()).unwrap();
        assert_eq!(batch.headers.len(), 18);
        // it resumes the receipt it verifies, and extends exactly that chain
        let seen = std::cell::RefCell::new(None);
        let journal = licash_chain::extend(&batch, &|id, j| {
            *seen.borrow_mut() = Some((*id, j.to_vec()));
        })
        .unwrap();
        assert_eq!(seen.into_inner(), Some((PROGRAM, kept.journal.to_bytes())));
        assert_eq!(journal, second.receipt.journal);
        assert_eq!(
            journal,
            chain.with(|l| l.through(PROGRAM, 30).unwrap().0).unwrap()
        );
        // the blocks of a dispute beyond the tip are the tip's
        chain.demand(900);
        std::fs::write(second.work.join("receipt"), b"two").unwrap();
        chain.done(&second).unwrap();
        let third = chain.next_batch().unwrap().unwrap();
        assert_eq!(third.through, 40);
    }

    #[tokio::test]
    async fn a_receipt_the_chain_does_not_commit_is_not_kept_and_the_old_ones_are_pruned() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(60);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 60).await.unwrap();
        for through in [10, 20, 30, 40, 50] {
            chain.demand(through);
            let pending = chain.next_batch().unwrap().unwrap();
            std::fs::write(pending.work.join("receipt"), b"r").unwrap();
            chain.done(&pending).unwrap();
        }
        // the newest and KEPT before it
        let counts: Vec<_> = chain
            .state()
            .receipts
            .iter()
            .map(|r| r.journal.count)
            .collect();
        assert_eq!(counts, [21, 31, 41, 51]);
        let dir = data.path().join("header-chain").join(hex::encode(PROGRAM));
        assert!(!dir.join("receipt-11").exists() && dir.join("receipt-21").exists());
        // a row whose journal is not what the chain commits is left out on a restart
        chain
            .state()
            .conn
            .execute(
                "UPDATE chain_receipts SET journal = ?1 WHERE count = 31",
                [vec![0u8; licash_chain::JOURNAL_LEN]],
            )
            .unwrap();
        drop(chain);
        let (again, told) =
            HubChain::open(data.path(), PROGRAM, ChainProfile::Core30DefaultRegtest).unwrap();
        assert!(told.unwrap().contains("31 blocks"));
        let counts: Vec<_> = again
            .state()
            .receipts
            .iter()
            .map(|r| r.journal.count)
            .collect();
        assert_eq!(counts, [21, 41, 51]);
    }

    /// A reorg while a batch is being proven takes its blocks back: its
    /// receipt is not kept, and the batch of the same height that follows is
    /// made of the blocks that are there, not of the input kept for the others.
    #[tokio::test]
    async fn a_batch_a_reorg_took_back_is_not_kept_and_its_work_is_not_taken_up_again() {
        let data = tempfile::tempdir().unwrap();
        let mut node = Node::new(20);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 20).await.unwrap();
        chain.demand(12);
        let pending = chain.next_batch().unwrap().unwrap();
        let old = std::fs::read(&pending.input).unwrap();
        // proven, but not yet kept, as a prover takes time: the node reorganizes
        std::fs::write(pending.work.join("receipt"), b"of the old blocks").unwrap();
        node.fork(10, 8);
        chain.follow(&node, 18).await.unwrap();
        let e = chain.done(&pending).unwrap_err();
        assert!(format!("{e:#}").contains("reorganized"), "{e:#}");
        assert!(chain.receipt_through(12).is_none());
        let dir = data.path().join("header-chain").join(hex::encode(PROGRAM));
        assert!(!dir.join("receipt-13").exists());
        // the same batch, of the same height, is of the blocks now there
        let again = chain.next_batch().unwrap().unwrap();
        assert_eq!(again.through, pending.through);
        assert_ne!(std::fs::read(&again.input).unwrap(), old);
        assert!(!again.work.join("receipt").exists(), "stale work is gone");
        let batch = Batch::from_bytes(&std::fs::read(&again.input).unwrap()).unwrap();
        assert_eq!(batch.headers[..], node.0[..12]);
        std::fs::write(again.work.join("receipt"), b"of the new").unwrap();
        chain.done(&again).unwrap();
        assert!(chain.receipt_through(12).is_some());
    }

    /// A reorg that goes back past the receipts made for disputes, a few
    /// blocks apart, leaves the one kept far below the tip.
    #[tokio::test]
    async fn a_receipt_far_below_the_tip_is_kept_past_the_newest() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(130);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 130).await.unwrap();
        for through in [5, 50, 51, 52, 53, 54] {
            chain.demand(through);
            let pending = chain.next_batch().unwrap().unwrap();
            std::fs::write(pending.work.join("receipt"), b"r").unwrap();
            chain.done(&pending).unwrap();
        }
        // the newest four, and the deep one, not the one between
        let tips: Vec<_> = chain
            .state()
            .receipts
            .iter()
            .map(|r| tip_height(&r.journal))
            .collect();
        assert_eq!(tips, [5, 51, 52, 53, 54]);
        let dir = data.path().join("header-chain").join(hex::encode(PROGRAM));
        assert!(dir.join("receipt-6").exists() && !dir.join("receipt-51").exists());
    }

    /// A receipt's file is the one that was made: another, or a damaged one,
    /// is not kept, and the operator is told.
    #[tokio::test]
    async fn a_receipts_file_that_is_not_the_one_made_is_not_kept() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(20);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 20).await.unwrap();
        chain.demand(10);
        let pending = chain.next_batch().unwrap().unwrap();
        std::fs::write(pending.work.join("receipt"), b"the receipt").unwrap();
        chain.done(&pending).unwrap();
        let file = chain.receipt_through(10).unwrap().file;
        drop(chain);
        let (again, told) =
            HubChain::open(data.path(), PROGRAM, ChainProfile::Core30DefaultRegtest).unwrap();
        assert_eq!(told, None);
        assert!(again.receipt_through(10).is_some());
        drop(again);
        std::fs::write(&file, b"the receipt, damaged").unwrap();
        let (again, told) =
            HubChain::open(data.path(), PROGRAM, ChainProfile::Core30DefaultRegtest).unwrap();
        assert!(told.unwrap().contains("not the one that was made"));
        assert!(again.receipt_through(10).is_none());
    }

    #[tokio::test]
    async fn the_tail_is_the_headers_after_the_receipt_that_the_work_on_the_last_block_needs() {
        let data = tempfile::tempdir().unwrap();
        let node = Node::new(30);
        let chain = chain(data.path());
        chain.begin(&genesis()).unwrap();
        chain.follow(&node, 30).await.unwrap();
        chain.demand(10);
        let pending = chain.next_batch().unwrap().unwrap();
        std::fs::write(pending.work.join("receipt"), b"r").unwrap();
        chain.done(&pending).unwrap();
        let receipt = chain.receipt_through(10).unwrap();
        let one = licash_statement::btc::work(0x207f_ffff);
        // the receipt's blocks past the last block count; the tail adds the rest
        assert!(chain.tail(&receipt, 10, 0).is_empty());
        assert!(chain.tail(&receipt, 10, 3 * one).len() == 3);
        assert_eq!(chain.tail(&receipt, 7, 3 * one).len(), 0);
        assert_eq!(chain.tail(&receipt, 7, 5 * one).len(), 2);
        // as many as there are, if the chain doesn't have the work
        assert_eq!(chain.tail(&receipt, 10, 99 * one).len(), 20);
        assert!(chain.tail(&receipt, 99, one).is_empty());
    }
}
