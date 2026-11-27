//! Silent payments (BIP352) to the wallet's address, found without a full
//! node: a hub the wallet trusts serves each block's tweaks, and a light
//! client ([`Blocks`]) the blocks' compact filters (BIP158) and the blocks
//! that match.
//!
//! From a first block its owner chose on ([`Wallet::watch_silent`]), the
//! wallet derives from each tweak the outputs a payment to it would pay
//! first, and fetches a block only if its filter matches one of them or a
//! coin it holds. A hub that withholds or forges tweaks hides payments; it
//! can never take them. Scanned with every hub trusted serving tweaks
//! ([`Wallet::scan_silent_trusted`]), a block is looked in with the tweaks
//! any of them that served it serves: a payment stays hidden only if every
//! hub that served its block hides it (one alone, if the others had not
//! indexed it yet or did not answer). Each of them is asked for each
//! batch of blocks. Tweaks of another block than the chain's at their
//! height are refused. Each batch of blocks is recorded whole, and a
//! reorganization drops what the blocks it replaced held.
//!
//! Payers of no silent payments pay a fallback address instead, a plain
//! taproot address ([`Scanner::fallback`]) a payment code holds once
//! [`Wallet::payment_code`] hands one out: from then on those handed out,
//! and [`FALLBACK_GAP`] after, are watched in every block, and the next is
//! handed out once one is paid. Their coins are the address's like any.
//!
//! Without a hub serving tweaks, blocks are looked in for the fallback
//! addresses and the coins held only, the change of the wallet's own spends
//! with them: those blocks are looked in again for silent payments once a
//! hub serving their tweaks is scanned with.
//!
//! [`Wallet::spend_silent`] spends the coins found, to a script or a silent
//! payment address ([`Payee`]) and change to the wallet's change address:
//! a transaction for the application to broadcast.
//! [`Wallet::deposit_silent`] spends them on a deposit for a hub's notes.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use bitcoin::{
    absolute::LockTime,
    bip158::BlockFilter,
    hashes::Hash,
    key::{Keypair, Secp256k1, TweakedPublicKey},
    secp256k1::{Message, PublicKey, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    transaction, Amount, Block, BlockHash, FeeRate, OutPoint, Script, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use licash_api::{BlockTweaks, MAX_TWEAK_BLOCKS, TWEAKS};
use licash_onchain::silent::{self, Found, Scanner, SpAddress, CHANGE};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Transaction as Sql};

use crate::{
    hub_url, invalid, store::now, unavailable, Deposit, DepositState, Error, Transport, Wallet,
};

/// The blocks looked in that are kept, to notice reorganizations that deep.
const KEEP_BLOCKS: u32 = 288;

/// The fallback addresses watched past the highest handed out: a copy of
/// the wallet may have handed them out.
const FALLBACK_GAP: u32 = 20;

/// What the wallet reads of Bitcoin's best chain to find its silent
/// payments: a light client's view of it, or a full node's.
pub trait Blocks: Send + Sync {
    /// The best chain's height.
    fn height(&self) -> impl Future<Output = Result<u32, String>> + Send;

    /// The hash of the best chain's block at `height`.
    fn hash(&self, height: u32) -> impl Future<Output = Result<BlockHash, String>> + Send;

    /// The basic compact filter (BIP158) of the block of `hash`, checked
    /// against the chain's filter headers, if the source serves filters:
    /// without them, every block that could pay the wallet or spend its
    /// coins is fetched.
    fn filter(
        &self,
        hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, String>> + Send;

    /// The block of `hash`.
    fn block(&self, hash: &BlockHash) -> impl Future<Output = Result<Block, String>> + Send;
}

/// A coin paying the silent payment address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentCoin {
    pub outpoint: OutPoint,
    pub value: u64,
    /// The block it is in.
    pub height: u32,
    /// At the wallet's change address: one of its own spends paid it.
    pub change: bool,
    /// The wallet's transaction spending it, in no block yet.
    pub spending: Option<Txid>,
}

/// A transaction the wallet made of its coins, and where it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilentSpend {
    pub tx: Transaction,
    /// Paid to its miners: what the coins it spends held, less what it
    /// pays. Unknown while one of them is, forgotten with its block in a
    /// reorganization until found again.
    pub fee: Option<u64>,
    /// The block it is in, once a scan saw it there.
    pub height: Option<u32>,
}

/// What a [`Wallet::scan_silent`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scanned {
    /// The next block to look in.
    pub next: u32,
    /// The chain's height: done once `next` is past it.
    pub height: u32,
    /// The coins found.
    pub found: Vec<SilentCoin>,
    /// The coins seen spent.
    pub spent: Vec<OutPoint>,
    /// The blocks fetched whole, their filters matching.
    pub fetched: u32,
}

/// How long, once a hub answered with the tweaks of a batch of blocks, the
/// others asked are waited on: one slow or gone is passed over for the
/// batch rather than holding it up.
const GRACE: Duration = Duration::from_secs(10);

/// The tweaks of the blocks from one on, as every hub asked served them,
/// each block's of the chain's: of a block, those any served. Fetched ahead
/// of a scan ([`Wallet::silent_tweaks`]), so it holds no one waiting on
/// hubs.
#[derive(Clone, Debug)]
pub struct SilentTweaks {
    from: u32,
    /// Of each block from `from` on, its hash and its tweaks.
    blocks: Vec<(BlockHash, Vec<PublicKey>)>,
}

/// The answers of `asks`, asked at once: once one is `good`, the rest
/// waited on for `grace` at most, those that did not answer by then none.
async fn gather<F: Future>(
    asks: Vec<F>,
    good: impl Fn(&F::Output) -> bool,
    grace: Duration,
) -> Vec<Option<F::Output>> {
    let mut asks: Vec<_> = asks.into_iter().map(Box::pin).collect();
    let mut answers: Vec<Option<F::Output>> = asks.iter().map(|_| None).collect();
    let mut deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;
    std::future::poll_fn(|cx| {
        for (ask, answer) in asks.iter_mut().zip(answers.iter_mut()) {
            if answer.is_none() {
                if let Poll::Ready(output) = ask.as_mut().poll(cx) {
                    *answer = Some(output);
                }
            }
        }
        if answers.iter().all(Option::is_some) {
            return Poll::Ready(());
        }
        if deadline.is_none() && answers.iter().flatten().any(&good) {
            deadline = Some(Box::pin(tokio::time::sleep(grace)));
        }
        match &mut deadline {
            Some(deadline) => deadline.as_mut().poll(cx),
            None => Poll::Pending,
        }
    })
    .await;
    answers
}

/// What a batch of blocks held: recorded whole.
#[derive(Default)]
struct Batch {
    blocks: Vec<(u32, BlockHash)>,
    found: Vec<(OutPoint, u64, Found, u32)>,
    spent: Vec<(OutPoint, Txid, u32)>,
}

/// What finds the outputs paying the wallet: its silent payment address's,
/// with each block's tweaks, and its fallback addresses'.
struct Finder {
    scanner: Scanner,
    /// The fallback outputs watched, by key.
    fallbacks: HashMap<XOnlyPublicKey, Found>,
}

impl Finder {
    /// The fallback output `script` pays, if one.
    fn fallback(&self, script: &ScriptBuf) -> Option<&Found> {
        let key = script.is_p2tr().then(|| &script.as_bytes()[2..])?;
        self.fallbacks.get(&XOnlyPublicKey::from_slice(key).ok()?)
    }
}

/// The fallback outputs watched, by key, and the index to hand out next:
/// past every one paid, never before the highest handed out. None watched
/// until one is handed out (or [`Wallet::watch_fallbacks`]), then those
/// and [`FALLBACK_GAP`] past the highest handed out or paid, so a wallet
/// restored finds those its copy handed out one after another.
fn fallbacks(
    c: &rusqlite::Connection,
    scanner: &Scanner,
) -> Result<(HashMap<XOnlyPublicKey, Found>, u32), Error> {
    let shown: Option<u32> = c
        .query_row("SELECT shown FROM silent_fallback", [], |r| r.get(0))
        .optional()?;
    let Some(shown) = shown else {
        return Ok((HashMap::new(), 0));
    };
    let paid: HashSet<[u8; 32]> = {
        let mut stmt = c.prepare("SELECT output FROM silent_coins")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    let mut watched = HashMap::new();
    let mut next = shown;
    let mut index = 0u32;
    while index <= next.max(shown).saturating_add(FALLBACK_GAP) {
        let found = scanner.fallback(index).map_err(invalid)?;
        if paid.contains(&found.output.serialize()) {
            next = next.max(index.saturating_add(1));
        }
        watched.insert(found.output, found);
        index = match index.checked_add(1) {
            Some(i) => i,
            None => break,
        };
    }
    Ok((watched, next))
}

/// A coin the wallet holds, as a spend reads it.
#[derive(Clone)]
struct Held {
    outpoint: OutPoint,
    value: u64,
    found: Found,
}

pub(crate) fn chain_error(reason: impl std::fmt::Display) -> Error {
    Error::Chain(reason.to_string())
}

fn not_watching() -> Error {
    Error::Invalid("not watching for silent payments: watch_silent first".into())
}

/// Whether the blocks `tweaks` are of are still the chain's.
async fn still_of(chain: &impl Blocks, tweaks: &SilentTweaks) -> Result<bool, Error> {
    for (at, (hash, _)) in (tweaks.from..).zip(&tweaks.blocks) {
        if chain.hash(at).await.map_err(chain_error)? != *hash {
            return Ok(false);
        }
    }
    Ok(true)
}

fn raced() -> Error {
    Error::Invalid("another scan for silent payments ran meanwhile: try again".into())
}

/// Look again from block `from`, if the next block to look in is still
/// `next`: forget the coins found and the spends seen from it on (they are
/// found again if still in the best chain); a coin whose spend is forgotten
/// is the wallet's own spend's again, if one takes it. Whether it was still
/// `next`.
fn rewind(t: &Sql<'_>, next: u32, from: u32) -> Result<bool, Error> {
    if t.execute(
        "UPDATE silent_scan SET next_height = ?2 WHERE next_height = ?1",
        [next, from],
    )? == 0
    {
        return Ok(false);
    }
    t.execute("DELETE FROM silent_coins WHERE height >= ?1", [from])?;
    let unspent: Vec<OutPoint> = {
        let mut stmt = t.prepare("SELECT txid, vout FROM silent_coins WHERE spent_height >= ?1")?;
        let rows = stmt.query_map([from], |r| {
            Ok(OutPoint::new(Txid::from_byte_array(r.get(0)?), r.get(1)?))
        })?;
        rows.collect::<Result<_, _>>()?
    };
    let pending = pending_inputs(t)?;
    for outpoint in unspent {
        t.execute(
            "UPDATE silent_coins SET spent_height = NULL, spent_by = ?3
             WHERE txid = ?1 AND vout = ?2",
            params![
                outpoint.txid.to_byte_array(),
                outpoint.vout,
                pending.get(&outpoint).map(|txid| txid.to_byte_array())
            ],
        )?;
    }
    t.execute("DELETE FROM silent_blocks WHERE height >= ?1", [from])?;
    t.execute(
        "UPDATE silent_scan SET untweaked_height = NULL, untweaked_until = NULL
         WHERE untweaked_height >= ?1",
        [from],
    )?;
    t.execute(
        "UPDATE silent_scan SET untweaked_until = ?1 WHERE untweaked_until > ?1",
        [from],
    )?;
    Ok(true)
}

/// Give up the wallet's own spend `txid`, freeing the coins it takes that
/// no block spends: how many.
fn give_up(t: &Sql<'_>, txid: &Txid) -> Result<usize, Error> {
    let freed = t.execute(
        "UPDATE silent_coins SET spent_by = NULL WHERE spent_by = ?1 AND spent_height IS NULL",
        [txid.to_byte_array()],
    )?;
    // The spends of its coins it took the place of, given up with it: else
    // the latest of them takes them again once looked in again.
    let replaced = replaced_by(t, txid)?;
    for old in &replaced {
        t.execute("DELETE FROM silent_spends WHERE txid = ?1", [old])?;
    }
    let known = t.execute(
        "DELETE FROM silent_spends WHERE txid = ?1",
        [txid.to_byte_array()],
    )?;
    Ok(freed.max(known))
}

/// The wallet's spends made before its spend `txid` of any coin it spends,
/// in [`pending_inputs`]' order: those it took the place of, but for those
/// in a block.
fn replaced_by(t: &Sql<'_>, txid: &Txid) -> Result<Vec<[u8; 32]>, Error> {
    let mut stmt = t.prepare(
        "SELECT o.txid, o.tx FROM silent_spends o, silent_spends n
         WHERE n.txid = ?1 AND o.txid != n.txid
           AND (o.created_at < n.created_at
                OR (o.created_at = n.created_at AND o.rowid < n.rowid))
           AND NOT EXISTS (SELECT 1 FROM silent_coins c
                           WHERE c.spent_by = o.txid AND c.spent_height IS NOT NULL)",
    )?;
    let rows = stmt.query_map([txid.to_byte_array()], |r| {
        Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let raw = rows.collect::<Result<Vec<_>, _>>()?;
    let Some(new) = t
        .query_row(
            "SELECT tx FROM silent_spends WHERE txid = ?1",
            [txid.to_byte_array()],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?
    else {
        return Ok(Vec::new());
    };
    let new: Transaction = bitcoin::consensus::deserialize(&new).map_err(invalid)?;
    let spends: HashSet<OutPoint> = new.input.iter().map(|i| i.previous_output).collect();
    let mut replaced = Vec::new();
    for (old, tx) in raw {
        let tx: Transaction = bitcoin::consensus::deserialize(&tx).map_err(invalid)?;
        if tx.input.iter().any(|i| spends.contains(&i.previous_output)) {
            replaced.push(old);
        }
    }
    Ok(replaced)
}

/// The coins the wallet's own spends take, by the spend: the latest of
/// them, a coin's spend replaced ([`Wallet::replace_silent`]).
fn pending_inputs(t: &Sql<'_>) -> Result<HashMap<OutPoint, Txid>, Error> {
    let mut stmt = t.prepare("SELECT txid, tx FROM silent_spends ORDER BY created_at, rowid")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut taken = HashMap::new();
    for row in rows {
        let (txid, tx) = row?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx).map_err(invalid)?;
        for input in tx.input {
            taken.insert(input.previous_output, Txid::from_byte_array(txid));
        }
    }
    Ok(taken)
}

/// The taproot script of output key `key`, as is.
fn p2tr(key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

/// The tweak of `tx` if it spends coins of `coins` only: the wallet's own
/// spend, whose change it finds without a hub's tweaks.
fn own_tweak(tx: &Transaction, coins: &HashMap<OutPoint, XOnlyPublicKey>) -> Option<PublicKey> {
    let spent: Vec<ScriptBuf> = tx
        .input
        .iter()
        .map(|i| coins.get(&i.previous_output).map(|key| p2tr(*key)))
        .collect::<Option<_>>()?;
    let spent: Vec<&bitcoin::Script> = spent.iter().map(ScriptBuf::as_script).collect();
    silent::tweak(tx, &spent)
}

/// A taproot script of no key: any 32 bytes size one, to plan a spend
/// paying a silent payment or change.
fn any_taproot() -> ScriptBuf {
    ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0; 32]].concat())
}

/// Whom [`Wallet::spend_silent`] pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payee {
    /// This output script.
    Script(ScriptBuf),
    /// A silent payment address: the output paying it is derived from the
    /// coins spent.
    Silent(SpAddress),
}

impl From<ScriptBuf> for Payee {
    fn from(script: ScriptBuf) -> Self {
        Self::Script(script)
    }
}

impl From<SpAddress> for Payee {
    fn from(address: SpAddress) -> Self {
        Self::Silent(address)
    }
}

impl<T: Transport> Wallet<T> {
    /// Look for payments to the silent payment address from block `from`
    /// on, with the tweaks of the hub at `hub`: the chain's height when the
    /// wallet was made, or an earlier block to look again, forgetting what
    /// was found from it on until found again. Never later than it stands,
    /// nor earlier than the hub serves tweaks from. Without a hub, for any
    /// block: to scan without tweaks.
    pub fn watch_silent<'a>(
        &self,
        hub: impl Into<Option<&'a str>>,
        from: u32,
    ) -> Result<(), Error> {
        if let Some(hub) = hub.into() {
            let url = hub_url(hub)?;
            let first = self.tweaks_from(&url)?;
            if from < first {
                return Err(Error::Invalid(format!(
                    "hub {url} serves tweaks from block {first} on, not {from}"
                )));
            }
        }
        self.store.write(|t| {
            let next: Option<u32> = t
                .query_row("SELECT next_height FROM silent_scan", [], |r| r.get(0))
                .optional()?;
            match next {
                None => {
                    t.execute(
                        "INSERT INTO silent_scan (one, next_height) VALUES (1, ?1)",
                        [from],
                    )?;
                }
                Some(next) if from < next => {
                    rewind(t, next, from)?;
                }
                Some(_) => {}
            }
            Ok(())
        })?;
        tracing::info!(from, "watching for silent payments");
        Ok(())
    }

    /// The first block the hub at `url` serves tweaks of.
    fn tweaks_from(&self, url: &str) -> Result<u32, Error> {
        let (_, info) = self.hub(url)?;
        info.tweaks
            .ok_or_else(|| Error::Invalid(format!("hub {url} serves no silent payment tweaks")))
    }

    /// The next block to look in for silent payments: none until
    /// [`Wallet::watch_silent`].
    pub fn silent_next(&self) -> Result<Option<u32>, Error> {
        self.store.read(|c| {
            Ok(
                c.query_row("SELECT next_height FROM silent_scan", [], |r| r.get(0))
                    .optional()?,
            )
        })
    }

    /// Look in up to `max` blocks from the next for payments to the silent
    /// payment address and spends of its coins, with the tweaks of the hub
    /// at `hub` and the blocks of `chain`: up to the chain's height, or the
    /// newest block the hub indexed. Each batch of blocks is recorded whole,
    /// so an interrupted scan goes on from the last.
    ///
    /// Without a hub, for the fallback addresses and the coins held only,
    /// the change of the wallet's own spends with them. Scanned with a hub
    /// again, the blocks looked in so that it serves tweaks of are looked in
    /// again first.
    pub async fn scan_silent<'a>(
        &self,
        hub: impl Into<Option<&'a str>>,
        chain: &impl Blocks,
        max: u32,
    ) -> Result<Scanned, Error> {
        let hubs = match hub.into().map(hub_url).transpose()? {
            Some(url) => {
                let first = self.tweaks_from(&url)?;
                vec![(url, first)]
            }
            None => Vec::new(),
        };
        self.scan_with(&hubs, None, chain, max).await
    }

    /// As [`Wallet::scan_silent`], with the tweaks of every hub trusted
    /// serving the next block's, those of each block any of them serves
    /// (see [`Wallet::silent_tweaks`]): up to the newest block one indexed.
    /// Those `ahead`, fetched by [`Wallet::silent_tweaks`] meanwhile, are
    /// not fetched again, while still of the chain's blocks. If no hub
    /// trusted serves the next block's, without, up to the first block one
    /// does. Whether with tweaks.
    pub async fn scan_silent_trusted(
        &self,
        chain: &impl Blocks,
        max: u32,
        ahead: Option<SilentTweaks>,
    ) -> Result<(Scanned, bool), Error> {
        let hubs = self.tweak_hubs()?;
        let next = self.silent_next()?.ok_or_else(not_watching)?;
        if hubs.iter().any(|(_, first)| *first <= next) {
            return Ok((self.scan_with(&hubs, ahead, chain, max).await?, true));
        }
        let later = hubs.iter().map(|(_, first)| *first).find(|f| *f > next);
        let max = later.map_or(max, |first| max.min(first - next));
        Ok((self.scan_with(&[], None, chain, max).await?, false))
    }

    /// The tweaks of up to `max` blocks (and [`MAX_TWEAK_BLOCKS`]) from the
    /// next to look in, for [`Wallet::scan_silent_trusted`]: asked of every
    /// hub trusted serving the next block's at once, those of each block
    /// any of them serves, up to the newest block one indexed. One that
    /// names another block than the chain's, or does not answer within
    /// `GRACE` of another, is passed over; one that serves fewer of a
    /// block's tweaks than another is warned of. None if no hub trusted
    /// serves the next block's, or the chain has no next block; refused if
    /// none of those that do answers, with why the first did not.
    ///
    /// Changes nothing the wallet holds: fetched alongside anything else.
    pub async fn silent_tweaks(
        &self,
        chain: &impl Blocks,
        max: u32,
    ) -> Result<Option<SilentTweaks>, Error> {
        let Some(next) = self.silent_next()? else {
            return Ok(None);
        };
        let hubs = self.tweak_hubs()?;
        if max == 0 || !hubs.iter().any(|(_, first)| *first <= next) {
            return Ok(None);
        }
        let height = chain.height().await.map_err(chain_error)?;
        if next > height {
            return Ok(None);
        }
        let count = (height - next + 1).min(max).min(MAX_TWEAK_BLOCKS);
        Ok(Some(self.union(&hubs, chain, next, count).await?))
    }

    /// The hubs trusted serving tweaks, and the first block each serves
    /// the tweaks of, the earliest first.
    fn tweak_hubs(&self) -> Result<Vec<(String, u32)>, Error> {
        let hubs = self.hubs()?.into_iter();
        let mut hubs: Vec<(String, u32)> = hubs.filter_map(|(u, i)| Some((u, i.tweaks?))).collect();
        hubs.sort_by_key(|(_, first)| *first);
        Ok(hubs)
    }

    /// Look in up to `max` blocks from the next with the tweaks of `hubs`,
    /// each with the first block it serves the tweaks of, those `ahead`
    /// first; without any if none.
    async fn scan_with(
        &self,
        hubs: &[(String, u32)],
        mut ahead: Option<SilentTweaks>,
        chain: &impl Blocks,
        max: u32,
    ) -> Result<Scanned, Error> {
        let first = hubs.iter().min_by_key(|(_, first)| *first);
        if self.silent_next()?.is_none() {
            return Err(not_watching());
        }
        let height = chain.height().await.map_err(chain_error)?;
        let mut next = self.unwind(chain, height).await?;
        if let Some((_, first)) = first {
            next = self.look_again(next, *first)?;
        }
        let mut scanned = Scanned {
            next,
            height,
            found: Vec::new(),
            spent: Vec::new(),
            fetched: 0,
        };
        if next > height || max == 0 {
            return Ok(scanned);
        }
        if let Some((url, first)) = first {
            if next < *first {
                return Err(Error::Invalid(format!(
                    "hub {url} serves tweaks from block {first} on, not {next}"
                )));
            }
        }
        let end = height.min(next.saturating_add(max - 1));
        // Read after the chain's height: an address handed out meanwhile is
        // paid in a later block than these.
        let scanner = self.keys.silent.scanner([]);
        let (watched, _) = self.store.read(|c| fallbacks(c, &scanner))?;
        let mut finder = Finder {
            scanner,
            fallbacks: watched,
        };
        let mut coins = self.held_outputs()?;
        // The hubs served fewer blocks than asked for: none has more.
        let mut indexed = false;
        while scanned.next <= end && !indexed {
            let count = (end - scanned.next + 1).min(MAX_TWEAK_BLOCKS);
            let mut batch = Batch::default();
            if hubs.is_empty() {
                for at in scanned.next..scanned.next + count {
                    let hash = chain.hash(at).await.map_err(chain_error)?;
                    let fetched = self
                        .look(chain, &finder, at, hash, &[], &mut coins, &mut batch)
                        .await?;
                    scanned.fetched += u32::from(fetched);
                }
            } else {
                let tweaks = match ahead.take() {
                    Some(mut ahead) if ahead.from == scanned.next => {
                        ahead.blocks.truncate(count as usize);
                        match still_of(chain, &ahead).await? {
                            true => ahead,
                            false => self.union(hubs, chain, scanned.next, count).await?,
                        }
                    }
                    _ => self.union(hubs, chain, scanned.next, count).await?,
                };
                indexed = tweaks.blocks.len() < count as usize;
                for (at, (hash, points)) in (scanned.next..).zip(&tweaks.blocks) {
                    let fetched = self
                        .look(chain, &finder, at, *hash, points, &mut coins, &mut batch)
                        .await?;
                    scanned.fetched += u32::from(fetched);
                }
            }
            let Some(&(last, _)) = batch.blocks.last() else {
                break;
            };
            self.record_silent(scanned.next, &batch, hubs.is_empty())?;
            scanned.next = last + 1;
            // A fallback paid: those past it are watched from the next block.
            if !batch.found.is_empty() {
                finder.fallbacks = self.store.read(|c| fallbacks(c, &finder.scanner))?.0;
            }
            scanned
                .found
                .extend(
                    batch
                        .found
                        .iter()
                        .map(|(outpoint, value, found, height)| SilentCoin {
                            outpoint: *outpoint,
                            value: *value,
                            height: *height,
                            change: found.label == Some(CHANGE),
                            spending: None,
                        }),
                );
            scanned
                .spent
                .extend(batch.spent.iter().map(|(outpoint, ..)| *outpoint));
        }
        if !scanned.found.is_empty() || !scanned.spent.is_empty() {
            tracing::info!(
                found = scanned.found.len(),
                spent = scanned.spent.len(),
                next = scanned.next,
                "silent payments scanned"
            );
        }
        Ok(scanned)
    }

    /// The tweaks of up to `count` blocks from `from`, asked at once of
    /// those of `hubs` serving `from`'s ([`Wallet::silent_tweaks`]).
    async fn union(
        &self,
        hubs: &[(String, u32)],
        chain: &impl Blocks,
        from: u32,
        count: u32,
    ) -> Result<SilentTweaks, Error> {
        let asked: Vec<&str> = (hubs.iter())
            .filter(|(_, first)| *first <= from)
            .map(|(url, _)| url.as_str())
            .collect();
        let asks = asked
            .iter()
            .map(|url| self.tweaks_of(url, from, count))
            .collect();
        // Only once one served every block asked for: a hub behind answers
        // at once with fewer, and one ahead of it may be slower.
        let whole = |answer: &Result<Vec<_>, Error>| {
            answer.as_ref().is_ok_and(|b| b.len() == count as usize)
        };
        let answers = gather(asks, whole, GRACE).await;
        let mut served = Vec::new();
        // Why each hub, in the order asked, was passed over.
        let mut failed: Vec<Option<Error>> = asked.iter().map(|_| None).collect();
        let mut pass_over = |i: usize, e: Error| {
            if asked.len() > 1 {
                tracing::warn!(hub = %asked[i], from, "tweaks passed over: {e}");
            }
            failed[i] = Some(e);
        };
        for (i, (url, answer)) in asked.iter().zip(answers).enumerate() {
            match answer {
                Some(Ok(blocks)) => served.push((i, *url, blocks)),
                Some(Err(e)) => pass_over(i, e),
                None => {
                    tracing::warn!(
                        hub = %url,
                        from,
                        "tweaks passed over: no answer within {} s of another hub's",
                        GRACE.as_secs()
                    );
                    self.transport.gave_up(url);
                }
            }
        }
        // Each block's hash read once, for every hub that served it.
        let longest = served.iter().map(|(.., b)| b.len()).max().unwrap_or(0);
        let mut hashes = Vec::with_capacity(longest);
        for at in (from..).take(longest) {
            hashes.push(chain.hash(at).await.map_err(chain_error)?);
        }
        let mut checked: Vec<(&str, Vec<Vec<PublicKey>>)> = Vec::new();
        'hubs: for (i, url, blocks) in served {
            let mut points = Vec::with_capacity(blocks.len());
            for ((at, (hash, theirs)), chains) in (from..).zip(blocks).zip(&hashes) {
                if hash != chains.to_string() {
                    let e = format!("its block {at} is {hash}, the chain's {chains}");
                    pass_over(i, unavailable(url, e));
                    continue 'hubs;
                }
                points.push(theirs);
            }
            checked.push((url, points));
        }
        if checked.is_empty() {
            let first = failed.into_iter().flatten().next();
            return Err(first.unwrap_or_else(|| Error::Invalid("no hub serves the tweaks".into())));
        }
        let longest = checked.iter().map(|(_, b)| b.len()).max().unwrap_or(0);
        let mut blocks = Vec::with_capacity(longest);
        // Of each hub, the blocks it served fewer tweaks of than another,
        // and the first.
        let mut omitted: HashMap<&str, (u32, u32)> = HashMap::new();
        for (i, hash) in hashes.into_iter().take(longest).enumerate() {
            let serving: Vec<(&str, &Vec<PublicKey>)> = (checked.iter())
                .filter_map(|(url, b)| Some((*url, b.get(i)?)))
                .collect();
            let mut seen = HashSet::new();
            let points: Vec<PublicKey> = (serving.iter())
                .flat_map(|(_, points)| *points)
                .filter(|p| seen.insert(**p))
                .copied()
                .collect();
            for (url, theirs) in &serving {
                if theirs.iter().collect::<HashSet<_>>().len() < points.len() {
                    let at = from + i as u32;
                    omitted.entry(url).or_insert((0, at)).0 += 1;
                }
            }
            blocks.push((hash, points));
        }
        for (url, (count, first)) in omitted {
            let others: Vec<&str> = (checked.iter())
                .map(|(other, _)| *other)
                .filter(|other| *other != url)
                .collect();
            tracing::warn!(
                hub = %url,
                others = %others.join(", "),
                blocks = count,
                block = first,
                "a hub serves fewer tweaks of blocks than other hubs: one hides payments, \
                 or another adds tweaks of none"
            );
        }
        Ok(SilentTweaks { from, blocks })
    }

    /// The tweaks of up to `count` blocks from `from` the hub at `url`
    /// serves, and the hash it names each block by: up to the newest block
    /// it indexed.
    async fn tweaks_of(
        &self,
        url: &str,
        from: u32,
        count: u32,
    ) -> Result<Vec<(String, Vec<PublicKey>)>, Error> {
        let path = format!("{TWEAKS}?from={from}&count={count}");
        let served: Vec<BlockTweaks> = self.get(url, &path).await?;
        let mut blocks = Vec::with_capacity(served.len().min(count as usize));
        for (at, tweaks) in (from..).zip(served.into_iter().take(count as usize)) {
            if tweaks.height != at {
                return Err(unavailable(
                    url,
                    format!("tweaks of block {} asked for {at}", tweaks.height),
                ));
            }
            let points = tweaks.tweaks.iter().map(|t| PublicKey::from_slice(&t.0));
            let points = points
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| unavailable(url, format!("a tweak of block {at}: {e}")))?;
            blocks.push((tweaks.hash, points));
        }
        Ok(blocks)
    }

    /// Before looking on from `next` with a hub serving tweaks from block
    /// `first` on: look again from the first block looked in without them
    /// it serves tweaks of, forgetting what was found from it on until
    /// found again. The next block to look in. Those before `first` stay to
    /// look in again once a hub serves their tweaks; none is looked in
    /// again if the hub serves none of them.
    fn look_again(&self, next: u32, first: u32) -> Result<u32, Error> {
        if next < first {
            return Ok(next);
        }
        let from = self.store.write(|t| {
            let (untweaked, until): (Option<u32>, Option<u32>) = t.query_row(
                "SELECT untweaked_height, untweaked_until FROM silent_scan",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let Some(untweaked) = untweaked else {
                return Ok(next);
            };
            let from = untweaked.max(first);
            if from >= until.unwrap_or(next).min(next) {
                return Ok(next);
            }
            if !rewind(t, next, from)? {
                return Err(raced());
            }
            // What is left of them: those before `first`, if any.
            let kept = if untweaked < from {
                t.execute(
                    "UPDATE silent_scan SET untweaked_until = ?1 WHERE next_height = ?1",
                    [from],
                )?
            } else {
                t.execute(
                    "UPDATE silent_scan SET untweaked_height = NULL, untweaked_until = NULL
                     WHERE next_height = ?1",
                    [from],
                )?
            };
            if kept == 0 {
                return Err(raced());
            }
            Ok(from)
        })?;
        if from < next {
            tracing::info!(from, next, "silent payments looked for again with tweaks");
        }
        Ok(from)
    }

    /// Look in block `at`, of `hash`, with its tweaks `points`, adding to
    /// `batch` what it holds for the wallet, and to `coins` the coins found:
    /// whether the block was fetched.
    #[allow(clippy::too_many_arguments)]
    async fn look(
        &self,
        chain: &impl Blocks,
        finder: &Finder,
        at: u32,
        hash: BlockHash,
        points: &[PublicKey],
        coins: &mut HashMap<OutPoint, XOnlyPublicKey>,
        batch: &mut Batch,
    ) -> Result<bool, Error> {
        batch.blocks.push((at, hash));
        let candidates: Vec<Vec<XOnlyPublicKey>> = points
            .iter()
            .map(|p| finder.scanner.candidates(p))
            .collect();
        let scripts: Vec<ScriptBuf> = candidates
            .iter()
            .flatten()
            .chain(coins.values())
            .chain(finder.fallbacks.keys())
            .map(|key| p2tr(*key))
            .collect();
        if scripts.is_empty() {
            return Ok(false);
        }
        let matched = match chain.filter(&hash).await.map_err(chain_error)? {
            None => true,
            Some(filter) => BlockFilter::new(&filter)
                .match_any(&hash, scripts.iter().map(|s| s.as_bytes()))
                .map_err(|e| chain_error(format!("the filter of block {hash}: {e}")))?,
        };
        if !matched {
            return Ok(false);
        }
        let block = chain.block(&hash).await.map_err(chain_error)?;
        if block.block_hash() != hash || !block.check_merkle_root() {
            return Err(chain_error(format!(
                "block {hash} does not match its header"
            )));
        }
        // The transactions each output key is in: anyone may pay a key
        // seen again, in a transaction of its own.
        let mut keys: HashMap<XOnlyPublicKey, Vec<usize>> = HashMap::new();
        for (i, tx) in block.txdata.iter().enumerate() {
            for key in silent::taproot_outputs(tx) {
                keys.entry(key).or_default().push(i);
            }
        }
        let mut paying: HashMap<usize, Vec<&PublicKey>> = HashMap::new();
        for (point, candidates) in points.iter().zip(&candidates) {
            let txs: HashSet<usize> = candidates
                .iter()
                .filter_map(|c| keys.get(c))
                .flatten()
                .copied()
                .collect();
            for i in txs {
                paying.entry(i).or_default().push(point);
            }
        }
        // In the block's order: a coin may be paid and spent in one block.
        for (i, tx) in block.txdata.iter().enumerate() {
            let txid = tx.compute_txid();
            let own = own_tweak(tx, coins);
            for input in &tx.input {
                if coins.remove(&input.previous_output).is_some() {
                    batch.spent.push((input.previous_output, txid, at));
                }
            }
            let mut seen = HashSet::new();
            let points = paying.get(&i).into_iter().flatten().copied();
            for point in points.chain(own.as_ref()) {
                let outputs = silent::taproot_outputs(tx);
                for found in finder.scanner.scan(point, &outputs) {
                    // Each output paying its key, should it pay it twice.
                    let script = p2tr(found.output);
                    for (vout, output) in tx.output.iter().enumerate() {
                        if output.script_pubkey != script {
                            continue;
                        }
                        let outpoint = OutPoint::new(txid, vout as u32);
                        if seen.insert(outpoint) {
                            coins.insert(outpoint, found.output);
                            batch
                                .found
                                .push((outpoint, output.value.to_sat(), found, at));
                        }
                    }
                }
            }
            for (vout, output) in tx.output.iter().enumerate() {
                let Some(found) = finder.fallback(&output.script_pubkey) else {
                    continue;
                };
                let outpoint = OutPoint::new(txid, vout as u32);
                if seen.insert(outpoint) {
                    coins.insert(outpoint, found.output);
                    batch
                        .found
                        .push((outpoint, output.value.to_sat(), *found, at));
                }
            }
        }
        Ok(true)
    }

    /// Undo what blocks a reorganization took out of the best chain, of
    /// height `height`, held: the next block to look in.
    async fn unwind(&self, chain: &impl Blocks, height: u32) -> Result<u32, Error> {
        let (next, kept) = self.store.read(|c| {
            let next: u32 = c.query_row("SELECT next_height FROM silent_scan", [], |r| r.get(0))?;
            let mut stmt =
                c.prepare("SELECT height, hash FROM silent_blocks ORDER BY height DESC")?;
            let rows =
                stmt.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, [u8; 32]>(1)?)))?;
            let kept = rows.collect::<Result<Vec<_>, _>>()?;
            Ok((next, kept))
        })?;
        let Some(&(top, _)) = kept.first() else {
            return Ok(next);
        };
        // A chain behind the blocks looked in proves nothing: wait for it.
        if top > height {
            return Ok(next);
        }
        let mut fork = None;
        for (at, hash) in &kept {
            let theirs = chain.hash(*at).await.map_err(chain_error)?;
            if theirs.to_byte_array() == *hash {
                fork = Some(*at);
                break;
            }
        }
        let from = match fork {
            Some(at) if at == top => return Ok(next),
            Some(at) => at + 1,
            None => {
                return Err(Error::Invalid(format!(
                    "a reorganization deeper than the {} blocks kept: \
                     watch_silent from an earlier block to look again",
                    kept.len()
                )))
            }
        };
        self.store.write(|t| {
            if !rewind(t, next, from)? {
                return Err(raced());
            }
            Ok(())
        })?;
        tracing::warn!(
            from,
            top,
            "reorganization: silent payments looked for again"
        );
        Ok(from)
    }

    /// Record `batch`, looked in from block `from`, without tweaks if
    /// `untweaked`, unless another scan moved on meanwhile.
    fn record_silent(&self, from: u32, batch: &Batch, untweaked: bool) -> Result<(), Error> {
        let Some(&(last, _)) = batch.blocks.last() else {
            return Ok(());
        };
        self.store.write(|t| {
            let moved = t.execute(
                "UPDATE silent_scan SET next_height = ?2 WHERE next_height = ?1",
                [from, last + 1],
            )?;
            if moved == 0 {
                return Err(raced());
            }
            if untweaked {
                // Those looked in with tweaks between are looked in again
                // too: what is kept is one span.
                t.execute(
                    "UPDATE silent_scan
                     SET untweaked_height = coalesce(untweaked_height, ?1), untweaked_until = NULL",
                    [from],
                )?;
            } else {
                t.execute(
                    "UPDATE silent_scan SET untweaked_until = ?1
                     WHERE untweaked_height IS NOT NULL AND untweaked_until IS NULL",
                    [from],
                )?;
            }
            let pending = if batch.found.is_empty() && batch.spent.is_empty() {
                HashMap::new()
            } else {
                pending_inputs(t)?
            };
            for (outpoint, value, found, height) in &batch.found {
                t.execute(
                    "INSERT OR IGNORE INTO silent_coins
                         (txid, vout, value, output, tweak, label, height, spent_by)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        outpoint.txid.to_byte_array(),
                        outpoint.vout,
                        crate::store::sql(*value)?,
                        found.output.serialize(),
                        found.tweak.secret_bytes(),
                        found.label,
                        height,
                        pending.get(outpoint).map(|txid| txid.to_byte_array())
                    ],
                )?;
            }
            for (outpoint, by, height) in &batch.spent {
                t.execute(
                    "UPDATE silent_coins SET spent_by = ?3, spent_height = ?4
                     WHERE txid = ?1 AND vout = ?2",
                    params![
                        outpoint.txid.to_byte_array(),
                        outpoint.vout,
                        by.to_byte_array(),
                        height
                    ],
                )?;
                // A spend of the wallet's own that a block's conflicts with
                // can never confirm: its other coins are free again.
                if let Some(own) = pending.get(outpoint).filter(|own| *own != by) {
                    give_up(t, own)?;
                    tracing::info!(txid = %own, "silent payment spend replaced in a block");
                }
            }
            for (height, hash) in &batch.blocks {
                t.execute(
                    "INSERT OR REPLACE INTO silent_blocks (height, hash) VALUES (?1, ?2)",
                    params![height, hash.to_byte_array()],
                )?;
            }
            t.execute(
                "DELETE FROM silent_blocks WHERE height + ?2 <= ?1",
                [last, KEEP_BLOCKS],
            )?;
            Ok(())
        })
    }

    /// The output keys of the coins not spent in a block, by outpoint.
    fn held_outputs(&self) -> Result<HashMap<OutPoint, XOnlyPublicKey>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT txid, vout, output FROM silent_coins WHERE spent_height IS NULL",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, [u8; 32]>(0)?,
                    r.get::<_, u32>(1)?,
                    r.get::<_, [u8; 32]>(2)?,
                ))
            })?;
            let mut held = HashMap::new();
            for row in rows {
                let (txid, vout, output) = row?;
                let output = XOnlyPublicKey::from_slice(&output).map_err(invalid)?;
                held.insert(OutPoint::new(Txid::from_byte_array(txid), vout), output);
            }
            Ok(held)
        })
    }

    /// Watch the fallback addresses from the first on, though none is
    /// handed out here yet: a wallet restored from its words, whose copy
    /// may have handed some out and been paid there. Nothing if some are
    /// watched already.
    pub fn watch_fallbacks(&self) -> Result<(), Error> {
        self.store.write(|t| {
            t.execute(
                "INSERT INTO silent_fallback (one, shown) VALUES (1, 0)
                 ON CONFLICT (one) DO NOTHING",
                [],
            )?;
            Ok(())
        })
    }

    /// Hand out the fallback address to show: the one handed out last
    /// until it is paid, then the next. Watched from then on, also by scans
    /// without a hub's tweaks: a plain taproot address to fund the wallet
    /// at, or to pay back to.
    pub fn fallback_address(&self) -> Result<bitcoin::Address, Error> {
        let scanner = self.keys.silent.scanner([]);
        let found = self.store.write(|t| {
            let (_, next) = fallbacks(t, &scanner)?;
            t.execute(
                "INSERT INTO silent_fallback (one, shown) VALUES (1, ?1)
                 ON CONFLICT (one) DO UPDATE SET shown = max(shown, excluded.shown)",
                [next],
            )?;
            scanner.fallback(next).map_err(invalid)
        })?;
        let key = TweakedPublicKey::dangerous_assume_tweaked(found.output);
        Ok(bitcoin::Address::p2tr_tweaked(
            key,
            licash_onchain::network(self.network),
        ))
    }
}

impl<T: Transport> Wallet<T> {
    /// Every coin the wallet found, spent or not, or only those spent
    /// (`spent`): those that may have opened a contract.
    pub(crate) fn silent_outpoints(&self, spent: bool) -> Result<Vec<OutPoint>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT txid, vout FROM silent_coins
                 WHERE NOT ?1 OR spent_by IS NOT NULL ORDER BY height, txid, vout",
            )?;
            let rows = stmt.query_map([spent], |r| {
                Ok(OutPoint::new(
                    Txid::from_byte_array(r.get::<_, [u8; 32]>(0)?),
                    r.get(1)?,
                ))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The coins at the silent payment address not spent in a block,
    /// oldest first.
    pub fn silent_coins(&self) -> Result<Vec<SilentCoin>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT txid, vout, value, height, label, spent_by FROM silent_coins
                 WHERE spent_height IS NULL ORDER BY height, txid, vout",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(SilentCoin {
                    outpoint: OutPoint::new(
                        Txid::from_byte_array(r.get::<_, [u8; 32]>(0)?),
                        r.get(1)?,
                    ),
                    value: r.get::<_, i64>(2)? as u64,
                    height: r.get(3)?,
                    change: r.get::<_, Option<u32>>(4)? == Some(CHANGE),
                    spending: r.get::<_, Option<[u8; 32]>>(5)?.map(Txid::from_byte_array),
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The scripts of the fallback addresses watched: those handed out in
    /// payment codes, and 20 after; none until one is. What a
    /// light client watches unconfirmed transactions for.
    pub fn fallback_scripts(&self) -> Result<Vec<ScriptBuf>, Error> {
        let scanner = self.keys.silent.scanner([]);
        let (watched, _) = self.store.read(|c| fallbacks(c, &scanner))?;
        let mut scripts: Vec<ScriptBuf> = watched.into_keys().map(p2tr).collect();
        scripts.sort();
        Ok(scripts)
    }

    /// The outputs of `txs` paying the fallback addresses watched that no
    /// scan found in a block yet, with their values: payments on their way,
    /// as a light client's peers relay them. A peer can make one up, and
    /// one can be dropped or replaced: only a scan finds coins.
    pub fn unconfirmed_payments(&self, txs: &[Transaction]) -> Result<Vec<(OutPoint, u64)>, Error> {
        let scripts: HashSet<ScriptBuf> = self.fallback_scripts()?.into_iter().collect();
        let found: HashSet<OutPoint> = self.store.read(|c| {
            let mut stmt = c.prepare("SELECT txid, vout FROM silent_coins")?;
            let rows = stmt.query_map([], |r| {
                Ok(OutPoint::new(Txid::from_byte_array(r.get(0)?), r.get(1)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let (mut paying, mut seen) = (Vec::new(), HashSet::new());
        for tx in txs {
            let txid = tx.compute_txid();
            for (vout, output) in (0..).zip(&tx.output) {
                let outpoint = OutPoint::new(txid, vout);
                if scripts.contains(&output.script_pubkey)
                    && !found.contains(&outpoint)
                    && seen.insert(outpoint)
                {
                    paying.push((outpoint, output.value.to_sat()));
                }
            }
        }
        Ok(paying)
    }

    /// The wallet's transactions spending its coins that are in no block
    /// yet, oldest first: to broadcast again until they are.
    pub fn silent_spends(&self) -> Result<Vec<Transaction>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT tx FROM silent_spends s
                 WHERE EXISTS (SELECT 1 FROM silent_coins c
                               WHERE c.spent_by = s.txid AND c.spent_height IS NULL)
                 ORDER BY created_at, txid",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.map(|tx| bitcoin::consensus::deserialize(&tx?).map_err(invalid))
                .collect()
        })
    }

    /// The wallet's transactions of its coins paying `script`, oldest
    /// first, in a block or not: none given up.
    pub fn silent_spends_paying(&self, script: &Script) -> Result<Vec<SilentSpend>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare("SELECT tx FROM silent_spends ORDER BY created_at, txid")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            let raw = rows.collect::<Result<Vec<_>, _>>()?;
            let mut spends = Vec::new();
            for tx in raw {
                let tx: Transaction = bitcoin::consensus::deserialize(&tx).map_err(invalid)?;
                if tx.output.iter().any(|o| o.script_pubkey == *script) {
                    spends.push(described(c, tx)?);
                }
            }
            Ok(spends)
        })
    }

    /// The wallet's transaction `txid` of its coins, in a block or not:
    /// none unless it made it and did not give it up.
    pub fn silent_spend(&self, txid: &Txid) -> Result<Option<SilentSpend>, Error> {
        self.store.read(|c| {
            let raw: Option<Vec<u8>> = c
                .query_row(
                    "SELECT tx FROM silent_spends WHERE txid = ?1",
                    [txid.to_byte_array()],
                    |r| r.get(0),
                )
                .optional()?;
            raw.map(|raw| {
                let tx = bitcoin::consensus::deserialize(&raw).map_err(invalid)?;
                described(c, tx)
            })
            .transpose()
        })
    }

    /// What the wallet's coin at `outpoint` pays, as a transaction
    /// spending it names it: none unless it is the wallet's and no block
    /// spends it.
    pub fn silent_coin_output(&self, outpoint: &OutPoint) -> Result<Option<TxOut>, Error> {
        self.store.read(|c| {
            Ok(coin(c, outpoint)?.map(|(held, _)| TxOut {
                value: Amount::from_sat(held.value),
                script_pubkey: p2tr(held.found.output),
            }))
        })
    }

    /// The block a scan saw the wallet's coin at `outpoint` spent in: none
    /// while no block spends it, or once that block was replaced, or if
    /// the coin is not the wallet's. How deep another party's transaction
    /// spending it is, as a contract's funding.
    pub fn silent_spent_at(&self, outpoint: &OutPoint) -> Result<Option<u32>, Error> {
        self.store.read(|c| {
            let at = c
                .query_row(
                    "SELECT spent_height FROM silent_coins WHERE txid = ?1 AND vout = ?2",
                    params![outpoint.txid.to_byte_array(), outpoint.vout],
                    |r| r.get::<_, Option<u32>>(0),
                )
                .optional()?;
            Ok(at.flatten())
        })
    }

    /// Sign input `index` of `tx`, another party's transaction spending one
    /// of the wallet's coins among coins of its own, as a contract's
    /// funding does: on the key path, committing to `prevouts`, the coin
    /// each input spends. The wallet's coin is reserved for `tx`, so that
    /// no spend or deposit takes it, until [`Wallet::abandon_silent`]
    /// frees it or a scan sees it spent. Nothing is recorded to broadcast:
    /// completing `tx` is the other party's. Signing `tx` again signs it
    /// again; a coin reserved for another transaction, spent, not the
    /// wallet's, or other than `prevouts` says, is refused.
    pub fn sign_input(
        &self,
        tx: &Transaction,
        prevouts: &[TxOut],
        index: usize,
    ) -> Result<Transaction, Error> {
        if prevouts.len() != tx.input.len() {
            return Err(Error::Invalid(format!(
                "{} coins for {} inputs",
                prevouts.len(),
                tx.input.len()
            )));
        }
        let Some(input) = tx.input.get(index) else {
            return Err(Error::Invalid(format!("no input {index}")));
        };
        let outpoint = input.previous_output;
        let txid = tx.compute_txid();
        let keys = &self.keys.silent;
        let signed = self.store.write(|t| {
            let Some((held, spent_by)) = coin(t, &outpoint)? else {
                return Err(Error::Invalid(format!(
                    "coin {outpoint}: not the wallet's, or spent"
                )));
            };
            if spent_by.is_some_and(|by| by != txid) {
                return Err(Error::NoteTaken);
            }
            let want = TxOut {
                value: Amount::from_sat(held.value),
                script_pubkey: p2tr(held.found.output),
            };
            if prevouts[index] != want {
                return Err(Error::Invalid(format!(
                    "coin {outpoint}: not the coin the wallet holds"
                )));
            }
            let secret = keys.spend_secret(&held.found).map_err(invalid)?;
            let signature = key_spend(tx, prevouts, index, &held, &secret)?;
            t.execute(
                "UPDATE silent_coins SET spent_by = ?3
                 WHERE txid = ?1 AND vout = ?2 AND spent_height IS NULL",
                params![
                    outpoint.txid.to_byte_array(),
                    outpoint.vout,
                    txid.to_byte_array()
                ],
            )?;
            let mut signed = tx.clone();
            signed.input[index].witness = Witness::p2tr_key_spend(&signature);
            Ok(signed)
        })?;
        tracing::info!(%txid, %outpoint, "silent payment coin signed for another's transaction");
        Ok(signed)
    }

    /// Cancel the wallet's input `index` of `tx`, another party's
    /// transaction it signed ([`Wallet::sign_input`]), which it cannot
    /// broadcast: the coin spent whole back to the wallet's change address
    /// at `rate`, signed and recorded as its spend in the place of `tx`, for
    /// the application to broadcast. Asked again, the cancel made before.
    /// Refused unless the coin is the wallet's, reserved for `tx` or so
    /// canceled, and in no block spent; or if what is left is dust.
    pub fn cancel_signed(
        &self,
        tx: &Transaction,
        index: usize,
        rate: FeeRate,
    ) -> Result<Transaction, Error> {
        let Some(input) = tx.input.get(index) else {
            return Err(Error::Invalid(format!("no input {index}")));
        };
        let outpoint = input.previous_output;
        let txid = tx.compute_txid();
        let keys = &self.keys.silent;
        let cancel = self.store.write(|t| {
            let Some((held, spent_by)) = coin(t, &outpoint)? else {
                return Err(Error::Invalid(format!(
                    "coin {outpoint}: not the wallet's, or spent"
                )));
            };
            match spent_by {
                Some(by) if by == txid => {}
                Some(by) => {
                    let made: Option<Vec<u8>> = t
                        .query_row(
                            "SELECT tx FROM silent_spends WHERE txid = ?1",
                            [by.to_byte_array()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let made = made
                        .map(|m| bitcoin::consensus::deserialize::<Transaction>(&m))
                        .transpose()
                        .map_err(invalid)?;
                    return match made {
                        Some(m) if m.input.len() == 1 && m.input[0].previous_output == outpoint => {
                            Ok(m)
                        }
                        _ => Err(Error::NoteTaken),
                    };
                }
                None => {
                    return Err(Error::Invalid(format!(
                        "coin {outpoint}: signed into no transaction {txid}"
                    )))
                }
            }
            let secret = keys.spend_secret(&held.found).map_err(invalid)?;
            let change = keys.scanner([]).labeled(CHANGE);
            let script = silent::outputs(&[(secret, true)], &[outpoint], &[change])
                .map_err(invalid)?
                .into_iter()
                .map(p2tr)
                .next()
                .expect("the change's output");
            let mut output = TxOut {
                value: Amount::ZERO,
                script_pubkey: script,
            };
            let fee = fee(1, std::slice::from_ref(&output), rate);
            let dust = output.script_pubkey.minimal_non_dust().to_sat();
            output.value = Amount::from_sat(
                held.value
                    .checked_sub(fee)
                    .filter(|back| *back >= dust)
                    .ok_or(Error::Insufficient {
                        needed: fee.saturating_add(dust),
                        available: held.value,
                    })?,
            );
            let cancel = sign(&[held], &[secret], vec![output])?;
            let new = cancel.compute_txid().to_byte_array();
            t.execute(
                "INSERT INTO silent_spends (txid, tx, created_at) VALUES (?1, ?2, ?3)",
                params![new, bitcoin::consensus::serialize(&cancel), now()],
            )?;
            t.execute(
                "UPDATE silent_coins SET spent_by = ?3
                 WHERE txid = ?1 AND vout = ?2 AND spent_height IS NULL",
                params![outpoint.txid.to_byte_array(), outpoint.vout, new],
            )?;
            Ok(cancel)
        })?;
        tracing::info!(%txid, cancel = %cancel.compute_txid(), %outpoint, "silent payment coin signed for another's transaction canceled");
        Ok(cancel)
    }

    /// Set the wallet's coin at `outpoint` aside under `marker`, a txid of
    /// no transaction, as [`Wallet::sign_input`] sets one aside for a
    /// transaction to come: no spend or deposit takes it until
    /// [`Wallet::abandon_silent`] of `marker` frees it, or a scan sees it
    /// spent. Setting it aside again under `marker` is no error; a coin
    /// set aside otherwise, spent or not the wallet's is refused. A
    /// reorganization of its block frees it.
    pub fn reserve_silent(&self, outpoint: &OutPoint, marker: &Txid) -> Result<(), Error> {
        self.store.write(|t| {
            let Some((_, spent_by)) = coin(t, outpoint)? else {
                return Err(Error::Invalid(format!(
                    "coin {outpoint}: not the wallet's, or spent"
                )));
            };
            if spent_by.is_some_and(|by| by != *marker) {
                return Err(Error::NoteTaken);
            }
            t.execute(
                "UPDATE silent_coins SET spent_by = ?3
                 WHERE txid = ?1 AND vout = ?2 AND spent_height IS NULL",
                params![
                    outpoint.txid.to_byte_array(),
                    outpoint.vout,
                    marker.to_byte_array()
                ],
            )?;
            Ok(())
        })?;
        tracing::info!(%marker, %outpoint, "silent payment coin set aside");
        Ok(())
    }

    /// Give up the wallet's spend `txid`, never broadcast or dropped by the
    /// network, freeing its coins: should it reach a block after all, a
    /// scan sees them spent.
    pub fn abandon_silent(&self, txid: &Txid) -> Result<(), Error> {
        let freed = self.store.write(|t| give_up(t, txid))?;
        if freed == 0 {
            return Err(Error::UnknownPayment(txid.to_string()));
        }
        tracing::info!(%txid, freed, "silent payment spend abandoned");
        Ok(())
    }

    /// Cancel the wallet's spend `txid`, in no block yet: a spend of its
    /// coins, all of them, back to the wallet's change address at `rate`,
    /// or at what takes the place of `txid` in a mempool if more (its fee
    /// and 1 sat/vB of its own size, BIP125), signed and recorded as their
    /// spend in its place, for the application to broadcast. A cancel is
    /// made again the same way. Refused unless `txid` is the wallet's spend
    /// of each of its coins, and no block spends them. Whichever of the two
    /// a block holds, a scan sees the coins spent by it, and the other
    /// given up.
    pub fn replace_silent(&self, txid: &Txid, rate: FeeRate) -> Result<Transaction, Error> {
        let tx = self.replace(txid, rate, false)?;
        tracing::info!(replaced = %txid, txid = %tx.compute_txid(), "silent payment spend canceled");
        Ok(tx)
    }

    /// Bump the wallet's spend `txid`, in no block yet: as
    /// [`Wallet::replace_silent`], but paying all `txid` pays besides its
    /// change, the fee taken from its change, which must stay. Refused
    /// as a cancel is, or if its change is gone or would be dust.
    pub fn bump_silent(&self, txid: &Txid, rate: FeeRate) -> Result<Transaction, Error> {
        let tx = self.replace(txid, rate, true)?;
        tracing::info!(replaced = %txid, txid = %tx.compute_txid(), "silent payment spend bumped");
        Ok(tx)
    }

    /// [`Wallet::replace_silent`], or, `keep`, [`Wallet::bump_silent`].
    fn replace(&self, txid: &Txid, rate: FeeRate, keep: bool) -> Result<Transaction, Error> {
        let keys = &self.keys.silent;
        let tx = self.store.write(|t| {
            let old: Option<Vec<u8>> = t
                .query_row(
                    "SELECT tx FROM silent_spends WHERE txid = ?1",
                    [txid.to_byte_array()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(old) = old else {
                return Err(Error::UnknownPayment(txid.to_string()));
            };
            let old: Transaction = bitcoin::consensus::deserialize(&old).map_err(invalid)?;
            let mut inputs = Vec::new();
            for input in &old.input {
                match coin(t, &input.previous_output)? {
                    Some((held, Some(by))) if by == *txid => inputs.push(held),
                    _ => {
                        return Err(Error::Invalid(format!(
                            "spend {txid}: not the wallet's spend of coin {}, or in a block",
                            input.previous_output
                        )))
                    }
                }
            }
            let held: u64 = inputs.iter().map(|h| h.value).sum();
            let old_fee = old
                .output
                .iter()
                .try_fold(held, |left, o| left.checked_sub(o.value.to_sat()))
                .ok_or_else(|| Error::Invalid(format!("spend {txid} pays more than its coins")))?;
            let secrets = inputs
                .iter()
                .map(|h| keys.spend_secret(&h.found))
                .collect::<Result<Vec<SecretKey>, _>>()
                .map_err(invalid)?;
            let keyed: Vec<(SecretKey, bool)> = secrets.iter().map(|s| (*s, true)).collect();
            let outpoints: Vec<OutPoint> = inputs.iter().map(|h| h.outpoint).collect();
            let change = keys.scanner([]).labeled(CHANGE);
            let script = silent::outputs(&keyed, &outpoints, &[change])
                .map_err(invalid)?
                .into_iter()
                .map(p2tr)
                .next()
                .expect("the change's output");
            let output = |value: u64| TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script.clone(),
            };
            // What it pays besides its change, in its order, if kept.
            let (mut paid, mut change) = (Vec::new(), None);
            for (i, o) in old.output.iter().enumerate() {
                match o.script_pubkey == script {
                    true => change = Some(i),
                    false => paid.push(o.clone()),
                }
            }
            if !keep {
                paid.clear();
            } else if change.is_none() {
                return Err(Error::Invalid(format!(
                    "spend {txid} pays no change to bump it with"
                )));
            }
            let pays = paid.iter().map(|o| o.value.to_sat()).sum::<u64>();
            let mut outputs = paid;
            let at = change.filter(|_| keep).unwrap_or(0).min(outputs.len());
            outputs.insert(at, output(0));
            let vsize = fee(inputs.len(), &outputs, FeeRate::from_sat_per_vb_u32(1));
            let fee = fee(inputs.len(), &outputs, rate).max(old_fee.saturating_add(vsize));
            let dust = script.minimal_non_dust().to_sat();
            let needed = fee.saturating_add(dust).saturating_add(pays);
            let back = (held.checked_sub(pays))
                .and_then(|left| left.checked_sub(fee))
                .filter(|back| *back >= dust)
                .ok_or(Error::Insufficient {
                    needed,
                    available: held,
                })?;
            outputs[at] = output(back);
            let tx = sign(&inputs, &secrets, outputs)?;
            let new = tx.compute_txid().to_byte_array();
            t.execute(
                "INSERT INTO silent_spends (txid, tx, created_at) VALUES (?1, ?2, ?3)",
                params![new, bitcoin::consensus::serialize(&tx), now()],
            )?;
            t.execute(
                "UPDATE silent_coins SET spent_by = ?2 WHERE spent_by = ?1 AND spent_height IS NULL",
                params![txid.to_byte_array(), new],
            )?;
            Ok(tx)
        })?;
        Ok(tx)
    }

    /// What spends the wallet's coin at `outpoint`, and the block a scan
    /// saw it in, if any: none unless the coin is the wallet's and a
    /// transaction of its own or a block spends it.
    pub fn silent_spender(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<(Txid, Option<u32>)>, Error> {
        self.store.read(|c| {
            let row = c
                .query_row(
                    "SELECT spent_by, spent_height FROM silent_coins WHERE txid = ?1 AND vout = ?2",
                    params![outpoint.txid.to_byte_array(), outpoint.vout],
                    |r| {
                        Ok((
                            r.get::<_, Option<[u8; 32]>>(0)?,
                            r.get::<_, Option<u32>>(1)?,
                        ))
                    },
                )
                .optional()?;
            Ok(row.and_then(|(by, at)| by.map(|by| (Txid::from_byte_array(by), at))))
        })
    }

    /// A transaction paying `amount` to `to`, or everything if `None`, of
    /// the coins at the silent payment address that no transaction spends,
    /// the fee at `rate` on top and change to the wallet's change address
    /// unless it would be dust: signed and recorded as spending its coins,
    /// for the application to broadcast.
    pub fn spend_silent(
        &self,
        to: impl Into<Payee>,
        amount: Option<u64>,
        rate: FeeRate,
    ) -> Result<Transaction, Error> {
        self.spend_silent_from(to.into(), amount, rate, Coins::Free)
    }

    /// [`Wallet::spend_silent`] of the one coin at `coin` alone, never
    /// joined with another: its change, if any, to the wallet's change
    /// address. For a wallet that never joins its coins, as joining them
    /// tells they are one owner's.
    pub fn spend_silent_coin(
        &self,
        to: impl Into<Payee>,
        coin: OutPoint,
        amount: Option<u64>,
        rate: FeeRate,
    ) -> Result<Transaction, Error> {
        self.spend_silent_from(to.into(), amount, rate, Coins::One(coin))
    }

    /// The largest of the wallet's free coins, if it pays `amount` to `to`
    /// alone, the fee at `rate` on top ([`Wallet::spend_silent_coin`]):
    /// none if no one coin does.
    pub fn silent_coin_paying(
        &self,
        to: &Payee,
        amount: u64,
        rate: FeeRate,
    ) -> Result<Option<OutPoint>, Error> {
        let script = match to {
            Payee::Script(script) => script.clone(),
            Payee::Silent(_) => any_taproot(),
        };
        let free = self.store.read(free_coins)?;
        let largest = free.into_iter().max_by_key(|h| h.value);
        Ok(largest
            .filter(|h| plan(std::slice::from_ref(h), &script, Some(amount), rate).is_ok())
            .map(|h| h.outpoint))
    }

    /// [`Wallet::spend_silent`] of `coins`.
    fn spend_silent_from(
        &self,
        to: Payee,
        amount: Option<u64>,
        rate: FeeRate,
        coins: Coins,
    ) -> Result<Transaction, Error> {
        if let Payee::Silent(address) = &to {
            let network = licash_onchain::network(self.network);
            if address.network != network.into() {
                return Err(Error::Invalid(format!(
                    "silent payment address {address}: not of {network}"
                )));
            }
        }
        let keys = &self.keys.silent;
        let tx = self.store.write(|t| {
            let script = match &to {
                Payee::Script(script) => script.clone(),
                Payee::Silent(_) => any_taproot(),
            };
            let held = coins.of(free_coins(t)?)?;
            let plan = plan(&held, &script, amount, rate)?;
            if matches!(coins, Coins::Whole(_)) && plan.change.is_some() {
                return Err(Error::Invalid(
                    "the coin pays more than is asked: change left".into(),
                ));
            }
            let secrets = plan
                .inputs
                .iter()
                .map(|h| keys.spend_secret(&h.found))
                .collect::<Result<Vec<SecretKey>, _>>()
                .map_err(invalid)?;
            // The silent payment outputs, the payee's first: derived
            // together, as those to one receiver must be.
            let mut silent = Vec::new();
            if let Payee::Silent(address) = &to {
                silent.push(*address);
            }
            if plan.change.is_some() {
                silent.push(keys.scanner([]).labeled(CHANGE));
            }
            let mut paid = match silent.is_empty() {
                true => Vec::new(),
                false => {
                    let keyed: Vec<(SecretKey, bool)> =
                        secrets.iter().map(|s| (*s, true)).collect();
                    let outpoints: Vec<OutPoint> = plan.inputs.iter().map(|h| h.outpoint).collect();
                    silent::outputs(&keyed, &outpoints, &silent).map_err(invalid)?
                }
            }
            .into_iter()
            .map(p2tr);
            let script_pubkey = match &to {
                Payee::Script(script) => script.clone(),
                Payee::Silent(_) => paid.next().expect("the payee's output"),
            };
            let mut outputs = vec![TxOut {
                value: Amount::from_sat(plan.pay),
                script_pubkey,
            }];
            if let Some(change) = plan.change {
                outputs.push(TxOut {
                    value: Amount::from_sat(change),
                    script_pubkey: paid.next().expect("the change's output"),
                });
                if OsRng.next_u32() & 1 == 1 {
                    outputs.swap(0, 1);
                }
            }
            let tx = sign(&plan.inputs, &secrets, outputs)?;
            let txid = tx.compute_txid();
            t.execute(
                "INSERT INTO silent_spends (txid, tx, created_at) VALUES (?1, ?2, ?3)",
                params![
                    txid.to_byte_array(),
                    bitcoin::consensus::serialize(&tx),
                    now()
                ],
            )?;
            for input in &plan.inputs {
                let taken = t.execute(
                    "UPDATE silent_coins SET spent_by = ?3
                     WHERE txid = ?1 AND vout = ?2 AND spent_by IS NULL",
                    params![
                        input.outpoint.txid.to_byte_array(),
                        input.outpoint.vout,
                        txid.to_byte_array()
                    ],
                )?;
                if taken != 1 {
                    return Err(Error::NoteTaken);
                }
            }
            Ok(tx)
        })?;
        tracing::info!(txid = %tx.compute_txid(), inputs = tx.input.len(), "silent payment coins spent");
        Ok(tx)
    }

    /// Deposit at the hub at `url` the coin at `coin`, whole and alone:
    /// notes of as much as it pays, the fee at `rate` and the hub's on
    /// top, no change left (what is too little to pay out goes to the
    /// fee). Refused if the hub takes less than all of it at once, or
    /// more. The deposit, and the transaction paying it, signed and
    /// recorded as spending the coin, for the application to broadcast.
    /// Should it never confirm, [`Wallet::abandon_silent`] frees the
    /// coin, and the deposit lapses unpaid. Nothing is kept of a deposit
    /// its hub did not answer: the coin stays free, to deposit again.
    pub async fn deposit_silent(
        &self,
        url: &str,
        coin: OutPoint,
        rate: FeeRate,
    ) -> Result<(Deposit, Transaction), Error> {
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let offer = info
            .deposits
            .ok_or_else(|| Error::Invalid(format!("hub {url} takes no deposits")))?;
        let least = least_deposited(&offer, rate);
        let (amount, pays) = self.whole(coin, rate, (offer.min, offer.max), least, &url, |a| {
            offer.pays(a)
        })?;
        let deposit = self
            .deposit_answered(hub, &info, (amount, pays), None)
            .await?;
        self.pay_deposit(deposit, coin, rate)
    }

    /// Deposit the coin at `coin`, whole and alone, through the swap
    /// provider at `provider` for notes at the hub at `url`
    /// ([`Wallet::deposit_through`]), as [`Wallet::deposit_silent`] does
    /// at a hub: the provider's fee and its claim's miners on top. A
    /// deposit the provider did not answer is kept, asked again on
    /// resuming, and lapses unpaid: the coin stays free.
    pub async fn deposit_silent_through(
        &self,
        provider: &str,
        url: &str,
        coin: OutPoint,
        rate: FeeRate,
    ) -> Result<(Deposit, Transaction), Error> {
        let offer = self.deposit_offer(provider, url).await?;
        let terms = offer.terms;
        let least = least_deposited_through(&terms, rate);
        let (amount, _) = self.whole(coin, rate, (terms.min, offer.max), least, provider, |a| {
            Some(terms.pays(a))
        })?;
        let deposit = self.deposit_through(provider, url, amount).await?;
        self.pay_deposit(deposit, coin, rate)
    }

    /// The most notes, within `min..=max`, a deposit paid by the coin at
    /// `coin` whole buys, the fee at `rate` and `pays` saying what each
    /// asks, and that payment: refused if the coin pays less than `least`,
    /// or more than `taker` takes at once.
    fn whole(
        &self,
        coin: OutPoint,
        rate: FeeRate,
        (min, max): (u64, u64),
        least: u64,
        taker: &str,
        pays: impl Fn(u64) -> Option<u64>,
    ) -> Result<(u64, u64), Error> {
        // What the coin pays a taproot output, as a deposit's is.
        let taproot = any_taproot();
        let held = Coins::One(coin).of(self.store.read(free_coins)?)?;
        let total = held.iter().map(|h| h.value).sum::<u64>();
        let available = plan(&held, &taproot, None, rate).map_or(0, |p| p.pay);
        let fits = |amount: u64| pays(amount).is_some_and(|pays| pays <= available);
        let (mut amount, mut over) = (0, max.saturating_add(1));
        while over - amount > 1 {
            let mid = amount + (over - amount) / 2;
            match fits(mid) {
                true => amount = mid,
                false => over = mid,
            }
        }
        if amount < min {
            return Err(Error::Insufficient {
                needed: least,
                available: total,
            });
        }
        // All of it, or not at all: none left as change.
        let pays = pays(amount).unwrap_or(u64::MAX);
        if plan(&held, &taproot, Some(pays), rate).is_ok_and(|p| p.change.is_some()) {
            return Err(Error::Invalid(format!(
                "a coin of {total} sat: more than {taker} takes at once ({max} sat of notes at most)"
            )));
        }
        Ok((amount, pays))
    }

    /// The transaction paying `deposit` with the coin at `coin`, whole, at
    /// `rate`: signed and recorded as spending it.
    fn pay_deposit(
        &self,
        deposit: Deposit,
        coin: OutPoint,
        rate: FeeRate,
    ) -> Result<(Deposit, Transaction), Error> {
        let terms = match (&deposit.state, &deposit.terms) {
            (DepositState::Open, Some(terms)) => terms,
            (state, _) => {
                return Err(Error::Invalid(format!(
                    "deposit {} is not open to pay: {state:?}",
                    deposit.hash
                )))
            }
        };
        let to = terms
            .address
            .parse::<bitcoin::Address<_>>()
            .ok()
            .and_then(|a| {
                a.require_network(licash_onchain::network(self.network()))
                    .ok()
            })
            .ok_or_else(|| Error::Invalid(format!("deposit address {}", terms.address)))?;
        let tx = self.spend_silent_from(
            to.script_pubkey().into(),
            Some(terms.pays),
            rate,
            Coins::Whole(coin),
        )?;
        let amount = deposit.amount;
        tracing::info!(hash = %deposit.hash, amount, txid = %tx.compute_txid(), "silent payment coins deposited");
        Ok((deposit, tx))
    }
}

/// What a spend takes and pays: to its payee, and the change.
struct Plan {
    inputs: Vec<Held>,
    pay: u64,
    change: Option<u64>,
}

/// The least a coin deposited whole at a hub offering `offer` holds, its
/// fee at `rate`: in sat.
pub fn least_deposited(offer: &licash_api::Deposits, rate: FeeRate) -> u64 {
    let output = TxOut {
        value: Amount::ZERO,
        script_pubkey: any_taproot(),
    };
    let fee = fee(1, &[output], rate);
    offer
        .pays(offer.min)
        .map_or(u64::MAX, |p| p.saturating_add(fee))
}

/// The least a coin deposited whole through a provider offering `offer`
/// holds, its fee at `rate`: in sat.
pub fn least_deposited_through(offer: &licash_api::swaps::Deposits, rate: FeeRate) -> u64 {
    let output = TxOut {
        value: Amount::ZERO,
        script_pubkey: any_taproot(),
    };
    offer
        .pays(offer.min)
        .saturating_add(fee(1, &[output], rate))
}

/// Which of the wallet's free coins a spend may take.
#[derive(Clone, Copy)]
enum Coins {
    /// Any, as many as it needs.
    Free,
    /// This one alone.
    One(OutPoint),
    /// This one alone, all of it: no change.
    Whole(OutPoint),
}

impl Coins {
    /// Those of `free` it takes: fails if its one coin is not free.
    fn of(self, free: Vec<Held>) -> Result<Vec<Held>, Error> {
        let one = match self {
            Self::Free => return Ok(free),
            Self::One(one) | Self::Whole(one) => one,
        };
        let held: Vec<Held> = free.into_iter().filter(|h| h.outpoint == one).collect();
        if held.is_empty() {
            return Err(Error::Invalid(format!(
                "no free coin of the wallet's at {one}"
            )));
        }
        Ok(held)
    }
}

/// The wallet's coin at `outpoint` that no block spends, and the
/// transaction it is reserved for, if any.
fn coin(
    t: &rusqlite::Connection,
    outpoint: &OutPoint,
) -> Result<Option<(Held, Option<Txid>)>, Error> {
    let row = t
        .query_row(
            "SELECT value, output, tweak, label, spent_by FROM silent_coins
             WHERE txid = ?1 AND vout = ?2 AND spent_height IS NULL",
            params![outpoint.txid.to_byte_array(), outpoint.vout],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, [u8; 32]>(1)?,
                    r.get::<_, [u8; 32]>(2)?,
                    r.get::<_, Option<u32>>(3)?,
                    r.get::<_, Option<[u8; 32]>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((value, output, tweak, label, spent_by)) = row else {
        return Ok(None);
    };
    let held = Held {
        outpoint: *outpoint,
        value: value as u64,
        found: Found {
            output: XOnlyPublicKey::from_slice(&output).map_err(invalid)?,
            tweak: SecretKey::from_slice(&tweak).map_err(invalid)?,
            label,
        },
    };
    Ok(Some((held, spent_by.map(Txid::from_byte_array))))
}

/// The wallet's spend `tx`, its fee and its block as its coins tell.
fn described(c: &rusqlite::Connection, tx: Transaction) -> Result<SilentSpend, Error> {
    let mut coin = c.prepare_cached(
        "SELECT value, spent_by, spent_height FROM silent_coins WHERE txid = ?1 AND vout = ?2",
    )?;
    let txid = tx.compute_txid().to_byte_array();
    let (mut held, mut height) = (Some(0u64), None);
    for input in &tx.input {
        let spent = input.previous_output;
        let params = params![spent.txid.to_byte_array(), spent.vout];
        let row = coin.query_row(params, |r| {
            let by: Option<[u8; 32]> = r.get(1)?;
            Ok((r.get::<_, i64>(0)? as u64, by, r.get::<_, Option<u32>>(2)?))
        });
        match row.optional()? {
            Some((value, by, at)) => {
                held = held.and_then(|h| h.checked_add(value));
                if by == Some(txid) {
                    height = height.or(at);
                }
            }
            None => held = None,
        }
    }
    let paid: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = held.and_then(|h| h.checked_sub(paid));
    Ok(SilentSpend { tx, fee, height })
}

/// The coins no transaction spends, largest first.
fn free_coins(t: &rusqlite::Connection) -> Result<Vec<Held>, Error> {
    let mut stmt = t.prepare(
        "SELECT txid, vout, value, output, tweak, label FROM silent_coins
         WHERE spent_by IS NULL AND spent_height IS NULL ORDER BY value DESC, txid, vout",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, [u8; 32]>(0)?,
            r.get::<_, u32>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, [u8; 32]>(3)?,
            r.get::<_, [u8; 32]>(4)?,
            r.get::<_, Option<u32>>(5)?,
        ))
    })?;
    let mut held = Vec::new();
    for row in rows {
        let (txid, vout, value, output, tweak, label) = row?;
        held.push(Held {
            outpoint: OutPoint::new(Txid::from_byte_array(txid), vout),
            value: value as u64,
            found: Found {
                output: XOnlyPublicKey::from_slice(&output).map_err(invalid)?,
                tweak: SecretKey::from_slice(&tweak).map_err(invalid)?,
                label,
            },
        });
    }
    Ok(held)
}

/// The fee at `rate` of a spend of `inputs` coins paying `outputs`.
fn fee(inputs: usize, outputs: &[TxOut], rate: FeeRate) -> u64 {
    let input = TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        // A key path signature's 64 bytes.
        witness: Witness::from_slice(&[[0; 64]]),
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input; inputs],
        output: outputs.to_vec(),
    };
    rate.fee_wu(tx.weight()).map_or(u64::MAX, Amount::to_sat)
}

/// The coins of `held`, largest first, that pay `amount` to `to`, or all
/// of them everything, and the fee at `rate`.
fn plan(held: &[Held], to: &ScriptBuf, amount: Option<u64>, rate: FeeRate) -> Result<Plan, Error> {
    let out = |value: u64, script: &ScriptBuf| TxOut {
        value: Amount::from_sat(value),
        script_pubkey: script.clone(),
    };
    let change_script = any_taproot();
    let (dust, change_dust) = (
        to.minimal_non_dust().to_sat(),
        change_script.minimal_non_dust().to_sat(),
    );
    let total = |n: usize| held[..n].iter().map(|h| h.value).sum::<u64>();
    let Some(amount) = amount else {
        let fee = fee(held.len(), &[out(0, to)], rate);
        let available = total(held.len());
        let pay = available
            .checked_sub(fee)
            .filter(|pay| !held.is_empty() && *pay >= dust)
            .ok_or(Error::Insufficient {
                needed: fee.saturating_add(dust),
                available,
            })?;
        return Ok(Plan {
            inputs: held.to_vec(),
            pay,
            change: None,
        });
    };
    if amount < dust {
        return Err(Error::Invalid(format!("{amount} is dust to that script")));
    }
    for n in 1..=held.len() {
        let paid = total(n);
        let with = fee(n, &[out(amount, to), out(0, &change_script)], rate);
        let change = paid.checked_sub(amount.saturating_add(with));
        if let Some(change) = change.filter(|c| *c >= change_dust) {
            return Ok(Plan {
                inputs: held[..n].to_vec(),
                pay: amount,
                change: Some(change),
            });
        }
        if paid >= amount.saturating_add(fee(n, &[out(amount, to)], rate)) {
            return Ok(Plan {
                inputs: held[..n].to_vec(),
                pay: amount,
                change: None,
            });
        }
    }
    Err(Error::Insufficient {
        needed: amount.saturating_add(fee(held.len().max(1), &[out(amount, to)], rate)),
        available: total(held.len()),
    })
}

/// The key-path signature of input `index` of `tx`, spending `held` with
/// `secret`, committing to `prevouts`.
fn key_spend(
    tx: &Transaction,
    prevouts: &[TxOut],
    index: usize,
    held: &Held,
    secret: &SecretKey,
) -> Result<bitcoin::taproot::Signature, Error> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, secret);
    if keypair.x_only_public_key().0 != held.found.output {
        return Err(Error::Invalid(format!("no key for coin {}", held.outpoint)));
    }
    let sighash = SighashCache::new(tx)
        .taproot_key_spend_signature_hash(index, &Prevouts::All(prevouts), TapSighashType::Default)
        .map_err(invalid)?;
    let message = Message::from_digest(sighash.to_byte_array());
    let mut aux = [0; 32];
    OsRng.fill_bytes(&mut aux);
    Ok(bitcoin::taproot::Signature {
        signature: secp.sign_schnorr_with_aux_rand(&message, &keypair, &aux),
        sighash_type: TapSighashType::Default,
    })
}

/// A transaction spending `inputs` on the key path with `secrets`, paying
/// `outputs`: replaceable.
fn sign(inputs: &[Held], secrets: &[SecretKey], output: Vec<TxOut>) -> Result<Transaction, Error> {
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|h| TxIn {
                previous_output: h.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output,
    };
    let prevouts: Vec<TxOut> = inputs
        .iter()
        .map(|h| TxOut {
            value: Amount::from_sat(h.value),
            script_pubkey: p2tr(h.found.output),
        })
        .collect();
    let signatures = inputs
        .iter()
        .zip(secrets)
        .enumerate()
        .map(|(i, (held, secret))| key_spend(&tx, &prevouts, i, held, secret))
        .collect::<Result<Vec<_>, Error>>()?;
    for (input, signature) in tx.input.iter_mut().zip(&signatures) {
        input.witness = Witness::p2tr_key_spend(signature);
    }
    Ok(tx)
}
