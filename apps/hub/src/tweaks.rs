//! The silent payment tweaks (BIP352) of the chain the hub follows, which
//! light wallets fetch to find what pays their silent payment addresses:
//! indexed from a first block on, chosen once, in a SQLite file of their
//! own. Deleting the file loses nothing but the index.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{ensure, Context};
use bitcoin::{hashes::Hash, secp256k1::PublicKey, BlockHash, Script};
use licash::spend::ChainProfile;
use licash_api::{BlockTweaks, Hex};
use licash_chain_client::{Follow, Source};
use licash_onchain::silent;
use rusqlite::{params, Connection, OptionalExtension};

/// The schema this index reads and writes, as SQLite's `user_version`.
const VERSION: i64 = 1;

const SCHEMA: &str = "
-- The first block indexed, chosen once.
CREATE TABLE meta (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    first INTEGER NOT NULL
) STRICT;
-- The blocks of the best chain from the first on, each with its tweaks:
-- compressed points, one after the other.
CREATE TABLE blocks (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    tweaks BLOB NOT NULL
) STRICT;
";

/// A compressed point.
const POINT: usize = 33;

/// The index, in its file.
pub struct Tweaks(Mutex<Connection>);

impl Tweaks {
    /// The index at `path`, a new file or one a hub wrote.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            let tables: i64 =
                conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))?;
            ensure!(tables == 0, "{} is not a tweak index", path.display());
            let tx = conn.transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "user_version", VERSION)?;
            tx.commit()?;
        } else {
            ensure!(
                version == VERSION,
                "tweak index schema {version}, this hub reads {VERSION}"
            );
        }
        Ok(Self(Mutex::new(conn)))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The first block indexed, once chosen.
    pub fn first(&self) -> anyhow::Result<Option<u32>> {
        let conn = self.conn();
        let first = conn.query_row("SELECT first FROM meta", [], |r| r.get(0));
        Ok(first.optional()?)
    }

    /// The newest block indexed.
    pub fn top(&self) -> anyhow::Result<Option<(u32, BlockHash)>> {
        let conn = self.conn();
        let top = conn
            .query_row(
                "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get::<_, [u8; 32]>(1)?)),
            )
            .optional()?;
        Ok(top.map(|(height, hash)| (height, BlockHash::from_byte_array(hash))))
    }

    fn hash_at(&self, height: u32) -> anyhow::Result<Option<BlockHash>> {
        let conn = self.conn();
        let hash = conn
            .query_row("SELECT hash FROM blocks WHERE height = ?1", [height], |r| {
                r.get::<_, [u8; 32]>(0)
            })
            .optional()?;
        Ok(hash.map(BlockHash::from_byte_array))
    }

    fn begin(&self, first: u32) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute("INSERT INTO meta (one, first) VALUES (1, ?1)", [first])?;
        Ok(())
    }

    fn add(&self, height: u32, hash: &BlockHash, tweaks: &[PublicKey]) -> anyhow::Result<()> {
        let points: Vec<u8> = tweaks.iter().flat_map(|t| t.serialize()).collect();
        let conn = self.conn();
        conn.execute(
            "INSERT INTO blocks (height, hash, tweaks) VALUES (?1, ?2, ?3)",
            params![height, hash.to_byte_array(), points],
        )?;
        Ok(())
    }

    /// Forget the blocks from `height` up, which left the best chain.
    fn rewind(&self, height: u32) -> anyhow::Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM blocks WHERE height >= ?1", [height])?;
        Ok(())
    }

    /// The tweaks of the `count` blocks from height `from`, of those
    /// indexed.
    pub fn blocks(&self, from: u32, count: u32) -> anyhow::Result<Vec<BlockTweaks>> {
        let conn = self.conn();
        let mut query = conn.prepare(
            "SELECT height, hash, tweaks FROM blocks
             WHERE height >= ?1 AND height < ?1 + ?2 ORDER BY height",
        )?;
        let rows = query.query_map(params![from, count], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, [u8; 32]>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut blocks = Vec::new();
        for row in rows {
            let (height, hash, points) = row?;
            ensure!(
                points.len() % POINT == 0,
                "block {height}: tweaks of bad length"
            );
            blocks.push(BlockTweaks {
                height,
                hash: BlockHash::from_byte_array(hash).to_string(),
                tweaks: points.chunks(POINT).map(|p| Hex(p.to_vec())).collect(),
            });
        }
        Ok(blocks)
    }
}

/// The longest the index waits between rounds failing one after another.
const MOST_WAIT: Duration = Duration::from_secs(5 * 60);

/// How long the index fails to move on before the operator is alerted.
const STUCK: Duration = Duration::from_secs(30 * 60);

/// How often a failure that does not change is logged as a warning again.
const WARN_AGAIN: Duration = Duration::from_secs(60 * 60);

/// Rounds failing one after another: since when the index has not moved
/// on, and what was told of it.
#[derive(Default)]
struct Failing {
    rounds: u32,
    /// The newest block indexed when it last moved on, and since when.
    top: Option<(Option<u32>, Instant)>,
    /// The failure last warned of, and when.
    warned: Option<(String, Instant)>,
    alerted: bool,
}

impl Failing {
    /// After a round failing with `text`, the newest block indexed `top`,
    /// at `now`: how long to wait for the next, twice as long as the
    /// last up to [`MOST_WAIT`], whether to warn of it (a failure new, or
    /// [`WARN_AGAIN`] since told), and what to alert the operator of, once,
    /// stuck [`STUCK`] at a block.
    fn failed(
        &mut self,
        text: &str,
        top: Option<u32>,
        every: Duration,
        now: Instant,
    ) -> (Duration, bool, Option<String>) {
        match self.top {
            Some((at, _)) if at == top => {}
            _ => {
                self.top = Some((top, now));
                self.alerted = false;
            }
        }
        self.rounds = self.rounds.saturating_add(1);
        let doubled = every.saturating_mul(1 << self.rounds.saturating_sub(1).min(16));
        let wait = doubled.min(MOST_WAIT.max(every));
        let warn = match &self.warned {
            Some((told, at)) => told != text || now.duration_since(*at) >= WARN_AGAIN,
            None => true,
        };
        if warn {
            self.warned = Some((text.to_owned(), now));
        }
        let since = self.top.map_or(now, |(_, since)| since);
        let stuck = now.duration_since(since);
        let alert = (!self.alerted && stuck >= STUCK).then(|| {
            self.alerted = true;
            let next = top.map_or_else(|| "its first block".into(), |t| format!("block {}", t + 1));
            format!(
                "the silent payment tweaks are not indexed past {next} for {} minutes: \
                 wallets scanning with this hub's tweaks wait. {text}",
                stuck.as_secs() / 60
            )
        });
        (wait, warn, alert)
    }

    /// After a round that did not fail: whether those before did.
    fn recovered(&mut self) -> bool {
        let failed = self.rounds > 0;
        *self = Self::default();
        failed
    }
}

/// Index the tweaks of `source`'s best chain into `tweaks`, a round every
/// `every`, for good, if it follows `network`: from block `from` on, or
/// from the tip, once, when the index is new. Rounds failing one after
/// another wait longer each time, up to `MOST_WAIT`; stuck at a block
/// for `STUCK`, the operator is told through `alert`, once.
pub async fn index(
    tweaks: Arc<Tweaks>,
    source: Source,
    network: ChainProfile,
    from: Option<u32>,
    every: Duration,
    alert: impl Fn(&str) + Send + Sync,
) {
    let profile = loop {
        match source.profile().await {
            Ok(profile) => break profile,
            Err(e) => tracing::debug!(chain = %source, "indexing tweaks: {e:#}"),
        }
        tokio::time::sleep(every).await;
    };
    if profile != network {
        // The scan alerts of it.
        return tracing::error!(chain = %source, %profile, %network, "not indexing tweaks of another network");
    }
    tracing::info!(chain = %source, "indexing silent payment tweaks");
    match (tweaks.first(), from) {
        (Ok(Some(first)), Some(from)) if first != from => tracing::warn!(
            first,
            from,
            "indexing tweaks from the first block chosen: delete tweaks.sqlite to index from another"
        ),
        _ => {}
    }
    let mut failing = Failing::default();
    loop {
        let wait = match step(&tweaks, &source, from).await {
            Ok(()) => {
                if failing.recovered() {
                    tracing::info!(chain = %source, "indexing tweaks again");
                }
                every
            }
            Err(e) => {
                let text = format!("{e:#}");
                let top = tweaks.top().ok().flatten().map(|(height, _)| height);
                let (wait, warn, stuck) = failing.failed(&text, top, every, Instant::now());
                let secs = wait.as_secs();
                if warn {
                    tracing::warn!(chain = %source, "indexing tweaks, again in {secs} s: {text}");
                } else {
                    tracing::debug!(chain = %source, "indexing tweaks, again in {secs} s: {text}");
                }
                if let Some(message) = stuck {
                    alert(&message);
                }
                wait
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// One round: index what `source`'s best chain has beyond the index, up
/// to its tip, rewinding first where it left the index. A new index
/// starts at block `from`, else at the tip.
pub async fn step(tweaks: &Tweaks, source: &Source, from: Option<u32>) -> anyhow::Result<()> {
    let tip = source.tip().await.context("the chain's tip")?;
    let first = match tweaks.first()? {
        Some(first) => first,
        None => {
            let first = from.unwrap_or(tip.height);
            tweaks.begin(first)?;
            tracing::info!(first, "indexing silent payment tweaks");
            first
        }
    };
    loop {
        let top = tweaks.top()?;
        let (next, block) = match source.follow(top, first, |h| tweaks.hash_at(h)).await? {
            Follow::Next(next, block) => (next, block),
            Follow::Rewind(height) => {
                tweaks.rewind(height)?;
                continue;
            }
            Follow::AtTip => break,
        };
        let hash = block.block_hash();
        let spends = source.taproot_spends(&block).await?;
        let found: Vec<PublicKey> = block
            .txdata
            .iter()
            .zip(&spends)
            .filter_map(|(tx, spent)| {
                let scripts: Vec<&Script> = spent.as_ref()?.iter().map(|s| s.as_script()).collect();
                silent::tweak(tx, &scripts)
            })
            .collect();
        tweaks.add(next, &hash, &found)?;
        tracing::debug!(height = next, tweaks = found.len(), "indexed tweaks");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_failing_wait_longer_warn_once_and_alert_once_stuck() {
        let every = Duration::from_secs(10);
        let start = Instant::now();
        let mut failing = Failing::default();
        let mut waits = Vec::new();
        let mut warned = 0;
        let mut alerts = Vec::new();
        let mut now = start;
        // Stuck at block 41 for over an hour.
        while now.duration_since(start) < Duration::from_secs(65 * 60) {
            let (wait, warn, alert) = failing.failed("no block", Some(40), every, now);
            waits.push(wait.as_secs());
            warned += u32::from(warn);
            alerts.extend(alert);
            now += wait;
        }
        assert_eq!(&waits[..7], [10, 20, 40, 80, 160, 300, 300]);
        assert!(waits.iter().all(|w| *w <= 300));
        // Warned on its first failure, then once more after an hour.
        assert_eq!(warned, 2);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert!(alerts[0].contains("past block 41"), "{}", alerts[0]);
        assert!(alerts[0].contains("no block"), "{}", alerts[0]);

        // Another failure is warned of at once, not waited on less.
        let (wait, warn, alert) = failing.failed("another", Some(40), every, now);
        assert_eq!((wait.as_secs(), warn, alert), (300, true, None));

        // Moved on, then stuck again: alerted again, once stuck as long.
        let (wait, warn, alert) = failing.failed("another", Some(45), every, now);
        assert_eq!((wait.as_secs(), warn, alert), (300, false, None));
        let later = now + STUCK;
        let (_, _, alert) = failing.failed("another", Some(45), every, later);
        assert!(alert.unwrap().contains("past block 46"));

        // Recovered: from the start again.
        assert!(failing.recovered());
        assert!(!failing.recovered());
        let (wait, warn, alert) = failing.failed("no block", Some(45), every, later);
        assert_eq!((wait.as_secs(), warn, alert), (10, true, None));
    }

    #[test]
    fn a_round_slower_than_the_longest_wait_waits_its_round() {
        let every = Duration::from_secs(600);
        let mut failing = Failing::default();
        let (wait, ..) = failing.failed("x", None, every, Instant::now());
        assert_eq!(wait, every);
        let (wait, ..) = failing.failed("x", None, every, Instant::now());
        assert_eq!(wait, every);
    }
}
