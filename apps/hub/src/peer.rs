//! A hash backs one own lock of the hub's notes
//! ([`licash_hub::Hub::lock_own`]), by one payment. The wallet that asks
//! for a deposit picks its hash, so it may pick one a swap of the provider
//! an earlier release embedded, or a Lightning receipt of its gateway,
//! holds: the deposits refuse a hash held so, and leave a lock under it to
//! the payment it was recorded for. They take their turns at checking a
//! hash and recording what they hold under it one at a time.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use licash::spend::ProposalId;
use licash_api::{Code, Problem};
use licash_store::Kind;
use rusqlite::OptionalExtension;
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::{deposit, Failure};

/// What a gateway recorded under a hash: a payment, if any, and the own
/// lock it backs once locked.
pub type Recorded = Option<Option<ProposalId>>;

/// What a gateway asks of its peer, if it has one ([`coordinate`]).
#[derive(Default)]
pub struct Peer(OnceLock<Paired>);

/// What the peer recorded under a hash.
type Lookup = dyn Fn(&[u8; 32]) -> Result<Recorded, String> + Send + Sync;

struct Paired {
    /// Held from checking a hash with the peer to recording what the
    /// deposits hold under it: a payment, or the lock it backs.
    turn: Arc<Mutex<()>>,
    recorded: Box<Lookup>,
    swaps: Option<PathBuf>,
}

impl Peer {
    pub(crate) fn holds_swap(&self, hash: &[u8; 32]) -> Result<bool, Failure> {
        let Some(path) = self.0.get().and_then(|p| p.swaps.as_ref()) else {
            return Ok(false);
        };
        licash_swaps::holds_hash(path, hash).map_err(|e| unreadable(e.to_string()))
    }

    pub(crate) fn swap_owns(&self, hash: &[u8; 32], lock: &ProposalId) -> Result<bool, Failure> {
        let Some(path) = self.0.get().and_then(|p| p.swaps.as_ref()) else {
            return Ok(false);
        };
        licash_swaps::owns_hash_lock(path, hash, lock).map_err(|e| unreadable(e.to_string()))
    }
    /// Wait for the turn to check a hash with the peer and record what
    /// the gateway holds under it, until dropped: none needed unpaired.
    pub(crate) async fn turn(&self) -> Option<OwnedMutexGuard<()>> {
        let paired = self.0.get()?;
        Some(paired.turn.clone().lock_owned().await)
    }

    /// What the peer recorded under `hash`: nothing unpaired.
    pub(crate) fn recorded(&self, hash: &[u8; 32]) -> Result<Recorded, Failure> {
        let Some(paired) = self.0.get() else {
            return Ok(None);
        };
        (paired.recorded)(hash).map_err(unreadable)
    }
}

fn unreadable(error: String) -> Failure {
    tracing::error!(%error, "the hub's other payment service cannot be read");
    Failure(Problem::new(Code::Unavailable, "the hub cannot serve now"))
}

/// What the component `component` of the hub's database at `db` recorded
/// under `hash` in its `table`, if the gateway ever ran there: read only,
/// beside the gateway running or without it.
fn recorded_file(
    db: Option<&Path>,
    component: &str,
    table: &str,
    hash: &[u8; 32],
) -> Result<Recorded, String> {
    let Some(db) = db else { return Ok(None) };
    let Some(conn) = reader(db, component).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let row: Option<Option<[u8; 32]>> = conn
        .query_row(
            &format!("SELECT lock FROM {table} WHERE hash = ?1"),
            [hash],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    Ok(row.map(|lock| lock.map(ProposalId::from_bytes)))
}

/// A read only connection to the hub's database at `db`, if it has one and
/// the gateway of `component` made its tables in it.
pub fn reader(db: &Path, component: &str) -> anyhow::Result<Option<rusqlite::Connection>> {
    let Some(conn) = licash_store::inspect(db, Kind::Hub)? else {
        return Ok(None);
    };
    // The layout of each gateway's tables this hub reads.
    let reads = match component {
        deposit::COMPONENT => deposit::VERSION,
        crate::lightning::COMPONENT => crate::lightning::VERSION,
        _ => anyhow::bail!("no gateway {component}"),
    };
    match licash_store::component_version(&conn, component)? {
        Some(v) if v == reads => Ok(Some(conn)),
        Some(v) => anyhow::bail!("{component} of version {v}, this hub reads {reads}"),
        None => Ok(None),
    }
}

/// Which of `hashes` `query`, of a hash, finds among the tables of the
/// gateway `component` in the hub's database at `db`, if the gateway ever
/// ran there: read only, beside it running or without it.
pub(crate) fn recorded_in(
    db: &Path,
    component: &str,
    query: &str,
    hashes: &[[u8; 32]],
) -> anyhow::Result<HashSet<[u8; 32]>> {
    let mut found = HashSet::new();
    let Some(conn) = reader(db, component)? else {
        return Ok(found);
    };
    let mut stmt = conn.prepare(query)?;
    for hash in hashes {
        if stmt.exists([hash])? {
            found.insert(*hash);
        }
    }
    Ok(found)
}

/// Coordinate the deposits, if the hub takes them, with what the swaps and
/// the receipts of an earlier release recorded in `data`.
pub fn coordinate(deposits: Option<&Arc<deposit::Gateway>>, data: &Path) {
    let Some(deposits) = deposits else { return };
    // The swap provider's tables are in its wallet's file.
    let swaps = Some(data.join("swaps/wallet.sqlite"));
    let file = licash_contracts::hub_db(data);
    let recorded = move |hash: &[u8; 32]| {
        recorded_file(
            Some(&file),
            crate::lightning::COMPONENT,
            "lightning_receipts",
            hash,
        )
    };
    let paired = Paired {
        turn: Arc::default(),
        recorded: Box::new(recorded),
        swaps,
    };
    assert!(deposits.peer.0.set(paired).is_ok(), "paired once");
}
