//! The Licash hub engine: a hub's operations over its durable ledger.
//!
//! A hub holds one secret, a 32-byte seed in a file of its own, and derives
//! from it its issuer keysets ([`IssuerKeys::from_seed`]), the unlock of
//! each grant it offers, its own address, at which spends pay its fees, and
//! the key it announces itself under on Nostr ([`Hub::nostr_secret`]) and
//! those it claims deposits on Bitcoin with ([`Hub::deposit_secret`]).
//! The database holds no secret: what the hub offered, which inputs it
//! retired, which outputs it issued and what it answered. Every operation
//! commits one transaction before it replies.
//!
//! Unlink nonces derive from a key drawn at each start and never stored,
//! and the hub also remembers what it answered since, so that neither a
//! database restored or copied before a start nor one replaced under the
//! running hub makes it answer twice under one nonce. A snapshot of the
//! process's memory resumed twice would. Outputs issued before a restart
//! can no longer be unlinked ([`Refusal::Expired`]); their holders keep
//! the value and can swap them for fresh outputs.
//!
//! Timed locks ([`Hub::lock`]) pay on a preimage or refund once expired,
//! as the hub's scan of Bitcoin decides ([`Hub::observe`]).
//!
//! Against a holder's recovery claim, the ledger yields its evidence
//! ([`Hub::evidence`]): the spends that retired the claimed notes and the
//! branch each claimed lock was not settled on.
//!
//! [`Ledger`] reads the database beside a running hub, for monitoring.

mod citable;
mod claims;
mod evidence;
mod forwards;
mod locks;
mod records;
mod store;

use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::Path,
    sync::{atomic::AtomicBool, Mutex, PoisonError},
    time::Instant,
};

use licash::{
    address::{Address, OwnerKeys},
    authorization::{Grant, PreparedGrant, SignedProposal, Unlock},
    chain::Checkpoint,
    crypto::{scalar_from_hash, schnorr_sign, tagged_hash, Point, ScalarBytes, Signature},
    note::{IssuerKeys, Keyset, Note},
    spend::{Output, Proposal, ProposalId},
    unlink::{self, Answer, Answered, Request},
};
use licash_api::Code;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use store::{now, setup_io, Store};

pub use citable::{uncitable, Uncitable, MAX_EVIDENCE_BYTES};
pub use evidence::Found;
pub use forwards::{Forward, Forwarded, LOCAL};
pub use locks::{Lock, Settled, Timing};
pub use records::{Excess, ForwardRecord, LockRecord, Movement, Notes, Unlinks};

/// The largest denomination exponent a hub issues: its ledger keeps
/// denominations as SQLite integers.
pub const MAX_POW: u32 = 62;

/// The most grants a hub process makes for one note not spent: a payer
/// abandoning a spend and trying again needs a few; anyone holding a note
/// could otherwise have it offered endlessly, each grant a row kept. As
/// many again of offers its owner signed ([`Hub::offer_held`]), which no
/// one else knowing the note, its payer say, can use up.
pub const MAX_OFFERS: u8 = 8;

/// How long, in seconds, a grant left unreleased is kept: a day. Then it
/// is deleted with its proposal, unless a double spend of it was refused,
/// and its payer releasing it after is refused as an unknown offer, to
/// offer the spend again: no row is kept for good of a spend never made.
pub const UNRELEASED_FOR: i64 = 24 * 3600;

/// How often at most offers delete the grants left unreleased too long.
const FORGET_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);

/// Why the hub did not serve a request, or could not.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request is valid but the hub will not serve it.
    #[error("refused: {0}")]
    Refused(#[from] Refusal),
    /// The request does not verify.
    #[error("invalid: {0}")]
    Invalid(#[from] licash::Error),
    /// The hub's files are missing, exist already or do not match.
    #[error("setup: {0}")]
    Setup(String),
    /// The database changed under the running hub, which serves nothing
    /// more. Restart it once the database is the one it should be.
    #[error("halted: the hub database changed under it")]
    Halted,
    #[error("storage: {0}")]
    Storage(#[source] StorageError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// A database error, opaque so that the storage engine stays private.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StorageError(rusqlite::Error);

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(StorageError(e))
    }
}

/// Why the hub will not serve a valid request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    #[error("unknown keyset")]
    UnknownKeyset,
    #[error("a timed spend is served as a lock")]
    Timed,
    #[error("not a plainly authorized timed lock")]
    NotALock,
    #[error("checkpoint: {0}")]
    Checkpoint(&'static str),
    #[error("lock timing: {0}")]
    Timing(&'static str),
    #[error("the hub's view of Bitcoin is behind")]
    Unsynced,
    #[error("the hub follows no chain yet: add a checkpoint")]
    NoChain,
    #[error("block: {0}")]
    Block(&'static str),
    #[error("unknown lock")]
    UnknownLock,
    #[error("not the preimage of the lock's hash")]
    Preimage,
    #[error("the lock was settled the other way")]
    Settled,
    #[error("the lock expired: it is refunded")]
    LockExpired,
    #[error("the lock has not expired at depth")]
    Unexpired,
    #[error("the lock was activated in time: it pays")]
    Activated,
    #[error("an own lock under this hash exists")]
    Exists,
    #[error("a note offered in too many spends not released: release or wait for a restart")]
    Offered,
    #[error("an input is already spent")]
    Spent,
    #[error("an output is already issued")]
    Reissued,
    /// More than a contract's statement reads of one spend: the hub could
    /// never cite it against a claim of its notes ([`MAX_EVIDENCE_BYTES`]).
    #[error(
        "a spend larger than a dispute can cite: at most {} notes and {} bytes",
        licash::spend::MAX_INPUTS,
        MAX_EVIDENCE_BYTES
    )]
    TooLarge,
    #[error("fee {paid} below {due}")]
    Fee { due: u64, paid: u64 },
    #[error("no offer for this proposal")]
    UnknownOffer,
    /// Or not to the capability the request carries.
    #[error("not issued by this hub")]
    NotIssued,
    #[error("already unlinked under another request")]
    Unlinked,
    #[error("unlinking closed by a hub restart: swap the note instead")]
    Expired,
    #[error("cannot forward: {0}")]
    Forward(&'static str),
    #[error("a payment for the lock is under way")]
    Forwarding,
}

impl Refusal {
    /// The code the API answers this refusal with.
    pub fn code(&self) -> Code {
        match self {
            Self::UnknownKeyset => Code::UnknownKeyset,
            Self::Timed => Code::Timed,
            Self::Spent => Code::Spent,
            Self::Reissued => Code::Reissued,
            Self::Fee { .. } => Code::Fee,
            Self::UnknownOffer => Code::UnknownOffer,
            Self::NotIssued => Code::NotIssued,
            Self::Unlinked => Code::Unlinked,
            Self::Expired => Code::Expired,
            Self::NotALock => Code::NotALock,
            Self::Checkpoint(_) => Code::Checkpoint,
            Self::Timing(_) => Code::Timing,
            Self::Unsynced | Self::NoChain | Self::Forwarding => Code::Unavailable,
            Self::Forward(_) => Code::Forward,
            Self::UnknownLock => Code::UnknownLock,
            Self::Preimage => Code::Preimage,
            Self::Settled => Code::Settled,
            Self::LockExpired => Code::LockExpired,
            Self::Unexpired => Code::Unexpired,
            Self::Activated => Code::Activated,
            Self::Block(_) | Self::Exists | Self::Offered | Self::TooLarge => Code::Invalid,
        }
    }
}

/// A fee, as the hub advertises it: what it charges is what payers compute.
pub use licash_api::Fee;

/// What the hub charges and the locks it admits. A spend pays its fee in
/// outputs to the hub's address ([`Info::address`]), a lock in each branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub spend: Fee,
    /// In a lock's pay branch.
    pub lock: Fee,
    /// In a lock's refund branch.
    pub refund: Fee,
    /// Charged besides, in thousandths of a sat, for each note a spend or
    /// a branch of a lock makes for others than the hub.
    pub output_msat: u64,
    pub timing: Timing,
}

impl Policy {
    /// The fees of this policy, as the hub advertises them: what it
    /// charges is computed from them, as payers do.
    pub fn fees(&self) -> licash_api::Fees {
        licash_api::Fees {
            spend: self.spend,
            lock: self.lock,
            refund: self.refund,
            output_msat: self.output_msat,
        }
    }
}

/// What the hub publishes of itself.
#[derive(Clone, Debug)]
pub struct Info {
    pub keysets: Vec<Keyset>,
    pub address: Address,
    pub policy: Policy,
}

/// Something a hub operator may want to hear about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Notice {
    /// The hub started. Outputs issued before can no longer be unlinked.
    Started { boot: String },
    /// A spend was released: `amount` moved, `fee` of it to the hub.
    Released {
        proposal: String,
        amount: u64,
        fee: u64,
    },
    /// The owners of inputs another spend retired signed `proposal`. Once
    /// per proposal.
    DoubleSpend { proposal: String, spent_by: String },
    /// A lock of `amount` until `expiry` was admitted, paying `fee` to the
    /// hub if it pays; `own` if the hub locked notes it issued itself.
    Locked {
        proposal: String,
        amount: u64,
        fee: u64,
        expiry: u32,
        own: bool,
    },
    /// A lock was paid or refunded, `fee` of it to the hub.
    Settled {
        proposal: String,
        amount: u64,
        fee: u64,
        branch: Settled,
    },
    /// The preimage of a lock was published on Bitcoin at `height`, in
    /// time: the lock pays. If the hub `refunded` it already, after a
    /// reorganization, it owes both branches.
    Activated {
        proposal: String,
        height: u32,
        refunded: bool,
    },
    /// Bitcoin reorganized at `height`, at or below a checkpoint: the hub
    /// scans no more until its operator acts.
    Reorg { height: u32 },
    /// A payment outside the ledger for a lock of `amount` paid, or
    /// `failed`, and why: the lock is refunded.
    Forwarded {
        proposal: String,
        amount: u64,
        failed: Option<String>,
    },
    /// Something the operator must look at, from a service on the hub.
    Alert { message: String },
}

impl Notice {
    /// Its kind, as its [`Event`] names it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Started { .. } => "started",
            Self::Released { .. } => "released",
            Self::DoubleSpend { .. } => "double_spend",
            Self::Locked { .. } => "locked",
            Self::Settled { .. } => "settled",
            Self::Activated { .. } => "activated",
            Self::Reorg { .. } => "reorg",
            Self::Forwarded { .. } => "forwarded",
            Self::Alert { .. } => "alert",
        }
    }
}

/// A [`Notice`] in the hub's outbox, in order of `seq`: its kind and its
/// JSON as stored, which a hub of another version may have written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Unix seconds.
    pub at: u64,
    pub kind: String,
    pub data: serde_json::Value,
}

impl Event {
    /// The notice, if this version knows it.
    pub fn notice(&self) -> Option<Notice> {
        serde_json::from_value(self.data.clone()).ok()
    }
}

/// Counts over a hub's ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub offers: u64,
    pub released: u64,
    pub locks: u64,
    /// Locks neither paid nor refunded.
    pub open_locks: u64,
    pub spent: u64,
    pub issued: u64,
    pub unlinked: u64,
    /// The value of the notes paid to the hub.
    pub income: u64,
    /// The last event's `seq`.
    pub events: u64,
}

/// A read-only view of a hub's database, beside the running hub or
/// without one. It needs no seed, takes no lock and writes nothing.
pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// The hub's database at `db`, read-only.
    pub fn open(db: &Path) -> Result<Self, Error> {
        Ok(Self {
            conn: store::inspect(db)?,
        })
    }

    /// The events after `after`, oldest first, at most `limit`.
    pub fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>, Error> {
        events(&self.conn, after, limit)
    }

    /// The last event's `seq`, or 0: [`Stats::events`] without the counts.
    pub fn last_event(&self) -> Result<u64, Error> {
        Ok(self
            .conn
            .query_row(LAST_EVENT, [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// Counts over the ledger.
    pub fn stats(&self) -> Result<Stats, Error> {
        let count = |sql: &str| -> Result<u64, Error> {
            Ok(self.conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        Ok(Stats {
            offers: count("SELECT count(*) FROM grants")?,
            released: count("SELECT count(*) FROM grants WHERE released_at IS NOT NULL")?,
            locks: count("SELECT count(*) FROM locks")?,
            open_locks: count("SELECT count(*) FROM locks WHERE settled IS NULL")?,
            spent: count("SELECT count(*) FROM spent")?,
            issued: count("SELECT count(*) FROM issued WHERE boot IS NOT NULL")?,
            unlinked: count("SELECT count(*) FROM issued WHERE answered IS NOT NULL")?,
            income: count("SELECT coalesce(sum(denom), 0) FROM income")?,
            events: count(LAST_EVENT)?,
        })
    }
}

const LAST_EVENT: &str = "SELECT coalesce(max(seq), 0) FROM events";

fn events(conn: &Connection, after: u64, limit: u32) -> Result<Vec<Event>, Error> {
    let mut rows = conn
        .prepare("SELECT seq, at, kind, json FROM events WHERE seq > ?1 ORDER BY seq LIMIT ?2")?;
    let rows = rows.query_map(params![sql(after)?, limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    rows.map(|row| {
        let (seq, at, kind, json) = row?;
        Ok(Event {
            seq: seq as u64,
            at: at as u64,
            kind,
            data: serde_json::from_str(&json).unwrap_or(serde_json::Value::String(json)),
        })
    })
    .collect()
}

/// A hub at work: its keys, derived from its seed, over its database,
/// which it holds for itself while open.
pub struct Hub {
    store: Store,
    keysets: BTreeMap<[u8; 32], (IssuerKeys, Keyset)>,
    /// The id of the keyset of [`Hub::issuing`].
    issuing: [u8; 32],
    owner: OwnerKeys,
    unlock_secret: [u8; 32],
    /// The Nostr key's secret, and its public key, x-only in hex.
    nostr: ([u8; 32], String),
    /// What each deposit's key derives from.
    deposit: [u8; 32],
    /// The key the hub signs what its contract witnesses keep with.
    witness: [u8; 32],
    /// This process's public boot id and its key, never stored.
    boot: [u8; 16],
    boot_key: [u8; 32],
    /// What this process answered: the hash of each request by its output.
    /// It outlives no nonce, so it is the authority over them.
    answered: Mutex<HashMap<[u8; 32], [u8; 32]>>,
    /// How many grants this process made for each note not spent, its
    /// identifier's bytes: [`MAX_OFFERS`] at most. Never stored, so
    /// nothing old is refused, and a restart forgets.
    offers: Mutex<HashMap<[u8; 33], u8>>,
    /// [`Hub::offers`] of the offers their notes' owners signed.
    held_offers: Mutex<HashMap<[u8; 33], u8>>,
    /// When this process last deleted the grants left unreleased too long.
    forgotten_at: Mutex<Option<Instant>>,
    policy: Policy,
    /// The newest checkpoint, as stored.
    newest: Mutex<Option<Checkpoint>>,
    /// The chain's tip the scan last reached, and until when that holds.
    synced_at: Mutex<Option<locks::SyncedTip>>,
    /// Whether this process alerted a reorganization of a checkpoint.
    reorg_alerted: AtomicBool,
    /// The identity it last proved, and the proof: the same while it is.
    proved: Mutex<Option<([u8; 32], Signature)>>,
}

impl Hub {
    /// Create a hub: a fresh seed at `seed` and its ledger at `db`, with
    /// keyset 0 of denominations 1 to `2^max_pow`. Neither may exist: a
    /// ledger is never made again for a seed, whose spent notes it would
    /// accept as unspent.
    pub fn init(seed: &Path, db: &Path, max_pow: u32) -> Result<(), Error> {
        if max_pow > MAX_POW {
            return Err(Error::Setup(format!("max_pow above {MAX_POW}")));
        }
        if db.exists() {
            return Err(Error::Setup(format!("{} exists", db.display())));
        }
        let mut secret = [0; 32];
        OsRng.fill_bytes(&mut secret);
        let keys = IssuerKeys::from_seed(&secret, 0, max_pow)?;
        write_seed(seed, &secret)?;
        let created = Store::create(db, |tx| {
            tx.execute(
                "INSERT INTO keysets (id, idx, max_pow, created_at) VALUES (?1, 0, ?2, ?3)",
                params![keys.id(), max_pow, now()],
            )?;
            Ok(())
        });
        if created.is_err() {
            // Nothing was issued under this seed.
            let _ = std::fs::remove_file(seed);
        }
        created
    }

    /// The hub that [`Hub::init`] created at `seed` and `db`.
    pub fn open(seed: &Path, db: &Path, policy: Policy) -> Result<Self, Error> {
        let secret = read_seed(seed)?;
        let store = Store::open(db)?;
        let rows: Vec<([u8; 32], u32, u32)> = store.read(|c| {
            let mut rows = c.prepare("SELECT id, idx, max_pow FROM keysets ORDER BY idx")?;
            let rows = rows
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            Ok(rows)
        })?;
        // By index: the first is the one it issues under.
        let issuing = rows.first().map(|(id, _, _)| *id);
        let issuing = issuing.ok_or_else(|| Error::Setup("the database has no keyset".into()))?;
        let mut keysets = BTreeMap::new();
        for (id, index, max_pow) in rows {
            let keys = IssuerKeys::from_seed(&secret, index, max_pow)?;
            if keys.id() != &id {
                return Err(Error::Setup("the seed does not match the database".into()));
            }
            let keyset = keys.keyset()?;
            keysets.insert(id, (keys, keyset));
        }
        if keysets.is_empty() {
            return Err(Error::Setup("the database has no keyset".into()));
        }
        let newest = store.read(locks::newest_checkpoint)?;
        let (mut boot, mut drawn) = ([0; 16], [0; 32]);
        OsRng.fill_bytes(&mut boot);
        OsRng.fill_bytes(&mut drawn);
        let hub = Self {
            store,
            keysets,
            issuing,
            owner: OwnerKeys::from_seed(&tagged_hash("licash-hub/owner", &[&secret]))?,
            unlock_secret: tagged_hash("licash-hub/unlock", &[&secret]),
            nostr: nostr_key(tagged_hash("licash-hub/nostr", &[&secret]))?,
            deposit: tagged_hash("licash-hub/deposit", &[&secret]),
            witness: witness_of(&secret),
            boot,
            boot_key: tagged_hash("licash-hub/boot", &[&secret, &drawn]),
            answered: Mutex::default(),
            offers: Mutex::default(),
            held_offers: Mutex::default(),
            forgotten_at: Mutex::default(),
            policy,
            newest: Mutex::new(newest),
            synced_at: Mutex::default(),
            reorg_alerted: AtomicBool::default(),
            proved: Mutex::default(),
        };
        let boot = hex::encode(boot);
        tracing::info!(keysets = hub.keysets.len(), %boot, "hub started");
        hub.store
            .write(|tx| notify(tx, &Notice::Started { boot }))?;
        Ok(hub)
    }

    /// Whether the hub stopped serving ([`Error::Halted`]): a restart
    /// serves the database as it then is.
    pub fn halted(&self) -> bool {
        self.store.halted()
    }

    /// The secret key the hub signs its Nostr announcements with: its
    /// public key is the `nostr` of [`Hub::advertise`].
    pub fn nostr_secret(&self) -> [u8; 32] {
        self.nostr.0
    }

    /// The secret key the hub signs each entry its contract witnesses keep
    /// with, and they check: of its seed alone, the same across restores,
    /// and of no use but to them. Not a valid key, by chance of about one
    /// in 2^128, is the caller's to refuse.
    pub fn witness_secret(&self) -> [u8; 32] {
        self.witness
    }

    /// The secret key the hub claims a deposit on Bitcoin under `hash`
    /// with, each deposit's its own: not a valid key, by chance of about
    /// one in 2^128, is the caller's to refuse.
    pub fn deposit_secret(&self, hash: &[u8; 32]) -> [u8; 32] {
        tagged_hash("licash-hub/deposit-key", &[&self.deposit, hash])
    }

    /// The secret of the hub's deposit root, from which it claims the
    /// deposits that return a contract's reserve, each under a key
    /// derived from the root's public key, which it publishes: not a valid
    /// key, by chance of about one in 2^128, is the caller's to refuse.
    pub fn deposit_root_secret(&self) -> [u8; 32] {
        tagged_hash("licash-hub/deposit-root", &[&self.deposit])
    }

    /// What the hub publishes of itself.
    pub fn info(&self) -> Info {
        Info {
            keysets: self.keysets.values().map(|(_, k)| k.clone()).collect(),
            address: self.owner.address(),
            policy: self.policy,
        }
    }

    /// What the hub says of itself at [`licash_api::INFO`]: with the locks
    /// it admits once it follows a chain, and then the proof of its
    /// identity on that chain's network.
    pub fn advertise(&self) -> Result<licash_api::Info, Error> {
        let info = self.info();
        let (policy, timing) = (info.policy, info.policy.timing);
        let fees = policy.fees();
        let locks = match (self.checkpoint(), self.scanned()?) {
            (Some(checkpoint), Some((height, _))) => Some(licash_api::Locks {
                checkpoint: licash_api::Hex(checkpoint.to_bytes()),
                height,
                window: timing.window,
                reaction: timing.reaction,
                min_depth: timing.min_depth,
                max_headers: timing.max_headers,
            }),
            _ => None,
        };
        let mut advertised = licash_api::Info::new(&info.keysets, info.address, fees, locks);
        advertised.nostr = Some(self.nostr.1.clone());
        if let Some(checkpoint) = self.checkpoint() {
            let identity = advertised
                .identity(checkpoint.profile())
                .map_err(|p| Error::Setup(format!("the hub's identity: {p}")))?;
            let mut proved = self.proved.lock().unwrap_or_else(PoisonError::into_inner);
            let signature = match &*proved {
                Some((digest, signature)) if *digest == identity => *signature,
                _ => {
                    let signature = schnorr_sign(self.owner.spend_secret(), &identity)?;
                    *proved = Some((identity, signature));
                    signature
                }
            };
            advertised.proof = Some(licash_api::Hex(signature.0.to_vec()));
        }
        Ok(advertised)
    }

    /// The keyset the hub issues under where it is the one to choose, as
    /// for the contracts it opens: of the lowest index, the only one it
    /// makes for now. A wallet names the keyset of what it asks for, and
    /// [`Hub::info`] lists them all, ordered by id.
    pub fn issuing(&self) -> &Keyset {
        &self.keysets[&self.issuing].1
    }

    /// The hub's keyset `id`, to decode requests under.
    pub fn keyset(&self, id: &[u8; 32]) -> Option<&Keyset> {
        self.keysets.get(id).map(|(_, keyset)| keyset)
    }

    /// The events after `seq`, oldest first, at most `limit`.
    pub fn events(&self, after: u64, limit: u32) -> Result<Vec<Event>, Error> {
        self.store.read(|c| events(c, after, limit))
    }

    /// Tell the operator `message`, through the notification outbox.
    pub fn alert(&self, message: &str) -> Result<(), Error> {
        tracing::error!("alert: {message}");
        self.store.write(|tx| {
            notify(
                tx,
                &Notice::Alert {
                    message: message.to_owned(),
                },
            )
        })
    }

    fn keys(&self, id: &[u8; 32]) -> Result<(&IssuerKeys, &Keyset), Error> {
        let (keys, keyset) = self.keysets.get(id).ok_or(Refusal::UnknownKeyset)?;
        Ok((keys, keyset))
    }

    /// The unlock of the grant of `proposal`: a scalar of the hub's secret,
    /// derived again rather than stored, its key in the grant
    /// ([`licash::authorization::Grant::unlock_key`]). Zero with negligible
    /// odds, which [`PreparedGrant::derive`] refuses.
    fn unlock(&self, keyset: &[u8; 32], proposal: &ProposalId, salt: &[u8; 32]) -> Unlock {
        let hash = tagged_hash(
            "licash-hub/grant-unlock",
            &[&self.unlock_secret, keyset, proposal.as_bytes(), salt],
        );
        ScalarBytes::from_scalar(&scalar_from_hash(&hash)).0
    }

    /// The secret of the unlink nonces of `proposal`'s outputs, for this
    /// process only.
    fn nonce_secret(&self, proposal: &[u8; 32]) -> [u8; 32] {
        tagged_hash("licash-hub/unlink-nonce", &[&self.boot_key, proposal])
    }
}

fn notify(tx: &Transaction<'_>, notice: &Notice) -> Result<(), Error> {
    let json = serde_json::to_string(notice).expect("notices serialize");
    tx.execute(
        "INSERT INTO events (at, kind, json) VALUES (?1, ?2, ?3)",
        params![now(), notice.kind(), json],
    )?;
    Ok(())
}

/// `value` as an SQLite integer: an error beyond it, not a lesser amount.
/// Denominations fit by [`MAX_POW`].
fn sql(value: u64) -> Result<i64, Error> {
    Ok(licash_store::sat(value)?)
}

/// `secret`, and its x-only public key in hex, as Nostr names keys.
fn nostr_key(secret: [u8; 32]) -> Result<([u8; 32], String), Error> {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    let pair = Keypair::from_seckey_slice(&Secp256k1::signing_only(), &secret)
        .map_err(|e| Error::Setup(format!("the Nostr key: {e}")))?;
    Ok((secret, hex::encode(pair.x_only_public_key().0.serialize())))
}

fn write_seed(path: &Path, seed: &[u8; 32]) -> Result<(), Error> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| setup_io(path, e))?;
    file.write_all(format!("{}\n", hex::encode(seed)).as_bytes())?;
    file.sync_all()?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// The hub's witness key ([`Hub::witness_secret`]) of its seed's secret.
fn witness_of(secret: &[u8; 32]) -> [u8; 32] {
    tagged_hash("licash-hub/witness", &[secret])
}

/// The ledger at `db` held as no hub runs on it, until the file returned is
/// dropped: refused while one runs. For a command that must not run beside
/// the hub.
pub fn stopped(db: &Path) -> Result<std::fs::File, Error> {
    store::lock(db)
}

/// The hub's witness key ([`Hub::witness_secret`]) of the seed at `seed`,
/// without opening its ledger: for a command run beside the hub, or with
/// it stopped.
pub fn witness_secret_of(seed: &Path) -> Result<[u8; 32], Error> {
    Ok(witness_of(&read_seed(seed)?))
}

fn read_seed(path: &Path) -> Result<[u8; 32], Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Setup(format!("seed {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            tracing::warn!(path = %path.display(), "the seed is readable by others than its owner");
        }
    }
    let mut seed = [0; 32];
    hex::decode_to_slice(text.trim(), &mut seed)
        .map_err(|_| Error::Setup(format!("seed {}: not 32 hex bytes", path.display())))?;
    Ok(seed)
}

/// Spends and unlinking.
impl Hub {
    /// The grant for `proposal`, spending `notes`: the hub's offer to issue
    /// its outputs once their owners authorize it ([`Hub::release`]). The
    /// same proposal gets the same offer.
    pub fn offer(&self, proposal: &Proposal, notes: &[Note]) -> Result<Grant, Error> {
        self.offer_held(proposal, notes, None)
    }

    /// [`Hub::offer`], signed by each of `notes`' hold key if `holds`, one
    /// for each in their order ([`licash::offer`]): its owner's offer,
    /// counted apart from those of anyone else knowing the notes. Refused
    /// if one is not its note's.
    pub fn offer_held(
        &self,
        proposal: &Proposal,
        notes: &[Note],
        holds: Option<&[Signature]>,
    ) -> Result<Grant, Error> {
        let (keys, keyset) = self.keys(proposal.keyset_id())?;
        if proposal.lock().is_some() {
            return Err(Refusal::Timed.into());
        }
        let id = proposal.id();
        // A note spent by another proposal is refused before any work on
        // it: checked again once the grant is made, as a spend may race.
        let named = proposal
            .inputs()
            .iter()
            .map(|message| message.identifier())
            .collect::<Result<Vec<Point>, _>>()?;
        if self.spent_by_other(&id, &named)? {
            return Err(Refusal::Spent.into());
        }
        let ys = proposal.verify(keyset, notes)?;
        if let Some(holds) = holds {
            if holds.len() != notes.len() {
                let why = "an offer's holds are not one for each note";
                return Err(licash::Error::Protocol(why.into()).into());
            }
            for (note, sig) in notes.iter().zip(holds) {
                licash::offer::verify(&id, note.message(), sig)?;
            }
        }
        let counted = match holds {
            Some(_) => &self.held_offers,
            None => &self.offers,
        };
        let (amount, fee, made) = self.charge(proposal)?;
        let due = self.policy.fees().spending().due(amount, made);
        if fee < due {
            return Err(Refusal::Fee { due, paid: fee }.into());
        }
        let full = |offers: &HashMap<[u8; 33], u8>| {
            ys.iter()
                .any(|y| offers.get(&y.0).is_some_and(|n| *n >= MAX_OFFERS))
        };
        self.forget_unreleased()?;
        // Refused before its grant is made, unless offered before: its
        // grant then, as kept.
        if full(&counted.lock().unwrap_or_else(PoisonError::into_inner)) && !self.offered(&id)? {
            return Err(Refusal::Offered.into());
        }
        let mut salt = [0; 32];
        OsRng.fill_bytes(&mut salt);
        let unlock = self.unlock(keyset.id(), &id, &salt);
        let grant =
            PreparedGrant::derive(keys, proposal, unlock, &self.nonce_secret(id.as_bytes()))?
                .offer();
        let offer = grant.to_bytes()?;
        // Held over the write: racing offers of a note count to the most.
        let mut offers = counted.lock().unwrap_or_else(PoisonError::into_inner);
        let (grant, new) = self.store.write(|tx| {
            if claims::claimed(tx, &ys)? {
                return Err(Refusal::Spent.into());
            }
            for y in &ys {
                let spent: Option<[u8; 32]> = tx
                    .query_row("SELECT proposal FROM spent WHERE y = ?1", [&y.0], |r| {
                        r.get(0)
                    })
                    .optional()?;
                if spent.is_some_and(|by| &by != id.as_bytes()) {
                    return Err(Refusal::Spent.into());
                }
            }
            let offered: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT offer FROM grants WHERE id = ?1",
                    [id.as_bytes()],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(offered) = offered {
                return Ok((Grant::from_bytes(&offered)?, false));
            }
            if full(&offers) {
                return Err(Refusal::Offered.into());
            }
            for output in proposal.outputs() {
                if issued(tx, output)? {
                    return Err(Refusal::Reissued.into());
                }
            }
            tx.execute(
                "INSERT INTO proposals (id, keyset, created_at) VALUES (?1, ?2, ?3)",
                params![id.as_bytes(), keyset.id(), now()],
            )?;
            tx.execute(
                "INSERT INTO grants (id, offer, salt, boot) VALUES (?1, ?2, ?3, ?4)",
                params![id.as_bytes(), offer, salt, self.boot],
            )?;
            Ok((grant, true))
        })?;
        if new {
            for y in &ys {
                *offers.entry(y.0).or_default() += 1;
            }
        }
        Ok(grant)
    }

    /// Delete the grants left unreleased [`UNRELEASED_FOR`], with their
    /// proposals, at most once each [`FORGET_EVERY`]. One released never
    /// has rows elsewhere: its issuance and inputs are kept at release.
    fn forget_unreleased(&self) -> Result<(), Error> {
        {
            let mut at = self
                .forgotten_at
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if at.is_some_and(|at| at.elapsed() < FORGET_EVERY) {
                return Ok(());
            }
            *at = Some(Instant::now());
        }
        let before = now() - UNRELEASED_FOR;
        let forgotten = self.store.write(|tx| {
            let ids = tx
                .prepare(
                    "SELECT g.id FROM grants g JOIN proposals p ON p.id = g.id
                     WHERE g.released_at IS NULL AND p.double_spent_at IS NULL
                       AND p.created_at < ?1",
                )?
                .query_map([before], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for id in &ids {
                tx.execute("DELETE FROM grants WHERE id = ?1", [id])?;
                tx.execute("DELETE FROM proposals WHERE id = ?1", [id])?;
            }
            Ok(ids.len())
        })?;
        if forgotten > 0 {
            tracing::info!(forgotten, "offers left unreleased for a day deleted");
        }
        Ok(())
    }

    /// Whether proposal `id` was offered.
    fn offered(&self, id: &ProposalId) -> Result<bool, Error> {
        self.store.read(|c| {
            Ok(c.prepare_cached("SELECT 1 FROM grants WHERE id = ?1")?
                .exists([id.as_bytes()])?)
        })
    }

    /// The unlock of the offer `signed` authorizes, once the owners of
    /// `notes` signed it: their inputs are retired and its outputs issued
    /// first. A released spend gets its unlock again.
    pub fn release(&self, signed: &SignedProposal, notes: &[Note]) -> Result<Unlock, Error> {
        let proposal = signed.proposal();
        let (_, keyset) = self.keys(proposal.keyset_id())?;
        let id = proposal.id();
        let offered: Option<(Vec<u8>, [u8; 32], [u8; 16])> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT offer, salt, boot FROM grants WHERE id = ?1",
                [id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
        })?;
        let (offer, salt, boot) = offered.ok_or(Refusal::UnknownOffer)?;
        let unlock = self.unlock(keyset.id(), &id, &salt);
        Grant::from_bytes(&offer)?.verify_release(keyset, notes, signed, &unlock)?;
        // Refused once known not to be released already: one released is
        // its unlock again, whatever this release would admit.
        let citable = citable::Citable::check(keyset, signed, notes, Some(unlock));
        let ys = proposal
            .inputs()
            .iter()
            .map(|message| message.identifier())
            .collect::<Result<Vec<Point>, _>>()?;
        let (amount, fee, _) = self.charge(proposal)?;
        let income = self
            .owner
            .scan_key()
            .receive(proposal)?
            .iter()
            .map(|r| {
                let index = r.position as usize;
                let note =
                    signed.open_granted_output(keyset, notes, index, &r.derivation, &unlock)?;
                Ok((r.position, note))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mut spent_by = None;
        let released = self.store.write(|tx| {
            // Deleted meanwhile, left unreleased too long: unknown now.
            let released: Option<i64> = tx
                .query_row(
                    "SELECT released_at FROM grants WHERE id = ?1",
                    [id.as_bytes()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Refusal::UnknownOffer)?;
            if released.is_some() {
                return Ok(false);
            }
            if let Some(by) = retire(tx, &id, &citable?)? {
                spent_by = Some(by);
                return Err(Refusal::Spent.into());
            }
            for (position, output) in (0i64..).zip(proposal.outputs()) {
                let inserted = tx.execute(
                    "INSERT INTO issued (keyset, denom, blinded, commitment, proposal, position, boot)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT DO NOTHING",
                    params![
                        keyset.id(),
                        sql(output.denomination())?,
                        &output.blinded().0,
                        output.unlink_commitment(),
                        id.as_bytes(),
                        position,
                        boot,
                    ],
                )?;
                if inserted == 0 {
                    return Err(Refusal::Reissued.into());
                }
            }
            for (position, note) in &income {
                tx.execute(
                    "INSERT INTO income (proposal, position, denom, note) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        id.as_bytes(),
                        position,
                        sql(note.message().denomination())?,
                        note.to_bytes()
                    ],
                )?;
            }
            tx.execute(
                "UPDATE grants SET signed = ?2, released_at = ?3 WHERE id = ?1",
                params![id.as_bytes(), signed.to_bytes(), now()],
            )?;
            let proposal = hex::encode(id.as_bytes());
            notify(tx, &Notice::Released { proposal, amount, fee })?;
            Ok(true)
        });
        if let Some(by) = spent_by {
            let (proposal, spent_by) = (hex::encode(id.as_bytes()), hex::encode(by));
            tracing::warn!(%proposal, %spent_by, "double spend refused");
            self.store.write(|tx| {
                let first = tx.execute(
                    "UPDATE proposals SET double_spent_at = ?2
                     WHERE id = ?1 AND double_spent_at IS NULL",
                    params![id.as_bytes(), now()],
                )?;
                if first == 1 {
                    notify(tx, &Notice::DoubleSpend { proposal, spent_by })?;
                }
                Ok(())
            })?;
        }
        if released? {
            tracing::info!(proposal = %hex::encode(id.as_bytes()), amount, fee, "released");
            // Its notes spent: offered no more, not counted.
            for counted in [&self.offers, &self.held_offers] {
                let mut offers = counted.lock().unwrap_or_else(PoisonError::into_inner);
                for y in &ys {
                    offers.remove(&y.0);
                }
            }
        }
        Ok(unlock)
    }

    /// Whether any of `identifiers` is spent by a proposal other than `id`.
    fn spent_by_other(&self, id: &ProposalId, identifiers: &[Point]) -> Result<bool, Error> {
        self.store.read_current(|c| {
            let mut stmt = c.prepare_cached("SELECT proposal FROM spent WHERE y = ?1")?;
            for y in identifiers {
                let by: Option<[u8; 32]> = stmt.query_row([&y.0], |r| r.get(0)).optional()?;
                if by.is_some_and(|by| &by != id.as_bytes()) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Whether each of the notes with these identifiers is spent: retired
    /// by a released spend, a lock or a claim on Bitcoin. For the operator
    /// and for tests: the hub serves it to no one, since anyone who knew a
    /// note's identifier could learn its state. A holder is shown only
    /// evidence of her own notes ([`Hub::inquire`]).
    pub fn spent(&self, identifiers: &[Point]) -> Result<Vec<bool>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare_cached("SELECT 1 FROM spent WHERE y = ?1")?;
            identifiers
                .iter()
                .map(|y| Ok(stmt.exists([&y.0])? || claims::is_claimed(c, y)?))
                .collect()
        })
    }

    /// The answer to an unlink request for an output this hub issued since
    /// it started, or the same answer again for the same request. Only the
    /// holder of the output's capability learns more than [`Refusal::NotIssued`].
    pub fn unlink(&self, request: &Request) -> Result<Answer, Error> {
        let (keys, keyset) = self.keys(request.keyset())?;
        keyset.key(request.denomination())?;
        let denom = sql(request.denomination())?;
        let blinded = request.blinded();
        let output_hash = tagged_hash(
            "licash-hub/issued",
            &[
                keyset.id(),
                &request.denomination().to_be_bytes(),
                &blinded.0,
            ],
        );
        let request_hash = tagged_hash("licash-hub/unlink-request", &[&request.to_bytes()]);
        self.store.write(|tx| {
            type Row = ([u8; 32], [u8; 32], Option<[u8; 16]>, Option<Vec<u8>>);
            let row: Option<Row> = tx
                .query_row(
                    "SELECT commitment, proposal, boot, answered FROM issued
                     WHERE keyset = ?1 AND denom = ?2 AND blinded = ?3",
                    params![keyset.id(), denom, &blinded.0],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            // A reserved output has no boot: it is not issued yet.
            let (commitment, proposal, boot, stored) = row
                .filter(|(commitment, ..)| *commitment == request.unlink_commitment())
                .and_then(|(c, p, boot, s)| Some((c, p, boot?, s)))
                .ok_or(Refusal::NotIssued)?;
            let mut answered = self.answered.lock().unwrap_or_else(PoisonError::into_inner);
            match (answered.get(&output_hash), stored) {
                (Some(asked), _) if *asked != request_hash => Err(Refusal::Unlinked.into()),
                // This process answered, and the database forgot.
                (Some(_), None) => Err(Error::Halted),
                (_, Some(stored)) => Answered::from_bytes(&stored)?
                    .replay(request)
                    .map_err(|_| Refusal::Unlinked.into()),
                (None, None) => {
                    if boot != self.boot {
                        return Err(Refusal::Expired.into());
                    }
                    let output = Output::new(request.denomination(), blinded, commitment)?;
                    let nonce =
                        unlink::Nonce::derive(&self.nonce_secret(&proposal), keyset, &output)?;
                    let record = nonce.answer(keys, request)?;
                    let updated = tx.execute(
                        "UPDATE issued SET answered = ?4
                         WHERE keyset = ?1 AND denom = ?2 AND blinded = ?3 AND answered IS NULL",
                        params![keyset.id(), denom, &blinded.0, record.to_bytes()],
                    )?;
                    if updated != 1 {
                        return Err(Error::Halted);
                    }
                    answered.insert(output_hash, request_hash);
                    Ok(record.answer())
                }
            }
        })
    }

    /// The amount `proposal`, no lock, moves, the part of it paid to the
    /// hub, and how many notes it makes for others.
    fn charge(&self, proposal: &Proposal) -> Result<(u64, u64, usize), Error> {
        let amount = proposal
            .inputs()
            .iter()
            .fold(0u64, |sum, m| sum.saturating_add(m.denomination()));
        let received = self.owner.scan_key().receive(proposal)?;
        let fee = received.iter().fold(0u64, |sum, r| {
            sum.saturating_add(r.derivation.message().denomination())
        });
        let made = proposal.outputs().len().saturating_sub(received.len());
        Ok((amount, fee, made))
    }
}

/// Whether `output` was issued or reserved before, under any keyset.
fn issued(tx: &Transaction<'_>, output: &Output) -> Result<bool, Error> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM issued WHERE blinded = ?1",
            [&output.blinded().0],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Retire the inputs of proposal `id`, a spend its contracts can cite:
/// none, or the proposal that retired one of them first. Refused if a
/// claim on Bitcoin holds one of them. The one way notes are retired by a
/// spend, so that none is retired by a spend no dispute could cite.
fn retire(
    tx: &Transaction<'_>,
    id: &ProposalId,
    spend: &citable::Citable<'_>,
) -> Result<Option<[u8; 32]>, Error> {
    let ys = spend.ys();
    if claims::claimed(tx, ys)? {
        tracing::warn!(proposal = %hex::encode(id.as_bytes()), "a spend of claimed notes refused");
        return Err(Refusal::Spent.into());
    }
    for (position, (y, note)) in (0i64..).zip(ys.iter().zip(spend.notes())) {
        let inserted = tx.execute(
            "INSERT INTO spent (y, proposal, position, note) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT DO NOTHING",
            params![&y.0, id.as_bytes(), position, note.to_bytes()],
        )?;
        if inserted == 0 {
            return Ok(Some(tx.query_row(
                "SELECT proposal FROM spent WHERE y = ?1",
                [&y.0],
                |r| r.get(0),
            )?));
        }
    }
    Ok(None)
}
