//! Notes of another wallet a recovery of this one may claim: those a
//! bridge keeping this wallet's account exported once frozen, should its
//! hub stop cooperating ([`Wallet::export_notes`]), and the refunds of the
//! locks it made that its hub never settled, a payment stuck on it say.
//!
//! A note's hold key is all a claim needs of it: the export is of each
//! note spendable, its coordinates, and its hold key, and of each lock its
//! signed body, its certificate, and the openings and hold keys of its
//! refund ([`crate::claims::Refund`]), sealed to the wallet's key at the
//! bridge, none of the bridge's seed nor its spending keys. Imported, the
//! notes fill what a contract's own notes, funding and locks leave of its
//! cap only ([`Wallet::claim_imported`]), then the locks owed
//! ([`Wallet::claim_imported_locks`]), never displacing them. A claim that
//! would not be owed whole with them is made again without the locks
//! ([`Wallet::release_imported_locks`]), then without the notes, dropped
//! for good ([`Wallet::void_imported`]). The wallet's balance and what it
//! shows protected count none of them: they are the bridge's until a
//! recovery claims them.
//!
//! A hold key signing claims in two contracts voids its note in both: a
//! bridge exports only once frozen, and is unfrozen only once its owner
//! discarded the import ([`Wallet::discard_imported`]).
//!
//! Kept in their own tables of the wallet's file, the notes in one
//! component (`imports`, version [`VERSION`]) and the locks in another
//! (`imported_locks`, version [`LOCKS_VERSION`]), each made as the first
//! import writing to it is: absent, nothing was imported; of another
//! version, nothing imported is claimed.
//!
//! An export is of format 1 of notes alone, as builds reading no locks
//! read it, and of format 2 with locks: a build that reads neither format
//! refuses the export whole, never part of it, and this build refuses a
//! later format by its number.

use std::collections::{BTreeMap, HashSet};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use licash::{
    crypto::{random_scalar, tagged_hash, x_only_pub, Point, ScalarBytes},
    note::{Keyset, Message},
    source::Certificate,
    spend::ProposalId,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::{
    claims::{ClaimNote, LockClaim, Refund, RefundOutput},
    held, Error, Transport, Wallet,
};

const COMPONENT: &str = "imports";
const VERSION: i64 = 1;

/// No foreign keys, indexes or triggers, as the codes' tables.
const SCHEMA: &str = "
-- A note of another wallet, by its point: its keyset, denomination, its
-- coordinates (ClaimNote::to_bytes), its hold key sealed under a key of
-- this wallet's seed, and the Nostr key of the bridge it came from. The
-- recovery claiming it, once taken, and why it was dropped from one, if
-- it was: never claimed again.
CREATE TABLE imported_notes (
    y BLOB PRIMARY KEY,
    keyset BLOB NOT NULL,
    denom INTEGER NOT NULL,
    note BLOB NOT NULL,
    hold_key BLOB NOT NULL,
    source BLOB NOT NULL,
    claimed_by BLOB,
    void TEXT,
    added_at INTEGER NOT NULL
) STRICT;
";

const LOCKS_COMPONENT: &str = "imported_locks";
const LOCKS_VERSION: i64 = 1;

const LOCKS_SCHEMA: &str = "
-- The refund of a lock of another wallet, by its id and branch (1, the
-- refund): its keyset, what its outputs to that wallet are worth, how many
-- hold keys sign for it, the height it is owed at (its expiry at depth),
-- what claims it (an ExportedLock in JSON) sealed under a key of this
-- wallet's seed, and the Nostr key of the bridge it came from. The
-- recovery claiming it, once taken.
CREATE TABLE imported_locks (
    id BLOB NOT NULL,
    branch INTEGER NOT NULL,
    keyset BLOB NOT NULL,
    value INTEGER NOT NULL,
    keys INTEGER NOT NULL,
    owed_at INTEGER NOT NULL,
    record BLOB NOT NULL,
    source BLOB NOT NULL,
    claimed_by BLOB,
    added_at INTEGER NOT NULL,
    PRIMARY KEY (id, branch)
) STRICT;
";

/// The layout of an export: its format, the Nostr key of the bridge it is
/// of, the key it is sealed to, an ephemeral key, then its notes sealed:
/// of [`Plain`] in format 1, of [`PlainLocks`] in format 2.
const FORMAT: u8 = 1;
const FORMAT_LOCKS: u8 = 2;
const HEADER: usize = 1 + 32 + 32 + 33;

/// The branch of an imported lock's row: its refund, the only one kept.
const REFUND: i64 = 1;

/// The notes of a wallet sealed for another to claim
/// ([`Wallet::export_notes`]).
#[derive(Clone, Debug)]
pub struct SealedNotes {
    pub sealed: Vec<u8>,
    pub notes: usize,
    /// What they are worth, in sat.
    pub amount: u64,
    /// The locks whose refunds it holds, and what those are worth in sat.
    pub locks: usize,
    pub locked: u64,
}

/// What an import added ([`Wallet::import_notes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// The Nostr key of the bridge they came from, in hex.
    pub source: String,
    /// The notes new to the wallet, and what they are worth in sat.
    pub added: usize,
    pub amount: u64,
    /// The locks' refunds new to the wallet, and what they are worth in
    /// sat.
    pub locks: usize,
    pub locked: u64,
    /// The notes and locks imported before.
    pub known: usize,
    /// Those of a keyset the wallet never held, which none of its
    /// contracts claim: left out.
    pub unknown: usize,
}

/// The notes imported from a bridge ([`Wallet::imported_notes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedSource {
    pub source: String,
    pub notes: usize,
    /// What they are worth in sat, those dropped from a claim aside.
    pub amount: u64,
    /// The locks' refunds, and what they are worth in sat.
    pub locks: usize,
    pub locked: u64,
    /// The notes and locks a recovery claims.
    pub claimed: usize,
    /// Those dropped from a claim that would not be owed whole with them.
    pub void: usize,
}

/// An export of format 1 before sealing: keysets, and notes of them by
/// position.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    keysets: Vec<String>,
    notes: Vec<Exported>,
}

/// An export of format 2 before sealing: [`Plain`]'s, and locks.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlainLocks {
    keysets: Vec<String>,
    notes: Vec<Exported>,
    locks: Vec<ExportedLock>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exported {
    keyset: usize,
    note: String,
    hold_key: String,
}

/// A lock's [`Refund`] exported, under the keyset its request names; its
/// hub's certificate and its inputs' hold keys in hex, of the bytes the
/// hub and the keys are.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportedLock {
    request: licash_api::Lock,
    certificate: Option<String>,
    outputs: Vec<ExportedOutput>,
    inputs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportedOutput {
    index: u32,
    message: String,
    blinding: String,
    hold_key: String,
}

impl ExportedLock {
    fn of(refund: &Refund) -> Self {
        Self {
            request: licash_api::Lock::new(&refund.signed, &refund.notes),
            certificate: (refund.certificate.as_ref()).map(|c| hex::encode(c.to_bytes())),
            outputs: (refund.outputs.iter())
                .map(|o| ExportedOutput {
                    index: o.index,
                    message: hex::encode(o.message.to_bytes()),
                    blinding: hex::encode(o.blinding.0),
                    hold_key: hex::encode(o.hold_key.0),
                })
                .collect(),
            inputs: (refund.inputs.iter()).map(|k| hex::encode(k.0)).collect(),
        }
    }

    /// The keyset its request names.
    fn keyset(&self) -> Result<[u8; 32], Error> {
        (self.request.keyset.0.as_slice().try_into()).map_err(|_| bad("a lock's keyset"))
    }

    /// Its [`Refund`] under `keyset`, read, not checked
    /// ([`Refund::check`]).
    fn refund(&self, keyset: &Keyset) -> Result<Refund, Error> {
        let lookup = |id: &[u8; 32]| (id == keyset.id()).then_some(keyset);
        let (signed, notes) = (self.request.decode(lookup)).map_err(|_| bad("a lock"))?;
        let certificate = match &self.certificate {
            Some(c) => {
                let bytes = hex::decode(c).map_err(|_| bad("a lock's certificate"))?;
                Some(Certificate::from_bytes(keyset, &bytes)?)
            }
            None => None,
        };
        let key = |k: &str| {
            let mut key = [0u8; 32];
            hex::decode_to_slice(k, &mut key).map_err(|_| bad("a lock's key"))?;
            Ok::<_, Error>(ScalarBytes(key))
        };
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for o in &self.outputs {
            let message = hex::decode(&o.message).map_err(|_| bad("a lock's output"))?;
            outputs.push(RefundOutput {
                index: o.index,
                message: Message::from_bytes(&message)?,
                blinding: key(&o.blinding)?,
                hold_key: key(&o.hold_key)?,
            });
        }
        let inputs = self
            .inputs
            .iter()
            .map(|k| key(k))
            .collect::<Result<_, _>>()?;
        Ok(Refund {
            signed,
            notes,
            certificate,
            outputs,
            inputs,
        })
    }
}

fn component_version(c: &Connection) -> Result<Option<i64>, Error> {
    licash_store::component_version(c, COMPONENT).map_err(stored)
}

fn stored(e: licash_store::Error) -> Error {
    match e {
        licash_store::Error::Sqlite(e) => Error::Storage(e),
        e => Error::Setup(e.to_string()),
    }
}

/// Whether this build reads the notes imported in `c`: some imported, of
/// [`VERSION`].
fn present(c: &Connection) -> Result<bool, Error> {
    Ok(component_version(c)? == Some(VERSION))
}

fn writable(tx: &Transaction) -> Result<(), Error> {
    match component_version(tx)? {
        Some(VERSION) => Ok(()),
        Some(_) => Err(Error::Invalid(
            "notes imported, the wallet's file keeping them as a later version does".into(),
        )),
        None => licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(stored),
    }
}

/// The key an export to `to` from `source` is sealed with, of the
/// Diffie-Hellman secret `shared` of its ephemeral key and `to`.
fn export_key(shared: &[u8; 32], ephemeral: &Point, to: &[u8; 32], source: &[u8; 32]) -> Key {
    Key::from(tagged_hash(
        "licash/notes/export",
        &[shared, &ephemeral.0, to, source],
    ))
}

/// The point of the x-only key `x`, of even y.
fn lifted(x: &[u8; 32]) -> Result<k256::ProjectivePoint, Error> {
    let mut bytes = [2u8; 33];
    bytes[1..].copy_from_slice(x);
    Point(bytes)
        .to_projective()
        .map_err(|_| Error::Invalid("not a key".into()))
}

/// The cipher a hold key imported as note `y` is kept under, of `root`.
fn kept(root: &[u8; 32], y: &[u8; 33]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(tagged_hash("licash/imports/key", &[root, y])))
}

fn bad(why: &str) -> Error {
    Error::Invalid(format!("not an export of notes: {why}"))
}

/// The hold key imported as note `y`, kept under `root`, if imported.
pub(crate) fn hold_key(
    c: &Connection,
    root: &[u8; 32],
    y: &[u8; 33],
) -> Result<Option<ScalarBytes>, Error> {
    if !present(c)? {
        return Ok(None);
    }
    let sealed: Option<Vec<u8>> = c
        .query_row(
            "SELECT hold_key FROM imported_notes WHERE y = ?1",
            [y.as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(sealed) = sealed else {
        return Ok(None);
    };
    let payload = Payload {
        msg: &sealed,
        aad: y,
    };
    let key = (kept(root, y).decrypt(&Nonce::default(), payload))
        .map_err(|_| Error::Invalid("an imported hold key not of this wallet's seed".into()))?;
    let key: [u8; 32] = key.try_into().map_err(|_| bad("a hold key's length"))?;
    Ok(Some(ScalarBytes(key)))
}

/// Whether this build reads the locks imported in `c`: some imported, of
/// [`LOCKS_VERSION`].
fn locks_present(c: &Connection) -> Result<bool, Error> {
    let version = licash_store::component_version(c, LOCKS_COMPONENT).map_err(stored)?;
    Ok(version == Some(LOCKS_VERSION))
}

fn locks_writable(tx: &Transaction) -> Result<(), Error> {
    match licash_store::component_version(tx, LOCKS_COMPONENT).map_err(stored)? {
        Some(LOCKS_VERSION) => Ok(()),
        Some(_) => Err(Error::Invalid(
            "locks imported, the wallet's file keeping them as a later version does".into(),
        )),
        None => licash_store::component_in(tx, LOCKS_COMPONENT, LOCKS_VERSION, LOCKS_SCHEMA)
            .map_err(stored),
    }
}

/// The cipher the refund of lock `id` imported is kept under, of `root`,
/// and the bytes it authenticates with it.
fn kept_lock(root: &[u8; 32], id: &[u8; 32]) -> (ChaCha20Poly1305, [u8; 33]) {
    let key = Key::from(tagged_hash("licash/imports/lock", &[root, id]));
    let mut aad = [0u8; 33];
    aad[..32].copy_from_slice(id);
    aad[32] = REFUND as u8;
    (ChaCha20Poly1305::new(&key), aad)
}

/// The claim of the refund of lock `id` imported as `record`, kept under
/// `root`, of `keyset`, and the points of its inputs and outputs.
fn opened_lock(
    root: &[u8; 32],
    keyset: &Keyset,
    id: &[u8; 32],
    record: &[u8],
) -> Result<(LockClaim, Vec<[u8; 33]>), Error> {
    let (cipher, aad) = kept_lock(root, id);
    let payload = Payload {
        msg: record,
        aad: &aad,
    };
    let plain = (cipher.decrypt(&Nonce::default(), payload))
        .map_err(|_| Error::Invalid("a lock imported not of this wallet's seed".into()))?;
    let exported: ExportedLock =
        serde_json::from_slice(&plain).map_err(|_| bad("a lock imported"))?;
    let refund = exported.refund(keyset)?;
    let points = points(&refund)?;
    let (claim, _) = refund
        .claim(keyset)?
        .ok_or_else(|| bad("a lock paying nothing"))?;
    if claim.id.as_bytes() != id {
        return Err(bad("a lock imported as another"));
    }
    Ok((claim, points))
}

/// The points of `refund`'s inputs and of its outputs to the wallet.
fn points(refund: &Refund) -> Result<Vec<[u8; 33]>, Error> {
    let inputs = refund.notes.iter().map(|n| n.message());
    let outputs = refund.outputs.iter().map(|o| &o.message);
    (inputs.chain(outputs))
        .map(|m| Ok(m.identifier()?.0))
        .collect()
}

/// The points of the inputs and outputs of the locks imported a recovery
/// took, kept under `root`: notes imported later of them (their refund, or
/// their inputs freed) are claimed by no other.
fn taken_points(c: &Connection, root: &[u8; 32]) -> Result<HashSet<[u8; 33]>, Error> {
    let mut points = HashSet::new();
    if !locks_present(c)? {
        return Ok(points);
    }
    let mut stmt =
        c.prepare("SELECT id, keyset, record FROM imported_locks WHERE claimed_by IS NOT NULL")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, [u8; 32]>(0)?,
            r.get::<_, [u8; 32]>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in rows {
        let (id, keyset, record) = row?;
        let opened = crate::claims::keyset_in(c, &keyset)
            .and_then(|keyset| opened_lock(root, &keyset, &id, &record));
        match opened {
            Ok((_, of)) => points.extend(of),
            // Never claimed, then: a recovery could not have filed it.
            Err(e) => tracing::warn!(lock = %hex::encode(id), "a lock imported unread: {e}"),
        }
    }
    Ok(points)
}

/// Whether one of `points` is a note of this wallet's, or one imported.
fn overlaps(c: &Connection, points: &[[u8; 33]]) -> Result<bool, Error> {
    let imported = present(c)?;
    for y in points {
        let own: bool = c.query_row(
            "SELECT EXISTS (SELECT 1 FROM notes WHERE y = ?1)",
            [y.as_slice()],
            |r| r.get(0),
        )?;
        let theirs = imported
            && c.query_row(
                "SELECT EXISTS (SELECT 1 FROM imported_notes WHERE y = ?1)",
                [y.as_slice()],
                |r| r.get(0),
            )?;
        if own || theirs {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the recovery of contract `id` took locks imported.
fn took_locks(c: &Connection, id: &[u8; 32]) -> Result<bool, Error> {
    if !locks_present(c)? {
        return Ok(false);
    }
    Ok(c.query_row(
        "SELECT EXISTS (SELECT 1 FROM imported_locks WHERE claimed_by = ?1)",
        [id],
        |r| r.get(0),
    )?)
}

/// Whether the recovery of contract `id` took notes or locks imported.
pub(crate) fn took(c: &Connection, id: &[u8; 32]) -> Result<bool, Error> {
    Ok(took_notes(c, id)? || took_locks(c, id)?)
}

/// Whether the recovery of contract `id` took notes imported.
fn took_notes(c: &Connection, id: &[u8; 32]) -> Result<bool, Error> {
    if !present(c)? {
        return Ok(false);
    }
    Ok(c.query_row(
        "SELECT EXISTS (SELECT 1 FROM imported_notes WHERE claimed_by = ?1)",
        [id],
        |r| r.get(0),
    )?)
}

/// The refunds of locks imported the recovery of contract `id` took, of
/// `keyset`, kept under `root`, by id.
pub(crate) fn claimed_locks(
    c: &Connection,
    root: &[u8; 32],
    keyset: &Keyset,
    id: &[u8; 32],
) -> Result<Vec<LockClaim>, Error> {
    if !locks_present(c)? {
        return Ok(Vec::new());
    }
    let mut stmt = c.prepare(
        "SELECT id, record FROM imported_locks WHERE claimed_by = ?1 AND keyset = ?2
         ORDER BY id",
    )?;
    let rows = stmt.query_map(params![id, keyset.id()], |r| {
        Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let rows = rows.collect::<Result<Vec<_>, _>>()?;
    (rows.iter())
        .map(|(lock, record)| Ok(opened_lock(root, keyset, lock, record)?.0))
        .collect()
}

/// Give back the locks imported the recovery of contract `id` took: how
/// many.
pub(crate) fn release_locks(t: &Transaction<'_>, id: &[u8; 32]) -> Result<usize, Error> {
    if !locks_present(t)? {
        return Ok(0);
    }
    Ok(t.execute(
        "UPDATE imported_locks SET claimed_by = NULL WHERE claimed_by = ?1",
        [id],
    )?)
}

/// The notes imported the recovery of contract `id` took, of `keyset`,
/// the largest first.
pub(crate) fn claimed(
    c: &Connection,
    keyset: &Keyset,
    id: &[u8; 32],
) -> Result<Vec<ClaimNote>, Error> {
    if !present(c)? {
        return Ok(Vec::new());
    }
    let mut stmt = c.prepare(
        "SELECT note FROM imported_notes WHERE claimed_by = ?1 AND keyset = ?2
         ORDER BY denom DESC, y",
    )?;
    let rows = stmt.query_map(params![id, keyset.id()], |r| r.get::<_, Vec<u8>>(0))?;
    let notes = rows.collect::<Result<Vec<_>, _>>()?;
    notes
        .iter()
        .map(|n| ClaimNote::from_bytes(keyset, n))
        .collect()
}

/// Give back the notes imported the recovery of contract `id` took: how
/// many.
pub(crate) fn release(t: &Transaction<'_>, id: &[u8; 32]) -> Result<usize, Error> {
    if !present(t)? {
        return Ok(0);
    }
    Ok(t.execute(
        "UPDATE imported_notes SET claimed_by = NULL WHERE claimed_by = ?1",
        [id],
    )?)
}

impl<T: Transport> Wallet<T> {
    /// Every note of this wallet spendable, its coordinates and its hold
    /// key, and the refund of each of its locks unsettled that pays it
    /// (`Refund`), sealed to `to`, a wallet's x-only key at the bridge
    /// answering as `source`, for that wallet to claim in a recovery of its
    /// own ([`Wallet::import_notes`]). Nothing that spends them: whoever
    /// holds the export may claim them, which voids them should this
    /// wallet claim them too, but not spend them. Of format 1 without
    /// locks, of format 2 with: read at once, the notes and the locks as
    /// they are together.
    pub fn export_notes(&self, source: &[u8; 32], to: &[u8; 32]) -> Result<SealedNotes, Error> {
        let (keysets, notes, locks, amount, locked) = self.store.read(|c| {
            let mut keysets: BTreeMap<[u8; 32], (usize, Keyset)> = BTreeMap::new();
            let mut index = |c: &Connection, id: &[u8; 32]| -> Result<usize, Error> {
                if !keysets.contains_key(id) {
                    let at = keysets.len();
                    keysets.insert(*id, (at, crate::claims::keyset_in(c, id)?));
                }
                Ok(keysets[id].0)
            };
            let rows: Vec<([u8; 33], [u8; 32])> = {
                let mut stmt = c.prepare(
                    "SELECT y, keyset FROM notes
                     WHERE spent_by IS NULL AND session IS NULL AND gone_at IS NULL
                     ORDER BY keyset, denom DESC, y",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            let mut at = Vec::with_capacity(rows.len());
            for (_, id) in &rows {
                at.push(index(c, id)?);
            }
            let (mut notes, mut amount) = (Vec::with_capacity(rows.len()), 0u64);
            for ((y, id), at) in rows.iter().zip(at) {
                let held = held(c, &keysets[id].1, y)?;
                let derivation = self.derivation(&held)?;
                if derivation.message() != held.note.message() {
                    return Err(Error::Invalid("a note not of this wallet's keys".into()));
                }
                let key = derivation.hold_key(self.owner.hold_root())?;
                amount = amount.saturating_add(held.note.message().denomination());
                let note = ClaimNote {
                    note: held.note,
                    ephemeral: held.ephemeral.0,
                    branch: held.branch,
                    position: held.position,
                };
                notes.push(Exported {
                    keyset: at,
                    note: hex::encode(note.to_bytes()),
                    hold_key: hex::encode(key.0),
                });
            }
            // As a recovery of this wallet's would read them
            // ([`Wallet::claim_with_locks`]), due or not.
            let rows: Vec<([u8; 32], String, Option<Vec<u8>>)> = {
                let mut stmt = c.prepare(
                    "SELECT id, request, certificate FROM locks
                     WHERE id NOT IN (SELECT id FROM lock_settlements)
                        AND abandoned IS NULL AND claimed_by IS NULL
                     ORDER BY id",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                rows.collect::<Result<_, _>>()?
            };
            let (mut locks, mut locked) = (Vec::new(), 0u64);
            for (id, request, certificate) in &rows {
                let refund = (serde_json::from_str::<licash_api::Lock>(request))
                    .map_err(crate::invalid)
                    .and_then(|r| {
                        let keyset: [u8; 32] =
                            r.keyset.0.as_slice().try_into().map_err(crate::invalid)?;
                        crate::claims::keyset_in(c, &keyset)
                    })
                    .and_then(|keyset| {
                        self.refund(c, &keyset, id, request, certificate.as_deref())
                    });
                match refund {
                    Ok(Some(refund)) if !refund.outputs.is_empty() => {
                        let worth = refund.outputs.iter().map(|o| o.message.denomination());
                        locked = locked.saturating_add(worth.sum());
                        locks.push(ExportedLock::of(&refund));
                    }
                    Ok(_) => {}
                    // As a recovery of its own would leave it out.
                    Err(e) => {
                        tracing::warn!(lock = %hex::encode(id), "a lock's refund not exported: {e}")
                    }
                }
            }
            Ok((keysets, notes, locks, amount, locked))
        })?;
        let mut ordered: Vec<_> = keysets.into_values().collect();
        ordered.sort_by_key(|(at, _)| *at);
        let keysets: Vec<String> = (ordered.iter())
            .map(|(_, k)| hex::encode(k.to_bytes()))
            .collect();
        let count = (notes.len(), locks.len());
        let (format, plain) = match locks.is_empty() {
            true => (FORMAT, serde_json::to_vec(&Plain { keysets, notes })),
            false => (
                FORMAT_LOCKS,
                serde_json::to_vec(&PlainLocks {
                    keysets,
                    notes,
                    locks,
                }),
            ),
        };
        let plain = plain.map_err(crate::invalid)?;
        let ephemeral = random_scalar();
        let public = Point::from_projective(&licash::crypto::generator_mul(&ephemeral));
        let shared = Point::from_projective(&(lifted(to)? * ephemeral)).x_only();
        let mut sealed = Vec::with_capacity(HEADER + plain.len() + 16);
        sealed.push(format);
        sealed.extend(source);
        sealed.extend(to);
        sealed.extend(public.0);
        let cipher = ChaCha20Poly1305::new(&export_key(&shared, &public, to, source));
        let payload = Payload {
            msg: &plain,
            aad: &sealed[..HEADER],
        };
        let body = (cipher.encrypt(&Nonce::default(), payload))
            .map_err(|_| Error::Invalid("notes not sealed".into()))?;
        sealed.extend(body);
        Ok(SealedNotes {
            sealed,
            notes: count.0,
            amount,
            locks: count.1,
            locked,
        })
    }

    /// Keep the notes and the locks' refunds `sealed` exports to this
    /// wallet's key at the bridge that made it ([`Wallet::export_notes`]),
    /// for its recoveries to claim: all or none, refused if one is not a
    /// note its keyset's issuer signed or its hold key is not the note's,
    /// or a refund is not all it says (`Refund::check`). The same export
    /// again adds nothing; a later one of the same bridge, what is new.
    pub fn import_notes(&self, sealed: &[u8]) -> Result<Imported, Error> {
        if sealed.len() < HEADER + 16 {
            return Err(bad("too short"));
        }
        let format = sealed[0];
        if format != FORMAT && format != FORMAT_LOCKS {
            return Err(bad(&format!(
                "of format {format}, which this build does not read: a later build's"
            )));
        }
        let source: [u8; 32] = sealed[1..33].try_into().map_err(|_| bad("its bridge"))?;
        let to: [u8; 32] = sealed[33..65].try_into().map_err(|_| bad("its key"))?;
        let public = Point(sealed[65..HEADER].try_into().map_err(|_| bad("its key"))?);
        let secret = ScalarBytes(self.bridge_secret(&source))
            .to_scalar()
            .map_err(|_| Error::Setup("no bridge key from this seed".into()))?;
        if x_only_pub(&secret) != to {
            return Err(Error::Invalid(
                "an export of notes to another wallet's key".into(),
            ));
        }
        let shared = Point::from_projective(&(public.to_projective()? * secret)).x_only();
        let cipher = ChaCha20Poly1305::new(&export_key(&shared, &public, &to, &source));
        let payload = Payload {
            msg: &sealed[HEADER..],
            aad: &sealed[..HEADER],
        };
        let plain =
            (cipher.decrypt(&Nonce::default(), payload)).map_err(|_| bad("it does not open"))?;
        let plain = match format {
            FORMAT => {
                let plain: Plain = serde_json::from_slice(&plain).map_err(|_| bad("its notes"))?;
                PlainLocks {
                    keysets: plain.keysets,
                    notes: plain.notes,
                    locks: Vec::new(),
                }
            }
            _ => serde_json::from_slice(&plain).map_err(|_| bad("its notes and locks"))?,
        };
        let mut keysets = Vec::with_capacity(plain.keysets.len());
        for bytes in &plain.keysets {
            let theirs = Keyset::from_bytes(&hex::decode(bytes).map_err(|_| bad("a keyset"))?)?;
            // Only a keyset the wallet holds is one its contracts claim.
            keysets.push(self.keyset_of(theirs.id()).ok());
        }
        let mut rows = Vec::with_capacity(plain.notes.len());
        let mut unknown = 0;
        for exported in &plain.notes {
            let keyset = keysets
                .get(exported.keyset)
                .ok_or_else(|| bad("a note of no keyset"))?;
            let Some(keyset) = keyset else {
                unknown += 1;
                continue;
            };
            let bytes = hex::decode(&exported.note).map_err(|_| bad("a note"))?;
            // Verified as read: its keyset's issuer signed it.
            let note = ClaimNote::from_bytes(keyset, &bytes)?;
            let mut key = [0u8; 32];
            hex::decode_to_slice(&exported.hold_key, &mut key).map_err(|_| bad("a hold key"))?;
            let message: &Message = note.note.message();
            let holds = ScalarBytes(key)
                .to_scalar()
                .is_ok_and(|k| x_only_pub(&k) == *message.hold());
            if !holds {
                return Err(bad("a hold key not its note's"));
            }
            let y = message.identifier()?.0;
            rows.push((y, *keyset.id(), message.denomination(), bytes, key));
        }
        let mut locks = Vec::with_capacity(plain.locks.len());
        for exported in &plain.locks {
            let Ok(keyset) = self.keyset_of(&exported.keyset()?) else {
                unknown += 1;
                continue;
            };
            let refund = exported.refund(&keyset)?;
            refund.check(&keyset)?;
            let (claim, owed) =
                (refund.claim(&keyset)?).ok_or_else(|| bad("a lock paying nothing"))?;
            let record = serde_json::to_vec(exported).map_err(crate::invalid)?;
            locks.push((claim, owed, *keyset.id(), record));
        }
        let root = self.keys.bridges;
        let (added, amount, known, new_locks, locked) = self.store.write(|t| {
            writable(t)?;
            let (mut added, mut amount, mut known) = (0, 0u64, 0);
            for (y, keyset, denom, note, key) in &rows {
                let own: bool = t.query_row(
                    "SELECT EXISTS (SELECT 1 FROM notes WHERE y = ?1)",
                    [y.as_slice()],
                    |r| r.get(0),
                )?;
                if own {
                    known += 1;
                    continue;
                }
                let payload = Payload {
                    msg: key.as_slice(),
                    aad: y,
                };
                let sealed = (kept(&root, y).encrypt(&Nonce::default(), payload))
                    .map_err(|_| Error::Invalid("a hold key not sealed".into()))?;
                let new = t.execute(
                    "INSERT OR IGNORE INTO imported_notes
                        (y, keyset, denom, note, hold_key, source, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        y.as_slice(),
                        keyset,
                        i64::try_from(*denom).map_err(crate::invalid)?,
                        note,
                        sealed,
                        source,
                        licash_store::now()
                    ],
                )?;
                if new == 1 {
                    added += 1;
                    amount = amount.saturating_add(*denom);
                } else {
                    known += 1;
                }
            }
            let (mut new_locks, mut locked) = (0, 0u64);
            if !locks.is_empty() {
                locks_writable(t)?;
            }
            for (claim, owed, keyset, record) in &locks {
                let id = claim.id.as_bytes();
                let own: bool = t.query_row(
                    "SELECT EXISTS (SELECT 1 FROM locks WHERE id = ?1)",
                    [id],
                    |r| r.get(0),
                )?;
                if own {
                    known += 1;
                    continue;
                }
                let (cipher, aad) = kept_lock(&root, id);
                let payload = Payload {
                    msg: record.as_slice(),
                    aad: &aad,
                };
                let sealed = (cipher.encrypt(&Nonce::default(), payload))
                    .map_err(|_| Error::Invalid("a lock's refund not sealed".into()))?;
                let new = t.execute(
                    "INSERT OR IGNORE INTO imported_locks
                        (id, branch, keyset, value, keys, owed_at, record, source, added_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        id,
                        REFUND,
                        keyset,
                        i64::try_from(claim.value).map_err(crate::invalid)?,
                        i64::try_from(claim.keys.len()).map_err(crate::invalid)?,
                        owed,
                        sealed,
                        source,
                        licash_store::now()
                    ],
                )?;
                if new == 1 {
                    new_locks += 1;
                    locked = locked.saturating_add(claim.value);
                } else {
                    known += 1;
                }
            }
            Ok((added, amount, known, new_locks, locked))
        })?;
        tracing::info!(
            source = %hex::encode(source), added, amount, locks = new_locks, locked, known, unknown,
            "notes imported"
        );
        Ok(Imported {
            source: hex::encode(source),
            added,
            amount,
            locks: new_locks,
            locked,
            known,
            unknown,
        })
    }

    /// The notes and locks imported, by the bridge they came from.
    pub fn imported_notes(&self) -> Result<Vec<ImportedSource>, Error> {
        self.store.read(|c| {
            let mut by: BTreeMap<Vec<u8>, ImportedSource> = BTreeMap::new();
            let empty = |source: &[u8]| ImportedSource {
                source: hex::encode(source),
                notes: 0,
                amount: 0,
                locks: 0,
                locked: 0,
                claimed: 0,
                void: 0,
            };
            if present(c)? {
                let mut stmt = c.prepare(
                    "SELECT source, COUNT(*),
                        COALESCE(SUM(CASE WHEN void IS NULL THEN denom ELSE 0 END), 0),
                        COUNT(claimed_by), COUNT(void)
                     FROM imported_notes GROUP BY source",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                })?;
                for row in rows {
                    let (source, notes, amount, claimed, void) = row?;
                    let at = by.entry(source.clone()).or_insert_with(|| empty(&source));
                    at.notes = notes as usize;
                    at.amount = amount as u64;
                    at.claimed += claimed as usize;
                    at.void = void as usize;
                }
            }
            if locks_present(c)? {
                let mut stmt = c.prepare(
                    "SELECT source, COUNT(*), COALESCE(SUM(value), 0), COUNT(claimed_by)
                     FROM imported_locks GROUP BY source",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })?;
                for row in rows {
                    let (source, locks, locked, claimed) = row?;
                    let at = by.entry(source.clone()).or_insert_with(|| empty(&source));
                    at.locks = locks as usize;
                    at.locked = locked as u64;
                    at.claimed += claimed as usize;
                }
            }
            Ok(by.into_values().collect())
        })
    }

    /// Forget the notes and locks imported from the bridge answering as
    /// `source`, in hex, for it to spend them again: how many. Refused
    /// while a recovery claims one, which may file it yet.
    pub fn discard_imported(&self, source: &str) -> Result<usize, Error> {
        let mut key = [0u8; 32];
        hex::decode_to_slice(source, &mut key)
            .map_err(|_| Error::Invalid("not a bridge's Nostr key".into()))?;
        self.store.write(|t| {
            let (notes, locks) = (present(t)?, locks_present(t)?);
            let claimed = |table: &str| -> Result<bool, Error> {
                Ok(t.query_row(
                    &format!(
                        "SELECT EXISTS (SELECT 1 FROM {table}
                            WHERE source = ?1 AND claimed_by IS NOT NULL)"
                    ),
                    [key],
                    |r| r.get(0),
                )?)
            };
            if (notes && claimed("imported_notes")?) || (locks && claimed("imported_locks")?) {
                return Err(Error::Invalid(
                    "a recovery claims notes of this bridge: they stay".into(),
                ));
            }
            let mut gone = 0;
            if notes {
                gone += t.execute("DELETE FROM imported_notes WHERE source = ?1", [key])?;
            }
            if locks {
                gone += t.execute("DELETE FROM imported_locks WHERE source = ?1", [key])?;
            }
            Ok(gone)
        })
    }

    /// Take for the recovery of contract `id`, of `keyset`, the refunds of
    /// locks imported owed by `tip` (expired at depth), each whole, worth
    /// `cap` sat at most with `max` hold keys at most signing for them in
    /// all: what its own notes, funding and locks and the notes imported
    /// left of its cap and its count. The largest first; none of whose
    /// inputs or outputs is a note of the wallet's or one imported, which
    /// a claim would have twice, or of a lock imported a recovery took.
    /// None if it took locks imported already.
    pub fn claim_imported_locks(
        &self,
        id: &[u8; 32],
        keyset: &[u8; 32],
        tip: u32,
        cap: u64,
        max: usize,
    ) -> Result<Vec<LockClaim>, Error> {
        if cap == 0 || max == 0 || !self.store.read(locks_present)? {
            return Ok(Vec::new());
        }
        let keyset = self.keyset_of(keyset)?;
        let root = self.keys.bridges;
        self.store.write(|t| {
            if took_locks(t, id)? {
                return Ok(Vec::new());
            }
            let rows: Vec<([u8; 32], Vec<u8>)> = {
                let mut stmt = t.prepare(
                    "SELECT id, record FROM imported_locks
                     WHERE keyset = ?1 AND branch = ?2 AND claimed_by IS NULL AND owed_at <= ?3
                     ORDER BY value DESC, id",
                )?;
                let rows = stmt.query_map(params![keyset.id(), REFUND, tip], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
                rows.collect::<Result<_, _>>()?
            };
            let mut held = taken_points(t, &root)?;
            let (mut cap, mut max, mut taken) = (cap, max, Vec::new());
            for (lock, record) in rows {
                let (claim, points) = match opened_lock(&root, &keyset, &lock, &record) {
                    Ok(opened) => opened,
                    Err(e) => {
                        tracing::warn!(lock = %hex::encode(lock), "a lock imported not claimable: {e}");
                        continue;
                    }
                };
                if claim.value > cap || claim.keys.len() > max {
                    continue;
                }
                if points.iter().any(|y| held.contains(y)) || overlaps(t, &points)? {
                    tracing::info!(
                        lock = %hex::encode(lock),
                        "a lock imported left out: a note of it is held or imported too"
                    );
                    continue;
                }
                let took = t.execute(
                    "UPDATE imported_locks SET claimed_by = ?1
                     WHERE id = ?2 AND branch = ?3 AND claimed_by IS NULL",
                    params![id, lock, REFUND],
                )?;
                if took != 1 {
                    return Err(Error::NoteTaken);
                }
                cap -= claim.value;
                max -= claim.keys.len();
                held.extend(points);
                taken.push(claim);
            }
            Ok(taken)
        })
    }

    /// Give back the refunds of locks imported the recovery of contract
    /// `id` took, for a claim that would not be owed whole with them: their
    /// ids. Not dropped, unlike notes ([`Wallet::void_imported`]): a
    /// recovery of another contract may claim them.
    pub fn release_imported_locks(
        &self,
        id: &[u8; 32],
        why: &str,
    ) -> Result<Vec<ProposalId>, Error> {
        let ids = self.store.write(|t| {
            if !locks_present(t)? {
                return Ok(Vec::new());
            }
            let ids: Vec<[u8; 32]> = {
                let mut stmt = t.prepare("SELECT id FROM imported_locks WHERE claimed_by = ?1")?;
                let rows = stmt.query_map([id], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            release_locks(t, id)?;
            Ok(ids)
        })?;
        if !ids.is_empty() {
            tracing::warn!(
                id = %hex::encode(id), released = ids.len(),
                "locks imported left out of a claim: {why}"
            );
        }
        Ok(ids.into_iter().map(ProposalId::from_bytes).collect())
    }

    /// Take for the recovery of contract `id`, of `keyset`, notes imported
    /// worth `cap` sat at most in `max` notes at most: what its own notes,
    /// funding and locks left of its cap and its count. As its own are
    /// shared, the least of them above what is left if none come to it.
    /// None of a lock imported a recovery took, its refund or its inputs
    /// imported again later as notes. None if it took notes imported
    /// already.
    pub fn claim_imported(
        &self,
        id: &[u8; 32],
        keyset: &[u8; 32],
        cap: u64,
        max: usize,
    ) -> Result<Vec<ClaimNote>, Error> {
        if cap == 0 || max == 0 {
            return Ok(Vec::new());
        }
        let present = self.store.read(present)?;
        if !present {
            return Ok(Vec::new());
        }
        let keyset = self.keyset_of(keyset)?;
        let root = self.keys.bridges;
        self.store.write(|t| {
            if took_notes(t, id)? {
                return Ok(Vec::new());
            }
            let taken = taken_points(t, &root)?;
            let mut stock: Vec<([u8; 33], u64, Vec<u8>)> = {
                let mut stmt = t.prepare(
                    "SELECT y, denom, note FROM imported_notes
                     WHERE keyset = ?1 AND claimed_by IS NULL AND void IS NULL
                     ORDER BY denom DESC, y",
                )?;
                let rows = stmt.query_map([keyset.id()], |r| {
                    Ok((r.get(0)?, r.get::<_, i64>(1)? as u64, r.get(2)?))
                })?;
                rows.collect::<Result<_, _>>()?
            };
            stock.retain(|(y, _, _)| !taken.contains(y));
            let denoms: Vec<u64> = stock.iter().map(|(_, d, _)| *d).collect();
            let mut notes = Vec::new();
            for i in crate::claims::share(&denoms, cap, max) {
                let (y, _, note) = &stock[i];
                let taken = t.execute(
                    "UPDATE imported_notes SET claimed_by = ?1
                     WHERE y = ?2 AND claimed_by IS NULL AND void IS NULL",
                    params![id, y.as_slice()],
                )?;
                if taken != 1 {
                    return Err(Error::NoteTaken);
                }
                notes.push(ClaimNote::from_bytes(&keyset, note)?);
            }
            Ok(notes)
        })
    }

    /// Drop the notes imported from the claim of contract `id`, for good,
    /// as `why` says its claim would not be owed whole with them: their
    /// points.
    pub fn void_imported(&self, id: &[u8; 32], why: &str) -> Result<Vec<[u8; 33]>, Error> {
        self.store.write(|t| {
            if !present(t)? {
                return Ok(Vec::new());
            }
            let ys: Vec<[u8; 33]> = {
                let mut stmt = t.prepare("SELECT y FROM imported_notes WHERE claimed_by = ?1")?;
                let rows = stmt.query_map([id], |r| r.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            t.execute(
                "UPDATE imported_notes SET claimed_by = NULL, void = ?2 WHERE claimed_by = ?1",
                params![id, why],
            )?;
            if !ys.is_empty() {
                tracing::warn!(id = %hex::encode(id), dropped = ys.len(), "notes imported dropped from a claim: {why}");
            }
            Ok(ys)
        })
    }
}
