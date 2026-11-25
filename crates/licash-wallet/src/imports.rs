//! Notes of another wallet a recovery of this one may claim: those a
//! bridge keeping this wallet's account exported once frozen, should its
//! hub stop cooperating ([`Wallet::export_notes`]).
//!
//! A note's hold key is all a claim needs of it: the export is of each
//! note spendable, its coordinates, and its hold key, sealed to the
//! wallet's key at the bridge, none of the bridge's seed nor its spending
//! keys. Imported, the notes fill what a contract's own notes, funding
//! and locks leave of its cap only ([`Wallet::claim_imported`]), never
//! displacing them, and are dropped from a claim that would not be owed
//! whole with them ([`Wallet::void_imported`]). The wallet's balance and
//! what it shows protected count none of them: they are the bridge's
//! until a recovery claims them.
//!
//! A hold key signing claims in two contracts voids its note in both: a
//! bridge exports only once frozen, and is unfrozen only once its owner
//! discarded the import ([`Wallet::discard_imported`]).
//!
//! Kept in their own table of the wallet's file (`imports`, version
//! [`VERSION`]), made as the first import is written: absent, nothing was
//! imported; of another version, nothing imported is claimed.

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use licash::{
    crypto::{random_scalar, tagged_hash, x_only_pub, Point, ScalarBytes},
    note::{Keyset, Message},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::{claims::ClaimNote, Error, Transport, Wallet};

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

/// The layout of an export: its format, the Nostr key of the bridge it is
/// of, the key it is sealed to, an ephemeral key, then its notes sealed.
const FORMAT: u8 = 1;
const HEADER: usize = 1 + 32 + 32 + 33;

/// The notes of a wallet sealed for another to claim
/// ([`Wallet::export_notes`]).
#[derive(Clone, Debug)]
pub struct SealedNotes {
    pub sealed: Vec<u8>,
    pub notes: usize,
    /// What they are worth, in sat.
    pub amount: u64,
}

/// What an import added ([`Wallet::import_notes`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    /// The Nostr key of the bridge they came from, in hex.
    pub source: String,
    /// The notes new to the wallet, and what they are worth in sat.
    pub added: usize,
    pub amount: u64,
    /// Those imported before.
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
    /// Those a recovery claims.
    pub claimed: usize,
    /// Those dropped from a claim that would not be owed whole with them.
    pub void: usize,
}

/// An export before sealing: keysets, and notes of them by position.
#[derive(Serialize, Deserialize)]
struct Plain {
    keysets: Vec<String>,
    notes: Vec<Exported>,
}

#[derive(Serialize, Deserialize)]
struct Exported {
    keyset: usize,
    note: String,
    hold_key: String,
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

/// Whether the recovery of contract `id` took notes imported.
pub(crate) fn took(c: &Connection, id: &[u8; 32]) -> Result<bool, Error> {
    if !present(c)? {
        return Ok(false);
    }
    Ok(c.query_row(
        "SELECT EXISTS (SELECT 1 FROM imported_notes WHERE claimed_by = ?1)",
        [id],
        |r| r.get(0),
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
    /// key, sealed to `to`, a wallet's x-only key at the bridge answering
    /// as `source`, for that wallet to claim in a recovery of its own
    /// ([`Wallet::import_notes`]). Nothing that spends them: whoever holds
    /// the export may claim them, which voids them should this wallet
    /// claim them too, but not spend them.
    pub fn export_notes(&self, source: &[u8; 32], to: &[u8; 32]) -> Result<SealedNotes, Error> {
        let rows: Vec<([u8; 33], [u8; 32])> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT y, keyset FROM notes
                 WHERE spent_by IS NULL AND session IS NULL AND gone_at IS NULL
                 ORDER BY keyset, denom DESC, y",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut keysets: BTreeMap<[u8; 32], (usize, Keyset)> = BTreeMap::new();
        let mut notes = Vec::with_capacity(rows.len());
        for (y, id) in &rows {
            if !keysets.contains_key(id) {
                let at = keysets.len();
                keysets.insert(*id, (at, self.keyset_of(id)?));
            }
            let (at, keyset) = &keysets[id];
            let note = self
                .store
                .read(|c| crate::claims::claim_note(c, keyset, y))?;
            notes.push((*at, note));
        }
        let claimed: Vec<ClaimNote> = notes.iter().map(|(_, n)| n.clone()).collect();
        let keys = self.hold_keys(&claimed)?;
        let mut amount = 0u64;
        let exported = (notes.iter().zip(&keys))
            .map(|((at, note), (message, key))| {
                amount = amount.saturating_add(message.denomination());
                Exported {
                    keyset: *at,
                    note: hex::encode(note.to_bytes()),
                    hold_key: hex::encode(key.0),
                }
            })
            .collect();
        let mut ordered: Vec<_> = keysets.into_values().collect();
        ordered.sort_by_key(|(at, _)| *at);
        let plain = Plain {
            keysets: ordered
                .iter()
                .map(|(_, k)| hex::encode(k.to_bytes()))
                .collect(),
            notes: exported,
        };
        let plain = serde_json::to_vec(&plain).map_err(crate::invalid)?;
        let ephemeral = random_scalar();
        let public = Point::from_projective(&licash::crypto::generator_mul(&ephemeral));
        let shared = Point::from_projective(&(lifted(to)? * ephemeral)).x_only();
        let mut sealed = Vec::with_capacity(HEADER + plain.len() + 16);
        sealed.push(FORMAT);
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
            notes: rows.len(),
            amount,
        })
    }

    /// Keep the notes `sealed` exports to this wallet's key at the bridge
    /// that made it ([`Wallet::export_notes`]), for its recoveries to
    /// claim: all or none, refused if one is not a note its keyset's
    /// issuer signed or its hold key is not the note's. The same export
    /// again adds nothing; a later one of the same bridge, what is new.
    pub fn import_notes(&self, sealed: &[u8]) -> Result<Imported, Error> {
        if sealed.len() < HEADER + 16 || sealed[0] != FORMAT {
            return Err(bad("of no format this build reads"));
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
        let plain: Plain = serde_json::from_slice(&plain).map_err(|_| bad("its notes"))?;
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
        let root = self.keys.bridges;
        let (added, amount, known) = self.store.write(|t| {
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
            Ok((added, amount, known))
        })?;
        tracing::info!(source = %hex::encode(source), added, amount, known, unknown, "notes imported");
        Ok(Imported {
            source: hex::encode(source),
            added,
            amount,
            known,
            unknown,
        })
    }

    /// The notes imported, by the bridge they came from.
    pub fn imported_notes(&self) -> Result<Vec<ImportedSource>, Error> {
        self.store.read(|c| {
            if !present(c)? {
                return Ok(Vec::new());
            }
            let mut stmt = c.prepare(
                "SELECT source, COUNT(*),
                    COALESCE(SUM(CASE WHEN void IS NULL THEN denom ELSE 0 END), 0),
                    COUNT(claimed_by), COUNT(void)
                 FROM imported_notes GROUP BY source ORDER BY source",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(ImportedSource {
                    source: hex::encode(r.get::<_, Vec<u8>>(0)?),
                    notes: r.get::<_, i64>(1)? as usize,
                    amount: r.get::<_, i64>(2)? as u64,
                    claimed: r.get::<_, i64>(3)? as usize,
                    void: r.get::<_, i64>(4)? as usize,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Forget the notes imported from the bridge answering as `source`,
    /// in hex, for it to spend them again: how many. Refused while a
    /// recovery claims one, which may file it yet.
    pub fn discard_imported(&self, source: &str) -> Result<usize, Error> {
        let mut key = [0u8; 32];
        hex::decode_to_slice(source, &mut key)
            .map_err(|_| Error::Invalid("not a bridge's Nostr key".into()))?;
        self.store.write(|t| {
            if !present(t)? {
                return Ok(0);
            }
            let claimed: bool = t.query_row(
                "SELECT EXISTS (SELECT 1 FROM imported_notes
                    WHERE source = ?1 AND claimed_by IS NOT NULL)",
                [key],
                |r| r.get(0),
            )?;
            if claimed {
                return Err(Error::Invalid(
                    "a recovery claims notes of this bridge: they stay".into(),
                ));
            }
            Ok(t.execute("DELETE FROM imported_notes WHERE source = ?1", [key])?)
        })
    }

    /// Take for the recovery of contract `id`, of `keyset`, notes imported
    /// worth `cap` sat at most in `max` notes at most: what its own notes,
    /// funding and locks left of its cap and its count. As its own are
    /// shared, the least of them above what is left if none come to it.
    /// None if it took notes imported already.
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
        self.store.write(|t| {
            if took(t, id)? {
                return Ok(Vec::new());
            }
            let stock: Vec<([u8; 33], u64, Vec<u8>)> = {
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
