//! What the hub may retire notes for: only a spend its contracts can cite.
//!
//! A note the hub retires is one it must later show spent, should its
//! holder claim it on Bitcoin: its statement reads the spend as evidence
//! ([`licash::recovery::evidence_from_bytes`]) under its Base's limits, and
//! a spend it cannot read is no evidence. The hub would then answer nothing,
//! and her timeout pay her for a note already spent. So nothing is retired
//! but by a [`Citable`]: the spend as the hub cites it, by its owners'
//! signatures ([`licash::recovery::Evidence::Signed`]), every one of them,
//! encoded, read back under limits every contract's statement admits, no
//! larger than [`MAX_EVIDENCE_BYTES`], and verified as the statement does.
//! The same knowledge finds the spends a ledger of an earlier release
//! retired that cannot be cited ([`uncitable`]).

use std::path::Path;

use licash::{
    authorization::{SignedProposal, Unlock},
    crypto::Point,
    note::{Keyset, Note},
    recovery::{
        by_signature, evidence_from_bytes, evidence_to_bytes, voids_note, MAX_PUBLICATION_BYTES,
    },
    spend::MAX_INPUTS,
};
use licash_store::Kind;
use serde::Serialize;

use crate::{Error, Refusal};

/// The most bytes a spend's evidence may be, its notes and its signed
/// proposal together: what a statement reads of one publication, so that
/// the proof of a response citing it stays as the hub plans it.
pub const MAX_EVIDENCE_BYTES: usize = MAX_PUBLICATION_BYTES;

/// The notes a spend retires, checked citable: as its evidence it encodes
/// within [`MAX_EVIDENCE_BYTES`] and reads back under a limit of
/// [`MAX_INPUTS`] notes, which every Base admits.
pub(crate) struct Citable<'a> {
    ys: Vec<Point>,
    notes: &'a [Note],
}

impl<'a> Citable<'a> {
    /// `signed` spending `notes`, with its `unlock` if granted, as the
    /// ledger would cite it: refused if any statement could not read it.
    pub(crate) fn check(
        keyset: &Keyset,
        signed: &SignedProposal,
        notes: &'a [Note],
        unlock: Option<Unlock>,
    ) -> Result<Self, Error> {
        let inputs = signed.proposal().inputs();
        if notes.len() > MAX_INPUTS || inputs.len() > MAX_INPUTS {
            return Err(Refusal::TooLarge.into());
        }
        let evidence = by_signature(signed, unlock, &(0..inputs.len()).collect())?;
        let bytes = evidence_to_bytes(std::slice::from_ref(&evidence));
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(Refusal::TooLarge.into());
        }
        let [read] = <[_; 1]>::try_from(evidence_from_bytes(keyset, MAX_INPUTS, &bytes)?)
            .map_err(|_| Error::Invalid(licash::Error::Protocol("one spend cited".into())))?;
        // As a statement would: every signature, and the unlock of a grant.
        if !voids_note(keyset, &inputs[0], &read)? {
            return Err(Error::Invalid(licash::Error::Protocol(
                "a spend cited does not void its input".into(),
            )));
        }
        let ys = signed
            .proposal()
            .inputs()
            .iter()
            .map(|message| message.identifier())
            .collect::<Result<_, _>>()?;
        Ok(Self { ys, notes })
    }

    /// The identifiers of its inputs, in order.
    pub(crate) fn ys(&self) -> &[Point] {
        &self.ys
    }

    /// Its notes, in order.
    pub(crate) fn notes(&self) -> &'a [Note] {
        self.notes
    }
}

/// A spend the ledger retired notes for that a statement may not read:
/// its proposal, how many notes it retired, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Uncitable {
    pub proposal: String,
    pub notes: u64,
    pub why: String,
}

/// Each spend the hub's database at `db` retired notes for that a contract
/// of `max_authorizations` (its Base's limit) cannot cite: of more notes,
/// of a signed proposal or a note over a statement's blob limit, or with no
/// signed proposal kept at all. Read-only, without opening a hub, and of a
/// ledger of this release (schema 4) or one before (schema 1 to 3), whose
/// tables are the same: what an operator checks before closing the
/// contracts of an earlier release. Each claim on Bitcoin of one of these
/// spends' notes is unanswered and paid whole.
pub fn uncitable(db: &Path, max_authorizations: u64) -> Result<Vec<Uncitable>, Error> {
    let setup = |e: licash_store::Error| Error::Setup(e.to_string());
    let conn = licash_store::inspect(db, Kind::Hub)
        .map_err(setup)?
        .ok_or_else(|| Error::Setup(format!("no hub database at {}", db.display())))?;
    match licash_store::component_version(&conn, crate::store::COMPONENT).map_err(setup)? {
        Some(1..=4) => {}
        Some(v) => return Err(Error::Setup(format!("ledger schema {v}, not 1 to 4"))),
        None => return Err(Error::Setup("no ledger in the hub's database".into())),
    }
    let mut stmt = conn.prepare(
        "SELECT s.proposal, count(*), max(length(s.note)),
                coalesce(
                  (SELECT length(g.signed) FROM grants g
                   WHERE g.id = s.proposal AND g.released_at IS NOT NULL),
                  (SELECT length(l.signed) FROM locks l WHERE l.id = s.proposal))
         FROM spent s GROUP BY s.proposal ORDER BY s.proposal",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?,
            r.get::<_, Option<i64>>(3)?,
        ))
    })?;
    let blob = MAX_PUBLICATION_BYTES as i64;
    let mut found = Vec::new();
    for row in rows {
        let (proposal, notes, note, signed) = row?;
        let notes = notes as u64;
        let why = match signed {
            None => Some("no signed spend kept".to_owned()),
            Some(_) if notes > max_authorizations => Some(format!(
                "{notes} notes, more than the {max_authorizations} a statement reads"
            )),
            Some(signed) if signed > blob => Some(format!(
                "its signed spend is {signed} bytes, more than the {blob} a statement reads"
            )),
            Some(_) if note.is_some_and(|n| n > blob) => {
                Some(format!("a note over the {blob} bytes a statement reads"))
            }
            Some(_) => None,
        };
        if let Some(why) = why {
            found.push(Uncitable {
                proposal: hex::encode(proposal),
                notes,
                why,
            });
        }
    }
    Ok(found)
}
