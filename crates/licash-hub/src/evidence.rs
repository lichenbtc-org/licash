//! What the ledger holds against a holder's recovery claim.
//!
//! A claim names notes (its items' identifiers) and the sources of its
//! pending items (their inputs' identifiers, their timed terms). The hub
//! knows of each identifier it retired the proposal that spent it, signed
//! by the notes' owners, and of each timed source which branch it settled.
//! These are candidates only: [`licash::recovery::owed`] decides which void
//! anything. The hub cites against a timed source only the branch it did
//! not pay: a lock it refunded is not voided by its preimage, one it paid
//! not by its expiry.

use std::collections::BTreeSet;

use licash::{
    authorization::{Authorization, SignedProposal},
    claim::UnsignedClaim,
    crypto::{Point, Signature},
    inquiry,
    note::{Message, Note},
    recovery::{evidence_from_bytes, Evidence},
    spend::ProposalId,
};
use rusqlite::{Connection, OptionalExtension};

use crate::{Error, Hub};

/// What the ledger holds against a claim ([`Hub::found`]): its evidence, and
/// why each record of it that the ledger could not read back was left out.
/// One left out is evidence the hub had and cannot cite: her claim may then
/// be paid in full for a note it retired, and the operator must be told.
#[derive(Default)]
pub struct Found {
    pub evidence: Vec<Evidence>,
    pub unread: Vec<String>,
}

impl Hub {
    /// [`Hub::found`]'s evidence, the records left out told in warnings
    /// only: for a holder's view and tests, not for a dispute.
    pub fn evidence(&self, claim: &UnsignedClaim) -> Result<Vec<Evidence>, Error> {
        Ok(self.found(claim)?.evidence)
    }

    /// The evidence the ledger holds against `claim`: each owner-signed
    /// spend that retired one of its notes or one of its sources' inputs,
    /// a granted spend with its unlock (released, so its payee has it), and
    /// against each of its timed sources the branch the hub did not settle
    /// it on: the preimage of a lock paid, the expiry of one refunded, of
    /// one unsettled the preimage if the hub saw it, else its expiry, which
    /// the statement checks against the chain (a v3 contract's only: under
    /// v4 a Pay without an activation is owed nothing, and the statement
    /// refuses an expiry, so the dispute drops it). Ordered by proposal, then
    /// source. A spend the ledger can no longer read back (its keyset gone,
    /// its signed proposal not kept) is left out alone, and said in
    /// [`Found::unread`]. After the spends, each lock another claim gave one
    /// of its notes up by, never served ([`Hub::retire_claimed`]): an
    /// owner-signed spend as well. Then each other claim on Bitcoin of any
    /// of its notes. Any of these not read back is left out alone and said.
    pub fn found(&self, claim: &UnsignedClaim) -> Result<Found, Error> {
        let parts = claim.parts();
        let mut ys = Vec::new();
        for item in &parts.items {
            ys.push(item.message().identifier()?);
        }
        for source in &parts.sources {
            ys.extend(source.inputs().iter().copied());
        }
        self.store.read(|c| {
            let mut evidence = Vec::new();
            let mut unread = Vec::new();
            let served = spenders(c, &ys)?;
            for id in &served {
                let proposal = hex::encode(id.as_bytes());
                match self.spend(c, id) {
                    Ok(Some(spend)) => evidence.push(spend),
                    Ok(None) => {
                        tracing::warn!(%proposal, "a retired spend not kept, not cited against a claim");
                        unread.push(format!("the spend {proposal} that retired a note is not kept"));
                    }
                    Err(e) => {
                        tracing::warn!(%proposal, "a retired spend not cited against a claim: {e}");
                        unread.push(format!("the spend {proposal} does not read back: {e}"));
                    }
                }
            }
            evidence.extend(self.shown(c, &ys, &served, &mut unread)?);
            for source in &parts.sources {
                let Some(terms) = source.terms() else {
                    continue;
                };
                let id = source.id();
                let settled: Option<String> = c
                    .query_row(
                        "SELECT settled FROM locks WHERE id = ?1",
                        [id.as_bytes()],
                        |r| r.get(0),
                    )
                    .optional()?
                    .flatten();
                let seen = preimage(c, terms.hash())?;
                evidence.extend(against_timed(id, settled.as_deref(), seen));
            }
            let context = claim.hold_context();
            evidence.extend(crate::claims::second_claims(c, &ys, &context, &mut unread)?);
            Ok(Found { evidence, unread })
        })
    }

    /// What the ledger holds against each of the notes `asked`, in order,
    /// for the holder who signed the inquiry of each (`licash::inquiry`): the
    /// owner-signed spend that retired it, with its unlock if granted, and
    /// each claim of it on Bitcoin or for a cooperative close, as its hold
    /// key signed it. Evidence the asker made herself or has already, so it
    /// shows her nothing new, and only a signer of a note's hold key learns of
    /// the note: an inquiry that does not verify is refused whole. Nothing
    /// is written. None for a note the ledger holds nothing against, which
    /// is not shown to be unspent.
    pub fn inquire(
        &self,
        keyset: &[u8; 32],
        at: u64,
        asked: &[(Message, Signature)],
    ) -> Result<Vec<Vec<Evidence>>, Error> {
        if asked.len() > inquiry::MAX_NOTES {
            return Err(Error::Invalid(licash::Error::Protocol(
                "too many notes in an inquiry".into(),
            )));
        }
        self.keyset_of(keyset)?;
        let now = u64::try_from(crate::store::now()).unwrap_or(0);
        for (note, sig) in asked {
            inquiry::verify(keyset, at, note, sig, now)?;
        }
        self.store.read(|c| {
            asked
                .iter()
                .map(|(note, _)| {
                    let y = note.identifier()?;
                    let mut evidence = Vec::new();
                    let served = spenders(c, &[y])?;
                    for id in &served {
                        match self.spend(c, id) {
                            Ok(Some(spend)) => evidence.push(spend),
                            Ok(None) => {}
                            Err(e) => tracing::warn!(
                                proposal = %hex::encode(id.as_bytes()),
                                "a retired spend not shown to its holder: {e}"
                            ),
                        }
                    }
                    evidence.extend(self.shown(c, &[y], &served, &mut Vec::new())?);
                    evidence.extend(crate::claims::claims_of(c, &y)?);
                    Ok(evidence)
                })
                .collect()
        })
    }

    /// The locks claims gave any of `ys` up by ([`Hub::retire_claimed`]),
    /// each the owner-signed spend its claim showed, but those `served`.
    /// One the ledger can no longer read back (its keyset gone, its bytes
    /// not what it kept) is left out alone, as a spend is, and said in
    /// `unread`: the rest of the evidence stands.
    fn shown(
        &self,
        c: &Connection,
        ys: &[Point],
        served: &BTreeSet<ProposalId>,
        unread: &mut Vec<String>,
    ) -> Result<Vec<Evidence>, Error> {
        let mut evidence = Vec::new();
        for lock in crate::claims::shown(c, ys, unread)? {
            if served.contains(&lock.id) {
                continue;
            }
            let read = self.keyset_of(&lock.keyset).and_then(|keyset| {
                let read = evidence_from_bytes(keyset, u32::MAX as usize, &lock.evidence)?;
                match <[Evidence; 1]>::try_from(read) {
                    Ok([spend @ Evidence::Spend { unlock: None, .. }]) => Ok(spend),
                    _ => Err(Error::Invalid(licash::Error::Protocol(
                        "not one lock shown".into(),
                    ))),
                }
            });
            match read {
                Ok(spend) => evidence.push(spend),
                Err(e) => {
                    let proposal = hex::encode(lock.id.as_bytes());
                    tracing::warn!(%proposal, "a lock a claim showed not cited: {e}");
                    unread.push(format!(
                        "the lock {proposal} a claim showed does not read back: {e}"
                    ));
                }
            }
        }
        Ok(evidence)
    }

    /// The spend `id` as its owners signed it, with the notes it retired in
    /// order and, granted, its unlock: none if it is neither a lock nor a
    /// released grant.
    fn spend(&self, c: &Connection, id: &ProposalId) -> Result<Option<Evidence>, Error> {
        let signed: Option<Vec<u8>> = c
            .query_row(
                "SELECT signed FROM locks WHERE id = ?1
                 UNION ALL
                 SELECT signed FROM grants WHERE id = ?1 AND released_at IS NOT NULL",
                [id.as_bytes()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(signed) = signed else {
            return Ok(None);
        };
        let keyset_id: [u8; 32] = c.query_row(
            "SELECT keyset FROM proposals WHERE id = ?1",
            [id.as_bytes()],
            |r| r.get(0),
        )?;
        let keyset = self.keyset_of(&keyset_id)?;
        let mut stmt =
            c.prepare_cached("SELECT note FROM spent WHERE proposal = ?1 ORDER BY position")?;
        let notes = stmt
            .query_map([id.as_bytes()], |r| r.get::<_, Vec<u8>>(0))?
            .map(|bytes| Ok(Note::from_bytes(keyset, &bytes?)?))
            .collect::<Result<Vec<_>, Error>>()?;
        let signed = SignedProposal::from_bytes(keyset, &notes, &signed)?;
        let unlock = match signed.authorization() {
            Authorization::Plain => None,
            // As kept at its release, by a ledger that has every one or
            // is opened by no hub: read by a copy without the seed too.
            Authorization::Granted(_) => Some(c.query_row(
                "SELECT unlock FROM released_unlocks WHERE id = ?1",
                [id.as_bytes()],
                |r| r.get(0),
            )?),
        };
        Ok(Some(Evidence::Spend {
            signed,
            notes,
            unlock,
        }))
    }
}

/// Against the timed source `id`, settled on `settled` (`pay`, `refund`,
/// none) with `seen` the preimage of its hash the hub saw, if any: the
/// branch the hub did not pay. A lock refunded may share its hash with
/// one activated, or be activated after its expiry: its preimage is never
/// cited. One paid without a preimage known has nothing against it.
fn against_timed(
    id: ProposalId,
    settled: Option<&str>,
    seen: Option<[u8; 32]>,
) -> Option<Evidence> {
    match (settled, seen) {
        (Some("refund"), _) | (None, None) => Some(Evidence::Expired { source: id }),
        (_, Some(preimage)) => Some(Evidence::PayPreimage {
            source: id,
            preimage,
        }),
        (_, None) => None,
    }
}

/// The proposals that retired any of `ys`, each once, by id.
fn spenders(c: &Connection, ys: &[Point]) -> Result<BTreeSet<ProposalId>, Error> {
    let mut stmt = c.prepare_cached("SELECT proposal FROM spent WHERE y = ?1")?;
    let mut ids = BTreeSet::new();
    for y in ys {
        if let Some(id) = stmt
            .query_row([&y.0], |r| r.get::<_, [u8; 32]>(0))
            .optional()?
        {
            ids.insert(ProposalId::from_bytes(id));
        }
    }
    Ok(ids)
}

/// A preimage of `hash` the hub saw: an activation it scanned, or one a
/// lock or a forward was settled with.
fn preimage(c: &Connection, hash: &[u8; 32]) -> Result<Option<[u8; 32]>, Error> {
    Ok(c.query_row(
        "SELECT secret FROM activations WHERE hash = ?1
         UNION ALL SELECT preimage FROM locks WHERE hash = ?1 AND preimage IS NOT NULL
         UNION ALL SELECT preimage FROM forwards WHERE hash = ?1 AND preimage IS NOT NULL
         LIMIT 1",
        [hash],
        |r| r.get(0),
    )
    .optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cited(settled: Option<&str>, seen: Option<[u8; 32]>) -> &'static str {
        match against_timed(ProposalId::from_bytes([1; 32]), settled, seen) {
            Some(Evidence::PayPreimage { preimage, .. }) => {
                assert_eq!(Some(preimage), seen);
                "preimage"
            }
            Some(Evidence::Expired { .. }) => "expired",
            Some(_) => "other",
            None => "nothing",
        }
    }

    #[test]
    fn a_timed_source_is_met_on_the_branch_the_hub_did_not_pay() {
        let z = Some([2; 32]);
        // Paid: its preimage voids the refund she claims.
        assert_eq!(cited(Some("pay"), z), "preimage");
        assert_eq!(cited(Some("pay"), None), "nothing");
        // Refunded: its expiry voids the pay she claims, whatever
        // activation of its hash the hub saw.
        assert_eq!(cited(Some("refund"), z), "expired");
        assert_eq!(cited(Some("refund"), None), "expired");
        // Unsettled: the preimage if seen, else its expiry, which the
        // statement checks on the chain.
        assert_eq!(cited(None, z), "preimage");
        assert_eq!(cited(None, None), "expired");
    }
}
