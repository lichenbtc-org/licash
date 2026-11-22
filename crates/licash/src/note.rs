//! Notes: the issuer's keyset, blind issuance, note identity, one-time owner
//! keys and independent hold authority.

use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    ProjectivePoint, Scalar, Secp256k1,
};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    codec::Reader,
    crypto::{
        dleq_verify_blinded, dleq_verify_unblinded, generator_mul, scalar_from_hash,
        seal_verify_opened, tagged_hash, Dleq, DleqCommit, Point, ScalarBytes, Seal,
    },
    ec::Pt,
    Error,
};

const TAG: &[u8] = b"licash/note/v3";
const NOTE_TAG: &[u8] = b"LICASH-NT\x05";
const DST: &[u8] = b"LICASH-V2-secp256k1_XMD:SHA-256_SSWU_RO_";
const KEYSET_TAG: &[u8] = b"LICASH-KS\x05";
const ISSUED_TAG: &[u8] = b"LICASH-IS\x05";
const MAX_KEYS: usize = 64;
pub const PUBLIC_FIELDS_BYTES: usize = 8 + 32 + 32;
pub const MESSAGE_BYTES: usize = TAG.len() + PUBLIC_FIELDS_BYTES;

fn bad(reason: &str) -> Error {
    Error::Protocol(reason.into())
}

pub(crate) fn non_identity(point: &Point) -> Result<ProjectivePoint, Error> {
    let decoded = point.to_projective()?;
    if decoded == ProjectivePoint::IDENTITY {
        return Err(Error::InvalidPoint);
    }
    Ok(decoded)
}

/// The note format, which every keyset id commits to. v3 is v2 with an
/// issuance proof whose challenge hashes its base
/// ([`crate::crypto::dleq_prove`]). v4 is v3 with grants anyone verifies
/// ([`crate::authorization::Grant`]): a note opened from one carries its
/// packet's proof ([`Evidence::Granted`]), and its owners sign the grant's
/// head. v5 is v4 with a message of the denomination, owner key and hold
/// key alone: the owner key is one-time, so a nonce made nothing unique
/// that it did not. A note, keyset or Base of an earlier format is refused
/// by its framing and id, never verified under the other rule.
fn format_commitment() -> [u8; 32] {
    tagged_hash("licash/note-format/v5", &[TAG, DST])
}

/// Separately typed public issuer metadata. Its ID commits the exact note
/// format/map as well as the denomination and credential keys.
/// The issuer Schnorr key is also monetary admission authority for certified
/// pending claims; it is not a low-trust metadata-signing key.
/// Native denominations count satoshis, not per-contract exchange-rate units.
#[derive(Clone, PartialEq, Eq)]
pub struct Keyset {
    id: [u8; 32],
    keys: BTreeMap<u64, Point>,
    issuer: [u8; 32],
}

impl std::fmt::Debug for Keyset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keyset(..)")
    }
}

impl Keyset {
    fn from_parts(keys: BTreeMap<u64, Point>, issuer: [u8; 32]) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > MAX_KEYS {
            return Err(bad("denomination-key count"));
        }
        k256::schnorr::VerifyingKey::from_bytes(&issuer).map_err(|_| Error::InvalidPoint)?;
        let mut distinct = BTreeSet::from([issuer]);
        let mut records = Vec::with_capacity(keys.len() * 41);
        for (denom, key) in &keys {
            if *denom == 0 {
                return Err(bad("zero note denomination"));
            }
            non_identity(key)?;
            if !distinct.insert(key.x_only()) {
                return Err(bad("reused signing key"));
            }
            records.extend(denom.to_be_bytes());
            records.extend(key.0);
        }
        let id = tagged_hash(
            "licash/keyset/v2",
            &[
                &format_commitment(),
                &issuer,
                &(keys.len() as u32).to_be_bytes(),
                &records,
            ],
        );
        Ok(Self { id, keys, issuer })
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }
    /// Admission authority on the certified branch, not denomination issuance
    /// proof. Compromise can create capped pending liabilities on its own.
    pub fn issuer(&self) -> &[u8; 32] {
        &self.issuer
    }
    pub fn key(&self, denom: u64) -> Result<Point, Error> {
        self.keys
            .get(&denom)
            .copied()
            .ok_or(Error::UnknownDenomination(denom))
    }
    /// The denominations it issues, smallest first.
    pub fn denominations(&self) -> impl DoubleEndedIterator<Item = u64> + '_ {
        self.keys.keys().copied()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = KEYSET_TAG.to_vec();
        bytes.extend(self.id);
        bytes.extend(self.issuer);
        bytes.extend((self.keys.len() as u32).to_be_bytes());
        for (denom, key) in &self.keys {
            bytes.extend(denom.to_be_bytes());
            bytes.extend(key.0);
        }
        bytes
    }

    /// Strict, bounded metadata parsing. No old keyset or missing ID is
    /// interpreted as this format. Secret-key import is deliberately absent.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let header = KEYSET_TAG.len() + 32 + 32 + 4;
        if bytes.len() < header || &bytes[..KEYSET_TAG.len()] != KEYSET_TAG {
            return Err(bad("keyset framing"));
        }
        let at = KEYSET_TAG.len();
        let claimed_id: [u8; 32] = bytes[at..at + 32]
            .try_into()
            .expect("checked header length");
        let issuer = bytes[at + 32..at + 64]
            .try_into()
            .expect("checked header length");
        let count = u32::from_be_bytes(
            bytes[at + 64..header]
                .try_into()
                .expect("checked header length"),
        ) as usize;
        if count == 0 || count > MAX_KEYS || bytes.len() != header + count * 41 {
            return Err(bad("keyset length"));
        }
        let mut keys = BTreeMap::new();
        let mut previous = 0;
        for record in bytes[header..].as_chunks::<41>().0 {
            let denom = u64::from_be_bytes(record[..8].try_into().expect("fixed record"));
            if denom <= previous {
                return Err(bad("noncanonical denomination order"));
            }
            previous = denom;
            keys.insert(denom, Point(record[8..].try_into().expect("fixed record")));
        }
        let keyset = Self::from_parts(keys, issuer)?;
        if keyset.id != claimed_id {
            return Err(bad("keyset ID mismatch"));
        }
        Ok(keyset)
    }
}

/// Issuer keys. This is not Hub state, an admission service or a
/// durable issuance API. The Schnorr admission secret needs the same custody as denomination secrets:
/// a certificate can acknowledge pending debt without producing an actual coin.
#[derive(Clone)]
pub struct IssuerKeys {
    notes: BTreeMap<u64, Scalar>,
    issuer: Scalar,
    id: [u8; 32],
}

impl std::fmt::Debug for IssuerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuerKeys(..)")
    }
}

impl IssuerKeys {
    pub(crate) fn denomination_secret(&self, denom: u64) -> Result<&Scalar, Error> {
        self.notes
            .get(&denom)
            .ok_or(Error::UnknownDenomination(denom))
    }

    pub(crate) fn issuer_secret(&self) -> &Scalar {
        &self.issuer
    }

    /// The id of [`Self::keyset`], without deriving the public keys.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn random(max_pow: u32) -> Result<Self, Error> {
        if max_pow >= 64 {
            return Err(bad("denomination exponent exceeds u64"));
        }
        let notes = (0..=max_pow)
            .map(|power| (1u64 << power, crate::crypto::random_scalar()))
            .collect();
        Self::from_secrets(notes, crate::crypto::random_scalar())
    }

    /// The keys of keyset `index` of an issuer seed, denominations 1 to
    /// `2^max_pow`. Each `(index, max_pow)` gives independent keys.
    pub fn from_seed(seed: &[u8; 32], index: u32, max_pow: u32) -> Result<Self, Error> {
        if max_pow >= 64 {
            return Err(bad("denomination exponent exceeds u64"));
        }
        let path = [index.to_be_bytes(), max_pow.to_be_bytes()].concat();
        let notes = (0..=max_pow)
            .map(|power| {
                let denom = 1u64 << power;
                let hash = tagged_hash(
                    "licash/issuer/denomination/v2",
                    &[seed, &path, &denom.to_be_bytes()],
                );
                (denom, scalar_from_hash(&hash))
            })
            .collect();
        let issuer = tagged_hash("licash/issuer/admission/v2", &[seed, &path]);
        Self::from_secrets(notes, scalar_from_hash(&issuer))
    }

    fn from_secrets(notes: BTreeMap<u64, Scalar>, issuer: Scalar) -> Result<Self, Error> {
        if issuer == Scalar::ZERO || notes.values().any(|k| *k == Scalar::ZERO) {
            return Err(Error::InvalidScalar);
        }
        let public = notes
            .iter()
            .map(|(denom, k)| (*denom, Point::from_projective(&generator_mul(k))))
            .collect();
        let keyset = Keyset::from_parts(public, crate::crypto::x_only_pub(&issuer))?;
        Ok(Self {
            notes,
            issuer,
            id: *keyset.id(),
        })
    }

    pub fn keyset(&self) -> Result<Keyset, Error> {
        let keys = self
            .notes
            .iter()
            .map(|(denom, scalar)| (*denom, Point::from_projective(&generator_mul(scalar))))
            .collect();
        Keyset::from_parts(keys, crate::crypto::x_only_pub(&self.issuer))
    }

    /// Stateless curve/DLEQ primitive only. It does not record issuance,
    /// promise unlinking, create accepted notes or replace durable Hub policy.
    pub fn prove_blinded(&self, denom: u64, blinded: Point) -> Result<BlindProof, Error> {
        let key = self
            .notes
            .get(&denom)
            .ok_or(Error::UnknownDenomination(denom))?;
        let point = non_identity(&blinded)?;
        let signature = crate::crypto::blind_sign(key, &point);
        Ok(BlindProof {
            keyset: self.id,
            denom,
            blinded,
            signature: Point::from_projective(&signature),
            proof: crate::crypto::dleq_prove(key, &point, &signature),
        })
    }
}

/// Proof of a blinded multiplication under an exact typed keyset/amount.
/// This is not a receipt, grant, unlink round or issued-note type.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindProof {
    keyset: [u8; 32],
    denom: u64,
    blinded: Point,
    signature: Point,
    proof: crate::crypto::Dleq,
}

impl std::fmt::Debug for BlindProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindProof(..)")
    }
}

impl BlindProof {
    /// Public proof data, not secret issuer or unlink authority.
    pub fn dleq(&self) -> crate::crypto::Dleq {
        self.proof
    }

    pub fn signature(&self) -> Point {
        self.signature
    }

    /// Verify the exact request and unblind its curve point. No issued-note
    /// or recovery entitlement is created by this primitive alone.
    pub fn open_point(&self, keyset: &Keyset, output: &Derivation) -> Result<Point, Error> {
        let denom = output.message().denomination();
        self.verify(keyset, denom, &output.blinded()?)?;
        let point = crate::crypto::unblind(
            &self.signature.to_projective()?,
            &output.blinding.to_scalar()?,
            &keyset.key(denom)?.to_projective()?,
        );
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::InvalidPoint);
        }
        Ok(Point::from_projective(&point))
    }

    pub fn verify(&self, keyset: &Keyset, denom: u64, blinded: &Point) -> Result<(), Error> {
        if &self.keyset != keyset.id() || self.denom != denom || &self.blinded != blinded {
            return Err(bad("issuance context mismatch"));
        }
        crate::crypto::dleq_verify_blinded(
            &self.proof,
            &crate::ec::Pt::from_point(&keyset.key(denom)?)?,
            &crate::ec::Pt::from_point(blinded)?,
            &crate::ec::Pt::from_point(&self.signature)?,
        )
    }
}

/// An issuer-authenticated note, not a balance or recovery
/// allocation. Ownership, unspent state and protection are separate checks.
#[derive(Clone, PartialEq, Eq)]
pub struct Note {
    keyset: [u8; 32],
    message: Message,
    signature: Point,
    evidence: Evidence,
}

impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Note(..)")
    }
}

impl Note {
    /// Validate externally supplied public note data under the exact named
    /// keyset.
    pub fn from_parts(
        keyset: &Keyset,
        claimed_keyset: [u8; 32],
        message: Message,
        signature: Point,
        evidence: Evidence,
    ) -> Result<Self, Error> {
        let note = Self {
            keyset: claimed_keyset,
            message,
            signature,
            evidence,
        };
        note.verify(keyset)?;
        Ok(note)
    }

    pub fn keyset_id(&self) -> &[u8; 32] {
        &self.keyset
    }
    pub fn message(&self) -> &Message {
        &self.message
    }
    pub fn signature(&self) -> Point {
        self.signature
    }
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn verify(&self, keyset: &Keyset) -> Result<(), Error> {
        if &self.keyset != keyset.id() {
            return Err(bad("note keyset mismatch"));
        }
        non_identity(&self.signature)?;
        self.evidence.verify(
            &crate::ec::Pt::from_point(&keyset.key(self.message.denom)?)?,
            &crate::ec::Pt::from_point(&self.message.identifier()?)?,
            &crate::ec::Pt::from_point(&self.signature)?,
        )
    }

    /// `LICASH-NT\x04 ‖ keyset ‖ public fields ‖ C ‖ evidence`, the evidence
    /// a tag (0 Unlinked, 1 Linked, 2 Granted) and its fields in order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = NOTE_TAG.to_vec();
        bytes.extend(self.keyset);
        bytes.extend(self.message.public_fields());
        bytes.extend(self.compact_tail());
        bytes
    }

    /// `C ‖ evidence`: what a note's bytes say beyond what its holder
    /// already has, its keyset and its message, as a filing's witness of a
    /// settled item ([`Note::from_compact_bytes`]).
    pub fn to_compact_bytes(&self) -> Vec<u8> {
        self.compact_tail()
    }

    fn compact_tail(&self) -> Vec<u8> {
        let mut bytes = self.signature.0.to_vec();
        let put_dleq = |bytes: &mut Vec<u8>, d: &Dleq| {
            bytes.extend(d.e.0);
            bytes.extend(d.s.0);
        };
        match &self.evidence {
            Evidence::Unlinked(dleq) => {
                bytes.push(0);
                put_dleq(&mut bytes, dleq);
            }
            Evidence::Linked {
                dleq,
                blinding,
                commit,
            } => {
                bytes.push(1);
                put_dleq(&mut bytes, dleq);
                bytes.extend(blinding.0);
                bytes.extend(commit.r1.0);
                bytes.extend(commit.r2.0);
            }
            Evidence::Granted {
                seal,
                blinding,
                commit,
                unlock,
                mask,
            } => {
                bytes.push(2);
                bytes.extend(seal.to_bytes());
                bytes.extend(blinding.0);
                bytes.extend(commit.r1.0);
                bytes.extend(commit.r2.0);
                bytes.extend(unlock.0);
                bytes.extend(mask.0);
            }
        }
        bytes
    }

    /// Decode `to_bytes` and verify the note under `keyset`, the issuer
    /// keyset the caller expects (never one the bytes merely name).
    pub fn from_bytes(keyset: &Keyset, bytes: &[u8]) -> Result<Self, Error> {
        let note = Self::decode(bytes)?;
        note.verify(keyset)?;
        Ok(note)
    }

    /// Decode `to_bytes` and verify nothing: for a decoder that verifies
    /// the note right after, with the spend it is an input of
    /// ([`crate::authorization::SignedProposal::from_bytes`]), rather than
    /// twice.
    pub(crate) fn from_bytes_unverified(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }

    /// What `to_bytes` say of a note, decoded but not verified: for a
    /// ledger reading back the notes it verified before keeping them. It
    /// proves nothing about the note.
    pub fn peek(bytes: &[u8]) -> Result<Peek, Error> {
        let note = Self::decode(bytes)?;
        Ok(Peek {
            keyset: note.keyset,
            unlinked: matches!(note.evidence, Evidence::Unlinked(_)),
            message: note.message,
        })
    }

    /// Decode `to_compact_bytes` as the note of `message` under `keyset`,
    /// and verify it. Its keyset and message are the caller's, so no
    /// bytes can name another.
    pub fn from_compact_bytes(
        keyset: &Keyset,
        message: Message,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let r = Reader::new(bytes, "note", &[])?;
        let note = Self::decode_tail(r, *keyset.id(), message)?;
        note.verify(keyset)?;
        Ok(note)
    }

    /// [`Note::from_compact_bytes`], the note not verified: only for the
    /// statement's decoding of a filing whose uncited notes it takes as
    /// they are, and verifies those the Hub cites as invalid
    /// ([`Note::verify`]). Never a note to rely on.
    pub(crate) fn from_compact_unverified(
        keyset: &Keyset,
        message: Message,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        let r = Reader::new(bytes, "note", &[])?;
        Self::decode_tail(r, *keyset.id(), message)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, "note", NOTE_TAG)?;
        let claimed = r.array()?;
        let message = Message::from_public_fields(r.take(PUBLIC_FIELDS_BYTES)?)?;
        Self::decode_tail(r, claimed, message)
    }

    fn decode_tail(mut r: Reader, claimed: [u8; 32], message: Message) -> Result<Self, Error> {
        let signature = Point(r.array()?);
        let dleq = |r: &mut Reader| -> Result<Dleq, Error> {
            Ok(Dleq {
                e: ScalarBytes(r.array()?),
                s: ScalarBytes(r.array()?),
            })
        };
        let evidence = match r.byte()? {
            0 => Evidence::Unlinked(dleq(&mut r)?),
            1 => Evidence::Linked {
                dleq: dleq(&mut r)?,
                blinding: ScalarBytes(r.array()?),
                commit: DleqCommit {
                    r1: Point(r.array()?),
                    r2: Point(r.array()?),
                },
            },
            2 => Evidence::Granted {
                seal: Seal::from_bytes(&r.array()?),
                blinding: ScalarBytes(r.array()?),
                commit: DleqCommit {
                    r1: Point(r.array()?),
                    r2: Point(r.array()?),
                },
                unlock: ScalarBytes(r.array()?),
                mask: Point(r.array()?),
            },
            _ => return Err(bad("unknown note evidence")),
        };
        r.finish()?;
        Ok(Self {
            keyset: claimed,
            message,
            signature,
            evidence,
        })
    }
}

/// A note's keyset, message and kind of evidence as its bytes claim them,
/// unverified ([`Note::peek`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peek {
    pub keyset: [u8; 32],
    pub message: Message,
    /// Whether its evidence is of an unlinked issuance.
    pub unlinked: bool,
}

/// A linked issuance of one output: the issuer's blind signature with its
/// DLEQ proof, and the commitment of the unlink nonce drawn for the output
/// ([`crate::unlink::Nonce::issue`]). The output's holder opens it into a
/// note.
#[derive(Clone, PartialEq, Eq)]
pub struct MintResponse {
    proof: BlindProof,
    commit: crate::crypto::DleqCommit,
}

impl std::fmt::Debug for MintResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MintResponse(..)")
    }
}

impl MintResponse {
    pub(crate) fn new(proof: BlindProof, commit: crate::crypto::DleqCommit) -> Self {
        Self { proof, commit }
    }

    pub fn proof(&self) -> &BlindProof {
        &self.proof
    }

    /// `LICASH-IS\x04 ‖ keyset ‖ denomination ‖ B ‖ C' ‖ DLEQ ‖ R1 ‖ R2`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = &self.proof;
        let mut bytes = ISSUED_TAG.to_vec();
        bytes.extend(p.keyset);
        bytes.extend(p.denom.to_be_bytes());
        bytes.extend(p.blinded.0);
        bytes.extend(p.signature.0);
        bytes.extend(p.proof.e.0);
        bytes.extend(p.proof.s.0);
        bytes.extend(self.commit.r1.0);
        bytes.extend(self.commit.r2.0);
        bytes
    }

    /// Decode `to_bytes` and verify the proof under `keyset`, the issuer
    /// keyset the caller expects. The nonce commitment is checked only for
    /// its points' encodings: unlinking checks the rest.
    pub fn from_bytes(keyset: &Keyset, bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, "issuance", ISSUED_TAG)?;
        let proof = BlindProof {
            keyset: r.array()?,
            denom: r.u64()?,
            blinded: Point(r.array()?),
            signature: Point(r.array()?),
            proof: Dleq {
                e: ScalarBytes(r.array()?),
                s: ScalarBytes(r.array()?),
            },
        };
        let commit = crate::crypto::DleqCommit {
            r1: Point(r.array()?),
            r2: Point(r.array()?),
        };
        r.finish()?;
        proof.verify(keyset, proof.denom, &proof.blinded)?;
        non_identity(&commit.r1)?;
        non_identity(&commit.r2)?;
        Ok(Self { proof, commit })
    }

    pub fn open(&self, keyset: &Keyset, output: &Derivation) -> Result<Note, Error> {
        let signature = self.proof.open_point(keyset, output)?;
        // open_point has checked the exact derived target and its DLEQ; the
        // unblinded Linked evidence represents that same verified equation.
        Ok(Note {
            keyset: self.proof.keyset,
            message: output.message.clone(),
            signature,
            evidence: Evidence::Linked {
                dleq: self.proof.proof,
                blinding: output.blinding,
                commit: self.commit,
            },
        })
    }
}

#[derive(Clone)]
struct IssuanceRecord {
    proof: BlindProof,
    unlink_nonce: Scalar,
}

impl IssuanceRecord {
    fn response(&self) -> MintResponse {
        let target = self
            .proof
            .blinded
            .to_projective()
            .expect("validated issuance target");
        MintResponse {
            proof: self.proof.clone(),
            commit: crate::crypto::dleq_commit(&self.unlink_nonce, &target),
        }
    }
}

/// Mint-only in-memory statement-layer ledger. This is neither persistent
/// authority nor a payment service. No holds, spends, claims or unlink answer
/// exist here. Cloning preserves records, not cross-process exclusivity.
#[derive(Clone)]
pub struct MintLedger {
    keys: IssuerKeys,
    keyset: Keyset,
    records: BTreeMap<Point, IssuanceRecord>,
}

impl std::fmt::Debug for MintLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MintLedger(..)")
    }
}

impl MintLedger {
    /// Explicit fresh keys and state, never a reset/import of old authority.
    pub fn fresh(max_pow: u32) -> Result<Self, Error> {
        let keys = IssuerKeys::random(max_pow)?;
        let keyset = keys.keyset()?;
        Ok(Self {
            keys,
            keyset,
            records: BTreeMap::new(),
        })
    }

    pub fn keyset(&self) -> &Keyset {
        &self.keyset
    }
    pub fn issued_count(&self) -> usize {
        self.records.len()
    }

    pub fn mint(&mut self, denom: u64, blinded: Point) -> Result<MintResponse, Error> {
        if let Some(record) = self.records.get(&blinded) {
            if record.proof.denom != denom {
                return Err(bad("blinded point already has different mint terms"));
            }
            return Ok(record.response());
        }
        let proof = self.keys.prove_blinded(denom, blinded)?;
        let record = IssuanceRecord {
            proof,
            unlink_nonce: crate::crypto::random_scalar(),
        };
        // Record before producing the public commitment/answer. This is an
        // in-memory ordering invariant, not a durable commit or restart claim.
        self.records.insert(blinded, record);
        Ok(self
            .records
            .get(&blinded)
            .expect("just recorded issuance")
            .response())
    }
}

/// Public canonical message. Q is part of Y, not a detachable certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    denom: u64,
    owner: [u8; 32],
    hold: [u8; 32],
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoteMessage(..)")
    }
}

impl Message {
    pub fn new(denom: u64, owner: [u8; 32], hold: [u8; 32]) -> Result<Self, Error> {
        if denom == 0 {
            return Err(bad("zero note denomination"));
        }
        k256::schnorr::VerifyingKey::from_bytes(&owner).map_err(|_| Error::InvalidPoint)?;
        k256::schnorr::VerifyingKey::from_bytes(&hold).map_err(|_| Error::InvalidPoint)?;
        Ok(Self { denom, owner, hold })
    }

    pub fn denomination(&self) -> u64 {
        self.denom
    }
    pub fn owner(&self) -> &[u8; 32] {
        &self.owner
    }
    pub fn hold(&self) -> &[u8; 32] {
        &self.hold
    }

    pub fn to_bytes(&self) -> [u8; MESSAGE_BYTES] {
        let mut bytes = [0; MESSAGE_BYTES];
        bytes[..TAG.len()].copy_from_slice(TAG);
        bytes[TAG.len()..].copy_from_slice(&self.public_fields());
        bytes
    }

    /// Compact public fields for an enclosing, explicitly versioned v2
    /// carrier. Untagged fields alone are not a note or an issuer proof.
    pub fn public_fields(&self) -> [u8; PUBLIC_FIELDS_BYTES] {
        let mut bytes = [0; PUBLIC_FIELDS_BYTES];
        bytes[..8].copy_from_slice(&self.denom.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.owner);
        bytes[40..].copy_from_slice(&self.hold);
        bytes
    }

    pub fn from_public_fields(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_FIELDS_BYTES {
            return Err(bad("public note field length"));
        }
        Self::new(
            u64::from_be_bytes(bytes[..8].try_into().expect("checked field length")),
            bytes[8..40].try_into().expect("checked field length"),
            bytes[40..].try_into().expect("checked field length"),
        )
    }

    /// Exact framing, with no other tag, trailing data or default Q.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != MESSAGE_BYTES || &bytes[..TAG.len()] != TAG {
            return Err(bad("noncanonical note message"));
        }
        Self::from_public_fields(&bytes[TAG.len()..])
    }

    /// Standard fixed-work SSWU mapping under licash's own domain.
    ///
    /// Y is a pure function of the message, and hashing to the curve is the
    /// dominant cost of every predicate that names a note: a claim of 32
    /// notes names each of them several times (as an item, under its hold
    /// authorization, in the holder's evidence and in every spend the Hub
    /// cites). The results are therefore remembered per thread, in a bounded
    /// table that is emptied when full.
    pub fn identifier(&self) -> Result<Point, Error> {
        const REMEMBERED: usize = 1024;
        thread_local! {
            static IDENTIFIERS: std::cell::RefCell<BTreeMap<[u8; MESSAGE_BYTES], Point>> =
                const { std::cell::RefCell::new(BTreeMap::new()) };
        }
        let bytes = self.to_bytes();
        if let Some(point) = IDENTIFIERS.with_borrow(|known| known.get(&bytes).copied()) {
            return Ok(point);
        }
        let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[&bytes], &[DST])
            .map_err(|_| bad("note hash-to-curve"))?;
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::InvalidPoint);
        }
        let point = Point::from_projective(&point);
        IDENTIFIERS.with_borrow_mut(|known| {
            if known.len() >= REMEMBERED {
                known.clear();
            }
            known.insert(bytes, point);
        });
        Ok(point)
    }
}

/// `to_bytes`, hex in JSON.
impl serde::Serialize for Message {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        crate::crypto::serialize_fixed(&self.to_bytes(), s)
    }
}

impl<'de> serde::Deserialize<'de> for Message {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = crate::crypto::deserialize_fixed::<D, MESSAGE_BYTES>(d, "note message")?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Long-lived hold authority, not a spending key. Exporting it delegates
/// holds on future receipts too; it cannot be revoked.
#[derive(Clone)]
pub struct HoldRoot(Scalar);

impl std::fmt::Debug for HoldRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HoldRoot(..)")
    }
}

impl HoldRoot {
    /// The hold root derived from a wallet seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
        Self::from_scalar(scalar_from_hash(&tagged_hash(
            "licash/root/hold/v2",
            &[seed],
        )))
    }

    /// Import independent hold authority, never a spending scalar.
    pub fn from_scalar(scalar: Scalar) -> Result<Self, Error> {
        if scalar == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        Ok(Self(scalar))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Self::from_scalar(ScalarBytes(bytes).to_scalar()?)
    }

    /// Sensitive delegation material, not part of a public note message.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    pub fn public(&self) -> Point {
        Point::from_projective(&generator_mul(&self.0))
    }
}

fn hold_tweak(hold: &Point, spend: &Point, seed: &[u8; 32]) -> Scalar {
    scalar_from_hash(&tagged_hash(
        "licash/hold-tweak/v2",
        &[&hold.0, &spend.0, seed],
    ))
}

/// Private recovery-root witness, not a spending key or issuance credential.
/// The seed is also unlink delegation material: keep it inside the holder
/// witness. No raw export, persisted encoding or unlink-answer API is supplied.
#[derive(Clone)]
pub struct Ownership {
    seed: [u8; 32],
}

impl std::fmt::Debug for Ownership {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ownership(..)")
    }
}

impl Ownership {
    /// Import explicitly retained private witness data. Missing seeds do not
    /// acquire a default, and a supplied scalar tweak is never accepted.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Recompute H("licash/tweak", compressed root, seed), then root+tG.
    /// This checks only the owner field. Issuance, monetary denomination,
    /// Q authorization and eligibility remain separate predicate obligations.
    pub fn verify(&self, root: &Point, message: &Message) -> Result<(), Error> {
        non_identity(root)?;
        if !owner_bound(
            root,
            &crate::ec::Pt::from_point(root)?,
            &self.seed,
            message.owner(),
        )? {
            return Err(bad("note owner is not bound to recovery root"));
        }
        Ok(())
    }

    /// The signing secret of the one-time owner key under the spend root
    /// whose secret is `spend`: `spend + H("licash/tweak", spend G, seed)`.
    pub fn owner_secret(&self, spend: &Scalar) -> Result<Scalar, Error> {
        if *spend == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        let root = Point::from_projective(&generator_mul(spend));
        Ok(*spend + bound_tweak(&root, &self.seed).to_scalar()?)
    }

    /// Public source-output linkage, not an unlink answer or release authority.
    pub fn unlink_commitment(&self) -> [u8; 32] {
        unlink_commitment(&self.seed)
    }
}

/// Private output derivation. Sender and scan agent use public spend/hold
/// roots and the receipt shared secret; neither needs a spending scalar.
#[derive(Clone)]
pub struct Derivation {
    message: Message,
    spend_root: Point,
    hold_root: Point,
    seed: [u8; 32],
    blinding: ScalarBytes,
}

impl std::fmt::Debug for Derivation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoteDerivation(..)")
    }
}

impl Derivation {
    pub fn derive(
        denom: u64,
        spend_root: Point,
        hold_root: Point,
        shared: &[u8; 32],
        index: u32,
    ) -> Result<Self, Error> {
        let hold = non_identity(&hold_root)?;
        non_identity(&spend_root)?;
        let derived = derive_output(&spend_root, shared, index)?;
        let point = hold + generator_mul(&hold_tweak(&hold_root, &spend_root, &derived.seed));
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::InvalidPoint);
        }
        if derived.blinding.to_scalar()? == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        let message = Message::new(
            denom,
            derived.owner_point.x_only(),
            Point::from_projective(&point).x_only(),
        )?;
        Ok(Self {
            message,
            spend_root,
            hold_root,
            seed: derived.seed,
            blinding: derived.blinding,
        })
    }

    /// Receiving code must compare the actual public message to this expected
    /// derivation, including Q, before accepting addressed output data.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// Private opening data for blinding/unblinding, never public hold data.
    pub fn blinding(&self) -> &ScalarBytes {
        &self.blinding
    }

    pub fn ownership(&self) -> Ownership {
        Ownership::from_seed(self.seed)
    }

    /// Public commitment to this output's private unlink authority. This
    /// does not expose the capability or authorize an unlink answer.
    pub fn unlink_commitment(&self) -> [u8; 32] {
        unlink_commitment(&self.seed)
    }

    /// The private authority the commitment commits to, revealed to the
    /// issuer only in an unlink request.
    pub(crate) fn unlink_capability(&self) -> [u8; 32] {
        unlink_capability(&self.seed)
    }

    pub fn blinded(&self) -> Result<Point, Error> {
        let point = self.message.identifier()?.to_projective()?
            + generator_mul(&self.blinding.to_scalar()?);
        if point == ProjectivePoint::IDENTITY {
            return Err(Error::InvalidPoint);
        }
        Ok(Point::from_projective(&point))
    }

    pub fn hold_key(&self, root: &HoldRoot) -> Result<ScalarBytes, Error> {
        if root.public() != self.hold_root {
            return Err(bad("hold root does not match receiving address"));
        }
        let key = root.0 + hold_tweak(&self.hold_root, &self.spend_root, &self.seed);
        if key == Scalar::ZERO {
            return Err(Error::InvalidScalar);
        }
        Ok(ScalarBytes::from_scalar(&key))
    }
}

// Owner keys and issuance evidence (the paper's "Owner keys" and "Notes").

/// What shows anyone that `C = k Y` for the denomination's key, without
/// the key: a spend's recipient, a claim statement, a counter's checker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// A DLEQ on `(Y, C)` itself, blinded at issuance (`Note::unlink`): it
    /// shares nothing with what the hub issued, so a spend showing it is
    /// not linked to the issuance.
    Unlinked(Dleq),
    /// The issuance's DLEQ on `(B_, C_)` and `B_`'s blinding `r`, with the
    /// hub's commitment to unlink it. The hub kept `B_ = Y + rG`, so a spend
    /// showing this is linked to the issuance: a fallback, while the hub has
    /// not answered.
    Linked {
        dleq: Dleq,
        blinding: ScalarBytes,
        commit: DleqCommit,
    },
    /// Opened from a grant's packet (`crate::authorization::Grant`): the
    /// packet's proof that it sealed the issuance on `B_` under the grant's
    /// unlock `t` with the mask base `U` ([`Seal`]), with `B_`'s blinding,
    /// `t`, `U` and the hub's unlink commitment. It shows `C = kY` to
    /// anyone, whatever `U` is. Linked to the grant as `Linked` is to its
    /// issuance; `Note::unlink` replaces it.
    Granted {
        seal: Seal,
        blinding: ScalarBytes,
        commit: DleqCommit,
        unlock: ScalarBytes,
        mask: Point,
    },
}

impl Evidence {
    pub fn verify(&self, key: &Pt, y: &Pt, c: &Pt) -> Result<(), Error> {
        match self {
            Evidence::Unlinked(d) => dleq_verify_blinded(d, key, y, c),
            Evidence::Linked { dleq, blinding, .. } => {
                dleq_verify_unblinded(dleq, key, y, c, &blinding.to_scalar()?)
            }
            Evidence::Granted {
                seal,
                blinding,
                commit,
                unlock,
                mask,
            } => seal_verify_opened(
                seal,
                key,
                y,
                c,
                &blinding.to_scalar()?,
                &*unlock.to_nonzero()?,
                &Pt::from_point(mask)?,
                &commit.to_bytes(),
            ),
        }
    }

    /// The blinding and unlink commitment of evidence the hub can still
    /// link to what it signed; `None` once unlinked.
    pub fn linked(&self) -> Option<(&ScalarBytes, &DleqCommit)> {
        match self {
            Evidence::Unlinked(_) => None,
            Evidence::Linked {
                blinding, commit, ..
            }
            | Evidence::Granted {
                blinding, commit, ..
            } => Some((blinding, commit)),
        }
    }
}

fn unlink_capability(seed: &[u8; 32]) -> [u8; 32] {
    tagged_hash("licash/unlink-capability", &[seed])
}

/// Public output commitment to its private unlink authority. Separate
/// domains keep the commitment, capability, and note derivations distinct.
pub fn unlink_commitment(seed: &[u8; 32]) -> [u8; 32] {
    unlink_commitment_of(&unlink_capability(seed))
}

pub(crate) fn unlink_commitment_of(capability: &[u8; 32]) -> [u8; 32] {
    tagged_hash("licash/unlink-commitment", &[capability])
}

/// The one-time key's tweak for root `spend` and output seed `seed`:
/// `H("licash/tweak", spend, seed)`, a commitment to the root (as a taproot
/// tweak commits to its internal key). A free tweak let a holder rewrite a
/// note's owner `P + tG` as `(P + dG) + (t - d)G` and claim it again under
/// a related root with another claim key; here no other root opens the
/// same owner.
pub fn bound_tweak(spend: &Point, seed: &[u8; 32]) -> ScalarBytes {
    ScalarBytes::from_scalar(&scalar_from_hash(&tagged_hash(
        "licash/tweak",
        &[&spend.0, seed],
    )))
}

/// Everything derived for output `j` of a spend addressed to `recipient`
/// under shared secret `shared`.
#[derive(Clone)]
pub struct Derived {
    pub tweak: ScalarBytes,
    pub seed: [u8; 32],
    pub blinding: ScalarBytes,
    pub owner_point: Point,
}

/// Names the point alone: the seed, the tweak and the blinding are keys,
/// which no log or panic message may print.
impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Derived")
            .field("owner_point", &self.owner_point)
            .finish_non_exhaustive()
    }
}

pub fn derive_output(recipient_spend: &Point, shared: &[u8; 32], j: u32) -> Result<Derived, Error> {
    // The owner key is one-time only if the shared secret is: a payer
    // draws its ephemeral key anew for each spend. Reusing one gives the
    // same output again, which the hub issues once.
    let jb = j.to_be_bytes();
    let seed = tagged_hash("licash/seed", &[shared, &jb]);
    let tweak = bound_tweak(recipient_spend, &seed).to_scalar()?;
    let owner = recipient_spend.to_projective()? + generator_mul(&tweak);
    let owner_point = Point::from_projective(&owner);
    let blinding = scalar_from_hash(&tagged_hash("licash/blind", &[shared, &jb]));
    Ok(Derived {
        tweak: ScalarBytes::from_scalar(&tweak),
        seed,
        blinding: ScalarBytes::from_scalar(&blinding),
        owner_point,
    })
}

/// Is `owner` (x-only) the one-time key of root `spend` (`spend_pt`,
/// decompressed) and `seed`? What a claim checks of every item.
pub fn owner_bound(
    spend: &Point,
    spend_pt: &Pt,
    seed: &[u8; 32],
    owner: &[u8; 32],
) -> Result<bool, Error> {
    owner_matches_pt(spend_pt, &bound_tweak(spend, seed), owner)
}

/// `owner_matches` with the spend key already decompressed (a claim checks
/// every item against the same key).
pub fn owner_matches_pt(spend: &Pt, tweak: &ScalarBytes, owner: &[u8; 32]) -> Result<bool, Error> {
    let p = spend.add(&crate::ec::gen_mul(&tweak.to_scalar()?));
    Ok(p.to_point().x_only() == *owner)
}
