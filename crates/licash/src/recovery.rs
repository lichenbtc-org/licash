//! Recovery: the signed publication P, the claim as filed on Bitcoin
//! ([`Filing`]), and what it is owed ([`owed`]).
//!
//! The holder files P with a public eligibility witness and proves nothing.
//! The Hub decides what the claim is owed from the filing and its own
//! evidence, and proves that decision in its statement (`licash-hp`, whose
//! guest evaluates [`owed`]). Notes are designated by their hold keys alone,
//! not owned through any root key (see [`Filing`] for what that changes).
//! A claim binds its opening's Base digest and E, so a proof for one opening
//! or claim is useless for any other. What is owed is owed: there is no
//! penalty mode.

use crate::{
    authorization::{
        granted_digest, plain_digest, Authorization, GrantHead, SignedProposal, Unlock,
        GRANT_HEAD_BYTES,
    },
    base::Base,
    chain::{Activation, ActivationRef, Chain, Checkpoint, Inclusion},
    claim::{self, ActivationRecord, Branch, Item, Source, UnsignedClaim, MAX_ITEMS},
    crypto::{self, Point, ScalarBytes, Signature},
    disclosure::{Disclosures, SLOTS},
    hold::{self, Envelope, Record},
    note::{Keyset, Message, Note, PUBLIC_FIELDS_BYTES},
    request::Request,
    source::Certificate,
    spend::{
        body_id, body_input, Proposal, ProposalId, TimedTerms, MAX_BODY_BYTES, MAX_INPUTS,
        TIMED_TERMS_BYTES,
    },
    Error,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const P_MAGIC: &[u8] = b"LICASH-P\x02";
const P_MAGIC_COMPACT: &[u8] = b"LICASH-P\x03";
/// A filing's magic: with no activation, or each with the lock checkpoint
/// it is anchored to.
const F_MAGIC: &[u8] = b"LICASH-F\x01";
const F_MAGIC_ANCHORED: &[u8] = b"LICASH-F\x02";
/// Its activations anchored, and the outputs her Base's funded part names
/// listed after them, which its funded items open.
const F_MAGIC_FUNDED: &[u8] = b"LICASH-F\x03";
/// The compact format's: unanchored, anchored, and funded as [`F_MAGIC_FUNDED`].
const F_MAGIC_COMPACT: &[u8] = b"LICASH-F\x11";
const F_MAGIC_COMPACT_ANCHORED: &[u8] = b"LICASH-F\x12";
const F_MAGIC_COMPACT_FUNDED: &[u8] = b"LICASH-F\x13";

/// The first graph id whose contracts file [`Format::Compact`].
pub const COMPACT_FROM: u32 = 9;

/// The first graph id whose contracts are decided as [`Format::Lean`].
pub const LEAN_FROM: u32 = 10;

/// The first graph id whose contracts' statement reads Bitcoin's headers
/// from a receipt of the hub's header chain, not from every header of the
/// exit ([`chained`]). Their filing is [`Format::Lean`].
pub const CHAINED_FROM: u32 = 11;

/// The first graph id whose claims no other claim of the same contract
/// voids ([`Evidence::SecondClaim`]): her own claim made before, which a
/// claim she makes again in its place may hold notes of, is no evidence
/// against it. Before it, any claim but the one judged is.
pub const OWN_CLAIMS_FROM: u32 = 12;

/// The first graph id whose notes are of the note format v3, the issuance
/// proof's challenge hashing its base ([`crate::crypto::dleq_prove`]), and
/// otherwise judged as [`OWN_CLAIMS_FROM`]'s. It names the change rather
/// than selecting a rule: the Base of an earlier graph embeds a keyset of
/// the format before, which this code no longer reads.
pub const BOUND_BASE_FROM: u32 = 13;

/// The first graph id whose hub cites a spend by its owners' signatures
/// ([`Evidence::Signed`], [`cite`]) and whose grants anyone verifies
/// ([`crate::authorization::Grant`]), and otherwise judged as
/// [`BOUND_BASE_FROM`]'s. It names the change rather than selecting a rule,
/// as that one does: this code reads no grant of the format before.
pub const SIGNED_FROM: u32 = 14;

/// The first graph id whose links carry their bytes, her claim's and the
/// hub's disclosure's, in an envelope of a leaf script their spends
/// reveal, in the witness, not in nulldata ([`leaf_carried`]); otherwise
/// judged as [`SIGNED_FROM`]'s.
pub const LEAF_FROM: u32 = 15;

/// The first graph id whose `assert` carries π1 alone, its leaf taking no
/// π2 and π3 beside it (Lichen's `Tail::pair` off): the hub hands them over
/// off chain, as before, and nothing unsigned rides in its witness for a
/// relayer to replace ([`pair_on_chain`]); otherwise judged as
/// [`LEAF_FROM`]'s.
pub const PI1_ALONE_FROM: u32 = 16;

/// Whether, in a contract of graph `id`, another claim of the same
/// contract voids the notes it holds ([`OWN_CLAIMS_FROM`]).
pub fn own_claims_void(id: u32) -> bool {
    id < OWN_CLAIMS_FROM
}

/// Whether a contract of graph `id` is decided on a header chain proven
/// beforehand: a function of its Base alone, as its [`Format`] is.
pub fn chained(id: u32) -> bool {
    id >= CHAINED_FROM
}

/// Whether a contract of graph `id` carries its claim and disclosure in a
/// leaf script's envelope ([`LEAF_FROM`]): a function of its Base alone,
/// as its [`Format`] is.
pub fn leaf_carried(id: u32) -> bool {
    id >= LEAF_FROM
}

/// Whether, in a contract of graph `id`, `assert` carries π2 and π3 beside
/// π1 ([`PI1_ALONE_FROM`]).
pub fn pair_on_chain(id: u32) -> bool {
    id < PI1_ALONE_FROM
}

/// How a contract's filing is written, a function of its Base alone: the
/// holder writes it, the Hub reads it and the statement decides on it all
/// by [`Format::of`], so that a contract is decided by the codec it was
/// opened under for as long as it lives. Each format has its own magics
/// and the other's bytes don't decode.
///
/// `Compact` writes nothing a decoder can take from elsewhere in the
/// filing: a record that authorizes an item names it by its index, and a
/// settled note's witness leaves out its keyset and public fields, which
/// are its item's. Everything decoded is the same, so every check after
/// decoding is the same.
///
/// `Lean` files as `Compact` and judges differently: not every item is
/// verified, only those the Hub cites as invalid ([`owed_flagged`]), so that
/// a proof costs what it contests and not the whole claim. The statement
/// takes every other item as valid, which can only raise what the claim is
/// owed: the Hub cites the invalid ones, and an invalid item is worth
/// nothing rather than voiding the claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Legacy,
    Compact,
    Lean,
}

impl Format {
    /// Whether it writes the compact encoding: `Compact` and `Lean` do.
    pub fn compact(self) -> bool {
        self != Self::Legacy
    }

    pub fn lean(self) -> bool {
        self == Self::Lean
    }

    pub fn of(base: &Base) -> Self {
        Self::at(base.parts().graph.id)
    }

    /// The format of the contracts of graph `id`.
    pub fn at(id: u32) -> Self {
        match id {
            id if id >= LEAN_FROM => Self::Lean,
            id if id >= COMPACT_FROM => Self::Compact,
            _ => Self::Legacy,
        }
    }
}
/// A filing's limit: its bytes fit Lichen's claim carrier
/// (`licash_statement::claim_script`), which Core relays under default
/// policy.
pub const MAX_PUBLICATION_BYTES: usize = 64_000;
const MAX_CERTIFICATE_BYTES: usize = 8_192;

fn bad(reason: &str) -> Error {
    Error::Protocol(reason.into())
}

fn put_count(bytes: &mut Vec<u8>, n: usize) {
    bytes.extend(u32::try_from(n).expect("bounded count").to_be_bytes());
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(bad("truncated native publication"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("fixed field"))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn count(&mut self, limit: usize) -> Result<usize, Error> {
        let n = self.u32()? as usize;
        if n > limit {
            return Err(bad("native publication component limit"));
        }
        Ok(n)
    }
    fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.count(MAX_PUBLICATION_BYTES)?;
        self.take(n)
    }
}

fn put_blob(bytes: &mut Vec<u8>, blob: &[u8]) {
    put_count(bytes, blob.len());
    bytes.extend(blob);
}

/// Signed claim publication P: every counted field of E plus every Q
/// signature, filed with its witness ([`Filing`]) after R. Decoding
/// recomputes E, so P is authority only for the E that R actually signed.
#[derive(Clone)]
pub struct Publication {
    claim: UnsignedClaim,
    envelope: Envelope,
}

impl std::fmt::Debug for Publication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Publication(..)")
    }
}

impl Publication {
    /// Sign every required Q authorization (items plus OwnInputs inputs).
    pub fn sign(
        claim: UnsignedClaim,
        hold_keys: &[(Message, ScalarBytes)],
        limit: usize,
    ) -> Result<Self, Error> {
        let mut entries = Vec::with_capacity(hold_keys.len());
        for (message, key) in hold_keys {
            entries.push((message.identifier()?, message.clone(), *key));
        }
        entries.sort_by_key(|(y, _, _)| *y);
        let entries: Vec<_> = entries.into_iter().map(|(_, m, k)| (m, k)).collect();
        let envelope = Envelope::sign(claim.hold_context(), &entries, limit)?;
        envelope.verify(&claim.hold_context(), claim.hold_root(), limit)?;
        Ok(Self { claim, envelope })
    }

    pub fn claim(&self) -> &UnsignedClaim {
        &self.claim
    }
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    pub fn to_bytes(&self, format: Format) -> Vec<u8> {
        let claim = &self.claim;
        let context = claim.context();
        let parts = claim.parts();
        let mut bytes = match format.compact() {
            false => P_MAGIC,
            true => P_MAGIC_COMPACT,
        }
        .to_vec();
        bytes.extend(context.base);
        bytes.extend(context.deposit);
        bytes.extend(context.cap.to_be_bytes());
        bytes.extend(claim.keyset_id());
        bytes.extend(claim.amount().to_be_bytes());
        put_count(&mut bytes, parts.items.len());
        for item in &parts.items {
            match item {
                Item::Settled(message) => {
                    bytes.push(0);
                    bytes.extend(message.public_fields());
                }
                Item::Pending {
                    message,
                    source,
                    branch,
                    index,
                    blinding,
                    preimage,
                } => {
                    bytes.push(1);
                    bytes.extend(message.public_fields());
                    bytes.extend(source.as_bytes());
                    bytes.push(u8::from(*branch == Branch::Refund));
                    bytes.extend(index.to_be_bytes());
                    bytes.extend(blinding.0);
                    match preimage {
                        None => bytes.push(0),
                        Some(z) => {
                            bytes.push(1);
                            bytes.extend(z);
                        }
                    }
                }
                Item::Funded {
                    message,
                    index,
                    blinding,
                } => {
                    bytes.push(2);
                    bytes.extend(message.public_fields());
                    bytes.extend(index.to_be_bytes());
                    bytes.extend(blinding.0);
                }
            }
        }
        put_count(&mut bytes, parts.sources.len());
        for source in &parts.sources {
            match source {
                Source::Plain { id, inputs } | Source::OwnInputs { id, inputs, .. } => {
                    bytes.push(u8::from(matches!(source, Source::OwnInputs { .. })));
                    bytes.extend(id.as_bytes());
                    put_count(&mut bytes, inputs.len());
                    for input in inputs {
                        bytes.extend(input.0);
                    }
                    if let Source::OwnInputs { terms, .. } = source {
                        bytes.extend(terms.to_bytes());
                    }
                }
                Source::Admitted(cert) => {
                    bytes.push(2);
                    let cert = cert.to_bytes();
                    put_count(&mut bytes, cert.len());
                    bytes.extend(cert);
                }
            }
        }
        put_count(&mut bytes, parts.activations.len());
        for activation in &parts.activations {
            bytes.extend(activation.source.as_bytes());
            bytes.extend(activation.reference.to_bytes());
        }
        let records = self.envelope.records();
        put_count(&mut bytes, records.len());
        for record in records {
            match format.compact() {
                false => bytes.extend(record.message.public_fields()),
                // An item's own record is its index: the item names the
                // message, and it is the first and only one that does.
                true => match parts
                    .items
                    .iter()
                    .position(|i| i.message() == &record.message)
                {
                    Some(index) => {
                        bytes.push(0);
                        bytes.push(u8::try_from(index).expect("at most 32 items"));
                    }
                    None => {
                        bytes.push(1);
                        bytes.extend(record.message.public_fields());
                    }
                },
            }
            bytes.extend(record.sig.0);
        }
        bytes
    }

    /// Strict canonical decoding. The keyset and authorization limit are the
    /// opening's authenticated terms, never taken from the payload.
    pub fn from_bytes(
        format: Format,
        keyset: &Keyset,
        limit: usize,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        Self::decode(format, keyset, limit, bytes, true)
    }

    /// [`Publication::from_bytes`], each hold signature verified only if
    /// `checked` (of a lean format alone: [`owed_flagged`] verifies those of
    /// the items it is shown to be wrong about).
    fn decode(
        format: Format,
        keyset: &Keyset,
        limit: usize,
        bytes: &[u8],
        checked: bool,
    ) -> Result<Self, Error> {
        if !checked && !format.lean() {
            return Err(bad("signatures are skipped of a lean filing alone"));
        }
        let magic = match format.compact() {
            false => P_MAGIC,
            true => P_MAGIC_COMPACT,
        };
        if bytes.len() > MAX_PUBLICATION_BYTES || !bytes.starts_with(magic) {
            return Err(bad("native publication framing"));
        }
        let mut r = Reader(&bytes[magic.len()..]);
        let context = claim::Context {
            base: r.array()?,
            deposit: r.array()?,
            cap: r.u32()?,
        };
        if &r.array::<32>()? != keyset.id() {
            return Err(bad("native publication keyset"));
        }
        let amount = r.u32()?;
        let mut items = Vec::new();
        for _ in 0..r.count(MAX_ITEMS)? {
            let tag = r.byte()?;
            let message = Message::from_public_fields(r.take(PUBLIC_FIELDS_BYTES)?)?;
            items.push(match tag {
                0 => Item::Settled(message),
                1 => {
                    let source = ProposalId::from_bytes(r.array()?);
                    let branch = match r.byte()? {
                        0 => Branch::Pay,
                        1 => Branch::Refund,
                        _ => return Err(bad("native publication branch")),
                    };
                    let index = r.u32()?;
                    let blinding = ScalarBytes(r.array()?);
                    let preimage = match r.byte()? {
                        0 => None,
                        1 => Some(r.array()?),
                        _ => return Err(bad("native publication preimage flag")),
                    };
                    Item::Pending {
                        message,
                        source,
                        branch,
                        index,
                        blinding,
                        preimage,
                    }
                }
                2 => Item::Funded {
                    message,
                    index: r.u32()?,
                    blinding: ScalarBytes(r.array()?),
                },
                _ => return Err(bad("native publication item tag")),
            });
        }
        let mut sources = Vec::new();
        for _ in 0..r.count(MAX_ITEMS)? {
            let tag = r.byte()?;
            sources.push(match tag {
                0 | 1 => {
                    let id = ProposalId::from_bytes(r.array()?);
                    let mut inputs = Vec::new();
                    for _ in 0..r.count(limit)? {
                        inputs.push(Point(r.array()?));
                    }
                    if tag == 0 {
                        Source::Plain { id, inputs }
                    } else {
                        let terms = TimedTerms::from_bytes(r.take(TIMED_TERMS_BYTES)?)?;
                        Source::OwnInputs { id, inputs, terms }
                    }
                }
                2 => {
                    let n = r.count(MAX_CERTIFICATE_BYTES)?;
                    Source::Admitted(Certificate::from_bytes(keyset, r.take(n)?)?)
                }
                _ => return Err(bad("native publication source tag")),
            });
        }
        let mut activations = Vec::new();
        for _ in 0..r.count(MAX_ITEMS)? {
            let source = ProposalId::from_bytes(r.array()?);
            let reference = ActivationRef {
                height: r.u32()?,
                block_hash: r.array()?,
                txid: r.array()?,
                output: r.u32()?,
            };
            activations.push(ActivationRecord { source, reference });
        }
        let mut records = Vec::new();
        for _ in 0..r.count(limit)? {
            let own = match format.compact() {
                false => false,
                true => match r.byte()? {
                    0 => true,
                    1 => false,
                    _ => return Err(bad("native publication record tag")),
                },
            };
            let message = match own {
                true => {
                    let index = usize::from(r.byte()?);
                    items
                        .get(index)
                        .ok_or_else(|| bad("native publication record index"))?
                        .message()
                        .clone()
                }
                false => Message::from_public_fields(r.take(PUBLIC_FIELDS_BYTES)?)?,
            };
            records.push(Record {
                message,
                sig: Signature(r.array()?),
            });
        }
        if !r.0.is_empty() {
            return Err(bad("trailing native publication bytes"));
        }
        let authorizations = records
            .iter()
            .map(|record| record.message.clone())
            .collect();
        let claim = UnsignedClaim::new(
            context,
            keyset,
            amount,
            claim::Parts {
                items,
                sources,
                activations,
                authorizations,
            },
            limit,
        )?;
        let envelope = match checked {
            true => {
                Envelope::from_records(claim.hold_context(), claim.hold_root(), records, limit)?
            }
            false => Envelope::from_records_unchecked(
                claim.hold_context(),
                claim.hold_root(),
                records,
                limit,
            )?,
        };
        let publication = Self { claim, envelope };
        if publication.to_bytes(format) != bytes {
            return Err(bad("noncanonical native publication"));
        }
        Ok(publication)
    }

    /// P is authority only for the request R signed under this opening.
    pub fn bind(&self, base: &Base, request: &Request) -> Result<(), Error> {
        let parts = base.parts();
        let context = self.claim.context();
        if context.base != base.digest()
            || context.deposit != parts.deposit
            || context.cap != parts.cap
            || self.claim.keyset_id() != parts.keyset.id()
            || request.amount != self.claim.amount()
            || &request.claim_digest != self.claim.digest()
        {
            return Err(bad("publication does not match the opening request"));
        }
        Ok(())
    }

    /// Its hold authorizations that verify ([`Held`]): all of them, of a P
    /// decoded with [`Publication::from_bytes`].
    pub fn held(&self) -> Held {
        let records = self.envelope.records().iter();
        Held {
            context: *self.envelope.context(),
            records: records
                .filter(|record| self.envelope.verify_record(&record.message).is_ok())
                .cloned()
                .collect(),
        }
    }
}

/// The hold authorizations of a filed claim that verify: each the signature
/// of this claim by a note's hold key, which is the whole of the authority
/// to recover that note ([`Filing`]). What the Hub retires of a claim and
/// cites against any other claim of the same notes
/// ([`Evidence::SecondClaim`]). A record that does not verify is nobody's
/// word, and is never in it: who knows a note's public fields, as its payer
/// does, signs nothing for it.
#[derive(Clone)]
pub struct Held {
    context: hold::Context,
    records: Vec<Record>,
}

impl std::fmt::Debug for Held {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Held(..)")
    }
}

impl Held {
    /// The claim the records sign.
    pub fn context(&self) -> &hold::Context {
        &self.context
    }

    /// Each verified under its note's hold key, in the claim's order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

/// Holder's private evidence for one source: the complete owner-signed body.
/// Plain/OwnInputs need input issuance evidence; certified (Admitted) sources
/// use the issuer's admission signature instead of payer note evidence.
#[derive(Clone)]
pub enum SourceWitness {
    Signed {
        signed: SignedProposal,
        notes: Vec<Note>,
    },
    Certified {
        proposal: Proposal,
        signatures: Vec<Signature>,
    },
}

impl SourceWitness {
    fn proposal(&self) -> &Proposal {
        match self {
            Self::Signed { signed, .. } => signed.proposal(),
            Self::Certified { proposal, .. } => proposal,
        }
    }

    /// Authenticate against the claim's public source metadata.
    fn authenticate(&self, keyset: &Keyset, source: &Source) -> Result<(), Error> {
        let lock_terms = self.proposal().lock().map(|lock| lock.terms());
        match (source, self) {
            (
                Source::Admitted(cert),
                Self::Certified {
                    proposal,
                    signatures,
                },
            ) => cert.authenticate_source(keyset, proposal, signatures),
            (Source::Admitted(cert), Self::Signed { signed, notes }) => {
                cert.verify_source(keyset, signed, notes)
            }
            (Source::Plain { .. } | Source::OwnInputs { .. }, Self::Signed { signed, notes }) => {
                // Verified as the filing was decoded, its notes with it.
                let mut inputs = signed.inputs_of(keyset, notes)?;
                inputs.sort_unstable();
                if inputs != source.inputs() || lock_terms != source.terms() {
                    return Err(bad("source body differs from claimed metadata"));
                }
                Ok(())
            }
            _ => Err(bad("source witness class")),
        }
    }
}

fn opens(
    output: &crate::spend::Output,
    message: &Message,
    blinding: &ScalarBytes,
) -> Result<bool, Error> {
    output.opened_by(message, blinding)
}

/// The Hub's evidence against a claim. Each evidence must void at least one
/// item (or value a Plain source's fallbacks); voided items are excluded and
/// everything else stays owed.
#[derive(Clone)]
pub enum Evidence {
    /// An owner-signed spend. It voids items it consumes (own Y) and pending
    /// outputs of another source whose inputs it double-spends, except an
    /// activated certified Pay. Executing a Plain source values its fallbacks.
    /// A granted spend is cited with its unlock, which the Hub publishes:
    /// retiring the payer's inputs releases the payee's outputs.
    Spend {
        signed: SignedProposal,
        notes: Vec<Note>,
        unlock: Option<Unlock>,
    },
    /// A Q key that authorized this claim authorized a different claim too. It
    /// voids that key's item and, for a lock of the holder's own notes
    /// (`Source::OwnInputs`, whose inputs' keys must authorize the claim), the
    /// outputs of the lock that the key's note funds: the Hub may never have
    /// seen that lock, and the note may have been paid in the other claim.
    SecondClaim {
        context: hold::Context,
        record: Record,
    },
    /// The Pay preimage of a timed source is known: its Refund items are void.
    /// The Hub publishes the preimage.
    PayPreimage {
        source: ProposalId,
        preimage: [u8; 32],
    },
    /// The source expired at depth with no activation referenced by the claim.
    /// It voids nothing: a lock's Pay is owed only with an activation, so a
    /// claim with evidence of it is refused.
    Expired { source: ProposalId },
    /// A spend by the word of the owners the Hub relies on, and nothing
    /// else of it: the bytes its proposal commits to, hashed to its id and
    /// otherwise unread, and the owner's signature of each input relied on,
    /// by its index, in order. It voids what [`Evidence::Spend`] does, of
    /// those inputs alone: whoever signed a spend of her note gave it up,
    /// whatever else the spend took and made, so what it costs to read
    /// does not grow with either. Shown to execute a Plain source it is
    /// signed for by every input of it (`void`).
    ///
    /// Of a granted spend, with what its owners signed of the grant
    /// ([`GrantHead`]) and the unlock, the secret of the key they signed:
    /// each verified its every packet before she signed
    /// ([`crate::authorization::Grant::verify`]), so the unlock published
    /// is the payee's outputs released, and no packet is read.
    Signed {
        body: Vec<u8>,
        signers: Vec<(u32, Signature)>,
        grant: Option<(GrantHead, Unlock)>,
    },
}

/// The id of the spend of `keyset` that commits to `body`, and the
/// identifiers of the inputs `signers` show given up to it: each the
/// signature, by the owner of the input at its index, of the spend, plain
/// or with the grant of head `grant`, whose unlock is then its key's.
fn signed_by(
    keyset: &Keyset,
    body: &[u8],
    signers: &[(u32, Signature)],
    grant: Option<&(GrantHead, Unlock)>,
) -> Result<(ProposalId, BTreeSet<Point>), Error> {
    let id = body_id(body);
    let digest = match grant {
        None => plain_digest(&id),
        Some((head, unlock)) => {
            head.verify_unlock(unlock)?;
            granted_digest(&id, head)
        }
    };
    if signers.is_empty() {
        return Err(bad("a spend cited with no signature"));
    }
    if signers.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(bad("a spend's signers out of order"));
    }
    let mut spent = BTreeSet::new();
    for (index, sig) in signers {
        let input = body_input(keyset.id(), body, *index)?;
        crypto::schnorr_verify(input.owner(), &digest, sig)?;
        spent.insert(input.identifier()?);
    }
    Ok((id, spent))
}

/// `evidence` as the Hub cites it against `claim`: an owner-signed spend by
/// the signatures it relies on ([`Evidence::Signed`]), anything else as it
/// is. The inputs relied on are those the claim speaks of: each that is an
/// item of it, each of the spend if the claim names it as a Plain source,
/// which it then executes whole, and, of each other source the spend shares
/// an input with, one, which voids its outputs as well as all would. A
/// spend that touches nothing of the claim keeps one signature, and voids
/// nothing, as it did.
///
/// What it cites so costs the statement what the claim names, whatever the
/// spend took and made: it decides on it exactly as on the spend whole.
pub fn cite(claim: &UnsignedClaim, evidence: Evidence) -> Result<Evidence, Error> {
    let Evidence::Spend {
        signed,
        notes: _,
        unlock,
    } = evidence
    else {
        return Ok(evidence);
    };
    let parts = claim.parts();
    let mut items = BTreeSet::new();
    for item in &parts.items {
        items.insert(item.message().identifier()?);
    }
    let proposal = signed.proposal();
    let id = proposal.id();
    let inputs = (proposal.inputs().iter())
        .map(Message::identifier)
        .collect::<Result<Vec<_>, _>>()?;
    let whole = (parts.sources.iter())
        .any(|s| matches!(s, Source::Plain { id: source, .. } if *source == id));
    let mut relied: BTreeSet<usize> = (0..inputs.len())
        .filter(|&i| whole || items.contains(&inputs[i]))
        .collect();
    for source in parts.sources.iter().filter(|s| s.id() != id) {
        let shared = |i: &usize| source.inputs().contains(&inputs[*i]);
        if !relied.iter().any(shared) {
            relied.extend((0..inputs.len()).find(shared));
        }
    }
    if relied.is_empty() {
        relied.insert(0);
    }
    by_signature(&signed, unlock, &relied)
}

/// The owner-signed spend `signed`, with its `unlock` if granted, cited by
/// the signatures of its inputs at `relied` ([`Evidence::Signed`]).
pub fn by_signature(
    signed: &SignedProposal,
    unlock: Option<Unlock>,
    relied: &BTreeSet<usize>,
) -> Result<Evidence, Error> {
    let grant = match (signed.authorization(), unlock) {
        (Authorization::Plain, None) => None,
        (Authorization::Granted(grant), Some(unlock)) => Some((grant.head()?, unlock)),
        _ => return Err(bad("a granted spend is cited with its unlock")),
    };
    let signers = relied
        .iter()
        .map(|&i| {
            let sig = signed
                .signatures()
                .get(i)
                .ok_or_else(|| bad("a spend cited by an input it has not"))?;
            Ok((u32::try_from(i).map_err(|_| bad("input index"))?, *sig))
        })
        .collect::<Result<_, Error>>()?;
    Ok(Evidence::Signed {
        body: signed.proposal().commitment_bytes(),
        signers,
        grant,
    })
}

/// Most evidence a statement's input carries: one per item it voids, and
/// one per source.
pub const MAX_EVIDENCE: usize = 2 * MAX_ITEMS;

/// The Hub's evidence, canonically encoded for its statement's input.
pub fn evidence_to_bytes(evidence: &[Evidence]) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_count(&mut bytes, evidence.len());
    for e in evidence {
        match e {
            Evidence::Spend {
                signed,
                notes,
                unlock,
            } => {
                bytes.push(0);
                put_count(&mut bytes, notes.len());
                for note in notes {
                    put_blob(&mut bytes, &note.to_bytes());
                }
                put_blob(&mut bytes, &signed.to_bytes());
                match unlock {
                    None => bytes.push(0),
                    Some(unlock) => {
                        bytes.push(1);
                        bytes.extend(unlock);
                    }
                }
            }
            Evidence::SecondClaim { context, record } => {
                bytes.push(1);
                bytes.extend(context.to_bytes());
                bytes.extend(record.message.to_bytes());
                bytes.extend(record.sig.0);
            }
            Evidence::PayPreimage { source, preimage } => {
                bytes.push(2);
                bytes.extend(source.as_bytes());
                bytes.extend(preimage);
            }
            Evidence::Expired { source } => {
                bytes.push(3);
                bytes.extend(source.as_bytes());
            }
            Evidence::Signed {
                body,
                signers,
                grant,
            } => {
                bytes.push(4);
                put_blob(&mut bytes, body);
                put_count(&mut bytes, signers.len());
                for (index, sig) in signers {
                    bytes.extend(index.to_be_bytes());
                    bytes.extend(sig.0);
                }
                match grant {
                    None => bytes.push(0),
                    Some((head, unlock)) => {
                        bytes.push(1);
                        bytes.extend(head.to_bytes());
                        bytes.extend(unlock);
                    }
                }
            }
        }
    }
    bytes
}

/// Strict canonical decoding of [`evidence_to_bytes`]: every note verified
/// under `keyset`, every signed spend against its notes; of a spend cited
/// by its signatures ([`Evidence::Signed`]) nothing is, here. Whether the
/// evidence verifies and voids anything is [`owed`]'s to decide.
pub fn evidence_from_bytes(
    keyset: &Keyset,
    limit: usize,
    bytes: &[u8],
) -> Result<Vec<Evidence>, Error> {
    let mut r = Reader(bytes);
    let mut evidence = Vec::new();
    for _ in 0..r.count(MAX_EVIDENCE)? {
        evidence.push(match r.byte()? {
            0 => {
                // Verified once, as the spend's inputs it is read with.
                let notes = (0..r.count(limit)?)
                    .map(|_| Note::from_bytes_unverified(r.blob()?))
                    .collect::<Result<Vec<_>, _>>()?;
                let signed = SignedProposal::from_bytes(keyset, &notes, r.blob()?)?;
                let unlock = match r.byte()? {
                    0 => None,
                    1 => Some(r.array()?),
                    _ => return Err(bad("evidence unlock tag")),
                };
                Evidence::Spend {
                    signed,
                    notes,
                    unlock,
                }
            }
            1 => Evidence::SecondClaim {
                context: hold::Context::from_bytes(&r.array()?),
                record: Record {
                    message: Message::from_bytes(r.take(crate::note::MESSAGE_BYTES)?)?,
                    sig: Signature(r.array()?),
                },
            },
            2 => Evidence::PayPreimage {
                source: ProposalId::from_bytes(r.array()?),
                preimage: r.array()?,
            },
            3 => Evidence::Expired {
                source: ProposalId::from_bytes(r.array()?),
            },
            4 => {
                let body = r.blob()?;
                if body.len() > MAX_BODY_BYTES {
                    return Err(bad("evidence spend body too long"));
                }
                let signers = (0..r.count(MAX_INPUTS)?)
                    .map(|_| Ok((r.u32()?, Signature(r.array()?))))
                    .collect::<Result<Vec<_>, Error>>()?;
                let grant = match r.byte()? {
                    0 => None,
                    1 => Some((
                        GrantHead::from_bytes(&r.array::<GRANT_HEAD_BYTES>()?),
                        r.array()?,
                    )),
                    _ => return Err(bad("evidence grant tag")),
                };
                Evidence::Signed {
                    body: body.to_vec(),
                    signers,
                    grant,
                }
            }
            _ => return Err(bad("evidence tag")),
        });
    }
    if !r.0.is_empty() || evidence_to_bytes(&evidence) != bytes {
        return Err(bad("noncanonical evidence"));
    }
    Ok(evidence)
}

/// The secrets the Hub publishes with its response: the unlock of every
/// granted spend it cites and every Pay preimage, one slot per source in
/// source-id order, zero padded. Its statement holds only if its response
/// disclosed these exact bytes (when any slot is set). A source has one
/// slot: two secrets cited of one are an error, so that none is cited and
/// kept unpublished.
pub fn disclosures(evidence: &[Evidence]) -> Result<Disclosures, Error> {
    let mut by_source = BTreeMap::new();
    for e in evidence {
        let (source, secret) = match e {
            Evidence::Spend {
                signed,
                unlock: Some(unlock),
                ..
            } => (signed.proposal().id(), *unlock),
            Evidence::Signed {
                body,
                grant: Some((_, unlock)),
                ..
            } => (body_id(body), *unlock),
            Evidence::PayPreimage { source, preimage } => (*source, *preimage),
            _ => continue,
        };
        if by_source
            .insert(source, secret)
            .is_some_and(|other| other != secret)
        {
            return Err(bad("two secrets disclosed of one source"));
        }
    }
    if by_source.len() > SLOTS {
        return Err(bad("disclosures exceed their slots"));
    }
    let mut disclosures = Disclosures::empty();
    for (slot, value) in disclosures.values.iter_mut().zip(by_source.values()) {
        *slot = *value;
    }
    disclosures.used = by_source.len();
    Ok(disclosures)
}

/// The identifiers an owner-signed spend consumes, once verified: its
/// owners' signatures, which every [`SignedProposal`] was made or read
/// with, and for a granted spend its unlock. The owners committed to the
/// grant, so a granted spend cannot be cited as a plain one to keep its
/// unlock private.
fn spent_by(
    keyset: &Keyset,
    signed: &SignedProposal,
    notes: &[Note],
    unlock: Option<&Unlock>,
) -> Result<BTreeSet<Point>, Error> {
    let spent = signed.inputs_of(keyset, notes)?.into_iter().collect();
    match (signed.authorization(), unlock) {
        (Authorization::Plain, None) => {}
        (Authorization::Granted(grant), Some(unlock)) => grant.verify_unlock(keyset, unlock)?,
        _ => return Err(bad("a granted spend is cited with its unlock")),
    }
    Ok(spent)
}

/// A hold authorization of a claim of context `context`, as the Hub cites
/// it against another claim of the same note: signed by the note's hold key.
fn verify_second_claim(context: &hold::Context, record: &Record) -> Result<(), Error> {
    crypto::schnorr_verify(
        record.message.hold(),
        &context.signing_digest(&record.message),
        &record.sig,
    )
}

/// Whether `evidence`, verified, shows `note` spent or claimed elsewhere,
/// which is what voids it in any claim of it: an owner-signed spend that
/// consumes it, or its hold key's signature of another claim of it. An
/// error if the evidence does not verify. Only these two kinds speak of a
/// single note; the others are false.
///
/// This is [`owed`]'s own test of an item, so that a wallet that closes
/// without the Hub's proof drops exactly the notes the statement would void,
/// and only on evidence it checked itself.
pub fn voids_note(keyset: &Keyset, note: &Message, evidence: &Evidence) -> Result<bool, Error> {
    match evidence {
        Evidence::Spend {
            signed,
            notes,
            unlock,
        } => Ok(spent_by(keyset, signed, notes, unlock.as_ref())?.contains(&note.identifier()?)),
        Evidence::Signed {
            body,
            signers,
            grant,
        } => Ok(signed_by(keyset, body, signers, grant.as_ref())?
            .1
            .contains(&note.identifier()?)),
        Evidence::SecondClaim { context, record } => {
            verify_second_claim(context, record)?;
            Ok(&record.message == note)
        }
        Evidence::PayPreimage { .. } | Evidence::Expired { .. } => Ok(false),
    }
}

/// The items `evidence` voids (bit i for item i) and the sources it shows
/// executed, in a contract of graph `graph`. Each evidence must void an
/// item, or show a Plain source executed, which values its fallbacks; a
/// claim of the same contract voids none from [`OWN_CLAIMS_FROM`] on.
fn void(
    keyset: &Keyset,
    graph: u32,
    claim: &UnsignedClaim,
    evidence: &[Evidence],
) -> Result<(u32, BTreeSet<ProposalId>), Error> {
    let items = &claim.parts().items;
    let sources: BTreeMap<_, _> = claim.parts().sources.iter().map(|s| (s.id(), s)).collect();
    let activated: BTreeSet<_> = claim.parts().activations.iter().map(|a| a.source).collect();
    let immune = |source: &ProposalId, branch: &Branch| {
        *branch == Branch::Pay
            && activated.contains(source)
            && matches!(sources.get(source), Some(Source::Admitted(_)))
    };
    let mut mask = 0u32;
    let mut executed = BTreeSet::new();
    for e in evidence {
        let before = mask;
        let mut values_fallback = false;
        match e {
            Evidence::Spend { .. } | Evidence::Signed { .. } => {
                let (id, spent) = match e {
                    Evidence::Spend {
                        signed,
                        notes,
                        unlock,
                    } => (
                        signed.proposal().id(),
                        spent_by(keyset, signed, notes, unlock.as_ref())?,
                    ),
                    Evidence::Signed {
                        body,
                        signers,
                        grant,
                    } => signed_by(keyset, body, signers, grant.as_ref())?,
                    _ => unreachable!("a spend, matched above"),
                };
                if let Some(source @ Source::Plain { .. }) = sources.get(&id) {
                    // Its fallbacks are owed for its inputs, every one.
                    if !source.inputs().iter().all(|y| spent.contains(y)) {
                        return Err(bad("a source executed by a part of its inputs"));
                    }
                    values_fallback = true;
                }
                executed.insert(id);
                for (i, item) in items.iter().enumerate() {
                    let own = spent.contains(&item.message().identifier()?);
                    let shared = match item {
                        Item::Pending { source, branch, .. } => {
                            *source != id
                                && !immune(source, branch)
                                && sources[source].inputs().iter().any(|y| spent.contains(y))
                        }
                        Item::Settled(_) | Item::Funded { .. } => false,
                    };
                    if own || shared {
                        mask |= 1 << i;
                    }
                }
            }
            Evidence::SecondClaim { context, record } => {
                let own = claim.hold_context();
                if *context == own {
                    return Err(bad("second claim must be a different claim"));
                }
                let same = context.base == own.base && context.deposit == own.deposit;
                if same && !own_claims_void(graph) {
                    return Err(bad("a claim of the same contract voids nothing"));
                }
                verify_second_claim(context, record)?;
                let claimed = record.message.identifier()?;
                for (i, item) in items.iter().enumerate() {
                    let locked = match item {
                        Item::Pending { source, .. } => matches!(
                            &sources[source],
                            Source::OwnInputs { inputs, .. } if inputs.contains(&claimed)
                        ),
                        Item::Settled(_) | Item::Funded { .. } => false,
                    };
                    if locked || item.message() == &record.message {
                        mask |= 1 << i;
                    }
                }
            }
            Evidence::PayPreimage { source, preimage } => {
                let terms = sources
                    .get(source)
                    .and_then(|s| s.terms())
                    .ok_or_else(|| bad("preimage for an untimed or unclaimed source"))?;
                if <[u8; 32]>::from(Sha256::digest(preimage)) != *terms.hash() {
                    return Err(bad("pay preimage hash"));
                }
                for (i, item) in items.iter().enumerate() {
                    if matches!(item, Item::Pending { source: s, branch: Branch::Refund, .. } if s == source)
                    {
                        mask |= 1 << i;
                    }
                }
            }
            // A lock's activation is what shows it paid, not its expiry: the
            // statement can't see one.
            Evidence::Expired { .. } => return Err(bad("expiry voids nothing")),
        }
        if mask == before && !values_fallback {
            return Err(bad("evidence voids nothing"));
        }
    }
    Ok((mask, executed))
}

/// What no evidence voided: settled, funded and timed items, and the fallbacks of
/// the Plain sources shown executed, capped at the claim's amount. Under v4
/// a timed lock's Pay item counts only if the claim advertises an
/// activation of the lock (which [`eligible`] verified on Bitcoin): the
/// statement can't see an expiry, so a Pay without one may have been
/// refunded. And its Refund item counts only once the chain judged, to
/// `judged`, reaches its expiry at depth: any activation is buried by
/// then, so the Hub holds its preimage, and can't be owed the Pay later.
fn live(claim: &UnsignedClaim, mask: u32, executed: &BTreeSet<ProposalId>, judged: u32) -> u32 {
    let sources: BTreeMap<_, _> = claim.parts().sources.iter().map(|s| (s.id(), s)).collect();
    let activated: BTreeSet<_> = claim.parts().activations.iter().map(|a| a.source).collect();
    let mut live = 0u128;
    for (i, item) in claim.parts().items.iter().enumerate() {
        if mask & (1 << i) != 0 {
            continue;
        }
        let valued = match item {
            Item::Settled(_) | Item::Funded { .. } => true,
            Item::Pending { source, branch, .. } => match sources[source].terms() {
                None => executed.contains(source),
                Some(terms) => match branch {
                    Branch::Pay => activated.contains(source),
                    Branch::Refund => terms
                        .expiry()
                        .checked_add(terms.depth())
                        .is_some_and(|settled| judged >= settled),
                },
            },
        };
        if valued {
            live += u128::from(item.message().denomination());
        }
    }
    u32::try_from(live.min(u128::from(claim.amount()))).expect("bounded by amount")
}

/// The public evidence that a claim's items exist, filed with P under the
/// hub-proves model, so that the Hub, not the holder, can evaluate
/// eligibility.
#[derive(Clone)]
pub struct Witness {
    /// The issued note of each settled item, in item order.
    pub notes: Vec<Note>,
    /// The body of each claimed source, in P's (source-id) order.
    pub sources: Vec<SourceWitness>,
    /// The evidence of each advertised activation, in P's order.
    pub activations: Vec<ActivationWitness>,
    /// Of a claim of funded items, every output its Base's holder funded,
    /// in order: what the Base commits to ([`crate::spend::funded_root`]).
    /// Else none.
    pub funded: Vec<crate::spend::Output>,
}

/// An advertised activation's public evidence: its transaction's inclusion
/// and the lock checkpoint it is anchored to (the one the lock's terms
/// name), which must be a block of the chain the statement reads.
#[derive(Clone)]
pub struct ActivationWitness {
    pub inclusion: Inclusion,
    pub anchor: Option<Checkpoint>,
}

/// A claim as filed on Bitcoin under the hub-proves model: P and its public
/// witness W, `LICASH-F\x01 ‖ P ‖ W`, which the holder's publication
/// carries after R (Lichen's claim slot, `licash_statement::claim_script`).
/// Its activations anchored, `LICASH-F\x02 ‖ P ‖ W`, each activation's
/// inclusion followed by its anchor; and of a claim of funded items,
/// `LICASH-F\x03 ‖ P ‖ W`, anchored so, the funded outputs last.
///
/// **Recovery authority.** There is no ownership check: an item is
/// designated by its hold key Q signing this claim's context (P's
/// envelope), and that is the whole of the authority to recover it. So a
/// note can be claimed through any contract, not only one whose Base's spend
/// root derives its owner key, and the claim names no root. Whoever holds a
/// note's Q secret can recover it: the recipient, or anyone given its hold
/// root (exporting it delegates recovery as well as holds). A payer can't: it
/// knows the outputs it made, not their Q secrets. A Q that signs a second
/// claim, anywhere, voids its note in both ([`Evidence::SecondClaim`]).
///
/// **Privacy.** W is public. Beyond P (each item's public fields, its
/// sources and blindings), it shows each settled note's issuer signature and
/// evidence, each source's body (the payer's proposal, owner signatures and
/// input notes, or the issuer's certificate) and each activation's
/// inclusion: the Hub knew them all, and an observer learns the in-flight
/// payments a claim rests on. No root key, spend root or ownership seed is
/// published.
#[derive(Clone)]
pub struct Filing {
    publication: Publication,
    witness: Witness,
}

impl std::fmt::Debug for Filing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Filing(..)")
    }
}

impl Filing {
    /// P with its witness, checked to line up with it: the note of each
    /// settled item, the body of each source, an inclusion for each advertised
    /// activation. Whether they prove anything is [`owed`]'s to decide.
    pub fn new(publication: Publication, witness: Witness) -> Result<Self, Error> {
        let parts = publication.claim().parts();
        let settled: Vec<_> = parts
            .items
            .iter()
            .filter(|item| matches!(item, Item::Settled(_)))
            .map(Item::message)
            .collect();
        if witness.notes.len() != settled.len()
            || witness
                .notes
                .iter()
                .zip(settled)
                .any(|(note, message)| note.message() != message)
            || witness.sources.len() != parts.sources.len()
            || witness
                .sources
                .iter()
                .zip(&parts.sources)
                .any(|(w, source)| w.proposal().id() != source.id())
            || witness.activations.len() != parts.activations.len()
            || witness.activations.iter().any(|a| a.anchor.is_some())
                && witness.activations.iter().any(|a| a.anchor.is_none())
            || parts.items.iter().any(|i| matches!(i, Item::Funded { .. }))
                != !witness.funded.is_empty()
            || !witness.funded.is_empty() && witness.activations.iter().any(|a| a.anchor.is_none())
        {
            return Err(bad("the witness does not line up with P"));
        }
        Ok(Self {
            publication,
            witness,
        })
    }

    pub fn publication(&self) -> &Publication {
        &self.publication
    }
    pub fn witness(&self) -> &Witness {
        &self.witness
    }

    fn anchored(&self) -> bool {
        self.witness.activations.iter().any(|a| a.anchor.is_some())
    }

    pub fn to_bytes(&self, format: Format) -> Vec<u8> {
        let w = &self.witness;
        let magic = match (format.compact(), self.anchored(), w.funded.is_empty()) {
            (false, _, false) => F_MAGIC_FUNDED,
            (false, false, true) => F_MAGIC,
            (false, true, true) => F_MAGIC_ANCHORED,
            (true, _, false) => F_MAGIC_COMPACT_FUNDED,
            (true, false, true) => F_MAGIC_COMPACT,
            (true, true, true) => F_MAGIC_COMPACT_ANCHORED,
        };
        let mut bytes = magic.to_vec();
        put_blob(&mut bytes, &self.publication.to_bytes(format));
        put_count(&mut bytes, w.notes.len());
        for note in &w.notes {
            match format.compact() {
                false => put_blob(&mut bytes, &note.to_bytes()),
                true => put_blob(&mut bytes, &note.to_compact_bytes()),
            }
        }
        put_count(&mut bytes, w.sources.len());
        for source in &w.sources {
            match source {
                SourceWitness::Signed { signed, notes } => {
                    bytes.push(0);
                    put_count(&mut bytes, notes.len());
                    for note in notes {
                        put_blob(&mut bytes, &note.to_bytes());
                    }
                    put_blob(&mut bytes, &signed.to_bytes());
                }
                SourceWitness::Certified {
                    proposal,
                    signatures,
                } => {
                    bytes.push(1);
                    put_blob(&mut bytes, &proposal.commitment_bytes());
                    put_count(&mut bytes, signatures.len());
                    for sig in signatures {
                        bytes.extend(sig.0);
                    }
                }
            }
        }
        put_count(&mut bytes, w.activations.len());
        for ActivationWitness { inclusion, anchor } in &w.activations {
            put_blob(&mut bytes, &inclusion.transaction);
            bytes.extend(inclusion.index.to_be_bytes());
            put_count(&mut bytes, inclusion.siblings.len());
            for sibling in &inclusion.siblings {
                bytes.extend(sibling);
            }
            put_blob(&mut bytes, &inclusion.coinbase);
            put_count(&mut bytes, inclusion.coinbase_siblings.len());
            for sibling in &inclusion.coinbase_siblings {
                bytes.extend(sibling);
            }
            if let Some(anchor) = anchor {
                put_blob(&mut bytes, &anchor.to_bytes());
            }
        }
        if !w.funded.is_empty() {
            put_count(&mut bytes, w.funded.len());
            for output in &w.funded {
                bytes.extend(output.to_bytes());
            }
        }
        bytes
    }

    /// Strict canonical decoding: P as [`Publication::from_bytes`] decodes
    /// it, every note verified under `keyset` and every signed source against
    /// its notes. The keyset and authorization limit are the opening's.
    pub fn from_bytes(
        format: Format,
        keyset: &Keyset,
        limit: usize,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        Self::decode(format, keyset, limit, bytes, true)
    }

    /// [`Filing::from_bytes`], the issuance proof of each settled note and
    /// each hold signature verified only if `checked`: of a lean format
    /// alone, whose statement verifies those of the items it is shown to be
    /// wrong about ([`owed_flagged`]). What it decodes is never to rely on
    /// but through [`owed_flagged`] and [`named`], which check what they
    /// take of it: outside this module there is no filing unchecked.
    fn decode(
        format: Format,
        keyset: &Keyset,
        limit: usize,
        bytes: &[u8],
        checked: bool,
    ) -> Result<Self, Error> {
        if !checked && !format.lean() {
            return Err(bad(
                "a filing is skipped of its checks of a lean format alone",
            ));
        }
        let (plain, anchored_magic, funded_magic) = match format.compact() {
            false => (F_MAGIC, F_MAGIC_ANCHORED, F_MAGIC_FUNDED),
            true => (
                F_MAGIC_COMPACT,
                F_MAGIC_COMPACT_ANCHORED,
                F_MAGIC_COMPACT_FUNDED,
            ),
        };
        let funded = bytes.starts_with(funded_magic);
        let anchored = funded || bytes.starts_with(anchored_magic);
        if bytes.len() > MAX_PUBLICATION_BYTES || !(anchored || bytes.starts_with(plain)) {
            return Err(bad("filing framing"));
        }
        let mut r = Reader(&bytes[plain.len()..]);
        let publication = Publication::decode(format, keyset, limit, r.blob()?, checked)?;
        let notes = |r: &mut Reader, limit| -> Result<Vec<Note>, Error> {
            (0..r.count(limit)?)
                .map(|_| Note::from_bytes(keyset, r.blob()?))
                .collect()
        };
        let settled = match format.compact() {
            false => notes(&mut r, MAX_ITEMS)?,
            // Each settled note is its item's, in order, with no more or
            // fewer than the items settled.
            true => {
                let items = publication.claim().parts().items.iter();
                let messages: Vec<_> = items
                    .filter(|item| matches!(item, Item::Settled(_)))
                    .map(Item::message)
                    .collect();
                if r.count(MAX_ITEMS)? != messages.len() {
                    return Err(bad("filing settled notes"));
                }
                messages
                    .into_iter()
                    .map(|message| match checked {
                        true => Note::from_compact_bytes(keyset, message.clone(), r.blob()?),
                        false => Note::from_compact_unverified(keyset, message.clone(), r.blob()?),
                    })
                    .collect::<Result<_, _>>()?
            }
        };
        let mut sources = Vec::new();
        for _ in 0..r.count(MAX_ITEMS)? {
            sources.push(match r.byte()? {
                0 => {
                    // Verified once, as the spend's inputs it is read with.
                    let notes = (0..r.count(limit)?)
                        .map(|_| Note::from_bytes_unverified(r.blob()?))
                        .collect::<Result<Vec<_>, _>>()?;
                    let signed = SignedProposal::from_bytes(keyset, &notes, r.blob()?)?;
                    SourceWitness::Signed { signed, notes }
                }
                1 => SourceWitness::Certified {
                    proposal: Proposal::from_commitment_bytes(r.blob()?)?,
                    signatures: (0..r.count(limit)?)
                        .map(|_| r.array().map(Signature))
                        .collect::<Result<_, _>>()?,
                },
                _ => return Err(bad("filing source tag")),
            });
        }
        let siblings = |r: &mut Reader| -> Result<Vec<[u8; 32]>, Error> {
            (0..r.count(32)?).map(|_| r.array()).collect()
        };
        let mut activations = Vec::new();
        for _ in 0..r.count(MAX_ITEMS)? {
            let inclusion = Inclusion {
                transaction: r.blob()?.to_vec(),
                index: r.u32()?,
                siblings: siblings(&mut r)?,
                coinbase: r.blob()?.to_vec(),
                coinbase_siblings: siblings(&mut r)?,
            };
            let anchor = match anchored {
                true => Some(Checkpoint::from_bytes(r.blob()?)?),
                false => None,
            };
            activations.push(ActivationWitness { inclusion, anchor });
        }
        let mut outputs = Vec::new();
        if funded {
            for _ in 0..r.count(MAX_ITEMS)? {
                let bytes = r.take(crate::spend::OUTPUT_BYTES)?;
                outputs.push(crate::spend::Output::from_bytes(bytes)?);
            }
        }
        if !r.0.is_empty() {
            return Err(bad("trailing filing bytes"));
        }
        let filing = Self::new(
            publication,
            Witness {
                notes: settled,
                sources,
                activations,
                funded: outputs,
            },
        )?;
        if filing.to_bytes(format) != bytes {
            return Err(bad("noncanonical filing"));
        }
        Ok(filing)
    }
}

/// `filed` as the statement of `base`'s contract reads it: the one decoding
/// of a filing's bytes for all that decides on them, [`owed`] and what the
/// Hub does about a claim besides ([`named`]). Bytes one reads and another
/// refuses leave the Hub answering nothing to a claim its statement would
/// have proven owed less.
fn decoded(base: &Base, filed: &[u8]) -> Result<Filing, Error> {
    let parts = base.parts();
    let format = Format::of(base);
    let limit = parts.limits.max_authorizations as usize;
    Filing::decode(format, &parts.keyset, limit, filed, !format.lean())
}

/// What a filed claim names, as the Hub acts on it besides deciding what
/// it is owed ([`named`]).
#[derive(Clone)]
pub struct Named {
    claim: UnsignedClaim,
    held: Held,
    locks: Vec<Evidence>,
}

impl std::fmt::Debug for Named {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Named(..)")
    }
}

impl Named {
    /// The claim: what the Hub's ledger is asked for evidence against.
    /// Whether an item of it is valid is [`owed`]'s to say.
    pub fn claim(&self) -> &UnsignedClaim {
        &self.claim
    }

    /// The notes its holder gave up for it, whatever it is owed.
    pub fn held(&self) -> &Held {
        &self.held
    }

    /// Each lock of her own notes ([`Source::OwnInputs`]) the claim takes
    /// the refund of with an input it does not hold ([`Named::held`]), as
    /// its filing shows it, signed by the owners of the notes it spends: an
    /// [`Evidence::Spend`] of them, which the Hub may never have served.
    ///
    /// Under a lean format the statement verifies no hold signature of a
    /// lock's inputs: one not its note's neither voids the claim nor is
    /// flagged, and the refund is owed all the same. Such an input is given
    /// up for the claim by its owner's word, the lock, where the others are
    /// by their hold keys', and only the lock shows it spent to any other
    /// claim of it. None of a claim that holds every input of its locks,
    /// as every filing a wallet makes does.
    ///
    /// Only of a refund hers to take: an item of the lock's refund that its
    /// hold key signed for and that opens the output it names. Who merely
    /// holds a lock another signed, as its payee does, shows none of it,
    /// and gives up no note of its payer's.
    pub fn locks(&self) -> &[Evidence] {
        &self.locks
    }
}

/// What the claim filed as `filed` under `base` names: read exactly as
/// [`owed`] reads it, so that the Hub finds its evidence against, and
/// retires the notes of, every filing its statement decides on. An error
/// only of bytes [`owed`] finds ineligible as undecodable.
///
/// Under a lean format one invalid item does not void the claim, and it
/// does not blind the Hub to the rest either: the claim is the whole of
/// what was filed, and [`Named::held`] the authorizations that verify,
/// whether or not the note of each was ever issued.
pub fn named(base: &Base, filed: &[u8]) -> Result<Named, Error> {
    let filing = decoded(base, filed)?;
    let keyset = &base.parts().keyset;
    let claim = filing.publication.claim();
    let held = filing.publication.held();
    let holds = |message: &Message| held.records.iter().any(|r| &r.message == message);
    // A refund of `lock` that is hers: signed for, and opening its output.
    let refunded = |id: ProposalId, lock: &crate::spend::TimedLock| {
        claim.parts().items.iter().any(|item| match item {
            Item::Pending {
                message,
                source,
                branch: Branch::Refund,
                index,
                blinding,
                ..
            } => {
                *source == id
                    && holds(message)
                    && (lock.refund().get(*index as usize))
                        .is_some_and(|output| opens(output, message, blinding).unwrap_or(false))
            }
            _ => false,
        })
    };
    let sources = claim.parts().sources.iter().zip(&filing.witness.sources);
    let locks = sources
        .filter_map(|(source, witness)| {
            let (Source::OwnInputs { id, .. }, SourceWitness::Signed { signed, notes }) =
                (source, witness)
            else {
                return None;
            };
            let lock = signed.proposal().lock()?;
            let shown = matches!(signed.authorization(), Authorization::Plain)
                && witness.authenticate(keyset, source).is_ok()
                && notes.iter().any(|note| !holds(note.message()))
                && refunded(*id, lock);
            shown.then(|| Evidence::Spend {
                signed: signed.clone(),
                notes: notes.clone(),
                unlock: None,
            })
        })
        .collect();
    Ok(Named {
        claim: claim.clone(),
        held,
        locks,
    })
}

/// Whether a decoded filing is eligible under this opening and request: an
/// error is the holder's, and leaves the claim owed nothing.
///
/// A lock may name any checkpoint on the chain the statement reads, its
/// activation anchored to it, and a Pay is owed only with an activation
/// ([`live`]).
fn eligible(filing: &Filing, base: &Base, request: &Request, chain: &Chain) -> Result<(), Error> {
    let publication = &filing.publication;
    publication.bind(base, request)?;
    let parts = base.parts();
    let claim = publication.claim();
    let sources = &claim.parts().sources;
    for (source, w) in sources.iter().zip(&filing.witness.sources) {
        w.authenticate(&parts.keyset, source)?;
    }
    let metadata: BTreeMap<_, _> = sources.iter().map(|s| (s.id(), s)).collect();
    let bodies: BTreeMap<_, _> = filing
        .witness
        .sources
        .iter()
        .map(|w| (w.proposal().id(), w.proposal()))
        .collect();
    let funded = &filing.witness.funded;
    if !funded.is_empty() {
        let root = crate::spend::funded_root(funded)?;
        if base.parts().funded != root {
            return Err(bad("funded outputs not those Base commits to"));
        }
        // What she funded is what the outputs are worth: no more is owed.
        let worth = funded
            .iter()
            .try_fold(0u64, |s, o| s.checked_add(o.denomination()));
        if worth != Some(u64::from(parts.graph.deposit_units)) {
            return Err(bad("funded outputs not worth what she funded"));
        }
    }
    for item in &claim.parts().items {
        let Item::Funded {
            message,
            index,
            blinding,
        } = item
        else {
            continue;
        };
        let output = funded
            .get(*index as usize)
            .ok_or_else(|| bad("claimed funded output index"))?;
        if !opens(output, message, blinding)? {
            return Err(bad("funded item does not open its output"));
        }
    }
    for item in &claim.parts().items {
        let Item::Pending {
            message,
            source,
            branch,
            index,
            blinding,
            ..
        } = item
        else {
            continue;
        };
        let outputs = match branch {
            Branch::Pay => bodies[source].outputs(),
            Branch::Refund => bodies[source]
                .lock()
                .ok_or_else(|| bad("refund of an untimed source"))?
                .refund(),
        };
        let output = outputs
            .get(*index as usize)
            .ok_or_else(|| bad("claimed source output index"))?;
        if !opens(output, message, blinding)? {
            return Err(bad("pending item does not open its source output"));
        }
    }
    let max = parts.limits.max_transaction_bytes as usize;
    for (record, w) in claim
        .parts()
        .activations
        .iter()
        .zip(&filing.witness.activations)
    {
        let terms = metadata[&record.source]
            .terms()
            .expect("admitted source is timed");
        let anchor = w
            .anchor
            .as_ref()
            .ok_or_else(|| bad("an activation without its lock checkpoint"))?;
        Activation {
            reference: record.reference,
            inclusion: w.inclusion.clone(),
        }
        .verify(chain, anchor, terms, max)?;
    }
    Ok(())
}

/// What the Hub's statement decides of a filed claim ([`owed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owed {
    /// What the claim is owed: the `b′` the Hub's response signs.
    pub owed: u32,
    /// Bit i: item i voided by the Hub's evidence.
    pub mask: u32,
    /// Bit i: item i invalid (its note not issued, its hold signature not
    /// its note's), under a lean format ([`Format::Lean`]): worth nothing,
    /// the others as ever. The Hub's statement takes it as an input and
    /// verifies the items it flags, and only those ([`owed_flagged`]).
    pub invalid: u32,
    /// What the Hub's response must disclose ([`disclosures`]): nothing if
    /// every slot is empty.
    pub disclosures: Disclosures,
    /// Why the claim is owed nothing, if the holder filed it wrong.
    pub ineligible: Option<String>,
}

/// The Hub's statement under the hub-proves model: what the claim filed as
/// `filed` (a filing's bytes, [`Filing::to_bytes`]) is owed under request R.
///
/// A claim the holder got wrong is ineligible, and owed 0: bytes that don't
/// decode, a P for another opening or request, a note the issuer didn't
/// sign, a source body that doesn't authenticate or an output it doesn't
/// open, a funded item that doesn't open an output her Base commits to, an
/// activation `chain` doesn't bury at its terms' depth, after the lock's
/// checkpoint, which must be a block of `chain`. Otherwise the claim is
/// owed what the Hub's evidence leaves live, capped at its amount: with no
/// evidence, its amount, less any lock's Pay it advertises no
/// activation of and any lock's Refund `chain` doesn't reach the expiry of
/// at depth.
///
/// An error is the Hub's, and it can't prove with these inputs: evidence
/// that doesn't verify or voids nothing, evidence against an ineligible
/// claim, or a chain not from Base's checkpoint. The statement fixes
/// `chain` (from Base's checkpoint through the block of the claim's
/// publication), so the Hub can't shorten it to bury an activation less,
/// and decides at signing what it proves later.
pub fn owed(
    base: &Base,
    request: &Request,
    filed: &[u8],
    evidence: &[Evidence],
    chain: &Chain,
) -> Result<Owed, Error> {
    judged(base, request, filed, evidence, chain, None)
}

/// [`owed`] as the Hub's statement computes it under a lean format
/// ([`Format::Lean`]): the items `invalid` flags verified, as the Hub says
/// they are not valid, and no others, which are taken as they are. A flagged
/// item that verifies is the Hub's error, as is a flag beyond the claim's
/// items; under another format, any flag is. Of a claim the Hub found fully
/// valid, [`owed`] is this with no flags, and the same amount: what it
/// skips can only raise it, so the Hub must flag what is invalid to prove
/// the claim owed less, and the holder checks only what it flags.
pub fn owed_flagged(
    base: &Base,
    request: &Request,
    filed: &[u8],
    evidence: &[Evidence],
    chain: &Chain,
    invalid: u32,
) -> Result<Owed, Error> {
    judged(base, request, filed, evidence, chain, Some(invalid))
}

/// [`owed`] if `flagged` is none, which finds the invalid items of a lean
/// filing itself, else [`owed_flagged`].
fn judged(
    base: &Base,
    request: &Request,
    filed: &[u8],
    evidence: &[Evidence],
    chain: &Chain,
    flagged: Option<u32>,
) -> Result<Owed, Error> {
    let parts = base.parts();
    let format = Format::of(base);
    if flagged.is_some_and(|flags| flags != 0) && !format.lean() {
        return Err(bad("items are flagged of a lean filing alone"));
    }
    if chain.checkpoint().commitment() != parts.chain.checkpoint.commitment() {
        return Err(bad("the chain is not from Base's checkpoint"));
    }
    let filing = decoded(base, filed)
        .and_then(|filing| eligible(&filing, base, request, chain).map(|()| filing));
    let filing = match filing {
        Ok(filing) => filing,
        Err(_) if !evidence.is_empty() => {
            return Err(bad("evidence against an ineligible claim"));
        }
        Err(e) => {
            return Ok(Owed {
                owed: 0,
                mask: 0,
                invalid: 0,
                disclosures: Disclosures::empty(),
                ineligible: Some(e.to_string()),
            })
        }
    };
    let claim = filing.publication.claim();
    let invalid = match format.lean() {
        true => invalid_items(&filing, &parts.keyset, flagged)?,
        false => 0,
    };
    let (mask, executed) = void(&parts.keyset, parts.graph.id, claim, evidence)?;
    Ok(Owed {
        owed: live(claim, mask | invalid, &executed, chain.tip_height()),
        mask,
        invalid,
        disclosures: disclosures(evidence)?,
        ineligible: None,
    })
}

/// The items of a lean filing that are invalid, as a mask: those `flagged`,
/// each verified to be, or, if none, every one that is.
fn invalid_items(filing: &Filing, keyset: &Keyset, flagged: Option<u32>) -> Result<u32, Error> {
    let items = filing.publication.claim().parts().items.len();
    let invalid = |i: usize| item_valid(filing, keyset, i).is_err();
    match flagged {
        None => Ok((0..items)
            .filter(|&i| invalid(i))
            .fold(0, |mask, i| mask | 1 << i)),
        Some(flags) => {
            if items < 32 && flags >> items != 0 {
                return Err(bad("an item flagged that the claim has not"));
            }
            for i in (0..items).filter(|i| flags & (1 << i) != 0) {
                if !invalid(i) {
                    return Err(bad("an item flagged invalid that is valid"));
                }
            }
            Ok(flags)
        }
    }
}

/// Whether item `i` of a lean filing is valid: its hold key signed the
/// claim and, settled, its note is the issuer's, and, of a lock of her own
/// inputs, so are the notes it spent, which the lock's outputs stand on.
fn item_valid(filing: &Filing, keyset: &Keyset, i: usize) -> Result<(), Error> {
    let claim = filing.publication.claim();
    let items = &claim.parts().items;
    let check = |k: usize| -> Result<(), Error> {
        filing
            .publication
            .envelope()
            .verify_record(items[k].message())?;
        if let Item::Settled(_) = &items[k] {
            let at = items[..k]
                .iter()
                .filter(|item| matches!(item, Item::Settled(_)))
                .count();
            filing.witness.notes[at].verify(keyset)?;
        }
        Ok(())
    };
    check(i)?;
    if let Item::Pending { source, .. } = &items[i] {
        let spent = claim.parts().sources.iter().find_map(|s| match s {
            Source::OwnInputs { id, inputs, .. } if id == source => Some(inputs),
            _ => None,
        });
        for (k, item) in items.iter().enumerate() {
            let on = matches!(item, Item::Settled(_))
                && spent.is_some_and(|inputs| {
                    item.message()
                        .identifier()
                        .is_ok_and(|y| inputs.contains(&y))
                });
            if on {
                check(k)?;
            }
        }
    }
    Ok(())
}
