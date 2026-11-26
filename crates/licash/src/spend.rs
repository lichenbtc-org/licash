//! Unsigned spend proposal commitments, not authorization or a spend ledger.
//!
//! The body excludes issuance witnesses and any later grant-dependent owner
//! authorization. Decoding checks structure, not issuer evidence, ownership,
//! spentness, admission, activation, or recovery capacity.

use std::collections::BTreeSet;

use crate::{
    crypto::{generator_mul, tagged_hash, Point, ScalarBytes},
    note::{non_identity, Derivation, Keyset, Message, Note, MESSAGE_BYTES},
    Error,
};

const TAG: &[u8] = b"LICASH-SP\x02";
pub const OUTPUT_BYTES: usize = 8 + 33 + 32;

/// The most inputs a proposal spends. A spend is evidence against a claim
/// of any of its notes, and a statement reads at most its Base's
/// `max_authorizations` notes of one (never fewer than this,
/// [`crate::base`]): a spend of more could never be cited, and a hub that
/// retired its notes would answer nothing to a claim of one.
pub const MAX_INPUTS: usize = 64;

/// The most outputs of one branch of a proposal: two splits of an amount in
/// every denomination a keyset has, a payment and its change. With
/// [`MAX_INPUTS`], its signed proposal fits the bytes a statement reads of
/// one ([`crate::recovery::MAX_PUBLICATION_BYTES`]), granted or a lock.
pub const MAX_OUTPUTS: usize = 128;
pub const TIMED_TERMS_BYTES: usize = 1 + 32 + 4 + 4 + 32;

/// A proposal's commitment bytes before its inputs' count: its tag, keyset
/// and ephemeral key.
const BODY_HEAD_BYTES: usize = TAG.len() + 32 + 33;

/// The most bytes a proposal commits to ([`Proposal::commitment_bytes`]): a
/// lock of [`MAX_INPUTS`] notes with [`MAX_OUTPUTS`] outputs on each branch.
pub const MAX_BODY_BYTES: usize = BODY_HEAD_BYTES
    + 4
    + MAX_INPUTS * MESSAGE_BYTES
    + 2 * (4 + MAX_OUTPUTS * OUTPUT_BYTES)
    + 1
    + TIMED_TERMS_BYTES;

fn bad(reason: &str) -> Error {
    Error::Protocol(reason.into())
}

/// A source proposal identity, deliberately not a signed-spend authority.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct ProposalId([u8; 32]);

impl ProposalId {
    /// Opaque external identifier. This authenticates no proposal body.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for ProposalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProposalId(..)")
    }
}

/// The chains Licash follows, each under the consensus rules of its node.
///
/// The signets are for testing only: their block signature is in the
/// coinbase, not the header, so header checks alone cannot tell a signet
/// block from one anybody mined at its low difficulty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainProfile {
    Core30Mainnet,
    Core30DefaultRegtest,
    /// The default signet.
    Core30Signet,
    /// Mutinynet: a signet with blocks every 30 seconds.
    Mutinynet,
}

impl ChainProfile {
    /// Every profile.
    pub const ALL: [Self; 4] = [
        Self::Core30Mainnet,
        Self::Core30DefaultRegtest,
        Self::Core30Signet,
        Self::Mutinynet,
    ];

    /// Its byte in encodings. Tag 2 is unassigned.
    pub fn tag(self) -> u8 {
        match self {
            Self::Core30Mainnet => 0,
            Self::Core30DefaultRegtest => 1,
            Self::Core30Signet => 3,
            Self::Mutinynet => 4,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.tag() == tag)
    }

    /// Its network's name: `bitcoin`, `regtest`, `signet` or `mutinynet`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Core30Mainnet => "bitcoin",
            Self::Core30DefaultRegtest => "regtest",
            Self::Core30Signet => "signet",
            Self::Mutinynet => "mutinynet",
        }
    }

    /// Whether its coins are for testing only.
    pub fn is_test(self) -> bool {
        self != Self::Core30Mainnet
    }

    /// Blocks between retargets of the difficulty, or none if fixed.
    pub fn retarget_interval(self) -> Option<u32> {
        match self {
            Self::Core30Mainnet | Self::Core30Signet => Some(2016),
            Self::Mutinynet => Some(40_320),
            Self::Core30DefaultRegtest => None,
        }
    }

    /// The seconds the chain aims to take for a block.
    pub fn block_seconds(self) -> u32 {
        match self {
            Self::Mutinynet => 30,
            _ => 600,
        }
    }

    /// Blocks a day at its block time: 144 on Bitcoin, 2,880 on Mutinynet.
    /// For the time a count of blocks takes, and for interest by the year.
    /// The protocol's windows, depths and margins are counted in blocks, the
    /// same on every network: this is not their unit.
    pub fn blocks_a_day(self) -> u32 {
        86_400 / self.block_seconds()
    }

    /// Blocks a year at its block time: what a contract's interest by the
    /// year counts ([`blocks_a_day`](Self::blocks_a_day) of 365 days).
    pub fn blocks_a_year(self) -> u32 {
        self.blocks_a_day() * 365
    }
}

impl std::fmt::Display for ChainProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for ChainProfile {
    type Err = Error;

    /// A profile by its network's [`name`](Self::name).
    fn from_str(name: &str) -> Result<Self, Error> {
        Self::ALL
            .into_iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| bad("unknown network: bitcoin, regtest, signet or mutinynet"))
    }
}

/// Source-bound public activation terms. A digest alone authenticates no
/// checkpoint history. Admission must match its profile and lower scan height
/// and check expiry against that anchor, before checking the actual ancestry.
#[derive(Clone, PartialEq, Eq)]
pub struct TimedTerms {
    profile: ChainProfile,
    checkpoint: [u8; 32],
    expiry: u32,
    depth: u32,
    hash: [u8; 32],
}

impl std::fmt::Debug for TimedTerms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TimedTerms(..)")
    }
}

impl TimedTerms {
    pub fn new(
        profile: ChainProfile,
        checkpoint: [u8; 32],
        expiry: u32,
        depth: u32,
        hash: [u8; 32],
    ) -> Result<Self, Error> {
        if expiry == 0 || depth == 0 || expiry.checked_add(depth).is_none() {
            return Err(bad("invalid timed activation horizon"));
        }
        Ok(Self {
            profile,
            checkpoint,
            expiry,
            depth,
            hash,
        })
    }

    pub fn profile(&self) -> ChainProfile {
        self.profile
    }
    pub fn checkpoint(&self) -> &[u8; 32] {
        &self.checkpoint
    }
    pub fn expiry(&self) -> u32 {
        self.expiry
    }
    pub fn depth(&self) -> u32 {
        self.depth
    }
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn to_bytes(&self) -> [u8; TIMED_TERMS_BYTES] {
        let mut bytes = [0; TIMED_TERMS_BYTES];
        bytes[0] = self.profile.tag();
        bytes[1..33].copy_from_slice(&self.checkpoint);
        bytes[33..37].copy_from_slice(&self.expiry.to_be_bytes());
        bytes[37..41].copy_from_slice(&self.depth.to_be_bytes());
        bytes[41..].copy_from_slice(&self.hash);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TIMED_TERMS_BYTES {
            return Err(bad("timed terms length"));
        }
        Self::decode(&mut Reader(bytes))
    }

    /// Same fixed public metadata root as the isolated certificate model.
    pub fn root(&self) -> [u8; 32] {
        tagged_hash("licash/timed-lock-terms/v1", &[&self.to_bytes()])
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, Error> {
        let profile = ChainProfile::from_tag(reader.array::<1>()?[0])
            .ok_or_else(|| bad("unknown activation chain profile"))?;
        Self::new(
            profile,
            reader.array()?,
            reader.u32()?,
            reader.u32()?,
            reader.array()?,
        )
    }
}

/// Output intent only. The commitment must match the recipient's private
/// derivation when accepting a receipt; structure alone cannot establish it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Output {
    denom: u64,
    blinded: Point,
    unlink_commitment: [u8; 32],
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpendOutput(..)")
    }
}

impl Output {
    pub fn new(denom: u64, blinded: Point, unlink_commitment: [u8; 32]) -> Result<Self, Error> {
        if denom == 0 {
            return Err(bad("zero output denomination"));
        }
        non_identity(&blinded)?;
        Ok(Self {
            denom,
            blinded,
            unlink_commitment,
        })
    }

    pub fn from_derivation(output: &Derivation) -> Result<Self, Error> {
        Self::new(
            output.message().denomination(),
            output.blinded()?,
            output.unlink_commitment(),
        )
    }

    pub fn denomination(&self) -> u64 {
        self.denom
    }
    pub fn blinded(&self) -> Point {
        self.blinded
    }
    pub fn unlink_commitment(&self) -> &[u8; 32] {
        &self.unlink_commitment
    }

    /// Whether `message` blinded by `blinding` is this output: what a claim
    /// of it as an item opens it with. Says nothing of its unlink
    /// commitment, nor of who may sign for `message`.
    pub fn opened_by(&self, message: &Message, blinding: &ScalarBytes) -> Result<bool, Error> {
        let blinded =
            message.identifier()?.to_projective()? + generator_mul(&blinding.to_scalar()?);
        Ok(
            self.denom == message.denomination()
                && self.blinded == Point::from_projective(&blinded),
        )
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.denom.to_be_bytes());
        bytes.extend(self.blinded.0);
        bytes.extend(self.unlink_commitment);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(OUTPUT_BYTES);
        self.encode(&mut bytes);
        bytes
    }

    /// Exactly [`OUTPUT_BYTES`] of [`Output::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != OUTPUT_BYTES {
            return Err(bad("output length"));
        }
        Self::decode(&mut Reader(bytes))
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, Error> {
        Self::new(
            u64::from_be_bytes(reader.array()?),
            Point(reader.array()?),
            reader.array()?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TimedLock {
    terms: TimedTerms,
    refund: Vec<Output>,
}

impl std::fmt::Debug for TimedLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TimedLock(..)")
    }
}

impl TimedLock {
    pub fn new(terms: TimedTerms, refund: Vec<Output>) -> Result<Self, Error> {
        bounded(&refund, MAX_OUTPUTS)?;
        Ok(Self { terms, refund })
    }
    pub fn terms(&self) -> &TimedTerms {
        &self.terms
    }
    pub fn refund(&self) -> &[Output] {
        &self.refund
    }
}

/// Ordered unsigned body. Neither its ID nor verified issuance witnesses
/// authorize consumption. Owner signatures and a complete grant must be
/// checked by a later, separate authorization layer before any state change.
#[derive(Clone, PartialEq, Eq)]
pub struct Proposal {
    keyset: [u8; 32],
    eph: Point,
    inputs: Vec<Message>,
    outputs: Vec<Output>,
    lock: Option<TimedLock>,
}

impl std::fmt::Debug for Proposal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SpendProposal(..)")
    }
}

impl Proposal {
    /// Build from authenticated notes. This is still an unsigned proposal.
    pub fn new(
        keyset: &Keyset,
        notes: &[Note],
        eph: Point,
        outputs: Vec<Output>,
        lock: Option<TimedLock>,
    ) -> Result<Self, Error> {
        let proposal = Self {
            keyset: *keyset.id(),
            eph,
            inputs: notes.iter().map(|note| note.message().clone()).collect(),
            outputs,
            lock,
        };
        proposal.verify_structure()?;
        proposal.verify(keyset, notes)?;
        Ok(proposal)
    }

    pub fn keyset_id(&self) -> &[u8; 32] {
        &self.keyset
    }
    pub fn ephemeral(&self) -> Point {
        self.eph
    }
    pub fn inputs(&self) -> &[Message] {
        &self.inputs
    }
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }
    pub fn lock(&self) -> Option<&TimedLock> {
        self.lock.as_ref()
    }

    /// Issuance evidence is a separate witness. Both C and proof variants are
    /// intentionally outside the source ID, but never outside this cash check.
    /// Third-party evidence path, not a private issuer submission shape: Linked
    /// evidence discloses blinding. Uncertified paths must call this check, not
    /// accept a Proposal as cash authority. Certificate-backed source matching
    /// separately delegates input validity to the debtor's admission signature.
    /// Keyset is caller-authenticated context, never a keyset trusted merely
    /// because an untrusted bundle names its ID. Returned Ys are in body order;
    /// the separate canonical certificate input root must sort a copy of them.
    pub fn verify(&self, keyset: &Keyset, notes: &[Note]) -> Result<Vec<Point>, Error> {
        if &self.keyset != keyset.id() || notes.len() != self.inputs.len() {
            return Err(bad("proposal input witness context"));
        }
        let mut identifiers = Vec::new();
        for (message, note) in self.inputs.iter().zip(notes) {
            if note.message() != message {
                return Err(bad("proposal input witness order or message"));
            }
            note.verify(keyset)?;
            identifiers.push(message.identifier()?);
        }
        self.verify_output_denominations(keyset)?;
        Ok(identifiers)
    }

    /// Typed constructors/decoders establish structure; this adds expected
    /// keyset and declared denomination checks, never input issuance evidence.
    pub(crate) fn verify_declared_context(&self, keyset: &Keyset) -> Result<(), Error> {
        if &self.keyset != keyset.id() {
            return Err(bad("proposal input witness context"));
        }
        for input in &self.inputs {
            keyset.key(input.denomination())?;
        }
        self.verify_output_denominations(keyset)
    }

    fn verify_output_denominations(&self, keyset: &Keyset) -> Result<(), Error> {
        for output in self
            .outputs
            .iter()
            .chain(self.lock.iter().flat_map(|lock| &lock.refund))
        {
            keyset.key(output.denom)?;
        }
        Ok(())
    }

    fn verify_structure(&self) -> Result<(), Error> {
        non_identity(&self.eph)?;
        bounded(&self.inputs, MAX_INPUTS)?;
        let mut seen = BTreeSet::new();
        let mut total = 0u128;
        for input in &self.inputs {
            if !seen.insert(input.to_bytes()) {
                return Err(bad("duplicate proposal input"));
            }
            total = total
                .checked_add(u128::from(input.denomination()))
                .ok_or_else(|| bad("input value overflow"))?;
        }
        let mut targets = BTreeSet::new();
        let mut check_outputs = |outputs: &[Output]| -> Result<(), Error> {
            bounded(outputs, MAX_OUTPUTS)?;
            let mut value = 0u128;
            for output in outputs {
                non_identity(&output.blinded)?;
                if !targets.insert(output.blinded) {
                    return Err(bad("duplicate proposal output"));
                }
                value = value
                    .checked_add(u128::from(output.denom))
                    .ok_or_else(|| bad("output value overflow"))?;
            }
            if value != total {
                return Err(bad("proposal branch value mismatch"));
            }
            Ok(())
        };
        check_outputs(&self.outputs)?;
        if let Some(lock) = &self.lock {
            check_outputs(&lock.refund)?;
        }
        Ok(())
    }

    /// Canonical commitment body, not a complete signed-source wire message.
    /// No proof, signature, grant, activation witness or private capability is
    /// included. Preserve order because output positions identify receipts.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = TAG.to_vec();
        bytes.extend(self.keyset);
        bytes.extend(self.eph.0);
        bytes.extend(count(&self.inputs).expect("validated inputs").to_be_bytes());
        for input in &self.inputs {
            bytes.extend(input.to_bytes());
        }
        encode_outputs(&self.outputs, &mut bytes);
        match &self.lock {
            None => bytes.push(0),
            Some(lock) => {
                bytes.push(1); // explicit presence under the new proposal tag
                bytes.extend(lock.terms.to_bytes());
                encode_outputs(&lock.refund, &mut bytes);
            }
        }
        bytes
    }

    pub fn id(&self) -> ProposalId {
        body_id(&self.commitment_bytes())
    }

    /// Structural decoding only. A valid body can still have no valid issuer
    /// witness, supported keyset/denominations or owner authorization. Call
    /// verify separately; this decoder is deliberately context-free.
    pub fn from_commitment_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader(bytes);
        if reader.take(TAG.len())? != TAG {
            return Err(bad("proposal tag"));
        }
        let keyset_id = reader.array()?;
        let eph = Point(reader.array()?);
        let n = reader.count(MESSAGE_BYTES)?;
        let mut inputs = Vec::new();
        for _ in 0..n {
            inputs.push(Message::from_bytes(reader.take(MESSAGE_BYTES)?)?);
        }
        let outputs = decode_outputs(&mut reader)?;
        let lock = match reader.array::<1>()?[0] {
            0 => None,
            1 => {
                if reader.0.len() < TIMED_TERMS_BYTES {
                    return Err(bad("truncated timed terms"));
                }
                Some(TimedLock::new(
                    TimedTerms::decode(&mut reader)?,
                    decode_outputs(&mut reader)?,
                )?)
            }
            _ => return Err(bad("unknown proposal lock tag")),
        };
        if !reader.0.is_empty() {
            return Err(bad("trailing proposal bytes"));
        }
        let proposal = Self {
            keyset: keyset_id,
            eph,
            inputs,
            outputs,
            lock,
        };
        proposal.verify_structure()?;
        Ok(proposal)
    }
}

fn count<T>(items: &[T]) -> Result<u32, Error> {
    if items.is_empty() {
        return Err(bad("empty proposal vector"));
    }
    u32::try_from(items.len()).map_err(|_| bad("proposal count overflow"))
}

/// [`count`], and no more than `most`.
fn bounded<T>(items: &[T], most: usize) -> Result<u32, Error> {
    if items.len() > most {
        return Err(bad("more inputs or outputs than a proposal may have"));
    }
    count(items)
}

/// The id of the proposal that commits to `body`
/// ([`Proposal::commitment_bytes`]), with nothing of it read. Whoever signed
/// the id knows what the bytes say; whoever only cites her signature need
/// not ([`body_input`]).
pub fn body_id(body: &[u8]) -> ProposalId {
    ProposalId(tagged_hash("licash/source-proposal/v2", &[body]))
}

/// Input `index` of the proposal of `keyset` that commits to `body`, read
/// where it lies: nothing else of the body is decoded, so reading it costs
/// the same whatever the proposal spends and makes. The body is one a
/// proposal may have as far as it is read: its tag, its keyset, from one
/// to [`MAX_INPUTS`] inputs, no more than [`MAX_BODY_BYTES`]. Whether the
/// rest of it is a proposal is for whoever signed its id to have known.
pub fn body_input(keyset: &[u8; 32], body: &[u8], index: u32) -> Result<Message, Error> {
    if body.len() > MAX_BODY_BYTES {
        return Err(bad("proposal body too long"));
    }
    let head = body
        .get(..BODY_HEAD_BYTES + 4)
        .ok_or_else(|| bad("truncated proposal body"))?;
    if &head[..TAG.len()] != TAG {
        return Err(bad("proposal tag"));
    }
    if &head[TAG.len()..TAG.len() + 32] != keyset {
        return Err(bad("proposal keyset"));
    }
    let inputs = u32::from_be_bytes(head[BODY_HEAD_BYTES..].try_into().expect("four bytes"));
    if inputs == 0 || inputs as usize > MAX_INPUTS {
        return Err(bad("proposal body input count"));
    }
    if index >= inputs {
        return Err(bad("proposal body input index"));
    }
    // Bounded by MAX_INPUTS, so nothing here overflows.
    let at = BODY_HEAD_BYTES + 4 + index as usize * MESSAGE_BYTES;
    let bytes = body
        .get(at..at + MESSAGE_BYTES)
        .ok_or_else(|| bad("truncated proposal body"))?;
    Message::from_bytes(bytes)
}

/// The commitment a Base makes to the outputs its holder funds, in
/// order: refused if there are none.
pub fn funded_root(outputs: &[Output]) -> Result<[u8; 32], Error> {
    count(outputs)?;
    let mut bytes = Vec::new();
    encode_outputs(outputs, &mut bytes);
    Ok(tagged_hash("licash/funded-outputs/v1", &[&bytes]))
}

fn encode_outputs(outputs: &[Output], bytes: &mut Vec<u8>) {
    bytes.extend(count(outputs).expect("validated outputs").to_be_bytes());
    for output in outputs {
        output.encode(bytes);
    }
}

fn decode_outputs(reader: &mut Reader<'_>) -> Result<Vec<Output>, Error> {
    let n = reader.count(OUTPUT_BYTES)?;
    let mut outputs = Vec::new();
    for _ in 0..n {
        outputs.push(Output::decode(reader)?);
    }
    Ok(outputs)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(bad("truncated proposal body"));
        }
        let (bytes, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("checked field width"))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn count(&mut self, width: usize) -> Result<usize, Error> {
        let n = usize::try_from(self.u32()?).map_err(|_| bad("proposal count overflow"))?;
        // Check before looping or allocating. This is a framing bound, not
        // a measured production witness or source-capacity profile.
        if n == 0 || n > self.0.len() / width {
            return Err(bad("proposal count exceeds body"));
        }
        Ok(n)
    }
}

/// The hash of a timed lock's preimage: SHA256, as in Bitcoin and Lightning.
pub fn lock_hash(preimage: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(preimage).into()
}
