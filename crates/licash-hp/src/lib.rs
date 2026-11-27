//! The Hub's statement for a Licash recovery on Lichen's hub-proves exit:
//! "the claim the holder's publication carries is owed at most `b′`".
//!
//! What Bitcoin shows of the exit (her `request` of `b` and `E`, her
//! publication of the claim, the Hub's `respond` of `b′` and its
//! disclosure) is `licash_statement`'s to read ([`licash_statement::read`]).
//! What the claim is owed is Licash's: [`licash::recovery::owed`] of the
//! publication's bytes (a [`licash::recovery::Filing`]) under the request
//! `(b, E)`, against the Hub's evidence, on the Licash chain from Base's
//! checkpoint through the publication's block ([`chain`]). The statement
//! holds if that is at most `b′`, and the response disclosed what the
//! evidence needs (the unlocks and preimages it cites).
//!
//! The statement is fixed when the contract opens ([`contract`]): its
//! journal is `licash_statement`'s, `c ‖ word ‖ H(O_D ‖ checkpoint ‖ W)`,
//! with Licash's word `H("licash/hp/word" ‖ Base digest)`. Base fixes the
//! keyset, the limits, the checkpoint and the work, and its digest is what
//! every claim's context binds, so a proof for one contract is useless for
//! any other.
//!
//! The statement also checks her request's one-time
//! signatures on `b` and `E` against the keys Base binds
//! ([`RequestKeys`]): only she can sign a request, so no proof can be made
//! of an exit she didn't start, on any chain, however long before.
//!
//! The holder garbles for this journal at opening (BABE with the roles
//! swapped); the Hub evaluates [`check`] natively to decide its response
//! (the same chain, the same evidence), and proves it in `r0/hp-guest`
//! only when it contests the claim, for the assertion that follows its
//! response.

pub mod headers;

use bitcoin::hashes::{hash160, Hash};
use headers::{ChainProof, View};
use licash::{
    base::Base,
    chain::Chain,
    crypto::tagged_hash,
    disclosure::Disclosures,
    recovery::{self, Evidence, Format, Owed},
    request::Request,
};
use licash_statement::{
    btc::{self, Header, OutPoint},
    checksum_digits,
    codec::{R, W},
    script_digit, Carrier, Checkpoint, Contract, Exit, Payout, Read, Reject, JOURNAL_LEN,
};
use sha2::{Digest, Sha256};

/// Licash names a contract by its Base digest (in the word), not by a
/// number: `c` is always this.
pub const C: u32 = 0;

/// Why the Hub can't prove with an input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The input doesn't decode.
    Input,
    /// Bitcoin doesn't show the exit, as `licash_statement` reads it.
    Exit(Reject),
    /// The headers through the publication aren't a Licash chain from
    /// Base's checkpoint.
    Chain(String),
    /// The Hub's evidence doesn't prove what it says (licash's reason).
    Evidence(String),
    /// Her request isn't signed under the one-time keys her Base binds,
    /// or the input's keys aren't those.
    Unsigned,
    /// The response didn't disclose what the evidence needs.
    Undisclosed,
    /// The claim is owed more than `b′`.
    Owed,
    /// The claim's judgment reads blocks of the chain that the input does not
    /// open (their heights): the Hub can't prove with it, and the claim is
    /// not owed nothing for it.
    Openings(Vec<u32>),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Input => f.write_str("the statement's input doesn't decode"),
            Refusal::Exit(r) => write!(f, "the exit doesn't read: {r:?}"),
            Refusal::Chain(e) => write!(f, "the chain doesn't verify: {e}"),
            Refusal::Evidence(e) => write!(f, "the evidence doesn't prove: {e}"),
            Refusal::Unsigned => f.write_str("her request isn't signed under the keys Base binds"),
            Refusal::Undisclosed => f.write_str("the response didn't disclose what is needed"),
            Refusal::Owed => f.write_str("the claim is owed more than the response says"),
            Refusal::Openings(h) => write!(f, "blocks of the chain are not opened: {h:?}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// The payout of `base`, by which the statement reads a signed word: its
/// bits, those it has no outputs below, and the rest of a cap past them
/// ([`licash::base::Parts::rest`]). The payout the contract's terms build
/// (Lichen's `Terms::payout`).
pub fn payout(base: &Base) -> Payout {
    let p = base.parts();
    Payout {
        bits: p.graph.bits.into(),
        low_bits: p.graph.low_bits.into(),
        rest: p.rest().expect("a Base's rest is checked"),
    }
}

/// The contract of `base` as its statement fixes it at opening.
pub fn contract(base: &Base) -> Contract {
    let p = base.parts();
    let cp = &p.chain.checkpoint;
    let header = Header(*cp.header());
    let mut word = Sha256::new();
    word.update(b"licash/hp/word");
    word.update(base.digest());
    let mut txid = [0; 32];
    txid.copy_from_slice(&p.deposit[..32]);
    let vout = u32::from_le_bytes(p.deposit[32..].try_into().expect("36-byte outpoint"));
    Contract {
        c: C,
        d: word.finalize().into(),
        deposit: OutPoint { txid, vout },
        checkpoint: Checkpoint {
            height: cp.height(),
            hash: header.hash(),
        },
        work: u128::from(p.chain.work_depth).saturating_mul(btc::work(header.bits())),
        payout: payout(base),
    }
}

/// Where `base`'s links carry their bytes ([`recovery::leaf_carried`]): a
/// function of its Base alone, never of the input's choosing, as an exit
/// read under another carrier could read her claim as none.
pub fn carrier(base: &Base) -> Carrier {
    match recovery::leaf_carried(base.parts().graph.id) {
        true => Carrier::Leaf,
        false => Carrier::Nulldata,
    }
}

/// Whether `exit`'s slot spends are each of the shape `base`'s carrier
/// reads ([`carrier`]).
fn carried_as(base: &Base, exit: &Exit) -> bool {
    let leaf = carrier(base) == Carrier::Leaf;
    std::iter::once(&exit.publish)
        .chain(&exit.disclosure)
        .all(|s| s.reserved.is_some() == leaf)
}

/// The Licash chain the statement decides on: Base's checkpoint, then
/// `headers` (the exit's, through the publication's block).
pub fn chain(base: &Base, headers: &[[u8; 80]]) -> Result<Chain, Refusal> {
    let terms = &base.parts().chain;
    Chain::verify(
        terms.checkpoint.clone(),
        &terms.checkpoint.commitment(),
        headers.to_vec(),
        terms.max_headers as usize,
    )
    .map_err(|e| Refusal::Chain(e.to_string()))
}

/// The exit's headers through the block of her publication.
pub fn through_publication<'a>(contract: &Contract, exit: &'a Exit, read: &Read) -> &'a [[u8; 80]] {
    let at = read.heights.publish - contract.checkpoint.height;
    &exit.headers[..at as usize]
}

/// Her request's one-time public keys, each digit's chain end (HASH160
/// chains, as `lichen_wots`'s `WotsPublic`): `b`'s 8 message digits and 2
/// checksum digits, `E`'s 64 and 3. Her Base binds their digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestKeys {
    b: Vec<[u8; 20]>,
    e: Vec<[u8; 20]>,
}

/// The digits of a signature on `bytes` bytes: its message's and checksum's.
fn digits(bytes: usize) -> usize {
    2 * bytes + checksum_digits(bytes)
}

impl RequestKeys {
    pub fn new(b: Vec<[u8; 20]>, e: Vec<[u8; 20]>) -> Option<Self> {
        (b.len() == digits(4) && e.len() == digits(32)).then_some(Self { b, e })
    }

    /// What her Base binds of them (`Parts::holder_wots`).
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(
            "licash/hp/request-keys",
            &[&self.b.concat(), &self.e.concat()],
        )
    }

    fn write(&self, w: &mut W) {
        for key in self.b.iter().chain(&self.e) {
            w.put(key);
        }
    }

    fn read(r: &mut R) -> Option<Self> {
        let mut key = || r.take::<20>().ok();
        let b = (0..digits(4)).map(|_| key()).collect::<Option<_>>()?;
        let e = (0..digits(32)).map(|_| key()).collect::<Option<_>>()?;
        Self::new(b, e)
    }

    /// Whether her request's witness (bottom first: her signature on `E`,
    /// then on `b`, then the 2-of-2's) is signed under these keys, as the
    /// request's script checks it: each digit read as the script reads it
    /// ([`script_digit`]), its item hashed up its chain to the key's end,
    /// and the checksum digits those of the message's.
    pub fn signed(&self, witness: &[&[u8]]) -> bool {
        let e_items = 2 * self.e.len();
        witness.len() >= e_items + 2 * self.b.len()
            && signs(&witness[..e_items], &self.e, 32)
            && signs(&witness[e_items..], &self.b, 4)
    }

    /// The items of a signature on `E` (bottom first, as in her request's
    /// witness): `2 * 67`.
    pub fn e_items() -> usize {
        2 * digits(32)
    }

    /// The message digits `items`, exactly a signature on `E`'s worth
    /// ([`Self::e_items`]), sign under the key on `E`, each read as the
    /// script reads it: none if they sign none.
    fn e_signed(&self, items: &[&[u8]]) -> Option<Vec<u32>> {
        (items.len() == Self::e_items())
            .then(|| signed_digits(items, &self.e, 32))
            .flatten()
    }
}

/// Whether `items` (bottom first: `hash_0, digit_0, hash_1, …`) are a
/// Winternitz signature on `bytes` bytes under the chain ends `keys`.
fn signs(items: &[&[u8]], keys: &[[u8; 20]], bytes: usize) -> bool {
    signed_digits(items, keys, bytes).is_some()
}

/// The message digits of `items` if they are a signature as [`signs`]
/// takes one, each as the script reads it ([`script_digit`]).
fn signed_digits(items: &[&[u8]], keys: &[[u8; 20]], bytes: usize) -> Option<Vec<u32>> {
    let mut read = Vec::with_capacity(keys.len());
    for (i, end) in keys.iter().enumerate() {
        let (item, digit) = (items.get(2 * i)?, items.get(2 * i + 1)?);
        let digit = script_digit(digit)?;
        let mut h = item.to_vec();
        for _ in digit..15 {
            h = hash160::Hash::hash(&h).to_byte_array().to_vec();
        }
        if h != end {
            return None;
        }
        read.push(u32::from(digit));
    }
    let (message, checksum) = read.split_at(2 * bytes);
    let sum: u32 = message.iter().map(|d| 15 - d).sum();
    (checksum.iter().fold(0, |value, d| value * 16 + d) == sum).then(|| message.to_vec())
}

/// The statement's input: Base, the exit as the Hub shows it, its
/// evidence against the claim and her request's keys.
#[derive(Clone)]
pub struct HubInput {
    pub base: Base,
    pub exit: Exit,
    pub evidence: Vec<Evidence>,
    pub keys: RequestKeys,
    /// Under a lean format, the items of her filing the Hub says are invalid
    /// ([`recovery::owed_flagged`]): none, else, unless they are the items
    /// that are not, no proof. Zero under another.
    pub invalid: u32,
    /// Of a chained contract ([`licash::recovery::chained`]) the proof of the
    /// chain its exit's blocks are in, and the exit's headers are those
    /// after the chain's tip; of another, none and the exit's headers are
    /// every one from the checkpoint.
    pub chain: Option<ChainProof>,
    /// Of a contract whose claims are void signed twice
    /// ([`recovery::two_claims_void`]), her other signature on another `E`,
    /// if the Hub holds one: the items of her other request's witness
    /// signing it ([`RequestKeys::e_items`], bottom first). With it, no
    /// evidence and nothing flagged; the claim is owed nothing. Of another
    /// contract, none, and nothing of it in its bytes.
    pub other_e: Option<Vec<Vec<u8>>>,
}

impl HubInput {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.bytes(&self.base.to_bytes());
        self.exit.write(&mut w);
        w.bytes(&recovery::evidence_to_bytes(&self.evidence));
        self.keys.write(&mut w);
        if Format::of(&self.base).lean() {
            w.put(&self.invalid.to_be_bytes());
        }
        if let Some(chain) = &self.chain {
            chain.write(&mut w);
        }
        if recovery::two_claims_void(self.base.parts().graph.id) {
            match &self.other_e {
                None => w.put(&[0]),
                Some(items) => {
                    w.put(&[1]);
                    for item in items {
                        w.bytes(item);
                    }
                }
            }
        }
        w.0
    }

    /// Strict decoding: Base validated, every note and signed spend in the
    /// evidence verified under its keyset.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        let mut r = R(bytes);
        let base = Base::from_bytes(&r.bytes().map_err(|_| Refusal::Input)?)
            .map_err(|_| Refusal::Input)?;
        let exit = Exit::read(&mut r, carrier(&base)).map_err(|_| Refusal::Input)?;
        let p = base.parts();
        let evidence = recovery::evidence_from_bytes(
            &p.keyset,
            p.limits.max_authorizations as usize,
            &r.bytes().map_err(|_| Refusal::Input)?,
        )
        .map_err(|_| Refusal::Input)?;
        let keys = RequestKeys::read(&mut r).ok_or(Refusal::Input)?;
        let invalid = match Format::of(&base).lean() {
            true => u32::from_be_bytes(r.take::<4>().map_err(|_| Refusal::Input)?),
            false => 0,
        };
        let chain = match recovery::chained(p.graph.id) {
            true => Some(ChainProof::read(&mut r)?),
            false => None,
        };
        let other_e = match recovery::two_claims_void(p.graph.id) {
            true => match r.take::<1>().map_err(|_| Refusal::Input)? {
                [0] => None,
                [1] => Some(
                    (0..RequestKeys::e_items())
                        .map(|_| {
                            // A hash of 20 bytes, a digit of 1 at most.
                            let item = r.bytes().map_err(|_| Refusal::Input)?;
                            match item.len() <= 20 {
                                true => Ok(item),
                                false => Err(Refusal::Input),
                            }
                        })
                        .collect::<Result<_, _>>()?,
                ),
                _ => return Err(Refusal::Input),
            },
            false => None,
        };
        r.end().map_err(|_| Refusal::Input)?;
        Ok(Self {
            base,
            exit,
            evidence,
            keys,
            invalid,
            chain,
            other_e,
        })
    }
}

/// The chain program a chained contract's statement is built with: its image
/// id, and how a receipt of it is verified, which the zkVM does for its
/// guest (`env::verify`) and the Hub, holding the receipt, need not.
pub struct Program<'a> {
    pub id: [u8; 32],
    pub verify: &'a dyn Fn(&[u8; 32], &[u8]),
}

/// What the statement decides of `exit` under `base` against `evidence`:
/// what the claim is owed, and what Bitcoin shows of the exit. Her request
/// must be signed under `keys`, the keys Base binds.
pub fn decide(
    base: &Base,
    keys: &RequestKeys,
    exit: &Exit,
    evidence: &[Evidence],
) -> Result<(Owed, Read), Refusal> {
    decide_with(base, keys, exit, evidence, None, None, None, &mut |_| {})
}

/// The items of her filing the statement must flag as invalid, to prove the
/// claim owed what it is: what a Hub finds natively, and puts in its
/// input ([`HubInput::invalid`]). None under a format that does not flag.
pub fn flagged(
    base: &Base,
    keys: &RequestKeys,
    exit: &Exit,
    evidence: &[Evidence],
) -> Result<u32, Refusal> {
    Ok(decide(base, keys, exit, evidence)?.0.invalid)
}

/// The chain of a chained contract's exit, as its statement is given it.
#[derive(Clone, Copy)]
pub struct Chained<'a> {
    pub proof: &'a ChainProof,
    pub program: &'a Program<'a>,
}

/// [`flagged`] of a chained contract.
pub fn flagged_on(
    base: &Base,
    keys: &RequestKeys,
    exit: &Exit,
    evidence: &[Evidence],
    chained: Chained,
) -> Result<u32, Refusal> {
    let decided = decide_with(
        base,
        keys,
        exit,
        evidence,
        None,
        None,
        Some(chained),
        &mut |_| {},
    )?;
    Ok(decided.0.invalid)
}

/// The proof of the chain `proven` has for `exit`, as a Hub puts it in its
/// input: openings, in the tree of the journal of the receipt the statement
/// verifies, of the checkpoint's block, the exit's and every one the judgment
/// of the claim reads. Which those are only the
/// judgment knows: it is run, and the blocks it finds it was not shown are
/// opened and it is run again, until it asks for none. `exit`'s headers are
/// those after the chain's tip. With her other signature on `E`,
/// `other_e` ([`HubInput::other_e`]), the claim is not judged: the exit's
/// blocks alone are opened.
pub fn open_chain(
    proven: headers::Proven,
    base: &Base,
    keys: &RequestKeys,
    exit: &Exit,
    evidence: &[Evidence],
    other_e: Option<&[Vec<u8>]>,
    program: &Program,
) -> Result<ChainProof, Refusal> {
    let headers::Proven {
        lineage,
        journal,
        tip,
    } = proven;
    let mut heights = std::collections::BTreeSet::from([base.parts().chain.checkpoint.height()]);
    let blocks = [
        &exit.request.header,
        &exit.publish.header,
        &exit.respond.header,
    ]
    .into_iter()
    .chain(exit.disclosure.as_ref().map(|d| &d.header));
    heights.extend(blocks.filter_map(|header| lineage.height_of(header)));
    loop {
        let openings = heights
            .iter()
            .map(|h| {
                lineage.open(*h, journal.count).ok_or_else(|| {
                    Refusal::Chain(format!("block {h} is not in the receipt's chain"))
                })
            })
            .collect::<Result<_, _>>()?;
        let proof = ChainProof {
            journal: journal.to_bytes(),
            tip: tip.to_bytes(),
            openings,
        };
        let chained = Chained {
            proof: &proof,
            program,
        };
        match decide_with(
            base,
            keys,
            exit,
            evidence,
            None,
            other_e,
            Some(chained),
            &mut |_| {},
        ) {
            Err(Refusal::Openings(more)) => {
                let before = heights.len();
                heights.extend(more);
                if heights.len() == before {
                    return Err(Refusal::Chain("a block asked for is already opened".into()));
                }
            }
            Err(e) => return Err(e),
            Ok(_) => return Ok(proof),
        }
    }
}

/// [`decide`], calling `mark` with the name of each step as it ends: the
/// guest's profile build counts the cycles between them.
///
/// Of a chained contract the exit's blocks are read from `chained` (and only
/// then): its chain's receipt verified, the blocks the exit and the claim's
/// judgment look up opened from it. A block the judgment needs that the
/// input does not open leaves the Hub unable to prove ([`Refusal::Openings`]),
/// and never leaves the claim owed nothing, which the Hub could otherwise
/// choose by leaving it out.
///
/// Of a contract whose claims are void signed twice
/// ([`recovery::two_claims_void`]), `other_e`, her signature on another `E`
/// than her request's ([`HubInput::other_e`]), owes the claim nothing, its
/// filing unread: with no evidence and nothing flagged, and none other.
#[allow(clippy::too_many_arguments)]
pub fn decide_with(
    base: &Base,
    keys: &RequestKeys,
    exit: &Exit,
    evidence: &[Evidence],
    invalid: Option<u32>,
    other_e: Option<&[Vec<u8>]>,
    chained: Option<Chained>,
    mark: &mut dyn FnMut(&'static str),
) -> Result<(Owed, Read), Refusal> {
    let contract = contract(base);
    if recovery::chained(base.parts().graph.id) != chained.is_some() {
        return Err(Refusal::Chain(
            "a chained contract is decided on its chain, and no other is".into(),
        ));
    }
    if !carried_as(base, exit) {
        return Err(Refusal::Input);
    }
    let (read, view) = match chained {
        None => (
            licash_statement::read(&contract, exit).map_err(Refusal::Exit)?,
            None,
        ),
        Some(c) => {
            (c.program.verify)(&c.program.id, &c.proof.journal);
            let view = View::new(
                &c.program.id,
                c.proof,
                &base.parts().chain.checkpoint,
                &exit.headers,
            )?;
            let read = licash_statement::read_on(&contract, exit, &view).map_err(Refusal::Exit)?;
            (read, Some(view))
        }
    };
    mark("the exit read: its headers' work, its transactions");
    if keys.digest() != base.parts().holder_wots {
        return Err(Refusal::Unsigned);
    }
    let witness = exit
        .request
        .spending(&contract.deposit)
        .ok_or(Refusal::Exit(Reject::Posted))?;
    if !keys.signed(&witness) {
        return Err(Refusal::Unsigned);
    }
    mark("her request's one-time signatures");
    if let Some(other) = other_e {
        let two = recovery::two_claims_void(base.parts().graph.id)
            && evidence.is_empty()
            && invalid.unwrap_or(0) == 0;
        let other: Vec<&[u8]> = other.iter().map(Vec::as_slice).collect();
        let items = RequestKeys::e_items();
        let (Some(theirs), Some(hers)) = (keys.e_signed(&other), keys.e_signed(&witness[..items]))
        else {
            return Err(Refusal::Unsigned);
        };
        if !two || theirs == hers {
            return Err(Refusal::Input);
        }
        let owed = Owed {
            owed: 0,
            mask: 0,
            invalid: 0,
            disclosures: Disclosures::empty(),
            ineligible: Some("her one-time key on E signed two claims".into()),
        };
        return Ok((owed, read));
    }
    let terms = &base.parts().chain;
    let chain = match &view {
        None => chain(base, through_publication(&contract, exit, &read))?,
        Some(view) => {
            // the budget `Chain::verify` holds a dense chain to
            if read.heights.publish - terms.checkpoint.height() > terms.max_headers {
                return Err(Refusal::Chain("header budget".into()));
            }
            view.chain(&terms.checkpoint, read.heights.publish)
                .map_err(|e| Refusal::Chain(e.to_string()))?
        }
    };
    mark("the Licash header chain through her publication");
    let request = Request {
        amount: read.b,
        claim_digest: read.e,
    };
    let owed = match invalid {
        None => recovery::owed(base, &request, &read.claim, evidence, &chain),
        Some(invalid) => {
            recovery::owed_flagged(base, &request, &read.claim, evidence, &chain, invalid)
        }
    };
    // Before what the judgment made of them: a block it was not shown, found
    // missing, may have made it a claim owed nothing, which only the holder
    // is to bring on herself.
    let unshown = chain.unshown();
    if !unshown.is_empty() {
        return Err(Refusal::Openings(unshown));
    }
    let owed = owed.map_err(|e| Refusal::Evidence(e.to_string()))?;
    mark("her filing decoded and judged against the evidence");
    Ok((owed, read))
}

/// The Hub's statement: it holds if the claim is owed at most the
/// response's `b′`, and the response disclosed what the evidence needs.
/// On success, the journal fixed at opening.
pub fn check(input: &HubInput) -> Result<[u8; JOURNAL_LEN], Refusal> {
    check_with(input, None, &mut |_| {})
}

/// [`check`] of an input of a chained contract, whose statement is built
/// with `program`, the chain program it verifies receipts of.
pub fn check_on(input: &HubInput, program: &Program) -> Result<[u8; JOURNAL_LEN], Refusal> {
    check_with(input, Some(program), &mut |_| {})
}

/// [`check`], calling `mark` as [`decide_with`] does, with the chain program
/// of a chained contract.
pub fn check_with(
    input: &HubInput,
    program: Option<&Program>,
    mark: &mut dyn FnMut(&'static str),
) -> Result<[u8; JOURNAL_LEN], Refusal> {
    let chained = match (&input.chain, program) {
        (Some(proof), Some(program)) => Some(Chained { proof, program }),
        (None, None) => None,
        _ => {
            return Err(Refusal::Chain(
                "a chained contract's input holds its chain, and its statement its program".into(),
            ))
        }
    };
    let (owed, read) = decide_with(
        &input.base,
        &input.keys,
        &input.exit,
        &input.evidence,
        Some(input.invalid),
        input.other_e.as_deref(),
        chained,
        mark,
    )?;
    verdict(
        &owed,
        read.b2,
        read.disclosed.as_deref(),
        Format::of(&input.base).lean(),
    )?;
    licash_statement::holds(&contract(&input.base), &read, owed.owed).map_err(|_| Refusal::Owed)
}

/// Whether a response of `b2` that disclosed `disclosed` bears out what the
/// claim is owed: the response disclosed what its evidence uses, and the
/// claim is owed at most `b2`. The statement's own test of a response, which
/// a holder makes too before she lets one stand ([`bears_out`]).
pub fn verdict(owed: &Owed, b2: u32, disclosed: Option<&[u8]>, lean: bool) -> Result<(), Refusal> {
    if owed.disclosures != Disclosures::empty()
        && disclosed != Some(&owed.disclosures.encode(lean)[..])
    {
        return Err(Refusal::Undisclosed);
    }
    match owed.owed > b2 {
        true => Err(Refusal::Owed),
        false => Ok(()),
    }
}

/// What a holder makes of the Hub's response to her claim, as its statement
/// would: whether the claim `filed` (her filing's bytes) under `request` is
/// owed at most `b2` against `evidence`, on the headers from Base's
/// checkpoint through her publication's block, and the response disclosed
/// what the evidence uses (`disclosed`, the bytes of its disclosure, if it
/// made one). The statement is a deterministic function of these, so a
/// holder for whom this holds may leave the response uncontested: nothing
/// the Hub could prove would say otherwise. `b2` and her request's amount
/// are as the payout counts their words ([`payout`]). A response of `b2`
/// not below
/// her claim, and not 0, concedes it ([`Reject::Conceded`]): the statement
/// proves nothing of it, and her contest wins her claim and the Hub's
/// reserve, where the response left alone pays her the bits of `b2` alone
/// (none above the graph's).
pub fn bears_out(
    base: &Base,
    request: &Request,
    filed: &[u8],
    evidence: &[Evidence],
    headers: &[[u8; 80]],
    b2: u32,
    disclosed: Option<&[u8]>,
) -> Result<(), Refusal> {
    if b2 != 0 && b2 >= request.amount {
        return Err(Refusal::Exit(Reject::Conceded));
    }
    let chain = chain(base, headers)?;
    let owed = recovery::owed(base, request, filed, evidence, &chain)
        .map_err(|e| Refusal::Evidence(e.to_string()))?;
    verdict(&owed, b2, disclosed, Format::of(base).lean())
}
