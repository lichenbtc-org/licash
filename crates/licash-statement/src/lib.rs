//! The statement of a recovery's exit on Lichen's hub-proves graph: what
//! Bitcoin shows of the exit, read in the Hub's guest (`licash-hp`, which
//! decides what her claim is owed). It was Lichen's `lichen-statement`,
//! moved here byte for byte (the journal's encoding and tags unchanged):
//! it is licash's statement, not Lichen's.
//!
//! **The exit.** Alice's `request`, the spend of the contract's funding
//! (the transaction spending its deposit coin), carries her one-time
//! signatures on `b`, what she claims, and on `E`, her claim's
//! fingerprint. Her publication, the spend of `request`'s slot output
//! ([`SLOT_VOUT`]), carries the claim's bytes in nulldata
//! ([`claim_script`]), which script can't check: her signature on the
//! publication, which commits to its outputs, and its txid in its block
//! bind them, and the L2 checks they hash to `E`. The hub's `respond`
//! carries its signature on `b′`, what it says she is owed, and its
//! disclosure, the spend of `respond`'s slot, any bytes the L2's grounds
//! cite.
//!
//! **The chain.** The hub shows the headers from the contract's
//! checkpoint (a block both sides checked at opening) through the last of
//! those transactions' blocks and on, with the contract's work `W` on top
//! of it. Each header follows the last within its own target. Script and
//! consensus aren't checked: Bitcoin checked them, and forging a block
//! with `W` on top costs `W`. So the signatures in `request`'s and
//! `respond`'s witnesses are read for their digits only. The heights the
//! L2 reads count from the checkpoint's.
//!
//! **The statement.** The hub proves she is owed at most `b′`. Its guest
//! reads its input, calls [`read`], decides what the claim is owed from
//! [`Read`] and its own evidence, and commits what [`holds`] returns: the
//! journal, fixed at opening ([`Contract::journal`]), so `b′` and the
//! claim are read from Bitcoin, not the journal.
//!
//! Integers are big-endian in the encodings ([`codec`]).

#![no_std]

extern crate alloc;

use alloc::{vec, vec::Vec};
use sha2::{Digest, Sha256};

pub mod btc;
pub mod codec;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use btc::{sha256d, work, Header, OutPoint};
use codec::{R, W};

pub type Hash = [u8; 32];

/// Why an input is rejected: the hub can't prove with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Encoding,
    /// A header that doesn't follow the last (from the checkpoint) within
    /// its target, a transaction's block not among them, or too little
    /// work on the last.
    Depth,
    /// `request` doesn't spend the contract's funding output, its witness
    /// isn't a request's, or her publication isn't the spend of its slot.
    Posted,
    /// `respond` isn't in its block, doesn't spend `request`'s output 0, or
    /// its witness isn't a respond's.
    Responded,
    /// The hub's `b′` isn't below her `b`, nor 0: it conceded.
    Conceded,
    /// The disclosure isn't in its block or doesn't spend `respond`'s slot.
    Disclosed,
    /// The claim is owed more than `b′`.
    Owed,
}

// ----- the carrier: the bytes a transaction's nulldata outputs push -----

/// The vout of a link's slot output: `request`'s, which her publication
/// spends, and `respond`'s, which the hub's disclosure spends (the main
/// output 0, the anchor 1, the slot after them).
pub const SLOT_VOUT: u32 = 2;

/// The largest script a publication's nulldata output carries (Bitcoin
/// Core's default `-datacarriersize`).
pub const CARRIER_BUDGET: usize = 100_000;

/// No push larger (a script's).
pub const CARRIER_PUSH: usize = 520;

/// The nulldata script of a publication's output carrying `bytes`:
/// `OP_RETURN` and pushes of at most 520, in order. None if they don't
/// fit the budget.
pub fn claim_script(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() >= CARRIER_BUDGET {
        return None;
    }
    let mut s = vec![0x6a];
    push_all(&mut s, bytes);
    (s.len() <= CARRIER_BUDGET).then_some(s)
}

/// `bytes` as pushes of at most 520, in order, appended to `s`.
fn push_all(s: &mut Vec<u8>, bytes: &[u8]) {
    for chunk in bytes.chunks(CARRIER_PUSH) {
        if let [n @ 1..=16] = chunk {
            s.push(0x50 + n);
            continue;
        }
        if chunk == [0x81] {
            s.push(0x4f);
            continue;
        }
        match chunk.len() {
            n @ 1..=75 => {
                s.push(n as u8);
                s.extend_from_slice(chunk);
            }
            n @ 76..=255 => {
                s.push(0x4c);
                s.push(n as u8);
                s.extend_from_slice(chunk);
            }
            n => {
                s.push(0x4d);
                s.extend_from_slice(&(n as u16).to_le_bytes());
                s.extend_from_slice(chunk);
            }
        }
    }
}

/// Where a link's slot spend carries its bytes, which the contract's
/// graph fixes: in a nulldata output ([`claim_script`]), or in the leaf
/// script of an input it spends by its script path ([`envelope_script`]),
/// out of the txid and in the witness, which costs a quarter as much and
/// which Bitcoin Core relays since long before it relayed large nulldata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Nulldata,
    Leaf,
}

/// The envelope's start after its key: `OP_CHECKSIG OP_FALSE OP_IF`.
const ENVELOPE_OPEN: [u8; 3] = [0xac, 0x00, 0x63];
/// Its end: `OP_ENDIF`.
const ENVELOPE_CLOSE: u8 = 0x68;

/// The leaf script of an output only `key` (x-only) spends that carries
/// `bytes` when spent by it: `<key> OP_CHECKSIG OP_FALSE OP_IF`, pushes of
/// at most 520, `OP_ENDIF`. The branch never runs, so the bytes are any;
/// the output commits to the script, so its spend carries them, and no
/// other, whoever relays it. None if they don't fit the budget.
pub fn envelope_script(key: &[u8; 32], bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() >= CARRIER_BUDGET {
        return None;
    }
    let mut s = vec![0x20];
    s.extend_from_slice(key);
    s.extend_from_slice(&ENVELOPE_OPEN);
    push_all(&mut s, bytes);
    s.push(ENVELOPE_CLOSE);
    (s.len() <= CARRIER_BUDGET).then_some(s)
}

/// The bytes an [`envelope_script`] carries, if `script` is one (of any
/// key), else None.
pub fn enveloped(script: &[u8]) -> Option<Vec<u8>> {
    let inner = script
        .strip_prefix(&[0x20][..])
        .and_then(|s| s.get(32..))
        .and_then(|s| s.strip_prefix(&ENVELOPE_OPEN[..]))
        .and_then(|s| s.strip_suffix(&[ENVELOPE_CLOSE][..]))?;
    Some(pushes_only(inner)?.concat())
}

/// The leaf script of a witness spending by a taproot script path
/// (BIP341: its annex, if any, left out; the script second to last, above
/// the control block), if it is one.
fn leaf_script<'a>(witness: &[&'a [u8]]) -> Option<&'a [u8]> {
    let items = match witness {
        [rest @ .., last] if rest.len() >= 2 && last.first() == Some(&0x50) => rest,
        all => all,
    };
    let [.., script, control] = items else {
        return None;
    };
    let tapscript = control.first().is_some_and(|b| b & 0xfe == 0xc0);
    let shaped = control.len() >= 33 && (control.len() - 33) % 32 == 0;
    (tapscript && shaped).then_some(*script)
}

/// The bytes a transaction (witness serialization) carries in envelopes:
/// those of each input spending an [`envelope_script`] by its script path,
/// in input order. A leaf script that isn't one carries nothing.
pub fn carried_in_leaves(tx: &btc::WitnessTx) -> Vec<u8> {
    let mut out = vec![];
    for witness in &tx.witness {
        if let Some(bytes) = leaf_script(witness).and_then(enveloped) {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

/// The bytes the pushes of a nulldata script (`OP_RETURN` then pushes
/// only) push, in order. None if it isn't one.
pub fn pushes(script: &[u8]) -> Option<Vec<&[u8]>> {
    pushes_only(script.strip_prefix(&[0x6a][..])?)
}

/// The bytes `script`'s pushes push, in order: None unless it is pushes
/// only, each of at most 520.
fn pushes_only(script: &[u8]) -> Option<Vec<&[u8]>> {
    // The byte `OP_0`, `OP_1NEGATE` and `OP_1`..`OP_16` push
    const PUSHED: [&[u8]; 18] = [
        b"",
        &[0x81],
        &[1],
        &[2],
        &[3],
        &[4],
        &[5],
        &[6],
        &[7],
        &[8],
        &[9],
        &[10],
        &[11],
        &[12],
        &[13],
        &[14],
        &[15],
        &[16],
    ];
    let mut out = vec![];
    let mut at = 0;
    while at < script.len() {
        let op = script[at];
        at += 1;
        let n = match op {
            0x00 | 0x4f | 0x51..=0x60 => {
                out.push(
                    PUSHED[match op {
                        0x00 => 0,
                        0x4f => 1,
                        n => n as usize - 0x4f,
                    }],
                );
                continue;
            }
            n @ 0x01..=0x4b => n as usize,
            0x4c => {
                let n = *script.get(at)? as usize;
                at += 1;
                n
            }
            0x4d => {
                let b = script.get(at..at + 2)?;
                at += 2;
                u16::from_le_bytes([b[0], b[1]]) as usize
            }
            0x4e => {
                let b = script.get(at..at + 4)?;
                at += 4;
                usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok()?
            }
            _ => return None,
        };
        if n > CARRIER_PUSH {
            return None;
        }
        out.push(script.get(at..at + n)?);
        at += n;
    }
    Some(out)
}

/// The bytes a transaction carries: its nulldata outputs' payloads, in
/// output order. None if an output starting `OP_RETURN` isn't pushes
/// only.
pub fn carried(tx: &btc::Tx) -> Option<Vec<u8>> {
    let mut out = vec![];
    for (_, script) in &tx.outputs {
        if script.first() == Some(&0x6a) {
            for push in pushes(script)? {
                out.extend_from_slice(push);
            }
        }
    }
    Some(out)
}

// ----- the one-time signatures, read from the links' witnesses -----

/// What `request` carries: `b` and `E`, both script-checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requested {
    pub b: u32,
    pub e: Hash,
}

/// A signature's digit as the verifying script reads its witness item: a
/// number of at most 4 bytes, little-endian, its sign the last byte's top
/// bit, minimal or not (consensus doesn't require it in tapscript), then
/// `OP_MIN 15`. So `[0x10]` is 15, as are all positives above it, and
/// `[0x80]`, negative zero, is 0. None where the script fails: a negative
/// digit, or an item longer than a number.
pub fn script_digit(item: &[u8]) -> Option<u8> {
    let Some((&last, rest)) = item.split_last() else {
        return Some(0);
    };
    if item.len() > 4 {
        return None;
    }
    if last & 0x80 != 0 {
        return (last == 0x80 && rest.iter().all(|b| *b == 0)).then_some(0);
    }
    let value = item
        .iter()
        .rev()
        .fold(0u32, |v, b| (v << 8) | u32::from(*b));
    Some(value.min(15) as u8)
}

/// A Winternitz signature's message from its witness items, bottom first
/// (`hash_0, digit_0, hash_1, digit_1, …`): its first `bytes` bytes'
/// digits, each as the script reads it ([`script_digit`]).
fn signed_message(items: &[&[u8]], bytes: usize) -> Option<Vec<u8>> {
    let digit = |i: usize| script_digit(items.get(2 * i + 1)?);
    (0..bytes)
        .map(|k| Some((digit(2 * k)? << 4) | digit(2 * k + 1)?))
        .collect()
}

/// The checksum digits of a signature on `bytes` bytes (`lichen-btc`'s
/// `WotsParams::for_bytes`).
pub fn checksum_digits(bytes: usize) -> usize {
    let most = 15 * 2 * bytes as u64;
    (1..).find(|n| 16u64.pow(*n) > most).unwrap() as usize
}

/// `request`'s witness (the input spending the contract's funding output,
/// bottom first): Alice's signature on `E` (32 bytes), then on `b` (4),
/// each a hash and a digit a digit, below the 2-of-2's two signatures, the
/// script and the control block.
pub fn requested(witness: &[&[u8]]) -> Option<Requested> {
    let e_items = 2 * (64 + checksum_digits(32));
    let b_items = 2 * (8 + checksum_digits(4));
    if witness.len() != e_items + b_items + 4 {
        return None;
    }
    let e = signed_message(&witness[..e_items], 32)?;
    let b = signed_message(&witness[e_items..e_items + b_items], 4)?;
    Some(Requested {
        b: u32::from_be_bytes(b.try_into().ok()?),
        e: e.try_into().ok()?,
    })
}

/// `respond`'s witness (the input spending `request`'s output 0, bottom
/// first): the hub's signature on `b′` (4 bytes), below the 2-of-2's two
/// signatures, the script and the control block. Its `b′`.
pub fn responded(witness: &[&[u8]]) -> Option<u32> {
    let items = 2 * (8 + checksum_digits(4));
    if witness.len() != items + 4 {
        return None;
    }
    Some(u32::from_be_bytes(
        signed_message(&witness[..items], 4)?.try_into().ok()?,
    ))
}

// ----- the exit's transactions, each in its block -----

/// The witness of the input of `tx` (witness serialization) spending
/// `spent`, if it spends it.
pub fn input_witness<'a>(tx: &'a [u8], spent: &OutPoint) -> Option<Vec<&'a [u8]>> {
    let t = btc::parse_witness_tx(tx)?;
    let i = t.tx.inputs.iter().position(|o| o == spent)?;
    t.witness.into_iter().nth(i)
}

/// `request` in a block, with its witness: the transaction (witness
/// serialization), the block's header, the transaction's index and path
/// in the block's witness tree, and the block's coinbase (non-witness),
/// its path in the txid tree (which fixes the trees' depth) and its
/// witness reserved value; and the contract's funding transaction
/// (non-witness), whose output 0 `request` spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub funding: Vec<u8>,
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
    pub reserved: Hash,
}

impl Request {
    /// The witness of the input spending the contract's funding output, the
    /// funding the transaction spending `deposit` (the contract's deposit
    /// coin: nothing else can spend it): none unless the transaction spends
    /// it and is in the header's block.
    pub fn spending(&self, deposit: &OutPoint) -> Option<Vec<&[u8]>> {
        if !btc::parse_tx(&self.funding)?.inputs.contains(deposit) {
            return None;
        }
        let funding = OutPoint {
            txid: sha256d(&self.funding),
            vout: 0,
        };
        if !btc::witness_in_block(
            &self.tx,
            &Header(self.header),
            self.index,
            &self.path,
            &self.coinbase,
            &self.coinbase_path,
            &self.reserved,
        ) {
            return None;
        }
        input_witness(&self.tx, &funding)
    }

    /// Its txid.
    pub fn txid(&self) -> Option<Hash> {
        Some(sha256d(&btc::bare_tx(&self.tx)?))
    }

    pub fn write(&self, w: &mut W) {
        w.bytes(&self.funding);
        w.bytes(&self.tx);
        w.put(&self.header);
        w.put(&self.index.to_be_bytes());
        w.list(&self.path);
        w.bytes(&self.coinbase);
        w.list(&self.coinbase_path);
        w.put(&self.reserved);
    }

    pub fn read(r: &mut R) -> Result<Request, Reject> {
        Ok(Request {
            funding: r.bytes()?,
            tx: r.bytes()?,
            header: r.take()?,
            index: u32::from_be_bytes(r.take()?),
            path: r.list()?,
            coinbase: r.bytes()?,
            coinbase_path: r.list()?,
            reserved: r.take()?,
        })
    }
}

/// The confirmed spender of a link's slot (`request`'s: her publication;
/// `respond`'s: the hub's disclosure) in its block: of a nulldata
/// [`Carrier`], by the txid tree (`tx` its non-witness serialization,
/// `reserved` none); of a leaf one, by the witness tree, as [`Respond`]
/// is (`tx` its witness serialization, `reserved` the coinbase's witness
/// reserved value), its envelopes in its witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSpend {
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
    pub reserved: Option<Hash>,
}

impl SlotSpend {
    /// The bytes it carries (of nulldata, none if its nulldata isn't
    /// pushes only), if it is in its block and spends `slot`.
    pub fn carrying(&self, slot: &OutPoint) -> Option<Vec<u8>> {
        let header = Header(self.header);
        match &self.reserved {
            None => {
                if !btc::in_block(
                    &self.tx,
                    &header,
                    self.index,
                    &self.path,
                    &self.coinbase,
                    &self.coinbase_path,
                ) {
                    return None;
                }
                let tx = btc::parse_tx(&self.tx).filter(|tx| tx.inputs.contains(slot))?;
                Some(carried(&tx).unwrap_or_default())
            }
            Some(reserved) => {
                if !btc::witness_in_block(
                    &self.tx,
                    &header,
                    self.index,
                    &self.path,
                    &self.coinbase,
                    &self.coinbase_path,
                    reserved,
                ) {
                    return None;
                }
                let tx = btc::parse_witness_tx(&self.tx).filter(|t| t.tx.inputs.contains(slot))?;
                Some(carried_in_leaves(&tx))
            }
        }
    }

    /// Its txid.
    pub fn txid(&self) -> Option<Hash> {
        match self.reserved {
            None => Some(sha256d(&self.tx)),
            Some(_) => Some(sha256d(&btc::bare_tx(&self.tx)?)),
        }
    }

    pub fn write(&self, w: &mut W) {
        w.bytes(&self.tx);
        w.put(&self.header);
        w.put(&self.index.to_be_bytes());
        w.list(&self.path);
        w.bytes(&self.coinbase);
        w.list(&self.coinbase_path);
        if let Some(reserved) = &self.reserved {
            w.put(reserved);
        }
    }

    /// One written by [`Self::write`] of a contract whose slots `carrier`
    /// carries: the shape is the contract's, not the input's to choose.
    pub fn read(r: &mut R, carrier: Carrier) -> Result<SlotSpend, Reject> {
        Ok(SlotSpend {
            tx: r.bytes()?,
            header: r.take()?,
            index: u32::from_be_bytes(r.take()?),
            path: r.list()?,
            coinbase: r.bytes()?,
            coinbase_path: r.list()?,
            reserved: match carrier {
                Carrier::Nulldata => None,
                Carrier::Leaf => Some(r.take()?),
            },
        })
    }
}

/// `respond` in a block, with its witness, as [`Request`] is: the
/// transaction (witness serialization), the block's header, its index and
/// path in the witness tree, the coinbase (non-witness), its path in the
/// txid tree and its witness reserved value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Respond {
    pub tx: Vec<u8>,
    pub header: [u8; 80],
    pub index: u32,
    pub path: Vec<Hash>,
    pub coinbase: Vec<u8>,
    pub coinbase_path: Vec<Hash>,
    pub reserved: Hash,
}

impl Respond {
    /// The witness of its input spending output 0 of `request` (a txid):
    /// none unless it spends it and is in the header's block.
    pub fn spending(&self, request: &Hash) -> Option<Vec<&[u8]>> {
        if !btc::witness_in_block(
            &self.tx,
            &Header(self.header),
            self.index,
            &self.path,
            &self.coinbase,
            &self.coinbase_path,
            &self.reserved,
        ) {
            return None;
        }
        input_witness(
            &self.tx,
            &OutPoint {
                txid: *request,
                vout: 0,
            },
        )
    }

    pub fn write(&self, w: &mut W) {
        w.bytes(&self.tx);
        w.put(&self.header);
        w.put(&self.index.to_be_bytes());
        w.list(&self.path);
        w.bytes(&self.coinbase);
        w.list(&self.coinbase_path);
        w.put(&self.reserved);
    }

    pub fn read(r: &mut R) -> Result<Respond, Reject> {
        Ok(Respond {
            tx: r.bytes()?,
            header: r.take()?,
            index: u32::from_be_bytes(r.take()?),
            path: r.list()?,
            coinbase: r.bytes()?,
            coinbase_path: r.list()?,
            reserved: r.take()?,
        })
    }
}

/// The work of headers on top of block `from`, if each follows the last
/// and is within its own target.
pub fn work_on(from: &Hash, headers: &[[u8; 80]]) -> Option<u128> {
    let mut prev = *from;
    let mut sum = 0u128;
    for h in headers {
        let h = Header(*h);
        let hash = h.hash();
        if h.prev() != prev || !h.pow_met_by(hash) {
            return None;
        }
        sum = sum.saturating_add(work(h.bits()));
        prev = hash;
    }
    Some(sum)
}

// ----- the contract, the exit, and the statement -----

/// A block both sides checked at opening: the headers start on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    /// Its hash, in internal order.
    pub hash: Hash,
}

/// What the contract fixes of its statement at opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contract {
    /// The contract's number.
    pub c: u32,
    /// The L2's word: what else its statement depends on (its keys and
    /// terms), hashed. An L2 binds there whatever its grounds rest on.
    pub d: Hash,
    /// The deposit coin its funding spends: what names its `request`.
    pub deposit: OutPoint,
    pub checkpoint: Checkpoint,
    /// The work `W` on top of the exit's last block.
    pub work: u128,
    /// How its payout counts a signed word. Not in the journal: the L2
    /// derives it from the terms `d` binds.
    pub payout: Payout,
}

/// A payout's outputs, as they count a signed word (`lichen_contract`'s
/// `Terms::amount`): bit `i` of the word `2^i` units, but with a rest
/// (`rest > 0`) bit `bits` that rest's units, the output beyond the binary
/// ones that makes the contract any size. A word with no rest is its
/// number, as before there was one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Payout {
    pub bits: u32,
    pub rest: u32,
}

impl Payout {
    /// What `word` counts, in units: the word, its bit `bits` counting the
    /// rest instead of `2^bits` (below it). Any other bit counts as in a
    /// number, so a word is never counted less than its outputs pay.
    pub fn amount(&self, word: u32) -> u32 {
        let k = 1u64 << self.bits;
        match self.rest > 0 && u64::from(word) & k != 0 {
            true => (u64::from(word) - k + u64::from(self.rest)) as u32,
            false => word,
        }
    }
}

/// The journal's length: `c ‖ D ‖ H(O_D ‖ checkpoint ‖ W)`.
pub const JOURNAL_LEN: usize = 68;

impl Contract {
    /// `H(O_D ‖ checkpoint ‖ W)`, as the journal commits it.
    pub fn digest(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"lichen/hp/contract");
        h.update(self.deposit.to_bytes());
        h.update(self.checkpoint.height.to_be_bytes());
        h.update(self.checkpoint.hash);
        h.update(self.work.to_be_bytes());
        h.finalize().into()
    }

    /// The journal `c ‖ D ‖ H(O_D ‖ checkpoint ‖ W)`, `c` little-endian:
    /// what BABE's instances, garbled at opening, take as the statement's
    /// public input.
    pub fn journal(&self) -> [u8; JOURNAL_LEN] {
        let mut j = [0u8; JOURNAL_LEN];
        j[..4].copy_from_slice(&self.c.to_le_bytes());
        j[4..36].copy_from_slice(&self.d);
        j[36..].copy_from_slice(&self.digest());
        j
    }

    pub fn write(&self, w: &mut W) {
        w.put(&self.c.to_be_bytes());
        w.put(&self.d);
        w.put(&self.deposit.to_bytes());
        w.put(&self.checkpoint.height.to_be_bytes());
        w.put(&self.checkpoint.hash);
        w.put(&self.work.to_be_bytes());
        w.put(&self.payout.bits.to_be_bytes());
        w.put(&self.payout.rest.to_be_bytes());
    }

    pub fn read(r: &mut R) -> Result<Contract, Reject> {
        Ok(Contract {
            c: u32::from_be_bytes(r.take()?),
            d: r.take()?,
            deposit: OutPoint::from_bytes(&r.take()?),
            checkpoint: Checkpoint {
                height: u32::from_be_bytes(r.take()?),
                hash: r.take()?,
            },
            work: u128::from_be_bytes(r.take()?),
            payout: Payout {
                bits: u32::from_be_bytes(r.take()?),
                rest: u32::from_be_bytes(r.take()?),
            },
        })
    }
}

/// The exit on Bitcoin, as the hub shows it: the headers on the
/// checkpoint, through the last block of `request`, her publication,
/// `respond` and its disclosure (none: nothing disclosed), and on with
/// the contract's work on top; and those transactions, each in its block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub headers: Vec<[u8; 80]>,
    pub request: Request,
    pub publish: SlotSpend,
    pub respond: Respond,
    pub disclosure: Option<SlotSpend>,
}

impl Exit {
    pub fn write(&self, w: &mut W) {
        w.list(&self.headers);
        self.request.write(w);
        self.publish.write(w);
        self.respond.write(w);
        match &self.disclosure {
            None => w.put(&[0]),
            Some(d) => {
                w.put(&[1]);
                d.write(w);
            }
        }
    }

    /// One written by [`Self::write`] of a contract whose slots `carrier`
    /// carries ([`SlotSpend::read`]).
    pub fn read(r: &mut R, carrier: Carrier) -> Result<Exit, Reject> {
        Ok(Exit {
            headers: r.list()?,
            request: Request::read(r)?,
            publish: SlotSpend::read(r, carrier)?,
            respond: Respond::read(r)?,
            disclosure: match r.take()? {
                [0] => None,
                [1] => Some(SlotSpend::read(r, carrier)?),
                _ => return Err(Reject::Encoding),
            },
        })
    }
}

/// The heights of the exit's blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heights {
    pub request: u32,
    pub publish: u32,
    pub respond: u32,
    pub disclosure: Option<u32>,
}

/// What the exit shows: what the L2's grounds judge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    /// What she claims (the word she signed in `request`, as the payout
    /// counts it, [`Payout::amount`]), and her claim's fingerprint `E`, as
    /// she signed it.
    pub b: u32,
    pub e: Hash,
    /// The bytes her publication carries: her claim, if she made one (the
    /// L2 checks they are one, and hash to `E`). Empty if the slot's spend
    /// carries none, or nulldata that isn't pushes only.
    pub claim: Vec<u8>,
    /// What the hub's response says she is owed (the word it signed, as
    /// the payout counts it): below `b`, or 0.
    pub b2: u32,
    /// The bytes the hub's disclosure carries, if it disclosed.
    pub disclosed: Option<Vec<u8>>,
    pub heights: Heights,
}

/// The blocks an exit's transactions are in, as the statement reads them:
/// a chain from the contract's checkpoint, shown in full ([`Dense`]) or
/// proven beforehand and opened where the exit needs it (`licash-hp`'s
/// `headers`). What it holds of them is the same: where a block is, and the
/// work above it.
pub trait Blocks {
    /// Whether the blocks are a chain from the contract's checkpoint, each
    /// within its own target.
    fn linked(&self, contract: &Contract) -> bool;
    /// The height of the block of `header` on the chain, if it is on it
    /// and above the checkpoint.
    fn height_of(&self, contract: &Contract, header: &[u8; 80]) -> Option<u32>;
    /// The work of the chain above the block at `height`, which
    /// `height_of` found.
    fn work_above(&self, contract: &Contract, height: u32) -> Option<u128>;
}

/// Every header of the exit, after the checkpoint.
pub struct Dense<'a>(pub &'a [[u8; 80]]);

impl Blocks for Dense<'_> {
    fn linked(&self, contract: &Contract) -> bool {
        work_on(&contract.checkpoint.hash, self.0).is_some()
    }

    fn height_of(&self, contract: &Contract, header: &[u8; 80]) -> Option<u32> {
        let at = self.0.iter().position(|x| x == header)?;
        Some(
            contract
                .checkpoint
                .height
                .saturating_add(1)
                .saturating_add(at as u32),
        )
    }

    fn work_above(&self, contract: &Contract, height: u32) -> Option<u128> {
        let at = height
            .checked_sub(contract.checkpoint.height)?
            .checked_sub(1)?;
        let after = self.0.get(at as usize + 1..)?;
        Some(
            after
                .iter()
                .fold(0u128, |s, h| s.saturating_add(work(Header(*h).bits()))),
        )
    }
}

/// Read `exit` for `contract`: its transactions, each in a block among
/// the headers, which follow the checkpoint, with the contract's work on
/// top of the last of those blocks.
pub fn read(contract: &Contract, exit: &Exit) -> Result<Read, Reject> {
    read_on(contract, exit, &Dense(&exit.headers))
}

/// [`read`] with the blocks `blocks` (which the exit's own `headers` are
/// not, or not all of, under a chain proven beforehand).
pub fn read_on(contract: &Contract, exit: &Exit, blocks: &impl Blocks) -> Result<Read, Reject> {
    if !blocks.linked(contract) {
        return Err(Reject::Depth);
    }
    let position = |h: &[u8; 80]| blocks.height_of(contract, h).ok_or(Reject::Depth);
    let witness = exit
        .request
        .spending(&contract.deposit)
        .ok_or(Reject::Posted)?;
    let Requested { b, e } = requested(&witness).ok_or(Reject::Posted)?;
    let b = contract.payout.amount(b);
    let request = exit.request.txid().ok_or(Reject::Posted)?;
    let claim = exit
        .publish
        .carrying(&OutPoint {
            txid: request,
            vout: SLOT_VOUT,
        })
        .ok_or(Reject::Posted)?;
    let b2 = exit
        .respond
        .spending(&request)
        .and_then(|w| responded(&w))
        .map(|word| contract.payout.amount(word))
        .ok_or(Reject::Responded)?;
    // b′ below her b (at b′ = b the hub would keep its reserve from an
    // honest claim), or 0 (a claim of nothing, which it may still prove
    // false)
    if b2 != 0 && b2 >= b {
        return Err(Reject::Conceded);
    }
    let disclosed = match &exit.disclosure {
        None => None,
        Some(d) => {
            let respond = sha256d(&btc::bare_tx(&exit.respond.tx).ok_or(Reject::Responded)?);
            Some(
                d.carrying(&OutPoint {
                    txid: respond,
                    vout: SLOT_VOUT,
                })
                .ok_or(Reject::Disclosed)?,
            )
        }
    };
    let at = [
        position(&exit.request.header)?,
        position(&exit.publish.header)?,
        position(&exit.respond.header)?,
    ];
    let disclosure = exit
        .disclosure
        .as_ref()
        .map(|d| position(&d.header))
        .transpose()?;
    // the work on the last block: earlier work doesn't protect a later
    // block against fabrication
    let last = at
        .iter()
        .copied()
        .chain(disclosure)
        .max()
        .expect("three blocks");
    if blocks.work_above(contract, last).ok_or(Reject::Depth)? < contract.work {
        return Err(Reject::Depth);
    }
    let heights = Heights {
        request: at[0],
        publish: at[1],
        respond: at[2],
        disclosure,
    };
    Ok(Read {
        b,
        e,
        claim,
        b2,
        disclosed,
        heights,
    })
}

/// The statement, once the L2 has found what the claim `read` is owed:
/// it holds if that is at most `b′`. On success, the journal.
pub fn holds(contract: &Contract, read: &Read, owed: u32) -> Result<[u8; JOURNAL_LEN], Reject> {
    if owed > read.b2 {
        return Err(Reject::Owed);
    }
    Ok(contract.journal())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::testing::*;
    use super::*;

    #[test]
    fn work_and_targets() {
        // regtest's bits: target 0x7fffff · 256^29, work 2
        assert_eq!(work(0x207fffff), 2);
        let t = btc::target(0x207fffff).unwrap();
        assert_eq!((t[0], t[1], t[2], t[3]), (0x7f, 0xff, 0xff, 0));
        // mainnet's genesis: 0x1d00ffff, work 2^32 + 2^16 + 1 (about 2^32)
        assert_eq!(work(0x1d00ffff), (1u128 << 48) / 0xffff);
        assert_eq!(work(0x1d00ffff), 4295032833);
        // no target: negative, zero
        assert_eq!(work(0x1d800000), 0);
        assert_eq!(work(0x1d000000), 0);
        assert!(btc::target(0x22010000).is_none(), "beyond 256 bits");
    }

    /// Past 2^128 only once the work is: below, rounded down as ever.
    #[test]
    fn work_saturates_only_once_it_is_past_what_a_u128_holds() {
        // Exponent 19, the largest mantissa: 2^128 / 0x7fffff, about 2^105.
        let w = work(0x137fffff);
        assert!(w > 1 << 105 && w < (1 << 105) + (1 << 83), "{w}");
        assert_eq!(w, 40564824043007195767232224305152);
        // Exponent 19, a mantissa of 1: 2^128, past it.
        assert_eq!(work(0x13000001), u128::MAX);
        // Exponents 18 and 17: 2^136 and 2^144 over it, about 2^113 and
        // 2^121, as exact as ever.
        assert_eq!(work(0x127fffff), 10384594955009842116411449422118912);
        assert_eq!(work(0x117fffff), 2658456308482519581801331052062441536);
        // Exponent 16 and below: past it whatever the mantissa.
        assert_eq!(work(0x107fffff), u128::MAX);
        assert_eq!(work(0x03000001), u128::MAX);
    }

    #[test]
    fn carrier_encoding_and_parsing() {
        for n in [0, 1, 75, 76, 255, 256, 520, 521, 1200, 99_000] {
            let bytes = vec![0x42; n];
            let script = claim_script(&bytes).unwrap();
            assert_eq!(pushes(&script).unwrap().concat(), bytes);
            assert!(pushes(&script)
                .unwrap()
                .iter()
                .all(|p| p.len() <= CARRIER_PUSH));
        }
        assert!(claim_script(&vec![0; CARRIER_BUDGET]).is_none());
        for n in 1..=16 {
            assert_eq!(claim_script(&[n]).unwrap(), vec![0x6a, 0x50 + n]);
            assert_eq!(pushes(&[0x6a, 0x50 + n]).unwrap().concat(), vec![n]);
        }
        assert_eq!(pushes(&[0x6a, 0, 0x4f]).unwrap().concat(), vec![0x81]);
        // Readers accept nonminimal encodings, but not operations,
        // truncated pushes, or pushes beyond the carrier limit.
        assert_eq!(
            pushes(&[0x6a, 0x4e, 1, 0, 0, 0, 0x42]).unwrap().concat(),
            vec![0x42]
        );
        for script in [
            &[0x51][..],
            &[0x6a, 0x76],
            &[0x6a, 2, 1],
            &[0x6a, 0x4c],
            &[0x6a, 0x4d, 1],
        ] {
            assert!(pushes(script).is_none());
        }
        let mut oversized = vec![0x6a, 0x4d, 9, 2];
        oversized.extend(vec![0; 521]);
        assert!(pushes(&oversized).is_none());
        let a = claim_script(&[1, 2]).unwrap();
        let b = claim_script(&[3, 4]).unwrap();
        let mut tx = btc::Tx {
            inputs: vec![],
            outputs: vec![(0, &a), (1, &[0x51]), (0, &b)],
        };
        assert_eq!(carried(&tx), Some(vec![1, 2, 3, 4]));
        tx.outputs.push((0, &[0x6a, 0x76]));
        assert_eq!(carried(&tx), None);
    }

    #[test]
    fn the_exit_reads_back_with_its_heights() {
        let x = exit(5, [7; 32], b"her claim", 3);
        let read = read(&x.contract, &x.exit).unwrap();
        // the checkpoint at height 100, request in the first header on it,
        // the publication in the next, respond after ten more
        let heights = Heights {
            request: 101,
            publish: 102,
            respond: 113,
            disclosure: None,
        };
        assert_eq!(
            read,
            Read {
                b: 5,
                e: [7; 32],
                claim: b"her claim".to_vec(),
                b2: 3,
                disclosed: None,
                heights
            }
        );
        // a disclosure, ten headers on it
        let mut x = x;
        x.disclose(b"an unlock");
        let read = super::read(&x.contract, &x.exit).unwrap();
        assert_eq!(
            (read.disclosed.as_deref(), read.heights.disclosure),
            (Some(&b"an unlock"[..]), Some(124))
        );
        // the input round-trips
        let mut w = W::default();
        x.contract.write(&mut w);
        x.exit.write(&mut w);
        let mut r = R(&w.0);
        assert_eq!(
            (
                Contract::read(&mut r).unwrap(),
                Exit::read(&mut r, Carrier::Nulldata).unwrap()
            ),
            (x.contract, x.exit.clone())
        );
        r.end().unwrap();
        let mut r = R(&w.0[..w.0.len() - 1]);
        Contract::read(&mut r).unwrap();
        assert_eq!(Exit::read(&mut r, Carrier::Nulldata), Err(Reject::Encoding));
    }

    /// Of a leaf carrier: her claim and the hub's disclosure read from the
    /// envelopes in their witnesses, by the witness tree, as nulldata is.
    #[test]
    fn a_leaf_carrier_reads_the_envelopes_of_its_spends() {
        let mut x = leaf_exit(5, [7; 32], &[0xab; 1300], 3);
        x.disclose_leaf(b"an unlock");
        let got = read(&x.contract, &x.exit).unwrap();
        assert_eq!(got.claim, vec![0xab; 1300]);
        assert_eq!(got.disclosed.as_deref(), Some(&b"an unlock"[..]));
        assert_eq!(
            (got.heights.publish, got.heights.disclosure),
            (102, Some(124))
        );
        // the input round-trips only as the contract's carrier
        let mut w = W::default();
        x.exit.write(&mut w);
        let mut r = R(&w.0);
        assert_eq!(Exit::read(&mut r, Carrier::Leaf).unwrap(), x.exit);
        r.end().unwrap();
        let mut r = R(&w.0);
        let shaped = Exit::read(&mut r, Carrier::Nulldata).and_then(|e| r.end().map(|_| e));
        assert!(shaped.is_err());
        // a nulldata reading of it: its txid isn't in the txid tree
        let mut e = x.exit.clone();
        e.publish.reserved = None;
        assert_eq!(read(&x.contract, &e), Err(Reject::Posted));
        // a changed witness: not the transaction the block committed
        let mut e = x.exit.clone();
        let n = e.publish.tx.len();
        e.publish.tx[n - 10] ^= 1;
        assert_eq!(read(&x.contract, &e), Err(Reject::Posted));
        // another reserved value: not the commitment
        let mut e = x.exit.clone();
        e.publish.reserved = Some([0x5b; 32]);
        assert_eq!(read(&x.contract, &e), Err(Reject::Posted));
    }

    #[test]
    fn an_envelope_is_read_from_a_script_path_spend_alone() {
        let key = [0x4b; 32];
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1100).collect();
        let script = envelope_script(&key, &bytes).unwrap();
        assert_eq!(enveloped(&script), Some(bytes.clone()));
        // the bytes of 1, 16 and 0x81, as Bitcoin pushes them
        for one in [[1u8], [16], [0x81], [0]] {
            let script = envelope_script(&key, &one).unwrap();
            assert_eq!(enveloped(&script), Some(one.to_vec()));
        }
        assert_eq!(
            enveloped(&envelope_script(&key, &[]).unwrap()),
            Some(vec![])
        );
        // more than pushes, or not closed: none
        let mut bad = script.clone();
        bad.insert(bad.len() - 1, 0x76);
        assert_eq!(enveloped(&bad), None);
        assert_eq!(enveloped(&script[..script.len() - 1]), None);
        // a script path: the script below the control block, an annex left
        // out; a key path, or a control block not a tapscript's, none
        let control = vec![0xc1; 65];
        let sig = vec![1; 64];
        assert_eq!(leaf_script(&[&sig, &script, &control]), Some(&script[..]));
        assert_eq!(
            leaf_script(&[&sig, &script, &control, &[0x50, 1]]),
            Some(&script[..])
        );
        assert_eq!(leaf_script(&[&sig]), None);
        assert_eq!(leaf_script(&[&sig, &script, &vec![0xc2; 33]]), None);
        assert_eq!(leaf_script(&[&sig, &script, &vec![0xc0; 34]]), None);
        // each input's envelope, in input order
        let (tx, _) = tx_spending_all(&[
            (
                OutPoint {
                    txid: [1; 32],
                    vout: 0,
                },
                envelope_witness(b"one "),
            ),
            (
                OutPoint {
                    txid: [2; 32],
                    vout: 0,
                },
                vec![vec![9; 64]],
            ),
            (
                OutPoint {
                    txid: [3; 32],
                    vout: 0,
                },
                envelope_witness(b"two"),
            ),
        ]);
        let tx = btc::parse_witness_tx(&tx).unwrap();
        assert_eq!(carried_in_leaves(&tx), b"one two".to_vec());
    }

    #[test]
    fn the_statement_holds_of_what_is_owed_at_most_b2() {
        let x = exit(5, [7; 32], b"", 3);
        let read = read(&x.contract, &x.exit).unwrap();
        for owed in 0..=3 {
            assert_eq!(holds(&x.contract, &read, owed), Ok(x.contract.journal()));
        }
        assert_eq!(holds(&x.contract, &read, 4), Err(Reject::Owed));
        // the journal: c, D, then the digest of the deposit, checkpoint and W
        let j = x.contract.journal();
        assert_eq!(
            (&j[..4], &j[4..36], &j[36..]),
            (
                &x.contract.c.to_le_bytes()[..],
                &x.contract.d[..],
                &x.contract.digest()[..]
            )
        );
        for other in [
            Contract {
                deposit: OutPoint {
                    vout: 2,
                    ..x.contract.deposit
                },
                ..x.contract
            },
            Contract {
                checkpoint: Checkpoint {
                    height: 99,
                    ..x.contract.checkpoint
                },
                ..x.contract
            },
            Contract {
                checkpoint: Checkpoint {
                    hash: [1; 32],
                    ..x.contract.checkpoint
                },
                ..x.contract
            },
            Contract {
                work: 21,
                ..x.contract
            },
        ] {
            assert_ne!(other.digest(), x.contract.digest());
        }
        // the payout is not the journal's: the L2's terms in D bind it
        let other = Contract {
            payout: Payout { bits: 3, rest: 5 },
            ..x.contract
        };
        assert_eq!(other.journal(), x.contract.journal());
    }

    #[test]
    fn the_headers_follow_the_checkpoint() {
        let x = exit(5, [7; 32], b"", 3);
        // headers on another block
        let mut c = x.contract;
        c.checkpoint.hash = [1; 32];
        assert_eq!(read(&c, &x.exit), Err(Reject::Depth));
        // a header dropped from the middle
        let mut e = x.exit.clone();
        e.headers.remove(5);
        assert_eq!(read(&x.contract, &e), Err(Reject::Depth));
        // the request's block not among them
        let mut e = x.exit.clone();
        let (h, request) = request_on(
            &[0x55; 32],
            &x.contract.deposit,
            &request_witness(&[7; 32], 5),
        );
        e.request = Request {
            header: h,
            ..request
        };
        assert_eq!(read(&x.contract, &e), Err(Reject::Depth));
        // more work asked than the headers carry on respond's block
        let mut c = x.contract;
        c.work += 1;
        assert_eq!(read(&c, &x.exit), Err(Reject::Depth));
    }

    #[test]
    fn a_digit_reads_as_the_script_reads_it() {
        for (item, digit) in [
            (&[][..], Some(0)),
            (&[0][..], Some(0)),
            (&[0x80][..], Some(0)),
            (&[0, 0, 0, 0x80][..], Some(0)),
            (&[7][..], Some(7)),
            (&[7, 0][..], Some(7)),
            (&[15][..], Some(15)),
            (&[16][..], Some(15)),
            (&[0x7f][..], Some(15)),
            (&[0, 1][..], Some(15)),
            (&[0xff, 0xff, 0xff, 0x7f][..], Some(15)),
            (&[0x81][..], None),
            (&[0, 0x80, 0][..], Some(15)),
            (&[1, 0x80][..], None),
            (&[0, 0, 0, 0, 0][..], None),
        ] {
            assert_eq!(script_digit(item), digit, "{item:?}");
        }
        // A request whose 15s are written as 16, as Bitcoin accepts it:
        // the same `b` and `E`.
        let honest = request_witness(&[0xf7; 32], 0x0f0f_f0ff);
        let mut loose = honest.clone();
        for item in loose.iter_mut().filter(|i| i.as_slice() == [15]) {
            *item = vec![16];
        }
        assert_ne!(loose, honest);
        fn items(w: &[Vec<u8>]) -> Vec<&[u8]> {
            w.iter().map(Vec::as_slice).collect()
        }
        assert_eq!(requested(&items(&loose)), requested(&items(&honest)));
        assert_eq!(requested(&items(&loose)).map(|r| r.b), Some(0x0f0f_f0ff));
        // A negative digit fails the script: no request.
        let mut negative = honest;
        let at = negative.iter().position(|i| i.as_slice() == [15]).unwrap();
        negative[at] = vec![0x81];
        assert_eq!(requested(&items(&negative)), None);
    }

    #[test]
    fn the_request_names_the_contract() {
        let x = exit(5, [7; 32], b"", 3);
        // another deposit coin: another contract's request
        let mut c = x.contract;
        c.deposit.vout += 1;
        assert_eq!(read(&c, &x.exit), Err(Reject::Posted));
        // a witness that isn't a request's: an item slipped in below
        let mut witness = request_witness(&[7; 32], 5);
        witness.insert(0, vec![0xde, 0xad]);
        let y = exit_with(&witness, b"", 3);
        assert_eq!(read(&y.contract, &y.exit), Err(Reject::Posted));
        // a changed witness path
        let mut e = x.exit.clone();
        e.request.path[0][0] ^= 1;
        assert_eq!(read(&x.contract, &e), Err(Reject::Posted));
    }

    #[test]
    fn the_publication_spends_the_requests_slot() {
        let witness = request_witness(&[7; 32], 5);
        let x = exit_with(&witness, b"her claim", 3);
        // another output of request's
        let y = exit_publishing(
            &witness,
            |prev, slot| {
                published(
                    prev,
                    &OutPoint {
                        vout: SLOT_VOUT + 1,
                        ..*slot
                    },
                    b"her claim",
                )
            },
            3,
        );
        assert_eq!(read(&y.contract, &y.exit), Err(Reject::Posted));
        // a changed txid path
        let mut e = x.exit.clone();
        e.publish.path[0][0] ^= 1;
        assert_eq!(read(&x.contract, &e), Err(Reject::Posted));
        // off the headers' chain: it spends the slot, but no work covers it
        let mut e = x.exit.clone();
        let slot = OutPoint {
            txid: x.exit.request.txid().unwrap(),
            vout: SLOT_VOUT,
        };
        e.publish = published(&[0x55; 32], &slot, b"her claim");
        assert_eq!(read(&x.contract, &e), Err(Reject::Depth));
        // nulldata that isn't pushes only: no claim
        let y = exit_publishing(
            &witness,
            |prev, slot| {
                let mut tx = spend_of(slot);
                let n = tx.len();
                tx[n - 6..n - 4].copy_from_slice(&[2, 0x6a]);
                tx.insert(n - 4, 0x76);
                slot_spend_on(prev, tx)
            },
            3,
        );
        assert_eq!(read(&y.contract, &y.exit).map(|r| r.claim), Ok(vec![]));
    }

    /// With a rest, `b` and `b′` are the words as the payout counts them:
    /// of 12 units (1, 2, 4 and a rest of 5), the word `0b1101` is 10.
    #[test]
    fn the_words_are_read_as_the_payout_counts_them() {
        let payout = Payout { bits: 3, rest: 5 };
        assert_eq!(
            [0, 7, 0b1000, 0b1011, 0b1101, 0b1111, 16].map(|w| payout.amount(w)),
            [0, 7, 5, 8, 10, 12, 16]
        );
        assert_eq!(Payout::default().amount(u32::MAX), u32::MAX);
        let answered = |b: u32, b2: u32| {
            let mut x = exit(b, [7; 32], b"", b2);
            x.contract.payout = payout;
            read(&x.contract, &x.exit).map(|r| (r.b, r.b2))
        };
        assert_eq!(answered(0b1101, 7), Ok((10, 7)));
        assert_eq!(answered(0b1101, 0b1011), Ok((10, 8)));
        assert_eq!(answered(0b1101, 0b1000), Ok((10, 5)));
        // conceded as the payout counts it: 10, and 16
        assert_eq!(answered(0b1101, 0b1101), Err(Reject::Conceded));
        assert_eq!(answered(0b1101, 16), Err(Reject::Conceded));
        // the rest alone is 5, below 7: no rest, 8, above
        assert_eq!(answered(7, 0b1000), Ok((7, 5)));
        let x = exit(7, [7; 32], b"", 0b1000);
        assert_eq!(read(&x.contract, &x.exit), Err(Reject::Conceded));
    }

    #[test]
    fn the_response_spends_the_request_and_reduces_the_claim() {
        let answered = |b: u32, b2: u32| {
            let x = exit(b, [7; 32], b"", b2);
            read(&x.contract, &x.exit).map(|r| r.b2)
        };
        assert_eq!((answered(5, 0), answered(5, 4)), (Ok(0), Ok(4)));
        // at b′ = b the hub concedes: it would keep its reserve
        assert_eq!(
            (answered(5, 5), answered(5, 6)),
            (Err(Reject::Conceded), Err(Reject::Conceded))
        );
        // a claim of nothing is answered with 0, and only 0
        assert_eq!(
            (answered(0, 0), answered(0, 1)),
            (Ok(0), Err(Reject::Conceded))
        );
        // a spend of another output of request's, a witness with an item
        // slipped in below: not a respond
        let x = exit(5, [7; 32], b"", 3);
        let request = x.exit.request.txid().unwrap();
        let at = x
            .exit
            .headers
            .iter()
            .position(|h| *h == x.exit.respond.header)
            .unwrap();
        let spending = |op: &OutPoint, witness: &[Vec<u8>]| {
            let mut e = x.exit.clone();
            let (h, respond) = respond_spending(&sha256d(&e.headers[at - 1]), op, witness);
            e.headers.truncate(at);
            e.headers.push(h);
            e.headers.extend(headers_on(&sha256d(&h), 10));
            e.respond = respond;
            read(&x.contract, &e).map(|r| r.b2)
        };
        let main = OutPoint {
            txid: request,
            vout: 0,
        };
        assert_eq!(spending(&main, &respond_witness(3, &[])), Ok(3));
        assert_eq!(
            spending(&OutPoint { vout: 1, ..main }, &respond_witness(3, &[])),
            Err(Reject::Responded)
        );
        assert_eq!(
            spending(&main, &respond_witness(3, &[vec![0xde, 0xad]])),
            Err(Reject::Responded)
        );
        // a changed witness path
        let mut e = x.exit.clone();
        e.respond.path[0][0] ^= 1;
        assert_eq!(read(&x.contract, &e), Err(Reject::Responded));
        // off the headers' chain
        let mut e = x.exit.clone();
        e.respond = respond_block(&[0x55; 32], &e.request.tx, 3).1;
        assert_eq!(read(&x.contract, &e), Err(Reject::Depth));
        // in one header on top: no work covers it
        let mut e = x.exit.clone();
        let (h, respond) = respond_block(&sha256d(e.headers.last().unwrap()), &e.request.tx, 3);
        e.respond = respond;
        e.headers.push(h);
        assert_eq!(read(&x.contract, &e), Err(Reject::Depth));
    }

    #[test]
    fn a_disclosure_spends_the_responds_slot_with_work_on_it() {
        let x = exit(5, [7; 32], b"", 3);
        // her publication's slot, or another output of respond's
        let request = x.exit.request.txid().unwrap();
        for other in [
            OutPoint {
                txid: request,
                vout: SLOT_VOUT,
            },
            OutPoint {
                vout: SLOT_VOUT + 1,
                ..x.disclose_slot()
            },
        ] {
            let mut y = x.clone();
            y.disclose_from(&other, b"an unlock");
            assert_eq!(read(&y.contract, &y.exit), Err(Reject::Disclosed));
        }
        // ten headers short of the work
        let mut y = x.clone();
        y.disclose(b"an unlock");
        y.exit.headers.truncate(y.exit.headers.len() - 10);
        assert_eq!(read(&y.contract, &y.exit), Err(Reject::Depth));
    }
}
