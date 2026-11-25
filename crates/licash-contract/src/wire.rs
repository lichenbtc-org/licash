//! Canonical, versioned opening messages. Counts are bounded by the
//! remaining input before allocation, and decoders require the whole body.
use anyhow::{ensure, Context, Result};
use k256::ProjectivePoint;
use licash::{
    base::{Base, ChainTerms, Fees, GraphTerms, Limits, Recipe},
    chain::Checkpoint,
    crypto::Point,
    note::Keyset,
};
use lichen_babe::{
    opening::Opened as ShareOpening,
    reveal::LamportPub,
    setup::{DIGITS, VALUES},
    vsss::Dealing,
};
use lichen_btc::{
    adaptor::AdaptorSig,
    bitcoin::{
        consensus::{deserialize, serialize},
        secp256k1::{PublicKey, SecretKey, XOnlyPublicKey},
        OutPoint, ScriptBuf, Transaction, TxOut, Witness,
    },
};
use lichen_contract::PartyPubKeys;
use lichen_wots::{WotsParams, WotsPublic};
use std::collections::HashMap;

use crate::{
    graph::{HolderPub, HubPub},
    opening::Quote,
};

pub const MAGIC: [u8; 4] = *b"LCOP";
/// 3: she signs her deposit into F first, in her Consent, and the hub
/// signs its inputs only once it holds the whole F, which it broadcasts
/// and answers ([`Funded`]). Under 2 the hub signed first ([`Signed`]),
/// handing out its signatures on an F she might never sign.
pub const VERSION: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Open = 1,
    Terms,
    Commit,
    Choose,
    Opened,
    Instance,
    Offer,
    Consent,
    Signed,
    Funded,
}

impl Kind {
    pub fn from_u8(n: u8) -> Option<Self> {
        Some(match n {
            1 => Self::Open,
            2 => Self::Terms,
            3 => Self::Commit,
            4 => Self::Choose,
            5 => Self::Opened,
            6 => Self::Instance,
            7 => Self::Offer,
            8 => Self::Consent,
            9 => Self::Signed,
            10 => Self::Funded,
            _ => return None,
        })
    }

    pub fn peek(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 7 || bytes[..4] != MAGIC || bytes[4..6] != VERSION.to_be_bytes() {
            return None;
        }
        Self::from_u8(bytes[6])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    pub id: [u8; 32],
    pub body: Vec<u8>,
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(&MAGIC);
        w.u16(VERSION);
        w.u8(self.kind as u8);
        w.bytes(&self.id);
        w.blob(&self.body);
        w.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        ensure!(r.array::<4>()? == MAGIC, "not an opening message");
        ensure!(r.u16()? == VERSION, "another opening version");
        let kind = Kind::from_u8(r.u8()?).context("unknown message kind")?;
        let id = r.array()?;
        let body = r.blob()?.to_vec();
        r.end()?;
        Ok(Self { kind, id, body })
    }
}

#[derive(Default)]
pub struct Writer(pub Vec<u8>);
pub struct Reader<'a>(pub &'a [u8]);

impl Writer {
    pub fn u8(&mut self, n: u8) {
        self.0.push(n);
    }
    pub fn u16(&mut self, n: u16) {
        self.bytes(&n.to_be_bytes());
    }
    pub fn u32(&mut self, n: u32) {
        self.bytes(&n.to_be_bytes());
    }
    pub fn u64(&mut self, n: u64) {
        self.bytes(&n.to_be_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    pub fn count(&mut self, n: usize) {
        self.u32(n.try_into().expect("count fits u32"));
    }
    pub fn blob(&mut self, b: &[u8]) {
        self.count(b.len());
        self.bytes(b);
    }
    pub fn tx(&mut self, tx: &Transaction) {
        self.blob(&serialize(tx));
    }
    pub fn outpoint(&mut self, op: &OutPoint) {
        self.bytes(&serialize(op));
    }
    pub fn txout(&mut self, out: &TxOut) {
        self.blob(&serialize(out));
    }
    pub fn party(&mut self, p: &PartyPubKeys) {
        for k in [p.funding, p.payment, p.delayed] {
            self.bytes(&k.serialize());
        }
        self.blob(p.payout_spk.as_bytes());
    }
    pub fn hashes<const N: usize>(&mut self, hashes: &[[u8; N]]) {
        self.count(hashes.len());
        for hash in hashes {
            self.bytes(hash);
        }
    }
    pub fn digits<T>(&mut self, digits: &[[T; VALUES]], mut each: impl FnMut(&mut Self, &T)) {
        self.count(digits.len());
        for v in digits.iter().flatten() {
            each(self, v);
        }
    }
    pub fn dealing(&mut self, d: &Dealing) {
        self.count(d.commitments.len());
        for v in d.commitments.iter().flatten() {
            self.count(v.len());
            for p in v {
                self.bytes(&Point::from_projective(p).0);
            }
        }
    }
    pub fn adaptor_sig(&mut self, s: &AdaptorSig) {
        self.bytes(&s.r_final.serialize());
        self.bytes(&s.r.serialize());
        self.bytes(&s.s_prime.secret_bytes());
    }
    pub fn sigs(&mut self, sigs: &HashMap<String, Vec<u8>>) {
        let mut names: Vec<_> = sigs.keys().collect();
        names.sort();
        self.count(names.len());
        for name in names {
            self.blob(name.as_bytes());
            self.blob(&sigs[name]);
        }
    }
    fn wots(&mut self, key: &WotsPublic) {
        self.u32(key.params.message_digits);
        self.u32(key.params.checksum_digits);
        self.hashes(&key.digits);
    }
    pub fn holder_pub(&mut self, p: &HolderPub) {
        self.wots(&p.b_key);
        self.wots(&p.e_key);
    }
    pub fn hub_pub(&mut self, p: &HubPub) {
        self.wots(&p.b_key);
        self.digits(&p.lamport.0, |w, h| w.bytes(h));
        self.digits(&p.adaptor, |w, k| w.bytes(&k.serialize()));
    }
    pub fn opened(&mut self, opened: &[ShareOpening]) {
        self.count(opened.len());
        for o in opened {
            self.u32(o.i);
            self.bytes(&o.seed);
            self.digits(&o.shares, |w, s| w.bytes(s));
        }
    }
    pub fn quote(&mut self, q: &Quote) {
        self.blob(&q.keyset.to_bytes());
        self.u32(q.cap);
        let g = &q.graph;
        self.u32(g.id);
        self.u64(g.unit_sats);
        self.u8(g.bits);
        self.u8(g.low_bits);
        self.u32(g.deposit_units);
        self.u32(g.close_height);
        self.u64(g.reserve_alice);
        self.u64(g.reserve_hub);
        self.u16(g.to_self_delay);
        for n in [g.commit_fee, g.presign_fee, g.dust] {
            self.u64(n);
        }
        self.u16(g.delta);
        self.u16(g.delta_prime);
        self.u32(g.deadline_margin);
        self.u32(g.request_height);
        for n in [
            g.response_window,
            g.publication_window,
            g.contest_window,
            g.assert_window,
            g.challenge_window,
            g.answer_window,
        ] {
            self.u16(n);
        }
        self.u32(q.recipe.graph_version);
        self.bytes(&q.recipe.program);
        self.u16(q.recipe.instances);
        self.u16(q.recipe.kept);
        self.blob(&q.chain.checkpoint.to_bytes());
        for n in [
            q.chain.funding_depth,
            q.chain.work_depth,
            q.chain.max_headers,
            q.limits.max_transaction_bytes,
            q.limits.max_publication_bytes,
            q.limits.max_authorizations,
            q.limits.max_source_inputs,
        ] {
            self.u32(n);
        }
        self.u64(q.fees.max_rate_sat_per_kvb);
        self.u64(q.fees.opening_fee_quote);
    }
}

impl<'a> Reader<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(n <= self.0.len(), "message cut short");
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn count(&mut self, min: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        ensure!(n <= self.0.len() / min.max(1), "count past message");
        Ok(n)
    }
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let n = self.count(1)?;
        self.take(n)
    }
    pub fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "bytes past message");
        Ok(())
    }
    pub fn tx(&mut self) -> Result<Transaction> {
        Ok(deserialize(self.blob()?)?)
    }
    pub fn outpoint(&mut self) -> Result<OutPoint> {
        Ok(deserialize(self.take(36)?)?)
    }
    pub fn txout(&mut self) -> Result<TxOut> {
        Ok(deserialize(self.blob()?)?)
    }
    pub fn xonly(&mut self) -> Result<XOnlyPublicKey> {
        Ok(XOnlyPublicKey::from_slice(self.take(32)?)?)
    }
    pub fn party(&mut self) -> Result<PartyPubKeys> {
        Ok(PartyPubKeys {
            funding: self.xonly()?,
            payment: self.xonly()?,
            delayed: self.xonly()?,
            payout_spk: ScriptBuf::from_bytes(self.blob()?.to_vec()),
        })
    }
    pub fn hashes<const N: usize>(&mut self) -> Result<Vec<[u8; N]>> {
        let n = self.count(N)?;
        (0..n).map(|_| self.array()).collect()
    }
    pub fn digits<T>(
        &mut self,
        size: usize,
        mut each: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<[T; VALUES]>> {
        let n = self.count(size * VALUES)?;
        ensure!(n == DIGITS, "wrong digit count");
        (0..n)
            .map(|_| {
                let v: Vec<_> = (0..VALUES).map(|_| each(self)).collect::<Result<_>>()?;
                Ok(v.try_into().unwrap_or_else(|_| unreachable!()))
            })
            .collect()
    }
    pub fn dealing(&mut self) -> Result<Dealing> {
        let n = self.count(VALUES * 4)?;
        ensure!(n == DIGITS, "wrong dealing digit count");
        let commitments = (0..n)
            .map(|_| {
                let values: Vec<Vec<ProjectivePoint>> = (0..VALUES)
                    .map(|_| {
                        let n = self.count(33)?;
                        (0..n)
                            .map(|_| {
                                let bytes: [u8; 33] = self.array()?;
                                ensure!(
                                    matches!(bytes[0], 2 | 3),
                                    "dealing point must not be identity"
                                );
                                Ok(Point(bytes).to_projective()?)
                            })
                            .collect()
                    })
                    .collect::<Result<_>>()?;
                Ok(values.try_into().unwrap_or_else(|_| unreachable!()))
            })
            .collect::<Result<_>>()?;
        Ok(Dealing { commitments })
    }
    pub fn adaptor_sig(&mut self) -> Result<AdaptorSig> {
        Ok(AdaptorSig {
            r_final: self.xonly()?,
            r: PublicKey::from_slice(self.take(33)?)?,
            s_prime: SecretKey::from_slice(self.take(32)?)?,
        })
    }
    pub fn sigs(&mut self) -> Result<HashMap<String, Vec<u8>>> {
        let n = self.count(8)?;
        let mut out = HashMap::new();
        let mut last = None;
        for _ in 0..n {
            let name = String::from_utf8(self.blob()?.to_vec())?;
            ensure!(
                last.as_ref() < Some(&name),
                "signatures not strictly ordered"
            );
            out.insert(name.clone(), self.blob()?.to_vec());
            last = Some(name);
        }
        Ok(out)
    }
    fn wots(&mut self) -> Result<WotsPublic> {
        Ok(WotsPublic {
            params: WotsParams {
                message_digits: self.u32()?,
                checksum_digits: self.u32()?,
            },
            digits: self.hashes()?,
        })
    }
    pub fn holder_pub(&mut self) -> Result<HolderPub> {
        let p = HolderPub {
            b_key: self.wots()?,
            e_key: self.wots()?,
        };
        p.check()?;
        Ok(p)
    }
    pub fn hub_pub(&mut self) -> Result<HubPub> {
        let p = HubPub {
            b_key: self.wots()?,
            lamport: LamportPub(self.digits(20, |r| r.array())?),
            adaptor: self.digits(32, |r| r.xonly())?,
        };
        p.check()?;
        Ok(p)
    }
    pub fn opened(&mut self) -> Result<Vec<ShareOpening>> {
        let n = self.count(40)?;
        (0..n)
            .map(|_| {
                Ok(ShareOpening {
                    i: self.u32()?,
                    seed: self.array()?,
                    shares: self.digits(32, |r| r.array())?,
                })
            })
            .collect()
    }
    pub fn quote(&mut self) -> Result<Quote> {
        Ok(Quote {
            keyset: Keyset::from_bytes(self.blob()?)?,
            cap: self.u32()?,
            graph: GraphTerms {
                id: self.u32()?,
                unit_sats: self.u64()?,
                bits: self.u8()?,
                low_bits: self.u8()?,
                deposit_units: self.u32()?,
                close_height: self.u32()?,
                reserve_alice: self.u64()?,
                reserve_hub: self.u64()?,
                to_self_delay: self.u16()?,
                commit_fee: self.u64()?,
                presign_fee: self.u64()?,
                dust: self.u64()?,
                delta: self.u16()?,
                delta_prime: self.u16()?,
                deadline_margin: self.u32()?,
                request_height: self.u32()?,
                response_window: self.u16()?,
                publication_window: self.u16()?,
                contest_window: self.u16()?,
                assert_window: self.u16()?,
                challenge_window: self.u16()?,
                answer_window: self.u16()?,
            },
            recipe: Recipe {
                graph_version: self.u32()?,
                program: self.array()?,
                instances: self.u16()?,
                kept: self.u16()?,
            },
            chain: ChainTerms {
                checkpoint: Checkpoint::from_bytes(self.blob()?)?,
                funding_depth: self.u32()?,
                work_depth: self.u32()?,
                max_headers: self.u32()?,
            },
            limits: Limits {
                max_transaction_bytes: self.u32()?,
                max_publication_bytes: self.u32()?,
                max_authorizations: self.u32()?,
                max_source_inputs: self.u32()?,
            },
            fees: Fees {
                max_rate_sat_per_kvb: self.u64()?,
                opening_fee_quote: self.u64()?,
            },
        })
    }
}

// The common framing stays here; each message lists its fields in wire order.
macro_rules! message {
    ($name:ident, $w:ident, $s:ident, $r:ident, $encode:block, $decode:block) => {
        impl $name {
            pub fn encode(&$s) -> Vec<u8> { let mut $w = Writer::default(); $encode; $w.0 }
            pub fn decode(bytes: &[u8]) -> Result<Self> {
                let mut $r = Reader(bytes); let value = $decode; $r.end()?; Ok(value)
            }
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wanted {
    pub request_height: u32,
    pub close_height: u32,
    pub response_window: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    pub party: PartyPubKeys,
    pub claim_key: XOnlyPublicKey,
    pub deposit: OutPoint,
    pub coin: TxOut,
    pub wanted: Wanted,
    pub mock: bool,
    /// The digest of her request's one-time keys
    /// ([`HolderPub::request_keys`]), which Base binds: unbound, the
    /// statement could be proved of an exit she never started.
    pub request_keys: [u8; 32],
    /// What she funds of the contract herself, which Base commits to.
    pub funded: FundedNotes,
    /// Where the default returns her reserve and what the Hub keeps of it,
    /// which Base commits to ([`licash::base::Close`]).
    pub close: CloseOffer,
}

/// The Hub's deposit that swaps her reserve for notes, as she names it: the
/// script the default pays her reserve to, and the fee the Hub keeps of it
/// if the swap happens. The Hub holds her to the fee its deposits ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseOffer {
    pub script: ScriptBuf,
    pub fee: u64,
}

/// The notes she funds her part of a contract with: the outputs, in
/// order, that the Hub issues her once F confirms, worth the quote's
/// `deposit_units`, and the ephemeral key she derived them with, which
/// its issuance carries for her to find them by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedNotes {
    pub ephemeral: licash::crypto::Point,
    pub outputs: Vec<licash::spend::Output>,
}
message!(
    Open,
    w,
    self,
    r,
    {
        w.party(&self.party);
        w.bytes(&self.claim_key.serialize());
        w.outpoint(&self.deposit);
        w.txout(&self.coin);
        w.u32(self.wanted.request_height);
        w.u32(self.wanted.close_height);
        w.u16(self.wanted.response_window);
        w.u8(self.mock as u8);
        w.bytes(&self.request_keys);
        w.bytes(&self.funded.ephemeral.0);
        w.count(self.funded.outputs.len());
        for output in &self.funded.outputs {
            w.bytes(&output.to_bytes());
        }
        w.blob(self.close.script.as_bytes());
        w.u64(self.close.fee);
    },
    {
        let party = r.party()?;
        let claim_key = r.xonly()?;
        let deposit = r.outpoint()?;
        let coin = r.txout()?;
        let wanted = Wanted {
            request_height: r.u32()?,
            close_height: r.u32()?,
            response_window: r.u16()?,
        };
        let mock = r.u8()?;
        ensure!(mock <= 1, "invalid mock flag");
        let request_keys = r.array()?;
        let ephemeral = licash::crypto::Point(r.array()?);
        ephemeral.to_projective()?;
        let n = r.count(licash::spend::OUTPUT_BYTES)?;
        ensure!(n > 0, "an empty funded list");
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            let bytes = r.take(licash::spend::OUTPUT_BYTES)?;
            outputs.push(licash::spend::Output::from_bytes(bytes)?);
        }
        let close = CloseOffer {
            script: ScriptBuf::from_bytes(r.blob()?.to_vec()),
            fee: r.u64()?,
        };
        Self {
            party,
            claim_key,
            deposit,
            coin,
            wanted,
            mock: mock == 1,
            request_keys,
            funded: FundedNotes { ephemeral, outputs },
            close,
        }
    }
);

#[derive(Clone, Debug)]
pub struct Terms {
    pub base: Base,
    pub hub: HubPub,
}
message!(
    Terms,
    w,
    self,
    r,
    {
        w.blob(&self.base.to_bytes());
        w.hub_pub(&self.hub);
    },
    {
        Self {
            base: Base::from_bytes(r.blob()?)?,
            hub: r.hub_pub()?,
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub holder: HolderPub,
    pub commitments: Vec<[u8; 32]>,
    pub dealing: Dealing,
}
message!(
    Commit,
    w,
    self,
    r,
    {
        w.holder_pub(&self.holder);
        w.hashes(&self.commitments);
        w.dealing(&self.dealing);
    },
    {
        Self {
            holder: r.holder_pub()?,
            commitments: r.hashes()?,
            dealing: r.dealing()?,
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choose {
    pub kept: Vec<u32>,
}
message!(
    Choose,
    w,
    self,
    r,
    {
        w.count(self.kept.len());
        for i in &self.kept {
            w.u32(*i);
        }
    },
    {
        let n = r.count(4)?;
        Self {
            kept: (0..n).map(|_| r.u32()).collect::<Result<_>>()?,
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub opened: Vec<ShareOpening>,
}
message!(
    Opened,
    w,
    self,
    r,
    {
        w.opened(&self.opened);
    },
    {
        Self {
            opened: r.opened()?,
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub i: u32,
    pub bytes: Vec<u8>,
}
message!(
    Instance,
    w,
    self,
    r,
    {
        w.u32(self.i);
        w.blob(&self.bytes);
    },
    {
        Self {
            i: r.u32()?,
            bytes: r.blob()?.to_vec(),
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub funding: Transaction,
    pub prevouts: Vec<TxOut>,
    pub sigs: HashMap<String, Vec<u8>>,
    pub presigs: Vec<[AdaptorSig; VALUES]>,
}
message!(
    Offer,
    w,
    self,
    r,
    {
        w.tx(&self.funding);
        w.count(self.prevouts.len());
        for out in &self.prevouts {
            w.txout(out);
        }
        w.sigs(&self.sigs);
        w.digits(&self.presigs, |w, s| w.adaptor_sig(s));
    },
    {
        let funding = r.tx()?;
        let n = r.count(4)?;
        let prevouts = (0..n).map(|_| r.txout()).collect::<Result<_>>()?;
        Self {
            funding,
            prevouts,
            sigs: r.sigs()?,
            presigs: r.digits(97, |r| r.adaptor_sig())?,
        }
    }
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consent {
    pub sigs: HashMap<String, Vec<u8>>,
    /// Her deposit input's witness in F: empty until she signed it, and
    /// in a consent stored under snapshot format 5, before she signed
    /// first ([`Consent::decode_legacy`]).
    pub deposit: Witness,
}
message!(
    Consent,
    w,
    self,
    r,
    {
        w.sigs(&self.sigs);
        w.blob(&serialize(&self.deposit));
    },
    {
        Self {
            sigs: r.sigs()?,
            deposit: deserialize(r.blob()?)?,
        }
    }
);
impl Consent {
    /// A consent as snapshot format 5 stored it: her signatures alone.
    pub fn decode_legacy(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        let sigs = r.sigs()?;
        r.end()?;
        Ok(Self {
            sigs,
            deposit: Witness::new(),
        })
    }
}
/// F with the hub's inputs signed and hers not, sent by the hub under
/// version 2 only: an opening it signed then finishes as it began.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub funding: Transaction,
}
message!(
    Signed,
    w,
    self,
    r,
    {
        w.tx(&self.funding);
    },
    { Self { funding: r.tx()? } }
);
/// F whole: the hub's answer to her signed Consent, once it signed and
/// broadcast F; under version 2, hers to its Signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Funded {
    pub funding: Transaction,
}
message!(
    Funded,
    w,
    self,
    r,
    {
        w.tx(&self.funding);
    },
    { Self { funding: r.tx()? } }
);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelopes_are_whole_and_versioned() {
        let e = Envelope {
            kind: Kind::Consent,
            id: [5; 32],
            body: vec![1, 2, 3],
        };
        let bytes = e.to_bytes();
        assert_eq!(Envelope::from_bytes(&bytes).unwrap(), e);
        assert_eq!(Kind::peek(&bytes), Some(e.kind));
        for len in 0..bytes.len() {
            assert!(Envelope::from_bytes(&bytes[..len]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(Envelope::from_bytes(&bad).is_err());
        let mut bad = bytes;
        bad[5] = 1;
        assert!(Envelope::from_bytes(&bad).is_err());
    }
    #[test]
    fn counts_are_checked_before_allocation() {
        let bytes = u32::MAX.to_be_bytes();
        assert!(Reader(&bytes).hashes::<32>().is_err());
        assert!(Reader(&bytes).sigs().is_err());
        assert!(Reader(&bytes).blob().is_err());
    }
    #[test]
    fn keys_and_quote_round_trip() {
        let a = crate::keys::HolderKeys::derive(&[1; 32], &[2; 32]).public();
        let h = crate::keys::HubKeys::from_secret(&[3; 32]).public();
        let q = Quote::from_base(&crate::opening::testing::base(&[2; 32]));
        let mut w = Writer::default();
        w.holder_pub(&a);
        w.hub_pub(&h);
        w.quote(&q);
        let mut r = Reader(&w.0);
        assert_eq!(r.holder_pub().unwrap(), a);
        assert_eq!(r.hub_pub().unwrap(), h);
        let read = r.quote().unwrap();
        let mut original = Writer::default();
        original.quote(&q);
        let mut decoded = Writer::default();
        decoded.quote(&read);
        assert_eq!(original.0, decoded.0);
        r.end().unwrap();
    }
    /// An Open carries her request's keys, her funded notes and the script
    /// her default pays her reserve to, all of them: any less is no Open.
    #[test]
    fn an_open_carries_her_keys_her_funded_notes_and_her_close_and_reads_back_whole() {
        let keys = crate::keys::HolderKeys::derive(&[1; 32], &[2; 32]);
        let coin = TxOut {
            value: lichen_btc::bitcoin::Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let output = |n: u64| {
            let point = licash::crypto::generator_mul(&n.into());
            licash::spend::Output::new(
                n,
                licash::crypto::Point::from_projective(&point),
                [n as u8; 32],
            )
            .unwrap()
        };
        let open = Open {
            party: keys.party.public(),
            claim_key: keys.claim_key(),
            deposit: OutPoint::null(),
            coin,
            wanted: Wanted {
                request_height: 100,
                close_height: 1000,
                response_window: 24,
            },
            mock: false,
            request_keys: keys.public().request_keys().unwrap().digest(),
            funded: FundedNotes {
                ephemeral: output(3).blinded(),
                outputs: vec![output(4), output(8)],
            },
            close: CloseOffer {
                script: ScriptBuf::from_bytes(vec![0x51, 0x20, 7, 7]),
                fee: 700,
            },
        };
        let encoded = open.encode();
        assert_eq!(Open::decode(&encoded).unwrap(), open);
        // Cut anywhere in the keys, the notes or the close, or extended:
        // no Open.
        for cut in [1, 8, 9, 20, 73, 150] {
            assert!(
                Open::decode(&encoded[..encoded.len() - cut]).is_err(),
                "{cut}"
            );
        }
        assert!(Open::decode(&[encoded.as_slice(), &[0]].concat()).is_err());
        // No funded notes at all.
        let mut empty = open.clone();
        empty.funded.outputs.clear();
        assert!(Open::decode(&empty.encode()).is_err());
    }
}
