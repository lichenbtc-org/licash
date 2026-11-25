//! LCOS 3 snapshots (3: the contract output on lichenbtc-org/lichen, its
//! internal key both parties' MuSig2 key). Unknown, partial and older formats are rejected, not
//! upgraded or restarted. Drivers must never reuse an abandoned opening ID.
//! Binding contracts retain their pinned program after a trust rotation.
use super::*;
use crate::keys::DERIVATION;
use crate::wire::{Reader, Writer};
use lichen_btc::bitcoin::hashes::sha256;

const MAGIC: [u8; 4] = *b"LCOS";
pub const FORMAT: u16 = 5;

#[derive(Clone, Debug)]
pub struct Peek {
    pub phase: HubPhase,
    pub id: [u8; 32],
    pub base: Base,
    pub funding: Option<Transaction>,
}
fn begin(side: u8, phase: u8) -> Writer {
    let mut w = Writer::default();
    w.bytes(&MAGIC);
    w.u16(FORMAT);
    w.u8(DERIVATION);
    w.u8(side);
    w.u8(phase);
    w
}
fn finish(mut w: Writer) -> Vec<u8> {
    let digest = sha256::Hash::hash(&w.0).to_byte_array();
    w.bytes(&digest);
    w.0
}
fn read(bytes: &[u8], side: u8) -> Result<(Reader<'_>, u8)> {
    ensure!(bytes.len() >= 41, "state cut short");
    let (body, digest) = bytes.split_at(bytes.len() - 32);
    ensure!(
        sha256::Hash::hash(body).as_byte_array() == digest,
        "state checksum mismatch"
    );
    let mut r = Reader(body);
    ensure!(r.array::<4>()? == MAGIC, "not opening state");
    ensure!(r.u16()? == FORMAT, "unsupported opening state format");
    ensure!(r.u8()? == DERIVATION, "another key derivation");
    ensure!(r.u8()? == side, "another opening side");
    let phase = r.u8()?;
    Ok((r, phase))
}
fn put<T>(w: &mut Writer, value: Option<&T>, encode: impl FnOnce(&T) -> Vec<u8>) {
    w.u8(value.is_some() as u8);
    if let Some(value) = value {
        w.blob(&encode(value));
    }
}
fn get<T>(r: &mut Reader<'_>, decode: impl FnOnce(&[u8]) -> Result<T>) -> Result<Option<T>> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decode(r.blob()?)?)),
        _ => bail!("invalid state flag"),
    }
}
fn tx(bytes: &[u8]) -> Result<Transaction> {
    Ok(lichen_btc::bitcoin::consensus::deserialize(bytes)?)
}
fn stored_context(base: Option<&Base>, binding: bool, ctx: &Context) -> Context {
    Context {
        // Loading is not permission to fund. step checks the current tip.
        tip: 0,
        trust: Trust {
            program: if binding {
                base.expect("binding Base").parts().recipe.program
            } else {
                ctx.trust.program
            },
            mock: ctx.trust.mock,
            compact: ctx.trust.compact,
            lean: ctx.trust.lean,
            chained: ctx.trust.chained,
            own_claims: ctx.trust.own_claims,
        },
    }
}

impl Holder {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = begin(0, self.phase() as u8);
        w.bytes(&self.id);
        w.quote(&self.quote);
        w.blob(&self.checkpoint.to_bytes());
        w.blob(&self.open.encode());
        put(&mut w, self.terms.as_ref(), wire::Terms::encode);
        put(&mut w, self.commit.as_ref(), wire::Commit::encode);
        w.hashes(&self.hmsg);
        put(&mut w, self.kept.as_ref(), |k| {
            wire::Choose { kept: k.clone() }.encode()
        });
        put(&mut w, self.offer.as_ref(), wire::Offer::encode);
        put(&mut w, self.consent.as_ref(), wire::Consent::encode);
        put(&mut w, self.signed.as_ref(), serialize);
        put(&mut w, self.funded.as_ref(), serialize);
        finish(w)
    }
    pub fn load(bytes: &[u8], seed: &[u8; 32], ctx: &Context) -> Result<Self> {
        let (mut r, phase) = read(bytes, 0)?;
        let phase = *Phase::ALL
            .get(phase as usize)
            .context("unknown holder phase")?;
        let id = r.array()?;
        let quote = r.quote()?;
        let checkpoint = Checkpoint::from_bytes(r.blob()?)?;
        let open = wire::Open::decode(r.blob()?)?;
        let terms = get(&mut r, wire::Terms::decode)?;
        let commit = get(&mut r, wire::Commit::decode)?;
        let hmsg = r.hashes()?;
        let kept = get(&mut r, |b| Ok(wire::Choose::decode(b)?.kept))?;
        let offer = get(&mut r, wire::Offer::decode)?;
        let consent = get(&mut r, wire::Consent::decode)?;
        let signed = get(&mut r, tx)?;
        let funded = get(&mut r, tx)?;
        r.end()?;
        let h = Self {
            id,
            keys: HolderKeys::derive(seed, &id),
            quote,
            checkpoint,
            open,
            terms,
            commit,
            hmsg,
            kept,
            offer,
            consent,
            signed,
            funded,
        };
        same_kind(h.open.mock, ctx)?;
        ensure!(
            PartyPubKeys {
                payout_spk: h.open.party.payout_spk.clone(),
                ..h.keys.party.public()
            } == h.open.party
                && h.open.claim_key == h.keys.claim_key(),
            "state of another seed"
        );
        check_deposit(&h.open, &h.quote.graph, &h.quote.fees)?;
        if phase < Phase::Funded {
            h.quote.check(h.checkpoint.profile())?;
        }
        ensure!(h.phase() == phase, "holder phase mismatch");
        ensure!(
            h.terms.is_some() == (phase >= Phase::Committed)
                && h.commit.is_some() == (phase >= Phase::Committed)
                && h.kept.is_some() == (phase >= Phase::Chosen)
                && h.offer.is_some() == (phase >= Phase::Consented)
                && h.consent.is_some() == (phase >= Phase::Consented)
                && h.signed.is_some() == (phase >= Phase::Signing)
                && h.funded.is_some() == (phase >= Phase::Funded),
            "holder sections mismatch"
        );
        let ctx = stored_context(h.base(), phase >= Phase::Funded, ctx);
        if let Some(t) = &h.terms {
            h.check_terms(t, &ctx)?;
            let c = h.commit.as_ref().unwrap();
            let n = t.base.parts().recipe.instances as usize;
            ensure!(
                c.holder == h.keys.public() && c.commitments.len() == n && h.hmsg.len() == n,
                "invalid stored commitments"
            );
            ensure!(
                c.dealing == *h.garbler().dealing(),
                "stored dealing of another garbler"
            );
        } else {
            ensure!(h.hmsg.is_empty(), "hashlocks before terms");
        }
        if let Some(k) = &h.kept {
            check_kept(k, h.base().unwrap())?;
        }
        if let Some(o) = &h.offer {
            let (babe, set) = h.graph(&o.funding)?;
            check_funds(
                h.base().unwrap(),
                &h.open,
                &o.funding,
                &o.prevouts,
                &contract_output(&babe)?,
            )?;
            check_sigs(
                &set,
                &graph::party_pub(&h.base().unwrap().parts().parties[1])?.payment,
                &o.sigs,
                HubProves::withheld,
            )?;
            ensure!(
                check_presigs(
                    &h.terms.as_ref().unwrap().hub.adaptor,
                    &HubProves::challenge_sighash(&set)?,
                    &points(&h.commit.as_ref().unwrap().dealing),
                    &o.presigs
                ),
                "invalid stored presignatures"
            );
            check_sigs(
                &set,
                &h.keys.party.public().payment,
                &h.consent.as_ref().unwrap().sigs,
                |_| false,
            )?;
        }
        if let Some(signed) = &h.signed {
            let o = h.offer.as_ref().unwrap();
            ensure!(
                signed.compute_txid() == o.funding.compute_txid(),
                "stored F changed"
            );
            let mine = at(&o.funding, h.deposit());
            ensure!(
                signed.input[mine].witness.is_empty()
                    && signed
                        .input
                        .iter()
                        .enumerate()
                        .all(|(i, input)| input.script_sig.is_empty()
                            && (i == mine || !input.witness.is_empty())),
                "stored F signatures missing"
            );
        }
        if let Some(funded) = &h.funded {
            let o = h.offer.as_ref().unwrap();
            whole(&o.funding, funded)?;
            check_key_spend(funded, at(funded, h.deposit()), &o.prevouts)?;
        }
        Ok(h)
    }
}

impl Hub {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = begin(1, self.phase() as u8);
        w.bytes(&self.secret);
        w.quote(&self.quote);
        put(&mut w, self.id.as_ref(), |id| id.to_vec());
        put(&mut w, self.open.as_ref(), wire::Open::encode);
        put(&mut w, self.base.as_ref(), Base::to_bytes);
        put(&mut w, self.commit.as_ref(), wire::Commit::encode);
        put(&mut w, self.kept.as_ref(), |k| {
            wire::Choose { kept: k.clone() }.encode()
        });
        put(&mut w, self.draft.as_ref(), |out| {
            let mut w = Writer::default();
            w.txout(out);
            w.0
        });
        put(&mut w, self.opened.as_ref(), wire::Opened::encode);
        w.count(self.received.len());
        for (i, hash) in &self.received {
            w.u32(*i);
            w.bytes(hash);
        }
        put(&mut w, self.funds.as_ref(), |(funding, prevouts)| {
            let mut w = Writer::default();
            w.tx(funding);
            w.count(prevouts.len());
            for out in prevouts {
                w.txout(out);
            }
            w.0
        });
        put(&mut w, self.offer.as_ref(), wire::Offer::encode);
        put(&mut w, self.consent.as_ref(), wire::Consent::encode);
        put(&mut w, self.signed.as_ref(), serialize);
        put(&mut w, self.funded.as_ref(), serialize);
        finish(w)
    }
    pub fn load(bytes: &[u8], ctx: &Context) -> Result<Self> {
        let (mut r, phase) = read(bytes, 1)?;
        let phase = *HubPhase::ALL
            .get(phase as usize)
            .context("unknown hub phase")?;
        let secret = r.array()?;
        let quote = r.quote()?;
        let mut h = Self::with(&secret, quote, None);
        h.id = get(&mut r, |b| Ok(b.try_into()?))?;
        h.open = get(&mut r, wire::Open::decode)?;
        h.base = get(&mut r, |b| Ok(Base::from_bytes(b)?))?;
        h.commit = get(&mut r, wire::Commit::decode)?;
        h.kept = get(&mut r, |b| Ok(wire::Choose::decode(b)?.kept))?;
        h.draft = get(&mut r, |b| {
            let mut r = Reader(b);
            let out = r.txout()?;
            r.end()?;
            Ok(out)
        })?;
        h.opened = get(&mut r, wire::Opened::decode)?;
        let n = r.count(36)?;
        for _ in 0..n {
            let i = r.u32()?;
            let hash = r.array()?;
            ensure!(
                h.received.insert(i, hash).is_none(),
                "duplicate stored instance"
            );
        }
        h.funds = get(&mut r, |b| {
            let mut r = Reader(b);
            let tx = r.tx()?;
            let n = r.count(4)?;
            let prevouts = (0..n).map(|_| r.txout()).collect::<Result<_>>()?;
            r.end()?;
            Ok((tx, prevouts))
        })?;
        h.offer = get(&mut r, wire::Offer::decode)?;
        h.consent = get(&mut r, wire::Consent::decode)?;
        h.signed = get(&mut r, tx)?;
        h.funded = get(&mut r, tx)?;
        r.end()?;
        ensure!(h.phase() == phase, "hub phase mismatch");
        ensure!(
            h.open.is_some() == h.id.is_some() && h.base.is_some() == h.id.is_some(),
            "hub terms mismatch"
        );
        ensure!(
            h.commit.is_some() == (phase >= HubPhase::Chosen)
                && h.kept.is_some() == (phase >= HubPhase::Chosen)
                && h.draft.is_some() == (phase >= HubPhase::Chosen)
                && h.offer.is_some() == (phase >= HubPhase::Offered)
                && h.consent.is_some() == (phase >= HubPhase::Consented)
                && h.signed.is_some() == (phase >= HubPhase::Signed)
                && h.funded.is_some() == (phase >= HubPhase::Funded),
            "hub sections mismatch"
        );
        if phase < HubPhase::Signed {
            h.quote.check(h.quote.chain.checkpoint.profile())?;
        }
        h.payout = h
            .base
            .as_ref()
            .map(|b| ScriptBuf::from_bytes(b.parts().parties[1].payout_script.clone()));
        if let Some(open) = &h.open {
            same_kind(open.mock, ctx)?;
            check_deposit(open, &h.quote.graph, &h.quote.fees)?;
            let ctx = stored_context(h.base(), phase >= HubPhase::Signed, ctx);
            let expected = offer(
                &h.quote,
                h.id.unwrap(),
                open,
                ctx.trust.program,
                &h.quote.chain.checkpoint,
                h.party()?,
            )?;
            ensure!(
                h.base.as_ref().unwrap().to_bytes() == expected.to_bytes(),
                "stored terms changed"
            );
        }
        if let Some(c) = &h.commit {
            let b = h.base.as_ref().context("commit before terms")?;
            let recipe = &b.parts().recipe;
            ensure!(
                c.commitments.len() == recipe.instances as usize
                    && c.dealing
                        .commitments
                        .iter()
                        .flatten()
                        .all(|v| v.len() == (recipe.instances - recipe.kept) as usize + 1),
                "stored commitment shape"
            );
            check_kept(h.kept.as_ref().unwrap(), b)?;
        }
        for i in h.received.keys() {
            ensure!(
                h.kept.as_ref().is_some_and(|k| k.contains(i)),
                "stored instance not kept"
            );
        }
        if let Some(o) = &h.opened {
            let c = h.commit.as_ref().context("opened before commit")?;
            let k = h.kept.as_ref().unwrap();
            let n = h.base.as_ref().unwrap().parts().recipe.instances as u32;
            let expected: Vec<_> = (1..=n).filter(|i| !k.contains(i)).collect();
            ensure!(
                o.opened.iter().map(|o| o.i).collect::<Vec<_>>() == expected,
                "stored opened indices"
            );
            let shares = o
                .opened
                .iter()
                .map(|o| (o.i as u64, o.shares.clone()))
                .collect::<Vec<_>>();
            ensure!(
                c.dealing.verify(&shares, &mut OsRng),
                "stored shares not on dealing"
            );
        }
        if let Some((f, prevouts)) = &h.funds {
            check_funds(
                h.base.as_ref().context("funds before terms")?,
                h.open.as_ref().unwrap(),
                f,
                prevouts,
                &h.draft_output()?,
            )?;
        }
        if let Some(o) = &h.offer {
            ensure!(
                h.opened.is_some() && h.missing().is_empty(),
                "offer before instances checked"
            );
            let (f, prevouts) = h.funds.as_ref().context("offer before F")?;
            ensure!(
                o.funding == *f && o.prevouts == *prevouts,
                "stored offer changed F"
            );
            let (_, set) = h.graph(f)?;
            check_sigs(
                &set,
                &h.keys.party.public().payment,
                &o.sigs,
                HubProves::withheld,
            )?;
            ensure!(
                check_presigs(
                    &h.keys.public().adaptor,
                    &HubProves::challenge_sighash(&set)?,
                    &points(&h.commit.as_ref().unwrap().dealing),
                    &o.presigs
                ),
                "stored adaptor signatures invalid"
            );
            if let Some(c) = &h.consent {
                check_sigs(
                    &set,
                    &graph::party_pub(&h.base.as_ref().unwrap().parts().parties[0])?.payment,
                    &c.sigs,
                    |_| false,
                )?;
            }
        }
        if let Some(s) = &h.signed {
            let f = &h.offer.as_ref().unwrap().funding;
            ensure!(
                s.compute_txid() == f.compute_txid(),
                "stored signed F changed"
            );
            let mine = at(f, h.open.as_ref().unwrap().deposit);
            ensure!(
                s.input[mine].witness.is_empty()
                    && s.input
                        .iter()
                        .enumerate()
                        .all(|(i, v)| v.script_sig.is_empty()
                            && (i == mine || !v.witness.is_empty())),
                "stored hub signatures missing"
            );
        }
        if let Some(f) = &h.funded {
            let o = h.offer.as_ref().unwrap();
            whole(&o.funding, f)?;
            check_key_spend(f, at(f, h.open.as_ref().unwrap().deposit), &o.prevouts)?;
        }
        Ok(h)
    }
    /// Cheap, untrusted metadata for routing only. Never authorizes funding.
    pub fn peek(bytes: &[u8]) -> Result<Peek> {
        let (mut r, phase) = read(bytes, 1)?;
        let phase = *HubPhase::ALL
            .get(phase as usize)
            .context("unknown hub phase")?;
        r.take(32)?;
        r.quote()?;
        let id = get(&mut r, |b| Ok(b.try_into()?))?.context("no opening ID")?;
        get(&mut r, wire::Open::decode)?.context("no Open")?;
        let base = get(&mut r, |b| Ok(Base::from_bytes(b)?))?.context("no Base")?;
        get(&mut r, wire::Commit::decode)?;
        get(&mut r, wire::Choose::decode)?;
        get(&mut r, |b| Ok(b.to_vec()))?;
        get(&mut r, wire::Opened::decode)?;
        let n = r.count(36)?;
        r.take(n * 36)?;
        let funds = get(&mut r, |b| {
            let mut r = Reader(b);
            let tx = r.tx()?;
            let n = r.count(4)?;
            for _ in 0..n {
                r.txout()?;
            }
            r.end()?;
            Ok(tx)
        })?;
        get(&mut r, wire::Offer::decode)?;
        get(&mut r, wire::Consent::decode)?;
        let signed = get(&mut r, tx)?;
        let funded = get(&mut r, tx)?;
        r.end()?;
        Ok(Peek {
            phase,
            id,
            base,
            funding: funded.or(signed).or(funds),
        })
    }
}

/// Snapshots written by FORMAT 5, the format of every opening stored
/// before her deposit was signed first: of the unit opening's hub and
/// holder ([`super::tests`]), captured as that format wrote them. Each is
/// read as it was then: live contracts are never written again.
#[cfg(test)]
mod format5 {
    use super::*;

    const HOLDER_CONSENTED: &[u8] = include_bytes!("../../tests/data/format5/holder-consented.bin");
    const HOLDER_SIGNING: &[u8] = include_bytes!("../../tests/data/format5/holder-signing.bin");
    const HOLDER_FUNDED: &[u8] = include_bytes!("../../tests/data/format5/holder-funded.bin");
    const HUB_CONSENTED: &[u8] = include_bytes!("../../tests/data/format5/hub-consented.bin");
    const HUB_SIGNED: &[u8] = include_bytes!("../../tests/data/format5/hub-signed.bin");
    const HUB_FUNDED: &[u8] = include_bytes!("../../tests/data/format5/hub-funded.bin");

    fn ctx() -> Context {
        Context {
            tip: 1,
            trust: Trust::mock(),
        }
    }

    fn holder(bytes: &[u8]) -> Holder {
        Holder::load(bytes, &[1; 32], &ctx()).unwrap()
    }

    #[test]
    fn a_funded_contract_is_read_and_played_by_either_side() {
        let a = holder(HOLDER_FUNDED);
        assert_eq!(a.phase(), Phase::Funded);
        let h = Hub::load(HUB_FUNDED, &ctx()).unwrap();
        assert_eq!(h.phase(), HubPhase::Funded);
        assert_eq!(Hub::peek(HUB_FUNDED).unwrap().phase, HubPhase::Funded);
        let (ao, ho) = (a.signed().unwrap(), h.signed().unwrap());
        assert_eq!(ao.funding, ho.funding);
        assert!(ho.default_close().is_ok());
        assert!(!a.abandonable() && !h.abandonable());
    }

    /// The hub signed F: it is irrevocable, and her app finishes it,
    /// signing her deposit and broadcasting F herself.
    #[test]
    fn an_opening_the_hub_signed_finishes_as_it_began() {
        let h = Hub::load(HUB_SIGNED, &ctx()).unwrap();
        assert_eq!(h.phase(), HubPhase::Signed);
        assert!(!h.abandonable());
        let a = holder(HOLDER_SIGNING);
        assert_eq!(a.phase(), Phase::Signing);
        let sign = a.pending().unwrap();
        assert!(
            matches!(&sign[..], [Out::Sign { inputs, .. }] if inputs.len() == 1),
            "{sign:?}"
        );
    }

    #[test]
    fn an_opening_short_of_signatures_is_read() {
        assert_eq!(holder(HOLDER_CONSENTED).phase(), Phase::Consented);
        let h = Hub::load(HUB_CONSENTED, &ctx()).unwrap();
        assert_eq!(h.phase(), HubPhase::Consented);
    }
}
