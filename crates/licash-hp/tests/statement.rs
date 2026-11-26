//! The Hub's statement on an exit as Bitcoin shows it: blocks on regtest's
//! genesis (Base's checkpoint) carrying her request, her publication of a
//! filing, the Hub's response and its disclosure.

use bitcoin::hashes::{hash160, Hash as _};
use k256::Scalar;
use licash::{
    authorization::{Authorization, PreparedGrant, SignedProposal},
    base::{Base, ChainTerms, Close, Fees, GraphTerms, Limits, Parts, Party, Recipe},
    chain::Checkpoint,
    claim::{self, Branch, Item, Source, UnsignedClaim},
    crypto::{self, Point},
    note::Evidence as Issuance,
    note::{Derivation, HoldRoot, IssuerKeys, Keyset, Note},
    recovery::{disclosures, Evidence, Filing, Format, Publication, SourceWitness, Witness},
    spend::{ChainProfile, Output, Proposal},
};
use licash_hp::{check, contract, decide, HubInput, Refusal, RequestKeys, C};
use licash_statement::{
    btc::{bare_tx, sha256d, Header, OutPoint},
    checksum_digits,
    testing::{headers_on, published, request_on, request_witness, respond_block},
    Exit, Hash, SLOT_VOUT,
};

const SEED: [u8; 32] = [7; 32];
const SPEND: u64 = 17;
const LIMIT: usize = 128;

fn point(value: u64) -> Point {
    Point::from_projective(&crypto::generator_mul(&Scalar::from(value)))
}
fn hold() -> HoldRoot {
    HoldRoot::from_seed(&SEED).unwrap()
}
fn party(value: u64) -> Party {
    let mut script = vec![0x51, 0x20];
    script.extend(point(value + 3).x_only());
    Party {
        funding: point(value).x_only(),
        payment: point(value + 1).x_only(),
        delayed: point(value + 2).x_only(),
        payout_script: script,
    }
}
/// The graph id the contracts are opened on: `LICASH_HP_GRAPH` if set,
/// to run the suite under the compact filing's (`recovery::COMPACT_FROM`).
fn graph() -> u32 {
    std::env::var("LICASH_HP_GRAPH").map_or(7, |n| n.parse().expect("LICASH_HP_GRAPH"))
}
fn base(keyset: Keyset, nonce: u8) -> Base {
    base_on(keyset, nonce, graph())
}

/// Her request's one-time keys, which every Base here binds.
fn keys() -> RequestKeys {
    signed_request(3, &[0; 32], 0).0
}
fn base_on(keyset: Keyset, nonce: u8, id: u32) -> Base {
    let checkpoint = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    base_with(keyset, nonce, id, checkpoint)
}
/// [`base_on`] of a contract whose checkpoint is `checkpoint`.
fn base_with(keyset: Keyset, nonce: u8, id: u32, checkpoint: Checkpoint) -> Base {
    let mut deposit = [31; 36];
    deposit[32..].copy_from_slice(&7u32.to_le_bytes());
    Base::new(Parts {
        nonce: [nonce; 32],
        holder_wots: keys().digest(),
        funded: [1; 32],
        claim_key: point(19).x_only(),
        keyset,
        deposit,
        cap: 128,
        parties: [party(23), party(29)],
        graph: GraphTerms {
            id,
            unit_sats: 1,
            bits: 21,
            low_bits: 9,
            deposit_units: 4,
            close_height: 1_000,
            reserve_alice: 20_000,
            reserve_hub: 100_000,
            to_self_delay: 6,
            commit_fee: 1_000,
            presign_fee: 1_000,
            dust: 330,
            delta: 6,
            delta_prime: 6,
            deadline_margin: 8,
            request_height: 800,
            response_window: 12,
            publication_window: 3,
            contest_window: 12,
            assert_window: 12,
            challenge_window: 24,
            answer_window: 12,
        },
        recipe: Recipe {
            graph_version: 2,
            program: [11; 32],
            instances: 4,
            kept: 2,
        },
        chain: ChainTerms {
            checkpoint,
            funding_depth: 1,
            work_depth: 6,
            max_headers: 1_000 + pad() as u32,
        },
        limits: Limits {
            max_transaction_bytes: 100_000,
            max_publication_bytes: 64_000,
            max_authorizations: LIMIT as u32,
            max_source_inputs: 128,
        },
        fees: Fees {
            max_rate_sat_per_kvb: 10_000,
            opening_fee_quote: 3_000,
        },
        close: Close {
            script: vec![0x51, 0x20, 3, 3, 3],
            fee: 1_000,
        },
    })
    .unwrap()
}

fn derive(root: u64, hold: &HoldRoot, denom: u64, shared: u8, index: u32) -> Derivation {
    Derivation::derive(denom, point(root), hold.public(), &[shared; 32], index).unwrap()
}
fn owner(root: u64, shared: u8, index: u32) -> Scalar {
    Scalar::from(root)
        + licash::note::derive_output(&point(root), &[shared; 32], index)
            .unwrap()
            .tweak
            .to_scalar()
            .unwrap()
}
fn mint(keys: &IssuerKeys, keyset: &Keyset, d: &Derivation) -> Note {
    let blinded = d.blinded().unwrap();
    let proof = keys
        .prove_blinded(d.message().denomination(), blinded)
        .unwrap();
    Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, d).unwrap(),
        Issuance::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: crypto::dleq_commit(&Scalar::from(71u64), &blinded.to_projective().unwrap()),
        },
    )
    .unwrap()
}
fn hold_keys(ds: &[Derivation]) -> Vec<(licash::note::Message, crypto::ScalarBytes)> {
    ds.iter()
        .map(|d| (d.message().clone(), d.hold_key(&hold()).unwrap()))
        .collect()
}

/// A contract, its issuer, and a filed claim: the filing's bytes and the
/// `(b, E)` her request signs.
struct Filed {
    issuer: IssuerKeys,
    base: Base,
    bytes: Vec<u8>,
    b: u32,
    e: Hash,
}

fn file(
    issuer: IssuerKeys,
    base: Base,
    parts: claim::Parts,
    signers: &[Derivation],
    b: u32,
    witness: Witness,
) -> Filed {
    let p = base.parts();
    let unsigned = UnsignedClaim::new(
        claim::Context {
            base: base.digest(),
            deposit: p.deposit,
            cap: p.cap,
        },
        &p.keyset,
        b,
        parts,
        LIMIT,
    )
    .unwrap();
    let publication = Publication::sign(unsigned, &hold_keys(signers), LIMIT).unwrap();
    let e = *publication.claim().digest();
    let bytes = Filing::new(publication, witness)
        .unwrap()
        .to_bytes(Format::of(&base));
    Filed {
        issuer,
        base,
        bytes,
        b,
        e,
    }
}

/// 32 notes of 4, of which the holder paid 16 to Bob after her backup;
/// she claims all 32, b = 128. The Hub's evidence: the spend.
fn stale() -> (Filed, Evidence) {
    stale_on(graph())
}
/// [`stale`] on a contract of graph id `id`.
fn stale_on(id: u32) -> (Filed, Evidence) {
    let checkpoint = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    stale_with(id, checkpoint)
}
/// [`stale_on`] of a contract whose checkpoint is `checkpoint`.
fn stale_with(id: u32, checkpoint: Checkpoint) -> (Filed, Evidence) {
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    let base = base_with(keyset.clone(), 53, id, checkpoint);
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&issuer, &keyset, d)).collect();
    let owners: Vec<_> = (0..16).map(|i| owner(SPEND, 23, i)).collect();
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    let to = (0..8)
        .map(|i| Output::from_derivation(&derive(41, &bob, 8, 29, i)).unwrap())
        .collect();
    let proposal = Proposal::new(&keyset, &notes[..16], point(43), to, None).unwrap();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes[..16],
        Authorization::Plain,
        &owners,
    )
    .unwrap();
    let parts = claim::Parts {
        items: ds
            .iter()
            .map(|d| Item::Settled(d.message().clone()))
            .collect(),
        sources: vec![],
        activations: vec![],
        authorizations: sorted(&ds),
    };
    let witness = Witness {
        notes: notes.clone(),
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    let filed = file(issuer, base, parts, &ds, 128, witness);
    let spent = Evidence::Spend {
        signed,
        notes: notes[..16].to_vec(),
        unlock: None,
    };
    (filed, spent)
}

/// Under a Base that funds her part with 32 notes of 4, which the Hub
/// issued her; she spent 16 of them to Bob after her backup and claims all
/// 32 as funded, b = 128. The Hub's evidence: the spend.
fn funded_notes() -> (Filed, Evidence) {
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let outputs: Vec<_> = ds
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let mut parts = base(keyset.clone(), 53).parts().clone();
    parts.funded = licash::spend::funded_root(&outputs).unwrap();
    parts.graph.deposit_units = 128;
    let base = Base::new(parts).unwrap();
    let notes: Vec<_> = ds.iter().map(|d| mint(&issuer, &keyset, d)).collect();
    let owners: Vec<_> = (0..16).map(|i| owner(SPEND, 23, i)).collect();
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    let to = (0..8)
        .map(|i| Output::from_derivation(&derive(41, &bob, 8, 29, i)).unwrap())
        .collect();
    let proposal = Proposal::new(&keyset, &notes[..16], point(43), to, None).unwrap();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes[..16],
        Authorization::Plain,
        &owners,
    )
    .unwrap();
    let parts = claim::Parts {
        items: ds
            .iter()
            .enumerate()
            .map(|(i, d)| Item::Funded {
                message: d.message().clone(),
                index: i as u32,
                blinding: *d.blinding(),
            })
            .collect(),
        sources: vec![],
        activations: vec![],
        authorizations: sorted(&ds),
    };
    let witness = Witness {
        notes: vec![],
        sources: vec![],
        activations: vec![],
        funded: outputs,
    };
    let filed = file(issuer, base, parts, &ds, 128, witness);
    let spent = Evidence::Spend {
        signed,
        notes: notes[..16].to_vec(),
        unlock: None,
    };
    (filed, spent)
}

fn sorted(ds: &[Derivation]) -> Vec<licash::note::Message> {
    let mut m: Vec<_> = ds.iter().map(|d| d.message().clone()).collect();
    m.sort_by_key(|m| m.identifier().unwrap());
    m
}

/// The exit on regtest's genesis: her request of `b` and `e` (block 1),
/// her publication carrying `claim` (block 2), six blocks, the Hub's
/// response of `b2` (block 9), six blocks.
fn exit(base: &Base, b: u32, e: &Hash, claim: &[u8], b2: u32) -> Exit {
    signed_exit(base, &signed_request(3, e, b).1, claim, b2)
}

/// Empty headers between the checkpoint and her request, for measuring
/// what a header costs the statement: `LICASH_HP_PAD`, none if unset.
fn pad() -> usize {
    std::env::var("LICASH_HP_PAD").map_or(0, |n| n.parse().expect("LICASH_HP_PAD"))
}

/// [`exit`] with her request's witness `witness`, on [`pad`] headers.
fn signed_exit(base: &Base, witness: &[Vec<u8>], claim: &[u8], b2: u32) -> Exit {
    let c = contract(base);
    let padding = headers_on(&c.checkpoint.hash, pad());
    let tip = padding.last().map_or(c.checkpoint.hash, |h| sha256d(h));
    let (rh, request) = request_on(&tip, &c.deposit, witness);
    let slot = OutPoint {
        txid: request.txid().unwrap(),
        vout: SLOT_VOUT,
    };
    let publish = published(&sha256d(&rh), &slot, claim);
    let mut headers = padding;
    headers.extend([rh, publish.header]);
    headers.extend(headers_on(&sha256d(&publish.header), 6));
    let (h, respond) = respond_block(&sha256d(headers.last().unwrap()), &request.tx, b2);
    headers.push(h);
    headers.extend(headers_on(&sha256d(&h), 6));
    Exit {
        headers,
        request,
        publish,
        respond,
        disclosure: None,
    }
}

/// The Hub discloses `bytes` spending the response's slot, in a block on
/// the exit's last; six blocks on it.
fn disclose(exit: &mut Exit, bytes: &[u8]) {
    let slot = OutPoint {
        txid: sha256d(&bare_tx(&exit.respond.tx).unwrap()),
        vout: SLOT_VOUT,
    };
    let d = published(&sha256d(exit.headers.last().unwrap()), &slot, bytes);
    exit.headers.push(d.header);
    exit.headers.extend(headers_on(&sha256d(&d.header), 6));
    exit.disclosure = Some(d);
}

fn input(base: &Base, exit: Exit, evidence: Vec<Evidence>) -> HubInput {
    HubInput {
        base: base.clone(),
        exit,
        evidence,
        keys: keys(),
        invalid: 0,
        chain: None,
    }
}

/// A one-time key of `bytes` bytes from `seed`: its chain ends, and its
/// signature on `msg` as the witness carries it (bottom first: each
/// digit's hash, then the digit), as `lichen_wots` signs.
fn wots(seed: u8, msg: &[u8]) -> (Vec<[u8; 20]>, Vec<Vec<u8>>) {
    let chain = |h: [u8; 20], n: u8| (0..n).fold(h, |h, _| hash160::Hash::hash(&h).to_byte_array());
    let mut digits: Vec<u8> = msg.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
    let mut sum: u32 = digits.iter().map(|d| 15 - u32::from(*d)).sum();
    let at = digits.len();
    digits.resize(at + checksum_digits(msg.len()), 0);
    for d in digits[at..].iter_mut().rev() {
        *d = (sum % 16) as u8;
        sum /= 16;
    }
    let secret = |i: usize| hash160::Hash::hash(&[seed, i as u8]).to_byte_array();
    let ends = (0..digits.len()).map(|i| chain(secret(i), 15)).collect();
    let items = digits
        .iter()
        .enumerate()
        .flat_map(|(i, d)| {
            let digit = if *d == 0 { vec![] } else { vec![*d] };
            [chain(secret(i), *d).to_vec(), digit]
        })
        .collect();
    (ends, items)
}

/// Her keys from `seed`, and her request's witness signing `b` and `e`
/// under them.
fn signed_request(seed: u8, e: &Hash, b: u32) -> (RequestKeys, Vec<Vec<u8>>) {
    let (e_ends, mut witness) = wots(seed, e);
    let (b_ends, b_items) = wots(seed.wrapping_add(1), &b.to_be_bytes());
    witness.extend(b_items);
    witness.extend([vec![1; 64], vec![2; 64], vec![0x51], vec![0xc0; 33]]);
    (RequestKeys::new(b_ends, e_ends).unwrap(), witness)
}

/// A spend as the Hub cites it, by the signatures of every input of it:
/// all of them are her claim's, in these fixtures.
fn cite(spent: Evidence) -> Evidence {
    let Evidence::Spend { signed, unlock, .. } = spent else {
        return spent;
    };
    let all = (0..signed.proposal().inputs().len()).collect();
    licash::recovery::by_signature(&signed, unlock, &all).unwrap()
}

/// The inputs r0/host measures the guest on (`licash-r0 hp-exec`),
/// written to `LICASH_HP_INPUTS` if set: the 32-item claim the Hub
/// answers with a 16-note spend, the same claim unanswered, and its like of
/// notes she funded her part of the contract with.
#[test]
fn export_inputs() {
    let Ok(dir) = std::env::var("LICASH_HP_INPUTS") else {
        return;
    };
    let (f, spent) = stale();
    println!("filing: {} bytes", f.bytes.len());
    let answered = input(
        &f.base,
        exit(&f.base, f.b, &f.e, &f.bytes, 64),
        vec![cite(spent)],
    );
    let unanswered = input(&f.base, exit(&f.base, f.b, &f.e, &f.bytes, 127), vec![]);
    let (f, spent) = funded_notes();
    let funded = input(
        &f.base,
        exit(&f.base, f.b, &f.e, &f.bytes, 64),
        vec![cite(spent)],
    );
    let inputs = [
        ("answered", answered),
        ("unanswered", unanswered),
        ("answered-funded", funded),
    ];
    for (name, i) in inputs {
        let bytes = i.to_bytes();
        println!("{name}: {} input bytes, {:?}", bytes.len(), check(&i).err());
        std::fs::write(format!("{dir}/{name}.bin"), bytes).unwrap();
    }
}

/// With `LICASH_HP_INPUTS` set, the statement's input of the most evidence
/// a claim may need (`worst.bin`, docs/r0.md): each of her 32 settled notes
/// spent in a spend of its own of the most inputs and outputs a proposal
/// may have, 63 other notes with it, each cited as the Hub cites it, by her
/// signature alone; and `worst-alone.bin`, each spent alone to one output,
/// whose bodies are the least. Printed: their bytes, of which their
/// spends' bodies, and how long the statement takes natively, beside the
/// answered input's.
#[test]
fn export_worst_inputs() {
    let Ok(dir) = std::env::var("LICASH_HP_INPUTS") else {
        return;
    };
    use licash::spend::{MAX_INPUTS, MAX_OUTPUTS};
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    let base = base_on(keyset.clone(), 53, graph());
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&issuer, &keyset, d)).collect();
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    let spends = |others: u32, outputs: u32| -> Vec<Evidence> {
        (0..32u32)
            .map(|i| {
                let shared = 100 + i as u8;
                let mut inputs = vec![notes[i as usize].clone()];
                inputs.extend(
                    (0..others)
                        .map(|j| mint(&issuer, &keyset, &derive(SPEND, &hold(), 4, shared, j))),
                );
                let mut owners = vec![owner(SPEND, 23, i)];
                owners.extend((0..others).map(|j| owner(SPEND, shared, j)));
                let denom = 4 * u64::from(others + 1) / u64::from(outputs);
                let to = (0..outputs)
                    .map(|j| Output::from_derivation(&derive(41, &bob, denom, shared, j)).unwrap())
                    .collect();
                let proposal = Proposal::new(&keyset, &inputs, point(43), to, None).unwrap();
                let signed =
                    SignedProposal::sign(&keyset, proposal, &inputs, Authorization::Plain, &owners)
                        .unwrap();
                // As the Hub cites it: by the signature of her note alone.
                licash::recovery::by_signature(&signed, None, &[0].into()).unwrap()
            })
            .collect()
    };
    let parts = claim::Parts {
        items: ds
            .iter()
            .map(|d| Item::Settled(d.message().clone()))
            .collect(),
        sources: vec![],
        activations: vec![],
        authorizations: sorted(&ds),
    };
    let witness = Witness {
        notes: notes.clone(),
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    let f = file(issuer.clone(), base, parts, &ds, 128, witness);
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 0);
    // 64 notes of 4 to 128 outputs of 2; and one of 4 to one.
    let (most, alone) = (
        spends(MAX_INPUTS as u32 - 1, MAX_OUTPUTS as u32),
        spends(0, 1),
    );
    let bodies = |evidence: &[Evidence]| -> usize {
        (evidence.iter())
            .map(|e| match e {
                Evidence::Signed { body, .. } => body.len(),
                _ => 0,
            })
            .sum()
    };
    for spends in [&most, &alone] {
        let (owed, _) = decide(&f.base, &keys(), &x, spends).unwrap();
        assert_eq!(owed.owed, 0);
    }
    let (a, spent) = stale();
    let answered = input(
        &a.base,
        exit(&a.base, a.b, &a.e, &a.bytes, 64),
        vec![cite(spent)],
    );
    let inputs = [
        ("worst", bodies(&most), input(&f.base, x.clone(), most)),
        ("worst-alone", bodies(&alone), input(&f.base, x, alone)),
        ("answered", 0, answered),
    ];
    for (name, bodies, i) in inputs {
        let bytes = i.to_bytes();
        let start = std::time::Instant::now();
        let read = HubInput::from_bytes(&bytes).unwrap();
        check(&read).unwrap();
        println!(
            "{name}: {} input bytes, {bodies} of spends' bodies, read and checked natively in {:?}",
            bytes.len(),
            start.elapsed()
        );
        std::fs::write(format!("{dir}/{name}.bin"), bytes).unwrap();
    }
}

#[test]
fn the_contract_is_bases() {
    let issuer = IssuerKeys::random(3).unwrap();
    let a = base(issuer.keyset().unwrap(), 53);
    let c = contract(&a);
    let genesis = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    assert_eq!(c.c, C);
    assert_eq!(c.checkpoint.height, 0);
    assert_eq!(c.checkpoint.hash, Header(*genesis.header()).hash());
    // six regtest blocks of work 2
    assert_eq!(c.work, 12);
    assert_eq!(c.deposit.txid, [31; 32]);
    assert_eq!(c.deposit.vout, 7);
    // Another opening (here, another nonce) is another word.
    let b = base(issuer.keyset().unwrap(), 54);
    assert_ne!(contract(&b).d, c.d);
    assert_ne!(contract(&b).journal(), c.journal());
}

/// The contract counts the words as its payout does: a cap past the
/// graph's bits has a rest, whose bit counts it; a cap within them none.
#[test]
fn the_contract_counts_words_as_its_payout() {
    use licash_hp::payout;
    use licash_statement::Payout;

    let issuer = IssuerKeys::random(3).unwrap();
    let plain = base(issuer.keyset().unwrap(), 53);
    assert_eq!(contract(&plain).payout, Payout { bits: 21, rest: 0 });
    let mut parts = plain.parts().clone();
    parts.graph.bits = 10;
    parts.cap = 1_023 + 600;
    let rested = Base::new(parts).unwrap();
    assert_eq!(
        payout(&rested),
        Payout {
            bits: 10,
            rest: 600
        }
    );
    assert_eq!(contract(&rested).payout, payout(&rested));
    assert_eq!(payout(&rested).amount((1 << 10) | 23), 623);
    // not in the journal, which D binds through Base
    assert_ne!(contract(&rested).d, contract(&plain).d);
}

#[test]
fn the_hub_proves_what_its_evidence_leaves_owed() {
    let (f, spent) = stale();
    let journal = contract(&f.base).journal();
    // The spend leaves half owed: the Hub responds 64 and proves it.
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
    let (owed, read) = decide(&f.base, &keys(), &x, std::slice::from_ref(&spent)).unwrap();
    assert_eq!(
        (owed.owed, owed.mask, read.b, read.b2),
        (64, 0xffff, 128, 64)
    );
    assert_eq!(
        check(&input(&f.base, x.clone(), vec![spent.clone()])).unwrap(),
        journal
    );
    // The statement's input travels as bytes, decoded strictly.
    let bytes = input(&f.base, x.clone(), vec![spent.clone()]).to_bytes();
    assert_eq!(
        check(&HubInput::from_bytes(&bytes).unwrap()).unwrap(),
        journal
    );
    assert_eq!(
        HubInput::from_bytes(&bytes[..bytes.len() - 1]).err(),
        Some(Refusal::Input)
    );
    // It can't prove less than its evidence leaves, nor with no evidence.
    let short = exit(&f.base, f.b, &f.e, &f.bytes, 63);
    assert_eq!(
        check(&input(&f.base, short, vec![spent.clone()])),
        Err(Refusal::Owed)
    );
    assert_eq!(check(&input(&f.base, x, vec![])), Err(Refusal::Owed));
    // Nor under another contract: the claim names this Base.
    let other = base(f.issuer.keyset().unwrap(), 54);
    let x = exit(&other, f.b, &f.e, &f.bytes, 64);
    assert!(matches!(
        check(&input(&other, x, vec![spent])),
        Err(Refusal::Evidence(_))
    ));
}

/// The Hub cites a spend by the signatures of the inputs her claim relies
/// on ([`Evidence::Signed`]), as it does: the statement proves the same of
/// it as of the spend whole, from fewer bytes, and nothing of a part of it.
#[test]
fn the_hub_proves_the_same_of_a_spend_cited_by_its_signatures() {
    let (f, spent) = stale();
    let journal = contract(&f.base).journal();
    let Evidence::Spend { signed, .. } = &spent else {
        panic!("a spend");
    };
    let cited = licash::recovery::by_signature(signed, None, &(0..16).collect()).unwrap();
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
    let (owed, _) = decide(&f.base, &keys(), &x, std::slice::from_ref(&cited)).unwrap();
    assert_eq!((owed.owed, owed.mask), (64, 0xffff));
    let bytes = input(&f.base, x.clone(), vec![cited.clone()]).to_bytes();
    assert!(
        bytes.len()
            < input(&f.base, x.clone(), vec![spent.clone()])
                .to_bytes()
                .len()
    );
    assert_eq!(
        check(&HubInput::from_bytes(&bytes).unwrap()).unwrap(),
        journal
    );
    // Cited by 15 of its 16 inputs it voids 15 notes: 64 is not proven.
    let part = licash::recovery::by_signature(signed, None, &(1..16).collect()).unwrap();
    assert_eq!(
        check(&input(&f.base, x.clone(), vec![part.clone()])),
        Err(Refusal::Owed)
    );
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 68);
    assert_eq!(check(&input(&f.base, x, vec![part])).unwrap(), journal);
}

/// The statement holds only of a request signed under the keys Base binds:
/// the Hub can't prove of an exit she didn't start, on a chain of its own,
/// however long before.
#[test]
fn her_request_must_be_signed_under_the_keys_base_binds() {
    let keys = keys();
    let (f, spent) = stale();
    let journal = contract(&f.base).journal();
    let (_, witness) = signed_request(3, &f.e, f.b);
    let x = signed_exit(&f.base, &witness, &f.bytes, 64);
    let signed = input(&f.base, x.clone(), vec![spent.clone()]);
    assert_eq!(check(&signed).unwrap(), journal);
    // Its keys travel with the input, after the evidence.
    let bytes = signed.to_bytes();
    let decoded = HubInput::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.keys, keys);
    assert_eq!(check(&decoded).unwrap(), journal);
    for n in [bytes.len() - 1, bytes.len() - 20 * 77] {
        assert_eq!(
            HubInput::from_bytes(&bytes[..n]).err(),
            Some(Refusal::Input)
        );
    }
    // A 15 written as 16, which Bitcoin accepts, signs as 15.
    let mut loose = witness.clone();
    for item in loose.iter_mut().filter(|i| i.as_slice() == [15]) {
        *item = vec![16];
    }
    assert_ne!(loose, witness);
    let x = signed_exit(&f.base, &loose, &f.bytes, 64);
    assert_eq!(
        check(&input(&f.base, x, vec![spent.clone()])).unwrap(),
        journal
    );
    // Her (b, E) signed under other keys, or a request no key signed, or
    // the input's keys not those Base binds: no proof.
    let (other, forged) = signed_request(5, &f.e, f.b);
    for (keys, witness) in [
        (&keys, forged.clone()),
        (&keys, request_witness(&f.e, f.b)),
        (&other, forged),
        (&other, witness.clone()),
    ] {
        let x = signed_exit(&f.base, &witness, &f.bytes, 64);
        assert_eq!(
            check(&HubInput {
                keys: keys.clone(),
                ..input(&f.base, x, vec![spent.clone()])
            }),
            Err(Refusal::Unsigned)
        );
    }
    // A digit changed, its hash not: the chain doesn't reach the key.
    let mut changed = witness;
    let at = changed.iter().position(|i| i.as_slice() == [15]).unwrap();
    changed[at] = vec![14];
    let x = signed_exit(&f.base, &changed, &f.bytes, 64);
    assert!(check(&input(&f.base, x, vec![spent])).is_err());
}

/// Her funded notes are owed as the outputs her Base commits to, those
/// spent void: the Hub proves the rest owed, on her signed request.
#[test]
fn her_funded_notes_are_owed_unless_spent() {
    let keys = keys();
    let (f, spent) = funded_notes();
    let journal = contract(&f.base).journal();
    let (_, witness) = signed_request(3, &f.e, f.b);
    let x = signed_exit(&f.base, &witness, &f.bytes, 64);
    let (owed, _) = decide(&f.base, &keys, &x, std::slice::from_ref(&spent)).unwrap();
    assert_eq!((owed.owed, owed.mask, owed.ineligible), (64, 0xffff, None));
    let signed = input(&f.base, x, vec![spent.clone()]);
    assert_eq!(check(&signed).unwrap(), journal);
    let decoded = HubInput::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(check(&decoded).unwrap(), journal);
    // Without the spend all 128 stay owed: a response of 64 proves nothing.
    let x = signed_exit(&f.base, &witness, &f.bytes, 64);
    assert_eq!(check(&input(&f.base, x, vec![])), Err(Refusal::Owed));
}

#[test]
fn a_claim_that_isnt_one_is_owed_nothing() {
    let (f, _) = stale();
    let journal = contract(&f.base).journal();
    // Garbage, an empty slot, or a filing she didn't sign E for.
    for claim in [&b"not a filing"[..], &[], &f.bytes[..f.bytes.len() - 1]] {
        let x = exit(&f.base, f.b, &f.e, claim, 0);
        assert_eq!(check(&input(&f.base, x, vec![])).unwrap(), journal);
    }
    let x = exit(&f.base, f.b, &[0; 32], &f.bytes, 0);
    assert_eq!(check(&input(&f.base, x, vec![])).unwrap(), journal);
    // Bitcoin must show the exit: a response that isn't below her b.
    let x = exit(&f.base, f.b, &f.e, b"not a filing", f.b);
    assert!(matches!(
        check(&input(&f.base, x, vec![])),
        Err(Refusal::Exit(_))
    ));
}

/// The paper's example at half scale: Alice pays Bob 50 from a 128 note
/// under a grant; the Hub withholds the unlock. Her claim of the input
/// (the change as fallbacks) is voided only if the Hub's response
/// discloses the unlock.
#[test]
fn evidence_that_needs_a_disclosure_proves_only_with_it() {
    let issuer = IssuerKeys::random(7).unwrap();
    let keyset = issuer.keyset().unwrap();
    let base = base(keyset.clone(), 53);
    let n = derive(SPEND, &hold(), 128, 23, 0);
    let note = mint(&issuer, &keyset, &n);
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    let paid: Vec<_> = [32, 16, 2]
        .iter()
        .enumerate()
        .map(|(i, d)| derive(41, &bob, *d, 29, i as u32))
        .collect();
    let change: Vec<_> = [64, 8, 4, 2]
        .iter()
        .enumerate()
        .map(|(i, d)| derive(SPEND, &hold(), *d, 71, i as u32))
        .collect();
    let outputs = paid
        .iter()
        .chain(&change)
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let notes = std::slice::from_ref(&note);
    let proposal = Proposal::new(&keyset, notes, point(43), outputs, None).unwrap();
    let prepared = PreparedGrant::new(&issuer, &proposal).unwrap();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        notes,
        Authorization::Granted(Box::new(prepared.offer())),
        &[owner(SPEND, 23, 0)],
    )
    .unwrap();
    let unlock = prepared.release(&keyset, notes, &signed).unwrap();
    let id = signed.proposal().id();
    let mut items = vec![Item::Settled(n.message().clone())];
    items.extend(change.iter().enumerate().map(|(i, d)| Item::Pending {
        message: d.message().clone(),
        source: id,
        branch: Branch::Pay,
        index: (paid.len() + i) as u32,
        blinding: *d.blinding(),
        preimage: None,
    }));
    let held: Vec<_> = std::iter::once(n.clone()).chain(change.clone()).collect();
    let parts = claim::Parts {
        items,
        sources: vec![Source::Plain {
            id,
            inputs: vec![n.message().identifier().unwrap()],
        }],
        activations: vec![],
        authorizations: sorted(&held),
    };
    let witness = Witness {
        notes: vec![note.clone()],
        sources: vec![SourceWitness::Signed {
            signed: signed.clone(),
            notes: vec![note.clone()],
        }],
        activations: vec![],
        funded: vec![],
    };
    let f = file(issuer, base, parts, &held, 128, witness);
    let cite = Evidence::Spend {
        signed,
        notes: vec![note],
        unlock: Some(unlock),
    };
    let needed = disclosures(std::slice::from_ref(&cite)).unwrap().to_bytes();
    let mut x = exit(&f.base, f.b, &f.e, &f.bytes, 78);
    assert_eq!(
        check(&input(&f.base, x.clone(), vec![cite.clone()])),
        Err(Refusal::Undisclosed)
    );
    let mut wrong = x.clone();
    disclose(&mut wrong, &[0; 1024]);
    assert_eq!(
        check(&input(&f.base, wrong, vec![cite.clone()])),
        Err(Refusal::Undisclosed)
    );
    disclose(&mut x, &needed);
    assert_eq!(
        check(&input(&f.base, x, vec![cite])).unwrap(),
        contract(&f.base).journal()
    );
}

/// A response the statement would refuse as conceded (`b′` not below her
/// `b`, nor 0) is never borne out, though the claim is owed less: one of
/// her `b` keeps the Hub its reserve, and one of bits above the graph's
/// pays her nothing on chain. Her contest wins her claim.
#[test]
fn a_conceding_response_is_not_borne_out() {
    use licash::request::Request;
    use licash_hp::{bears_out, through_publication};
    use licash_statement::Reject;

    let (f, spent) = stale();
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
    let (_, read) = decide(&f.base, &keys(), &x, std::slice::from_ref(&spent)).unwrap();
    let headers = through_publication(&contract(&f.base), &x, &read);
    let request = Request {
        amount: f.b,
        claim_digest: f.e,
    };
    let bears = |b2| {
        bears_out(
            &f.base,
            &request,
            &f.bytes,
            std::slice::from_ref(&spent),
            headers,
            b2,
            None,
        )
    };
    assert_eq!(bears(64), Ok(()));
    assert_eq!(bears(f.b - 1), Ok(()));
    for conceded in [f.b, f.b + 1, 1 << f.base.parts().graph.bits, u32::MAX] {
        assert_eq!(
            bears(conceded),
            Err(Refusal::Exit(Reject::Conceded)),
            "{conceded}"
        );
    }
    // As the statement: it proves none of them.
    let x = exit(&f.base, f.b, &f.e, &f.bytes, f.b);
    assert_eq!(
        check(&input(&f.base, x, vec![spent])),
        Err(Refusal::Exit(Reject::Conceded))
    );
}

/// What a holder makes of a response is the statement's own test: owed at
/// most `b′`, and what the evidence uses disclosed, whole.
#[test]
fn a_response_is_borne_out_when_owed_at_most_what_it_says_and_what_it_uses_is_disclosed() {
    use licash::disclosure::Disclosures;
    use licash::recovery::Owed;
    use licash_hp::verdict;

    let owed = |owed, disclosures| Owed {
        owed,
        mask: 0,
        invalid: 0,
        disclosures,
        ineligible: None,
    };
    let none = Disclosures::empty();
    assert_eq!(verdict(&owed(10, none.clone()), 10, None, false), Ok(()));
    assert_eq!(
        verdict(&owed(11, none.clone()), 10, None, false),
        Err(Refusal::Owed)
    );
    // Disclosures it uses are published whole, or the response is not borne out.
    let mut used = Disclosures::empty();
    used.values[0] = [9; 32];
    let bytes = used.to_bytes();
    assert_eq!(
        verdict(&owed(5, used.clone()), 10, Some(&bytes), false),
        Ok(())
    );
    assert_eq!(
        verdict(&owed(5, used.clone()), 10, None, false),
        Err(Refusal::Undisclosed)
    );
    let mut other = bytes;
    other[0] ^= 1;
    assert_eq!(
        verdict(&owed(5, used), 10, Some(&other), false),
        Err(Refusal::Undisclosed)
    );
}

/// The statement under a lean filing: the Hub flags the items of her claim
/// that are not valid and proves the claim owed what is left; with none
/// flagged, a forged note is taken as valid, and the claim owed its value; a
/// flag on a valid item proves nothing. Its input carries the flags.
#[test]
fn a_lean_statement_proves_a_claim_owed_less_by_the_items_the_hub_flags() {
    let (f, spent) = stale_on(licash::recovery::LEAN_FROM);
    let filing = Filing::from_bytes(Format::Lean, &f.base.parts().keyset, LIMIT, &f.bytes).unwrap();
    // The proof of issuance of a note she did not spend forged (the 32nd of
    // her notes: she spent the first 16).
    let forged = derive(SPEND, &hold(), 4, 23, 31);
    let note = filing
        .witness()
        .notes
        .iter()
        .find(|n| n.message() == forged.message())
        .unwrap();
    let tail = note.to_compact_bytes();
    let mut bad = tail.clone();
    // C, the evidence's tag, then its DLEQ's e and s: the last byte of s.
    bad[33 + 1 + 63] ^= 1;
    let at = f
        .bytes
        .windows(tail.len())
        .position(|w| w == tail.as_slice())
        .unwrap();
    let mut bytes = f.bytes.clone();
    bytes[at..at + tail.len()].copy_from_slice(&bad);

    // Of 32 notes of 4, she spent 16 and forged one: owed 60 of her 128.
    let evidence = vec![spent];
    let x = exit(&f.base, f.b, &f.e, &bytes, 60);
    let invalid = licash_hp::flagged(&f.base, &keys(), &x, &evidence).unwrap();
    assert_eq!(invalid.count_ones(), 1);
    let (owed, _) = decide(&f.base, &keys(), &x, &evidence).unwrap();
    assert_eq!((owed.owed, owed.invalid), (60, invalid));
    let mut i = input(&f.base, x, evidence);
    // Unflagged, the forged note is taken as valid: owed 64, more than the
    // Hub responded, so no proof.
    assert_eq!(check(&i), Err(Refusal::Owed));
    // Flagged, it proves the response.
    i.invalid = invalid;
    check(&i).unwrap();
    // The flags travel with the input.
    let bytes = i.to_bytes();
    let back = HubInput::from_bytes(&bytes).unwrap();
    assert_eq!(back.invalid, invalid);
    assert_eq!(back.to_bytes(), bytes);
    // A flag on an item that is valid proves nothing, nor does the flag
    // of the wrong item alone.
    let valid = (0..32).find(|b| invalid & (1 << b) == 0).unwrap();
    for wrong in [invalid | 1 << valid, 1 << valid] {
        i.invalid = wrong;
        assert!(check(&i).is_err(), "flags {wrong:#b}");
    }
}

/// A lean format's disclosure carries the secrets used and no padding, the
/// other formats' all 32 slots: each only its own bytes.
#[test]
fn a_lean_disclosure_is_the_secrets_it_uses_and_no_padding() {
    use licash::recovery::Owed;
    use licash_hp::verdict;

    let mut used = licash::disclosure::Disclosures::empty();
    used.values[0] = [9; 32];
    used.values[1] = [8; 32];
    used.used = 2;
    let owed = Owed {
        owed: 5,
        mask: 0,
        invalid: 0,
        disclosures: used.clone(),
        ineligible: None,
    };
    let (padded, lean) = (used.encode(false), used.encode(true));
    assert_eq!((padded.len(), lean.len()), (1_024, 64));
    assert_eq!(verdict(&owed, 10, Some(&lean), true), Ok(()));
    assert_eq!(verdict(&owed, 10, Some(&padded), false), Ok(()));
    assert_eq!(
        verdict(&owed, 10, Some(&padded), true),
        Err(Refusal::Undisclosed)
    );
    assert_eq!(
        verdict(&owed, 10, Some(&lean), false),
        Err(Refusal::Undisclosed)
    );
}

// ----- a chained contract: the exit's blocks opened from a chain proven beforehand -----

mod chained {
    use super::*;
    use licash::recovery::{chained, Owed};
    use licash_hp::{
        decide_with, flagged_on,
        headers::{Lineage, Proven},
        open_chain, Chained, Program,
    };
    use licash_statement::Read;

    /// The chain program's image id, as a test has it.
    const CHAIN: [u8; 32] = [0xc1; 32];
    const ON: u32 = licash::recovery::CHAINED_FROM;

    fn program() -> Program<'static> {
        program_of(CHAIN)
    }

    fn program_of(id: [u8; 32]) -> Program<'static> {
        Program {
            id,
            verify: &|_, _| {},
        }
    }

    /// The chain a hub keeps: Base's checkpoint, then every header of `exit`.
    fn lineage(base: &Base, exit: &Exit) -> Lineage {
        let mut lineage = Lineage::new(base.parts().chain.checkpoint.clone()).unwrap();
        for header in &exit.headers {
            lineage.push(*header).unwrap();
        }
        lineage
    }

    /// What the statement decided before there were chains: every header from
    /// the checkpoint, the claim's judgment on a dense chain through her
    /// publication.
    fn dense(base: &Base, exit: &Exit, evidence: &[Evidence]) -> (Owed, Read) {
        let contract = contract(base);
        let read = licash_statement::read(&contract, exit).unwrap();
        let chain =
            licash_hp::chain(base, licash_hp::through_publication(&contract, exit, &read)).unwrap();
        let request = licash::request::Request {
            amount: read.b,
            claim_digest: read.e,
        };
        let owed = licash::recovery::owed(base, &request, &read.claim, evidence, &chain).unwrap();
        (owed, read)
    }

    /// `exit` as a hub shows it on a chain proven through height `through`:
    /// its headers those after, the chain's proof opened to what the
    /// judgment reads.
    fn on(base: &Base, exit: &Exit, evidence: &[Evidence], through: u32) -> (HubInput, Lineage) {
        on_chain(CHAIN, base, exit, evidence, through)
    }

    /// [`on`], the chain program's image id `chain`.
    fn on_chain(
        chain: [u8; 32],
        base: &Base,
        exit: &Exit,
        evidence: &[Evidence],
        through: u32,
    ) -> (HubInput, Lineage) {
        let lineage = lineage(base, exit);
        on_lineage(lineage, chain, base, exit, evidence, through)
    }

    /// [`on_chain`] on `lineage`, which may start below the contract's
    /// checkpoint: `exit`'s headers are those after it.
    fn on_lineage(
        lineage: Lineage,
        chain: [u8; 32],
        base: &Base,
        exit: &Exit,
        evidence: &[Evidence],
        through: u32,
    ) -> (HubInput, Lineage) {
        let program = || program_of(chain);
        let (journal, tip) = lineage.through(chain, through).unwrap();
        let checkpoint = base.parts().chain.checkpoint.height();
        let mut shown = exit.clone();
        shown.headers = exit.headers[(through - checkpoint) as usize..].to_vec();
        let proven = Proven {
            lineage: &lineage,
            journal: &journal,
            tip: &tip,
        };
        let proof = open_chain(proven, base, &keys(), &shown, evidence, &program()).unwrap();
        let chained = Chained {
            proof: &proof,
            program: &program(),
        };
        let invalid = flagged_on(base, &keys(), &shown, evidence, chained).unwrap();
        let input = HubInput {
            base: base.clone(),
            exit: shown,
            evidence: evidence.to_vec(),
            keys: keys(),
            invalid,
            chain: Some(proof),
        };
        (input, lineage)
    }

    fn decided(input: &HubInput) -> Result<(Owed, Read), Refusal> {
        let chained = Chained {
            proof: input.chain.as_ref().unwrap(),
            program: &program(),
        };
        decide_with(
            &input.base,
            &keys(),
            &input.exit,
            &input.evidence,
            None,
            Some(chained),
            &mut |_| {},
        )
    }

    /// Her request is block 1, her publication 2, the response 9, and six
    /// blocks follow each.
    #[test]
    fn a_chained_statement_decides_what_the_dense_one_does_wherever_the_chain_ends() {
        let (f, spent) = stale_on(ON);
        assert!(chained(f.base.parts().graph.id));
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        let want = dense(&f.base, &x, evidence);
        assert_eq!((want.0.owed, want.1.b2), (64, 64));
        // The chain ends at the response, among the six after it, and at the
        // exit's last block: the work on top comes from the chain and its tail.
        for through in [9, 10, 12, 15] {
            let (input, _) = on(&f.base, &x, evidence, through);
            assert_eq!(decided(&input).unwrap(), want, "through {through}");
            assert_eq!(
                licash_hp::check_on(&input, &program()).unwrap(),
                contract(&f.base).journal(),
                "through {through}"
            );
            // It travels as bytes, decoded strictly.
            let bytes = input.to_bytes();
            let back = HubInput::from_bytes(&bytes).unwrap();
            assert_eq!(
                licash_hp::check_on(&back, &program()).unwrap(),
                contract(&f.base).journal()
            );
            assert_eq!(
                HubInput::from_bytes(&bytes[..bytes.len() - 1]).err(),
                Some(Refusal::Input)
            );
        }
        // Of a claim the evidence leaves owed more than the response says, as ever.
        let short = exit(&f.base, f.b, &f.e, &f.bytes, 63);
        let (input, _) = on(&f.base, &short, evidence, 9);
        assert_eq!(licash_hp::check_on(&input, &program()), Err(Refusal::Owed));
    }

    /// The chain may start below the contract's checkpoint: it is a block of
    /// it, and what the statement opens there is the state Base binds.
    #[test]
    fn a_chain_that_started_below_the_contracts_checkpoint_decides_as_the_dense_one() {
        let genesis = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
        // the contract's checkpoint is block 4, reached from the genesis
        let below = headers_on(&sha256d(genesis.header()), 4);
        let mut checkpoint = genesis.clone();
        below.iter().for_each(|h| checkpoint.push(*h).unwrap());
        assert_eq!(checkpoint.height(), 4);
        let (f, spent) = stale_with(ON, checkpoint.clone());
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        let want = dense(&f.base, &x, evidence);
        assert_eq!(want.1.heights.request, 5);
        // a chain from the genesis, through the contract's checkpoint, the exit
        // and beyond: its tail, and where its receipt ends, are as before
        for through in [13, 14, 19] {
            let mut lineage = Lineage::new(genesis.clone()).unwrap();
            below.iter().for_each(|h| lineage.push(*h).unwrap());
            x.headers.iter().for_each(|h| lineage.push(*h).unwrap());
            let (input, _) = on_lineage(lineage, CHAIN, &f.base, &x, evidence, through);
            assert_eq!(decided(&input).unwrap(), want, "through {through}");
            assert_eq!(
                licash_hp::check_on(&input, &program()).unwrap(),
                contract(&f.base).journal()
            );
            let opened: Vec<u32> = input
                .chain
                .as_ref()
                .unwrap()
                .openings
                .iter()
                .map(|o| o.height)
                .collect();
            assert!(opened.contains(&4) && !opened.contains(&0), "{opened:?}");
        }
        // a chain from the same blocks that began after the checkpoint has no
        // block there to open
        let mut late = Lineage::new(x_start_checkpoint(&checkpoint, &x)).unwrap();
        x.headers[1..].iter().for_each(|h| late.push(*h).unwrap());
        let (journal, tip) = late.through(CHAIN, late.tip_height()).unwrap();
        let proof = licash_hp::headers::ChainProof {
            journal: journal.to_bytes(),
            tip: tip.to_bytes(),
            openings: vec![late.open(late.tip_height(), journal.count).unwrap()],
        };
        let mut shown = x.clone();
        shown.headers = vec![];
        let input = HubInput {
            base: f.base.clone(),
            exit: shown,
            evidence: evidence.to_vec(),
            keys: keys(),
            invalid: 0,
            chain: Some(proof),
        };
        assert!(matches!(
            decided(&input),
            Err(Refusal::Chain(_) | Refusal::Openings(_))
        ));
    }

    /// The state after the first block of `exit`, from `checkpoint`.
    fn x_start_checkpoint(checkpoint: &Checkpoint, exit: &Exit) -> Checkpoint {
        let mut state = checkpoint.clone();
        state.push(exit.headers[0]).unwrap();
        state
    }

    /// A contract is decided on its chain or on its exit's headers, by its
    /// graph id, and never the other.
    #[test]
    fn a_contract_is_decided_on_its_chain_or_its_headers_by_its_graph_id() {
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        let (input, _) = on(&f.base, &x, evidence, 9);
        // headers instead of the chain
        let dense_input = HubInput {
            chain: None,
            ..input.clone()
        };
        assert!(matches!(check(&dense_input), Err(Refusal::Chain(_))));
        // a chain, and no program to verify its receipt
        let mut w = licash_statement::codec::W::default();
        input.chain.as_ref().unwrap().write(&mut w);
        assert!(matches!(
            licash_hp::check_with(&input, None, &mut |_| {}),
            Err(Refusal::Chain(_))
        ));
        // a graph before the chain's, which has no chain to carry
        let (g, spent) = stale_on(ON - 1);
        let x = exit(&g.base, g.b, &g.e, &g.bytes, 64);
        let carried = HubInput {
            chain: input.chain.clone(),
            ..self::super::input(&g.base, x, vec![spent])
        };
        assert!(matches!(
            licash_hp::check_with(&carried, Some(&program()), &mut |_| {}),
            Err(Refusal::Chain(_))
        ));
    }

    /// What a hub can't leave out: the block at the checkpoint, and each the
    /// exit sits in.
    #[test]
    fn a_block_the_statement_needs_that_is_not_opened_is_no_proof() {
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        let (input, _) = on(&f.base, &x, evidence, 12);
        let proof = input.chain.clone().unwrap();
        let heights: Vec<u32> = proof.openings.iter().map(|o| o.height).collect();
        assert_eq!(heights, [0, 1, 2, 9]);
        for (left_out, want) in [
            (0, Some(Refusal::Openings(vec![0]))),
            (1, None),
            (2, None),
            (9, None),
        ] {
            let mut left = proof.clone();
            left.openings.retain(|o| o.height != left_out);
            let input = HubInput {
                chain: Some(left),
                ..input.clone()
            };
            let got = decided(&input).err();
            match want {
                Some(want) => assert_eq!(got, Some(want)),
                // an exit block that is not a leaf of the chain is no exit
                None => assert!(
                    matches!(got, Some(Refusal::Exit(licash_statement::Reject::Depth))),
                    "{left_out}: {got:?}"
                ),
            }
        }
    }

    /// Whatever the hub says of the chain is checked against the journal the
    /// statement verified.
    #[test]
    fn an_opening_the_journals_tree_doesnt_hold_is_refused() {
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        let (input, _) = on(&f.base, &x, evidence, 12);
        let refused = |proof: licash_hp::headers::ChainProof| {
            let input = HubInput {
                chain: Some(proof),
                ..input.clone()
            };
            decided(&input).err()
        };
        let proof = input.chain.clone().unwrap();
        let at = |height: u32| {
            proof
                .openings
                .iter()
                .position(|o| o.height == height)
                .unwrap()
        };
        // each field of a leaf and each sibling is bound
        for field in 0..5 {
            let mut p = proof.clone();
            let o = &mut p.openings[at(9)];
            match field {
                0 => o.work += 1,
                1 => o.state[0] ^= 1,
                2 => o.header[40] ^= 1,
                3 => o.path[5][0] ^= 1,
                _ => o.height += 1,
            }
            assert!(
                matches!(refused(p), Some(Refusal::Chain(_))),
                "field {field}"
            );
        }
        // the journal's fields the view reads against what it is given (its
        // program, start, root and tip); a forged count, frontier or work is
        // the receipt's to refuse, which the zkVM verifies and a test does not
        for byte in [0, 33, 45, 110] {
            let mut p = proof.clone();
            p.journal[byte] ^= 1;
            assert!(matches!(refused(p), Some(Refusal::Chain(_))), "byte {byte}");
        }
        let mut p = proof.clone();
        p.tip[20] ^= 1;
        assert!(matches!(refused(p), Some(Refusal::Chain(_))));
        // a journal of another program
        let mut p = proof.clone();
        p.journal[..32].copy_from_slice(&[0xc2; 32]);
        assert!(matches!(refused(p), Some(Refusal::Chain(_))));
        // the unaltered
        assert!(refused(proof).is_none());
    }

    /// The chain may start anywhere, but the leaf at the contract's
    /// checkpoint must hold the state Base binds: a chain that began after
    /// it, or on a state that was not its own, proves nothing of it.
    #[test]
    fn the_chain_must_pass_through_the_state_base_binds() {
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        // a chain that starts after the checkpoint, at block 1
        let time_of = |h: &[u8; 80]| u32::from_le_bytes(h[68..72].try_into().unwrap());
        let genesis = *Checkpoint::genesis(ChainProfile::Core30DefaultRegtest)
            .unwrap()
            .header();
        let mut late = Lineage::new(
            Checkpoint::new(
                ChainProfile::Core30DefaultRegtest,
                1,
                x.headers[0],
                vec![time_of(&genesis), time_of(&x.headers[0])],
                None,
            )
            .unwrap(),
        )
        .unwrap();
        for header in &x.headers[1..] {
            late.push(*header).unwrap();
        }
        let (journal, tip) = late.through(CHAIN, 15).unwrap();
        let (good, _) = on(&f.base, &x, evidence, 12);
        let mut shown = x.clone();
        shown.headers = vec![];
        let mut proof = good.chain.clone().unwrap();
        proof.journal = journal.to_bytes();
        proof.tip = tip.to_bytes();
        proof.openings = [1, 2, 9, 15]
            .into_iter()
            .map(|h| late.open(h, journal.count).unwrap())
            .collect();
        let input = HubInput {
            exit: shown,
            chain: Some(proof),
            ..good.clone()
        };
        assert!(matches!(
            decided(&input),
            Err(Refusal::Chain(_)) | Err(Refusal::Openings(_))
        ));
    }

    /// The work on top of the last block of the exit is the chain's after it
    /// and the tail's, and no less than the contract's.
    #[test]
    fn the_work_on_the_last_block_is_the_chains_and_the_tails() {
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        // six blocks on the response are the contract's work (6 blocks deep)
        let (input, _) = on(&f.base, &x, evidence, 9);
        assert_eq!(input.exit.headers.len(), 6);
        assert!(decided(&input).is_ok());
        // one fewer: in the tail, or among the chain's
        for through in [9, 10] {
            let (mut input, _) = on(&f.base, &x, evidence, through);
            input.exit.headers.pop();
            assert_eq!(
                decided(&input).err(),
                Some(Refusal::Exit(licash_statement::Reject::Depth)),
                "through {through}"
            );
        }
        // a header in the tail that isn't one: a block off the chain's tip
        let (mut input, _) = on(&f.base, &x, evidence, 9);
        input.exit.headers[2][4] ^= 1;
        assert!(matches!(decided(&input), Err(Refusal::Chain(_))));
    }

    /// The inputs the chain program and the statement's guest run on, for
    /// `licash-r0 chain-prove` and `hp-prove` (`LICASH_HP_INPUTS`, and the
    /// chain program's image id from `LICASH_CHAIN_ID` or r0/hp-guest/chain.id):
    /// the chain proven in two batches, `batch-1.bin` and `batch-2.bin`, then
    /// the answered claim on it, `answered-chained.bin`.
    #[test]
    fn export_chained_inputs() {
        use licash_hp::headers::{Batch, Builder, Origin};
        let Ok(dir) = std::env::var("LICASH_HP_INPUTS") else {
            return;
        };
        let hex = std::env::var("LICASH_CHAIN_ID").unwrap_or_else(|_| {
            let kept = format!("{}/../../r0/hp-guest/chain.id", env!("CARGO_MANIFEST_DIR"));
            std::fs::read_to_string(kept).unwrap()
        });
        let hex = hex.trim();
        let mut chain = [0u8; 32];
        for (i, byte) in chain.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let (f, spent) = stale_on(ON);
        let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
        let evidence = std::slice::from_ref(&spent);
        // the chain through the response's block, in two batches
        let through = Lineage::new(f.base.parts().chain.checkpoint.clone())
            .map(|mut l| {
                x.headers.iter().for_each(|h| l.push(*h).unwrap());
                l.height_of(&x.respond.header).unwrap()
            })
            .unwrap();
        let cut = (through / 2) as usize;
        let cp = f.base.parts().chain.checkpoint.clone();
        let first = Batch {
            chain,
            from: Origin::Start(cp.clone()),
            headers: x.headers[..cut].to_vec(),
        };
        let mut early = Builder::start(cp).unwrap();
        for header in &x.headers[..cut] {
            early.push(*header).unwrap();
        }
        let second = Batch {
            chain,
            from: Origin::Resume {
                journal: early.journal(chain),
                tip: early.tip().clone(),
                tree: early.tree().clone(),
            },
            headers: x.headers[cut..through as usize].to_vec(),
        };
        let (input, _) = on_chain(chain, &f.base, &x, evidence, through);
        for (name, bytes) in [
            ("batch-1", first.to_bytes()),
            ("batch-2", second.to_bytes()),
            ("answered-chained", input.to_bytes()),
        ] {
            println!("{name}: {} bytes", bytes.len());
            std::fs::write(format!("{dir}/{name}.bin"), bytes).unwrap();
        }
    }
}

/// [`stale`], but the 16 notes she paid away after her backup went out in
/// one spend of the most a proposal may be: 48 more of hers with them, to
/// the most outputs. The guest's input reads it back
/// (`HubInput::from_bytes`), and the statement holds of the response it
/// decides: the hub proves what its evidence voids. Of more, no proposal
/// is made, nor released by a hub (formerly, one of 129 notes was, and no
/// statement could read it).
#[test]
fn the_largest_spend_a_proposal_may_be_is_proven_against_a_claim() {
    use licash::spend::{MAX_INPUTS, MAX_OUTPUTS};
    let issuer = IssuerKeys::random(3).unwrap();
    let keyset = issuer.keyset().unwrap();
    let base = base_on(keyset.clone(), 53, graph());
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&issuer, &keyset, d)).collect();
    let extra = MAX_INPUTS as u32 - 16;
    let extra_ds: Vec<_> = (0..extra)
        .map(|i| derive(SPEND, &hold(), 4, 24, i))
        .collect();
    let mut inputs = notes[..16].to_vec();
    inputs.extend(extra_ds.iter().map(|d| mint(&issuer, &keyset, d)));
    let mut owners: Vec<_> = (0..16).map(|i| owner(SPEND, 23, i)).collect();
    owners.extend((0..extra).map(|i| owner(SPEND, 24, i)));
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    // 64 * 4 = 256 = 128 * 2.
    let to: Vec<_> = (0..MAX_OUTPUTS as u32)
        .map(|i| Output::from_derivation(&derive(41, &bob, 2, 29, i)).unwrap())
        .collect();
    let proposal = Proposal::new(&keyset, &inputs, point(43), to, None).unwrap();
    let signed =
        SignedProposal::sign(&keyset, proposal, &inputs, Authorization::Plain, &owners).unwrap();
    let parts = claim::Parts {
        items: ds
            .iter()
            .map(|d| Item::Settled(d.message().clone()))
            .collect(),
        sources: vec![],
        activations: vec![],
        authorizations: sorted(&ds),
    };
    let witness = Witness {
        notes: notes.clone(),
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    let f = file(issuer, base, parts, &ds, 128, witness);
    let spent = Evidence::Spend {
        signed,
        notes: inputs,
        unlock: None,
    };
    let x = exit(&f.base, f.b, &f.e, &f.bytes, 64);
    let (owed, _) = decide(&f.base, &keys(), &x, std::slice::from_ref(&spent)).unwrap();
    assert_eq!(owed.owed, 64);
    let bytes = input(&f.base, x, vec![spent]).to_bytes();
    let read = HubInput::from_bytes(&bytes).expect("the guest reads the spend back");
    assert!(check(&read).is_ok());
}
