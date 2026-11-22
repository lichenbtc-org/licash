//! Recovery without Bitcoin Core: the 32-item publication, its filing, and
//! what the Hub's statement decides it is owed.

use bitcoin::{
    absolute,
    block::{Header, Version},
    consensus::{deserialize, serialize},
    hashes::{sha256, sha256d, Hash},
    pow::CompactTarget,
    transaction, Amount, Block, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use k256::Scalar;
use licash::{
    authorization::{Authorization, PreparedGrant, SignedProposal},
    base::{Base, ChainTerms, Close, Fees, GraphTerms, Limits, Parts, Party, Recipe},
    chain::{self, Activation, ActivationRef, Chain, Checkpoint, Inclusion},
    claim::{self, ActivationRecord, Branch, Item, Source, UnsignedClaim},
    crypto::{self, Point},
    hold,
    note::Evidence as Issuance,
    note::{Derivation, HoldRoot, IssuerKeys, Keyset, Note},
    recovery::{
        self, disclosures, evidence_from_bytes, evidence_to_bytes, ActivationWitness, Evidence,
        Filing, Format, Owed, Publication, SourceWitness, Witness,
    },
    request::Request,
    source::Certificate,
    spend::{ChainProfile, Output, Proposal, TimedLock, TimedTerms},
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
fn base(keyset: Keyset) -> Base {
    base_at(keyset, 7)
}
fn base_at(keyset: Keyset, id: u32) -> Base {
    let mut deposit = [31; 36];
    deposit[32..].copy_from_slice(&7u32.to_le_bytes());
    Base::new(Parts {
        nonce: [53; 32],
        holder_wots: [5; 32],
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
            checkpoint: Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap(),
            funding_depth: 1,
            work_depth: 6,
            max_headers: 1_000,
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

/// Wallet-side derivation: a holder output at (shared, index).
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

struct Opened {
    issuer: IssuerKeys,
    base: Base,
}

fn open() -> Opened {
    open_with(3)
}

fn open_with(max_pow: u32) -> Opened {
    let issuer = IssuerKeys::random(max_pow).unwrap();
    let base = base(issuer.keyset().unwrap());
    Opened { issuer, base }
}

/// The statement's chain with no block after Base's checkpoint.
fn checkpoint_chain() -> Chain {
    let cp = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    Chain::verify(cp.clone(), &cp.commitment(), vec![], 100).unwrap()
}

/// What the Hub's statement decides of `p` filed with `witness` under
/// `request`, against `evidence`, on `chain` (or the checkpoint's alone).
fn decide(
    o: &Opened,
    request: &Request,
    p: &Publication,
    witness: &Witness,
    evidence: &[Evidence],
    chain: Option<&Chain>,
) -> Result<Owed, licash::Error> {
    let filing = Filing::new(p.clone(), witness.clone()).unwrap();
    let chain = chain.cloned().unwrap_or_else(checkpoint_chain);
    recovery::owed(
        &o.base,
        request,
        &filing.to_bytes(Format::of(&o.base)),
        evidence,
        &chain,
    )
}

fn claim(
    o: &Opened,
    items: Vec<Item>,
    sources: Vec<Source>,
    activations: Vec<ActivationRecord>,
    authorizations: &[Derivation],
    amount: u32,
) -> UnsignedClaim {
    let mut authorizations: Vec<_> = authorizations.iter().map(|d| d.message().clone()).collect();
    authorizations.sort_by_key(|m| m.identifier().unwrap());
    let p = o.base.parts();
    UnsignedClaim::new(
        claim::Context {
            base: o.base.digest(),
            deposit: p.deposit,
            cap: p.cap,
        },
        &p.keyset,
        amount,
        claim::Parts {
            items,
            sources,
            activations,
            authorizations,
        },
        LIMIT,
    )
    .unwrap()
}

fn hold_keys(ds: &[Derivation]) -> Vec<(licash::note::Message, crypto::ScalarBytes)> {
    ds.iter()
        .map(|d| (d.message().clone(), d.hold_key(&hold()).unwrap()))
        .collect()
}

fn spend(o: &Opened, notes: &[Note], owners: &[Scalar], to: Vec<Output>) -> SignedProposal {
    let keyset = &o.base.parts().keyset;
    let proposal = Proposal::new(keyset, notes, point(43), to, None).unwrap();
    SignedProposal::sign(keyset, proposal, notes, Authorization::Plain, owners).unwrap()
}

fn bob(denom: u64, index: u32) -> Output {
    let bob = HoldRoot::from_seed(&[9; 32]).unwrap();
    Output::from_derivation(&derive(41, &bob, denom, 29, index)).unwrap()
}

#[test]
fn publication_codec_is_strict() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let ds: Vec<_> = (0..3).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let items = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let publication = Publication::sign(
        claim(&o, items, vec![], vec![], &ds, 12),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let bytes = publication.to_bytes(Format::Legacy);
    assert!(Publication::from_bytes(Format::Legacy, &keyset, LIMIT, &bytes).is_ok());
    for n in 0..bytes.len() {
        assert!(Publication::from_bytes(Format::Legacy, &keyset, LIMIT, &bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Publication::from_bytes(Format::Legacy, &keyset, LIMIT, &trailing).is_err());
    let mut forged = bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1; // a Q signature byte
    assert!(Publication::from_bytes(Format::Legacy, &keyset, LIMIT, &forged).is_err());
    assert!(Publication::from_bytes(Format::Legacy, &keyset, 2, &bytes).is_err());
}

const Z: [u8; 32] = [83; 32];

fn terms() -> TimedTerms {
    let cp = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    TimedTerms::new(
        cp.profile(),
        cp.commitment(),
        4,
        3,
        sha256::Hash::hash(&Z).to_byte_array(),
    )
    .unwrap()
}

fn pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    sha256d::Hash::hash(&[a.as_slice(), b.as_slice()].concat()).to_byte_array()
}
fn merkle(mut hashes: Vec<[u8; 32]>) -> [u8; 32] {
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            hashes.push(*hashes.last().unwrap());
        }
        hashes = hashes.chunks(2).map(|p| pair(&p[0], &p[1])).collect();
    }
    hashes[0]
}

/// Activation witnesses of locks that name Base's own checkpoint, the
/// genesis block: their inclusions, anchored to it.
fn base_activations(inclusions: Vec<Inclusion>) -> Vec<ActivationWitness> {
    let genesis = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    inclusions
        .into_iter()
        .map(|inclusion| ActivationWitness {
            inclusion,
            anchor: Some(genesis.clone()),
        })
        .collect()
}

/// Seven regtest-difficulty blocks; block 1 carries the Pay activation.
fn activated_chain() -> (Chain, Activation) {
    activated_chain_at(1)
}

/// Seven regtest-difficulty blocks; block `at` carries the Pay activation.
fn activated_chain_at(at: u32) -> (Chain, Activation) {
    let cp = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    let mut previous: Header = deserialize(cp.header()).unwrap();
    let (mut headers, mut activation) = (vec![], None);
    for height in 1..=7u32 {
        let reserved = [7; 32];
        let mut txdata = vec![Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, height as u8, 0]),
                witness: bitcoin::Witness::from_slice(&[reserved]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }];
        if height == at {
            txdata.push(Transaction {
                version: transaction::Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([17; 32]),
                        vout: 1,
                    },
                    witness: bitcoin::Witness::from_slice(&[vec![1; 3], vec![0x51]]),
                    ..Default::default()
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(chain::activation_script(&Z)),
                }],
            });
        }
        let mut wtxids: Vec<_> = txdata
            .iter()
            .map(|tx| tx.compute_wtxid().to_byte_array())
            .collect();
        wtxids[0] = [0; 32];
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend(pair(&merkle(wtxids), &reserved));
        txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        });
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: previous.block_hash(),
                merkle_root: previous.merkle_root,
                time: previous.time + 600,
                bits: CompactTarget::from_consensus(0x207fffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce += 1;
        }
        if height == at {
            let raw = serialize(&block);
            activation = Some(Activation {
                reference: ActivationRef {
                    height: at,
                    block_hash: block.block_hash().to_byte_array(),
                    txid: block.txdata[1].compute_txid().to_byte_array(),
                    output: 0,
                },
                inclusion: Inclusion::capture(&raw, 1, raw.len()).unwrap(),
            });
        }
        headers.push(serialize(&block.header).try_into().unwrap());
        previous = block.header;
    }
    (
        Chain::verify(cp.clone(), &cp.commitment(), headers, 100).unwrap(),
        activation.unwrap(),
    )
}

#[test]
fn pending_sources_follow_activation_refund_and_preimage_rules() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let (chain, activation) = activated_chain();
    // Bob pays the holder 4 sats under an issuer-certified timed lock.
    let bob_hold = HoldRoot::from_seed(&[9; 32]).unwrap();
    let bob_note = mint(&o.issuer, &keyset, &derive(41, &bob_hold, 4, 29, 0));
    let pay = derive(SPEND, &hold, 4, 61, 0);
    let lock = TimedLock::new(terms(), vec![bob(4, 1)]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&bob_note),
        point(43),
        vec![Output::from_derivation(&pay).unwrap()],
        Some(lock),
    )
    .unwrap();
    let bob_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&bob_note),
        Authorization::Plain,
        &[owner(41, 29, 0)],
    )
    .unwrap();
    let cert =
        Certificate::attest(&o.issuer, &bob_signed, std::slice::from_ref(&bob_note)).unwrap();
    let bob_id = bob_signed.proposal().id();
    // The holder locked one of her own notes to Carol and claims its refund.
    let own = derive(SPEND, &hold, 4, 23, 40);
    let own_note = mint(&o.issuer, &keyset, &own);
    let refund = derive(SPEND, &hold, 4, 67, 0);
    let carol = derive(53, &HoldRoot::from_seed(&[11; 32]).unwrap(), 4, 31, 0);
    let lock = TimedLock::new(terms(), vec![Output::from_derivation(&refund).unwrap()]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&own_note),
        point(47),
        vec![Output::from_derivation(&carol).unwrap()],
        Some(lock),
    )
    .unwrap();
    let own_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&own_note),
        Authorization::Plain,
        &[owner(SPEND, 23, 40)],
    )
    .unwrap();
    let own_id = own_signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);

    let items = vec![
        Item::Settled(settled.message().clone()),
        Item::Pending {
            message: pay.message().clone(),
            source: bob_id,
            branch: Branch::Pay,
            index: 0,
            blinding: *pay.blinding(),
            preimage: Some(Z),
        },
        Item::Pending {
            message: refund.message().clone(),
            source: own_id,
            branch: Branch::Refund,
            index: 0,
            blinding: *refund.blinding(),
            preimage: None,
        },
    ];
    let sources = vec![
        Source::Admitted(cert),
        Source::OwnInputs {
            id: own_id,
            inputs: vec![own_note.message().identifier().unwrap()],
            terms: terms(),
        },
    ];
    let signers = [settled.clone(), pay.clone(), refund.clone(), own];
    let publish = |activations| {
        let unsigned = claim(
            &o,
            items.clone(),
            sources.clone(),
            activations,
            &signers,
            12,
        );
        let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
        let p =
            Publication::from_bytes(Format::Legacy, &keyset, LIMIT, &p.to_bytes(Format::Legacy))
                .unwrap();
        let request = Request {
            amount: 12,
            claim_digest: *p.claim().digest(),
        };
        (p, request)
    };
    // The public witness: the settled note, each source's body (in P's
    // source-id order), and the given activations' inclusions.
    let witness = |activations: Vec<Inclusion>| {
        let mut sources = vec![
            (
                bob_id,
                SourceWitness::Certified {
                    proposal: bob_signed.proposal().clone(),
                    signatures: bob_signed.signatures().to_vec(),
                },
            ),
            (
                own_id,
                SourceWitness::Signed {
                    signed: own_signed.clone(),
                    notes: vec![own_note.clone()],
                },
            ),
        ];
        sources.sort_by_key(|(id, _)| *id);
        let sources = sources.into_iter().map(|(_, w)| w).collect();
        Witness {
            notes: vec![settled_note.clone()],
            sources,
            activations: base_activations(activations),
            funded: vec![],
        }
    };
    let bob_elsewhere = spend(
        &o,
        std::slice::from_ref(&bob_note),
        &[owner(41, 29, 0)],
        vec![bob(4, 2)],
    );
    let shared = Evidence::Spend {
        signed: bob_elsewhere,
        notes: vec![bob_note],
        unlock: None,
    };
    let counter = |p: &Publication, r: &Request, w: &Witness, e: Evidence| {
        decide(&o, r, p, w, &[e], Some(&chain))
    };

    // Activated certified Pay: expiry and input sharing cannot void it.
    let record = ActivationRecord {
        source: bob_id,
        reference: activation.reference,
    };
    let (p, request) = publish(vec![record]);
    let activated = witness(vec![activation.inclusion.clone()]);
    let uncontested = decide(&o, &request, &p, &activated, &[], Some(&chain)).unwrap();
    assert_eq!((uncontested.owed, uncontested.ineligible), (12, None));
    let expired = || Evidence::Expired { source: bob_id };
    assert!(counter(&p, &request, &activated, expired()).is_err());
    assert!(counter(&p, &request, &activated, shared.clone()).is_err());
    // The Pay preimage voids the holder's own refund; the rest stays owed.
    let preimage = |preimage| Evidence::PayPreimage {
        source: own_id,
        preimage,
    };
    let c = counter(&p, &request, &activated, preimage(Z)).unwrap();
    assert_eq!((c.mask, c.owed), (0b100, 8));
    // Voiding the refund discloses the preimage, which is what the payee of
    // the lock needs to collect.
    let posted = disclosures(&[preimage(Z)]).unwrap();
    assert_eq!((posted.values[0], &c.disclosures), (Z, &posted));
    assert!(counter(&p, &request, &activated, preimage([0; 32])).is_err());

    // Without an advertised activation, input sharing voids the Pay, and
    // expiry is no evidence: the statement can't see one, and a Pay with no
    // activation is owed nothing as it stands.
    let (p, request) = publish(vec![]);
    let plain = witness(vec![]);
    assert!(counter(&p, &request, &plain, expired()).is_err());
    assert_eq!(counter(&p, &request, &plain, shared).unwrap().mask, 0b010);

    // An advertised activation must come with its inclusion.
    let (p, _) = publish(vec![record]);
    assert!(Filing::new(p, witness(vec![])).is_err());
}

/// A lock's Pay is owed only with an activation, anchored to the
/// checkpoint the lock names: any block of the chain the statement reads,
/// after Base's. Expiry is no evidence: without an activation the Pay is
/// owed nothing, whether or not the lock expired.
#[test]
fn a_locks_pay_is_owed_only_on_an_activation_anchored_to_its_checkpoint() {
    let issuer = IssuerKeys::random(3).unwrap();
    let o = Opened {
        base: base(issuer.keyset().unwrap()),
        issuer,
    };
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let (chain, activation) = activated_chain_at(3);
    // The lock names block 1, after Base's checkpoint (the genesis block).
    let anchor = |height: u32| {
        let times = (0..=height)
            .map(|h| u32::from_le_bytes(chain.header(h).unwrap()[68..72].try_into().unwrap()))
            .collect();
        Checkpoint::new(
            ChainProfile::Core30DefaultRegtest,
            height,
            *chain.header(height).unwrap(),
            times,
            None,
        )
        .unwrap()
    };
    let lock_cp = anchor(1);
    let terms = TimedTerms::new(
        lock_cp.profile(),
        lock_cp.commitment(),
        5,
        3,
        sha256::Hash::hash(&Z).to_byte_array(),
    )
    .unwrap();
    // Bob pays the holder 4 sats under an issuer-certified timed lock.
    let bob_hold = HoldRoot::from_seed(&[9; 32]).unwrap();
    let bob_note = mint(&o.issuer, &keyset, &derive(41, &bob_hold, 4, 29, 0));
    let pay = derive(SPEND, &hold, 4, 61, 0);
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&bob_note),
        point(43),
        vec![Output::from_derivation(&pay).unwrap()],
        Some(TimedLock::new(terms, vec![bob(4, 1)]).unwrap()),
    )
    .unwrap();
    let bob_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&bob_note),
        Authorization::Plain,
        &[owner(41, 29, 0)],
    )
    .unwrap();
    let cert =
        Certificate::attest(&o.issuer, &bob_signed, std::slice::from_ref(&bob_note)).unwrap();
    let bob_id = bob_signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);
    let items = vec![
        Item::Settled(settled.message().clone()),
        Item::Pending {
            message: pay.message().clone(),
            source: bob_id,
            branch: Branch::Pay,
            index: 0,
            blinding: *pay.blinding(),
            preimage: Some(Z),
        },
    ];
    let signers = [settled.clone(), pay.clone()];
    let publish = |activations| {
        let unsigned = claim(
            &o,
            items.clone(),
            vec![Source::Admitted(cert.clone())],
            activations,
            &signers,
            8,
        );
        let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
        let request = Request {
            amount: 8,
            claim_digest: *p.claim().digest(),
        };
        (p, request)
    };
    let witness = |activations| Witness {
        notes: vec![settled_note.clone()],
        sources: vec![SourceWitness::Certified {
            proposal: bob_signed.proposal().clone(),
            signatures: bob_signed.signatures().to_vec(),
        }],
        activations,
        funded: vec![],
    };
    let anchored = |anchor| {
        vec![ActivationWitness {
            inclusion: activation.inclusion.clone(),
            anchor,
        }]
    };
    let record = ActivationRecord {
        source: bob_id,
        reference: activation.reference,
    };

    // Activated and anchored: owed in full, and expiry is no evidence.
    let (p, request) = publish(vec![record]);
    let full = witness(anchored(Some(lock_cp.clone())));
    let c = decide(&o, &request, &p, &full, &[], Some(&chain)).unwrap();
    assert_eq!((c.owed, c.ineligible), (8, None));
    let expired = Evidence::Expired { source: bob_id };
    let error = decide(&o, &request, &p, &full, &[expired], Some(&chain)).unwrap_err();
    assert!(error.to_string().contains("voids nothing"), "{error}");
    // The anchored filing has its own magic, and decodes as it was.
    let bytes = Filing::new(p.clone(), full.clone())
        .unwrap()
        .to_bytes(Format::Legacy);
    assert!(bytes.starts_with(b"LICASH-F\x02"));
    let decoded = Filing::from_bytes(Format::Legacy, &keyset, LIMIT, &bytes).unwrap();
    assert_eq!(decoded.to_bytes(Format::Legacy), bytes);
    for n in [bytes.len() - 1, bytes.len() - 40] {
        assert!(Filing::from_bytes(Format::Legacy, &keyset, LIMIT, &bytes[..n]).is_err());
    }
    // Unanchored, or anchored to another block than the
    // lock names, the activation makes the claim ineligible.
    let ineligible = |w: &Witness| {
        decide(&o, &request, &p, w, &[], Some(&chain))
            .unwrap()
            .ineligible
    };
    assert!(ineligible(&witness(anchored(None)))
        .unwrap()
        .contains("without its lock checkpoint"));
    assert!(ineligible(&witness(anchored(Some(anchor(2))))).is_some());
    // On a chain that doesn't bury the activation at the lock's depth, too.
    let short = Chain::verify(
        chain.checkpoint().clone(),
        &chain.checkpoint().commitment(),
        (1..=4).map(|h| *chain.header(h).unwrap()).collect(),
        100,
    )
    .unwrap();
    assert!(decide(&o, &request, &p, &full, &[], Some(&short))
        .unwrap()
        .ineligible
        .is_some());

    // Without an activation the Pay is owed nothing; the rest is owed, and
    // the lock's checkpoint not being Base's makes nothing ineligible.
    let (p, request) = publish(vec![]);
    let c = decide(&o, &request, &p, &witness(vec![]), &[], Some(&chain)).unwrap();
    assert_eq!((c.owed, c.ineligible), (4, None));
}

/// A chain that shows only some of its blocks judges a claim as the whole
/// chain does when it shows those the judgment reads, and records the ones it
/// was not shown, so that a block left out is never taken for a claim owed
/// nothing: a lock's activation, in the block that holds it and the block its
/// lock's checkpoint is.
#[test]
fn a_sparse_chain_judges_an_anchored_activation_as_the_dense_one_and_records_what_it_lacks() {
    let issuer = IssuerKeys::random(3).unwrap();
    let o = Opened {
        base: base(issuer.keyset().unwrap()),
        issuer,
    };
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let (dense, activation) = activated_chain_at(3);
    let header = |h: u32| *dense.header(h).unwrap();
    let times = (0..=1)
        .map(|h| u32::from_le_bytes(header(h)[68..72].try_into().unwrap()))
        .collect();
    let lock_cp = Checkpoint::new(
        ChainProfile::Core30DefaultRegtest,
        1,
        header(1),
        times,
        None,
    )
    .unwrap();
    let terms = TimedTerms::new(
        lock_cp.profile(),
        lock_cp.commitment(),
        5,
        3,
        sha256::Hash::hash(&Z).to_byte_array(),
    )
    .unwrap();
    let bob_hold = HoldRoot::from_seed(&[9; 32]).unwrap();
    let bob_note = mint(&o.issuer, &keyset, &derive(41, &bob_hold, 4, 29, 0));
    let pay = derive(SPEND, &hold, 4, 61, 0);
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&bob_note),
        point(43),
        vec![Output::from_derivation(&pay).unwrap()],
        Some(TimedLock::new(terms, vec![bob(4, 1)]).unwrap()),
    )
    .unwrap();
    let bob_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&bob_note),
        Authorization::Plain,
        &[owner(41, 29, 0)],
    )
    .unwrap();
    let cert =
        Certificate::attest(&o.issuer, &bob_signed, std::slice::from_ref(&bob_note)).unwrap();
    let bob_id = bob_signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);
    let items = vec![
        Item::Settled(settled.message().clone()),
        Item::Pending {
            message: pay.message().clone(),
            source: bob_id,
            branch: Branch::Pay,
            index: 0,
            blinding: *pay.blinding(),
            preimage: Some(Z),
        },
    ];
    let signers = [settled.clone(), pay.clone()];
    let record = ActivationRecord {
        source: bob_id,
        reference: activation.reference,
    };
    let unsigned = claim(
        &o,
        items,
        vec![Source::Admitted(cert)],
        vec![record],
        &signers,
        8,
    );
    let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![settled_note],
        sources: vec![SourceWitness::Certified {
            proposal: bob_signed.proposal().clone(),
            signatures: bob_signed.signatures().to_vec(),
        }],
        activations: vec![ActivationWitness {
            inclusion: activation.inclusion.clone(),
            anchor: Some(lock_cp),
        }],
        funded: vec![],
    };
    let sparse = |tip: u32, shown: &[u32]| {
        let shown = shown.iter().map(|h| (*h, header(*h))).collect();
        Chain::sparse(dense.checkpoint().clone(), tip, shown).unwrap()
    };
    let judged = |chain: &Chain| decide(&o, &request, &p, &witness, &[], Some(chain)).unwrap();

    // The dense chain: owed in full.
    let want = judged(&dense);
    assert_eq!((want.owed, want.ineligible.as_deref()), (8, None));
    // Shown the activation's block and the lock's checkpoint: as dense, and
    // nothing asked for that was not shown, wherever its tip is that dense's is.
    let shown = sparse(7, &[1, 3]);
    assert_eq!(judged(&shown), want);
    assert!(shown.unshown().is_empty());
    // Blocks shown that the judgment does not read change nothing.
    let more = sparse(7, &[1, 2, 3, 6]);
    assert_eq!(judged(&more), want);
    assert!(more.unshown().is_empty());
    // The activation's block left out: owed what the judgment makes of a claim
    // with an activation that is not there, which is 0, but the height asked
    // for is recorded: it is the hub that omitted it, not the holder.
    let no_block = sparse(7, &[1]);
    let judged_without = judged(&no_block);
    assert_eq!(judged_without.owed, 0);
    assert!(judged_without.ineligible.is_some());
    assert_eq!(no_block.unshown(), vec![3]);
    // The lock's checkpoint left out, as well.
    let no_anchor = sparse(7, &[3]);
    assert_eq!(judged(&no_anchor).owed, 0);
    assert_eq!(no_anchor.unshown(), vec![1]);
    // Neither: the judgment stops at the first it lacks, so the second is
    // asked for once the first is shown (a hub opens until none is asked for).
    let neither = sparse(7, &[]);
    assert_eq!(judged(&neither).owed, 0);
    assert_eq!(neither.unshown(), vec![1]);
    // The holder's own error is not the hub's omission: a chain that does not
    // bury the activation at the lock's depth, or that ends before its block,
    // is as ineligible on a sparse chain as on a dense one, and nothing was
    // left out of it.
    for tip in [4, 2] {
        let short = sparse(tip, &[1, 3.min(tip)]);
        let short = judged(&short);
        assert!(short.ineligible.is_some(), "tip {tip}");
        let again = sparse(tip, &[1, 3.min(tip)]);
        judged(&again);
        assert!(
            again.unshown().is_empty(),
            "tip {tip}: {:?}",
            again.unshown()
        );
    }
}

/// A lock's Refund is owed only once the chain judged reaches its
/// expiry at depth: before, she could take it and her payee activate the
/// lock later, both owed. Then, as ever, its preimage voids it.
#[test]
fn a_locks_refund_is_owed_only_once_it_expired_at_depth() {
    let issuer = IssuerKeys::random(3).unwrap();
    let o = Opened {
        base: base(issuer.keyset().unwrap()),
        issuer,
    };
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    // Seven blocks: the lock expires at 4, 3 deep at 7.
    let (chain, _) = activated_chain_at(1);
    assert_eq!(chain.tip_height(), 7);
    let to = |top: u32| {
        Chain::verify(
            chain.checkpoint().clone(),
            &chain.checkpoint().commitment(),
            (1..=top).map(|h| *chain.header(h).unwrap()).collect(),
            100,
        )
        .unwrap()
    };
    // The holder locked one of her own notes to Carol and claims its refund.
    let own = derive(SPEND, &hold, 4, 23, 40);
    let own_note = mint(&o.issuer, &keyset, &own);
    let refund = derive(SPEND, &hold, 4, 67, 0);
    let carol = derive(53, &HoldRoot::from_seed(&[11; 32]).unwrap(), 4, 31, 0);
    let lock = TimedLock::new(terms(), vec![Output::from_derivation(&refund).unwrap()]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&own_note),
        point(47),
        vec![Output::from_derivation(&carol).unwrap()],
        Some(lock),
    )
    .unwrap();
    let own_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&own_note),
        Authorization::Plain,
        &[owner(SPEND, 23, 40)],
    )
    .unwrap();
    let own_id = own_signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);
    let items = vec![
        Item::Settled(settled.message().clone()),
        Item::Pending {
            message: refund.message().clone(),
            source: own_id,
            branch: Branch::Refund,
            index: 0,
            blinding: *refund.blinding(),
            preimage: None,
        },
    ];
    let sources = vec![Source::OwnInputs {
        id: own_id,
        inputs: vec![own_note.message().identifier().unwrap()],
        terms: terms(),
    }];
    let signers = [settled.clone(), refund.clone(), own];
    let unsigned = claim(&o, items, sources, vec![], &signers, 8);
    let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![settled_note],
        sources: vec![SourceWitness::Signed {
            signed: own_signed,
            notes: vec![own_note.clone()],
        }],
        activations: vec![],
        funded: vec![],
    };
    let owed = |top: u32, evidence: &[Evidence]| {
        decide(&o, &request, &p, &witness, evidence, Some(&to(top))).unwrap()
    };
    // Expired at depth: owed in full.
    assert_eq!((owed(7, &[]).owed, owed(7, &[]).ineligible), (8, None));
    // Short of it, expired or not: the refund is owed nothing, the rest is.
    for top in [3, 4, 6] {
        let c = owed(top, &[]);
        assert_eq!((c.owed, c.ineligible), (4, None), "at {top}");
    }
    // Its preimage voids it, as under v3.
    let preimage = Evidence::PayPreimage {
        source: own_id,
        preimage: Z,
    };
    let c = owed(7, &[preimage]);
    assert_eq!((c.mask, c.owed), (0b10, 4));
    // A lock of hers the hub never admitted, its inputs spent in another
    // the hub holds (one it admitted, say): expired at depth or not, that
    // spend voids its refund.
    let admitted = spend(
        &o,
        std::slice::from_ref(&own_note),
        &[owner(SPEND, 23, 40)],
        vec![Output::from_derivation(&carol).unwrap()],
    );
    let shared = Evidence::Spend {
        signed: admitted,
        notes: vec![own_note],
        unlock: None,
    };
    let c = owed(7, &[shared]);
    assert_eq!((c.mask, c.owed), (0b10, 4));
}

/// The paper's example at half scale. Alice pays Bob 50 from a 128 note with
/// 78 change, under a grant. The Hub records the spend and withholds the
/// unlock. Alice claims her input with the change as fallbacks.
struct Withheld {
    o: Opened,
    note: Note,
    signed: SignedProposal,
    unlock: [u8; 32],
    paid: Vec<Derivation>,
    change: Vec<Derivation>,
    request: Request,
    publication: Publication,
    witness: Witness,
}

fn withheld() -> Withheld {
    let o = open_with(7);
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let n = derive(SPEND, &hold, 128, 23, 0);
    let note = mint(&o.issuer, &keyset, &n);
    let bob_hold = HoldRoot::from_seed(&[9; 32]).unwrap();
    let paid: Vec<_> = [32, 16, 2]
        .iter()
        .enumerate()
        .map(|(i, d)| derive(41, &bob_hold, *d, 29, i as u32))
        .collect();
    let change: Vec<_> = [64, 8, 4, 2]
        .iter()
        .enumerate()
        .map(|(i, d)| derive(SPEND, &hold, *d, 71, i as u32))
        .collect();
    let outputs = paid
        .iter()
        .chain(&change)
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let notes = std::slice::from_ref(&note);
    let proposal = Proposal::new(&keyset, notes, point(43), outputs, None).unwrap();
    let prepared = PreparedGrant::new(&o.issuer, &proposal).unwrap();
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
    let source = Source::Plain {
        id,
        inputs: vec![n.message().identifier().unwrap()],
    };
    let held: Vec<_> = std::iter::once(n.clone()).chain(change.clone()).collect();
    let unsigned = claim(&o, items, vec![source], vec![], &held, 128);
    let publication = Publication::sign(unsigned, &hold_keys(&held), LIMIT).unwrap();
    let request = Request {
        amount: 128,
        claim_digest: *publication.claim().digest(),
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
    Withheld {
        o,
        note,
        signed,
        unlock,
        paid,
        change,
        request,
        publication,
        witness,
    }
}

#[test]
fn a_withheld_granted_payment_is_countered_only_by_publishing_its_unlock() {
    let w = withheld();
    let (o, keyset) = (&w.o, w.o.base.parts().keyset.clone());
    let owed = |e: &[Evidence]| decide(o, &w.request, &w.publication, &w.witness, e, None);
    // Unanswered, Alice recovers her input in full.
    assert_eq!(owed(&[]).unwrap().owed, 128);

    let cite = |unlock| Evidence::Spend {
        signed: w.signed.clone(),
        notes: vec![w.note.clone()],
        unlock,
    };
    let counter = |e: Evidence| owed(&[e]);
    // The Hub cannot retire her input while keeping the unlock to itself.
    assert!(counter(cite(None)).is_err());
    assert!(counter(cite(Some([5; 32]))).is_err());
    // Nor by presenting the granted spend as a plain one: the owner signed
    // the grant commitment.
    assert!(SignedProposal::from_parts(
        &keyset,
        w.signed.proposal().clone(),
        std::slice::from_ref(&w.note),
        Authorization::Plain,
        w.signed.signatures().to_vec(),
    )
    .is_err());

    // The valid evidence voids the input, values the change and names the
    // unlock the Hub's response must disclose.
    let c = counter(cite(Some(w.unlock))).unwrap();
    assert_eq!((c.mask, c.owed), (1, 78));
    let posted = disclosures(&[cite(Some(w.unlock))]).unwrap();
    assert_eq!(posted.values[0], w.unlock);
    assert!(posted.values[1..].iter().all(|slot| *slot == [0; 32]));
    assert_eq!(c.disclosures, posted);
    assert_ne!(c.disclosures, disclosures(&[cite(None)]).unwrap());

    // Bob, holding the grant, opens his 50 from the published slots alone;
    // Alice opens her change the same way.
    let Authorization::Granted(grant) = w.signed.authorization() else {
        panic!("granted fixture");
    };
    let found = grant.unlock_in(&posted.values).unwrap();
    let mut opened = 0;
    for (index, d) in w.paid.iter().chain(&w.change).enumerate() {
        let note = w
            .signed
            .open_granted_output(&keyset, std::slice::from_ref(&w.note), index, d, &found)
            .unwrap();
        note.verify(&keyset).unwrap();
        opened += note.message().denomination();
    }
    assert_eq!(opened, 128);
    assert!(grant.unlock_in(&[[0; 32]; 32]).is_none());
}

/// The Hub's evidence travels to its prover as bytes the guest decodes
/// strictly, verifying the notes and the signed spend again.
#[test]
fn evidence_codec_is_strict() {
    let w = withheld();
    let keyset = w.o.base.parts().keyset.clone();
    let id = w.signed.proposal().id();
    let context = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let record = hold::Envelope::sign(context, &hold_keys(&w.change[..1]), LIMIT)
        .unwrap()
        .records()[0]
        .clone();
    let evidence = vec![
        Evidence::Spend {
            signed: w.signed.clone(),
            notes: vec![w.note.clone()],
            unlock: Some(w.unlock),
        },
        Evidence::SecondClaim { context, record },
        Evidence::PayPreimage {
            source: id,
            preimage: [5; 32],
        },
        Evidence::Expired { source: id },
    ];
    let bytes = evidence_to_bytes(&evidence);
    let decoded = evidence_from_bytes(&keyset, LIMIT, &bytes).unwrap();
    assert_eq!(evidence_to_bytes(&decoded), bytes);
    let c = decide(
        &w.o,
        &w.request,
        &w.publication,
        &w.witness,
        &decoded[..1],
        None,
    )
    .unwrap();
    assert_eq!((c.mask, c.owed), (1, 78));
    for n in (0..bytes.len()).step_by(7) {
        assert!(evidence_from_bytes(&keyset, LIMIT, &bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(evidence_from_bytes(&keyset, LIMIT, &trailing).is_err());
    let other = IssuerKeys::random(7).unwrap().keyset().unwrap();
    assert!(evidence_from_bytes(&other, LIMIT, &bytes).is_err());
    assert_eq!(
        evidence_from_bytes(&keyset, LIMIT, &[0; 4]).unwrap().len(),
        0
    );
}

/// A claim of the refund of an unsubmitted lock carries Q's authorization for
/// the lock's inputs, because the Hub may never have seen the lock. A note
/// claimed in one contract and the refund of a lock of it in another are then
/// two claims of the same value, and the first voids the second.
#[test]
fn second_claim_of_an_input_voids_the_outputs_of_a_lock_of_the_holders_own_notes() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let own = derive(SPEND, &hold, 4, 23, 40);
    let own_note = mint(&o.issuer, &keyset, &own);
    let refund = derive(SPEND, &hold, 4, 67, 0);
    let carol = derive(53, &HoldRoot::from_seed(&[11; 32]).unwrap(), 4, 31, 0);
    let lock = TimedLock::new(terms(), vec![Output::from_derivation(&refund).unwrap()]).unwrap();
    let notes = std::slice::from_ref(&own_note);
    let outputs = vec![Output::from_derivation(&carol).unwrap()];
    let body = Proposal::new(&keyset, notes, point(47), outputs, Some(lock)).unwrap();
    let owners = [owner(SPEND, 23, 40)];
    let signed = SignedProposal::sign(&keyset, body, notes, Authorization::Plain, &owners).unwrap();
    let id = signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let items = vec![
        Item::Settled(settled.message().clone()),
        Item::Pending {
            message: refund.message().clone(),
            source: id,
            branch: Branch::Refund,
            index: 0,
            blinding: *refund.blinding(),
            preimage: None,
        },
    ];
    let sources = vec![Source::OwnInputs {
        id,
        inputs: vec![own_note.message().identifier().unwrap()],
        terms: terms(),
    }];
    let signers = [settled.clone(), refund.clone(), own.clone()];
    let unsigned = claim(&o, items, sources, vec![], &signers, 8);
    let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![mint(&o.issuer, &keyset, &settled)],
        sources: vec![SourceWitness::Signed {
            signed,
            notes: vec![own_note],
        }],
        activations: vec![],
        funded: vec![],
    };
    // Its refund is owed once the chain reaches the lock's expiry at depth.
    let (chain, _) = activated_chain();
    let owed = |e: &[Evidence]| decide(&o, &request, &p, &witness, e, Some(&chain));
    assert_eq!(owed(&[]).unwrap().owed, 8);

    // The locked note was claimed in another contract.
    let elsewhere = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let second = |signer: &Derivation| Evidence::SecondClaim {
        context: elsewhere,
        record: hold::Envelope::sign(elsewhere, &hold_keys(std::slice::from_ref(signer)), LIMIT)
            .unwrap()
            .records()[0]
            .clone(),
    };
    let c = owed(&[second(&own)]).unwrap();
    assert_eq!((c.mask, c.owed), (0b10, 4));
    // A claim of a note that this one does not rely on is no evidence.
    let unrelated = derive(SPEND, &hold, 4, 23, 41);
    assert!(owed(&[second(&unrelated)]).is_err());
}

/// The value left after a counter is capped by the request, whatever the
/// denominations of the surviving items add up to.
#[test]
fn surviving_value_beyond_u64_is_capped_at_the_request() {
    let o = open_with(63);
    let keyset = o.base.parts().keyset.clone();
    let ds: Vec<_> = (0..3)
        .map(|i| derive(SPEND, &hold(), 1 << 63, 23, i))
        .collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let items = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let unsigned = claim(&o, items, vec![], vec![], &ds, 128);
    let p = Publication::sign(unsigned, &hold_keys(&ds), LIMIT).unwrap();
    let request = Request {
        amount: 128,
        claim_digest: *p.claim().digest(),
    };
    let spent = Evidence::Spend {
        signed: spend(
            &o,
            &notes[..1],
            &[owner(SPEND, 23, 0)],
            vec![bob(1 << 63, 0)],
        ),
        notes: notes[..1].to_vec(),
        unlock: None,
    };
    let witness = Witness {
        notes,
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    let c = decide(&o, &request, &p, &witness, &[spent], None).unwrap();
    assert_eq!((c.mask, c.owed), (0b1, 128));
}

#[test]
fn second_claim_signature_cannot_be_assigned_to_a_different_note_with_the_same_q() {
    let o = open();
    let first = derive(SPEND, &hold(), 4, 23, 0);
    let second = derive(SPEND, &hold(), 8, 23, 0);
    assert_eq!(first.message().hold(), second.message().hold());
    let unsigned = claim(
        &o,
        vec![Item::Settled(second.message().clone())],
        vec![],
        vec![],
        std::slice::from_ref(&second),
        8,
    );
    let p = Publication::sign(unsigned, &hold_keys(std::slice::from_ref(&second)), LIMIT).unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let context = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let envelope = hold::Envelope::sign(context, &hold_keys(&[first]), LIMIT).unwrap();
    let mut record = envelope.records()[0].clone();
    record.message = second.message().clone();
    let evidence = Evidence::SecondClaim { context, record };
    let witness = Witness {
        notes: vec![mint(&o.issuer, &o.base.parts().keyset, &second)],
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    assert_eq!(
        decide(&o, &request, &p, &witness, &[], None).unwrap().owed,
        8
    );
    assert!(decide(&o, &request, &p, &witness, &[evidence], None).is_err());
}

/// Input Q authority is required only for OwnInputs. Certified outputs belong
/// to their payee and cannot be retired by a signature from the payer's Q key.
/// For OwnInputs, however, even one conflicting input retires every dependent
/// output, on either branch. Such a source must be recovered in one claim.
#[test]
fn input_claim_conflicts_preserve_certified_outputs_but_retire_all_own_outputs() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let inputs: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = inputs.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let pay: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 61, i)).collect();
    let refund: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 67, i)).collect();
    let outputs = |ds: &[Derivation]| {
        ds.iter()
            .map(|d| Output::from_derivation(d).unwrap())
            .collect()
    };
    let lock = TimedLock::new(terms(), outputs(&refund)).unwrap();
    let proposal = Proposal::new(&keyset, &notes, point(47), outputs(&pay), Some(lock)).unwrap();
    let owners: Vec<_> = (0..2).map(|i| owner(SPEND, 23, i)).collect();
    let signed =
        SignedProposal::sign(&keyset, proposal, &notes, Authorization::Plain, &owners).unwrap();
    let id = signed.proposal().id();
    let cert = Certificate::attest(&o.issuer, &signed, &notes).unwrap();
    let settled = derive(SPEND, &hold(), 4, 23, 40);
    let (chain, activation) = activated_chain();
    let publish = |branch: Branch, admitted: bool, indices: &[usize]| {
        let ds = if branch == Branch::Pay { &pay } else { &refund };
        let mut items = vec![Item::Settled(settled.message().clone())];
        let mut signers = vec![settled.clone()];
        for i in indices {
            let d = &ds[*i];
            items.push(Item::Pending {
                message: d.message().clone(),
                source: id,
                branch,
                index: *i as u32,
                blinding: *d.blinding(),
                preimage: (branch == Branch::Pay).then_some(Z),
            });
            signers.push(d.clone());
        }
        let (mut activations, mut inclusions) = (vec![], vec![]);
        let source = if admitted {
            if branch == Branch::Pay {
                activations.push(ActivationRecord {
                    source: id,
                    reference: activation.reference,
                });
                inclusions.push(activation.inclusion.clone());
            }
            Source::Admitted(cert.clone())
        } else {
            signers.extend(inputs.iter().cloned());
            Source::OwnInputs {
                id,
                inputs: {
                    let mut ys: Vec<_> = (signed.proposal().inputs().iter())
                        .map(|m| m.identifier().unwrap())
                        .collect();
                    ys.sort_unstable();
                    ys
                },
                terms: terms(),
            }
        };
        let amount = (4 * (1 + indices.len())) as u32;
        let unsigned = claim(&o, items, vec![source], activations, &signers, amount);
        let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
        let request = Request {
            amount,
            claim_digest: *p.claim().digest(),
        };
        let body = if admitted {
            SourceWitness::Certified {
                proposal: signed.proposal().clone(),
                signatures: signed.signatures().to_vec(),
            }
        } else {
            SourceWitness::Signed {
                signed: signed.clone(),
                notes: notes.clone(),
            }
        };
        let witness = Witness {
            notes: vec![mint(&o.issuer, &keyset, &settled)],
            sources: vec![body],
            activations: base_activations(inclusions),
            funded: vec![],
        };
        (p, request, witness)
    };
    let elsewhere = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let e = Evidence::SecondClaim {
        context: elsewhere,
        record: hold::Envelope::sign(elsewhere, &hold_keys(&inputs[..1]), LIMIT)
            .unwrap()
            .records()[0]
            .clone(),
    };
    let e = std::slice::from_ref(&e);
    for branch in [Branch::Pay, Branch::Refund] {
        let (p, r, w) = publish(branch, true, &[0, 1]);
        let eligible = decide(&o, &r, &p, &w, &[], Some(&chain)).unwrap();
        assert_eq!((eligible.owed, eligible.ineligible), (12, None));
        assert!(decide(&o, &r, &p, &w, e, Some(&chain)).is_err());
        let (p, r, w) = publish(branch, false, &[0, 1]);
        let c = decide(&o, &r, &p, &w, e, None).unwrap();
        assert_eq!((c.mask, c.owed), (0b110, 4));
    }
    // Even disjoint outputs of one OwnInputs source share its input Q
    // authorities: splitting this recovery across claims is not supported.
    let (first, r1, w1) = publish(Branch::Refund, false, &[0]);
    let (second, r2, w2) = publish(Branch::Refund, false, &[1]);
    for (here, r, w, other) in [(&first, &r1, &w1, &second), (&second, &r2, &w2, &first)] {
        let evidence = Evidence::SecondClaim {
            context: other.claim().hold_context(),
            record: other
                .envelope()
                .records()
                .iter()
                .find(|record| record.message == *inputs[0].message())
                .unwrap()
                .clone(),
        };
        let c = decide(&o, r, here, w, &[evidence], None).unwrap();
        assert_eq!((c.mask, c.owed), (0b10, 4));
    }
}

// The holder files P with its public witness and proves nothing; the Hub's
// statement (`recovery::owed`) decides what the claim is owed.

/// `bytes` with the unique occurrence of `inside` replaced by `with`.
fn swap(bytes: &[u8], inside: &[u8], with: &[u8]) -> Vec<u8> {
    let at: Vec<_> = bytes
        .windows(inside.len())
        .enumerate()
        .filter(|(_, w)| *w == inside)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1);
    [&bytes[..at[0]], with, &bytes[at[0] + inside.len()..]].concat()
}

/// `bytes` with the last byte of the unique occurrence of `inside` flipped.
fn flip(bytes: &[u8], inside: &[u8]) -> Vec<u8> {
    let mut with = inside.to_vec();
    *with.last_mut().unwrap() ^= 1;
    swap(bytes, inside, &with)
}

#[test]
fn the_hub_decides_what_a_filed_claim_is_owed() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let (chain, _) = activated_chain();
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold, 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    // After her backup, the holder paid Bob 64 sats from 16 of the notes.
    let owners: Vec<_> = (0..16).map(|i| owner(SPEND, 23, i)).collect();
    let payment = spend(
        &o,
        &notes[..16],
        &owners,
        (0..8).map(|i| bob(8, i)).collect(),
    );
    let items = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let p = Publication::sign(
        claim(&o, items, vec![], vec![], &ds, 128),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 128,
        claim_digest: *p.claim().digest(),
    };
    let filing = Filing::new(
        p,
        Witness {
            notes: notes.clone(),
            sources: vec![],
            activations: vec![],
            funded: vec![],
        },
    )
    .unwrap();
    let bytes = filing.to_bytes(Format::Legacy);
    assert!(bytes.len() < 25_000, "{} bytes", bytes.len());
    let owed = |request: &Request, bytes: &[u8], evidence: &[Evidence]| {
        recovery::owed(&o.base, request, bytes, evidence, &chain)
    };

    // Unanswered by evidence, the claim is owed in full: nothing to prove.
    let whole = owed(&request, &bytes, &[]).unwrap();
    assert_eq!((whole.owed, whole.mask, whole.ineligible), (128, 0, None));
    // The stale backup: the Hub's evidence of the spend voids 16 items, as
    // in a counter.
    let spent = Evidence::Spend {
        signed: payment,
        notes: notes[..16].to_vec(),
        unlock: None,
    };
    let stale = owed(&request, &bytes, std::slice::from_ref(&spent)).unwrap();
    assert_eq!((stale.owed, stale.mask), (64, 0xffff));
    // A Q signature over any other claim, in any contract, voids its item.
    let other = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let record = hold::Envelope::sign(other, &hold_keys(&ds[20..21]), LIMIT)
        .unwrap()
        .records()[0]
        .clone();
    let second = Evidence::SecondClaim {
        context: other,
        record: record.clone(),
    };
    let both = owed(&request, &bytes, &[spent.clone(), second]).unwrap();
    assert_eq!((both.owed, both.mask), (60, 0xffff | 1 << 20));

    // The Hub's errors: it can't prove with evidence that voids nothing,
    // with this claim cited as its own second claim, or on another chain.
    let unrelated = derive(SPEND, &hold, 4, 23, 40);
    let unrelated_note = mint(&o.issuer, &keyset, &unrelated);
    let unrelated = Evidence::Spend {
        signed: spend(
            &o,
            std::slice::from_ref(&unrelated_note),
            &[owner(SPEND, 23, 40)],
            vec![bob(4, 9)],
        ),
        notes: vec![unrelated_note],
        unlock: None,
    };
    assert!(owed(&request, &bytes, &[unrelated]).is_err());
    let same = Evidence::SecondClaim {
        context: filing.publication().claim().hold_context(),
        record,
    };
    assert!(owed(&request, &bytes, &[same]).is_err());
    let signet = Checkpoint::genesis(ChainProfile::Core30Signet).unwrap();
    let elsewhere = Chain::verify(signet.clone(), &signet.commitment(), vec![], 100).unwrap();
    assert!(recovery::owed(&o.base, &request, &bytes, &[], &elsewhere).is_err());

    // A filing for another request is the holder's error: owed nothing, which
    // the Hub shows with no evidence (and may attach none).
    let wrong = Request {
        amount: 127,
        ..request
    };
    let nothing = owed(&wrong, &bytes, &[]).unwrap();
    assert_eq!((nothing.owed, nothing.mask), (0, 0));
    assert!(nothing.ineligible.is_some());
    assert_eq!(nothing.disclosures, disclosures(&[]).unwrap());
    assert!(owed(&wrong, &bytes, &[spent]).is_err());
}

#[test]
fn a_wallet_tests_a_note_against_evidence_as_the_statement_does() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let ds: Vec<_> = (0..32).map(|i| derive(SPEND, &hold, 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let owners: Vec<_> = (0..16).map(|i| owner(SPEND, 23, i)).collect();
    let payment = spend(
        &o,
        &notes[..16],
        &owners,
        (0..8).map(|i| bob(8, i)).collect(),
    );
    let spent = Evidence::Spend {
        signed: payment,
        notes: notes[..16].to_vec(),
        unlock: None,
    };
    let message = |i: usize| ds[i].message();
    // A spend shows the notes it consumed spent, and no other.
    assert!(recovery::voids_note(&keyset, message(0), &spent).unwrap());
    assert!(recovery::voids_note(&keyset, message(15), &spent).unwrap());
    assert!(!recovery::voids_note(&keyset, message(16), &spent).unwrap());
    // The hold key's signature of another claim shows that note claimed, and
    // only that one.
    let other = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let record = hold::Envelope::sign(other, &hold_keys(&ds[20..21]), LIMIT)
        .unwrap()
        .records()[0]
        .clone();
    let second = Evidence::SecondClaim {
        context: other,
        record: record.clone(),
    };
    assert!(recovery::voids_note(&keyset, message(20), &second).unwrap());
    assert!(!recovery::voids_note(&keyset, message(21), &second).unwrap());
    // Proof, not assertion: a signature that is not the hold key's, or of
    // another context than it says, shows nothing and is an error.
    let mut forged = record.clone();
    forged.sig.0[63] ^= 1;
    let forged = Evidence::SecondClaim {
        context: other,
        record: forged,
    };
    assert!(recovery::voids_note(&keyset, message(20), &forged).is_err());
    let misdated = Evidence::SecondClaim {
        context: hold::Context { amount: 5, ..other },
        record,
    };
    assert!(recovery::voids_note(&keyset, message(20), &misdated).is_err());
    // A hub's preimage or expiry speaks of no single note.
    let preimage = Evidence::PayPreimage {
        source: licash::spend::ProposalId::from_bytes([9; 32]),
        preimage: [8; 32],
    };
    assert!(!recovery::voids_note(&keyset, message(0), &preimage).unwrap());
}

#[test]
fn a_note_is_claimed_in_any_contract_its_hold_key_designates() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let (chain, _) = activated_chain();
    // Notes of a wallet whose spend root (41) isn't this contract's.
    let ds: Vec<_> = (0..2).map(|i| derive(41, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let items: Vec<_> = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let unsigned = claim(&o, items, vec![], vec![], &ds, 8);
    let p = Publication::sign(unsigned.clone(), &hold_keys(&ds), LIMIT).unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    // Filed, their Q signatures designate this contract, and they are owed.
    let signatures: Vec<_> = p.envelope().records().iter().map(|r| r.sig.0).collect();
    let filing = Filing::new(
        p,
        Witness {
            notes,
            sources: vec![],
            activations: vec![],
            funded: vec![],
        },
    )
    .unwrap();
    let bytes = filing.to_bytes(Format::Legacy);
    let owed = |bytes: &[u8]| recovery::owed(&o.base, &request, bytes, &[], &chain).unwrap();
    assert_eq!((owed(&bytes).owed, owed(&bytes).ineligible), (8, None));

    // Only the notes' Q keys designate. Another hold root (a payer's, say,
    // who knows the outputs it made) doesn't derive their Q secrets, a key
    // that isn't Q's secret can't sign P, and a forged Q signature leaves the
    // claim owed nothing.
    let payer = HoldRoot::from_seed(&[9; 32]).unwrap();
    assert!(ds.iter().all(|d| d.hold_key(&payer).is_err()));
    let theirs: Vec<_> = ds
        .iter()
        .map(|d| (d.message().clone(), crypto::ScalarBytes([7; 32])))
        .collect();
    assert!(Publication::sign(unsigned, &theirs, LIMIT).is_err());
    for sig in signatures {
        let forged = owed(&flip(&bytes, &sig));
        assert_eq!(forged.owed, 0);
        assert!(forged.ineligible.is_some());
    }
}

#[test]
fn fabricated_or_malformed_filings_are_owed_nothing() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let (chain, _) = activated_chain();
    let ds: Vec<_> = (0..3).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let items: Vec<_> = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let p = Publication::sign(
        claim(&o, items, vec![], vec![], &ds, 12),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 12,
        claim_digest: *p.claim().digest(),
    };
    let file = |notes: Vec<Note>| {
        Filing::new(
            p.clone(),
            Witness {
                notes,
                sources: vec![],
                activations: vec![],
                funded: vec![],
            },
        )
    };
    let bytes = file(notes.clone()).unwrap().to_bytes(Format::Legacy);
    let owed = |bytes: &[u8], evidence: &[Evidence]| {
        recovery::owed(&o.base, &request, bytes, evidence, &chain)
    };
    assert_eq!(owed(&bytes, &[]).unwrap().owed, 12);
    let nothing = |bytes: &[u8]| {
        let o = owed(bytes, &[]).unwrap();
        assert_eq!((o.owed, o.mask), (0, 0));
        assert!(o.ineligible.is_some());
    };

    // A note another issuer signed, or the issuer's signature forged.
    let other = IssuerKeys::random(3).unwrap();
    let mut fake = notes.clone();
    fake[1] = mint(&other, &other.keyset().unwrap(), &ds[1]);
    nothing(&file(fake).unwrap().to_bytes(Format::Legacy));
    nothing(&flip(&bytes, &notes[1].signature().0));
    let borrowed = swap(&bytes, &notes[1].signature().0, &notes[0].signature().0);
    let reason = owed(&borrowed, &[]).unwrap().ineligible.unwrap();
    assert!(!reason.contains("point"), "{reason}");
    nothing(&borrowed);
    // A filing that doesn't decode: cut short, extended, not a filing (P
    // alone), or nothing at all.
    for n in [0, 9, bytes.len() / 2, bytes.len() - 1] {
        nothing(&bytes[..n]);
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    nothing(&trailing);
    nothing(&p.to_bytes(Format::Legacy));
    // A witness that doesn't line up with P can't be filed.
    assert!(file(notes[..2].to_vec()).is_err());
    assert!(file(vec![notes[1].clone(), notes[0].clone(), notes[2].clone()]).is_err());

    // Evidence against an ineligible claim is the Hub's error.
    let spent = Evidence::Spend {
        signed: spend(&o, &notes[..1], &[owner(SPEND, 23, 0)], vec![bob(4, 0)]),
        notes: notes[..1].to_vec(),
        unlock: None,
    };
    assert_eq!(owed(&bytes, std::slice::from_ref(&spent)).unwrap().owed, 8);
    assert!(owed(&trailing, &[spent]).is_err());
}

#[test]
fn pending_items_are_eligible_by_their_sources_public_bodies() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    let (chain, activation) = activated_chain();
    // Bob pays the holder 4 sats under an issuer-certified timed lock.
    let bob_hold = HoldRoot::from_seed(&[9; 32]).unwrap();
    let bob_note = mint(&o.issuer, &keyset, &derive(41, &bob_hold, 4, 29, 0));
    let pay = derive(SPEND, &hold, 4, 61, 0);
    let lock = TimedLock::new(terms(), vec![bob(4, 1)]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&bob_note),
        point(43),
        vec![Output::from_derivation(&pay).unwrap()],
        Some(lock),
    )
    .unwrap();
    let bob_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&bob_note),
        Authorization::Plain,
        &[owner(41, 29, 0)],
    )
    .unwrap();
    let cert =
        Certificate::attest(&o.issuer, &bob_signed, std::slice::from_ref(&bob_note)).unwrap();
    let bob_id = bob_signed.proposal().id();
    // The holder locked one of her own notes to Carol and claims its refund.
    let own = derive(SPEND, &hold, 4, 23, 40);
    let own_note = mint(&o.issuer, &keyset, &own);
    let refund = derive(SPEND, &hold, 4, 67, 0);
    let carol = derive(53, &HoldRoot::from_seed(&[11; 32]).unwrap(), 4, 31, 0);
    let lock = TimedLock::new(terms(), vec![Output::from_derivation(&refund).unwrap()]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&own_note),
        point(47),
        vec![Output::from_derivation(&carol).unwrap()],
        Some(lock),
    )
    .unwrap();
    let own_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&own_note),
        Authorization::Plain,
        &[owner(SPEND, 23, 40)],
    )
    .unwrap();
    let own_id = own_signed.proposal().id();
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);

    let items = |refund_blinding| {
        vec![
            Item::Settled(settled.message().clone()),
            Item::Pending {
                message: pay.message().clone(),
                source: bob_id,
                branch: Branch::Pay,
                index: 0,
                blinding: *pay.blinding(),
                preimage: Some(Z),
            },
            Item::Pending {
                message: refund.message().clone(),
                source: own_id,
                branch: Branch::Refund,
                index: 0,
                blinding: refund_blinding,
                preimage: None,
            },
        ]
    };
    let sources = |own_terms| {
        vec![
            Source::Admitted(cert.clone()),
            Source::OwnInputs {
                id: own_id,
                inputs: vec![own_note.message().identifier().unwrap()],
                terms: own_terms,
            },
        ]
    };
    // The sources' bodies, in P's (source-id) order.
    let mut bodies = vec![
        (
            bob_id,
            SourceWitness::Certified {
                proposal: bob_signed.proposal().clone(),
                signatures: bob_signed.signatures().to_vec(),
            },
        ),
        (
            own_id,
            SourceWitness::Signed {
                signed: own_signed,
                notes: vec![own_note.clone()],
            },
        ),
    ];
    bodies.sort_by_key(|(id, _)| *id);
    let bodies: Vec<_> = bodies.into_iter().map(|(_, w)| w).collect();
    let signers = [settled.clone(), pay.clone(), refund.clone(), own];
    let file = |items, sources, activations, inclusions| {
        let p = Publication::sign(
            claim(&o, items, sources, activations, &signers, 12),
            &hold_keys(&signers),
            LIMIT,
        )
        .unwrap();
        let request = Request {
            amount: 12,
            claim_digest: *p.claim().digest(),
        };
        let filing = Filing::new(
            p,
            Witness {
                notes: vec![settled_note.clone()],
                sources: bodies.clone(),
                activations: base_activations(inclusions),
                funded: vec![],
            },
        )
        .unwrap();
        (filing.to_bytes(Format::Legacy), request)
    };
    let owed = |(bytes, request): &(Vec<u8>, Request), evidence: &[Evidence], chain: &Chain| {
        recovery::owed(&o.base, request, bytes, evidence, chain)
    };
    let nothing = |filed: &(Vec<u8>, Request), chain: &Chain| {
        let o = owed(filed, &[], chain).unwrap();
        assert_eq!(o.owed, 0);
        assert!(o.ineligible.is_some());
    };
    let record = ActivationRecord {
        source: bob_id,
        reference: activation.reference,
    };
    let preimage = Evidence::PayPreimage {
        source: own_id,
        preimage: Z,
    };

    // Activated certified Pay: eligible, and expiry can't void it; the Pay
    // preimage voids the holder's own refund, and is disclosed.
    let activated = file(
        items(*refund.blinding()),
        sources(terms()),
        vec![record],
        vec![activation.inclusion.clone()],
    );
    assert_eq!(owed(&activated, &[], &chain).unwrap().owed, 12);
    assert!(owed(&activated, &[Evidence::Expired { source: bob_id }], &chain).is_err());
    let c = owed(&activated, std::slice::from_ref(&preimage), &chain).unwrap();
    assert_eq!((c.mask, c.owed), (0b100, 8));
    assert_eq!(c.disclosures, disclosures(&[preimage]).unwrap());
    // Without an advertised activation, expiry is no evidence.
    let plain = file(items(*refund.blinding()), sources(terms()), vec![], vec![]);
    assert!(owed(&plain, &[Evidence::Expired { source: bob_id }], &chain).is_err());

    // What the holder can get wrong of a pending item leaves the claim owed
    // nothing: an activation the statement's chain doesn't bury at its
    // terms' depth, or that isn't what it says; an output the source doesn't
    // make; source metadata its body doesn't match.
    let short = Chain::verify(
        chain.checkpoint().clone(),
        &chain.checkpoint().commitment(),
        (1..=2).map(|h| *chain.header(h).unwrap()).collect(),
        100,
    )
    .unwrap();
    nothing(&activated, &short);
    let elsewhere = ActivationRecord {
        source: bob_id,
        reference: ActivationRef {
            output: 1,
            ..activation.reference
        },
    };
    nothing(
        &file(
            items(*refund.blinding()),
            sources(terms()),
            vec![elsewhere],
            vec![activation.inclusion.clone()],
        ),
        &chain,
    );
    nothing(
        &file(items(*pay.blinding()), sources(terms()), vec![], vec![]),
        &chain,
    );
    let cp = Checkpoint::genesis(ChainProfile::Core30DefaultRegtest).unwrap();
    let later = TimedTerms::new(
        cp.profile(),
        cp.commitment(),
        5,
        3,
        sha256::Hash::hash(&Z).to_byte_array(),
    )
    .unwrap();
    nothing(
        &file(items(*refund.blinding()), sources(later), vec![], vec![]),
        &chain,
    );
}

/// A v5 Base of `issuer`'s keyset whose holder funds it with `outputs`.
fn funded_base(issuer: &IssuerKeys, outputs: &[Output], amount: u32) -> Base {
    funded_base_at(issuer, outputs, amount, 7)
}

/// [`funded_base`] of a graph of `id`.
fn funded_base_at(issuer: &IssuerKeys, outputs: &[Output], amount: u32, id: u32) -> Base {
    let mut parts = base(issuer.keyset().unwrap()).parts().clone();
    parts.graph.id = id;
    parts.funded = licash::spend::funded_root(outputs).unwrap();
    parts.graph.deposit_units = amount;
    Base::new(parts).unwrap()
}

fn funded_items(ds: &[Derivation], indices: &[u32]) -> Vec<Item> {
    indices
        .iter()
        .map(|&i| Item::Funded {
            message: ds[i as usize].message().clone(),
            index: i,
            blinding: *ds[i as usize].blinding(),
        })
        .collect()
}

/// Of a v5 Base, the notes its holder funded it with: claimed by the
/// outputs it commits to, owed at face whether issued or not, and void
/// only once spent or claimed elsewhere.
#[test]
fn v5_owes_her_funded_notes_unless_spent_or_claimed_elsewhere() {
    let issuer = IssuerKeys::random(3).unwrap();
    let ds: Vec<_> = (0..4).map(|i| derive(SPEND, &hold(), 4, 24, i)).collect();
    let outputs: Vec<_> = ds
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let o = Opened {
        base: funded_base(&issuer, &outputs, 16),
        issuer,
    };
    assert_eq!(
        o.base.parts().funded,
        licash::spend::funded_root(&outputs).unwrap()
    );
    let decoded = Base::from_bytes(&o.base.to_bytes()).unwrap();
    assert_eq!(decoded.digest(), o.base.digest());

    // Three of the four claimed: 12 sat.
    let p = Publication::sign(
        claim(
            &o,
            funded_items(&ds, &[0, 1, 3]),
            vec![],
            vec![],
            &[ds[0].clone(), ds[1].clone(), ds[3].clone()],
            12,
        ),
        &hold_keys(&[ds[0].clone(), ds[1].clone(), ds[3].clone()]),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 12,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![],
        sources: vec![],
        activations: vec![],
        funded: outputs.clone(),
    };
    let filing = Filing::new(p.clone(), witness.clone()).unwrap();
    let bytes = filing.to_bytes(Format::Legacy);
    assert!(bytes.starts_with(b"LICASH-F\x03"));
    assert_eq!(
        Filing::from_bytes(Format::Legacy, &o.base.parts().keyset, LIMIT, &bytes)
            .unwrap()
            .to_bytes(Format::Legacy),
        bytes
    );
    for n in 0..bytes.len() {
        assert!(
            Filing::from_bytes(Format::Legacy, &o.base.parts().keyset, LIMIT, &bytes[..n]).is_err()
        );
    }
    let whole = decide(&o, &request, &p, &witness, &[], None).unwrap();
    assert_eq!((whole.owed, whole.mask, whole.ineligible), (12, 0, None));

    // Issued and spent: void.
    let note = mint(&o.issuer, &o.base.parts().keyset, &ds[1]);
    let spent = Evidence::Spend {
        signed: spend(
            &o,
            std::slice::from_ref(&note),
            &[owner(SPEND, 24, 1)],
            vec![bob(4, 0)],
        ),
        notes: vec![note],
        unlock: None,
    };
    let after = decide(
        &o,
        &request,
        &p,
        &witness,
        std::slice::from_ref(&spent),
        None,
    )
    .unwrap();
    assert_eq!((after.owed, after.mask), (8, 0b010));
    // Claimed in another contract: void.
    let other = hold::Context {
        base: [1; 32],
        deposit: [2; 36],
        amount: 4,
        claim_digest: [3; 32],
    };
    let record = hold::Envelope::sign(other, &hold_keys(&ds[3..4]), LIMIT)
        .unwrap()
        .records()[0]
        .clone();
    let second = Evidence::SecondClaim {
        context: other,
        record,
    };
    let both = decide(&o, &request, &p, &witness, &[spent, second], None).unwrap();
    assert_eq!((both.owed, both.mask), (4, 0b110));
    // No preimage or expiry touches them: evidence voiding nothing.
    let preimage = Evidence::PayPreimage {
        source: licash::spend::ProposalId::from_bytes([9; 32]),
        preimage: Z,
    };
    assert!(decide(&o, &request, &p, &witness, &[preimage], None).is_err());

    // Filed against outputs Base doesn't commit to, or opening none: owed
    // nothing.
    let mut fewer = witness.clone();
    fewer.funded.pop();
    let ineligible = decide(&o, &request, &p, &fewer, &[], None).unwrap();
    assert_eq!(ineligible.owed, 0);
    assert!(ineligible.ineligible.unwrap().contains("funded outputs"));
    let mut swapped = witness.clone();
    swapped.funded.swap(0, 1);
    assert_eq!(
        decide(&o, &request, &p, &swapped, &[], None).unwrap().owed,
        0
    );
    let wrong = vec![Item::Funded {
        message: ds[0].message().clone(),
        index: 1,
        blinding: *ds[0].blinding(),
    }];
    let p_wrong = Publication::sign(
        claim(&o, wrong, vec![], vec![], &ds[..1], 4),
        &hold_keys(&ds[..1]),
        LIMIT,
    )
    .unwrap();
    let request_wrong = Request {
        amount: 4,
        claim_digest: *p_wrong.claim().digest(),
    };
    let owed = decide(&o, &request_wrong, &p_wrong, &witness, &[], None).unwrap();
    assert!(owed.ineligible.unwrap().contains("does not open"));

    // Funded items and the outputs they open come together.
    assert!(Filing::new(
        p.clone(),
        Witness {
            funded: vec![],
            ..witness.clone()
        }
    )
    .is_err());
    let settled = Publication::sign(
        claim(
            &o,
            vec![Item::Settled(ds[2].message().clone())],
            vec![],
            vec![],
            &ds[2..3],
            4,
        ),
        &hold_keys(&ds[2..3]),
        LIMIT,
    )
    .unwrap();
    assert!(Filing::new(settled, witness.clone()).is_err());
    // One output claimed twice: refused.
    let p = o.base.parts();
    let twice = UnsignedClaim::new(
        claim::Context {
            base: o.base.digest(),
            deposit: p.deposit,
            cap: p.cap,
        },
        &p.keyset,
        4,
        claim::Parts {
            items: vec![
                funded_items(&ds, &[0]).remove(0),
                Item::Funded {
                    message: ds[1].message().clone(),
                    index: 0,
                    blinding: *ds[1].blinding(),
                },
            ],
            sources: vec![],
            activations: vec![],
            authorizations: {
                let mut m: Vec<_> = ds[..2].iter().map(|d| d.message().clone()).collect();
                m.sort_by_key(|m| m.identifier().unwrap());
                m
            },
        },
        LIMIT,
    );
    assert!(twice.is_err());
}

/// A claim of funded items under a Base committing to no funded outputs
/// (v3, v4) is owed nothing.
#[test]
fn funded_items_under_a_base_of_no_funding_are_owed_nothing() {
    let o = open();
    let ds: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 24, i)).collect();
    let outputs: Vec<_> = ds
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let p = Publication::sign(
        claim(&o, funded_items(&ds, &[0, 1]), vec![], vec![], &ds, 8),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![],
        sources: vec![],
        activations: vec![],
        funded: outputs,
    };
    let owed = decide(&o, &request, &p, &witness, &[], None).unwrap();
    assert_eq!(owed.owed, 0);
    assert!(owed.ineligible.is_some());
}

#[test]
fn a_base_funds_at_most_its_cap_and_something() {
    let issuer = IssuerKeys::random(3).unwrap();
    let outputs = vec![bob(4, 0)];
    let mut parts = funded_base(&issuer, &outputs, 4).parts().clone();
    for (units, funded) in [(0, [1; 32]), (129, [1; 32]), (4, [0; 32])] {
        parts.graph.deposit_units = units;
        parts.funded = funded;
        assert!(Base::new(parts.clone()).is_err(), "{units}");
    }
    parts.graph.deposit_units = 4;
    parts.funded = [1; 32];
    parts.holder_wots = [0; 32];
    assert!(Base::new(parts).is_err());
    assert!(licash::spend::funded_root(&[]).is_err());
}

/// Her funded outputs are owed only if worth exactly what she funded.
#[test]
fn funded_outputs_worth_other_than_she_funded_are_owed_nothing() {
    let ds: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 24, i)).collect();
    let outputs: Vec<_> = ds
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    for (amount, owed) in [(8, 8), (7, 0), (9, 0)] {
        let issuer = IssuerKeys::random(3).unwrap();
        let o = Opened {
            base: funded_base(&issuer, &outputs, amount),
            issuer,
        };
        let p = Publication::sign(
            claim(&o, funded_items(&ds, &[0, 1]), vec![], vec![], &ds, 8),
            &hold_keys(&ds),
            LIMIT,
        )
        .unwrap();
        let request = Request {
            amount: 8,
            claim_digest: *p.claim().digest(),
        };
        let witness = Witness {
            notes: vec![],
            sources: vec![],
            activations: vec![],
            funded: outputs.clone(),
        };
        let decided = decide(&o, &request, &p, &witness, &[], None).unwrap();
        assert_eq!(decided.owed, owed, "{amount}");
    }
}

// ----- the compact filing -----

fn open_at(id: u32) -> Opened {
    let issuer = IssuerKeys::random(3).unwrap();
    let base = base_at(issuer.keyset().unwrap(), id);
    Opened { issuer, base }
}

/// `n` settled notes of 4 filed under `o`, with the request that signs them.
fn settled(o: &Opened, n: u32) -> (Filing, Request, Vec<Derivation>) {
    let keyset = o.base.parts().keyset.clone();
    let ds: Vec<_> = (0..n).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let items = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let p = Publication::sign(
        claim(o, items, vec![], vec![], &ds, 4 * n),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 4 * n,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes,
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    (Filing::new(p, witness).unwrap(), request, ds)
}

fn owed_of(o: &Opened, request: &Request, bytes: &[u8]) -> Owed {
    recovery::owed(&o.base, request, bytes, &[], &checkpoint_chain()).unwrap()
}

#[test]
fn a_contract_files_the_format_its_graph_id_names() {
    assert_eq!(
        Format::of(&open_at(recovery::COMPACT_FROM - 1).base),
        Format::Legacy
    );
    assert_eq!(
        Format::of(&open_at(recovery::COMPACT_FROM).base),
        Format::Compact
    );
    assert_eq!(
        Format::of(&open_at(recovery::LEAN_FROM - 1).base),
        Format::Compact
    );
    assert_eq!(Format::of(&open_at(recovery::LEAN_FROM).base), Format::Lean);
    assert_eq!(
        Format::of(&open_at(recovery::LEAN_FROM + 1).base),
        Format::Lean
    );
}

#[test]
fn a_compact_filing_is_owed_what_a_legacy_one_is_and_is_smaller() {
    let (legacy, compact) = (open_at(7), open_at(recovery::COMPACT_FROM));
    let (lf, lr, _) = settled(&legacy, 7);
    let (cf, cr, _) = settled(&compact, 7);
    let (lb, cb) = (lf.to_bytes(Format::Legacy), cf.to_bytes(Format::Compact));
    // The same claim of the same notes, decided the same.
    let (l, c) = (owed_of(&legacy, &lr, &lb), owed_of(&compact, &cr, &cb));
    assert_eq!((l.owed, l.ineligible), (28, None));
    assert_eq!((c.owed, c.ineligible), (28, None));
    // A settled note saves its item's fields repeated as its record (72
    // of 136, for 66) and its witness's keyset and fields (114): 184 of
    // 523, to 339.
    assert_eq!(lb.len() - cb.len(), 7 * 184);
    assert!(cb.starts_with(b"LICASH-F\x11"));
    // It decodes to what it was filed as, and encodes to the same bytes.
    let keyset = compact.base.parts().keyset.clone();
    let decoded = Filing::from_bytes(Format::Compact, &keyset, LIMIT, &cb).unwrap();
    assert_eq!(decoded.to_bytes(Format::Compact), cb);
    assert_eq!(
        decoded.publication().claim().digest(),
        cf.publication().claim().digest()
    );
}

/// A contract is decided by its own format: the other's bytes aren't a
/// filing under it, so that a holder that files the wrong one is owed
/// nothing, as for any bytes that don't decode.
#[test]
fn the_other_formats_bytes_are_no_filing() {
    let (legacy, compact) = (open_at(7), open_at(recovery::COMPACT_FROM));
    let (lf, lr, _) = settled(&legacy, 2);
    let (cf, cr, _) = settled(&compact, 2);
    let wrong = owed_of(&legacy, &lr, &lf.to_bytes(Format::Compact));
    assert_eq!(wrong.owed, 0);
    assert!(wrong.ineligible.is_some());
    let wrong = owed_of(&compact, &cr, &cf.to_bytes(Format::Legacy));
    assert_eq!(wrong.owed, 0);
    assert!(wrong.ineligible.is_some());
    let keyset = compact.base.parts().keyset.clone();
    assert!(Filing::from_bytes(
        Format::Legacy,
        &keyset,
        LIMIT,
        &cf.to_bytes(Format::Compact)
    )
    .is_err());
    assert!(Filing::from_bytes(
        Format::Compact,
        &keyset,
        LIMIT,
        &cf.to_bytes(Format::Legacy)
    )
    .is_err());
}

#[test]
fn the_compact_publication_has_one_encoding() {
    let o = open_at(recovery::COMPACT_FROM);
    let keyset = o.base.parts().keyset.clone();
    let (filing, _, ds) = settled(&o, 3);
    let p = filing.publication();
    let bytes = p.to_bytes(Format::Compact);
    assert!(Publication::from_bytes(Format::Compact, &keyset, LIMIT, &bytes).is_ok());
    for n in 0..bytes.len() {
        assert!(Publication::from_bytes(Format::Compact, &keyset, LIMIT, &bytes[..n]).is_err());
    }
    // The records close P: a count, then each a tag, an index, a signature.
    let record = 1 + 1 + 64;
    let head = bytes.len() - 3 * record;
    let with = |records: Vec<Vec<u8>>| {
        let mut changed = bytes[..head].to_vec();
        changed.extend(records.concat());
        Publication::from_bytes(Format::Compact, &keyset, LIMIT, &changed)
    };
    let own: Vec<Vec<u8>> = bytes[head..].chunks(record).map(<[u8]>::to_vec).collect();
    assert!(with(own.clone()).is_ok());
    // An item's record spelled out in full, which has a shorter spelling.
    let mut spelled = own.clone();
    let message = ds
        .iter()
        .map(|d| d.message().clone())
        .find(|m| {
            let index = usize::from(own[0][1]);
            p.claim().parts().items[index].message() == m
        })
        .unwrap();
    let mut full = vec![1];
    full.extend(message.public_fields());
    full.extend(&own[0][2..]);
    spelled[0] = full;
    assert!(with(spelled).is_err());
    // An index past the items, a tag that isn't one, the same item twice.
    let mut past = own.clone();
    past[0][1] = 200;
    assert!(with(past).is_err());
    let mut tag = own.clone();
    tag[0][0] = 2;
    assert!(with(tag).is_err());
    let mut twice = own.clone();
    twice[1][1] = twice[0][1];
    assert!(with(twice).is_err());
    // Legacy's magic isn't compact's.
    let mut old = bytes.clone();
    old[8] = 2;
    assert!(Publication::from_bytes(Format::Compact, &keyset, LIMIT, &old).is_err());
}

#[test]
fn a_compact_filing_names_each_settled_note_once_and_no_other() {
    let o = open_at(recovery::COMPACT_FROM);
    let keyset = o.base.parts().keyset.clone();
    let (filing, _, _) = settled(&o, 3);
    let bytes = filing.to_bytes(Format::Compact);
    for n in 0..bytes.len() {
        assert!(Filing::from_bytes(Format::Compact, &keyset, LIMIT, &bytes[..n]).is_err());
    }
    // The count of notes after P, one short and one over.
    let publication = filing.publication().to_bytes(Format::Compact);
    let at = F_MAGIC_LEN + 4 + publication.len();
    for count in [2u32, 4] {
        let mut changed = bytes.clone();
        changed[at..at + 4].copy_from_slice(&count.to_be_bytes());
        assert!(Filing::from_bytes(Format::Compact, &keyset, LIMIT, &changed).is_err());
    }
    // A note of the issuer's for another message than its item's.
    let mut swapped = bytes.clone();
    let note = filing.witness().notes[0].to_compact_bytes();
    let other = filing.witness().notes[1].to_compact_bytes();
    let first = bytes
        .windows(note.len())
        .position(|w| w == note.as_slice())
        .unwrap();
    swapped[first..first + note.len()].copy_from_slice(&other);
    assert!(Filing::from_bytes(Format::Compact, &keyset, LIMIT, &swapped).is_err());
}

const F_MAGIC_LEN: usize = 9;

/// A v5 Base's funded filing is compact too, under its graph id: its own
/// magic, the same claim owed.
#[test]
fn a_funded_filing_is_compact_under_a_graph_of_the_compact_format() {
    let issuer = IssuerKeys::random(3).unwrap();
    let ds: Vec<_> = (0..4).map(|i| derive(SPEND, &hold(), 4, 24, i)).collect();
    let outputs: Vec<_> = ds
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let o = Opened {
        base: funded_base_at(&issuer, &outputs, 16, recovery::COMPACT_FROM),
        issuer,
    };
    let claimed = [ds[0].clone(), ds[1].clone(), ds[3].clone()];
    let p = Publication::sign(
        claim(
            &o,
            funded_items(&ds, &[0, 1, 3]),
            vec![],
            vec![],
            &claimed,
            12,
        ),
        &hold_keys(&claimed),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount: 12,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: vec![],
        sources: vec![],
        activations: vec![],
        funded: outputs,
    };
    let keyset = o.base.parts().keyset.clone();
    let bytes = Filing::new(p.clone(), witness.clone())
        .unwrap()
        .to_bytes(Format::Compact);
    assert!(bytes.starts_with(b"LICASH-F\x13"));
    let decoded = Filing::from_bytes(Format::Compact, &keyset, LIMIT, &bytes).unwrap();
    assert_eq!(decoded.to_bytes(Format::Compact), bytes);
    assert!(Filing::from_bytes(Format::Legacy, &keyset, LIMIT, &bytes).is_err());
    for n in 0..bytes.len() {
        assert!(Filing::from_bytes(Format::Compact, &keyset, LIMIT, &bytes[..n]).is_err());
    }
    let whole = decide(&o, &request, &p, &witness, &[], None).unwrap();
    assert_eq!((whole.owed, whole.mask, whole.ineligible), (12, 0, None));
}

/// A claim of `count` settled notes of 4 sat, filed under `o`: what the Hub
/// decides it on.
struct Plain {
    request: Request,
    p: Publication,
    witness: Witness,
    notes: Vec<Note>,
    ds: Vec<Derivation>,
}

fn plain(o: &Opened, count: u32) -> Plain {
    let keyset = o.base.parts().keyset.clone();
    let ds: Vec<_> = (0..count)
        .map(|i| derive(SPEND, &hold(), 4, 23, i))
        .collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let items = ds
        .iter()
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let amount = 4 * count;
    let p = Publication::sign(
        claim(o, items, vec![], vec![], &ds, amount),
        &hold_keys(&ds),
        LIMIT,
    )
    .unwrap();
    let request = Request {
        amount,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: notes.clone(),
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    Plain {
        request,
        p,
        witness,
        notes,
        ds,
    }
}

fn lean_open() -> Opened {
    let issuer = IssuerKeys::random(3).unwrap();
    let base = base_at(issuer.keyset().unwrap(), recovery::LEAN_FROM);
    Opened { issuer, base }
}

/// What the Hub proves of a lean claim, which it flags itself
/// ([`recovery::owed`]), is what the statement decides on its flags
/// ([`recovery::owed_flagged`]), and of a claim all valid, what the same
/// claim is owed under the compact filing, whole.
#[test]
fn a_lean_claim_all_valid_is_owed_what_the_compact_filing_is() {
    let lean = lean_open();
    let compact = Opened {
        issuer: lean.issuer.clone(),
        base: base_at(lean.issuer.keyset().unwrap(), recovery::COMPACT_FROM),
    };
    assert_eq!(Format::of(&lean.base), Format::Lean);
    assert_eq!(Format::of(&compact.base), Format::Compact);
    let chain = checkpoint_chain();
    let owed = |o: &Opened| {
        let s = plain(o, 8);
        let owners: Vec<_> = (0..2).map(|i| owner(SPEND, 23, i)).collect();
        let payment = spend(o, &s.notes[..2], &owners, vec![bob(8, 0)]);
        let spent = Evidence::Spend {
            signed: payment,
            notes: s.notes[..2].to_vec(),
            unlock: None,
        };
        let filing = Filing::new(s.p.clone(), s.witness.clone()).unwrap();
        let bytes = filing.to_bytes(Format::of(&o.base));
        let found = recovery::owed(
            &o.base,
            &s.request,
            &bytes,
            std::slice::from_ref(&spent),
            &chain,
        )
        .unwrap();
        let flagged = recovery::owed_flagged(
            &o.base,
            &s.request,
            &bytes,
            std::slice::from_ref(&spent),
            &chain,
            0,
        )
        .unwrap();
        (found, flagged)
    };
    let (found, flagged) = owed(&lean);
    // Two of eight notes spent: six owed, as under the compact filing.
    assert_eq!((found.owed, found.mask, found.invalid), (24, 0b11, 0));
    assert_eq!(found, flagged);
    let (compact_found, _) = owed(&compact);
    assert_eq!(
        (compact_found.owed, compact_found.mask),
        (found.owed, found.mask)
    );
    // Flags are for a lean filing alone, and for items that are there.
    let s = plain(&compact, 2);
    let bytes = Filing::new(s.p, s.witness)
        .unwrap()
        .to_bytes(Format::Compact);
    assert!(recovery::owed_flagged(&compact.base, &s.request, &bytes, &[], &chain, 1).is_err());
}

/// A note the issuer did not sign, or a signature that is not its hold key's,
/// is worth nothing in a lean claim, and the rest of the claim is owed: the
/// Hub flags it, and proves it. Under the compact filing it voids the whole
/// claim. Unflagged, it is taken as valid, which is the Hub's loss alone, and
/// a flag on a valid item is no proof.
#[test]
fn an_invalid_item_of_a_lean_claim_is_worth_nothing_and_the_rest_is_owed() {
    let o = lean_open();
    let chain = checkpoint_chain();
    let s = plain(&o, 4);
    let bytes = Filing::new(s.p.clone(), s.witness.clone())
        .unwrap()
        .to_bytes(Format::Lean);
    let owed = |bytes: &[u8], flags: Option<u32>| match flags {
        None => recovery::owed(&o.base, &s.request, bytes, &[], &chain),
        Some(flags) => recovery::owed_flagged(&o.base, &s.request, bytes, &[], &chain, flags),
    };
    assert_eq!(owed(&bytes, None).unwrap().owed, 16);

    // The second note's proof of issuance forged.
    let tail = s.notes[1].to_compact_bytes();
    let mut bad = tail.clone();
    // C, the evidence's tag, then its DLEQ's e and s: the last byte of s.
    bad[33 + 1 + 63] ^= 1;
    let forged_note = swap(&bytes, &tail, &bad);
    let found = owed(&forged_note, None).unwrap();
    assert_eq!((found.owed, found.invalid, found.mask), (12, 0b10, 0));
    assert!(found.ineligible.is_none());
    // As the statement decides on what the Hub flags.
    assert_eq!(owed(&forged_note, Some(0b10)).unwrap(), found);
    // Unflagged, the note is taken as valid: the whole claim.
    assert_eq!(owed(&forged_note, Some(0)).unwrap().owed, 16);
    // A flag on what is valid, or beyond the claim, is no proof.
    assert!(owed(&forged_note, Some(0b11)).is_err());
    assert!(owed(&forged_note, Some(0b1_0000)).is_err());
    assert!(owed(&bytes, Some(0b1)).is_err());

    // The third item's hold signature not its note's.
    let sig =
        s.p.envelope()
            .records()
            .iter()
            .find(|r| &r.message == s.ds[2].message())
            .unwrap();
    let forged_hold = flip(&bytes, &sig.sig.0);
    let found = owed(&forged_hold, None).unwrap();
    assert_eq!((found.owed, found.invalid), (12, 0b100));
    assert_eq!(owed(&forged_hold, Some(0b100)).unwrap(), found);
    assert_eq!(owed(&forged_hold, Some(0)).unwrap().owed, 16);

    // Both, as the claim of a holder who cannot be trusted with any.
    let both = flip(&forged_note, &sig.sig.0);
    assert_eq!(owed(&both, None).unwrap().owed, 8);

    // Under the compact filing, the same forgery voids the whole claim.
    let compact = Opened {
        issuer: o.issuer.clone(),
        base: base_at(o.issuer.keyset().unwrap(), recovery::COMPACT_FROM),
    };
    let s = plain(&compact, 4);
    let bytes = Filing::new(s.p, s.witness.clone())
        .unwrap()
        .to_bytes(Format::Compact);
    let tail = s.notes[1].to_compact_bytes();
    let mut bad = tail.clone();
    bad[33 + 1 + 63] ^= 1;
    let forged = swap(&bytes, &tail, &bad);
    let whole = recovery::owed(&compact.base, &s.request, &forged, &[], &chain).unwrap();
    assert_eq!(whole.owed, 0);
    assert!(whole.ineligible.is_some());
}

/// Her claim of a contract made again in place of one she made before (a
/// cooperative close's, never published, say): from graph id 12 on, the
/// one before, of the same contract, voids none of her notes; before it,
/// it voids those both hold, as any other claim does. A claim of another
/// contract voids them under either. Graph id 13, which only names the
/// note format v3, is judged as 12.
#[test]
fn a_claim_of_the_same_contract_voids_her_notes_only_before_graph_id_12() {
    assert!(recovery::chained(recovery::BOUND_BASE_FROM));
    let ids = [
        recovery::OWN_CLAIMS_FROM - 1,
        recovery::OWN_CLAIMS_FROM,
        recovery::BOUND_BASE_FROM,
    ];
    for id in ids {
        let o = open_at(id);
        let keyset = o.base.parts().keyset.clone();
        let ds: Vec<_> = (0..2).map(|i| derive(SPEND, &hold(), 4, 23, i)).collect();
        let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
        let items = |ds: &[Derivation]| -> Vec<Item> {
            ds.iter()
                .map(|d| Item::Settled(d.message().clone()))
                .collect()
        };
        let first = Publication::sign(
            claim(&o, items(&ds[..1]), vec![], vec![], &ds[..1], 4),
            &hold_keys(&ds[..1]),
            LIMIT,
        )
        .unwrap();
        let p = Publication::sign(
            claim(&o, items(&ds), vec![], vec![], &ds, 8),
            &hold_keys(&ds),
            LIMIT,
        )
        .unwrap();
        let request = Request {
            amount: 8,
            claim_digest: *p.claim().digest(),
        };
        let witness = Witness {
            notes,
            sources: vec![],
            activations: vec![],
            funded: vec![],
        };
        assert_eq!(
            decide(&o, &request, &p, &witness, &[], None).unwrap().owed,
            8
        );
        let context = *first.envelope().context();
        assert!(context.base == p.envelope().context().base);
        assert!(context.deposit == p.envelope().context().deposit);
        let record = first.envelope().records()[0].clone();
        let own = Evidence::SecondClaim {
            context,
            record: record.clone(),
        };
        let decided = decide(&o, &request, &p, &witness, &[own], None);
        match recovery::own_claims_void(id) {
            true => assert_eq!(decided.unwrap().owed, 4, "{id}"),
            false => assert!(decided.is_err(), "{id}"),
        }
        // Another contract's claim of the same note voids it under both.
        let other = hold::Context {
            base: [1; 32],
            ..context
        };
        let record = hold::Envelope::sign(other, &hold_keys(&ds[..1]), LIMIT)
            .unwrap()
            .records()[0]
            .clone();
        let elsewhere = Evidence::SecondClaim {
            context: other,
            record,
        };
        let decided = decide(&o, &request, &p, &witness, &[elsewhere], None);
        assert_eq!(decided.unwrap().owed, 4, "{id}");
    }
}

/// The Hub reads a lean filing with [`recovery::named`] exactly as its
/// statement does: one item that is not valid, which the strict decoding
/// refuses the whole filing for, leaves it the claim to find its evidence
/// against and the notes she signed for to retire. A hold signature that
/// does not verify retires nothing: its note is not hers to give up.
#[test]
fn the_hub_reads_a_lean_filing_of_an_invalid_item_as_its_statement_does() {
    let o = lean_open();
    let chain = checkpoint_chain();
    let keyset = o.base.parts().keyset.clone();
    let s = plain(&o, 4);
    let bytes = Filing::new(s.p.clone(), s.witness.clone())
        .unwrap()
        .to_bytes(Format::Lean);
    let ys = |named: &recovery::Named| -> Vec<Point> {
        let held = named.held();
        assert!(held.context() == &named.claim().hold_context());
        for record in held.records() {
            let digest = held.context().signing_digest(&record.message);
            crypto::schnorr_verify(record.message.hold(), &digest, &record.sig).unwrap();
        }
        (held.records().iter())
            .map(|r| r.message.identifier().unwrap())
            .collect()
    };
    let all: Vec<Point> = (s.p.envelope().records().iter())
        .map(|r| r.message.identifier().unwrap())
        .collect();

    // All valid: every note, as the strict decoding names them.
    let named = recovery::named(&o.base, &bytes).unwrap();
    assert_eq!(named.claim().digest(), s.p.claim().digest());
    assert_eq!(ys(&named), all);
    let strict = Filing::from_bytes(Format::Lean, &keyset, LIMIT, &bytes).unwrap();
    assert_eq!(
        ys(&named).len(),
        strict.publication().held().records().len()
    );

    // A note never issued, signed for by its hold key: the strict decoding
    // has no filing, the statement a claim owed less, and the Hub that
    // claim, with every note she signed for, the forged one too.
    let tail = s.notes[1].to_compact_bytes();
    let mut bad = tail.clone();
    bad[33 + 1 + 63] ^= 1;
    let forged_note = swap(&bytes, &tail, &bad);
    assert!(Filing::from_bytes(Format::Lean, &keyset, LIMIT, &forged_note).is_err());
    let found = recovery::owed(&o.base, &s.request, &forged_note, &[], &chain).unwrap();
    assert_eq!(
        (found.owed, found.invalid, found.ineligible),
        (12, 0b10, None)
    );
    let named = recovery::named(&o.base, &forged_note).unwrap();
    assert_eq!(named.claim().digest(), s.p.claim().digest());
    assert_eq!(ys(&named), all);

    // A hold signature that is not its note's: that note is not held, the
    // others are.
    let unsigned = s.ds[2].message();
    let sig = (s.p.envelope().records().iter())
        .find(|r| &r.message == unsigned)
        .unwrap();
    let forged_hold = flip(&bytes, &sig.sig.0);
    assert!(Filing::from_bytes(Format::Lean, &keyset, LIMIT, &forged_hold).is_err());
    let named = recovery::named(&o.base, &forged_hold).unwrap();
    let left: Vec<Point> = (all.iter().copied())
        .filter(|y| y != &unsigned.identifier().unwrap())
        .collect();
    assert_eq!(ys(&named), left);
    assert_eq!(left.len(), 3);

    // Whatever byte of the filing is changed, a claim the statement
    // decides on is one the Hub reads.
    let two = plain(&o, 2);
    let small = Filing::new(two.p.clone(), two.witness.clone())
        .unwrap()
        .to_bytes(Format::Lean);
    for at in 0..small.len() {
        let mut changed = small.clone();
        changed[at] ^= 1;
        let owed = recovery::owed(&o.base, &two.request, &changed, &[], &chain).unwrap();
        let named = recovery::named(&o.base, &changed);
        assert!(owed.ineligible.is_some() || named.is_ok(), "byte {at}");
        if let Ok(named) = named {
            ys(&named);
        }
    }

    // Under the compact filing nothing is skipped: the forgery is no
    // filing to either, and a valid one names all its notes.
    let compact = Opened {
        issuer: o.issuer.clone(),
        base: base_at(o.issuer.keyset().unwrap(), recovery::COMPACT_FROM),
    };
    let s = plain(&compact, 4);
    let bytes = Filing::new(s.p.clone(), s.witness.clone())
        .unwrap()
        .to_bytes(Format::Compact);
    let named = recovery::named(&compact.base, &bytes).unwrap();
    assert_eq!(named.held().records().len(), 4);
    let sig = &s.p.envelope().records()[0].sig.0;
    assert!(recovery::named(&compact.base, &flip(&bytes, sig)).is_err());
    let tail = s.notes[1].to_compact_bytes();
    let mut bad = tail.clone();
    bad[33 + 1 + 63] ^= 1;
    assert!(recovery::named(&compact.base, &swap(&bytes, &tail, &bad)).is_err());
}

/// A lean claim of the refund of a lock of her own note that the Hub never
/// served, that note's hold signature not its key's: the statement verifies
/// no hold signature of a lock's inputs, so the refund is owed and no flag
/// says otherwise. The Hub reads the lock itself in her filing, signed by
/// the note's owner, and it is evidence of the note spent against any
/// claim of it: the note is not paid for twice, nor left hers to spend.
#[test]
fn a_lock_a_lean_filing_shows_voids_any_other_claim_of_its_inputs() {
    let issuer = IssuerKeys::random(3).unwrap();
    let o = Opened {
        base: base_at(issuer.keyset().unwrap(), recovery::LEAN_FROM),
        issuer,
    };
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    // Seven blocks: the lock expired at 4, 3 deep at 7.
    let (chain, _) = activated_chain_at(1);
    let own = derive(SPEND, &hold, 4, 23, 40);
    let own_note = mint(&o.issuer, &keyset, &own);
    let refund = derive(SPEND, &hold, 4, 67, 0);
    let carol = derive(53, &HoldRoot::from_seed(&[11; 32]).unwrap(), 4, 31, 0);
    let lock = TimedLock::new(terms(), vec![Output::from_derivation(&refund).unwrap()]).unwrap();
    let body = Proposal::new(
        &keyset,
        std::slice::from_ref(&own_note),
        point(47),
        vec![Output::from_derivation(&carol).unwrap()],
        Some(lock),
    )
    .unwrap();
    let own_signed = SignedProposal::sign(
        &keyset,
        body,
        std::slice::from_ref(&own_note),
        Authorization::Plain,
        &[owner(SPEND, 23, 40)],
    )
    .unwrap();
    let own_id = own_signed.proposal().id();
    let owner_sig = own_signed.signatures()[0].0;
    let settled = derive(SPEND, &hold, 4, 23, 0);
    let settled_note = mint(&o.issuer, &keyset, &settled);
    // The claim of a settled note and of the lock's refund as the note of
    // `refunded`, filed.
    let file = |refunded: &Derivation| {
        let items = vec![
            Item::Settled(settled.message().clone()),
            Item::Pending {
                message: refunded.message().clone(),
                source: own_id,
                branch: Branch::Refund,
                index: 0,
                blinding: *refunded.blinding(),
                preimage: None,
            },
        ];
        let sources = vec![Source::OwnInputs {
            id: own_id,
            inputs: vec![own_note.message().identifier().unwrap()],
            terms: terms(),
        }];
        let signers = [settled.clone(), refunded.clone(), own.clone()];
        let unsigned = claim(&o, items, sources, vec![], &signers, 8);
        let p = Publication::sign(unsigned, &hold_keys(&signers), LIMIT).unwrap();
        let witness = Witness {
            notes: vec![settled_note.clone()],
            sources: vec![SourceWitness::Signed {
                signed: own_signed.clone(),
                notes: vec![own_note.clone()],
            }],
            activations: vec![],
            funded: vec![],
        };
        let bytes = Filing::new(p.clone(), witness)
            .unwrap()
            .to_bytes(Format::Lean);
        (p, bytes)
    };
    let sig_of = |p: &Publication, d: &Derivation| {
        let record = (p.envelope().records().iter()).find(|r| &r.message == d.message());
        record.unwrap().sig.0
    };
    let (p, bytes) = file(&refund);
    let request = Request {
        amount: 8,
        claim_digest: *p.claim().digest(),
    };
    let y = own.message().identifier().unwrap();
    let held = |named: &recovery::Named| -> Vec<Point> {
        (named.held().records().iter())
            .map(|r| r.message.identifier().unwrap())
            .collect()
    };

    // Signed for by all three, as a wallet files it: all held, and no
    // lock to show for an input, each given up by its hold key.
    let named = recovery::named(&o.base, &bytes).unwrap();
    assert_eq!(held(&named).len(), 3);
    assert!(named.locks().is_empty());

    // The input's hold signature forged: the statement owes the refund all
    // the same, and takes no flag against it.
    let forged = flip(&bytes, &sig_of(&p, &own));
    let found = recovery::owed(&o.base, &request, &forged, &[], &chain).unwrap();
    assert_eq!((found.owed, found.invalid, found.ineligible), (8, 0, None));
    for flags in [0b01, 0b10, 0b11] {
        assert!(recovery::owed_flagged(&o.base, &request, &forged, &[], &chain, flags).is_err());
    }
    // The Hub does not hold the input by its hold key, and holds it by the
    // lock, which its owner signed.
    let named = recovery::named(&o.base, &forged).unwrap();
    assert!(!held(&named).contains(&y));
    assert_eq!(held(&named).len(), 2);
    let [lock] = named.locks() else {
        panic!("the lock her filing shows")
    };
    assert!(recovery::voids_note(&keyset, own.message(), lock).unwrap());
    // Against this claim itself it voids nothing: its refund is owed once.
    assert!(recovery::owed(
        &o.base,
        &request,
        &forged,
        std::slice::from_ref(lock),
        &chain
    )
    .is_err());

    // Her claim of the same note in another contract, settled: the lock
    // voids it, through the codec the Hub pins its evidence with.
    let other = Opened {
        issuer: o.issuer.clone(),
        base: base_at(keyset.clone(), recovery::OWN_CLAIMS_FROM),
    };
    let twice = [settled.clone(), own.clone()];
    let items = (twice.iter())
        .map(|d| Item::Settled(d.message().clone()))
        .collect();
    let again = Publication::sign(
        claim(&other, items, vec![], vec![], &twice, 8),
        &hold_keys(&twice),
        LIMIT,
    )
    .unwrap();
    let again_request = Request {
        amount: 8,
        claim_digest: *again.claim().digest(),
    };
    let again_witness = Witness {
        notes: twice.iter().map(|d| mint(&o.issuer, &keyset, d)).collect(),
        sources: vec![],
        activations: vec![],
        funded: vec![],
    };
    let cited =
        recovery::evidence_from_bytes(&keyset, LIMIT, &recovery::evidence_to_bytes(named.locks()))
            .unwrap();
    let whole = decide(&other, &again_request, &again, &again_witness, &[], None).unwrap();
    assert_eq!(whole.owed, 8);
    let less = decide(&other, &again_request, &again, &again_witness, &cited, None).unwrap();
    let at = (again.claim().parts().items.iter())
        .position(|i| i.message() == own.message())
        .unwrap();
    assert_eq!((less.owed, less.mask), (4, 1 << at));

    // The refund not signed for either: an item not valid, worth nothing,
    // and no refund of hers that would give the lock's input up.
    let unheld = flip(&forged, &sig_of(&p, &refund));
    let found = recovery::owed(&o.base, &request, &unheld, &[], &chain).unwrap();
    assert_eq!(
        (found.owed, found.invalid, found.ineligible),
        (4, 0b10, None)
    );
    let named = recovery::named(&o.base, &unheld).unwrap();
    assert_eq!(held(&named).len(), 1);
    assert!(named.locks().is_empty());

    // Who holds the lock and is not its refund's, as its payee: she names
    // a note of her own as the refund, signs for it, and cannot sign for
    // the input. It opens no output of the lock, her claim is owed
    // nothing, and the lock shown gives up no note of its payer's.
    let hers = derive(SPEND, &hold, 4, 71, 0);
    let (theirs, bytes_of_theirs) = file(&hers);
    let grief = flip(&bytes_of_theirs, &sig_of(&theirs, &own));
    let theirs_request = Request {
        amount: 8,
        claim_digest: *theirs.claim().digest(),
    };
    let found = recovery::owed(&o.base, &theirs_request, &grief, &[], &chain).unwrap();
    assert!(found.owed == 0 && found.ineligible.is_some());
    let named = recovery::named(&o.base, &grief).unwrap();
    assert_eq!(held(&named).len(), 2);
    assert!(named.locks().is_empty());

    // A lock of a note never issued is no filing either: its outputs
    // stand on nothing.
    let tail = own_note.to_compact_bytes();
    let mut bad = tail.clone();
    bad[33 + 1 + 63] ^= 1;
    let unissued = swap(&forged, &tail, &bad);
    assert!(recovery::named(&o.base, &unissued).is_err());
    let none = recovery::owed(&o.base, &request, &unissued, &[], &chain).unwrap();
    assert!(none.owed == 0 && none.ineligible.is_some());

    // A lock its inputs' owners did not sign is no filing, to the Hub as
    // to its statement: who names a note signs nothing for its owner.
    let unsigned = flip(&forged, &owner_sig);
    assert!(recovery::named(&o.base, &unsigned).is_err());
    let none = recovery::owed(&o.base, &request, &unsigned, &[], &chain).unwrap();
    assert!(none.owed == 0 && none.ineligible.is_some());
}

/// Every spend a proposal may be is evidence every Base's statement reads:
/// the most inputs and outputs, granted, decode under the fewest notes a
/// Base admits, and a proposal of one more input or output is none. A hub
/// retiring the notes of a spend its statement cannot read would answer
/// nothing to a claim of one, and her timeout pay her for it.
#[test]
fn the_largest_spend_a_proposal_may_be_is_evidence_under_every_base() {
    use licash::spend::{MAX_INPUTS, MAX_OUTPUTS};
    let o = open_with(7);
    let keyset = o.base.parts().keyset.clone();
    let ds: Vec<_> = (0..MAX_INPUTS as u32)
        .map(|i| derive(SPEND, &hold(), 2, 23, i))
        .collect();
    let notes: Vec<_> = ds.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let owners: Vec<_> = (0..MAX_INPUTS as u32)
        .map(|i| owner(SPEND, 23, i))
        .collect();
    let to = |n: usize| (0..n as u32).map(|i| bob(1, i)).collect::<Vec<_>>();
    let proposal = Proposal::new(&keyset, &notes, point(43), to(MAX_OUTPUTS), None).unwrap();
    let prepared = PreparedGrant::new(&o.issuer, &proposal).unwrap();
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes,
        Authorization::Granted(Box::new(prepared.offer())),
        &owners,
    )
    .unwrap();
    assert!(signed.to_bytes().len() <= recovery::MAX_PUBLICATION_BYTES);
    let unlock = prepared.release(&keyset, &notes, &signed).unwrap();
    let evidence = [Evidence::Spend {
        signed,
        notes: notes.clone(),
        unlock: Some(unlock),
    }];
    let least = licash::base::MIN_AUTHORIZATIONS as usize;
    let read = evidence_from_bytes(&keyset, least, &evidence_to_bytes(&evidence)).unwrap();
    assert_eq!(read.len(), 1);

    // One more output, or one more input, is no proposal.
    assert!(Proposal::new(&keyset, &notes, point(43), to(MAX_OUTPUTS + 1), None).is_err());
    let mut more = notes.clone();
    more.push(mint(&o.issuer, &keyset, &derive(SPEND, &hold(), 2, 23, 99)));
    let balanced: Vec<_> = (0..more.len() as u32).map(|i| bob(2, i)).collect();
    assert!(Proposal::new(&keyset, &more, point(43), balanced.clone(), None).is_err());
    assert!(Proposal::new(&keyset, &more[1..], point(43), balanced[1..].to_vec(), None).is_ok());
    // Nor a lock of one more refund output.
    let refund = TimedLock::new(terms(), to(MAX_OUTPUTS + 1));
    assert!(refund.is_err());
    assert!(TimedLock::new(terms(), to(MAX_OUTPUTS)).is_ok());
}

/// A spend cited by the signatures of the inputs a claim relies on decides
/// exactly as the spend whole, and costs what the claim names: the Hub's
/// way to cite ([`recovery::cite`]).
#[test]
fn a_spend_cited_by_its_signatures_decides_as_the_spend_whole() {
    let o = open();
    let keyset = o.base.parts().keyset.clone();
    let hold = hold();
    // Alice paid Bob 4 of her two notes, keeping a change of 4; her third
    // note she spent with a stranger's 15 others, the Hub says.
    let a: Vec<_> = (0..3).map(|i| derive(SPEND, &hold, 4, 23, i)).collect();
    let notes: Vec<_> = a.iter().map(|d| mint(&o.issuer, &keyset, d)).collect();
    let change = derive(SPEND, &hold, 4, 71, 0);
    let paid = spend(
        &o,
        &notes[..2],
        &[owner(SPEND, 23, 0), owner(SPEND, 23, 1)],
        vec![bob(4, 0), Output::from_derivation(&change).unwrap()],
    );
    let id = paid.proposal().id();
    let strangers: Vec<_> = (0..15).map(|i| derive(SPEND, &hold, 4, 37, i)).collect();
    let mut mixed_notes: Vec<_> = strangers
        .iter()
        .map(|d| mint(&o.issuer, &keyset, d))
        .collect();
    mixed_notes.insert(9, notes[2].clone());
    let mut owners: Vec<_> = (0..15).map(|i| owner(SPEND, 37, i)).collect();
    owners.insert(9, owner(SPEND, 23, 2));
    let mixed = spend(
        &o,
        &mixed_notes,
        &owners,
        (0..16).map(|i| bob(4, 10 + i)).collect(),
    );
    let items = vec![
        Item::Settled(a[0].message().clone()),
        Item::Settled(a[1].message().clone()),
        Item::Settled(a[2].message().clone()),
        Item::Pending {
            message: change.message().clone(),
            source: id,
            branch: Branch::Pay,
            index: 1,
            blinding: *change.blinding(),
            preimage: None,
        },
    ];
    let mut inputs: Vec<_> = (notes[..2].iter())
        .map(|n| n.message().identifier().unwrap())
        .collect();
    inputs.sort_unstable();
    let sources = vec![Source::Plain { id, inputs }];
    let held: Vec<_> = a.iter().cloned().chain([change.clone()]).collect();
    let unsigned = claim(&o, items, sources, vec![], &held, 12);
    let p = Publication::sign(unsigned.clone(), &hold_keys(&held), LIMIT).unwrap();
    let request = Request {
        amount: 12,
        claim_digest: *p.claim().digest(),
    };
    let witness = Witness {
        notes: notes.clone(),
        sources: vec![SourceWitness::Signed {
            signed: paid.clone(),
            notes: notes[..2].to_vec(),
        }],
        activations: vec![],
        funded: vec![],
    };
    let owed = |e: &[Evidence]| decide(&o, &request, &p, &witness, e, None);
    let whole = |signed: &SignedProposal, notes: &[Note]| Evidence::Spend {
        signed: signed.clone(),
        notes: notes.to_vec(),
        unlock: None,
    };
    let relied = |e: &Evidence| match e {
        Evidence::Signed { signers, grant, .. } => {
            assert!(grant.is_none());
            signers.iter().map(|(i, _)| *i).collect::<Vec<_>>()
        }
        _ => panic!("cited by its signatures"),
    };

    // The mixed spend: the one input of Alice's, whatever else it took.
    let spent = whole(&mixed, &mixed_notes);
    let cited = recovery::cite(&unsigned, spent.clone()).unwrap();
    assert_eq!(relied(&cited), [9]);
    let (by_whole, by_sig) = (
        owed(std::slice::from_ref(&spent)).unwrap(),
        owed(std::slice::from_ref(&cited)).unwrap(),
    );
    assert_eq!((by_sig.mask, by_sig.owed), (0b0100, 8));
    assert_eq!((by_whole.mask, by_whole.owed), (by_sig.mask, by_sig.owed));
    let bytes = evidence_to_bytes(std::slice::from_ref(&cited));
    assert!(bytes.len() * 3 < evidence_to_bytes(std::slice::from_ref(&spent)).len());
    let read = evidence_from_bytes(&keyset, LIMIT, &bytes).unwrap();
    assert_eq!(evidence_to_bytes(&read), bytes);
    assert_eq!(owed(&read).unwrap().mask, 0b0100);

    // Her own payment, a Plain source she names: executed whole, so every
    // input of it is relied on, and its change is owed by fallback.
    let executed = recovery::cite(&unsigned, whole(&paid, &notes[..2])).unwrap();
    assert_eq!(relied(&executed), [0, 1]);
    let c = owed(std::slice::from_ref(&executed)).unwrap();
    assert_eq!((c.mask, c.owed), {
        let w = owed(&[whole(&paid, &notes[..2])]).unwrap();
        (w.mask, w.owed)
    });
    assert_eq!(c.mask, 0b0011);
    // By a part of its inputs it executes nothing: refused.
    let part = recovery::by_signature(&paid, None, &[0].into()).unwrap();
    assert!(owed(&[part]).is_err());

    // A spend of nothing she names keeps one signature, and voids nothing.
    let elsewhere = spend(&o, &mixed_notes[..1], &owners[..1], vec![bob(4, 40)]);
    let unrelated = recovery::cite(&unsigned, whole(&elsewhere, &mixed_notes[..1])).unwrap();
    assert_eq!(relied(&unrelated), [0]);
    assert!(owed(&[unrelated]).is_err());

    // Evidence the statement refuses, however it is framed.
    let Evidence::Signed { body, signers, .. } = &cited else {
        unreachable!()
    };
    let refused = |body: Vec<u8>, signers: Vec<(u32, crypto::Signature)>, grant| {
        owed(&[Evidence::Signed {
            body,
            signers,
            grant,
        }])
    };
    // No signature, a signature moved to another input, or signers out of
    // order or repeated.
    assert!(refused(body.clone(), vec![], None).is_err());
    assert!(refused(body.clone(), vec![(8, signers[0].1)], None).is_err());
    let two = recovery::by_signature(&mixed, None, &[3, 9].into()).unwrap();
    let Evidence::Signed { signers: both, .. } = &two else {
        unreachable!()
    };
    assert_eq!(owed(std::slice::from_ref(&two)).unwrap().mask, 0b0100);
    assert!(refused(body.clone(), vec![both[1], both[0]], None).is_err());
    assert!(refused(body.clone(), vec![both[1], both[1]], None).is_err());
    // An input index the body has not.
    assert!(refused(body.clone(), vec![(16, signers[0].1)], None).is_err());
    // A body changed anywhere is another spend, which she did not sign;
    // one of another keyset or framing is not read.
    for at in [0, 20, body.len() / 2, body.len() - 1] {
        let mut changed = body.clone();
        changed[at] ^= 1;
        assert!(
            refused(changed, signers.clone(), None).is_err(),
            "byte {at}"
        );
    }
    let mut long = body.clone();
    long.resize(licash::spend::MAX_BODY_BYTES + 1, 0);
    assert!(refused(long, signers.clone(), None).is_err());
    // A plain spend cited with an unlock is a granted one she never signed.
    let head = licash::authorization::GrantHead {
        unlock_key: point(5),
        rest: [0; 32],
    };
    let five = crypto::ScalarBytes::from_scalar(&Scalar::from(5u64)).0;
    assert!(refused(body.clone(), signers.clone(), Some((head, five))).is_err());
    assert!(recovery::by_signature(&mixed, Some(five), &[9].into()).is_err());
}

/// A granted spend cited by its signatures voids under its released unlock
/// alone, and discloses it: one equation, whatever its packets.
#[test]
fn a_granted_spend_cited_by_its_signatures_voids_only_with_its_unlock() {
    let w = withheld();
    let keyset = w.o.base.parts().keyset.clone();
    let owed = |e: &[Evidence]| decide(&w.o, &w.request, &w.publication, &w.witness, e, None);
    let spend = |unlock| Evidence::Spend {
        signed: w.signed.clone(),
        notes: vec![w.note.clone()],
        unlock,
    };
    let cited = recovery::cite(w.publication.claim(), spend(Some(w.unlock))).unwrap();
    let Evidence::Signed {
        body,
        signers,
        grant: Some((head, unlock)),
    } = &cited
    else {
        panic!("cited by its signatures, with its grant");
    };
    assert_eq!(*unlock, w.unlock);
    let c = owed(std::slice::from_ref(&cited)).unwrap();
    assert_eq!((c.mask, c.owed), (1, 78));
    let posted = disclosures(std::slice::from_ref(&cited)).unwrap();
    assert_eq!(posted, disclosures(&[spend(Some(w.unlock))]).unwrap());
    assert_eq!(c.disclosures, posted);
    let bytes = evidence_to_bytes(std::slice::from_ref(&cited));
    assert_eq!(
        evidence_to_bytes(&evidence_from_bytes(&keyset, LIMIT, &bytes).unwrap()),
        bytes
    );
    // Without its unlock it is no evidence, nor with another, nor as plain.
    assert!(recovery::cite(w.publication.claim(), spend(None)).is_err());
    let with = |grant| {
        owed(&[Evidence::Signed {
            body: body.clone(),
            signers: signers.clone(),
            grant,
        }])
    };
    assert!(with(None).is_err());
    let other = crypto::ScalarBytes::from_scalar(&Scalar::from(5u64)).0;
    assert!(with(Some((*head, other))).is_err());
    assert!(with(Some((*head, [0; 32]))).is_err());
    // Nor under another head: what the owners signed is the grant's.
    let mut forged = *head;
    forged.rest[0] ^= 1;
    assert!(with(Some((forged, *unlock))).is_err());
    let rekeyed = licash::authorization::GrantHead {
        unlock_key: point(5),
        rest: head.rest,
    };
    assert!(with(Some((rekeyed, other))).is_err());
    // Two unlocks cited of one spend: refused, so that none is kept back.
    let twice = [
        cited.clone(),
        Evidence::Signed {
            body: body.clone(),
            signers: signers.clone(),
            grant: Some((*head, other)),
        },
    ];
    assert!(disclosures(&twice).is_err());
    assert!(disclosures(&[cited.clone(), cited.clone()]).is_ok());
    // Nor with a preimage of the same source.
    let preimage = Evidence::PayPreimage {
        source: w.signed.proposal().id(),
        preimage: [5; 32],
    };
    assert!(disclosures(&[cited, preimage]).is_err());
}

/// Each note a spend is read with is verified once, with the spend, and
/// still verified: evidence or a filing of a note whose issuance does not
/// verify is no evidence and no filing. A spend made or read verified is
/// not verified again where it is relied on, only matched to the keyset
/// and the notes it is relied on with.
#[test]
fn notes_read_with_a_spend_are_verified_once_and_still_verified() {
    let w = withheld();
    let keyset = w.o.base.parts().keyset.clone();
    let spend = Evidence::Spend {
        signed: w.signed.clone(),
        notes: vec![w.note.clone()],
        unlock: Some(w.unlock),
    };
    let bytes = evidence_to_bytes(std::slice::from_ref(&spend));
    evidence_from_bytes(&keyset, LIMIT, &bytes).unwrap();
    // Any byte of the note changed so that it is no note of the keyset,
    // though it decodes, makes the evidence none: as it did when the note
    // was verified twice.
    let note = w.note.to_bytes();
    let at = (0..bytes.len() - note.len())
        .find(|&i| bytes[i..i + note.len()] == note[..])
        .unwrap();
    let mut forged = None;
    for i in 0..note.len() {
        let mut candidate = note.clone();
        candidate[i] ^= 1;
        let mut changed = bytes.clone();
        changed[at..at + note.len()].copy_from_slice(&candidate);
        if licash::note::Note::from_bytes(&keyset, &candidate).is_err() {
            assert!(
                evidence_from_bytes(&keyset, LIMIT, &changed).is_err(),
                "byte {i}"
            );
            if licash::note::Note::peek(&candidate).is_ok() {
                forged.get_or_insert(candidate);
            }
        }
    }
    let forged = forged.expect("a note that decodes and does not verify");
    // Relied on, a spend is matched to its keyset and notes.
    assert_eq!(
        w.signed
            .inputs_of(&keyset, std::slice::from_ref(&w.note))
            .unwrap(),
        vec![w.note.message().identifier().unwrap()]
    );
    let other = IssuerKeys::random(7).unwrap().keyset().unwrap();
    assert!(w
        .signed
        .inputs_of(&other, std::slice::from_ref(&w.note))
        .is_err());
    assert!(w.signed.inputs_of(&keyset, &[]).is_err());
    let stranger = mint(&w.o.issuer, &keyset, &derive(SPEND, &hold(), 128, 23, 1));
    assert!(w.signed.inputs_of(&keyset, &[stranger]).is_err());
    let filing = Filing::new(w.publication.clone(), w.witness.clone())
        .unwrap()
        .to_bytes(Format::of(&w.o.base));
    assert_eq!(
        decide(&w.o, &w.request, &w.publication, &w.witness, &[], None)
            .unwrap()
            .owed,
        128
    );
    let at = (0..filing.len() - note.len())
        .rev()
        .find(|&i| filing[i..i + note.len()] == note[..])
        .unwrap();
    let mut changed = filing.clone();
    changed[at..at + note.len()].copy_from_slice(&forged);
    let chain = checkpoint_chain();
    let read = recovery::owed(&w.o.base, &w.request, &changed, &[], &chain);
    assert!(
        read.as_ref().map_or(true, |o| o.owed == 0),
        "{:?}",
        read.map(|o| (o.owed, o.mask, o.ineligible))
    );
}
