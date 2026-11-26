use licash::{
    address::{Ephemeral, OwnerKeys},
    authorization::{Authorization, PreparedGrant, SignedProposal},
    claim::Branch,
    crypto::{schnorr_sign, tagged_hash, Signature},
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    source::Certificate,
    spend::{lock_hash, ChainProfile, Output, Proposal, ProposalId, TimedLock, TimedTerms},
    unlink::{Nonce, Session},
};
use licash_api::{
    rate, Code, ContractRange, Contracts, Fee, Fees, Hex, Info, Inquire, Inquired, Issued, Lock,
    LockState, Locked, Offer, Offered, Payment, Problem, Refund, Release, Released, Settle,
    Settled, Unlink, Unlinked,
};
use serde::{de::DeserializeOwned, Serialize};

fn json<T: Serialize + DeserializeOwned>(value: &T) -> T {
    serde_json::from_str(&serde_json::to_string(value).unwrap()).unwrap()
}

struct Fixture {
    keys: IssuerKeys,
    keyset: Keyset,
    owner: OwnerKeys,
    input: (Note, Derivation),
    proposal: Proposal,
    outputs: Vec<Derivation>,
}

fn note(keys: &IssuerKeys, keyset: &Keyset, d: &Derivation) -> Note {
    let output = Output::from_derivation(d).unwrap();
    let proof = keys
        .prove_blinded(d.message().denomination(), output.blinded())
        .unwrap();
    Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: Nonce::new(keyset, &output).unwrap().commit().unwrap(),
        },
    )
    .unwrap()
}

fn fixture() -> Fixture {
    let keys = IssuerKeys::random(3).unwrap();
    let keyset = keys.keyset().unwrap();
    let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let d = Ephemeral::random()
        .derive(&owner.address(), 8, Branch::Pay, 0)
        .unwrap();
    let input = (note(&keys, &keyset, &d), d);
    let e = Ephemeral::random();
    let outputs: Vec<_> = (0..2)
        .map(|i| e.derive(&owner.address(), 4, Branch::Pay, i).unwrap())
        .collect();
    let proposal = Proposal::new(
        &keyset,
        std::slice::from_ref(&input.0),
        e.public(),
        outputs
            .iter()
            .map(|d| Output::from_derivation(d).unwrap())
            .collect(),
        None,
    )
    .unwrap();
    Fixture {
        keys,
        keyset,
        owner,
        input,
        proposal,
        outputs,
    }
}

#[test]
fn bodies_carry_the_canonical_bytes_through_json() {
    let f = fixture();
    let lookup = |id: &[u8; 32]| (id == f.keyset.id()).then_some(&f.keyset);
    let notes = vec![f.input.0.clone()];

    let fees = Fees {
        spend: Fee { base: 1, ppm: 2 },
        ..Fees::default()
    };
    let info = json(&Info::new(
        std::slice::from_ref(&f.keyset),
        f.owner.address(),
        fees,
        None,
    ));
    assert_eq!(info.keysets().unwrap(), vec![f.keyset.clone()]);
    assert_eq!(info.address, f.owner.address());
    assert_eq!(info.fees, fees);

    let offer = json(&Offer::new(&f.proposal, &notes));
    let (proposal, decoded) = offer.decode(lookup).unwrap();
    assert_eq!(proposal.id(), f.proposal.id());
    assert_eq!(decoded, notes);
    assert_eq!(offer.holds().unwrap(), None);
    assert!(!serde_json::to_string(&offer).unwrap().contains("holds"));
    // Signed by its notes' owner: one signature each, kept as made.
    let holds = vec![licash::crypto::Signature([5; 64])];
    let held = json(&Offer::held(&f.proposal, &notes, &holds));
    assert_eq!(held.holds().unwrap(), Some(holds));
    let mut short = held.clone();
    short.holds.as_mut().unwrap()[0].0.pop();
    assert_eq!(short.holds().unwrap_err().code, Code::Invalid);
    let mut more = held.clone();
    more.holds.as_mut().unwrap().push(Hex(vec![0; 64]));
    assert_eq!(more.holds().unwrap_err().code, Code::Invalid);

    let prepared = PreparedGrant::new(&f.keys, &f.proposal).unwrap();
    let grant = prepared.offer();
    assert_eq!(
        json(&Offered::new(&grant).unwrap()).decode().unwrap(),
        grant
    );

    let secret = f
        .input
        .1
        .ownership()
        .owner_secret(f.owner.spend_secret())
        .unwrap();
    let signed = SignedProposal::sign(
        &f.keyset,
        f.proposal.clone(),
        &notes,
        Authorization::Granted(Box::new(grant)),
        &[secret],
    )
    .unwrap();
    let (back, decoded) = json(&Release::new(&signed, &notes)).decode(lookup).unwrap();
    assert_eq!(back.to_bytes(), signed.to_bytes());
    assert_eq!(decoded, notes);
    let unlock = prepared.release(&f.keyset, &notes, &signed).unwrap();
    assert_eq!(json(&Released::new(&unlock)).decode().unwrap(), unlock);

    // The payee's view of it.
    let payment = json(&Payment::new(
        "http://hub.example",
        &signed,
        &notes,
        &unlock,
    ));
    assert_eq!(payment.hub, "http://hub.example");
    let (paid, paid_notes, paid_unlock) = payment.decode(lookup).unwrap();
    assert_eq!(paid.to_bytes(), signed.to_bytes());
    assert_eq!((paid_notes, paid_unlock), (notes.clone(), unlock));
    let mut wrong = payment.clone();
    wrong.unlock = Hex(vec![0; 32]);
    assert_eq!(wrong.decode(lookup).unwrap_err().code, Code::Invalid);
    let none = |_: &[u8; 32]| None;
    assert_eq!(payment.decode(none).unwrap_err().code, Code::UnknownKeyset);
    let fields = serde_json::to_value(&payment).unwrap();
    let mut keys: Vec<_> = fields.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["hub", "keyset", "notes", "signed", "unlock"]);

    let paid = signed
        .open_granted_output(&f.keyset, &notes, 0, &f.outputs[0], &unlock)
        .unwrap();
    let session = Session::start(&f.keyset, &paid, &f.outputs[0]).unwrap();
    let request = json(&Unlink::new(session.request())).decode().unwrap();
    assert_eq!(&request, session.request());
    let nonce = prepared.unlink_nonces().remove(0);
    let answer = nonce.answer(&f.keys, &request).unwrap().answer();
    let answer = json(&Unlinked::new(&answer)).decode().unwrap();
    session.finish(&f.keyset, &answer).unwrap();

    let note = f.input.0.message().clone();
    let signature = Signature([3; 64]);
    let asked = json(&Inquire::new(
        &[1; 32],
        1_700_000_000,
        &[(note.clone(), signature)],
    ));
    let (keyset, at, notes) = asked.decode().unwrap();
    assert_eq!((keyset, at), ([1; 32], 1_700_000_000));
    assert!(notes == vec![(note, signature)]);
}

#[test]
fn an_inquiry_asks_of_whole_notes_and_a_bounded_number() {
    let f = fixture();
    let ask = |notes: usize, signature: usize| Inquire {
        keyset: Hex(vec![1; 32]),
        at: 1,
        notes: vec![
            Inquired {
                note: Hex(f.input.0.message().to_bytes().to_vec()),
                signature: Hex(vec![2; signature]),
            };
            notes
        ],
    };
    let most = licash::inquiry::MAX_NOTES;
    assert_eq!(ask(most, 64).decode().unwrap().2.len(), most);
    for refused in [ask(most + 1, 64), ask(1, 63)] {
        assert_eq!(refused.decode().err().map(|p| p.code), Some(Code::Invalid));
    }
}

#[test]
fn malformed_and_foreign_bodies_are_problems() {
    let f = fixture();
    let notes = vec![f.input.0.clone()];
    let none = |_: &[u8; 32]| None;
    assert_eq!(
        Offer::new(&f.proposal, &notes)
            .decode(none)
            .unwrap_err()
            .code,
        Code::UnknownKeyset
    );
    let lookup = |id: &[u8; 32]| (id == f.keyset.id()).then_some(&f.keyset);
    let mut offer = Offer::new(&f.proposal, &notes);
    offer.proposal.0.pop();
    assert_eq!(offer.decode(lookup).unwrap_err().code, Code::Invalid);
    let mut offer = Offer::new(&f.proposal, &notes);
    offer.notes[0].0[20] ^= 1;
    assert_eq!(offer.decode(lookup).unwrap_err().code, Code::Invalid);
    assert!(serde_json::from_str::<Unlink>(r#"{"request":"0g"}"#).is_err());
    assert!(serde_json::from_str::<Unlink>(r#"{"request":7}"#).is_err());
    let short = Released {
        unlock: Hex(vec![0; 31]),
    };
    assert_eq!(short.decode().unwrap_err().code, Code::Invalid);
    let release = Release {
        keyset: Hex(vec![0; 31]),
        signed: Hex(vec![]),
        notes: vec![],
    };
    assert_eq!(release.decode(lookup).unwrap_err().code, Code::Invalid);
    let unlinked = Unlinked {
        answer: Hex(vec![0xff; 32]),
    };
    assert_eq!(unlinked.decode().unwrap_err().code, Code::Invalid);
}

#[test]
fn problems_and_their_statuses_are_the_wire_contract() {
    let problem = Problem::new(Code::Spent, "an input is already spent");
    assert_eq!(
        serde_json::to_string(&problem).unwrap(),
        r#"{"code":"spent","message":"an input is already spent"}"#
    );
    assert_eq!(json(&problem), problem);
    for (code, name, status) in [
        (Code::Invalid, "invalid", 400),
        (Code::UnknownKeyset, "unknown_keyset", 404),
        (Code::UnknownOffer, "unknown_offer", 404),
        (Code::NotIssued, "not_issued", 404),
        (Code::Timed, "timed", 409),
        (Code::Spent, "spent", 409),
        (Code::Reissued, "reissued", 409),
        (Code::Fee, "fee", 409),
        (Code::Unlinked, "unlinked", 409),
        (Code::Expired, "expired", 409),
        (Code::UnknownLock, "unknown_lock", 404),
        (Code::NotALock, "not_a_lock", 409),
        (Code::Checkpoint, "checkpoint", 409),
        (Code::Timing, "timing", 409),
        (Code::Preimage, "preimage", 409),
        (Code::Settled, "settled", 409),
        (Code::LockExpired, "lock_expired", 409),
        (Code::Unexpired, "unexpired", 409),
        (Code::Activated, "activated", 409),
        (Code::Unavailable, "unavailable", 503),
        (Code::Forward, "forward", 409),
        (Code::Declined, "declined", 409),
    ] {
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{name}\""));
        assert_eq!(code.status(), status);
    }
    assert_eq!(licash_api::OFFER, "/v1/offer");
    let id = ProposalId::from_bytes([0xab; 32]);
    let path = licash_api::lock_state(&id);
    assert_eq!(path, format!("/v1/lock/{}", "ab".repeat(32)));
    assert_eq!(licash_api::lock_id(&path[9..]).unwrap(), id);
    assert_eq!(licash_api::lock_id("ab").unwrap_err().code, Code::Invalid);
    assert_eq!(licash_api::lock_id("zz").unwrap_err().code, Code::Invalid);
    // Info and fees of a hub that predates locks.
    let fees: Fees = serde_json::from_str(r#"{"spend":{"base":1,"ppm":0}}"#).unwrap();
    assert_eq!((fees.lock, fees.refund), (Fee::default(), Fee::default()));
    assert_eq!(format!("{:?}", Hex(vec![1, 2])), "Hex(2 bytes)");
}

#[test]
fn fees_compare_and_combine_each_with_its_like() {
    let fee = |base, ppm| Fee { base, ppm };
    let agreed = Fees {
        spend: fee(1, 100),
        lock: fee(1, 100),
        refund: fee(1, 100),
        output_msat: 100,
    };
    assert!(!agreed.above(&agreed));
    assert!(!Fees::default().above(&agreed));
    // One raised is above, whatever else went down.
    for raised in [
        Fees {
            spend: fee(2, 0),
            ..agreed
        },
        Fees {
            spend: fee(0, 101),
            ..agreed
        },
        Fees {
            lock: fee(2, 100),
            ..agreed
        },
        Fees {
            lock: fee(1, 101),
            ..agreed
        },
        Fees {
            refund: fee(2, 100),
            ..agreed
        },
        Fees {
            refund: fee(1, 101),
            ..agreed
        },
        Fees {
            output_msat: 101,
            ..Fees::default()
        },
    ] {
        assert!(raised.above(&agreed), "{raised:?}");
        assert!(!raised.most(&agreed).above(&raised.most(&agreed)));
        assert!(!agreed.above(&raised.most(&agreed)));
        assert!(!raised.above(&raised.most(&agreed)));
        assert!(!raised.least(&agreed).above(&agreed));
        assert!(!raised.least(&agreed).above(&raised));
    }
    let other = Fees {
        spend: fee(0, 500),
        lock: fee(3, 0),
        refund: fee(1, 100),
        output_msat: 0,
    };
    assert_eq!(
        agreed.least(&other),
        Fees {
            spend: fee(0, 100),
            lock: fee(1, 0),
            refund: fee(1, 100),
            output_msat: 0,
        }
    );
    assert_eq!(
        agreed.most(&other),
        Fees {
            spend: fee(1, 500),
            lock: fee(3, 100),
            refund: fee(1, 100),
            output_msat: 100,
        }
    );
}

#[test]
fn a_fee_on_the_notes_made_rounds_to_the_nearest_sat_beside_the_fee_on_value() {
    let fees = Fees {
        spend: Fee { base: 1, ppm: 100 },
        lock: Fee { base: 2, ppm: 0 },
        refund: Fee { base: 3, ppm: 0 },
        output_msat: 100,
    };
    let spend = fees.spending();
    // 1, and 100 ppm of 10,000 rounded up, 1: the notes made add a tenth
    // of a sat each, to the nearest sat.
    assert_eq!(spend.due(10_000, 0), 2);
    assert_eq!(spend.due(10_001, 4), 3);
    assert_eq!(spend.due(10_000, 4), 2);
    assert_eq!(spend.due(10_000, 5), 3);
    assert_eq!(spend.due(10_000, 14), 3);
    assert_eq!(spend.due(10_000, 15), 4);
    // Each branch of a lock its own fee on value, the same on notes.
    assert_eq!(fees.locking().due(0, 5), 3);
    assert_eq!(fees.refunding().due(0, 5), 4);
    // No part on the notes made is the fee on value alone.
    let plain = Fees {
        output_msat: 0,
        ..fees
    };
    assert_eq!(plain.spending().due(10_001, 64), fees.spend.due(10_001));
    assert_eq!(
        Fees {
            output_msat: u64::MAX,
            ..fees
        }
        .spending()
        .due(8, usize::MAX),
        u64::MAX
    );

    // Before the notes are known: as many as two parts of the value can
    // take, each of every power of two it holds.
    assert_eq!(spend.at_most(0), 1);
    assert_eq!(spend.at_most(7), 1 + 1 + 1);
    assert_eq!(spend.at_most(10_000), 1 + 1 + 3);
    for value in 0..2_000u64 {
        for payee in 0..=value {
            let notes = (payee.count_ones() + (value - payee).count_ones()) as usize;
            assert!(spend.due(value, notes) <= spend.at_most(value));
        }
    }
    assert_eq!(plain.spending().at_most(10_001), fees.spend.due(10_001));

    // A hub that predates the fee on notes says none, and one that charges
    // none says nothing an older wallet does not read.
    let old: Fees = serde_json::from_str(r#"{"spend":{"base":1,"ppm":0}}"#).unwrap();
    assert_eq!(old.output_msat, 0);
    assert!(!serde_json::to_string(&plain).unwrap().contains("output"));
    let said = serde_json::to_string(&fees).unwrap();
    assert!(said.contains(r#""output_msat":100"#), "{said}");
    assert_eq!(serde_json::from_str::<Fees>(&said).unwrap(), fees);
}

#[test]
fn lock_bodies_carry_a_lock_and_its_settlement() {
    let f = fixture();
    let lookup = |id: &[u8; 32]| (id == f.keyset.id()).then_some(&f.keyset);
    let notes = vec![f.input.0.clone()];
    let preimage = [7; 32];
    let terms = TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        [3; 32],
        100,
        1,
        lock_hash(&preimage),
    )
    .unwrap();
    let secret = f
        .input
        .1
        .ownership()
        .owner_secret(f.owner.spend_secret())
        .unwrap();
    // A lock of the fixture's outputs, refunding to a fresh output.
    let lock = || {
        let back = Ephemeral::random()
            .derive(&f.owner.address(), 8, Branch::Refund, 0)
            .unwrap();
        let refund = vec![Output::from_derivation(&back).unwrap()];
        let proposal = Proposal::new(
            &f.keyset,
            &notes,
            f.proposal.ephemeral(),
            f.proposal.outputs().to_vec(),
            Some(TimedLock::new(terms.clone(), refund).unwrap()),
        )
        .unwrap();
        SignedProposal::sign(&f.keyset, proposal, &notes, Authorization::Plain, &[secret]).unwrap()
    };
    let signed = lock();
    // A plain spend pays no one through a payment.
    let plain = Payment::new("h", &signed, &notes, &[0; 32]);
    assert_eq!(plain.decode(lookup).unwrap_err().code, Code::Invalid);
    let (decoded, decoded_notes) = json(&Lock::new(&signed, &notes)).decode(lookup).unwrap();
    assert_eq!(decoded.to_bytes(), signed.to_bytes());
    assert_eq!(decoded_notes, notes);

    let certificate = Certificate::attest(&f.keys, &signed, &notes).unwrap();
    let locked = json(&Locked::new(&certificate));
    let checked = locked.decode(&f.keyset, &signed, &notes).unwrap();
    assert_eq!(checked.to_bytes(), certificate.to_bytes());
    // Another lock's certificate is refused.
    let foreign = Certificate::attest(&f.keys, &lock(), &notes).unwrap();
    let wrong = Locked::new(&foreign).decode(&f.keyset, &signed, &notes);
    assert_eq!(wrong.unwrap_err().code, Code::Invalid);

    let id = signed.proposal().id();
    let open = LockState::new(signed.proposal(), &certificate, None, None);
    let view = json(&open).decode(lookup).unwrap();
    assert_eq!(view.proposal.id(), id);
    assert_eq!((view.settled, view.preimage), (None, None));
    // Its payer's signatures, as its hub kept them, prove it with its
    // certificate; none from an older hub, and others are refused.
    assert!(view.signatures.is_none());
    assert!(serde_json::to_value(&open)
        .unwrap()
        .get("signatures")
        .is_none());
    let kept = licash::authorization::SignedProposal::plain_signatures(&signed.to_bytes()).unwrap();
    assert_eq!(kept, signed.signatures());
    let proven = open.clone().with_signatures(&kept);
    let view = json(&proven).decode(lookup).unwrap();
    assert_eq!(view.signatures.as_deref(), Some(signed.signatures()));
    let forged = open
        .clone()
        .with_signatures(&[licash::crypto::Signature([1; 64])]);
    assert_eq!(forged.decode(lookup).unwrap_err().code, Code::Invalid);
    let paid = LockState::new(
        signed.proposal(),
        &certificate,
        Some(Settled::Pay),
        Some(preimage),
    );
    let view = json(&paid).decode(lookup).unwrap();
    assert_eq!(
        (view.settled, view.preimage),
        (Some(Settled::Pay), Some(preimage))
    );
    let lying = LockState::new(signed.proposal(), &certificate, None, Some([8; 32]));
    assert_eq!(lying.decode(lookup).unwrap_err().code, Code::Invalid);
    let swapped = LockState::new(signed.proposal(), &foreign, None, None);
    assert_eq!(swapped.decode(lookup).unwrap_err().code, Code::Invalid);
    let plain = LockState::new(&f.proposal, &foreign, None, None);
    assert_eq!(plain.decode(lookup).unwrap_err().code, Code::Invalid);
    let none = |_: &[u8; 32]| None;
    assert_eq!(open.decode(none).unwrap_err().code, Code::UnknownKeyset);
    assert_eq!(
        serde_json::to_value(&paid).unwrap()["settled"],
        serde_json::json!("pay")
    );

    assert_eq!(
        json(&Settle::new(&id, &preimage)).decode().unwrap(),
        (id, preimage)
    );
    assert_eq!(json(&Refund::new(&id)).decode().unwrap(), id);
    let short = Settle {
        lock: Hex(vec![0; 32]),
        preimage: Hex(vec![0; 31]),
    };
    assert_eq!(short.decode().unwrap_err().code, Code::Invalid);

    let issuances: Vec<_> = signed
        .proposal()
        .outputs()
        .iter()
        .map(|o| Nonce::new(&f.keyset, o).unwrap().issue(&f.keys).unwrap())
        .collect();
    let decoded = json(&Issued::new(&issuances)).decode(&f.keyset).unwrap();
    for (issuance, d) in decoded.iter().zip(&f.outputs) {
        issuance.open(&f.keyset, d).unwrap();
    }
    let mut broken = Issued::new(&issuances);
    broken.issuances[0].0.pop();
    assert_eq!(broken.decode(&f.keyset).unwrap_err().code, Code::Invalid);
}

#[test]
fn swap_bodies_name_hubs_by_address_and_locks_by_id() {
    use licash_api::swaps::{self, Hub, Request, State, Swap};

    let (hub_a, hub_b) = (
        OwnerKeys::from_seed(&[1; 32]).unwrap(),
        OwnerKeys::from_seed(&[2; 32]).unwrap(),
    );
    let (provider, client) = (
        OwnerKeys::from_seed(&[3; 32]).unwrap(),
        OwnerKeys::from_seed(&[4; 32]).unwrap(),
    );
    let info = swaps::Info {
        address: provider.address(),
        fee: Fee { base: 1, ppm: 1000 },
        min: 100,
        max: 50_000,
        margin: 12,
        hubs: vec![
            Hub {
                address: hub_a.address(),
                max: 20_000,
                margin: Some(40),
            },
            Hub {
                address: hub_b.address(),
                max: 0,
                margin: None,
            },
        ],
        nostr: None,
        chain: None,
        lightning: None,
        donations: None,
        receive: None,
        features: Vec::new(),
    };
    assert_eq!(json(&info), info);
    let at_a = info.hub(&hub_a.address()).unwrap();
    assert_eq!((at_a.max, info.margin_at(at_a)), (20_000, 40));
    // A hub with no margin of its own, as an older provider lists it.
    assert_eq!(info.margin_at(info.hub(&hub_b.address()).unwrap()), 12);
    assert!(info.hub(&client.address()).is_none());
    let text = serde_json::to_string(&info).unwrap();
    assert!(!text.contains("nostr"), "{text}");
    assert_eq!(text.matches("margin").count(), 2, "{text}");

    let id = ProposalId::from_bytes([0xcd; 32]);
    let request = Request::new(
        &hub_a.address(),
        &id,
        &hub_b.address(),
        &client.address(),
        5000,
    );
    assert_eq!(json(&request), request);
    assert_eq!(request.lock().unwrap(), id);
    let short = Request {
        lock: Hex(vec![1; 31]),
        ..request
    };
    assert_eq!(short.lock().unwrap_err().code, Code::Invalid);

    let swap = Swap {
        id: Hex(id.as_bytes().to_vec()),
        state: State::Locked,
        amount: 5000,
        lock: Some(Hex(vec![0xef; 32])),
        expiry: 140,
        reason: None,
    };
    assert_eq!(json(&swap), swap);
    assert_eq!(
        swap.lock().unwrap(),
        Some(ProposalId::from_bytes([0xef; 32]))
    );
    assert!(serde_json::to_string(&swap)
        .unwrap()
        .contains(r#""state":"locked""#));
    let path = swaps::swap_state(&id);
    assert_eq!(path, format!("/v1/swaps/{}", "cd".repeat(32)));
    assert_eq!(licash_api::lock_id(&path[10..]).unwrap(), id);
    assert_eq!(
        (swaps::SWAPS, swaps::SWAPS_INFO),
        ("/v1/swaps", "/v1/swaps/info")
    );
}

#[test]
fn payout_bodies_name_their_fields_on_the_wire() {
    use licash_api::{
        swaps::{self, Chain, ChainRequest, ChainSwap, State},
        Funding,
    };
    use serde_json::json;

    let terms = Chain {
        fee: Fee { base: 1, ppm: 2000 },
        miner: 300,
        rate: 1500,
        min: 10_000,
        max: 1_000_000,
        margin: 36,
    };
    assert_eq!(json(&terms), terms);
    assert_eq!(
        serde_json::to_value(terms).unwrap(),
        json!({"fee": {"base": 1, "ppm": 2000}, "miner": 300, "rate": 1500,
               "min": 10_000, "max": 1_000_000, "margin": 36})
    );
    assert_eq!(terms.pays(100_000), 100_000 + 201 + 300);

    let hub = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let id = ProposalId::from_bytes([0xcd; 32]);
    let request = ChainRequest::new(&hub.address(), &id, [0xab; 32], 20_000);
    assert_eq!(json(&request), request);
    assert_eq!(
        (request.lock().unwrap(), request.claim().unwrap()),
        (id, [0xab; 32])
    );
    let value = serde_json::to_value(&request).unwrap();
    let mut names: Vec<&String> = value.as_object().unwrap().keys().collect();
    names.sort();
    assert_eq!(names, ["claim", "from", "lock", "value"]);
    assert_eq!(value["claim"], json!("ab".repeat(32)));
    // Paying a silent payment address: its scan key blinded, 33 bytes.
    let silent = request.clone().with_scan([0x02; 33]);
    assert_eq!(json(&silent), silent);
    assert_eq!(silent.scan().unwrap(), Some([0x02; 33]));
    assert_eq!(
        serde_json::to_value(&silent).unwrap()["scan"],
        json!("02".repeat(33))
    );
    assert_eq!(request.scan().unwrap(), None);
    let short = ChainRequest {
        scan: Some(Hex(vec![2; 32])),
        ..request.clone()
    };
    assert!(short.scan().is_err());

    let answer = ChainSwap {
        id: Hex(id.as_bytes().to_vec()),
        state: State::Locked,
        value: 20_000,
        refund: Hex(vec![0xef; 32]),
        timeout: 400,
        funding: Some(Funding {
            txid: "11".repeat(32),
            vout: 1,
            height: 350,
        }),
        txid: None,
        reason: None,
        share: None,
    };
    assert_eq!(json(&answer), answer);
    assert_eq!(answer.refund().unwrap(), [0xef; 32]);
    assert_eq!(
        serde_json::to_value(&answer).unwrap(),
        json!({"id": "cd".repeat(32), "state": "locked", "value": 20_000,
               "refund": "ef".repeat(32), "timeout": 400,
               "funding": {"txid": "11".repeat(32), "vout": 1, "height": 350}})
    );
    // Not funded yet: no funding at all, which reads back as none.
    let waiting = ChainSwap {
        funding: None,
        state: State::Accepted,
        ..answer
    };
    let text = serde_json::to_string(&waiting).unwrap();
    assert!(
        !text.contains("funding") && !text.contains("reason"),
        "{text}"
    );
    assert_eq!(json(&waiting), waiting);
    // Broadcast, not confirmed: its transaction alone, which a provider
    // before it never says.
    let broadcast = ChainSwap {
        txid: Some("22".repeat(32)),
        ..waiting.clone()
    };
    let value = serde_json::to_value(&broadcast).unwrap();
    assert_eq!(value["txid"], json!("22".repeat(32)));
    assert_eq!(json(&broadcast), broadcast);
    let shared = ChainSwap {
        share: Some(swaps::Share {
            point: Hex(vec![3; 33]),
            e: Hex(vec![4; 32]),
            s: Hex(vec![5; 32]),
        }),
        ..broadcast.clone()
    };
    assert_eq!(
        serde_json::to_value(&shared).unwrap()["share"],
        json!({"point": "03".repeat(33), "e": "04".repeat(32), "s": "05".repeat(32)})
    );
    assert_eq!(json(&shared), shared);
    let mut old = value;
    old.as_object_mut().unwrap().remove("txid");
    let old: ChainSwap = serde_json::from_value(old).unwrap();
    assert_eq!(old, waiting);
    assert_eq!(
        (swaps::CHAIN_SWAPS, swaps::chain_swap_state(&id)),
        (
            "/v1/swaps/chain",
            format!("/v1/swaps/chain/{}", "cd".repeat(32))
        )
    );
    // A provider paying out nothing on Bitcoin says nothing of it, and an
    // old one's info reads as such.
    let info: swaps::Info = serde_json::from_value(json!({
        "address": hub.address(), "fee": {"base": 0, "ppm": 0}, "min": 1,
        "max": 2, "margin": 12, "hubs": []
    }))
    .unwrap();
    assert_eq!(info.chain, None);
    assert!(!serde_json::to_string(&info).unwrap().contains("chain"));
}

#[test]
fn lightning_payment_bodies_name_their_fields_on_the_wire() {
    use licash_api::swaps::{self, Lightning, LightningRequest, LightningSwap, State};
    use serde_json::json;

    let hub = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let id = ProposalId::from_bytes([0xcd; 32]);
    let request = LightningRequest::new(&hub.address(), &id, "lnbcrt1...");
    assert_eq!(json(&request), request);
    assert_eq!(request.lock().unwrap(), id);
    let value = serde_json::to_value(&request).unwrap();
    let mut names: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(names, ["from", "lock", "request"]);

    // Paying: no preimage yet, and nothing said of one.
    let paying = LightningSwap {
        id: Hex(id.as_bytes().to_vec()),
        state: State::Accepted,
        amount: 10_001,
        preimage: None,
        reason: None,
    };
    assert_eq!(
        serde_json::to_value(&paying).unwrap(),
        json!({"id": "cd".repeat(32), "state": "accepted", "amount": 10_001})
    );
    assert_eq!(json(&paying), paying);
    assert_eq!(paying.preimage().unwrap(), None);
    let paid = LightningSwap {
        state: State::Paid,
        preimage: Some(Hex(vec![0xef; 32])),
        ..paying
    };
    assert_eq!(
        serde_json::to_value(&paid).unwrap()["preimage"],
        json!("ef".repeat(32))
    );
    assert_eq!(json(&paid), paid);
    assert_eq!(paid.preimage().unwrap(), Some([0xef; 32]));
    assert_eq!(
        (swaps::LIGHTNING_SWAPS, swaps::lightning_swap_state(&id)),
        (
            "/v1/swaps/lightning",
            format!("/v1/swaps/lightning/{}", "cd".repeat(32))
        )
    );

    // The lock pays the invoice in whole satoshis, rounded up, and the fee
    // on them.
    let terms = Lightning {
        node: "02".repeat(33),
        fee: Fee { base: 2, ppm: 5000 },
        max: 100_000,
        slack: 12,
    };
    assert_eq!(terms.pays(10_000_000), 10_000 + 2 + 50);
    assert_eq!(terms.pays(10_000_001), 10_001 + 2 + 51);

    // A provider paying nothing over Lightning says nothing of it, and an
    // older one's info reads as such.
    let info: swaps::Info = serde_json::from_value(json!({
        "address": hub.address(), "fee": {"base": 0, "ppm": 0}, "min": 1,
        "max": 2, "margin": 12, "hubs": []
    }))
    .unwrap();
    assert_eq!(info.lightning, None);
    assert!(!serde_json::to_string(&info).unwrap().contains("lightning"));
    let offering = swaps::Info {
        lightning: Some(terms.clone()),
        ..info
    };
    let value = serde_json::to_value(&offering).unwrap();
    assert_eq!(
        value["lightning"],
        json!({"node": "02".repeat(33), "fee": {"base": 2, "ppm": 5000},
               "max": 100_000, "slack": 12})
    );
    assert_eq!(json(&offering), offering);
}

#[test]
fn a_provider_taking_donations_says_where_payers_reach_it() {
    use licash_api::swaps;
    use serde_json::json;

    let hub = OwnerKeys::from_seed(&[1; 32]).unwrap();
    // As a provider taking none answers: none.
    let info: swaps::Info = serde_json::from_value(json!({
        "address": hub.address(), "fee": {"base": 0, "ppm": 0}, "min": 1,
        "max": 2, "margin": 12, "hubs": []
    }))
    .unwrap();
    assert_eq!(info.donations, None);
    assert!(!serde_json::to_string(&info).unwrap().contains("donations"));
    let donating = swaps::Info {
        donations: Some(swaps::Donations {
            url: "https://swaps.example".into(),
            fee: Fee { base: 2, ppm: 5000 },
            min: 100,
            max: 1_000_000,
        }),
        ..info
    };
    let value = serde_json::to_value(&donating).unwrap();
    assert_eq!(
        value["donations"],
        json!({"url": "https://swaps.example", "fee": {"base": 2, "ppm": 5000},
               "min": 100, "max": 1_000_000})
    );
    assert_eq!(json(&donating), donating);
    assert_eq!(
        swaps::donation_url("https://swaps.example/", "licash1abc"),
        "https://swaps.example/v1/lnurlp/licash1abc"
    );
    assert_eq!(
        (swaps::DONATE, swaps::DONATE_CALLBACK),
        ("/v1/lnurlp/{code}", "/v1/lnurlp/{code}/callback")
    );
}

#[test]
fn a_provider_says_the_receipts_over_lightning_it_takes() {
    use licash_api::swaps;
    use serde_json::json;

    let hub = OwnerKeys::from_seed(&[1; 32]).unwrap();
    // As an older provider answers: none.
    let info: swaps::Info = serde_json::from_value(json!({
        "address": hub.address(), "fee": {"base": 0, "ppm": 0}, "min": 1,
        "max": 2, "margin": 12, "hubs": []
    }))
    .unwrap();
    assert_eq!(info.receive, None);
    assert!(!serde_json::to_string(&info).unwrap().contains("receive"));
    let receives = swaps::Receives {
        fee: Fee { base: 2, ppm: 5000 },
        min: 100,
        max: 1_000_000,
    };
    let receiving = swaps::Info {
        receive: Some(receives),
        ..info
    };
    let value = serde_json::to_value(&receiving).unwrap();
    assert_eq!(
        value["receive"],
        json!({"fee": {"base": 2, "ppm": 5000}, "min": 100, "max": 1_000_000})
    );
    assert_eq!(json(&receiving), receiving);
    // The invoice asks the amount and the fee on it.
    assert_eq!(receives.asks(1_000), 1_007);
    let request = swaps::ReceiveRequest {
        hub: hub.address(),
        address: hub.address(),
        amount: 1_000,
        hash: Hex(vec![7; 32]),
        memo: None,
    };
    assert_eq!(json(&request), request);
    assert!(!serde_json::to_string(&request).unwrap().contains("memo"));
    assert_eq!(request.hash().unwrap(), [7; 32]);
    assert_eq!(request.checked_memo().unwrap(), None);
    let saying = |memo: &str| swaps::ReceiveRequest {
        memo: Some(memo.into()),
        ..request.clone()
    };
    assert_eq!(
        saying("Lunch").checked_memo().unwrap(),
        Some("Lunch".into())
    );
    assert!(saying(" Lunch").checked_memo().is_err());
    assert_eq!(
        swaps::receive_state(&[0xab; 32]),
        format!("/v1/swaps/receive/{}", "ab".repeat(32))
    );
    assert_eq!(
        (swaps::RECEIVES, swaps::RECEIVE_STATE),
        ("/v1/swaps/receive", "/v1/swaps/receive/{hash}")
    );
}

#[test]
fn a_memo_is_its_words_one_space_apart_short_and_printable() {
    use licash_api::{memo, MAX_MEMO};
    assert_eq!(memo("  Lunch\n on\tFriday ").unwrap(), "Lunch on Friday");
    assert_eq!(memo("café ☕").unwrap(), "café ☕");
    let longest = "é".repeat(MAX_MEMO);
    assert_eq!(memo(&longest).unwrap(), longest);
    for refused in ["", " \n ", &"x".repeat(MAX_MEMO + 1), "a\u{7}b", "a\u{9f}b"] {
        assert_eq!(
            memo(refused).unwrap_err().code,
            Code::Invalid,
            "{refused:?}"
        );
    }
}

#[test]
fn a_receipt_says_a_memo_only_if_asked_and_only_as_a_memo_is_made() {
    use licash_api::Receive;
    let f = fixture();
    let outputs: Vec<Output> = f
        .outputs
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let ephemeral = Ephemeral::random().public();
    let receive = Receive::new(f.keyset.id(), &ephemeral, &outputs, &[5; 32]);
    // Without, the same bytes as before memos: a hub's stored receipts stay its own.
    let wire = serde_json::to_value(&receive).unwrap();
    assert!(wire.get("memo").is_none());
    let older: Receive = serde_json::from_value(wire).unwrap();
    assert_eq!(
        (older.memo.clone(), older.checked_memo().unwrap()),
        (None, None)
    );
    let said = receive.clone().with_memo(Some("Rent".into()));
    assert_eq!(json(&said).memo.as_deref(), Some("Rent"));
    assert_eq!(said.checked_memo().unwrap().as_deref(), Some("Rent"));
    for unmade in ["", " Rent", "Rent  due", "a\u{7}b"] {
        let unmade = receive.clone().with_memo(Some(unmade.into()));
        assert_eq!(unmade.checked_memo().unwrap_err().code, Code::Invalid);
    }
}

#[test]
fn an_exact_receipt_asks_its_total_and_commits_to_a_description_hash() {
    use licash_api::{receivable, Fee, Receive, MAX_RECEIVE_SURPLUS};
    let f = fixture();
    let outputs: Vec<Output> = f
        .outputs
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let ephemeral = Ephemeral::random().public();
    let receive = Receive::new(f.keyset.id(), &ephemeral, &outputs, &[5; 32]);
    // Without, the same bytes as before: a hub's stored receipts stay its own.
    let wire = serde_json::to_value(&receive).unwrap();
    assert!(wire.get("msat").is_none() && wire.get("description_hash").is_none());
    let fee = Fee { base: 1, ppm: 100 };
    assert_eq!(receive.asks(1_000, &fee).unwrap(), 1_002_000);
    assert_eq!(receive.checked_description_hash().unwrap(), None);

    let exact = receive.clone().with_lnurl(Some(1_002_999), Some([9; 32]));
    assert_eq!(json(&exact), exact);
    assert_eq!(exact.asks(1_000, &fee).unwrap(), 1_002_999);
    assert_eq!(exact.checked_description_hash().unwrap(), Some([9; 32]));
    // Less than the notes and the fee, or more than a surplus beyond.
    for msat in [1_001_999, 1_002_000 + MAX_RECEIVE_SURPLUS + 1] {
        let asked = receive.clone().with_lnurl(Some(msat), None);
        assert_eq!(asked.asks(1_000, &fee).unwrap_err().code, Code::Invalid);
    }
    // A memo or a description hash, never both.
    let both = exact.with_memo(Some("Rent".into()));
    assert_eq!(
        both.checked_description_hash().unwrap_err().code,
        Code::Invalid
    );

    // The most notes a total pays: what is left is under the surplus.
    for msat in [3_000, 21_000, 21_999, 1_002_000, 1_002_999, 100_000_000_123] {
        let notes = receivable(msat, &fee).unwrap();
        let least = (notes + fee.due(notes)) * 1000;
        assert!(
            least <= msat && msat - least <= MAX_RECEIVE_SURPLUS,
            "{msat}"
        );
        let more = (notes + 1 + fee.due(notes + 1)) * 1000;
        assert!(more > msat, "{msat}");
    }
    // The fee takes it all.
    assert_eq!(receivable(1_000, &fee), None);
    assert_eq!(receivable(1_999, &fee), None);
    assert_eq!(receivable(0, &fee), None);
}

#[test]
fn deposit_bodies_are_receipts_with_a_refund_key_and_a_payment() {
    use licash_api::{
        Deposit, DepositStatus, Depositing, Deposits, Funding, Receive, ReceiveState, ReceiveStatus,
    };
    let f = fixture();
    let outputs: Vec<Output> = f
        .outputs
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let ephemeral = Ephemeral::random().public();
    let receive = Receive::new(f.keyset.id(), &ephemeral, &outputs, &[5; 32]);
    let deposit = Deposit {
        receive: receive.clone(),
        refund: Hex(vec![2; 32]),
        close: None,
    };
    // The receipt's fields, and the refund key beside them.
    let wire = serde_json::to_value(&deposit).unwrap();
    let mut fields: Vec<&str> = wire
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    fields.sort();
    assert_eq!(fields, ["ephemeral", "hash", "keyset", "outputs", "refund"]);
    let back = json(&deposit);
    assert_eq!(back.receive.terms().unwrap(), receive.terms().unwrap());
    assert_eq!(back.receive.outputs().unwrap(), outputs);
    assert_eq!(back.refund, deposit.refund);

    let depositing = Depositing {
        address: "bcrt1p".into(),
        amount: 1_000,
        claim: Hex(vec![3; 32]),
        timeout: 300,
        fund_by: 150,
    };
    assert_eq!(json(&depositing), depositing);
    // Open and unpaid: no lock, no payment, on the wire too.
    let open = DepositStatus {
        status: ReceiveStatus {
            state: ReceiveState::Open,
            lock: None,
        },
        funding: None,
        request: None,
        terms: None,
    };
    assert_eq!(serde_json::to_string(&open).unwrap(), r#"{"state":"open"}"#);
    let locked = DepositStatus {
        status: ReceiveStatus {
            state: ReceiveState::Locked,
            lock: Some(Hex(vec![4; 32])),
        },
        funding: Some(Funding {
            txid: "ab".repeat(32),
            vout: 1,
            height: 120,
        }),
        request: None,
        terms: None,
    };
    assert_eq!(json(&locked), locked);
    // What was asked and answered, for a wallet finding it again.
    let found = DepositStatus {
        terms: Some(depositing.clone()),
        ..open.clone()
    };
    assert_eq!(json(&found), found);
    let deposits = Deposits {
        fee: Fee {
            base: 500,
            ppm: 1_000,
        },
        min: 10_000,
        max: 1_000_000,
        depth: 3,
        window: 144,
        timeout: 288,
        close_root: None,
    };
    assert_eq!(deposits.pays(100_000), Some(100_600));
    assert_eq!(deposits.pays(u64::MAX), None);
    // A hub's deposit root is hex in its info, and none is left out.
    assert!(serde_json::to_value(deposits)
        .unwrap()
        .get("close_root")
        .is_none());
    let rooted = Deposits {
        close_root: Some(licash_api::XOnly([7; 32])),
        ..deposits
    };
    assert_eq!(
        serde_json::to_value(rooted).unwrap()["close_root"],
        serde_json::json!("07".repeat(32))
    );
    assert_eq!(json(&rooted), rooted);
    let short: Result<Deposits, _> = serde_json::from_value(
        serde_json::json!({"fee": {"base": 0, "ppm": 0}, "min": 1, "max": 2, "depth": 1,
                           "window": 1, "timeout": 1, "close_root": "0707"}),
    );
    assert!(short.is_err());
    let mut info = Info::new(
        std::slice::from_ref(&f.keyset),
        f.owner.address(),
        Fees::default(),
        None,
    );
    info.deposits = Some(deposits);
    assert_eq!(json(&info).deposits, Some(deposits));
}

/// A hub's info as one following signet would advertise it: two keysets,
/// a Nostr key, proved by `signer`'s spend key.
fn proved_info(owner: &OwnerKeys, signer: &OwnerKeys) -> Info {
    let keysets: Vec<Keyset> = (0..2)
        .map(|i| {
            IssuerKeys::from_seed(&[7; 32], i, 3)
                .unwrap()
                .keyset()
                .unwrap()
        })
        .collect();
    let mut info = Info::new(&keysets, owner.address(), Fees::default(), None);
    info.nostr = Some(hex::encode([9; 32]));
    let identity = info.identity(ChainProfile::Core30Signet).unwrap();
    let signature = schnorr_sign(signer.spend_secret(), &identity).unwrap();
    info.proof = Some(Hex(signature.0.to_vec()));
    info
}

#[test]
fn a_hub_proves_its_identity_and_nothing_else() {
    let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let other = OwnerKeys::from_seed(&[2; 32]).unwrap();
    let signet = ChainProfile::Core30Signet;
    let info = json(&proved_info(&owner, &owner));
    assert_eq!(info.proved(signet), Ok(true));

    // What it signs, field by field, in fixed widths.
    let keysets = info.keysets().unwrap();
    let mut parts: Vec<&[u8]> = Vec::new();
    let address = owner.address().to_bytes();
    let count = 2u32.to_be_bytes();
    parts.extend([&[3u8][..], &address, &[1], &[9; 32], &count]);
    parts.extend(keysets.iter().map(|k| k.id().as_slice()));
    let restated = tagged_hash("licash/hub/identity/v1", &parts);
    assert_eq!(info.identity(signet).unwrap(), restated);
    let mut anonymous = info.clone();
    anonymous.nostr = None;
    let mut parts: Vec<&[u8]> = Vec::new();
    parts.extend([&[3u8][..], &address, &[0], &[0; 32], &count]);
    parts.extend(keysets.iter().map(|k| k.id().as_slice()));
    let restated = tagged_hash("licash/hub/identity/v1", &parts);
    assert_eq!(anonymous.identity(signet).unwrap(), restated);

    // None: proves nothing, refuses nothing.
    let mut unproved = info.clone();
    unproved.proof = None;
    assert_eq!(unproved.proved(signet), Ok(false));
    assert!(!serde_json::to_string(&unproved).unwrap().contains("proof"));

    let refused = |changed: Info, what: &str| {
        let problem = changed.proved(signet).expect_err(what);
        assert_eq!(problem.code, Code::Invalid, "{what}");
    };
    refused(proved_info(&owner, &other), "signed by another key");
    for network in [ChainProfile::Core30DefaultRegtest, ChainProfile::Mutinynet] {
        let problem = info.proved(network).expect_err("another network");
        assert_eq!(problem.code, Code::Invalid);
    }
    let mut changed = info.clone();
    changed.address = other.address();
    refused(changed, "another address");
    let mut changed = info.clone();
    changed.nostr = Some(hex::encode([8; 32]));
    refused(changed, "another Nostr key");
    refused(anonymous, "no Nostr key");
    let mut changed = info.clone();
    changed.keysets.pop();
    refused(changed, "a keyset removed");
    let mut changed = info.clone();
    changed.keysets.reverse();
    refused(changed, "the keysets reordered");
    let mut changed = info.clone();
    let third = IssuerKeys::from_seed(&[7; 32], 2, 3).unwrap();
    changed
        .keysets
        .push(Hex(third.keyset().unwrap().to_bytes()));
    refused(changed, "a keyset added");
    let mut changed = info.clone();
    changed.proof.as_mut().unwrap().0[10] ^= 1;
    refused(changed, "a byte of the signature");
    let mut changed = info.clone();
    changed.proof.as_mut().unwrap().0.pop();
    refused(changed, "63 bytes");
    let mut changed = info.clone();
    changed.nostr = Some("not hex".into());
    refused(changed, "a Nostr key not in hex");

    // What it does not sign may change.
    let mut changed = info.clone();
    changed.relays = vec!["wss://relay.example".into()];
    changed.fees.spend = Fee { base: 5, ppm: 0 };
    assert_eq!(changed.proved(signet), Ok(true));
}

#[test]
fn a_hubs_urls_are_left_out_when_none_and_are_not_its_identity() {
    let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let signet = ChainProfile::Core30Signet;
    let info = proved_info(&owner, &owner);
    assert!(info.urls.is_empty());
    // None: not sent, and an older hub's info, without them, reads.
    let sent = serde_json::to_value(&info).unwrap();
    assert!(sent.get("urls").is_none(), "{sent}");
    assert!(json(&info).urls.is_empty());

    let mut named = info.clone();
    named.urls = vec![
        "https://hub.example".into(),
        format!("http://{}.onion", "a".repeat(56)),
    ];
    assert_eq!(json(&named).urls, named.urls);
    // Changing them leaves its proof standing: they prove nothing.
    assert_eq!(named.identity(signet), info.identity(signet));
    assert_eq!(named.proved(signet), Ok(true));
}

/// What a hub says of its room for a new contract is new: one saying
/// nothing of it, as every hub before, reads as having room, and a hub
/// with room sends nothing a wallet before this has to make sense of.
#[test]
fn a_hubs_room_for_a_contract_is_unknown_and_open_unless_it_says() {
    use licash_api::Room;
    let before = r#"{"cap":131071,"price":23000,"reserve":20000,"blocks":1000,"mock":false}"#;
    let read: Contracts = serde_json::from_str(before).unwrap();
    assert_eq!((read.funds, read.full), (None, false));
    assert_eq!(read.room(), Room::Open);
    // Nothing of it sent while unknown and not full: as before.
    assert_eq!(
        serde_json::to_string(&read).unwrap(),
        before,
        "the fields of a hub before"
    );

    let full = Contracts { full: true, ..read };
    assert_eq!(json(&full), full);
    assert_eq!(full.room(), Room::Full);
    // Full, whatever its wallet funds.
    let both = Contracts {
        funds: Some(131_071),
        ..full
    };
    assert_eq!(both.room(), Room::Full);

    // Its wallet funds none of its one cap: only a contract its holder
    // funds whole opens there. All of it: room.
    let short = Contracts {
        funds: Some(0),
        ..read
    };
    assert_eq!(json(&short), short);
    assert_eq!(short.room(), Room::Unfunded);
    let funded = Contracts {
        funds: Some(131_071),
        ..read
    };
    assert_eq!(funded.room(), Room::Open);

    // With a range, against its smallest cap, not the fixed one.
    let range = ContractRange {
        min_cap: 262_143,
        max_cap: 134_217_727,
        min_blocks: 432,
        max_blocks: 26_280,
        per_coin: 2,
        reserve: 20_000,
        fee: 3_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
        year_blocks: licash_api::YEAR_BLOCKS,
    };
    let ranged = |funds| Contracts {
        range: Some(range),
        funds: Some(funds),
        ..read
    };
    assert_eq!(ranged(131_071).room(), Room::Unfunded);
    assert_eq!(ranged(262_143).room(), Room::Open);
    assert_eq!(Room::of(false, None, u32::MAX), Room::Open);
}

#[test]
fn a_hubs_contract_range_is_left_out_when_none_and_prices_the_hubs_part_by_the_year() {
    // Without one: read, none.
    let fixed = r#"{"cap":131071,"price":23000,"reserve":20000,"blocks":1000,"mock":false}"#;
    let read: Contracts = serde_json::from_str(fixed).unwrap();
    assert_eq!(read.range, None);
    let sent = serde_json::to_value(read).unwrap();
    assert!(sent.get("range").is_none(), "{sent}");

    let range = ContractRange {
        min_cap: 131_071,
        max_cap: 134_217_727,
        min_blocks: 432,
        max_blocks: 26_280,
        per_coin: 2,
        reserve: 20_000,
        fee: 3_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
        year_blocks: licash_api::YEAR_BLOCKS,
    };
    let offered = Contracts {
        range: Some(range),
        ..read
    };
    assert_eq!(json(&offered), offered);

    // 1% a year: 16 777 215 sat for half a year, 83 886 sat of interest
    // over her reserve and the fixed fee, rounded down.
    let fee = range.fee(16_777_215, 26_280, 0);
    assert_eq!(
        (fee.opening, fee.interest, fee.interest_funded),
        (3_000, 83_886, 0)
    );
    assert_eq!(range.price(16_777_215, 26_280, 0), 106_886);
    // Half of it hers: interest on the hub's half only, none on hers.
    let fee = range.fee(16_777_215, 26_280, 8_388_607);
    assert_eq!((fee.interest, fee.interest_funded), (41_943, 0));
    assert_eq!(range.price(16_777_215, 26_280, 8_388_607), 64_943);
    // Unless the hub charges for hers too; never more than the cap hers.
    let funded = ContractRange {
        ppm_year_funded: 2_000,
        ..range
    };
    assert_eq!(
        funded.fee(16_777_215, 26_280, 8_388_607).interest_funded,
        8_388
    );
    assert_eq!(funded.fee(131_071, 1_000, u32::MAX).interest, 0);
    assert_eq!(
        rate(10_000, u32::MAX, u32::MAX, licash_api::YEAR_BLOCKS),
        3_509_654_502_496
    );

    // Its caps: any within its bounds, 131 071 the least, whose payout's
    // rest is none or an output of 512 sat at least.
    assert!(range.allows_cap(131_071) && range.allows_cap(134_217_727));
    assert!(range.allows_cap(200_000) && range.allows_cap(131_071 + 512));
    assert!(!range.allows_cap(131_072) && !range.allows_cap(131_071 + 511));
    assert!(!range.allows_cap(131_070) && !range.allows_cap(134_217_728));
    assert_eq!(range.cap_at_least(0), Some(131_071));
    assert_eq!(range.cap_at_least(131_100), Some(131_071 + 512));
    assert_eq!(range.cap_at_least(10_000_000), Some(10_000_000));
    assert_eq!(range.cap_at_least(134_217_728), None);
    // The largest cap twice her coin covers, within the hub's bounds.
    assert_eq!(range.max_cap_for(10_000_000), Some(20_000_000));
    assert_eq!(range.max_cap_for(90_000_000), Some(134_217_727));
    assert_eq!(range.max_cap_for(65_536), Some(131_071));
    assert_eq!(range.max_cap_for(65_600), Some(131_071));
    assert_eq!(range.max_cap_for(65_535), None);
    assert_eq!(range.max_cap_for(u64::MAX), Some(134_217_727));
}

#[test]
fn a_deposit_paying_an_amount_exactly_locks_what_its_fee_leaves() {
    use licash_api::Deposits;
    let deposits = |base, ppm| Deposits {
        fee: Fee { base, ppm },
        min: 10_000,
        max: 1_000_000,
        depth: 3,
        window: 144,
        timeout: 288,
        close_root: None,
    };
    let flat = deposits(1_000, 0);
    assert_eq!(flat.paid_by(9_981_000), Some(9_980_000));
    assert_eq!(flat.paid_by(1_000), Some(0));
    assert_eq!(flat.paid_by(999), None);
    let both = deposits(500, 1_000);
    assert_eq!(both.paid_by(100_600), Some(100_000));
    // Its fee rounded up: no amount comes to some, each gap a sat wide.
    let rate = deposits(0, 10);
    assert_eq!(rate.paid_by(100_001), Some(100_000));
    assert_eq!(rate.paid_by(100_002), None);
    assert_eq!(rate.paid_by(100_003), Some(100_001));
    for pays in [0, 1, 499, 500, 501, 10_510, 1_000_000, 21_000_000_000_000] {
        match both.paid_by(pays) {
            Some(amount) => assert_eq!(both.pays(amount), Some(pays)),
            None => assert!(pays > 2_000_000 || (0..=pays).all(|a| both.pays(a) != Some(pays))),
        }
    }
    assert_eq!(deposits(0, 0).paid_by(u64::MAX), Some(u64::MAX));
}

/// A payment fixed beforehand, a contract's reserve, locks the most notes
/// it covers; the gap to it is the hub's.
#[test]
fn a_fixed_payment_locks_the_most_notes_it_covers() {
    use licash_api::Deposits;
    let deposits = |base, ppm| Deposits {
        fee: Fee { base, ppm },
        min: 10_000,
        max: 1_000_000,
        depth: 3,
        window: 144,
        timeout: 288,
        close_root: None,
    };
    let flat = deposits(1_000, 0);
    assert_eq!(flat.most_for(20_000), Some(19_000));
    assert_eq!(flat.most_for(1_000), Some(0));
    assert_eq!(flat.most_for(999), None);
    // Its fee rounded up leaves gaps that `paid_by` refuses, never this.
    let rate = deposits(0, 10);
    assert_eq!(rate.paid_by(100_002), None);
    assert_eq!(rate.most_for(100_002), Some(100_000));
    let both = deposits(500, 1_000);
    for pays in [500, 501, 10_510, 20_000, 1_000_000] {
        let notes = both.most_for(pays).unwrap();
        assert!(both.pays(notes).unwrap() <= pays, "{pays}");
        assert!(both.pays(notes + 1).unwrap() > pays, "{pays}");
        if let Some(exact) = both.paid_by(pays) {
            assert_eq!(exact, notes, "{pays}");
        }
    }
    assert_eq!(both.most_for(499), None);
    assert_eq!(deposits(0, 0).most_for(u64::MAX), Some(u64::MAX));
}

/// A deposit that returns a contract's reserve says so, and the hub reads
/// the terms back; an ordinary one's wire has no trace of it.
#[test]
fn a_close_deposit_names_its_payment_and_the_block_it_is_watched_until() {
    use licash_api::{CloseTerms, Deposit, Receive};
    let f = fixture();
    let outputs: Vec<Output> = f
        .outputs
        .iter()
        .map(|d| Output::from_derivation(d).unwrap())
        .collect();
    let ephemeral = Ephemeral::random().public();
    let receive = Receive::new(f.keyset.id(), &ephemeral, &outputs, &[5; 32]);
    let close = Deposit {
        receive,
        refund: Hex(vec![2; 32]),
        close: Some(CloseTerms {
            pays: 20_000,
            until: 5_000,
        }),
    };
    let wire = serde_json::to_value(&close).unwrap();
    assert_eq!(
        wire["close"],
        serde_json::json!({"pays": 20_000, "until": 5_000})
    );
    assert_eq!(json(&close), close);
    let ordinary = Deposit {
        close: None,
        ..close
    };
    assert!(serde_json::to_value(&ordinary)
        .unwrap()
        .get("close")
        .is_none());
    assert_eq!(json(&ordinary), ordinary);
}

#[test]
fn a_later_versions_codes_states_and_features_read_as_unknown_or_ignored() {
    use licash_api::swaps;

    // A refusal by a code this version does not know: still a refusal.
    let problem: Problem =
        serde_json::from_str(r#"{"code":"prepay_required","message":"pay first"}"#).unwrap();
    assert_eq!((problem.code, problem.code.status()), (Code::Unknown, 409));
    // A swap state this version does not know.
    let state: swaps::State = serde_json::from_str(r#""prepaid""#).unwrap();
    assert_eq!(state, swaps::State::Unknown);
    // Features named, and none by older hubs and providers.
    let owner = OwnerKeys::from_seed(&[1; 32]).unwrap();
    let mut info = Info::new(&[], owner.address(), Fees::default(), None);
    assert!(!serde_json::to_string(&info).unwrap().contains("features"));
    info.features = vec!["prepay".into()];
    let read: Info = serde_json::from_str(&serde_json::to_string(&info).unwrap()).unwrap();
    assert_eq!(read.features, ["prepay"]);
}

#[test]
fn a_contracts_interest_counts_the_year_its_hub_says() {
    // Bitcoin's year (144 blocks a day) is left out of the info, as hubs
    // before it said none, and read as it when absent.
    let bitcoin = ContractRange {
        min_cap: 131_071,
        max_cap: 134_217_727,
        min_blocks: 432,
        max_blocks: 26_280,
        per_coin: 2,
        reserve: 20_000,
        fee: 3_000,
        ppm_year: 10_000,
        ppm_year_funded: 0,
        year_blocks: licash_api::YEAR_BLOCKS,
    };
    let sent = serde_json::to_value(bitcoin).unwrap();
    assert!(sent.get("year_blocks").is_none(), "{sent}");
    let read: ContractRange = serde_json::from_value(sent).unwrap();
    assert_eq!(read, bitcoin);
    assert_eq!(read.year_blocks, 144 * 365);

    // Mutinynet's, 2 880 blocks a day: said, and read back.
    let quick = ContractRange {
        year_blocks: ChainProfile::Mutinynet.blocks_a_year(),
        ..bitcoin
    };
    assert_eq!(quick.year_blocks, 2_880 * 365);
    let sent = serde_json::to_value(quick).unwrap();
    assert_eq!(sent["year_blocks"], 1_051_200);
    assert_eq!(json(&quick), quick);
    // The same half year costs the same interest in 20 times the blocks,
    // and the same blocks a twentieth.
    let fee = |range: &ContractRange, blocks| range.fee(16_777_215, blocks, 0);
    assert_eq!(fee(&bitcoin, 26_280).interest, 83_886);
    assert_eq!(fee(&quick, 26_280 * 20), fee(&bitcoin, 26_280));
    assert_eq!(fee(&quick, 26_280).interest, 4_194);
    assert_eq!(quick.price(16_777_215, 26_280, 0), 20_000 + 3_000 + 4_194);
    // A year said as none cannot divide by zero.
    let none = ContractRange {
        year_blocks: 0,
        ..bitcoin
    };
    assert_eq!(rate(1, 1, 1, none.year_blocks), 0);
}

#[test]
fn a_signed_bridge_request_verifies_for_its_path_and_time_only() {
    use licash_api::bridge::{Signed, ACCOUNT, MAX_SKEW, REGISTER};
    let signed = Signed::sign(&[3; 32], REGISTER, 1_000, r#"{"pairing":"ab"}"#.into()).unwrap();
    let signed = json(&signed);
    let key = signed.verify(REGISTER, 1_000 + MAX_SKEW).unwrap();
    assert_eq!(key.to_vec(), signed.key.0);
    // Another path, too late or ahead, or another request: refused.
    assert!(signed.verify(ACCOUNT, 1_000).is_err());
    assert!(signed.verify(REGISTER, 1_001 + MAX_SKEW).is_err());
    assert!(signed.verify(REGISTER, 999 - MAX_SKEW).is_err());
    let mut forged = signed.clone();
    forged.request = r#"{"pairing":"cd"}"#.into();
    assert_eq!(
        forged.verify(REGISTER, 1_000).unwrap_err().code,
        Code::Invalid
    );
    let mut moved = signed;
    moved.at += 1;
    assert!(moved.verify(REGISTER, 1_000).is_err());
    assert!(Signed::sign(&[0; 32], REGISTER, 0, String::new()).is_err());
}

/// A contract's cap is any number of sat from 2^17 - 1 to 2^31 - 1 whose
/// payout's rest, past its binary outputs, is none or an output of 512
/// sat at least; rounded to one up or down by less than 512 sat.
#[test]
fn a_cap_is_any_size_its_payout_pays_exactly() {
    use licash_api::{
        cap_at_least, cap_at_most, is_cap, payout_bits, payout_rest, MAX_CAP, MIN_CAP, MIN_REST,
    };
    assert_eq!((MIN_CAP, MAX_CAP, MIN_REST), (131_071, 2_147_483_647, 512));
    assert_eq!((payout_bits(131_071), payout_rest(131_071)), (17, 0));
    assert_eq!((payout_bits(262_142), payout_rest(262_142)), (17, 131_071));
    assert_eq!((payout_bits(262_143), payout_rest(262_143)), (18, 0));
    assert_eq!(
        (payout_bits(1_000_000), payout_rest(1_000_000)),
        (19, 475_713)
    );
    for cap in [
        131_071, 131_583, 200_000, 262_142, 262_143, 1_000_000, MAX_CAP,
    ] {
        assert!(is_cap(cap), "{cap}");
        assert_eq!(
            (cap_at_least(cap.into()), cap_at_most(cap.into())),
            (Some(cap), Some(cap))
        );
        let rest = payout_rest(cap);
        assert!(rest < 1 << payout_bits(cap) && payout_bits(cap) <= 31);
    }
    for cap in [
        0,
        131_070,
        131_072,
        131_582,
        262_144,
        262_143 + 511,
        MAX_CAP + 1,
        u32::MAX,
    ] {
        assert!(!is_cap(cap), "{cap}");
    }
    assert_eq!(cap_at_least(131_072), Some(131_583));
    assert_eq!(cap_at_least(262_144), Some(262_143 + 512));
    assert_eq!(cap_at_least(0), Some(MIN_CAP));
    assert_eq!(cap_at_least(u64::from(MAX_CAP) + 1), None);
    assert_eq!(cap_at_most(131_582), Some(131_071));
    assert_eq!(cap_at_most(262_200), Some(262_143));
    assert_eq!(cap_at_most(u64::MAX), Some(MAX_CAP));
    assert_eq!(cap_at_most(131_070), None);
    // Every cap rounded is one, within MIN_REST.
    for sat in (MIN_CAP as u64..600_000).step_by(37) {
        let (up, down) = (cap_at_least(sat).unwrap(), cap_at_most(sat).unwrap());
        assert!(is_cap(up) && is_cap(down));
        assert!(u64::from(up) >= sat && u64::from(up) - sat < u64::from(MIN_REST));
        assert!(u64::from(down) <= sat && sat - u64::from(down) < u64::from(MIN_REST));
    }
}
