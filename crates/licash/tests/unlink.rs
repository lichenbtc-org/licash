use licash::{
    address::{Ephemeral, OwnerKeys},
    authorization::{Authorization, PreparedGrant, SignedProposal},
    claim::Branch,
    crypto::{self, Point, ScalarBytes},
    note::{Derivation, Evidence, IssuerKeys, Keyset, MintResponse, Note},
    spend::{Output, Proposal},
    unlink::{Answer, Answered, Nonce, Request, Session, ANSWERED_BYTES, REQUEST_BYTES},
};

/// Tag, keyset, public fields, C, evidence tag, DLEQ.
const UNLINKED_NOTE_BYTES: usize = 10 + 32 + 72 + 33 + 1 + 64;
/// Where the request's capability starts: tag, keyset, denomination, B.
const CAPABILITY_AT: usize = 10 + 32 + 8 + 33;

struct Issuer {
    keys: IssuerKeys,
    keyset: Keyset,
}

fn issuer() -> Issuer {
    let keys = IssuerKeys::random(3).unwrap();
    let keyset = keys.keyset().unwrap();
    Issuer { keys, keyset }
}

impl Issuer {
    /// Plain issuance of `d`'s output, as a hub issues a spend's outputs:
    /// the blind signature and the commitment of a fresh nonce.
    fn issue(&self, d: &Derivation) -> (Note, Nonce) {
        let output = Output::from_derivation(d).unwrap();
        let nonce = Nonce::new(&self.keyset, &output).unwrap();
        (self.issue_under(d, &nonce), nonce)
    }

    /// The issuance crosses to the holder as bytes.
    fn issue_under(&self, d: &Derivation, nonce: &Nonce) -> Note {
        let bytes = nonce.issue(&self.keys).unwrap().to_bytes();
        let issued = MintResponse::from_bytes(&self.keyset, &bytes).unwrap();
        let note = issued.open(&self.keyset, d).unwrap();
        let Evidence::Linked { commit, .. } = note.evidence() else {
            panic!("a linked note");
        };
        assert_eq!(*commit, nonce.commit().unwrap());
        note
    }

    fn unlink(&self, note: &Note, d: &Derivation, nonce: Nonce) -> Note {
        let session = Session::start(&self.keyset, note, d).unwrap();
        let answered = nonce.answer(&self.keys, session.request()).unwrap();
        session.finish(&self.keyset, &answered.answer()).unwrap()
    }
}

fn owner(seed: u8) -> OwnerKeys {
    OwnerKeys::from_seed(&[seed; 32]).unwrap()
}

fn received(to: &OwnerKeys, denom: u64) -> Derivation {
    Ephemeral::random()
        .derive(&to.address(), denom, Branch::Pay, 0)
        .unwrap()
}

fn assert_unlinked(issuer: &Issuer, linked: &Note, unlinked: &Note) {
    assert_eq!(unlinked.message(), linked.message());
    assert_eq!(unlinked.signature(), linked.signature());
    let Evidence::Unlinked(proof) = unlinked.evidence() else {
        panic!("expected unlinked evidence");
    };
    // From an issuance's evidence, or a grant's packet's when opened from
    // one, which has no DLEQ to reuse.
    match linked.evidence() {
        Evidence::Linked { dleq, .. } => assert_ne!(proof, dleq),
        Evidence::Granted { .. } => {}
        Evidence::Unlinked(_) => panic!("expected linked evidence"),
    }
    unlinked.verify(&issuer.keyset).unwrap();
    let bytes = unlinked.to_bytes();
    assert_eq!(bytes.len(), UNLINKED_NOTE_BYTES);
    assert_eq!(&Note::from_bytes(&issuer.keyset, &bytes).unwrap(), unlinked);
}

fn scalar(bytes: &[u8]) -> k256::Scalar {
    ScalarBytes(bytes.try_into().unwrap()).to_scalar().unwrap()
}

#[test]
fn granted_outputs_unlink_under_the_grants_nonces() {
    let issuer = issuer();
    let (alice, bob) = (owner(1), owner(2));
    let spent = received(&alice, 8);
    let (input, _) = issuer.issue(&spent);
    let inputs = [input];
    let e = Ephemeral::random();
    let outputs = [
        e.derive(&bob.address(), 4, Branch::Pay, 0).unwrap(),
        e.derive(&alice.address(), 4, Branch::Pay, 1).unwrap(),
    ];
    let proposal = Proposal::new(
        &issuer.keyset,
        &inputs,
        e.public(),
        outputs
            .iter()
            .map(|d| Output::from_derivation(d).unwrap())
            .collect(),
        None,
    )
    .unwrap();
    let prepared = PreparedGrant::new(&issuer.keys, &proposal).unwrap();
    let offer = prepared.offer();
    let signed = SignedProposal::sign(
        &issuer.keyset,
        proposal,
        &inputs,
        Authorization::Granted(Box::new(offer.clone())),
        &[spent
            .ownership()
            .owner_secret(alice.spend_secret())
            .unwrap()],
    )
    .unwrap();
    let unlock = prepared.release(&issuer.keyset, &inputs, &signed).unwrap();
    let nonces = prepared.unlink_nonces();
    assert_eq!(nonces.len(), 2);
    for (index, (d, nonce)) in outputs.iter().zip(nonces).enumerate() {
        assert_eq!(nonce.blinded(), d.blinded().unwrap());
        assert_eq!(nonce.commit().unwrap(), offer.packets[index].commit);
        let note = signed
            .open_granted_output(&issuer.keyset, &inputs, index, d, &unlock)
            .unwrap();
        let unlinked = issuer.unlink(&note, d, nonce);
        assert_unlinked(&issuer, &note, &unlinked);
    }
}

#[test]
fn plainly_issued_notes_unlink() {
    let issuer = issuer();
    let bob = owner(2);
    for denom in [1, 2, 4, 8] {
        let d = received(&bob, denom);
        let (note, nonce) = issuer.issue(&d);
        let unlinked = issuer.unlink(&note, &d, nonce);
        assert_unlinked(&issuer, &note, &unlinked);
    }
}

#[test]
fn a_nonce_answers_one_request_and_replays_only_that_one() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let (note, nonce) = issuer.issue(&d);
    let first = Session::start(&issuer.keyset, &note, &d).unwrap();
    let second = Session::start(&issuer.keyset, &note, &d).unwrap();
    assert_ne!(first.request(), second.request());
    let answered = nonce.clone().answer(&issuer.keys, first.request()).unwrap();
    assert_eq!(answered.blinded(), d.blinded().unwrap());
    assert_eq!(answered.replay(first.request()).unwrap(), answered.answer());
    assert!(answered.replay(second.request()).is_err());
    assert!(second.finish(&issuer.keyset, &answered.answer()).is_err());
    let unlinked = first.finish(&issuer.keyset, &answered.answer()).unwrap();
    assert_unlinked(&issuer, &note, &unlinked);

    // Why: a second answer under the same nonce (here from a copy of it,
    // as a restored store would hold) reveals the denomination's key.
    let again = nonce.answer(&issuer.keys, second.request()).unwrap();
    let challenge = |r: &Request| scalar(&r.to_bytes()[REQUEST_BYTES - 32..]);
    let (e1, e2) = (challenge(first.request()), challenge(second.request()));
    let (s1, s2) = (
        scalar(&answered.answer().to_bytes()),
        scalar(&again.answer().to_bytes()),
    );
    let k = (s1 - s2) * (e1 - e2).invert().unwrap();
    assert_eq!(
        Point::from_projective(&crypto::generator_mul(&k)),
        issuer.keyset.key(4).unwrap()
    );
}

#[test]
fn answers_need_the_outputs_capability_and_issuance() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let (note, nonce) = issuer.issue(&d);
    let session = Session::start(&issuer.keyset, &note, &d).unwrap();
    let bytes = session.request().to_bytes();
    let changed = |at: usize, value: &[u8]| {
        let mut b = bytes;
        b[at..at + value.len()].copy_from_slice(value);
        Request::from_bytes(&b).unwrap()
    };
    let mut capability = bytes[CAPABILITY_AT..CAPABILITY_AT + 32].to_vec();
    capability[0] ^= 1;
    for request in [
        // Another output's capability, another denomination, another keyset.
        changed(CAPABILITY_AT, &capability),
        changed(42, &2u64.to_be_bytes()),
        changed(10, &[7; 32]),
    ] {
        assert!(nonce.clone().answer(&issuer.keys, &request).is_err());
    }
    let commitment = *Output::from_derivation(&d).unwrap().unlink_commitment();
    assert_eq!(session.request().unlink_commitment(), commitment);
    assert_ne!(
        changed(CAPABILITY_AT, &capability).unlink_commitment(),
        commitment
    );
    // Another issuance's nonce, and another issuer's keys.
    let (_, other) = issuer.issue(&received(&owner(2), 4));
    assert!(other.answer(&issuer.keys, session.request()).is_err());
    assert!(nonce
        .clone()
        .answer(&IssuerKeys::random(3).unwrap(), session.request())
        .is_err());
    // The request as sent is answered.
    let answered = nonce.answer(&issuer.keys, session.request()).unwrap();
    session.finish(&issuer.keyset, &answered.answer()).unwrap();
}

#[test]
fn sessions_start_only_for_linked_notes_with_their_derivation() {
    let issuer = issuer();
    let bob = owner(2);
    let d = received(&bob, 4);
    let (note, nonce) = issuer.issue(&d);
    let unlinked = issuer.unlink(&note, &d, nonce);
    assert!(Session::start(&issuer.keyset, &unlinked, &d).is_err());
    assert!(Session::start(&issuer.keyset, &note, &received(&bob, 4)).is_err());
    let other = IssuerKeys::random(3).unwrap().keyset().unwrap();
    assert!(Session::start(&other, &note, &d).is_err());
    let session = Session::start(&issuer.keyset, &note, &d).unwrap();
    assert!(session
        .finish(&other, &Answer::from_bytes([1; 32]).unwrap())
        .is_err());
    // A wrong answer does not complete the session.
    assert!(session
        .finish(&issuer.keyset, &Answer::from_bytes([1; 32]).unwrap())
        .is_err());
    assert!(Answer::from_bytes([0xff; 32]).is_err());
}

#[test]
fn requests_roundtrip_and_refuse_malformed_bytes() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let (note, _) = issuer.issue(&d);
    let request = *Session::start(&issuer.keyset, &note, &d).unwrap().request();
    let bytes = request.to_bytes();
    assert_eq!(&bytes[..10], b"LICASH-UL\x02");
    assert_eq!(Request::from_bytes(&bytes).unwrap(), request);
    assert_eq!(request.keyset(), issuer.keyset.id());
    assert_eq!(request.denomination(), 4);
    assert_eq!(request.blinded(), d.blinded().unwrap());
    for n in 0..bytes.len() {
        assert!(Request::from_bytes(&bytes[..n]).is_err());
    }
    assert!(Request::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    for (at, value) in [
        (0, vec![b'X']),
        (REQUEST_BYTES - 32, vec![0; 32]),
        (REQUEST_BYTES - 32, vec![0xff; 32]),
        (50, vec![0; 33]),
        (50, vec![0x05]),
    ] {
        let mut b = bytes;
        b[at..at + value.len()].copy_from_slice(&value);
        assert!(Request::from_bytes(&b).is_err(), "byte {at}");
    }
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(json, format!("\"{}\"", hex::encode(bytes)));
    assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), request);
    let bin = bincode::serialize(&request).unwrap();
    assert_eq!(bincode::deserialize::<Request>(&bin).unwrap(), request);
}

#[test]
fn derived_nonces_are_fixed_by_their_secret_and_output() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let output = Output::from_derivation(&d).unwrap();
    let commit = |secret: &[u8; 32], keyset: &Keyset, output: &Output| {
        Nonce::derive(secret, keyset, output)
            .unwrap()
            .commit()
            .unwrap()
    };
    let nonce = commit(&[9; 32], &issuer.keyset, &output);
    assert_eq!(commit(&[9; 32], &issuer.keyset, &output), nonce);
    assert_ne!(commit(&[8; 32], &issuer.keyset, &output), nonce);
    let other = Output::from_derivation(&received(&owner(2), 4)).unwrap();
    assert_ne!(commit(&[9; 32], &issuer.keyset, &other), nonce);
    let unlinkable = Output::new(4, output.blinded(), [3; 32]).unwrap();
    assert_ne!(commit(&[9; 32], &issuer.keyset, &unlinkable), nonce);
    let keyset = IssuerKeys::random(3).unwrap().keyset().unwrap();
    assert_ne!(commit(&[9; 32], &keyset, &output), nonce);
    let big = Output::new(16, output.blinded(), *output.unlink_commitment()).unwrap();
    assert!(Nonce::derive(&[9; 32], &issuer.keyset, &big).is_err());
}

#[test]
fn sessions_persist_and_issuers_keep_nonce_secrets_and_answers() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let output = Output::from_derivation(&d).unwrap();
    let note = issuer.issue_under(
        &d,
        &Nonce::derive(&[9; 32], &issuer.keyset, &output).unwrap(),
    );
    let session = Session::start(&issuer.keyset, &note, &d).unwrap();
    let session: Session = bincode::deserialize(&bincode::serialize(&session).unwrap()).unwrap();
    let session: Session = serde_json::from_str(&serde_json::to_string(&session).unwrap()).unwrap();
    // The issuer keeps the secret, not the nonce, and derives it again.
    let nonce = Nonce::derive(&[9; 32], &issuer.keyset, &output).unwrap();
    assert_eq!(format!("{nonce:?}"), "UnlinkNonce(..)");
    let answered = nonce.answer(&issuer.keys, session.request()).unwrap();
    let bytes = answered.to_bytes();
    assert_eq!(bytes.len(), ANSWERED_BYTES);
    assert_eq!(&bytes[..REQUEST_BYTES], &session.request().to_bytes());
    let answered = Answered::from_bytes(&bytes).unwrap();
    for length in [0, REQUEST_BYTES, ANSWERED_BYTES - 1, ANSWERED_BYTES + 1] {
        let mut wrong = bytes.to_vec();
        wrong.resize(length, 0);
        assert!(Answered::from_bytes(&wrong).is_err());
    }
    let mut overflow = bytes;
    overflow[REQUEST_BYTES..].fill(0xff);
    assert!(Answered::from_bytes(&overflow).is_err());
    let answer = answered.replay(session.request()).unwrap();
    let answer: Answer = serde_json::from_str(&serde_json::to_string(&answer).unwrap()).unwrap();
    let unlinked = session.finish(&issuer.keyset, &answer).unwrap();
    assert_unlinked(&issuer, &note, &unlinked);
    assert_eq!(format!("{session:?}"), "UnlinkSession(..)");
    assert_eq!(format!("{answered:?}"), "UnlinkAnswered(..)");
    assert_eq!(format!("{:?}", session.request()), "UnlinkRequest(..)");
}

#[test]
fn issuances_roundtrip_under_their_keyset_only() {
    let issuer = issuer();
    let d = received(&owner(2), 4);
    let output = Output::from_derivation(&d).unwrap();
    let nonce = Nonce::new(&issuer.keyset, &output).unwrap();
    let issued = nonce.issue(&issuer.keys).unwrap();
    let bytes = issued.to_bytes();
    // Tag, keyset, denomination, B, C', DLEQ, R1, R2.
    assert_eq!(bytes.len(), 10 + 32 + 8 + 33 + 33 + 64 + 33 + 33);
    assert_eq!(
        MintResponse::from_bytes(&issuer.keyset, &bytes).unwrap(),
        issued
    );
    let other = self::issuer();
    assert!(MintResponse::from_bytes(&other.keyset, &bytes).is_err());
    assert!(nonce.issue(&other.keys).is_err());
    // Any change to the signature or proof, or a cut, is refused.
    for at in [10 + 32 + 8 + 33 + 5, 10 + 32 + 8 + 33 + 33 + 7] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(MintResponse::from_bytes(&issuer.keyset, &bad).is_err());
    }
    assert!(MintResponse::from_bytes(&issuer.keyset, &bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(MintResponse::from_bytes(&issuer.keyset, &longer).is_err());
    // Only the holder of the derivation opens it.
    assert!(issued
        .open(&issuer.keyset, &received(&owner(3), 4))
        .is_err());
}
