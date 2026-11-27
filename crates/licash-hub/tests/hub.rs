use std::path::{Path, PathBuf};

use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, Grant, PreparedGrant, SignedProposal},
    claim::Branch,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{ChainProfile, Output, Proposal, TimedLock, TimedTerms},
    unlink::{Nonce, Request, Session},
};
use licash_hub::{
    Error, Fee, Hub, Ledger, Notes, Notice, Policy, Refusal, Stats, Unlinks, MAX_OFFERS,
    UNRELEASED_FOR,
};

const MAX_POW: u32 = 6;

struct Files {
    _dir: tempfile::TempDir,
    seed: PathBuf,
    db: PathBuf,
}

fn files() -> Files {
    let dir = tempfile::tempdir().unwrap();
    let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
    Hub::init(&seed, &db, MAX_POW).unwrap();
    Files {
        _dir: dir,
        seed,
        db,
    }
}

fn open(files: &Files, policy: Policy) -> Hub {
    Hub::open(&files.seed, &files.db, policy).unwrap()
}

fn fee(base: u64, ppm: u64) -> Policy {
    Policy {
        spend: Fee { base, ppm },
        ..Policy::default()
    }
}

/// The hub's issuer keys, from its seed file: what it issued earlier.
fn issuer(files: &Files) -> (IssuerKeys, Keyset) {
    let mut seed = [0; 32];
    hex::decode_to_slice(
        std::fs::read_to_string(&files.seed).unwrap().trim(),
        &mut seed,
    )
    .unwrap();
    let keys = IssuerKeys::from_seed(&seed, 0, MAX_POW).unwrap();
    let keyset = keys.keyset().unwrap();
    (keys, keyset)
}

fn owner(seed: u8) -> OwnerKeys {
    OwnerKeys::from_seed(&[seed; 32]).unwrap()
}

/// A note of `denom` to `to`, as issued before the hub's ledger began.
fn mint(files: &Files, to: &OwnerKeys, denom: u64) -> Coin {
    let (keys, keyset) = issuer(files);
    mint_under(&keys, &keyset, to, denom)
}

fn mint_under(keys: &IssuerKeys, keyset: &Keyset, to: &OwnerKeys, denom: u64) -> Coin {
    let d = Ephemeral::random()
        .derive(&to.address(), denom, Branch::Pay, 0)
        .unwrap();
    let output = Output::from_derivation(&d).unwrap();
    let proof = keys.prove_blinded(denom, output.blinded()).unwrap();
    let note = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: Nonce::new(keyset, &output).unwrap().commit().unwrap(),
        },
    )
    .unwrap();
    Coin {
        note,
        derivation: d,
        owner: to.clone(),
    }
}

#[derive(Clone)]
struct Coin {
    note: Note,
    derivation: Derivation,
    owner: OwnerKeys,
}

/// A spend of `inputs` to `outputs`, with the derivations of its outputs.
struct Spend {
    inputs: Vec<Coin>,
    proposal: Proposal,
    outputs: Vec<Derivation>,
}

impl Spend {
    fn new(keyset: &Keyset, inputs: &[Coin], outputs: &[(Address, u64)]) -> Self {
        let e = Ephemeral::random();
        let outputs: Vec<Derivation> = outputs
            .iter()
            .enumerate()
            .map(|(i, (to, denom))| e.derive(to, *denom, Branch::Pay, i).unwrap())
            .collect();
        let proposal = Proposal::new(
            keyset,
            &notes(inputs),
            e.public(),
            outputs
                .iter()
                .map(|d| Output::from_derivation(d).unwrap())
                .collect(),
            None,
        )
        .unwrap();
        Self {
            inputs: inputs.to_vec(),
            proposal,
            outputs,
        }
    }

    fn notes(&self) -> Vec<Note> {
        notes(&self.inputs)
    }

    fn offer(&self, hub: &Hub) -> Result<Grant, Error> {
        hub.offer(&self.proposal, &self.notes())
    }

    fn sign(&self, keyset: &Keyset, authorization: Authorization) -> SignedProposal {
        let secrets: Vec<_> = self
            .inputs
            .iter()
            .map(|c| {
                c.derivation
                    .ownership()
                    .owner_secret(c.owner.spend_secret())
                    .unwrap()
            })
            .collect();
        SignedProposal::sign(
            keyset,
            self.proposal.clone(),
            &self.notes(),
            authorization,
            &secrets,
        )
        .unwrap()
    }

    /// Offer, sign and release: the notes of the outputs.
    fn complete(&self, hub: &Hub, keyset: &Keyset) -> Vec<Note> {
        let grant = self.offer(hub).unwrap();
        let signed = self.sign(keyset, Authorization::Granted(Box::new(grant)));
        let unlock = hub.release(&signed, &self.notes()).unwrap();
        (0..self.outputs.len())
            .map(|i| {
                signed
                    .open_granted_output(keyset, &self.notes(), i, &self.outputs[i], &unlock)
                    .unwrap()
            })
            .collect()
    }

    fn coin(&self, notes: &[Note], index: usize, owner: &OwnerKeys) -> Coin {
        Coin {
            note: notes[index].clone(),
            derivation: self.outputs[index].clone(),
            owner: owner.clone(),
        }
    }
}

fn notes(coins: &[Coin]) -> Vec<Note> {
    coins.iter().map(|c| c.note.clone()).collect()
}

fn refused(result: Result<impl Sized, Error>) -> Refusal {
    match result {
        Err(Error::Refused(refusal)) => refusal,
        Err(e) => panic!("expected a refusal, got {e}"),
        Ok(_) => panic!("expected a refusal"),
    }
}

fn setup_error(result: Result<impl Sized, Error>) -> String {
    match result {
        Err(Error::Setup(why)) => why,
        Err(e) => panic!("expected a setup error, got {e}"),
        Ok(_) => panic!("expected a setup error"),
    }
}

fn notices(hub: &Hub) -> Vec<Notice> {
    hub.events(0, 100)
        .unwrap()
        .into_iter()
        .map(|e| e.notice().unwrap())
        .collect()
}

/// `request` with another capability.
fn forge(request: &Request) -> Request {
    let mut bytes = request.to_bytes();
    bytes[10 + 32 + 8 + 33] ^= 1;
    Request::from_bytes(&bytes).unwrap()
}

fn sql(db: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(db).unwrap()
}

#[test]
fn init_never_replaces_a_seed_or_ledger_and_open_needs_both_matching() {
    let a = files();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&a.seed).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let seed = std::fs::read(&a.seed).unwrap();
    let dir = a.db.parent().unwrap();
    let (other_seed, other_db) = (dir.join("other-seed"), dir.join("other.sqlite"));
    setup_error(Hub::init(&a.seed, &a.db, MAX_POW));
    setup_error(Hub::init(&other_seed, &a.db, MAX_POW));
    assert!(!other_seed.exists());
    // A fresh ledger for an existing seed would take its spent notes again.
    setup_error(Hub::init(&a.seed, &other_db, MAX_POW));
    assert!(!other_db.exists());
    assert_eq!(std::fs::read(&a.seed).unwrap(), seed);
    setup_error(Hub::init(&other_seed, &other_db, 63));
    assert!(!other_seed.exists() && !other_db.exists());

    setup_error(Hub::open(&other_seed, &a.db, Policy::default()));
    setup_error(Hub::open(&a.seed, &other_db, Policy::default()));
    assert!(!other_db.exists());
    let b = files();
    let why = setup_error(Hub::open(&b.seed, &a.db, Policy::default()));
    assert!(why.contains("does not match"), "{why}");

    let hub = open(&a, Policy::default());
    let why = setup_error(Hub::open(&a.seed, &a.db, Policy::default()));
    assert!(why.contains("another hub"), "{why}");
    drop(hub);
    sql(&a.db)
        .execute(
            "UPDATE schema_versions SET version = 5 WHERE component = 'ledger'",
            [],
        )
        .unwrap();
    let why = setup_error(Hub::open(&a.seed, &a.db, Policy::default()));
    assert!(why.contains("schema 5"), "{why}");
    // A ledger of the release before holds notes of the note format v4:
    // refused by its schema, and told what to do with it.
    sql(&a.db)
        .execute(
            "UPDATE schema_versions SET version = 3 WHERE component = 'ledger'",
            [],
        )
        .unwrap();
    let why = setup_error(Hub::open(&a.seed, &a.db, Policy::default()));
    assert!(
        why.contains("schema 3") && why.contains("earlier release") && why.contains("init"),
        "{why}"
    );
    // One of the release before that holds notes of the note format v2:
    // refused by its schema, not taken for another hub's seed.
    sql(&a.db)
        .execute(
            "UPDATE schema_versions SET version = 1 WHERE component = 'ledger'",
            [],
        )
        .unwrap();
    let why = setup_error(Hub::open(&a.seed, &a.db, Policy::default()));
    assert!(why.contains("schema 1"), "{why}");
}

/// The keyset the hub issues under is its first by index, whatever the
/// order of their ids, which is the order it lists them in.
#[test]
fn a_hub_issues_under_its_keyset_of_the_lowest_index() {
    let files = files();
    let (_, first) = issuer(&files);
    assert_eq!(open(&files, Policy::default()).issuing().id(), first.id());
    // A later keyset of an id before the first's.
    let mut seed = [0; 32];
    let text = std::fs::read_to_string(&files.seed).unwrap();
    hex::decode_to_slice(text.trim(), &mut seed).unwrap();
    // The seed is random, and 63 indexes held an id below the first's only
    // 63 times in 64: any index will do, so look until one does.
    let (index, later) = (1..)
        .map(|index| (index, IssuerKeys::from_seed(&seed, index, MAX_POW).unwrap()))
        .find(|(_, keys)| keys.id() < first.id())
        .unwrap();
    sql(&files.db)
        .execute(
            "INSERT INTO keysets (id, idx, max_pow, created_at) VALUES (?1, ?2, ?3, 0)",
            rusqlite::params![later.id(), index, MAX_POW],
        )
        .unwrap();
    let hub = open(&files, Policy::default());
    let listed: Vec<_> = hub.info().keysets.iter().map(|k| *k.id()).collect();
    assert_eq!(listed, [*later.id(), *first.id()]);
    assert_eq!(hub.issuing().id(), first.id());
}

#[test]
fn a_hub_names_one_nostr_key_of_its_seed_across_restarts() {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    let (a, b) = (files(), files());
    let hub = open(&a, Policy::default());
    let secret = hub.nostr_secret().unwrap();
    let named = hub.advertise().unwrap().nostr.unwrap();
    let pair = Keypair::from_seckey_slice(&Secp256k1::new(), &secret).unwrap();
    assert_eq!(named, hex::encode(pair.x_only_public_key().0.serialize()));
    let seed = std::fs::read_to_string(&a.seed).unwrap();
    assert_ne!(hex::encode(secret), seed.trim());
    drop(hub);
    let again = open(&a, Policy::default());
    assert_eq!(again.nostr_secret().unwrap(), secret);
    assert_eq!(again.advertise().unwrap().nostr.unwrap(), named);
    assert_ne!(open(&b, Policy::default()).nostr_secret().unwrap(), secret);
}

#[test]
fn a_hub_claims_each_deposit_with_a_key_of_its_own_seed() {
    let (a, b) = (files(), files());
    let hub = open(&a, Policy::default());
    let (one, two) = (
        hub.deposit_secret(&[1; 32]).unwrap(),
        hub.deposit_secret(&[2; 32]).unwrap(),
    );
    assert_ne!(one, two);
    assert_ne!(one, hub.nostr_secret().unwrap());
    drop(hub);
    assert_eq!(
        open(&a, Policy::default())
            .deposit_secret(&[1; 32])
            .unwrap(),
        one
    );
    assert_ne!(
        open(&b, Policy::default())
            .deposit_secret(&[1; 32])
            .unwrap(),
        one
    );
}

#[test]
fn fees_round_up_and_saturate() {
    let fee = Fee { base: 3, ppm: 1 };
    assert_eq!(fee.due(0), 3);
    assert_eq!(fee.due(1), 4);
    assert_eq!(fee.due(1_000_000), 4);
    assert_eq!(fee.due(1_000_001), 5);
    assert_eq!(Fee { base: 0, ppm: 0 }.due(u64::MAX), 0);
    assert_eq!(
        Fee {
            base: 1,
            ppm: 2_000_000
        }
        .due(u64::MAX),
        u64::MAX
    );
    assert_eq!(Policy::default().spend.due(8), 0);
}

#[test]
fn a_spend_is_offered_once_released_once_and_pays_the_hub() {
    let files = files();
    let hub = open(&files, fee(1, 0));
    let (_, keyset) = issuer(&files);
    let info = hub.info();
    assert_eq!(info.keysets, vec![keyset.clone()]);
    assert_eq!(info.policy, fee(1, 0));
    assert_eq!(hub.keyset(keyset.id()), Some(&keyset));
    let (alice, bob) = (owner(1), owner(2));
    let coin = mint(&files, &alice, 8);
    let spend = Spend::new(
        &keyset,
        &[coin],
        &[
            (bob.address(), 4),
            (alice.address(), 2),
            (info.address, 1),
            (alice.address(), 1),
        ],
    );
    let grant = spend.offer(&hub).unwrap();
    grant.verify(&keyset, &spend.proposal).unwrap();
    assert_eq!(spend.offer(&hub).unwrap(), grant);
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant.clone())));
    let unlock = hub.release(&signed, &spend.notes()).unwrap();
    assert_eq!(hub.release(&signed, &spend.notes()).unwrap(), unlock);
    // Owners sign afresh; the release is the same.
    let again = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
    assert_eq!(hub.release(&again, &spend.notes()).unwrap(), unlock);
    for (index, d) in spend.outputs.iter().enumerate() {
        let note = signed
            .open_granted_output(&keyset, &spend.notes(), index, d, &unlock)
            .unwrap();
        note.verify(&keyset).unwrap();
    }
    let proposal = hex::encode(spend.proposal.id().as_bytes());
    assert!(matches!(&notices(&hub)[..], [
        Notice::Started { .. },
        Notice::Released { proposal: p, amount: 8, fee: 1 },
    ] if *p == proposal));
    let events = hub.events(1, 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 2);
    assert!(hub.events(2, 10).unwrap().is_empty());
    assert_eq!(hub.events(0, 1).unwrap().len(), 1);
    let income: (i64, i64) = sql(&files.db)
        .query_row("SELECT count(*), sum(denom) FROM income", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(income, (1, 1));
}

/// A claim of `coins`, as a holder files it in a contract at the hub.
fn claim_of(keyset: &Keyset, coins: &[&Coin]) -> licash::claim::UnsignedClaim {
    claim_in([7; 32], keyset, coins)
}

/// A claim of `coins` in the contract of Base digest `base`.
fn claim_in(base: [u8; 32], keyset: &Keyset, coins: &[&Coin]) -> licash::claim::UnsignedClaim {
    use licash::claim::{Context, Item, Parts, UnsignedClaim};
    let items: Vec<_> = coins
        .iter()
        .map(|c| Item::Settled(c.note.message().clone()))
        .collect();
    let mut authorizations: Vec<_> = items.iter().map(|i| i.message().clone()).collect();
    authorizations.sort_by_key(|m| m.identifier().unwrap());
    let context = Context {
        base,
        deposit: [8; 36],
        cap: 1_000,
    };
    let parts = Parts {
        items,
        sources: vec![],
        activations: vec![],
        authorizations,
    };
    UnsignedClaim::new(context, keyset, 1, parts, 16).unwrap()
}

#[test]
fn a_claim_of_notes_the_hub_released_a_spend_of_meets_that_spend_and_its_unlock() {
    use licash::recovery::Evidence as Against;
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (spent, kept) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    // Nothing against notes the ledger never retired.
    assert!(hub
        .evidence(&claim_of(&keyset, &[&spent, &kept]))
        .unwrap()
        .is_empty());
    let spend = Spend::new(&keyset, std::slice::from_ref(&spent), &[(bob.address(), 8)]);
    let grant = spend.offer(&hub).unwrap();
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant.clone())));
    let unlock = hub.release(&signed, &spend.notes()).unwrap();

    let found = hub.evidence(&claim_of(&keyset, &[&kept, &spent])).unwrap();
    let [Against::Spend {
        signed: cited,
        notes,
        unlock: Some(cited_unlock),
    }] = &found[..]
    else {
        panic!("not the released spend alone");
    };
    assert_eq!(cited.proposal().id(), spend.proposal.id());
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].to_bytes(), spent.note.to_bytes());
    assert_eq!(*cited_unlock, unlock);
    grant.verify_unlock(&keyset, cited_unlock).unwrap();
    // The same ledger, the same evidence, across a restart.
    drop(hub);
    let hub = open(&files, Policy::default());
    let again = hub.evidence(&claim_of(&keyset, &[&spent])).unwrap();
    assert_eq!(
        licash::recovery::evidence_to_bytes(&again),
        licash::recovery::evidence_to_bytes(&found)
    );
    // The unlock cited is the one the ledger kept at the release, not one
    // derived again: another kept in its place is the one cited.
    drop(hub);
    let conn = sql(&files.db);
    let kept: Vec<([u8; 32], [u8; 32])> = conn
        .prepare("SELECT id, unlock FROM released_unlocks")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(kept, [(*spend.proposal.id().as_bytes(), unlock)]);
    conn.execute("UPDATE released_unlocks SET unlock = ?1", [[7u8; 32]])
        .unwrap();
    drop(conn);
    let hub = open(&files, Policy::default());
    let cited = hub.evidence(&claim_of(&keyset, &[&spent])).unwrap();
    assert!(matches!(&cited[..], [Against::Spend { unlock: Some(u), .. }] if *u == [7; 32]));
    // Its payee is given the hub's own again all the same.
    assert_eq!(hub.release(&signed, &spend.notes()).unwrap(), unlock);
}

/// A standby opens a copy of the ledger with the keys its hub wrote for it
/// and no seed: it cites what the hub cites against a claim, a released
/// spend with its unlock among it, and retires what a claim gives up, and
/// signs for the witnesses as the hub. It issues nothing, releases nothing
/// and has no key of the hub's notes, deposits or Nostr identity.
#[test]
fn a_standby_cites_and_retires_as_its_hub_and_holds_no_key_that_issues() {
    let files = files();
    let hub = open(&files, Policy::default());
    assert!(!hub.standby());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let [spent, kept, claimed] = [8, 4, 2].map(|denom| mint(&files, &alice, denom));
    let spend = Spend::new(&keyset, std::slice::from_ref(&spent), &[(bob.address(), 8)]);
    let grant = spend.offer(&hub).unwrap();
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
    let unlock = hub.release(&signed, &spend.notes()).unwrap();
    let first = filed([7; 32], &keyset, &[&claimed]);
    hub.retire_claimed(&[1; 32], &first.held(), &[]).unwrap();
    let claim = claim_of(&keyset, &[&spent, &kept]);
    let second = filed([9; 32], &keyset, &[&claimed]);
    let evidence = |hub: &Hub| {
        [&claim, second.claim()]
            .map(|claim| licash::recovery::evidence_to_bytes(&hub.evidence(claim).unwrap()))
    };
    let found = evidence(&hub);
    assert!(found.iter().all(|bytes| !bytes.is_empty()));
    let (info, witness) = (hub.info(), hub.witness_secret());
    let keys = files.db.with_file_name("standby.json");
    // Beside the running hub.
    let write = |path: &Path| licash_hub::write_standby_keys(&files.seed, &files.db, path);
    write(&keys).unwrap();
    // Never over a file there, and its owner's alone to read.
    assert!(setup_error(write(&keys)).contains("exists"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&keys).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // The witness key and what the hub publishes: nothing of its seed.
    let text = std::fs::read_to_string(&keys).unwrap();
    let seed = std::fs::read_to_string(&files.seed).unwrap();
    assert!(!text.contains(seed.trim()));
    assert!(text.contains(&hex::encode(witness)));
    assert_eq!(licash_hub::standby_witness_secret(&keys).unwrap(), witness);
    drop(hub);

    let standby = Hub::open_standby(&keys, &files.db, Policy::default()).unwrap();
    assert!(standby.standby());
    assert_eq!(standby.witness_secret(), witness);
    assert_eq!(standby.info().keysets, info.keysets);
    assert_eq!(standby.info().address.to_bytes(), info.address.to_bytes());
    assert_eq!(standby.issuing().id(), keyset.id());
    // The same evidence, the released spend's unlock in it.
    assert_eq!(evidence(&standby), found);
    let cited = standby.evidence(&claim).unwrap();
    assert!(matches!(
        &cited[..],
        [licash::recovery::Evidence::Spend { unlock: Some(u), .. }] if *u == unlock
    ));
    // What a claim gives up is retired, and cited against the next.
    let third = filed([5; 32], &keyset, &[&kept]);
    standby
        .retire_claimed(&[2; 32], &third.held(), &[])
        .unwrap();
    let y = kept.note.message().identifier().unwrap();
    assert_eq!(standby.spent(&[y]).unwrap(), [true]);
    let again = filed([6; 32], &keyset, &[&kept]);
    assert_eq!(standby.evidence(again.claim()).unwrap().len(), 1);
    standby.alert("told").unwrap();
    // Nothing its seed alone does.
    let fresh = mint(&files, &alice, 16);
    let late = Spend::new(
        &keyset,
        std::slice::from_ref(&fresh),
        &[(bob.address(), 16)],
    );
    let no_seed = |why: String| assert!(why.contains("a standby holds no seed"), "{why}");
    no_seed(setup_error(late.offer(&standby)));
    no_seed(setup_error(standby.release(&signed, &spend.notes())));
    no_seed(setup_error(standby.nostr_secret()));
    no_seed(setup_error(standby.deposit_secret(&[1; 32])));
    no_seed(setup_error(standby.deposit_root_secret()));
    no_seed(setup_error(standby.advertise()));
    let y = fresh.note.message().identifier().unwrap();
    assert_eq!(standby.spent(&[y]).unwrap(), [false]);
    drop(standby);
    // The hub, on the ledger its standby wrote: what it retired stands.
    let hub = open(&files, Policy::default());
    assert_eq!(hub.evidence(again.claim()).unwrap().len(), 1);
}

/// A standby is refused a ledger that does not keep the unlock of every
/// spend released, which it could not cite; keys that are not its hub's;
/// and a file that is not its keys.
#[test]
fn a_standby_opens_only_a_ledger_it_can_cite_from_with_its_hubs_keys() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let coin = mint(&files, &alice, 8);
    let spend = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
    let grant = spend.offer(&hub).unwrap();
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
    hub.release(&signed, &spend.notes()).unwrap();
    // One offered and not released needs no unlock kept.
    let other = mint(&files, &alice, 4);
    Spend::new(&keyset, std::slice::from_ref(&other), &[(bob.address(), 4)])
        .offer(&hub)
        .unwrap();
    let keys = files.db.with_file_name("standby.json");
    licash_hub::write_standby_keys(&files.seed, &files.db, &keys).unwrap();
    // Not with another hub's seed.
    let theirs = self::files();
    let their_keys = theirs.db.with_file_name("standby.json");
    let mixed = licash_hub::write_standby_keys(&theirs.seed, &files.db, &their_keys);
    assert!(setup_error(mixed).contains("the seed does not match"));
    assert!(!their_keys.exists());
    // While the hub runs on it: one hub a database.
    let standby = || Hub::open_standby(&keys, &files.db, Policy::default());
    assert!(setup_error(standby()).contains("another hub"));
    drop(hub);
    drop(standby().unwrap());

    // A released spend whose unlock a release of before did not keep.
    let conn = sql(&files.db);
    let kept: Vec<u8> = conn
        .query_row("SELECT unlock FROM released_unlocks", [], |r| r.get(0))
        .unwrap();
    conn.execute("DELETE FROM released_unlocks", []).unwrap();
    drop(conn);
    let why = setup_error(standby());
    assert!(why.contains("1 spends it released have none kept"), "{why}");
    assert!(why.contains("with its seed"), "{why}");
    // A ledger of a release that kept none: not made here, which a seed
    // alone fills.
    let conn = sql(&files.db);
    conn.execute_batch(
        "DROP TABLE released_unlocks;
         DELETE FROM schema_versions WHERE component = 'unlocks';",
    )
    .unwrap();
    drop(conn);
    let why = setup_error(standby());
    assert!(why.contains("of a release that kept none"), "{why}");
    let conn = sql(&files.db);
    let tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'released_unlocks'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0);
    drop(conn);
    // The hub's start with its seed keeps them; its standby opens then.
    drop(open(&files, Policy::default()));
    let conn = sql(&files.db);
    let again: Vec<u8> = conn
        .query_row("SELECT unlock FROM released_unlocks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(again, kept);
    drop(conn);
    drop(standby().unwrap());

    // Another hub's keys.
    licash_hub::write_standby_keys(&theirs.seed, &theirs.db, &their_keys).unwrap();
    let why = setup_error(Hub::open_standby(&their_keys, &files.db, Policy::default()));
    assert!(why.contains("do not match the database"), "{why}");
    // Not its keys: a seed, a file of another format, none.
    for (text, why) in [
        (
            std::fs::read_to_string(&files.seed).unwrap(),
            "standby keys",
        ),
        (
            std::fs::read_to_string(&keys)
                .unwrap()
                .replace("\"standby\": 1", "\"standby\": 2"),
            "not of format 1",
        ),
    ] {
        let path = files.db.with_file_name("other.json");
        std::fs::write(&path, text).unwrap();
        let error = setup_error(Hub::open_standby(&path, &files.db, Policy::default()));
        assert!(error.contains(why), "{error}");
        assert!(licash_hub::standby_witness_secret(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }
    let none = files.db.with_file_name("none.json");
    let error = setup_error(Hub::open_standby(&none, &files.db, Policy::default()));
    assert!(error.contains("standby keys"), "{error}");
}

/// A ledger of before unlocks were kept has no tables of them: the hub's
/// next start with its seed makes them and keeps the unlock of each grant
/// released until then, and its evidence is what it was. So does it keep
/// one a release of before left out since, and no other.
#[test]
fn a_ledger_of_before_keeps_the_unlocks_of_its_released_grants_at_its_hubs_start() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let coins = [8, 4, 2].map(|denom| mint(&files, &alice, denom));
    let spends: Vec<Spend> = (coins.iter().zip([8, 4, 2]))
        .map(|(coin, denom)| {
            Spend::new(
                &keyset,
                std::slice::from_ref(coin),
                &[(bob.address(), denom)],
            )
        })
        .collect();
    // Two released, one offered only.
    let mut unlocks = Vec::new();
    for spend in &spends[..2] {
        let grant = spend.offer(&hub).unwrap();
        let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
        unlocks.push((
            *spend.proposal.id().as_bytes(),
            hub.release(&signed, &spend.notes()).unwrap(),
        ));
    }
    spends[2].offer(&hub).unwrap();
    unlocks.sort();
    let claim = claim_of(&keyset, &[&coins[0], &coins[1], &coins[2]]);
    let found = licash::recovery::evidence_to_bytes(&hub.evidence(&claim).unwrap());
    drop(hub);
    let kept = |conn: &rusqlite::Connection| -> Vec<([u8; 32], [u8; 32])> {
        conn.prepare("SELECT id, unlock FROM released_unlocks ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    // As a hub of before left it.
    let conn = sql(&files.db);
    assert_eq!(kept(&conn), unlocks);
    conn.execute_batch(
        "DROP TABLE released_unlocks;
         DELETE FROM schema_versions WHERE component = 'unlocks';",
    )
    .unwrap();
    drop(conn);
    let hub = open(&files, Policy::default());
    assert_eq!(
        licash::recovery::evidence_to_bytes(&hub.evidence(&claim).unwrap()),
        found
    );
    drop(hub);
    let conn = sql(&files.db);
    assert_eq!(kept(&conn), unlocks);
    // One a release of before left out, having released its grant on
    // this file since: kept at the next start, the others as they are.
    conn.execute("DELETE FROM released_unlocks WHERE id = ?1", [unlocks[0].0])
        .unwrap();
    conn.execute("UPDATE released_unlocks SET unlock = ?1", [[7u8; 32]])
        .unwrap();
    drop(conn);
    drop(open(&files, Policy::default()));
    let conn = sql(&files.db);
    assert_eq!(kept(&conn), [unlocks[0], (unlocks[1].0, [7; 32])]);
    // Tables of another version are refused, and nothing is written.
    conn.execute(
        "UPDATE schema_versions SET version = 2 WHERE component = 'unlocks'",
        [],
    )
    .unwrap();
    drop(conn);
    let error = setup_error(Hub::open(&files.seed, &files.db, Policy::default()));
    assert!(error.contains("unlocks is of version 2"), "{error}");
}

#[test]
fn spends_pay_the_policy_fee_in_outputs_to_the_hub() {
    let files = files();
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let free = open(&files, Policy::default());
    let address = free.info().address;
    drop(free);
    let coin = mint(&files, &alice, 8);
    let unpaid = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
    let paid = Spend::new(
        &keyset,
        &[coin],
        &[(bob.address(), 4), (bob.address(), 2), (address, 2)],
    );
    let hub = open(&files, fee(1, 0));
    assert_eq!(
        refused(unpaid.offer(&hub)),
        Refusal::Fee { due: 1, paid: 0 }
    );
    drop(hub);
    // 8 at 250,000 ppm is 2, plus a base of 1.
    let hub = open(&files, fee(1, 250_000));
    assert_eq!(refused(paid.offer(&hub)), Refusal::Fee { due: 3, paid: 2 });
    drop(hub);
    let hub = open(&files, fee(0, 250_000));
    paid.offer(&hub).unwrap();
}

#[test]
fn a_spend_pays_for_the_notes_it_makes_for_others_than_the_hub() {
    let files = files();
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let free = open(&files, Policy::default());
    let address = free.info().address;
    drop(free);
    let coin = mint(&files, &alice, 8);
    let spend =
        |outputs: &[(Address, u64)]| Spend::new(&keyset, std::slice::from_ref(&coin), outputs);
    let three = spend(&[
        (bob.address(), 4),
        (bob.address(), 2),
        (bob.address(), 1),
        (address, 1),
    ]);
    let two = spend(&[(bob.address(), 4), (bob.address(), 2), (address, 2)]);
    let one = spend(&[(bob.address(), 4), (address, 2), (address, 1), (address, 1)]);
    let per_note = |output_msat| Policy {
        output_msat,
        ..fee(1, 0)
    };
    // 0.6 sat a note, to the nearest sat: 2 for three notes, 1 for two,
    // beside the base of 1. The hub's own notes cost nothing.
    let hub = open(&files, per_note(600));
    assert_eq!(hub.advertise().unwrap().fees.output_msat, 600);
    assert_eq!(refused(three.offer(&hub)), Refusal::Fee { due: 3, paid: 1 });
    two.offer(&hub).unwrap();
    one.offer(&hub).unwrap();
    drop(hub);
    // A tenth of a sat a note is nothing on three notes.
    let hub = open(&files, per_note(100));
    three.offer(&hub).unwrap();
}

#[test]
fn an_input_is_spent_once_and_a_second_signed_spend_is_alerted() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob, carol) = (owner(1), owner(2), owner(3));
    let coin = mint(&files, &alice, 8);
    let first = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
    let second = Spend::new(
        &keyset,
        std::slice::from_ref(&coin),
        &[(carol.address(), 8)],
    );
    let second_grant = second.offer(&hub).unwrap();
    let y = coin.note.message().identifier().unwrap();
    let other = mint(&files, &alice, 8).note.message().identifier().unwrap();
    assert_eq!(hub.spent(&[y, other]).unwrap(), [false, false]);
    first.complete(&hub, &keyset);
    assert_eq!(hub.spent(&[y, other, y]).unwrap(), [true, false, true]);
    let signed = second.sign(&keyset, Authorization::Granted(Box::new(second_grant)));
    assert_eq!(
        refused(hub.release(&signed, &second.notes())),
        Refusal::Spent
    );
    assert_eq!(refused(second.offer(&hub)), Refusal::Spent);
    let third = Spend::new(&keyset, &[coin], &[(carol.address(), 8)]);
    assert_eq!(refused(third.offer(&hub)), Refusal::Spent);
    let (by, of) = (
        hex::encode(first.proposal.id().as_bytes()),
        hex::encode(second.proposal.id().as_bytes()),
    );
    assert!(
        matches!(notices(&hub).last(), Some(Notice::DoubleSpend { proposal, spent_by })
        if *proposal == of && *spent_by == by)
    );
    // Nothing of the refused spend was recorded.
    let issued: i64 = sql(&files.db)
        .query_row("SELECT count(*) FROM issued", [], |r| r.get(0))
        .unwrap();
    assert_eq!(issued, 1);
}

/// A spend of a note spent elsewhere is refused before the hub checks its
/// notes or makes its grant: no work for a spent note, however often.
#[test]
fn a_spent_note_is_refused_before_any_work_on_it() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob, carol) = (owner(1), owner(2), owner(3));
    let coin = mint(&files, &alice, 8);
    let first = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
    first.complete(&hub, &keyset);
    let again = Spend::new(&keyset, &[coin], &[(carol.address(), 8)]);
    // Its notes not even given: refused as spent all the same.
    assert_eq!(refused(hub.offer(&again.proposal, &[])), Refusal::Spent);
    // The spend released, offered again: its grant, as before.
    first.offer(&hub).unwrap();
    // Refused as spent from a database changed under the hub: halted
    // instead, as any write would.
    sql(&files.db)
        .execute("UPDATE meta SET seq = seq + 1", [])
        .unwrap();
    assert!(matches!(
        hub.offer(&again.proposal, &[]),
        Err(Error::Halted)
    ));
    assert!(hub.halted());
}

/// A grant left unreleased a day is deleted, its proposal with it, as
/// offers come: released after, it is an unknown offer, and offered again
/// it gets a grant anew that releases. One released, or one whose double
/// spend was refused, is kept.
#[test]
fn grants_left_unreleased_a_day_are_deleted_and_offered_again() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob, carol) = (owner(1), owner(2), owner(3));
    let pay = |to: &OwnerKeys| {
        let coin = mint(&files, &alice, 8);
        Spend::new(&keyset, &[coin], &[(to.address(), 8)])
    };
    let (left, released, double) = (pay(&bob), pay(&bob), pay(&bob));
    let grant = left.offer(&hub).unwrap();
    released.complete(&hub, &keyset);
    // Another spend of its note released first: the double spend refused.
    let other = Spend::new(
        &keyset,
        &[double.inputs[0].clone()],
        &[(carol.address(), 8)],
    );
    let doubled = double.sign(
        &keyset,
        Authorization::Granted(Box::new(double.offer(&hub).unwrap())),
    );
    other.complete(&hub, &keyset);
    assert_eq!(
        refused(hub.release(&doubled, &double.notes())),
        Refusal::Spent
    );
    let count = |table: &str| -> i64 {
        sql(&files.db)
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    };
    let (grants, proposals) = (count("grants"), count("proposals"));
    sql(&files.db)
        .execute(
            "UPDATE proposals SET created_at = created_at - ?1",
            [UNRELEASED_FOR + 1],
        )
        .unwrap();
    // Not before an offer comes, once this process deleted none yet.
    let signed = left.sign(&keyset, Authorization::Granted(Box::new(grant.clone())));
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!((count("grants"), count("proposals")), (grants, proposals));
    pay(&carol).offer(&hub).unwrap();
    assert_eq!(
        (count("grants"), count("proposals")),
        (grants, proposals),
        "one deleted, one made"
    );
    assert_eq!(
        refused(hub.release(&signed, &left.notes())),
        Refusal::UnknownOffer
    );
    // Released and double spent ones kept.
    released.complete(&hub, &keyset);
    assert_eq!(
        refused(hub.release(&doubled, &double.notes())),
        Refusal::Spent
    );
    // Offered again: a grant anew, released.
    let again = left.offer(&hub).unwrap();
    assert_ne!(again, grant);
    let signed = left.sign(&keyset, Authorization::Granted(Box::new(again)));
    hub.release(&signed, &left.notes()).unwrap();
}

/// A payer knows the notes she paid, and may offer her payee's in spends
/// of her own until the hub refuses them: an offer signed by each note's
/// hold key, which only its owner has, counts apart, so the owner still
/// offers hers. Those are as bounded, and a signature not her note's is
/// refused.
#[test]
fn a_note_offered_to_the_most_by_its_payer_is_still_offered_by_its_owner() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let pay = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    let issued = pay.complete(&hub, &keyset);
    // Opened from Alice's derivation and the hub's unlock: no key of Bob's.
    let seen = Coin {
        note: issued[0].clone(),
        derivation: pay.outputs[0].clone(),
        owner: alice.clone(),
    };
    let his = pay.coin(&issued, 0, &bob);
    let to = |k: u8, coin: &Coin| {
        Spend::new(
            &keyset,
            std::slice::from_ref(coin),
            &[(owner(10 + k).address(), 8)],
        )
    };
    let holds = |spend: &Spend, coin: &Coin| {
        let key = coin.derivation.hold_key(coin.owner.hold_root()).unwrap();
        let note = coin.note.message();
        vec![licash::offer::sign(&spend.proposal.id(), note, &key).unwrap()]
    };
    for k in 1..=MAX_OFFERS {
        to(k, &seen).offer(&hub).unwrap();
    }
    assert_eq!(refused(to(100, &his).offer(&hub)), Refusal::Offered);
    // Signed for another spend: refused.
    let forged = to(101, &his);
    let wrong = holds(&to(102, &his), &his);
    let result = hub.offer_held(&forged.proposal, &forged.notes(), Some(&wrong));
    assert!(result.is_err());
    // Bob's, signed: granted, up to the most.
    for k in 101..101 + MAX_OFFERS {
        let spend = to(k, &his);
        let signed = holds(&spend, &his);
        hub.offer_held(&spend.proposal, &spend.notes(), Some(&signed))
            .unwrap();
    }
    let spend = to(200, &his);
    let signed = holds(&spend, &his);
    let result = hub.offer_held(&spend.proposal, &spend.notes(), Some(&signed));
    assert_eq!(refused(result), Refusal::Offered);
}

/// One note is offered in so many spends not released at most by a hub
/// process: each input of a spend counts, the same spend offered again
/// does not, nor a spend refused, and a restart forgets.
#[test]
fn a_note_is_offered_in_a_bounded_number_of_spends_until_the_hub_restarts() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let alice = owner(1);
    let (coin, other) = (mint(&files, &alice, 8), mint(&files, &alice, 8));
    // Distinct spends of the same coins: to payee `k`.
    let to = |k: u8, coins: &[_]| {
        let payee = owner(10 + k).address();
        let outputs: Vec<_> = coins.iter().map(|_| (payee, 8)).collect();
        Spend::new(&keyset, coins, &outputs)
    };
    let both = [coin.clone(), other.clone()];
    // Notes that are none of the spend's: refused, counting nothing.
    for _ in 0..=MAX_OFFERS {
        assert!(hub.offer(&to(0, &both).proposal, &[]).is_err());
    }
    // One of both notes, then those of the one alone up to the most.
    let first = to(1, &both);
    let grant = first.offer(&hub).unwrap();
    for k in 2..=MAX_OFFERS {
        to(k, std::slice::from_ref(&coin)).offer(&hub).unwrap();
    }
    let over = to(MAX_OFFERS + 1, std::slice::from_ref(&coin));
    assert_eq!(refused(over.offer(&hub)), Refusal::Offered);
    assert_eq!(refused(to(0, &both).offer(&hub)), Refusal::Offered);
    // Offered before: the same grant all the same.
    assert_eq!(first.offer(&hub).unwrap(), grant);
    // The other note, counted once, offered still.
    to(2, std::slice::from_ref(&other)).offer(&hub).unwrap();
    // A restart forgets.
    drop(hub);
    let hub = open(&files, Policy::default());
    over.offer(&hub).unwrap();
}

#[test]
fn outputs_are_issued_once() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let first = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    first.complete(&hub, &keyset);
    let mut copy = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    copy.outputs = first.outputs.clone();
    copy.proposal = Proposal::new(
        &keyset,
        &copy.notes(),
        first.proposal.ephemeral(),
        first.proposal.outputs().to_vec(),
        None,
    )
    .unwrap();
    assert_eq!(refused(copy.offer(&hub)), Refusal::Reissued);
}

/// An output made again under another keyset, as by a payer who uses an
/// ephemeral key twice across keysets, is the same note: its identifier
/// does not name its keyset, so only one copy could be spent. It is
/// refused as under the first, before the payer's inputs are retired.
#[test]
fn outputs_are_issued_once_whatever_their_keyset() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let first = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    first.complete(&hub, &keyset);
    drop(hub);
    let mut seed = [0; 32];
    let text = std::fs::read_to_string(&files.seed).unwrap();
    hex::decode_to_slice(text.trim(), &mut seed).unwrap();
    let keys = IssuerKeys::from_seed(&seed, 1, MAX_POW).unwrap();
    sql(&files.db)
        .execute(
            "INSERT INTO keysets (id, idx, max_pow, created_at) VALUES (?1, 1, ?2, 0)",
            rusqlite::params![keys.id(), MAX_POW],
        )
        .unwrap();
    let hub = open(&files, Policy::default());
    let other = keys.keyset().unwrap();
    let input = mint_under(&keys, &other, &alice, 8);
    let mut copy = Spend::new(&other, std::slice::from_ref(&input), &[(bob.address(), 8)]);
    copy.outputs = first.outputs.clone();
    copy.proposal = Proposal::new(
        &other,
        &copy.notes(),
        first.proposal.ephemeral(),
        first.proposal.outputs().to_vec(),
        None,
    )
    .unwrap();
    assert_eq!(refused(copy.offer(&hub)), Refusal::Reissued);
    // The same input, to outputs of its own, is served under that keyset.
    Spend::new(&other, &[input], &[(bob.address(), 8)]).complete(&hub, &other);
}

#[test]
fn only_the_hubs_own_offers_release_and_only_untimed_spends_are_served() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (keys, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    // A grant signed under the hub's keys that the hub never offered.
    let foreign = PreparedGrant::new(&keys, &spend.proposal).unwrap().offer();
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(foreign)));
    assert_eq!(
        refused(hub.release(&signed, &spend.notes())),
        Refusal::UnknownOffer
    );
    spend.offer(&hub).unwrap();
    assert!(matches!(
        hub.release(&signed, &spend.notes()),
        Err(Error::Invalid(_))
    ));
    let plain = spend.sign(&keyset, Authorization::Plain);
    assert!(matches!(
        hub.release(&plain, &spend.notes()),
        Err(Error::Invalid(_))
    ));
    let mut wrong = spend.notes();
    wrong[0] = mint(&files, &alice, 8).note;
    assert!(matches!(
        spend.offer(&hub).and(hub.offer(&spend.proposal, &wrong)),
        Err(Error::Invalid(_))
    ));

    let other = IssuerKeys::random(MAX_POW).unwrap();
    let other_keyset = other.keyset().unwrap();
    let elsewhere = Spend::new(
        &other_keyset,
        &[mint_under(&other, &other_keyset, &alice, 8)],
        &[(bob.address(), 8)],
    );
    assert_eq!(refused(elsewhere.offer(&hub)), Refusal::UnknownKeyset);

    let terms = TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        [31; 32],
        1_000,
        3,
        [41; 32],
    )
    .unwrap();
    let coin = mint(&files, &alice, 8);
    let e = Ephemeral::random();
    let pay = e.derive(&bob.address(), 8, Branch::Pay, 0).unwrap();
    let refund = e.derive(&alice.address(), 8, Branch::Refund, 0).unwrap();
    let timed = Proposal::new(
        &keyset,
        std::slice::from_ref(&coin.note),
        e.public(),
        vec![Output::from_derivation(&pay).unwrap()],
        Some(TimedLock::new(terms, vec![Output::from_derivation(&refund).unwrap()]).unwrap()),
    )
    .unwrap();
    assert_eq!(refused(hub.offer(&timed, &[coin.note])), Refusal::Timed);
}

#[test]
fn issued_outputs_unlink_once_and_only_until_the_hub_restarts() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(
        &keyset,
        &[mint(&files, &alice, 8)],
        &[(bob.address(), 4), (alice.address(), 4)],
    );
    let notes = spend.complete(&hub, &keyset);
    let (paid, change) = (spend.coin(&notes, 0, &bob), spend.coin(&notes, 1, &alice));

    let asked = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    let session = asked.clone();
    // Without the output's capability the nonce stays unused, and the
    // output looks unknown.
    let forged = forge(session.request());
    assert_eq!(refused(hub.unlink(&forged)), Refusal::NotIssued);
    let answer = hub.unlink(session.request()).unwrap();
    let unlinked = session.finish(&keyset, &answer).unwrap();
    unlinked.verify(&keyset).unwrap();
    assert!(matches!(unlinked.evidence(), Evidence::Unlinked(_)));
    assert_eq!(hub.unlink(session.request()).unwrap(), answer);
    let other = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    assert_eq!(refused(hub.unlink(other.request())), Refusal::Unlinked);
    assert_eq!(refused(hub.unlink(&forged)), Refusal::NotIssued);

    let unknown = mint(&files, &bob, 4);
    let session = Session::start(&keyset, &unknown.note, &unknown.derivation).unwrap();
    assert_eq!(refused(hub.unlink(session.request())), Refusal::NotIssued);

    drop(hub);
    let hub = open(&files, Policy::default());
    let late = Session::start(&keyset, &change.note, &change.derivation).unwrap();
    assert_eq!(refused(hub.unlink(late.request())), Refusal::Expired);
    assert_eq!(
        refused(hub.unlink(&forge(late.request()))),
        Refusal::NotIssued
    );
    let first = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    assert_eq!(refused(hub.unlink(first.request())), Refusal::Unlinked);
    // The answer to the same request is kept across restarts.
    assert_eq!(hub.unlink(asked.request()).unwrap(), answer);
    // The change is still spendable, and its swap unlinks.
    let swap = Spend::new(&keyset, &[change], &[(alice.address(), 4)]);
    let swapped = swap.coin(&swap.complete(&hub, &keyset), 0, &alice);
    let session = Session::start(&keyset, &swapped.note, &swapped.derivation).unwrap();
    let answer = hub.unlink(session.request()).unwrap();
    session.finish(&keyset, &answer).unwrap();
}

/// An output unlinks once, to whoever asks first with its capability, and
/// its payer, who made it, has the capability: she may use up her payee's
/// unlink, leaving the note spendable and linked to her spend, never lost.
/// Documented, not prevented (`docs/hub.md`).
#[test]
fn a_payer_may_use_up_the_one_unlink_of_the_note_she_paid() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    let issued = spend.complete(&hub, &keyset);
    // Alice's view of Bob's note: what she derived.
    let seen = Coin {
        note: issued[0].clone(),
        derivation: spend.outputs[0].clone(),
        owner: alice.clone(),
    };
    let his = spend.coin(&issued, 0, &bob);
    let burnt = Session::start(&keyset, &seen.note, &seen.derivation).unwrap();
    let answer = hub.unlink(burnt.request()).unwrap();
    burnt.finish(&keyset, &answer).unwrap();
    let late = Session::start(&keyset, &his.note, &his.derivation).unwrap();
    assert_eq!(refused(hub.unlink(late.request())), Refusal::Unlinked);
    // The note is still his to spend.
    let onward = Spend::new(&keyset, &[his], &[(alice.address(), 8)]);
    onward.complete(&hub, &keyset);
}

#[test]
fn offers_survive_a_restart_and_release_after_it() {
    let files = files();
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    let hub = open(&files, Policy::default());
    let grant = spend.offer(&hub).unwrap();
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(spend.offer(&hub).unwrap(), grant);
    let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
    let unlock = hub.release(&signed, &spend.notes()).unwrap();
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(hub.release(&signed, &spend.notes()).unwrap(), unlock);
    signed
        .open_granted_output(&keyset, &spend.notes(), 0, &spend.outputs[0], &unlock)
        .unwrap();
    let started = notices(&hub)
        .iter()
        .filter(|n| matches!(n, Notice::Started { .. }))
        .count();
    assert_eq!(started, 3);
}

#[test]
fn a_database_changed_under_the_running_hub_halts_it() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    spend.offer(&hub).unwrap();
    // As a restored backup would be: one write behind.
    sql(&files.db)
        .execute("UPDATE meta SET seq = seq - 1", [])
        .unwrap();
    assert!(!hub.halted());
    assert!(matches!(spend.offer(&hub), Err(Error::Halted)));
    assert!(hub.halted());
    assert!(matches!(hub.events(0, 10), Err(Error::Halted)));
    let session =
        Session::start(&keyset, &spend.inputs[0].note, &spend.inputs[0].derivation).unwrap();
    assert!(matches!(hub.unlink(session.request()), Err(Error::Halted)));
    drop(hub);
    // A restart serves the database as it is, under a new boot.
    let hub = open(&files, Policy::default());
    spend.offer(&hub).unwrap();
}

#[test]
fn a_hub_is_shared_across_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<Hub>();
}

#[test]
fn a_hub_that_answered_halts_when_its_database_forgets_the_answer() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    let paid = spend.coin(&spend.complete(&hub, &keyset), 0, &bob);
    let first = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    hub.unlink(first.request()).unwrap();
    // As a file restored under the hub would read, with the write count
    // unchanged: the nonce looks unanswered.
    sql(&files.db)
        .execute("UPDATE issued SET answered = NULL", [])
        .unwrap();
    let second = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    assert_eq!(refused(hub.unlink(second.request())), Refusal::Unlinked);
    assert!(matches!(hub.unlink(first.request()), Err(Error::Halted)));
    assert!(matches!(hub.unlink(second.request()), Err(Error::Halted)));
}

#[test]
fn outputs_offered_before_a_restart_and_released_after_it_do_not_unlink() {
    let files = files();
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(&keyset, &[mint(&files, &alice, 8)], &[(bob.address(), 8)]);
    let hub = open(&files, Policy::default());
    spend.offer(&hub).unwrap();
    drop(hub);
    let hub = open(&files, Policy::default());
    let paid = spend.coin(&spend.complete(&hub, &keyset), 0, &bob);
    let session = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    assert_eq!(refused(hub.unlink(session.request())), Refusal::Expired);
}

#[test]
fn racing_releases_retire_an_input_once() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let signed = |coin: &Coin| {
        let spend = Spend::new(&keyset, std::slice::from_ref(coin), &[(bob.address(), 8)]);
        let grant = spend.offer(&hub).unwrap();
        let signed = spend.sign(&keyset, Authorization::Granted(Box::new(grant)));
        (signed, spend.notes())
    };
    let race = |releases: &[(SignedProposal, Vec<Note>)]| -> Vec<Result<_, Error>> {
        std::thread::scope(|scope| {
            let tasks: Vec<_> = releases
                .iter()
                .map(|(signed, notes)| scope.spawn(|| hub.release(signed, notes)))
                .collect();
            tasks.into_iter().map(|t| t.join().unwrap()).collect()
        })
    };
    // The same release four times at once.
    let same = signed(&mint(&files, &alice, 8));
    let unlocks: Vec<_> = race(&vec![same; 4])
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert!(unlocks.iter().all(|unlock| *unlock == unlocks[0]));
    // Four spends of one input at once.
    let coin = mint(&files, &alice, 8);
    let rivals: Vec<_> = (0..4).map(|_| signed(&coin)).collect();
    let results = race(&rivals);
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for result in results.into_iter().filter(Result::is_err) {
        assert_eq!(refused(result), Refusal::Spent);
    }
    let released = notices(&hub)
        .iter()
        .filter(|n| matches!(n, Notice::Released { .. }))
        .count();
    assert_eq!(released, 2);
}

#[test]
fn a_double_spend_is_alerted_once_per_proposal() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let coin = mint(&files, &alice, 8);
    let late = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
    let grant = late.offer(&hub).unwrap();
    Spend::new(&keyset, &[coin], &[(bob.address(), 8)]).complete(&hub, &keyset);
    let signed = late.sign(&keyset, Authorization::Granted(Box::new(grant)));
    for _ in 0..3 {
        assert_eq!(refused(hub.release(&signed, &late.notes())), Refusal::Spent);
    }
    let alerts = notices(&hub)
        .iter()
        .filter(|n| matches!(n, Notice::DoubleSpend { .. }))
        .count();
    assert_eq!(alerts, 1);
}

#[test]
fn an_empty_database_beside_a_seed_is_no_hub() {
    let files = files();
    let empty = files.db.with_file_name("empty.sqlite");
    std::fs::File::create(&empty).unwrap();
    let why = setup_error(Hub::open(&files.seed, &empty, Policy::default()));
    assert!(why.contains("not made by this layout"), "{why}");
    let other = files.db.with_file_name("other-seed");
    setup_error(Hub::init(&other, &empty, MAX_POW));
    assert!(!other.exists());
    assert!(Ledger::open(&empty).is_err());
}

#[test]
fn only_outputs_derived_for_the_hub_at_their_position_pay_its_fee() {
    let files = files();
    let hub = open(&files, fee(2, 0));
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let address = hub.info().address;
    let coin = mint(&files, &alice, 8);
    let spend = Spend::new(
        &keyset,
        std::slice::from_ref(&coin),
        &[(address, 2), (bob.address(), 4), (bob.address(), 2)],
    );
    // The hub's output moved to another position is not the hub's.
    let mut outputs = spend.proposal.outputs().to_vec();
    outputs.swap(0, 2);
    let moved = Proposal::new(
        &keyset,
        std::slice::from_ref(&coin.note),
        spend.proposal.ephemeral(),
        outputs,
        None,
    )
    .unwrap();
    assert_eq!(
        refused(hub.offer(&moved, std::slice::from_ref(&coin.note))),
        Refusal::Fee { due: 2, paid: 0 }
    );
    // Nor is one under another unlink commitment.
    let mut outputs = spend.proposal.outputs().to_vec();
    outputs[0] = Output::new(2, outputs[0].blinded(), [9; 32]).unwrap();
    let recommitted = Proposal::new(
        &keyset,
        std::slice::from_ref(&coin.note),
        spend.proposal.ephemeral(),
        outputs,
        None,
    )
    .unwrap();
    assert_eq!(
        refused(hub.offer(&recommitted, std::slice::from_ref(&coin.note))),
        Refusal::Fee { due: 2, paid: 0 }
    );
    spend.offer(&hub).unwrap();
}

#[test]
fn the_largest_denomination_is_spent_and_unlinked() {
    let dir = tempfile::tempdir().unwrap();
    let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
    Hub::init(&seed, &db, licash_hub::MAX_POW).unwrap();
    let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
    let mut secret = [0; 32];
    hex::decode_to_slice(std::fs::read_to_string(&seed).unwrap().trim(), &mut secret).unwrap();
    let keys = IssuerKeys::from_seed(&secret, 0, licash_hub::MAX_POW).unwrap();
    let keyset = keys.keyset().unwrap();
    let (alice, bob) = (owner(1), owner(2));
    let top = 1u64 << licash_hub::MAX_POW;
    let spend = Spend::new(
        &keyset,
        &[mint_under(&keys, &keyset, &alice, top)],
        &[(bob.address(), top)],
    );
    let paid = spend.coin(&spend.complete(&hub, &keyset), 0, &bob);
    let session = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    let answer = hub.unlink(session.request()).unwrap();
    session.finish(&keyset, &answer).unwrap();
    assert!(
        matches!(notices(&hub).last(), Some(Notice::Released { amount, .. }) if *amount == top)
    );
    setup_error(Hub::init(
        &dir.path().join("s"),
        &dir.path().join("d"),
        licash_hub::MAX_POW + 1,
    ));
}

#[test]
fn events_of_unknown_kinds_are_read_as_stored() {
    let files = files();
    let hub = open(&files, Policy::default());
    sql(&files.db)
        .execute(
            "INSERT INTO events (at, kind, json) VALUES (1, 'future', '{\"kind\":\"future\"}'),
             (2, 'broken', 'not json')",
            [],
        )
        .unwrap();
    let events = hub.events(0, 10).unwrap();
    assert_eq!(events.len(), 3);
    assert!(matches!(events[0].notice(), Some(Notice::Started { .. })));
    assert_eq!(events[1].kind, "future");
    assert_eq!(events[1].notice(), None);
    assert_eq!(events[2].data, serde_json::Value::from("not json"));
}

#[test]
fn the_ledger_reads_beside_the_running_hub_and_writes_nothing() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(
        &keyset,
        &[mint(&files, &alice, 8)],
        &[
            (bob.address(), 4),
            (bob.address(), 2),
            (hub.info().address, 2),
        ],
    );
    let paid = spend.coin(&spend.complete(&hub, &keyset), 0, &bob);
    let session = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    hub.unlink(session.request()).unwrap();
    let offer = |hub: &Hub| {
        Spend::new(&keyset, &[mint(&files, &alice, 4)], &[(bob.address(), 4)])
            .offer(hub)
            .unwrap()
    };
    offer(&hub);
    let ledger = Ledger::open(&files.db).unwrap();
    let stats = Stats {
        offers: 2,
        released: 1,
        locks: 0,
        open_locks: 0,
        spent: 1,
        issued: 3,
        unlinked: 1,
        income: 2,
        events: 2,
    };
    assert_eq!(ledger.stats().unwrap(), stats);
    assert_eq!(ledger.events(0, 10).unwrap(), hub.events(0, 10).unwrap());
    // The hub goes on writing beside it, and restarts beside it.
    offer(&hub);
    assert_eq!(ledger.stats().unwrap().offers, 3);
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(ledger.stats().unwrap().events, 3);
    assert_eq!(ledger.last_event().unwrap(), 3);
    drop(hub);
    let seq = |db: &Path| -> i64 {
        sql(db)
            .query_row("SELECT seq FROM meta", [], |r| r.get(0))
            .unwrap()
    };
    let before = seq(&files.db);
    let ledger = Ledger::open(&files.db).unwrap();
    ledger.stats().unwrap();
    ledger.events(0, 10).unwrap();
    drop(ledger);
    assert_eq!(seq(&files.db), before);
}

#[cfg(unix)]
#[test]
fn one_hub_runs_on_a_database_by_any_path() {
    let files = files();
    let alias = files.db.with_file_name("alias.sqlite");
    std::os::unix::fs::symlink(&files.db, &alias).unwrap();
    let _hub = open(&files, Policy::default());
    let why = setup_error(Hub::open(&files.seed, &alias, Policy::default()));
    assert!(why.contains("another hub"), "{why}");
}

#[test]
fn the_ledger_reads_back_the_notes_it_moved_and_the_unlinks_it_answered() {
    let files = files();
    let hub = open(&files, fee(1, 0));
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spend = Spend::new(
        &keyset,
        &[mint(&files, &alice, 8)],
        &[
            (bob.address(), 4),
            (alice.address(), 2),
            (hub.info().address, 1),
            (alice.address(), 1),
        ],
    );
    let notes = spend.complete(&hub, &keyset);
    // Bob unlinks his 4 and spends it, paying the hub again.
    let paid = spend.coin(&notes, 0, &bob);
    let session = Session::start(&keyset, &paid.note, &paid.derivation).unwrap();
    let answer = hub.unlink(session.request()).unwrap();
    let unlinked = Coin {
        note: session.finish(&keyset, &answer).unwrap(),
        ..paid
    };
    let swap = Spend::new(
        &keyset,
        &[unlinked],
        &[
            (bob.address(), 2),
            (bob.address(), 1),
            (hub.info().address, 1),
        ],
    );
    swap.complete(&hub, &keyset);

    let ledger = Ledger::open(&files.db).unwrap();
    assert!(ledger.created_at().unwrap() > 0);
    assert_eq!(ledger.tip().unwrap(), None);
    let Notes { movements, unlinks } = ledger.notes().unwrap();
    assert!(movements.iter().all(|m| m.keyset == 0));
    assert!(movements.windows(2).all(|w| w[0].at <= w[1].at));
    let moved = |issued: bool| {
        let mut moved: Vec<(u64, bool, bool)> = movements
            .iter()
            .filter(|m| m.issued == issued)
            .map(|m| (m.denom, m.hub, m.unlinked))
            .collect();
        moved.sort();
        moved
    };
    // Each spend's outputs, the hub's fee among them.
    assert_eq!(
        moved(true),
        [
            (1, false, false),
            (1, false, false),
            (1, true, false),
            (1, true, false),
            (2, false, false),
            (2, false, false),
            (4, false, false),
        ]
    );
    // The note issued before the ledger began, and Bob's unlinked 4.
    assert_eq!(moved(false), [(4, false, true), (8, false, false)]);
    assert_eq!(
        unlinks,
        [Unlinks {
            keyset: 0,
            denom: 4,
            answered: 1,
            retired: 1
        }]
    );
}

/// The claim of `coins` in the contract of Base digest `base`, as filed on
/// Bitcoin: signed by each note's hold key.
fn filed(base: [u8; 32], keyset: &Keyset, coins: &[&Coin]) -> licash::recovery::Publication {
    let holds: Vec<_> = coins
        .iter()
        .map(|c| {
            (
                c.note.message().clone(),
                c.derivation.hold_key(c.owner.hold_root()).unwrap(),
            )
        })
        .collect();
    licash::recovery::Publication::sign(claim_in(base, keyset, coins), &holds, 16).unwrap()
}

#[test]
fn a_note_a_claim_on_bitcoin_names_is_retired_for_good() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (claimed, other) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    // A spend offered before the claim is read is not released after it.
    let early = Spend::new(
        &keyset,
        std::slice::from_ref(&claimed),
        &[(bob.address(), 8)],
    );
    let grant = early.offer(&hub).unwrap();
    let y = claimed.note.message().identifier().unwrap();
    assert_eq!(hub.spent(&[y]).unwrap(), [false]);
    let contract = [1; 32];
    hub.retire_claimed(&contract, &filed([7; 32], &keyset, &[&claimed]).held(), &[])
        .unwrap();
    // Read again, as after a restart: the same.
    hub.retire_claimed(&contract, &filed([7; 32], &keyset, &[&claimed]).held(), &[])
        .unwrap();
    assert_eq!(hub.spent(&[y]).unwrap(), [true]);
    let signed = early.sign(&keyset, Authorization::Granted(Box::new(grant)));
    assert_eq!(
        refused(hub.release(&signed, &early.notes())),
        Refusal::Spent
    );
    let late = Spend::new(
        &keyset,
        std::slice::from_ref(&claimed),
        &[(bob.address(), 8)],
    );
    assert_eq!(refused(late.offer(&hub)), Refusal::Spent);
    // A note the claim does not name is spent as ever.
    Spend::new(&keyset, &[other], &[(bob.address(), 4)]).complete(&hub, &keyset);
    // Across a restart, still retired.
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(refused(late.offer(&hub)), Refusal::Spent);
    assert_eq!(hub.spent(&[y]).unwrap(), [true]);
}

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `coin`'s hold key's signature of an inquiry of `keyset` at `at`.
fn ask(
    keyset: &Keyset,
    at: u64,
    coin: &Coin,
) -> (licash::note::Message, licash::crypto::Signature) {
    let key = coin.derivation.hold_key(coin.owner.hold_root()).unwrap();
    let message = coin.note.message().clone();
    let sig = licash::inquiry::sign(keyset.id(), at, &message, &key).unwrap();
    (message, sig)
}

#[test]
fn a_holder_is_shown_what_the_hub_holds_against_her_notes_and_no_one_else() {
    use licash::recovery::{voids_note, Evidence as Against};
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (spent, kept, claimed) = (
        mint(&files, &alice, 8),
        mint(&files, &alice, 8),
        mint(&files, &alice, 4),
    );
    Spend::new(&keyset, std::slice::from_ref(&spent), &[(bob.address(), 8)])
        .complete(&hub, &keyset);
    hub.retire_claimed(&[1; 32], &filed([7; 32], &keyset, &[&claimed]).held(), &[])
        .unwrap();
    let at = unix();
    let asked: Vec<_> = [&spent, &kept, &claimed]
        .into_iter()
        .map(|c| ask(&keyset, at, c))
        .collect();
    let shown = hub.inquire(keyset.id(), at, &asked).unwrap();
    assert_eq!(shown.len(), 3);
    // The spend, with its unlock, and the claim, each proving its note spent
    // to whoever checks them; the note held against nothing shows nothing.
    assert!(matches!(
        &shown[0][..],
        [Against::Spend {
            unlock: Some(_),
            ..
        }]
    ));
    assert!(shown[1].is_empty());
    assert!(matches!(&shown[2][..], [Against::SecondClaim { .. }]));
    for (coin, shown) in [&spent, &claimed].into_iter().zip([&shown[0], &shown[2]]) {
        assert!(voids_note(&keyset, coin.note.message(), &shown[0]).unwrap());
    }
    assert!(!voids_note(&keyset, kept.note.message(), &shown[0][0]).unwrap());

    // Nobody who cannot sign for a note learns its state: a signature of
    // another note's key, of another time, or of another keyset is refused
    // whole, though it asks of other notes besides.
    let key = kept.derivation.hold_key(kept.owner.hold_root()).unwrap();
    let message = spent.note.message().clone();
    let borrowed = licash::crypto::schnorr_sign(
        key.to_nonzero().unwrap().as_ref(),
        &licash::inquiry::digest(keyset.id(), at, &message),
    )
    .unwrap();
    let wrong = [asked[1].clone(), (message, borrowed)];
    assert!(matches!(
        hub.inquire(keyset.id(), at, &wrong),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        hub.inquire(keyset.id(), at + 3_600, &asked),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        hub.inquire(&[9; 32], at, &asked),
        Err(Error::Refused(Refusal::UnknownKeyset))
    ));
    let many = vec![asked[0].clone(); licash::inquiry::MAX_NOTES + 1];
    assert!(matches!(
        hub.inquire(keyset.id(), at, &many),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn a_note_claimed_in_one_contract_is_cited_against_its_claim_in_another() {
    use licash::recovery::Evidence as Against;
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let alice = owner(1);
    let (twice, once) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    let first = filed([7; 32], &keyset, &[&twice, &once]);
    hub.retire_claimed(&[1; 32], &first.held(), &[]).unwrap();
    // Not against the claim itself.
    assert!(hub.evidence(first.claim()).unwrap().is_empty());
    // Against another claim of one of its notes: that note's signature of
    // the first claim.
    let second = filed([9; 32], &keyset, &[&twice]);
    let found = hub.evidence(second.claim()).unwrap();
    let [Against::SecondClaim { context, record }] = &found[..] else {
        panic!("not the first claim alone");
    };
    assert_eq!(*context, first.claim().hold_context());
    assert_eq!(record.message.to_bytes(), twice.note.message().to_bytes());
}

#[test]
fn a_fold_retires_the_notes_of_its_claim_once_and_for_the_same_claim_only() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (a, b) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    let ys: Vec<_> = [&a, &b]
        .iter()
        .map(|c| c.note.message().identifier().unwrap())
        .collect();
    let contract = [1; 32];
    let claim = filed([7; 32], &keyset, &[&a, &b]);
    // Asking retires nothing.
    hub.fold_claimable(&contract, &ys).unwrap();
    assert_eq!(hub.spent(&ys).unwrap(), [false, false]);
    hub.claim_for_fold(&contract, &claim).unwrap();
    assert_eq!(hub.spent(&ys).unwrap(), [true, true]);
    // The same claim again, as after a fold that never confirmed: the same.
    hub.fold_claimable(&contract, &ys).unwrap();
    hub.claim_for_fold(&contract, &claim).unwrap();
    // Not by a spend any longer, nor by another claim of them.
    let late = Spend::new(&keyset, std::slice::from_ref(&a), &[(bob.address(), 8)]);
    assert_eq!(refused(late.offer(&hub)), Refusal::Spent);
    assert_eq!(
        refused(hub.claim_for_fold(&[2; 32], &filed([9; 32], &keyset, &[&a]))),
        Refusal::Spent
    );
    assert_eq!(refused(hub.fold_claimable(&[2; 32], &ys)), Refusal::Spent);
    // Nor by a different claim in the same contract.
    assert_eq!(
        refused(hub.claim_for_fold(&contract, &filed([9; 32], &keyset, &[&a]))),
        Refusal::Spent
    );
    // The claim on Bitcoin of the same claim is not cited against itself.
    assert!(hub.evidence(claim.claim()).unwrap().is_empty());
}

#[test]
fn a_fold_refuses_a_claim_of_a_spent_note_and_retires_none_of_it() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (spent, kept) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    let kept_y = kept.note.message().identifier().unwrap();
    let spend = Spend::new(&keyset, std::slice::from_ref(&spent), &[(bob.address(), 8)]);
    spend.complete(&hub, &keyset);
    let ys = [spent.note.message().identifier().unwrap(), kept_y];
    let contract = [1; 32];
    assert_eq!(refused(hub.fold_claimable(&contract, &ys)), Refusal::Spent);
    assert_eq!(
        refused(hub.claim_for_fold(&contract, &filed([7; 32], &keyset, &[&spent, &kept]))),
        Refusal::Spent
    );
    // All or nothing: the note it did not spend is free still.
    assert_eq!(hub.spent(&[kept_y]).unwrap(), [false]);
    hub.claim_for_fold(&contract, &filed([7; 32], &keyset, &[&kept]))
        .unwrap();
    assert_eq!(hub.spent(&[kept_y]).unwrap(), [true]);
}

#[test]
fn the_ledger_is_a_component_of_a_hub_file_and_its_rows_hold_to_their_states() {
    let files = files();
    drop(open(&files, Policy::default()));
    let db = sql(&files.db);
    let id: i64 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .unwrap();
    assert_eq!(id, 0x4C48_5542);
    let version: i64 = db
        .query_row(
            "SELECT version FROM schema_versions WHERE component = 'ledger'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(version, 4);
    // Rows by themselves: what each refers to is not under test.
    db.pragma_update(None, "foreign_keys", false).unwrap();

    let lock = |own: i64, amount: i64, preimage: &str, settled: &str, at: &str| {
        db.execute(
            &format!(
                "INSERT INTO locks (id, hash, checkpoint, expiry_height, depth, decide_by_height, proposal,
                    signed, certificate, amount, own, preimage, settled, settled_at)
                 VALUES (randomblob(32), randomblob(32), x'00', 1, 1, 1, x'00', x'00', x'00',
                    {amount}, {own}, {preimage}, {settled}, {at})"
            ),
            [],
        )
    };
    let preimage = "x'1111111111111111111111111111111111111111111111111111111111111111'";
    assert!(lock(0, 5, "NULL", "NULL", "NULL").is_ok());
    assert!(lock(0, 5, "NULL", "'refund'", "1").is_ok());
    assert!(lock(0, 5, preimage, "'pay'", "1").is_ok());
    // Settled on a branch and at a time, or neither; a pay with its preimage.
    assert!(lock(0, 5, preimage, "'pay'", "NULL").is_err());
    assert!(lock(0, 5, "NULL", "NULL", "1").is_err());
    assert!(lock(0, 5, "NULL", "'pay'", "1").is_err());
    assert!(lock(0, 5, "NULL", "'paid'", "1").is_err());
    assert!(lock(2, 5, "NULL", "NULL", "NULL").is_err());
    assert!(lock(0, -5, "NULL", "NULL", "NULL").is_err());

    let forward = |state: &str, preimage: &str, reason: &str, resolved: &str| {
        db.execute(
            &format!(
                "INSERT INTO forwards (lock, hash, request, node, amount, state, preimage,
                    reason, created_at, resolved_at)
                 VALUES (randomblob(32), randomblob(32), 'r', 'n', 5, '{state}', {preimage},
                    {reason}, 0, {resolved})"
            ),
            [],
        )
    };
    assert!(forward("pending", "NULL", "NULL", "NULL").is_ok());
    assert!(forward("paid", preimage, "NULL", "1").is_ok());
    assert!(forward("failed", "NULL", "'no route'", "1").is_ok());
    assert!(forward("pending", "NULL", "NULL", "1").is_err());
    assert!(forward("paid", "NULL", "NULL", "1").is_err());
    assert!(forward("paid", preimage, "NULL", "NULL").is_err());
    assert!(forward("failed", "NULL", "NULL", "1").is_err());

    // A grant is released once signed: both or neither.
    let grant = |signed: &str, released: &str| {
        db.execute(
            &format!(
                "INSERT INTO grants (id, offer, salt, boot, signed, released_at)
                 VALUES (randomblob(32), x'00', x'00', x'00', {signed}, {released})"
            ),
            [],
        )
    };
    assert!(grant("NULL", "NULL").is_ok());
    assert!(grant("x'00'", "1").is_ok());
    assert!(grant("x'00'", "NULL").is_err());
    assert!(grant("NULL", "1").is_err());
}

/// A lock of `coins`, signed by their owners and never served, each refunded
/// to its owner: the spend a claim's filing shows of them.
fn shown_lock(keyset: &Keyset, coins: &[Coin]) -> licash::recovery::Evidence {
    let terms = TimedTerms::new(
        ChainProfile::Core30DefaultRegtest,
        [31; 32],
        1_000,
        3,
        [41; 32],
    )
    .unwrap();
    let e = Ephemeral::random();
    let bob = owner(2).address();
    let outputs = |branch| -> Vec<Output> {
        (0..)
            .zip(coins)
            .map(|(i, c)| {
                let to = match branch {
                    Branch::Pay => bob,
                    Branch::Refund => c.owner.address(),
                };
                let denom = c.note.message().denomination();
                Output::from_derivation(&e.derive(&to, denom, branch, i).unwrap()).unwrap()
            })
            .collect()
    };
    let lock = TimedLock::new(terms, outputs(Branch::Refund)).unwrap();
    let proposal = Proposal::new(
        keyset,
        &notes(coins),
        e.public(),
        outputs(Branch::Pay),
        Some(lock),
    )
    .unwrap();
    let secrets: Vec<_> = coins
        .iter()
        .map(|c| {
            c.derivation
                .ownership()
                .owner_secret(c.owner.spend_secret())
                .unwrap()
        })
        .collect();
    licash::recovery::Evidence::Spend {
        signed: SignedProposal::sign(
            keyset,
            proposal,
            &notes(coins),
            Authorization::Plain,
            &secrets,
        )
        .unwrap(),
        notes: notes(coins),
        unlock: None,
    }
}

fn rows(db: &Path, table: &str) -> i64 {
    sql(db)
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn a_note_a_claim_gives_up_by_a_lock_alone_is_retired_and_its_lock_cited() {
    use licash::recovery::{
        evidence_from_bytes, evidence_to_bytes, voids_note, Evidence as Against,
    };
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let shown = |files: &Files| {
        (
            rows(&files.db, "shown_locks"),
            rows(&files.db, "shown_inputs"),
        )
    };

    // A claim that holds the input of its lock, as a wallet files it: the
    // note is claimed by its hold key, and no lock is kept for it.
    let (mine, refund) = (mint(&files, &alice, 8), mint(&files, &alice, 8));
    let honest = shown_lock(&keyset, std::slice::from_ref(&mine));
    let held = filed([7; 32], &keyset, &[&mine, &refund]).held();
    hub.retire_claimed(&[1; 32], &held, &[honest]).unwrap();
    assert_eq!(shown(&files), (0, 0));

    // A lock of two notes neither of which the claim holds, in another
    // order than their identifiers'.
    let mut inputs = vec![mint(&files, &alice, 8), mint(&files, &alice, 4)];
    inputs.sort_by_key(|c| std::cmp::Reverse(c.note.message().identifier().unwrap()));
    let ys: Vec<_> = inputs
        .iter()
        .map(|c| c.note.message().identifier().unwrap())
        .collect();
    let denom = inputs[1].note.message().denomination();
    let early = Spend::new(&keyset, &inputs[1..], &[(bob.address(), denom)]);
    let grant = early.offer(&hub).unwrap();
    let lock = shown_lock(&keyset, &inputs);
    let refund = mint(&files, &alice, 8);
    let held = filed([8; 32], &keyset, &[&refund]).held();
    assert_eq!(hub.spent(&ys).unwrap(), [false, false]);
    hub.retire_claimed(&[2; 32], &held, std::slice::from_ref(&lock))
        .unwrap();
    assert_eq!(shown(&files), (1, 2));
    // Read again, as after a restart: the same.
    hub.retire_claimed(&[2; 32], &held, std::slice::from_ref(&lock))
        .unwrap();
    assert_eq!(shown(&files), (1, 2));
    assert_eq!(hub.spent(&ys).unwrap(), [true, true]);

    // No spend takes them, offered before or after, and no fold.
    let signed = early.sign(&keyset, Authorization::Granted(Box::new(grant)));
    assert_eq!(
        refused(hub.release(&signed, &early.notes())),
        Refusal::Spent
    );
    let denom = inputs[0].note.message().denomination();
    let late = Spend::new(&keyset, &inputs[..1], &[(bob.address(), denom)]);
    assert_eq!(refused(late.offer(&hub)), Refusal::Spent);
    assert_eq!(
        refused(hub.fold_claimable(&[3; 32], &ys[..1])),
        Refusal::Spent
    );
    let again = filed([9; 32], &keyset, &[&inputs[0]]);
    assert_eq!(
        refused(hub.claim_for_fold(&[3; 32], &again)),
        Refusal::Spent
    );
    // Retired, and spent by nothing: the lock is not served.
    assert_eq!((rows(&files.db, "spent"), rows(&files.db, "locks")), (0, 0));

    // Against another claim of either: the lock, a spend its owners signed,
    // which whoever checks it finds to void both.
    let found = hub.evidence(again.claim()).unwrap();
    assert!(matches!(&found[..], [Against::Spend { unlock: None, .. }]));
    let back = evidence_from_bytes(&keyset, 16, &evidence_to_bytes(&found)).unwrap();
    for coin in &inputs {
        assert!(voids_note(&keyset, coin.note.message(), &back[0]).unwrap());
    }
    // Not against the claim of a note it does not spend.
    assert!(hub
        .evidence(&claim_in([9; 32], &keyset, &[&mint(&files, &alice, 2)]))
        .unwrap()
        .is_empty());
    // And shown to the holder of either who asks.
    let at = unix();
    let asked = [ask(&keyset, at, &inputs[1])];
    let told = hub.inquire(keyset.id(), at, &asked).unwrap();
    assert!(matches!(
        &told[0][..],
        [Against::Spend { unlock: None, .. }]
    ));

    // Across a restart, still retired and still cited.
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(hub.spent(&ys).unwrap(), [true, true]);
    assert_eq!(hub.evidence(again.claim()).unwrap().len(), 1);
    assert_eq!(shown(&files), (1, 2));
}

#[test]
fn a_shown_lock_the_ledger_cannot_read_back_is_left_out_alone() {
    use licash::recovery::Evidence as Against;
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let alice = owner(1);
    let (twice, given, refund) = (
        mint(&files, &alice, 8),
        mint(&files, &alice, 4),
        mint(&files, &alice, 4),
    );
    hub.retire_claimed(&[1; 32], &filed([7; 32], &keyset, &[&twice]).held(), &[])
        .unwrap();
    let lock = shown_lock(&keyset, std::slice::from_ref(&given));
    let held = filed([8; 32], &keyset, &[&refund]).held();
    hub.retire_claimed(&[2; 32], &held, &[lock]).unwrap();
    let second = filed([9; 32], &keyset, &[&twice, &given]);
    assert!(matches!(
        &hub.evidence(second.claim()).unwrap()[..],
        [Against::Spend { .. }, Against::SecondClaim { .. }]
    ));
    // Its bytes not what was kept, then its row not: the other claim of the
    // other note is cited all the same, and the note stays retired.
    drop(hub);
    for damage in ["evidence = x'00'", "keyset = x'00'"] {
        sql(&files.db)
            .execute(&format!("UPDATE shown_locks SET {damage}"), [])
            .unwrap();
        let hub = open(&files, Policy::default());
        assert!(matches!(
            &hub.evidence(second.claim()).unwrap()[..],
            [Against::SecondClaim { .. }]
        ));
        let y = given.note.message().identifier().unwrap();
        assert_eq!(hub.spent(&[y]).unwrap(), [true]);
    }
}

#[test]
fn a_claim_the_ledger_cannot_read_back_is_left_out_alone() {
    use licash::recovery::Evidence as Against;
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let alice = owner(1);
    let (one, other) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    hub.retire_claimed(
        &[1; 32],
        &filed([7; 32], &keyset, &[&one, &other]).held(),
        &[],
    )
    .unwrap();
    let second = filed([9; 32], &keyset, &[&one, &other]);
    assert_eq!(hub.evidence(second.claim()).unwrap().len(), 2);
    drop(hub);
    // One row's message no longer a note's: the other's claim is cited all
    // the same, to the dispute and to its holder, and both stay retired.
    let y = one.note.message().identifier().unwrap();
    sql(&files.db)
        .execute("UPDATE claimed SET message = x'00' WHERE y = ?1", [&y.0])
        .unwrap();
    let hub = open(&files, Policy::default());
    let found = hub.evidence(second.claim()).unwrap();
    let [Against::SecondClaim { record, .. }] = &found[..] else {
        panic!("not the other claim alone");
    };
    assert_eq!(record.message.to_bytes(), other.note.message().to_bytes());
    let at = unix();
    let asked = [ask(&keyset, at, &one), ask(&keyset, at, &other)];
    let told = hub.inquire(keyset.id(), at, &asked).unwrap();
    assert!(told[0].is_empty());
    assert!(matches!(&told[1][..], [Against::SecondClaim { .. }]));
    let ys = [y, other.note.message().identifier().unwrap()];
    assert_eq!(hub.spent(&ys).unwrap(), [true, true]);
}

#[test]
fn a_hub_file_of_before_claims_showed_locks_gains_none_shown_when_opened() {
    let files = files();
    let (_, keyset) = issuer(&files);
    let alice = owner(1);
    let seq = |db: &Path| -> i64 {
        sql(db)
            .query_row("SELECT seq FROM meta", [], |r| r.get(0))
            .unwrap()
    };
    // What a hub writes of its own when it opens its file.
    let created = seq(&files.db);
    drop(open(&files, Policy::default()));
    let opening = seq(&files.db) - created;
    // As the release before made it: the ledger and nothing else.
    sql(&files.db)
        .execute_batch(
            "DROP TABLE shown_inputs; DROP TABLE shown_locks;
             DELETE FROM schema_versions WHERE component = 'shown';",
        )
        .unwrap();
    let before = seq(&files.db);
    // Read beside no hub, it is left as it is.
    let ledger = Ledger::open(&files.db).unwrap();
    ledger.stats().unwrap();
    drop(ledger);
    let version = |db: &Path| -> Option<i64> {
        sql(db)
            .query_row(
                "SELECT version FROM schema_versions WHERE component = 'shown'",
                [],
                |r| r.get(0),
            )
            .ok()
    };
    assert_eq!(version(&files.db), None);

    // Opened: the tables, empty, and no write of the ledger's for them.
    let hub = open(&files, Policy::default());
    assert_eq!(version(&files.db), Some(1));
    assert_eq!(
        (
            rows(&files.db, "shown_locks"),
            rows(&files.db, "shown_inputs")
        ),
        (0, 0)
    );
    assert_eq!(seq(&files.db), before + opening);
    // It writes on, and keeps what it is shown.
    let (given, refund) = (mint(&files, &alice, 8), mint(&files, &alice, 8));
    let lock = shown_lock(&keyset, std::slice::from_ref(&given));
    let held = filed([7; 32], &keyset, &[&refund]).held();
    hub.retire_claimed(&[1; 32], &held, &[lock]).unwrap();
    assert!(!hub.halted());
    let y = given.note.message().identifier().unwrap();
    assert_eq!(hub.spent(&[y]).unwrap(), [true]);
    drop(hub);
    let hub = open(&files, Policy::default());
    assert_eq!(hub.spent(&[y]).unwrap(), [true]);
    assert_eq!(rows(&files.db, "shown_inputs"), 1);
}

/// The largest spend a proposal may be, of [`licash::spend::MAX_INPUTS`]
/// notes to [`licash::spend::MAX_OUTPUTS`] outputs and granted, whose
/// evidence whole is larger than [`licash_hub::MAX_EVIDENCE_BYTES`], is
/// released: the hub cites it by its owners' signatures
/// ([`licash::recovery::Evidence::Signed`]), which no proposal makes too
/// large. Before evidence by signature it was refused as too large to cite
/// and retired nothing.
#[test]
fn the_largest_spend_is_released_and_cited_by_its_signatures() {
    use licash::recovery::{evidence_from_bytes, evidence_to_bytes, Evidence as Against};
    use licash::spend::{MAX_INPUTS, MAX_OUTPUTS};
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let inputs: Vec<_> = (0..MAX_INPUTS).map(|_| mint(&files, &alice, 2)).collect();
    let ys: Vec<_> = inputs
        .iter()
        .map(|c| c.note.message().identifier().unwrap())
        .collect();

    let large = Spend::new(&keyset, &inputs, &[(bob.address(), 1); MAX_OUTPUTS]);
    let grant = large.offer(&hub).unwrap();
    let signed = large.sign(&keyset, Authorization::Granted(Box::new(grant)));
    let notes = large.notes();
    let size = evidence_to_bytes(&[Against::Spend {
        signed: signed.clone(),
        notes: notes.clone(),
        unlock: None,
    }])
    .len();
    assert!(size > licash_hub::MAX_EVIDENCE_BYTES, "{size} bytes");
    hub.release(&signed, &notes).unwrap();
    assert_eq!(hub.spent(&ys).unwrap(), vec![true; MAX_INPUTS]);

    let claim = claim_in([7; 32], &keyset, &[&inputs[0]]);
    let found = hub.evidence(&claim).unwrap();
    let [spend @ Against::Spend { notes, .. }] = &found[..] else {
        panic!("not the released spend alone");
    };
    assert_eq!(notes.len(), MAX_INPUTS);
    let cited = licash::recovery::cite(&claim, spend.clone()).unwrap();
    let bytes = evidence_to_bytes(std::slice::from_ref(&cited));
    // Its body, hashed and never decoded but for the input relied on, and
    // one signature.
    assert!(
        bytes.len() < licash::spend::MAX_BODY_BYTES + 200 && bytes.len() < size / 2,
        "{} bytes",
        bytes.len()
    );
    let least = licash::base::MIN_AUTHORIZATIONS as usize;
    let read = evidence_from_bytes(&keyset, least, &bytes).unwrap();
    assert!(licash::recovery::voids_note(&keyset, inputs[0].note.message(), &read[0]).unwrap());
}

/// What the ledger holds against a claim and cannot read back is told to
/// the dispute ([`licash_hub::Found::unread`]), not only logged: evidence
/// the hub had and cannot cite, of which its operator is alerted.
#[test]
fn what_the_ledger_cannot_read_back_is_told_to_the_dispute() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let (spent, claimed) = (mint(&files, &alice, 8), mint(&files, &alice, 4));
    Spend::new(&keyset, std::slice::from_ref(&spent), &[(bob.address(), 8)])
        .complete(&hub, &keyset);
    hub.retire_claimed(&[1; 32], &filed([7; 32], &keyset, &[&claimed]).held(), &[])
        .unwrap();
    let claim = filed([9; 32], &keyset, &[&spent, &claimed]);
    let found = hub.found(claim.claim()).unwrap();
    assert_eq!((found.evidence.len(), found.unread.len()), (2, 0));
    drop(hub);

    sql(&files.db)
        .execute(
            "UPDATE grants SET signed = x'00' WHERE released_at IS NOT NULL",
            [],
        )
        .unwrap();
    let y = claimed.note.message().identifier().unwrap();
    sql(&files.db)
        .execute("UPDATE claimed SET message = x'00' WHERE y = ?1", [&y.0])
        .unwrap();
    let hub = open(&files, Policy::default());
    let found = hub.found(claim.claim()).unwrap();
    assert!(found.evidence.is_empty());
    assert_eq!(found.unread.len(), 2, "{:?}", found.unread);
    assert!(
        found.unread[0].contains("does not read back"),
        "{:?}",
        found.unread
    );
    // The view without them, as before.
    assert!(hub.evidence(claim.claim()).unwrap().is_empty());
}

/// The audit finds, in a ledger of the release before (schema 1), which
/// the hub no longer opens, each spend it retired notes for that a dispute
/// cannot cite: of more notes than a statement reads, or of a signed spend
/// over a statement's blob, and none of those it can. Read-only.
#[test]
fn the_audit_finds_the_spends_an_earlier_ledger_cannot_cite() {
    let files = files();
    let hub = open(&files, Policy::default());
    let (_, keyset) = issuer(&files);
    let (alice, bob) = (owner(1), owner(2));
    let spends: Vec<_> = (0..3)
        .map(|_| {
            let coin = mint(&files, &alice, 8);
            let spend = Spend::new(&keyset, std::slice::from_ref(&coin), &[(bob.address(), 8)]);
            spend.complete(&hub, &keyset);
            spend.proposal.id()
        })
        .collect();
    drop(hub);
    assert!(licash_hub::uncitable(&files.db, 128).unwrap().is_empty());

    // As an earlier release kept them: one spend of 129 notes, one whose
    // signed spend is larger than a statement reads.
    let db = sql(&files.db);
    db.execute(
        "UPDATE schema_versions SET version = 1 WHERE component = 'ledger'",
        [],
    )
    .unwrap();
    let (many, large) = (spends[0].as_bytes(), spends[1].as_bytes());
    for i in 1..129u32 {
        let mut y = [0u8; 33];
        y[..4].copy_from_slice(&i.to_le_bytes());
        db.execute(
            "INSERT INTO spent (y, proposal, position, note) VALUES (?1, ?2, ?3, x'00')",
            rusqlite::params![&y[..], &many[..], i],
        )
        .unwrap();
    }
    db.execute(
        "UPDATE grants SET signed = zeroblob(64001) WHERE id = ?1",
        [&large[..]],
    )
    .unwrap();
    let before = rows(&files.db, "spent");
    drop(db);

    let found = licash_hub::uncitable(&files.db, 128).unwrap();
    let ids: Vec<_> = found.iter().map(|s| s.proposal.clone()).collect();
    let mut expected = vec![hex::encode(many), hex::encode(large)];
    expected.sort();
    assert_eq!(ids, expected, "{found:?}");
    let of_many = found
        .iter()
        .find(|s| s.proposal == hex::encode(many))
        .unwrap();
    assert_eq!(of_many.notes, 129);
    // Under a Base reading more, the spend of many is cited.
    assert_eq!(licash_hub::uncitable(&files.db, 129).unwrap().len(), 1);
    // Nothing written, and the hub of this release still refuses the file.
    assert_eq!(rows(&files.db, "spent"), before);
    assert!(Hub::open(&files.seed, &files.db, Policy::default()).is_err());
}
