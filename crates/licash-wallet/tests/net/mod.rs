//! Hubs in process, behind URLs, with requests that fail on demand, each
//! following a regtest chain of its own.

mod chain;
mod inbox;

#[allow(unused_imports)]
pub use inbox::Conduct;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, SignedProposal},
    claim::Branch,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{Output, Proposal},
    unlink::Nonce,
};
use licash_api::{
    Code, Evidenced, Fee, Hex, Inquire, Issued, Lock, LockState, Locked, Offer, Offered, Payment,
    Problem, Refund, Released, Settle, Unlink, Unlinked,
};
use licash_hub::{Error, Hub, Policy, Settled, Timing};
use licash_wallet::{Response, Transport};

pub const MAX_POW: u32 = 6;
pub const HUB: &str = "http://hub.test";

#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// The request never reaches the hub.
    Lost,
    /// The hub serves it, but its answer is lost.
    Dropped,
    /// The hub does not serve it, and answers with this problem.
    Refused(Code),
    /// The hub serves it, and answers with this problem all the same, as
    /// a hub lying to its payer would.
    #[allow(dead_code)]
    Belied(Code),
    /// An inquiry the hub answers with no evidence of any note, as a hub
    /// that says nothing and shows nothing would.
    Hushed,
    /// The hub serves it, and its answer reaches the wallet changed so, as
    /// a hub that shows evidence missing or false would.
    #[allow(dead_code)]
    Tampered(Tamper),
}

/// How [`Fault::Tampered`] changes an answer.
pub type Tamper = fn(&[u8]) -> Vec<u8>;

/// An answer of an offer (its grant) or of issuances (the first of them)
/// with its evidence changed by `change`.
fn evidence_changed(body: &[u8], change: fn(&mut Vec<u8>)) -> Vec<u8> {
    let mut answer: serde_json::Value = serde_json::from_slice(body).unwrap();
    let field = match answer.get_mut("grant") {
        Some(grant) => grant,
        None => &mut answer["issuances"][0],
    };
    let mut bytes = hex::decode(field.as_str().unwrap()).unwrap();
    change(&mut bytes);
    *field = hex::encode(bytes).into();
    serde_json::to_vec(&answer).unwrap()
}

/// An answer whose evidence is cut short by a byte ([`Fault::Tampered`]).
#[allow(dead_code)]
pub fn evidence_missing(body: &[u8]) -> Vec<u8> {
    evidence_changed(body, |bytes| {
        bytes.pop();
    })
}

/// An answer whose last proof is false: a bit flipped in its last
/// response scalar, which both a grant's seal and an issuance's DLEQ end
/// with, before the nonce commitment's two points ([`Fault::Tampered`]).
#[allow(dead_code)]
pub fn evidence_false(body: &[u8]) -> Vec<u8> {
    evidence_changed(body, |bytes| {
        let at = bytes.len() - 2 * 33 - 1;
        bytes[at] ^= 1;
    })
}

/// What a hub serving a lock's state leaves out of it, or lies about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockLie {
    /// Its payer's signatures.
    Unsigned,
    /// The checkpoint its terms name.
    Unanchored,
    /// It says it was paid, showing no preimage.
    PaidUnshown,
}

struct Site {
    hub: Option<Arc<Hub>>,
    seed: PathBuf,
    db: PathBuf,
    policy: Policy,
    chain: Arc<Mutex<chain::Chain>>,
    inbox: Arc<Mutex<inbox::Inbox>>,
}

/// The timing of the hubs' locks: short, to expire them in a test.
pub const TIMING: Timing = Timing {
    window: 20,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

#[derive(Default)]
pub struct Net {
    sites: Mutex<HashMap<String, Site>>,
    faults: Mutex<Vec<(&'static str, Fault)>>,
    /// Fees the hubs advertise instead of their own.
    pub stale: Mutex<Option<Fee>>,
    /// The mailbox relays the hubs name.
    pub relays: Mutex<Vec<String>>,
    /// The proof of identity the hubs advertise instead of their own: none
    /// as from an older hub, or another.
    pub proof: Mutex<Option<Option<Hex>>>,
    /// What the hubs leave out of the locks' states they serve.
    pub lock_lies: Mutex<Vec<LockLie>>,
    /// The URLs asked, each with the lane it was asked in
    /// ([`licash_wallet::current_lane`]).
    pub asked: Mutex<Vec<(String, Option<u64>)>>,
    dirs: Mutex<Vec<tempfile::TempDir>>,
}

impl Net {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// A new hub at `url`, charging `fee` on spends and in each branch of
    /// a lock, at height 3 of its chain.
    pub fn start(&self, url: &str, fee: Fee) {
        self.start_timed(url, fee, TIMING);
    }

    /// [`Net::start`], its locks timed by `timing`.
    pub fn start_timed(&self, url: &str, fee: Fee, timing: Timing) {
        self.start_with(url, fee, 0, timing);
    }

    /// [`Net::start`], charging besides `output_msat` thousandths of a sat
    /// for each note made for others than the hub.
    pub fn start_per_note(&self, url: &str, fee: Fee, output_msat: u64) {
        self.start_with(url, fee, output_msat, TIMING);
    }

    fn start_with(&self, url: &str, fee: Fee, output_msat: u64, timing: Timing) {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, MAX_POW).unwrap();
        let policy = Policy {
            spend: fee,
            lock: fee,
            refund: fee,
            output_msat,
            timing,
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        self.dirs.lock().unwrap().push(dir);
        let site = Site {
            hub: Some(hub),
            seed,
            db,
            policy,
            chain: Arc::new(Mutex::new(chain)),
            inbox: Arc::default(),
        };
        self.sites.lock().unwrap().insert(url.into(), site);
        self.mine(url, 3, None);
    }

    /// Mine `blocks` on the chain of the hub at `url`, the first with an
    /// activation of `secret` if given, which its hub scans.
    pub fn mine(&self, url: &str, blocks: u32, mut secret: Option<[u8; 32]>) {
        let (hub, chain) = {
            let sites = self.sites.lock().unwrap();
            (sites[url].hub.clone().unwrap(), sites[url].chain.clone())
        };
        let mut chain = chain.lock().unwrap();
        for _ in 0..blocks {
            let block = chain.mine(secret.take()).clone();
            hub.observe(chain.height(), &block).unwrap();
        }
        assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
    }

    /// Mine a block holding `txs` on the chain of the hub at `url`, which
    /// its hub scans.
    #[allow(dead_code)]
    pub fn confirm(&self, url: &str, txs: Vec<bitcoin::Transaction>) {
        let (hub, chain) = {
            let sites = self.sites.lock().unwrap();
            (sites[url].hub.clone().unwrap(), sites[url].chain.clone())
        };
        let mut chain = chain.lock().unwrap();
        let block = chain.mine_with(None, txs).clone();
        hub.observe(chain.height(), &block).unwrap();
        assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
    }

    /// Bitcoin reorganizes the chain of the hub at `url` above `height`:
    /// its blocks past it are gone, which its hub forgets, and those mined
    /// next differ from them.
    #[allow(dead_code)]
    pub fn reorg(&self, url: &str, height: u32) {
        let (hub, chain) = {
            let sites = self.sites.lock().unwrap();
            (sites[url].hub.clone().unwrap(), sites[url].chain.clone())
        };
        let mut chain = chain.lock().unwrap();
        chain.blocks.truncate(height as usize + 1);
        hub.rewind(height + 1).unwrap();
    }

    /// The chain of the hub at `url`, as a wallet reads it.
    #[allow(dead_code)]
    pub fn view(&self, url: &str) -> View {
        View(self.sites.lock().unwrap()[url].chain.clone())
    }

    /// `url` serves the hub at `at` too.
    pub fn alias(&self, url: &str, at: &str) {
        let mut sites = self.sites.lock().unwrap();
        let site = &sites[at];
        let alias = Site {
            hub: site.hub.clone(),
            seed: site.seed.clone(),
            db: site.db.clone(),
            policy: site.policy,
            chain: site.chain.clone(),
            inbox: site.inbox.clone(),
        };
        sites.insert(url.into(), alias);
    }

    /// Stop the hub at `url` and start it again on its files.
    pub fn restart(&self, url: &str) {
        let mut sites = self.sites.lock().unwrap();
        let site = sites.get_mut(url).unwrap();
        drop(site.hub.take());
        let hub = Hub::open(&site.seed, &site.db, site.policy).unwrap();
        let chain = site.chain.lock().unwrap();
        assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
        site.hub = Some(Arc::new(hub));
    }

    /// The next request to `path` fails so.
    pub fn fail(&self, path: &'static str, fault: Fault) {
        self.faults.lock().unwrap().push((path, fault));
    }

    pub fn hub(&self, url: &str) -> Arc<Hub> {
        self.sites.lock().unwrap()[url].hub.clone().unwrap()
    }

    /// The issuer keys of the hub at `url`, from its seed file.
    fn issuer(&self, url: &str) -> (IssuerKeys, Keyset) {
        let text = std::fs::read_to_string(&self.sites.lock().unwrap()[url].seed).unwrap();
        let mut seed = [0; 32];
        hex::decode_to_slice(text.trim(), &mut seed).unwrap();
        let keys = IssuerKeys::from_seed(&seed, 0, MAX_POW).unwrap();
        let keyset = keys.keyset().unwrap();
        (keys, keyset)
    }

    pub fn serve(&self, url: &str, body: Option<Vec<u8>>) -> Result<Response, String> {
        let at = url.find("/v1/").ok_or("no such path")?;
        let (site, path) = url.split_at(at);
        let fault = {
            let mut faults = self.faults.lock().unwrap();
            let found = faults.iter().position(|(p, _)| *p == path);
            found.map(|i| faults.remove(i).1)
        };
        match fault {
            Some(Fault::Lost) => return Err("connection refused".into()),
            Some(Fault::Refused(code)) => {
                let problem = Problem::new(code, "refused as asked");
                return Ok(Response {
                    status: code.status(),
                    body: serde_json::to_vec(&problem).unwrap(),
                });
            }
            Some(Fault::Hushed) => {
                let asked: Inquire = serde_json::from_slice(&body.unwrap()).unwrap();
                let none = vec![Vec::new(); asked.notes.len()];
                return Ok(Response {
                    status: 200,
                    body: serde_json::to_vec(&Evidenced::new(&none)).unwrap(),
                });
            }
            _ => {}
        }
        let (hub, kept) = {
            let sites = self.sites.lock().unwrap();
            let site = sites.get(site).ok_or("no such host")?;
            (site.hub.clone().ok_or("no such host")?, site.inbox.clone())
        };
        if path.starts_with(licash_api::inbox::INBOX) {
            let answer = kept.lock().unwrap().serve(path, body.as_deref());
            if let Some(Fault::Dropped) = fault {
                return Err("connection reset".into());
            }
            return Ok(match answer {
                // As the service answers a route it does not serve.
                None => Response {
                    status: 404,
                    body: Vec::new(),
                },
                Some(Ok(body)) => Response { status: 200, body },
                Some(Err(problem)) => Response {
                    status: problem.code.status(),
                    body: serde_json::to_vec(&problem).unwrap(),
                },
            });
        }
        let answer = match (path, body) {
            (licash_api::INFO, None) => self.info(&hub, kept.lock().unwrap().conduct),
            (licash_api::RELEASE, Some(body)) => release(&hub, &kept, &body),
            (path, None) if path.starts_with("/v1/lock/") => {
                let lies = self.lock_lies.lock().unwrap().clone();
                lock_state(&hub, &path[9..], &lies)
            }
            (path, Some(body)) => post(&hub, path, &body),
            _ => Err(Problem::invalid("no such route")),
        };
        match fault {
            Some(Fault::Dropped) => return Err("connection reset".into()),
            Some(Fault::Belied(code)) => {
                let problem = Problem::new(code, "refused, served all the same");
                return Ok(Response {
                    status: code.status(),
                    body: serde_json::to_vec(&problem).unwrap(),
                });
            }
            _ => {}
        }
        Ok(match answer {
            Ok(body) => match fault {
                Some(Fault::Tampered(change)) => Response {
                    status: 200,
                    body: change(&body),
                },
                _ => Response { status: 200, body },
            },
            Err(problem) => Response {
                status: problem.code.status(),
                body: serde_json::to_vec(&problem).unwrap(),
            },
        })
    }

    fn info(&self, hub: &Hub, conduct: Conduct) -> Result<Vec<u8>, Problem> {
        let mut info = hub.advertise().map_err(problem)?;
        if !matches!(conduct, Conduct::None | Conduct::Noteless) {
            info.features.push(licash_api::inbox::FEATURE_NOTE.into());
        }
        if let Some(stale) = *self.stale.lock().unwrap() {
            info.fees.spend = stale;
        }
        info.relays = self.relays.lock().unwrap().clone();
        if let Some(proof) = self.proof.lock().unwrap().clone() {
            info.proof = proof;
        }
        Ok(serde_json::to_vec(&info).unwrap())
    }
}

fn post(hub: &Hub, path: &str, body: &[u8]) -> Result<Vec<u8>, Problem> {
    let json = |e: serde_json::Error| Problem::invalid(e.to_string());
    let lookup = |id: &[u8; 32]| hub.keyset(id);
    let answer = match path {
        licash_api::OFFER => {
            let offer: Offer = serde_json::from_slice(body).map_err(json)?;
            let (proposal, notes) = offer.decode(lookup)?;
            let holds = offer.holds()?;
            let grant = (hub.offer_held(&proposal, &notes, holds.as_deref())).map_err(problem)?;
            serde_json::to_vec(&Offered::new(&grant)?)
        }
        licash_api::UNLINK => {
            let unlink: Unlink = serde_json::from_slice(body).map_err(json)?;
            let answer = hub.unlink(&unlink.decode()?).map_err(problem)?;
            serde_json::to_vec(&Unlinked::new(&answer))
        }
        licash_api::INQUIRE => {
            let inquire: Inquire = serde_json::from_slice(body).map_err(json)?;
            let (keyset, at, notes) = inquire.decode()?;
            let evidence = hub.inquire(&keyset, at, &notes).map_err(problem)?;
            serde_json::to_vec(&Evidenced::new(&evidence))
        }
        licash_api::LOCK => {
            let lock: Lock = serde_json::from_slice(body).map_err(json)?;
            let (signed, notes) = lock.decode(lookup)?;
            let certificate = hub.lock(&signed, &notes).map_err(problem)?;
            serde_json::to_vec(&Locked::new(&certificate))
        }
        licash_api::SETTLE => {
            let settle: Settle = serde_json::from_slice(body).map_err(json)?;
            let (id, preimage) = settle.decode()?;
            let issued = hub.settle(&id, &preimage).map_err(problem)?;
            serde_json::to_vec(&Issued::new(&issued))
        }
        licash_api::REFUND => {
            let refund: Refund = serde_json::from_slice(body).map_err(json)?;
            let issued = hub.refund(&refund.decode()?).map_err(problem)?;
            serde_json::to_vec(&Issued::new(&issued))
        }
        _ => return Err(Problem::invalid("no such route")),
    };
    Ok(answer.unwrap())
}

/// Released, then kept for its payee if asked, as the hub service does.
fn release(hub: &Hub, kept: &Mutex<inbox::Inbox>, body: &[u8]) -> Result<Vec<u8>, Problem> {
    let release: licash_api::inbox::Release =
        serde_json::from_slice(body).map_err(|e| Problem::invalid(e.to_string()))?;
    let (signed, notes) = release.release.decode(|id| hub.keyset(id))?;
    if let Some(keep) = &release.keep {
        keep.decode()?;
    }
    let unlock = hub.release(&signed, &notes).map_err(problem)?;
    let kept = match &release.keep {
        Some(keep) => {
            let proposal = signed.proposal();
            let receipt = licash_api::inbox::Receipt {
                release: release.release.clone(),
                unlock: Hex(unlock.to_vec()),
                note: keep.note.clone(),
            };
            let ephemeral = proposal.ephemeral().0.to_vec();
            let id = *proposal.id().as_bytes();
            kept.lock().unwrap().keep(id, ephemeral, keep, receipt)?
        }
        None => false,
    };
    let released = licash_api::inbox::Released {
        released: Released::new(&unlock),
        kept,
    };
    Ok(serde_json::to_vec(&released).unwrap())
}

fn lock_state(hub: &Hub, id: &str, lies: &[LockLie]) -> Result<Vec<u8>, Problem> {
    let id = licash_api::lock_id(id)?;
    let lock = hub.locked(&id).map_err(problem)?;
    let signatures = hub.lock_signatures(&id).map_err(problem)?;
    let mut settled = lock.settled.map(|branch| match branch {
        Settled::Pay => licash_api::Settled::Pay,
        Settled::Refund => licash_api::Settled::Refund,
    });
    if lies.contains(&LockLie::PaidUnshown) {
        settled = Some(licash_api::Settled::Pay);
    }
    let mut state = LockState::new(&lock.proposal, &lock.certificate, settled, lock.preimage)
        .with_signatures(&signatures);
    let named = *lock.proposal.lock().unwrap().terms().checkpoint();
    if let Some(checkpoint) = hub.checkpoint_named(&named).map_err(problem)? {
        state = state.with_checkpoint(&checkpoint);
    }
    if lies.contains(&LockLie::Unsigned) {
        state.signatures.clear();
    }
    if lies.contains(&LockLie::Unanchored) {
        state.checkpoint = None;
    }
    Ok(serde_json::to_vec(&state).unwrap())
}

/// As the hub service answers.
fn problem(e: Error) -> Problem {
    let code = match &e {
        Error::Refused(refusal) => refusal.code(),
        Error::Invalid(_) => Code::Invalid,
        _ => Code::Unavailable,
    };
    Problem::new(code, e.to_string())
}

/// A wallet's way onto the network.
#[derive(Clone)]
pub struct Link(pub Arc<Net>);

impl Transport for Link {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        // Its lane as it is first polled, as a transport reads it.
        let (net, url) = (self.0.clone(), url.to_owned());
        async move {
            let lane = licash_wallet::current_lane();
            net.asked.lock().unwrap().push((url.clone(), lane));
            net.serve(&url, body)
        }
    }
}

/// `amount` in powers of two the keysets issue, largest first.
pub fn split(mut amount: u64) -> Vec<u64> {
    let mut denoms = Vec::new();
    for pow in (0..=MAX_POW).rev() {
        while amount >= 1 << pow {
            denoms.push(1 << pow);
            amount -= 1 << pow;
        }
    }
    denoms
}

impl Net {
    /// A payment of `amount` to `to` at the hub at `url`, its fee paid, from
    /// notes its keys made for someone outside any wallet.
    pub fn pay(&self, url: &str, to: &Address, amount: u64) -> Payment {
        self.pay_with(url, to, amount).0
    }

    /// How the hub at `url` keeps payments asked kept.
    #[allow(dead_code)]
    pub fn conduct(&self, url: &str, conduct: Conduct) {
        self.sites.lock().unwrap()[url]
            .inbox
            .lock()
            .unwrap()
            .conduct = conduct;
    }

    /// How many payments the hub at `url` keeps, and how many of them
    /// their payees acknowledged.
    #[allow(dead_code)]
    pub fn kept(&self, url: &str) -> (usize, usize) {
        self.sites.lock().unwrap()[url]
            .inbox
            .lock()
            .unwrap()
            .counts()
    }

    /// [`Net::pay`], kept at the hub under the tag and key `tagged` finds
    /// it by: the payee's, or another's.
    #[allow(dead_code)]
    pub fn pay_kept(&self, url: &str, to: &Address, amount: u64, tagged: &Address) -> Payment {
        let (payment, ephemeral) = self.pay_with(url, to, amount);
        let hub = self.hub(url);
        let (signed, _, _) = payment.decode(|id| hub.keyset(id)).unwrap();
        let id = signed.proposal().id();
        let keep = licash_api::inbox::Keep::new(&ephemeral.shared(tagged).unwrap(), &id).0;
        let receipt = licash_api::inbox::Receipt {
            release: payment.release.clone(),
            unlock: payment.unlock.clone(),
            note: None,
        };
        let eph = ephemeral.public().0.to_vec();
        let inbox = self.sites.lock().unwrap()[url].inbox.clone();
        assert!(inbox
            .lock()
            .unwrap()
            .keep(*id.as_bytes(), eph, &keep, receipt)
            .unwrap());
        payment
    }

    /// An entry `tagged` finds in the inbox of the hub at `url`, under a
    /// key it cannot take it with.
    #[allow(dead_code)]
    pub fn keep_junk(&self, url: &str, tagged: &Address) {
        let (payment, ephemeral) = self.pay_with(
            url,
            &OwnerKeys::from_seed(&[0xfb; 32]).unwrap().address(),
            2,
        );
        let shared = ephemeral.shared(tagged).unwrap();
        let keep = licash_api::inbox::Keep {
            tag: Hex(licash_api::inbox::tag(&shared).to_vec()),
            key: Hex(vec![0x55; 32]),
            commitment: Hex(vec![0x66; 32]),
            note: None,
        };
        let receipt = licash_api::inbox::Receipt {
            release: payment.release.clone(),
            unlock: payment.unlock.clone(),
            note: None,
        };
        let eph = ephemeral.public().0.to_vec();
        let inbox = self.sites.lock().unwrap()[url].inbox.clone();
        let mut proposal = [0; 32];
        proposal.copy_from_slice(&licash::crypto::tagged_hash("junk", &[&eph])[..32]);
        inbox
            .lock()
            .unwrap()
            .keep(proposal, eph, &keep, receipt)
            .unwrap();
    }

    /// [`Net::pay`], and the ephemeral key it was made with.
    fn pay_with(&self, url: &str, to: &Address, amount: u64) -> (Payment, Ephemeral) {
        let hub = self.hub(url);
        let (keys, keyset) = self.issuer(url);
        let info = hub.info();
        // The payee's notes are all it makes for others than the hub.
        let (fee, made) = (info.policy.fees().spending(), split(amount).len());
        let mut total = amount;
        while amount + fee.due(total, made) != total {
            total = amount + fee.due(total, made);
        }
        let payer = OwnerKeys::from_seed(&[0xfa; 32]).unwrap();
        let inputs: Vec<(Note, Derivation)> = split(total)
            .into_iter()
            .map(|denom| mint(&keys, &keyset, &payer.address(), denom))
            .collect();
        let notes: Vec<Note> = inputs.iter().map(|(note, _)| note.clone()).collect();
        let ephemeral = Ephemeral::random();
        let to_hub = split(total - amount)
            .into_iter()
            .map(|d| (d, &info.address));
        let outputs = split(amount)
            .into_iter()
            .map(|d| (d, to))
            .chain(to_hub)
            .enumerate()
            .map(|(i, (d, to))| {
                Output::from_derivation(&ephemeral.derive(to, d, Branch::Pay, i).unwrap()).unwrap()
            })
            .collect();
        let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None).unwrap();
        let grant = hub.offer(&proposal, &notes).unwrap();
        let owners: Vec<_> = inputs
            .iter()
            .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()).unwrap())
            .collect();
        let signed = SignedProposal::sign(
            &keyset,
            proposal,
            &notes,
            Authorization::Granted(Box::new(grant)),
            &owners,
        )
        .unwrap();
        let unlock = hub.release(&signed, &notes).unwrap();
        (Payment::new(url, &signed, &notes, &unlock), ephemeral)
    }
}

/// A note of `denom` to `to`, as issued before the hub's ledger began.
fn mint(keys: &IssuerKeys, keyset: &Keyset, to: &Address, denom: u64) -> (Note, Derivation) {
    let d = Ephemeral::random()
        .derive(to, denom, Branch::Pay, 0)
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
    (note, d)
}

/// A hub's chain, as a wallet reads it: without filters.
#[derive(Clone)]
#[allow(dead_code)]
pub struct View(Arc<Mutex<chain::Chain>>);

#[allow(dead_code)]
impl View {
    pub fn height(&self) -> u32 {
        self.0.lock().unwrap().height()
    }
}

impl licash_wallet::Blocks for View {
    fn height(&self) -> impl std::future::Future<Output = Result<u32, String>> + Send {
        std::future::ready(Ok(self.0.lock().unwrap().height()))
    }

    fn hash(
        &self,
        height: u32,
    ) -> impl std::future::Future<Output = Result<bitcoin::BlockHash, String>> + Send {
        let chain = self.0.lock().unwrap();
        let hash = chain.blocks.get(height as usize).map(|b| b.block_hash());
        std::future::ready(hash.ok_or_else(|| format!("no block {height}")))
    }

    fn filter(
        &self,
        _: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, String>> + Send {
        std::future::ready(Ok(None))
    }

    fn block(
        &self,
        hash: &bitcoin::BlockHash,
    ) -> impl std::future::Future<Output = Result<bitcoin::Block, String>> + Send {
        let chain = self.0.lock().unwrap();
        let block = chain
            .blocks
            .iter()
            .find(|b| b.block_hash() == *hash)
            .cloned();
        std::future::ready(block.ok_or_else(|| format!("no block {hash}")))
    }
}
