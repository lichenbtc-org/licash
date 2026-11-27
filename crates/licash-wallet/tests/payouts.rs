//! Payouts of notes on Bitcoin, through a provider played here: it locks
//! the coins the tests say on the hub's own chain, which the wallet reads.

#[allow(dead_code)]
mod net;

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use bitcoin::{
    hashes::Hash, secp256k1::SecretKey, transaction, Amount, FeeRate, OutPoint, ScriptBuf,
    Transaction, TxIn, TxOut, Txid,
};
use licash::spend::ChainProfile;
use licash_api::{
    swaps::{self, ChainRequest, ChainSwap},
    Code, Fee, Funding, Hex, Problem, INFO,
};
use licash_hub::Timing;
use licash_onchain::{deposit::Htlc, silent_claim::Share};
use licash_wallet::{
    Error, LockState, Payout, PayoutState, Response, Transport, Wallet, CLAIM_ROOM, PAYOUT_WINDOW,
};
use net::{Fault, Link, Net, View, TIMING};

const A: &str = "http://a.test";
const PROVIDER: &str = "http://payouts.test";
const FEE: Fee = Fee { base: 1, ppm: 0 };
/// Locks of up to 141 blocks, room for a payout's coin to time out first.
const TIMED: Timing = Timing {
    window: 144,
    ..TIMING
};
const TERMS: swaps::Chain = swaps::Chain {
    fee: Fee {
        base: 1,
        ppm: 10_000,
    },
    miner: 10,
    rate: 1_000,
    min: 500,
    max: 5_000,
    margin: 36,
};
/// A regtest address, P2WPKH: BIP173's.
const PAYEE: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
/// Allowed on top of each payout's amount: room for the claim's fee.
const MAX_FEE: u64 = 2_000;
const ONE_SAT: FeeRate = FeeRate::from_sat_per_vb_u32(1);

#[tokio::test]
async fn a_payout_whose_lock_cannot_be_prepared_keeps_its_failed_history_line() {
    let eco = Eco::new().await;
    let before = eco.held();
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 2_700, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let error = eco.client.payout(&quote).await.unwrap_err();
    assert!(matches!(error, Error::Insufficient { .. }), "{error}");
    let payouts = eco.client.payouts().unwrap();
    assert_eq!(payouts.len(), 1);
    assert_eq!(
        payouts[0].state,
        PayoutState::Failed(format!("its lock was not made: {error}"))
    );
    assert!(payouts[0].lock.is_none());
    assert!(eco.client.locks().unwrap().is_empty());
    assert_eq!(eco.held(), before);
}

/// The hub's lock fee as estimated is below what its lock signs once the
/// notes it takes are chosen: the payout is refused at its quote's ceiling
/// before anything is locked, a line of the history all the same.
#[tokio::test]
async fn a_payout_whose_signed_lock_fee_passes_its_ceiling_locks_nothing() {
    let eco = Eco::with_fee(Fee {
        base: 0,
        ppm: 100_000,
    })
    .await;
    let before = eco.held();
    let estimated = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1_000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1_000, estimated.costs(), ONE_SAT)
        .await
        .unwrap();
    let error = eco.client.payout(&quote).await.unwrap_err();
    assert!(matches!(error, Error::FeeRose { .. }), "{error}");
    assert!(
        error
            .to_string()
            .contains(&format!("more than {}", quote.costs())),
        "{error}"
    );
    let payouts = eco.client.payouts().unwrap();
    assert_eq!(payouts.len(), 1);
    assert_eq!(payouts[0].hash, quote.ticket);
    assert_eq!(
        payouts[0].state,
        PayoutState::Failed(format!("its lock was not made: {error}"))
    );
    assert!(payouts[0].lock.is_none());
    assert!(eco.client.locks().unwrap().is_empty());
    assert_eq!(eco.held(), before);
    // Within a ceiling the signed fee fits: paid out, under its ticket.
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1_000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let payout = eco.client.payout(&quote).await.unwrap();
    assert_eq!(payout.hash, quote.ticket);
    let lock = eco.client.locks().unwrap().remove(0);
    assert!(
        lock.fee > quote.lock_fee,
        "{} by {}",
        lock.fee,
        quote.lock_fee
    );
}

/// A payout admitted whose lock never reached its hub (as if the wallet
/// stopped before sending it) is open with its lock and notes: reopened,
/// the wallet sends that lock and has the provider take the payout.
#[tokio::test]
async fn a_payout_whose_lock_was_never_sent_goes_on_once_reopened() {
    let eco = Eco::new().await;
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 500, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    // Sent, then sent again before the provider is asked: both lost.
    eco.net.fail(licash_api::LOCK, Fault::Lost);
    eco.net.fail(licash_api::LOCK, Fault::Lost);
    let payout = eco.client.payout(&quote).await.unwrap();
    assert_eq!(payout.state, PayoutState::Open, "{payout:?}");
    let lock = eco.client.locks().unwrap().remove(0);
    assert_eq!(Some(&lock.id), payout.lock.as_ref());
    assert_eq!(lock.state, LockState::Requested);
    assert!(eco.desk.taken.lock().unwrap().is_empty());
    let reopened = Eco::client(&eco.net, &eco.desk, &eco.dir, false).await;
    match reopened.follow_payout(&payout.hash, &eco.view).await {
        Ok(_) | Err(Error::Pending { .. }) => {}
        Err(e) => panic!("{e}"),
    }
    let lock = reopened.locks().unwrap().remove(0);
    assert_eq!(lock.state, LockState::Locked, "{lock:?}");
    assert_eq!(eco.desk.taken.lock().unwrap().len(), 1);
    let payout = reopened.payouts().unwrap().remove(0);
    assert_eq!(payout.state, PayoutState::Open, "{payout:?}");
}

/// A quote pays out once: paid again, it is refused, nothing more locked.
#[tokio::test]
async fn a_quote_pays_out_once() {
    let eco = Eco::new().await;
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 500, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    eco.client.payout(&quote).await.unwrap();
    let held = eco.held();
    let e = eco.client.payout(&quote).await.unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    assert_eq!(eco.client.payouts().unwrap().len(), 1);
    assert_eq!(eco.client.locks().unwrap().len(), 1);
    assert_eq!(eco.held(), held);
}

/// A quote's expiry bounds its lock's: paid out blocks later, the lock
/// expires no later than quoted; quoted too long before, the provider's
/// coin would time out too soon, and nothing is locked.
#[tokio::test]
async fn a_quotes_expiry_bounds_its_lock() {
    let eco = Eco::new().await;
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 500, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    eco.mine(2);
    let payout = eco.client.payout(&quote).await.unwrap();
    let lock = eco.client.locks().unwrap().remove(0);
    assert_eq!(Some(&lock.id), payout.lock.as_ref());
    assert!(
        lock.expiry <= quote.expiry,
        "{} by {}",
        lock.expiry,
        quote.expiry
    );
    let stale = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 500, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    eco.mine_to(stale.expiry);
    let e = eco.client.payout(&stale).await.unwrap_err();
    assert!(e.to_string().contains("too soon to claim it"), "{e}");
    assert_eq!(eco.client.payouts().unwrap().len(), 1);
}

/// A payout is quoted to expire as soon as its coin may be paid and
/// claimed, not as late as its hub admits: the provider's coin and the
/// wallet's notes are held no longer than that if either never goes on.
#[tokio::test]
async fn a_quote_expires_as_soon_as_a_payout_can_be_made() {
    let eco = Eco::new().await;
    let height = eco.view.height();
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 500, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    // The hub admits locks expiring 141 blocks on.
    assert!(height + TERMS.margin + PAYOUT_WINDOW < height + TIMED.window - 3);
    assert_eq!(quote.expiry, height + TERMS.margin + PAYOUT_WINDOW);
    let payout = eco.client.payout(&quote).await.unwrap();
    let lock = eco.client.locks().unwrap().remove(0);
    assert_eq!(Some(&lock.id), payout.lock.as_ref());
    assert!(lock.expiry <= quote.expiry, "{}", lock.expiry);
    assert_eq!(eco.timeout(), lock.expiry - TERMS.margin);
}

/// A follower elsewhere (here a second handle on the same wallet, on
/// another thread) never sees a payout without its lock, which it would
/// fail as one whose lock was never made: the payout, its lock and its
/// notes are recorded at once.
#[tokio::test]
async fn a_concurrent_follower_never_fails_a_payout_being_made() {
    let eco = Eco::new().await;
    let follower = Eco::client(&eco.net, &eco.desk, &eco.dir, false).await;
    let view = eco.net.view(A);
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let following = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut rounds = 0;
            while !stopping.load(Ordering::Relaxed) {
                follower.follow_payouts(&view).await.unwrap();
                rounds += 1;
            }
            rounds
        })
    });
    for _ in 0..3 {
        eco.pay_out(500).await;
    }
    stop.store(true, Ordering::Relaxed);
    assert!(following.join().unwrap() > 0);
    let payouts = eco.client.payouts().unwrap();
    assert_eq!(payouts.len(), 3);
    for payout in payouts {
        assert!(
            !matches!(payout.state, PayoutState::Failed(_)),
            "{payout:?}"
        );
    }
}

/// A payout the provider took: its answer, and the coin's terms.
struct Taken {
    answer: ChainSwap,
    htlc: Htlc,
    lock: String,
}

/// The provider, as its clients reach it: the tests lock its coins.
struct Desk {
    net: Arc<Net>,
    wallet: Wallet<Link>,
    key: SecretKey,
    terms: Mutex<Option<swaps::Chain>>,
    decline: AtomicBool,
    /// Whether it answers a share of a scan key not its refund key's.
    false_share: AtomicBool,
    /// The timeout it names, if not the lock's expiry less its margin.
    timeout: Mutex<Option<u32>>,
    taken: Mutex<HashMap<Vec<u8>, Taken>>,
}

impl Desk {
    fn info(&self) -> swaps::Info {
        swaps::Info {
            address: self.wallet.address(),
            fee: TERMS.fee,
            min: 1,
            max: 0,
            margin: 6,
            hubs: vec![swaps::Hub {
                address: self.net.hub(A).info().address,
                max: 0,
                margin: None,
            }],
            nostr: None,
            chain: *self.terms.lock().unwrap(),
            lightning: None,
            donations: None,
            receive: None,
            deposits: None,
            features: Vec::new(),
        }
    }

    async fn take(&self, request: ChainRequest) -> Result<ChainSwap, Problem> {
        if self.decline.load(Ordering::Relaxed) {
            return Err(Problem::new(Code::Declined, "not today"));
        }
        if let Some(taken) = self.taken.lock().unwrap().get(&request.lock.0) {
            return Ok(taken.answer.clone());
        }
        let lock = hex::encode(&request.lock.0);
        let incoming = self.wallet.incoming(A, &lock).await;
        let incoming = incoming.map_err(|e| Problem::new(Code::Declined, e.to_string()))?;
        if incoming.amount < TERMS.pays(request.value) {
            return Err(Problem::new(Code::Declined, "the lock pays too little"));
        }
        let claim = request.claim().unwrap();
        let htlc = Htlc {
            hash: incoming.hash,
            claim: bitcoin::secp256k1::XOnlyPublicKey::from_slice(&claim).unwrap(),
            refund: self.refund_key(),
            timeout: self
                .timeout
                .lock()
                .unwrap()
                .unwrap_or(incoming.expiry - TERMS.margin),
            wait: None,
            sized: true,
        };
        let answer = ChainSwap {
            id: request.lock.clone(),
            state: swaps::State::Accepted,
            value: request.value,
            refund: Hex(self.refund_key().serialize().to_vec()),
            timeout: htlc.timeout,
            funding: None,
            txid: None,
            reason: None,
            share: request.scan().unwrap().map(|scan| {
                let scan = bitcoin::secp256k1::PublicKey::from_slice(&scan).unwrap();
                let key = match self.false_share.load(Ordering::Relaxed) {
                    true => SecretKey::from_slice(&[0x5f; 32]).unwrap(),
                    false => self.key,
                };
                let share = Share::new(&key, &scan).unwrap();
                swaps::Share {
                    point: Hex(share.point.serialize().to_vec()),
                    e: Hex(share.e.to_vec()),
                    s: Hex(share.s.to_vec()),
                }
            }),
        };
        let taken = Taken {
            answer: answer.clone(),
            htlc,
            lock,
        };
        self.taken.lock().unwrap().insert(request.lock.0, taken);
        Ok(answer)
    }

    fn refund_key(&self) -> bitcoin::secp256k1::XOnlyPublicKey {
        self.key
            .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
            .0
    }

    async fn serve(&self, path: &str, body: Option<Vec<u8>>) -> Result<Response, String> {
        let answer = match (path, body) {
            (swaps::SWAPS_INFO, None) => Ok(serde_json::to_vec(&self.info()).unwrap()),
            (swaps::CHAIN_SWAPS, Some(body)) => {
                let request: ChainRequest = serde_json::from_slice(&body).unwrap();
                self.take(request)
                    .await
                    .map(|swap| serde_json::to_vec(&swap).unwrap())
            }
            _ => Err(Problem::invalid("no such route")),
        };
        Ok(match answer {
            Ok(body) => Response { status: 200, body },
            Err(problem) => Response {
                status: problem.code.status(),
                body: serde_json::to_vec(&problem).unwrap(),
            },
        })
    }
}

/// What the tests have the provider do on chain.
impl Desk {
    /// The one payout taken.
    fn with<R>(&self, f: impl FnOnce(&mut Taken) -> R) -> R {
        let mut taken = self.taken.lock().unwrap();
        assert_eq!(taken.len(), 1);
        f(taken.values_mut().next().unwrap())
    }

    /// Lock its coin worth `value`, or what was asked, paying `script`, or
    /// the coin's terms, in a block of its own: as it says.
    fn fund(&self, value: Option<u64>, script: Option<ScriptBuf>) -> OutPoint {
        let (asked, htlc) = self.with(|t| (t.answer.value, t.htlc));
        let tx = unchecked(
            OutPoint::new(Txid::from_byte_array([0xf0; 32]), 7),
            TxOut {
                value: Amount::from_sat(value.unwrap_or(asked)),
                script_pubkey: script.unwrap_or_else(|| htlc.script_pubkey()),
            },
        );
        self.net.confirm(A, vec![tx.clone()]);
        let height = self.net.view(A).height();
        self.with(|t| {
            t.answer.state = swaps::State::Locked;
            t.answer.funding = Some(Funding {
                txid: tx.compute_txid().to_string(),
                vout: 0,
                height,
            });
        });
        OutPoint::new(tx.compute_txid(), 0)
    }

    /// Take the coin back, by any spend but a claim, in a block of its own.
    fn refund(&self, coin: OutPoint) {
        let back = unchecked(
            coin,
            TxOut {
                value: Amount::from_sat(500),
                script_pubkey: ScriptBuf::new_op_return([1]),
            },
        );
        self.net.confirm(A, vec![back]);
    }

    /// Claim the client's lock with the preimage `claim` reveals.
    async fn settle(&self, claim: &Transaction, coin: OutPoint) {
        let (htlc, lock) = self.with(|t| (t.htlc, t.lock.clone()));
        let preimage = htlc.preimage_in(claim, coin).expect("the claim's preimage");
        self.wallet.claim(A, &lock, &preimage).await.unwrap();
    }
}

/// A transaction spending `coin` to `output`, its witness none: the hub's
/// chain checks nothing.
fn unchecked(coin: OutPoint, output: TxOut) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: coin,
            ..Default::default()
        }],
        output: vec![output],
    }
}

/// A client's way to the hub and the provider, counting how often it asks
/// the hub what it says of itself.
#[derive(Clone)]
struct Client(Arc<Net>, Arc<Desk>, Arc<AtomicUsize>);

impl Transport for Client {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let (net, desk, url) = (self.0.clone(), self.1.clone(), url.to_owned());
        if url.ends_with(INFO) && !url.starts_with(PROVIDER) {
            self.2.fetch_add(1, Ordering::Relaxed);
        }
        async move {
            match url.strip_prefix(PROVIDER) {
                Some(path) => desk.serve(path, body).await,
                None => net.serve(&url, body),
            }
        }
    }
}

struct Eco {
    net: Arc<Net>,
    desk: Arc<Desk>,
    dir: tempfile::TempDir,
    client: Wallet<Client>,
    view: View,
}

impl Eco {
    /// Hub A at height 3, a provider paying out on its chain, and a client
    /// holding 3000 at A.
    async fn new() -> Self {
        Self::with_fee(FEE).await
    }

    async fn with_fee(fee: Fee) -> Self {
        let net = Net::new();
        net.start_timed(A, fee, TIMED);
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("provider.sqlite"),
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        wallet.add_hub(A).await.unwrap();
        let desk = Arc::new(Desk {
            net: net.clone(),
            wallet,
            key: SecretKey::from_slice(&[0x5e; 32]).unwrap(),
            terms: Mutex::new(Some(TERMS)),
            decline: AtomicBool::new(false),
            false_share: AtomicBool::new(false),
            timeout: Mutex::default(),
            taken: Mutex::default(),
        });
        let client = Self::client(&net, &desk, &dir, true).await;
        client
            .receive(&net.pay(A, &client.address(), 3000))
            .unwrap();
        let view = net.view(A);
        Self {
            net,
            desk,
            dir,
            client,
            view,
        }
    }

    /// The client's wallet, made or opened again.
    async fn client(
        net: &Arc<Net>,
        desk: &Arc<Desk>,
        dir: &tempfile::TempDir,
        new: bool,
    ) -> Wallet<Client> {
        let (path, link) = (
            dir.path().join("client.sqlite"),
            Client(net.clone(), desk.clone(), Arc::default()),
        );
        if !new {
            return Wallet::open(&path, link).unwrap();
        }
        let client =
            Wallet::create(&path, &[0xc1; 32], ChainProfile::Core30DefaultRegtest, link).unwrap();
        client.add_hub(A).await.unwrap();
        client
    }

    /// Pay `amount` out to [`PAYEE`]: the client's lock made, the provider
    /// asked.
    async fn pay_out(&self, amount: u64) -> Payout {
        let quote = self
            .client
            .payout_quote(PROVIDER, A, PAYEE, amount, MAX_FEE, ONE_SAT)
            .await
            .unwrap();
        let payout = self.client.payout(&quote).await.unwrap();
        assert!(payout.lock.is_some(), "{payout:?}");
        payout
    }

    async fn follow(&self, payout: &Payout) -> Result<Payout, Error> {
        self.client.follow_payout(&payout.hash, &self.view).await
    }

    /// Follow `payout` while it waits: where it stands then.
    async fn settled(&self, payout: &Payout) -> Payout {
        match self.follow(payout).await {
            Ok(payout) => payout,
            Err(Error::Pending { .. }) => self.client.payouts().unwrap().remove(0),
            Err(e) => panic!("{e}"),
        }
    }

    fn mine(&self, blocks: u32) {
        self.net.mine(A, blocks, None);
    }

    /// Mine until the chain is at `height`.
    fn mine_to(&self, height: u32) {
        let tip = self.view.height();
        assert!(tip <= height, "{tip} past {height}");
        self.mine(height - tip);
    }

    fn held(&self) -> u64 {
        let balance = self.client.balance().unwrap();
        balance
            .iter()
            .find(|b| b.hub == A)
            .map_or(0, |b| b.available)
    }

    fn timeout(&self) -> u32 {
        self.desk.with(|t| t.htlc.timeout)
    }
}

fn payee() -> ScriptBuf {
    bitcoin::Address::from_str(PAYEE)
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

fn pending(result: Result<Payout, Error>, why: &str) {
    match result {
        Err(Error::Pending { reason, .. }) => assert!(reason.contains(why), "{reason}"),
        other => panic!("{other:?}"),
    }
}

fn failed(payout: &Payout, why: &str) {
    match &payout.state {
        PayoutState::Failed(reason) => assert!(reason.contains(why), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_payouts_progress_shows_each_step_as_it_comes() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let progress = |eco: &Eco| eco.client.payout_progress(&payout.hash).unwrap();
    let first = progress(&eco);
    assert!(first.lock.is_some(), "{first:?}");
    assert_eq!((first.coin, first.claim, first.depth), (None, None, 1));
    pending(eco.follow(&payout).await, "not confirmed yet");
    // Certified, and the provider's terms taken: the block to claim by.
    let taken = progress(&eco);
    let (state, expiry) = taken.lock.clone().unwrap();
    assert_eq!(state, LockState::Locked);
    let timeout = eco.desk.with(|t| t.htlc.timeout);
    assert!(timeout < expiry, "{timeout} {expiry}");
    assert_eq!(taken.timeout, Some(timeout));
    assert_eq!(taken.claim_by, Some(timeout - CLAIM_ROOM));
    assert_eq!(taken.coin, None);
    // Broadcast, not confirmed: shown as the provider tells of it.
    let told = Txid::from_byte_array([0xab; 32]);
    eco.desk.with(|t| t.answer.txid = Some(told.to_string()));
    pending(eco.follow(&payout).await, "not confirmed yet");
    let broadcast = progress(&eco);
    assert_eq!((broadcast.coin, broadcast.coin_height), (Some(told), None));
    // Confirmed and claimed: the coin as found, then the claim's block.
    let coin = eco.desk.fund(None, None);
    let funded = eco.net.view(A).height();
    let claimed = eco.follow(&payout).await.unwrap();
    let claiming = progress(&eco);
    assert_eq!(claiming.coin, Some(coin.txid));
    assert_eq!(claiming.coin_height, Some(funded));
    assert_eq!(
        (claiming.claim, claiming.claim_height),
        (claimed.claim, None)
    );
    eco.net.confirm(A, eco.client.payout_claims().unwrap());
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    let done = progress(&eco);
    assert_eq!(done.claim_height, Some(eco.net.view(A).height()));
}

/// A payout done is looked at again until its claim is buried: under way
/// again, its claim broadcast again, once a reorganization takes its
/// block out.
#[tokio::test]
async fn a_payout_done_whose_claim_leaves_the_chain_is_under_way_again() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    let claims = eco.client.payout_claims().unwrap();
    eco.net.confirm(A, claims.clone());
    let claimed = eco.view.height();
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    eco.mine(2);
    // Still in the chain: done still, nothing to broadcast.
    let (followed, waiting) = eco.client.follow_payouts(&eco.view).await.unwrap();
    assert!(followed.is_empty() && waiting.is_empty(), "{waiting:?}");
    assert!(eco.client.payout_claims().unwrap().is_empty());
    // Its block replaced by a longer chain without it.
    eco.net.reorg(A, claimed - 1);
    eco.mine(4);
    let (followed, waiting) = eco.client.follow_payouts(&eco.view).await.unwrap();
    assert_eq!(followed.len(), 1);
    assert_ne!(followed[0].state, PayoutState::Done);
    assert!(waiting[0].1.contains("not confirmed yet"), "{waiting:?}");
    assert_eq!(eco.client.payout_claims().unwrap(), claims);
    // In a block again: done.
    eco.net.confirm(A, claims);
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_payout_pays_the_address_exactly_and_the_provider_its_lock() {
    let eco = Eco::new().await;
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let value = quote.value();
    assert_eq!(quote.fee, TERMS.pays(value) - value);
    assert_eq!(quote.lock_fee, FEE.base);
    let payout = eco.pay_out(1000).await;
    assert_eq!(payout.state, PayoutState::Open);
    assert_eq!(
        (payout.amount, payout.budget, payout.fee),
        (1000, quote.budget, quote.fee)
    );
    // Nothing is claimed before the coin confirms.
    pending(eco.follow(&payout).await, "not confirmed yet");
    assert!(eco.client.payout_claims().unwrap().is_empty());
    let coin = eco.desk.fund(None, None);
    let claimed = eco.follow(&payout).await.unwrap();
    assert_eq!(claimed.state, PayoutState::Claimed);
    assert_eq!(claimed.funding, Some(coin));
    let claims = eco.client.payout_claims().unwrap();
    assert_eq!(claims.len(), 1);
    let claim = &claims[0];
    assert_eq!(Some(claim.compute_txid()), claimed.claim);
    assert_eq!(claim.input[0].previous_output, coin);
    // The payee gets the amount exactly; the rest of the coin is the fee.
    assert_eq!(claim.output.len(), 1);
    assert_eq!(claim.output[0].value, Amount::from_sat(1000));
    assert_eq!(claim.output[0].script_pubkey, payee());
    assert!(
        quote.budget as usize >= claim.vsize() * 3,
        "{}",
        claim.vsize()
    );
    pending(eco.follow(&payout).await, "not confirmed yet");
    eco.net.confirm(A, claims.clone());
    let done = eco.follow(&payout).await.unwrap();
    assert_eq!(done.state, PayoutState::Done);
    assert!(eco.client.payout_claims().unwrap().is_empty());
    // The provider claims the client's lock with the preimage revealed.
    eco.desk.settle(claim, coin).await;
    let lock = eco
        .client
        .follow_lock(payout.lock.as_ref().unwrap())
        .await
        .unwrap();
    assert!(matches!(lock.state, LockState::Paid(_)), "{lock:?}");
    let total = value + quote.fee;
    assert_eq!(eco.held(), 3000 - total - FEE.base);
    assert_eq!(eco.client.payouts().unwrap(), vec![done]);
}

/// A payout's lock is claimed by the provider only once the payout's claim
/// revealed the preimage, after the payout is done: following the payouts
/// follows it on, the change of its notes back. Once, the change stayed
/// pending until `resume`.
#[tokio::test]
async fn following_payouts_settles_the_lock_of_one_done() {
    let eco = Eco::new().await;
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let payout = eco.pay_out(1000).await;
    let coin = eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    let claims = eco.client.payout_claims().unwrap();
    eco.net.confirm(A, claims.clone());
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    eco.desk.settle(&claims[0], coin).await;
    let total = quote.value() + quote.fee;
    assert!(eco.held() < 3000 - total - FEE.base, "its change pending");
    let (_, waiting) = eco.client.follow_payouts(&eco.view).await.unwrap();
    assert!(waiting.is_empty(), "{waiting:?}");
    let locks = eco.client.locks().unwrap();
    assert!(matches!(locks[0].state, LockState::Paid(_)), "{locks:?}");
    assert_eq!(eco.held(), 3000 - total - FEE.base);
    // Settled, it is not asked of again.
    let asked = || eco.client.transport().2.load(Ordering::Relaxed);
    let before = asked();
    eco.client.follow_payouts(&eco.view).await.unwrap();
    assert_eq!(asked(), before);
}

#[tokio::test]
async fn a_payout_asks_its_hub_what_it_says_of_itself_once_to_lock() {
    let eco = Eco::new().await;
    let asked = || eco.client.transport().2.load(Ordering::Relaxed);
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let before = asked();
    let payout = eco.client.payout(&quote).await.unwrap();
    // Once for its terms, its lock and whether that expired: each round
    // trip a wait over Tor.
    assert_eq!(asked() - before, 1);
    assert_eq!(payout.state, PayoutState::Open);
    // Followed, whether the lock expired is asked again, as is the height
    // once the provider names its coin, for the room left to claim it.
    let before = asked();
    pending(eco.follow(&payout).await, "not confirmed yet");
    assert_eq!(asked() - before, 1);
    eco.desk.fund(None, None);
    let before = asked();
    let claimed = eco.follow(&payout).await.unwrap();
    assert_eq!(claimed.state, PayoutState::Claimed);
    assert_eq!(asked() - before, 2);
}

#[tokio::test]
async fn a_coin_never_locked_reveals_nothing_and_the_lock_is_refunded() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let lock = eco.client.locks().unwrap().remove(0);
    pending(eco.follow(&payout).await, "not confirmed yet");
    // Expired, and buried: refunded.
    eco.mine_to(lock.expiry + 1);
    let payout = eco.settled(&payout).await;
    failed(&payout, "its lock was refunded");
    assert!(eco.client.payout_claims().unwrap().is_empty());
    assert_eq!(eco.held(), 3000 - FEE.base);
    // A coin locked late is not claimed.
    eco.desk.fund(None, None);
    assert_eq!(eco.settled(&payout).await, payout);
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_coin_worth_less_than_asked_is_never_claimed() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let asked = payout.amount + payout.budget;
    eco.desk.fund(Some(asked - 1), None);
    let payout = eco.follow(&payout).await.unwrap();
    failed(&payout, &format!("worth {} of {asked}", asked - 1));
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_coin_not_where_the_provider_says_is_waited_for() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    // Paying other terms: no coin of this payout.
    eco.desk.fund(None, Some(payee()));
    pending(eco.follow(&payout).await, "not in block");
    // Said to be in another block.
    let coin = eco.desk.fund(None, None);
    eco.desk
        .with(|t| t.answer.funding.as_mut().unwrap().height -= 1);
    pending(eco.follow(&payout).await, "not in block");
    // Said to be in a block not mined yet.
    eco.desk
        .with(|t| t.answer.funding.as_mut().unwrap().height += 2);
    pending(eco.follow(&payout).await, "past the tip");
    eco.desk
        .with(|t| t.answer.funding.as_mut().unwrap().height -= 1);
    let payout = eco.follow(&payout).await.unwrap();
    assert_eq!(
        (payout.state, payout.funding),
        (PayoutState::Claimed, Some(coin))
    );
}

#[tokio::test]
async fn a_coin_too_close_to_its_timeout_is_never_claimed() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    pending(eco.follow(&payout).await, "not confirmed yet");
    let timeout = eco.timeout();
    eco.mine_to(timeout - CLAIM_ROOM);
    eco.desk.fund(None, None);
    let payout = eco.follow(&payout).await.unwrap();
    failed(&payout, "too late to claim");
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_claim_made_is_kept_across_a_restart_until_it_confirms() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    eco.desk.fund(None, None);
    let claimed = eco.follow(&payout).await.unwrap();
    let claims = eco.client.payout_claims().unwrap();
    let Eco {
        net,
        desk,
        dir,
        client,
        view,
    } = eco;
    drop(client);
    let client = Eco::client(&net, &desk, &dir, false).await;
    let eco = Eco {
        net,
        desk,
        dir,
        client,
        view,
    };
    assert_eq!(eco.client.payouts().unwrap(), vec![claimed.clone()]);
    assert_eq!(eco.client.payout_claims().unwrap(), claims);
    // Not confirmed as the provider's coin times out: broadcast still, made
    // again at a higher fee, of the same coin to the same payee.
    eco.mine_to(eco.timeout() + 1);
    pending(eco.follow(&payout).await, "not confirmed yet");
    let again = eco.client.payout_claims().unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(
        again[0].input[0].previous_output,
        claims[0].input[0].previous_output
    );
    assert_eq!(again[0].output[0].script_pubkey, payee());
    assert!(again[0].output[0].value < claims[0].output[0].value);
    eco.net.confirm(A, again);
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
}

/// That `claim` spends `coin`, worth `value` and paying `htlc`, by its
/// claim leaf: the leaf committed to in the coin's output key, signed by
/// its claim key.
fn spends_by(htlc: &Htlc, claim: &Transaction, coin: OutPoint, value: u64) {
    use bitcoin::{
        secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey},
        sighash::{Prevouts, SighashCache},
        taproot::{ControlBlock, LeafVersion},
        TapLeafHash, TapSighashType,
    };
    assert!(htlc.claimed_by(claim, coin));
    let index = claim
        .input
        .iter()
        .position(|i| i.previous_output == coin)
        .unwrap();
    let witness: Vec<&[u8]> = claim.input[index].witness.iter().collect();
    let script = htlc.claim_script();
    let (control, leaf) = (witness[witness.len() - 1], witness[witness.len() - 2]);
    assert_eq!(leaf, script.as_bytes());
    let secp = Secp256k1::verification_only();
    let output = htlc.script_pubkey();
    let output_key = XOnlyPublicKey::from_slice(&output.as_bytes()[2..]).unwrap();
    let control = ControlBlock::decode(control).unwrap();
    assert!(control.verify_taproot_commitment(&secp, output_key, &script));
    let prevout = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: output,
    };
    let sighash = SighashCache::new(claim)
        .taproot_script_spend_signature_hash(
            index,
            &Prevouts::All(&[prevout]),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = schnorr::Signature::from_slice(witness[0]).unwrap();
    secp.verify_schnorr(&signature, &message, &htlc.claim)
        .unwrap();
}

/// A provider of a version before payout coins were sized locks its coin
/// to the payout's terms unsized: the wallet claims it as it pays, by the
/// unsized claim leaf, and follows that claim across a restart, made again
/// at a higher fee as the timeout nears, until it confirms.
#[tokio::test]
async fn a_coin_locked_unsized_by_a_provider_before_sized_coins_is_claimed_as_it_pays() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let legacy = Htlc {
        sized: false,
        ..eco.desk.with(|t| t.htlc)
    };
    let value = payout.amount + payout.budget;
    let coin = eco.desk.fund(None, Some(legacy.script_pubkey()));
    let claimed = eco.follow(&payout).await.unwrap();
    assert_eq!(
        (claimed.state, claimed.funding),
        (PayoutState::Claimed, Some(coin))
    );
    let first = eco.client.payout_claims().unwrap().remove(0);
    spends_by(&legacy, &first, coin, value);
    let Eco {
        net,
        desk,
        dir,
        client,
        view,
    } = eco;
    drop(client);
    let client = Eco::client(&net, &desk, &dir, false).await;
    let eco = Eco {
        net,
        desk,
        dir,
        client,
        view,
    };
    // Fewer than CLAIM_ROOM blocks left: made again, by the same leaf.
    eco.mine_to(eco.timeout() - CLAIM_ROOM + 1);
    pending(eco.follow(&payout).await, "not confirmed yet");
    let again = eco.client.payout_claims().unwrap().remove(0);
    assert_ne!(again, first);
    spends_by(&legacy, &again, coin, value);
    eco.net.confirm(A, vec![again.clone()]);
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    eco.desk.settle(&again, coin).await;
}

#[tokio::test]
async fn a_claim_in_no_block_as_the_timeout_nears_pays_more_the_payee_paid_less() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let coin = eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    let first = eco.client.payout_claims().unwrap().remove(0);
    let value = payout.amount + payout.budget;
    let fee = |claim: &Transaction| value - claim.output[0].value.to_sat();
    assert_eq!(fee(&first), payout.budget);
    // Kept while CLAIM_ROOM blocks are left.
    eco.mine_to(eco.timeout() - CLAIM_ROOM);
    pending(eco.follow(&payout).await, "not confirmed yet");
    assert_eq!(eco.client.payout_claims().unwrap(), vec![first.clone()]);
    // One fewer: made again, at twice its fee or so, of the payee's 1000.
    eco.mine(1);
    pending(eco.follow(&payout).await, "not confirmed yet");
    let second = eco.client.payout_claims().unwrap().remove(0);
    assert_ne!(second, first);
    let doubled = fee(&second);
    assert!(
        doubled >= 2 * payout.budget - 2 && doubled <= 2 * payout.budget,
        "{doubled} of {}",
        payout.budget
    );
    assert_eq!(
        second.output[0].value.to_sat(),
        1000 - (doubled - payout.budget)
    );
    // Followed again at that rate: kept.
    pending(eco.follow(&payout).await, "not confirmed yet");
    assert_eq!(eco.client.payout_claims().unwrap(), vec![second.clone()]);
    // The first mined after all: done, the provider paid its lock.
    eco.net.confirm(A, vec![first.clone()]);
    let done = eco.follow(&payout).await.unwrap();
    assert_eq!(done.state, PayoutState::Done);
    eco.desk.settle(&first, coin).await;
}

/// The preimage, public once the claim is broadcast, riding on the
/// provider's refund (as a taproot annex may carry it): still a refund,
/// the provider's coin back, never a claim paid out.
#[tokio::test]
async fn a_refund_carrying_the_preimage_is_not_a_claim() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let coin = eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    let claims = eco.client.payout_claims().unwrap();
    let htlc = eco.desk.with(|t| t.htlc);
    let preimage = htlc.preimage_in(&claims[0], coin).expect("revealed");
    eco.mine_to(eco.timeout() + 1);
    let mut back = unchecked(
        coin,
        TxOut {
            value: Amount::from_sat(500),
            script_pubkey: ScriptBuf::new_op_return([1]),
        },
    );
    back.input[0].witness = bitcoin::Witness::from_slice(&[preimage]);
    assert_eq!(htlc.preimage_in(&back, coin), Some(preimage));
    assert!(!htlc.claimed_by(&back, coin));
    eco.net.confirm(A, vec![back]);
    let payout = eco.follow(&payout).await.unwrap();
    failed(&payout, "took its coin back first");
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_claim_beaten_by_the_providers_refund_is_lost() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let coin = eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    eco.mine_to(eco.timeout() + 1);
    eco.desk.refund(coin);
    let payout = eco.follow(&payout).await.unwrap();
    failed(&payout, "took its coin back first");
    assert!(payout.claim.is_some());
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_declining_fails_the_payout_before_any_coin() {
    let eco = Eco::new().await;
    eco.desk.decline.store(true, Ordering::Relaxed);
    let payout = eco.pay_out(1000).await;
    failed(&payout, "the provider declined");
    let lock = eco.client.locks().unwrap().remove(0);
    eco.mine_to(lock.expiry + 1);
    eco.client.resume().await.unwrap();
    assert_eq!(eco.held(), 3000 - FEE.base);
}

#[tokio::test]
async fn the_most_a_provider_pays_out_is_its_largest_coin_less_the_claims_fee() {
    let eco = Eco::new().await;
    let info = eco.client.provider_info(PROVIDER).await.unwrap();
    let most = eco
        .client
        .payout_most(&info, A, PAYEE, ONE_SAT)
        .unwrap()
        .expect("it pays out from A");
    assert!(most < TERMS.max, "{most}");
    let quote = |amount| {
        eco.client
            .payout_quote(PROVIDER, A, PAYEE, amount, MAX_FEE, ONE_SAT)
    };
    assert_eq!(quote(most).await.unwrap().value(), TERMS.max);
    match quote(most + 1).await {
        Err(Error::Invalid(reason)) => assert!(reason.contains("pays out coins of"), "{reason}"),
        other => panic!("{other:?}"),
    }
    // A provider paying nothing out on Bitcoin pays out no most.
    let none = swaps::Info {
        chain: None,
        ..info
    };
    assert_eq!(
        eco.client.payout_most(&none, A, PAYEE, ONE_SAT).unwrap(),
        None
    );
}

/// A wallet paying itself a coin raises it to the least a provider pays
/// out: a provider's smallest coin, risen with fees, refused a contract's
/// coin of its price and her part on Mutinynet.
#[tokio::test]
async fn the_least_a_provider_pays_out_is_its_smallest_coin_less_the_claims_fee() {
    let eco = Eco::new().await;
    let terms = swaps::Chain {
        min: 2_000,
        ..TERMS
    };
    *eco.desk.terms.lock().unwrap() = Some(terms);
    let info = eco.client.provider_info(PROVIDER).await.unwrap();
    let least = eco
        .client
        .payout_least(&info, A, PAYEE, ONE_SAT)
        .unwrap()
        .expect("it pays out from A");
    assert!(least < terms.min, "{least}");
    let quote = |amount| {
        eco.client
            .payout_quote(PROVIDER, A, PAYEE, amount, MAX_FEE, ONE_SAT)
    };
    assert_eq!(quote(least).await.unwrap().value(), terms.min);
    match quote(least - 1).await {
        Err(Error::Invalid(reason)) => assert!(reason.contains("pays out coins of"), "{reason}"),
        other => panic!("{other:?}"),
    }
    // Its smallest coin all claim fee: what pays no dust, at least.
    let all = swaps::Info {
        chain: Some(swaps::Chain { min: 1, ..terms }),
        ..info.clone()
    };
    let dust = eco.client.payout_least(&all, A, PAYEE, ONE_SAT).unwrap();
    assert_eq!(dust, Some(294));
    // A provider paying nothing out on Bitcoin pays out no least.
    let none = swaps::Info {
        chain: None,
        ..info
    };
    assert_eq!(
        eco.client.payout_least(&none, A, PAYEE, ONE_SAT).unwrap(),
        None
    );
}

#[tokio::test]
async fn a_payout_is_refused_beyond_its_terms_before_any_lock() {
    let eco = Eco::new().await;
    let quote = |to: &'static str, amount: u64, max_fee: u64| {
        let client = &eco.client;
        async move {
            client
                .payout_quote(PROVIDER, A, to, amount, max_fee, ONE_SAT)
                .await
        }
    };
    let refused = |result: Result<_, Error>, why: &str| match result {
        Err(Error::Invalid(reason) | Error::FeeRose { reason, .. }) => {
            assert!(reason.contains(why), "{reason}")
        }
        other => panic!("{other:?}"),
    };
    let costs = quote(PAYEE, 1000, MAX_FEE).await.unwrap().costs();
    refused(
        quote(PAYEE, 1000, costs - 1).await,
        &format!("asks {costs} sat"),
    );
    refused(
        quote(PAYEE, 100, MAX_FEE).await,
        "too little to pay on Bitcoin",
    );
    refused(
        quote(PAYEE, 4800, MAX_FEE).await,
        "pays out coins of 500 to 5000",
    );
    let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    refused(quote(mainnet, 1000, MAX_FEE).await, "not on");
    refused(quote("bitcoin", 1000, MAX_FEE).await, "not an address");
    // A rate judged higher than the provider's budgets the claim higher.
    let rate = FeeRate::from_sat_per_vb_u32(2);
    let dearer = eco
        .client
        .payout_quote(PROVIDER, A, PAYEE, 1000, MAX_FEE, rate)
        .await
        .unwrap();
    let usual = quote(PAYEE, 1000, MAX_FEE).await.unwrap();
    assert_eq!(dearer.budget, 2 * usual.budget);
    // A provider naming a rate of its own makes the claim no dearer than
    // allowed.
    *eco.desk.terms.lock().unwrap() = Some(swaps::Chain {
        rate: 50_000,
        max: 100_000,
        ..TERMS
    });
    refused(quote(PAYEE, 1000, MAX_FEE).await, "more than 2000");
    *eco.desk.terms.lock().unwrap() = None;
    refused(
        quote(PAYEE, 1000, MAX_FEE).await,
        "pays nothing out on Bitcoin",
    );
    // Asked again when paid: quoted before, refused now.
    let e = eco.client.payout(&usual).await.unwrap_err();
    assert!(matches!(e, Error::Invalid(_)), "{e}");
    assert!(eco.client.locks().unwrap().is_empty());
    assert!(eco.client.payouts().unwrap().is_empty());
}

#[tokio::test]
async fn a_coin_timed_out_by_a_time_or_after_the_lock_is_never_claimed() {
    // 500,000,000 on: a time, long past, under OP_CHECKLOCKTIMEVERIFY.
    for timeout in [bitcoin::absolute::LOCK_TIME_THRESHOLD, 1_000] {
        let eco = Eco::new().await;
        *eco.desk.timeout.lock().unwrap() = Some(timeout);
        let payout = eco.pay_out(1000).await;
        eco.desk.fund(None, None);
        let payout = eco.settled(&payout).await;
        failed(
            &payout,
            &format!("times out at {timeout}, not a block before"),
        );
        assert!(eco.client.payout_claims().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_public_preimage_is_claimed_with_inside_the_claim_margin() {
    let eco = Eco::new().await;
    let payout = eco.pay_out(1000).await;
    let coin = eco.desk.fund(None, None);
    eco.follow(&payout).await.unwrap();
    let claims = eco.client.payout_claims().unwrap();
    eco.net.confirm(A, claims.clone());
    let lock = eco.client.locks().unwrap().remove(0);
    eco.mine_to(lock.expiry - licash_wallet::CLAIM_MARGIN);
    let (htlc, id) = eco.desk.with(|t| (t.htlc, t.lock.clone()));
    let preimage = htlc.preimage_in(&claims[0], coin).unwrap();
    match eco.desk.wallet.claim(A, &id, &preimage).await {
        Err(Error::Invalid(why)) => assert!(why.contains("too late to claim"), "{why}"),
        other => panic!("{other:?}"),
    }
    eco.desk
        .wallet
        .claim_revealed(A, &id, &preimage)
        .await
        .unwrap();
    let lock = eco.client.follow_lock(&lock.id).await.unwrap();
    assert!(matches!(lock.state, LockState::Paid(_)), "{lock:?}");
}

/// A payout to a silent payment address: the provider asked its share of
/// the payee's scan key blinded, never the key itself; the claim pays the
/// output the payee finds of the claim's own input, exactly the amount.
#[tokio::test]
async fn a_payout_pays_a_silent_payment_address_its_payee_finds() {
    use bitcoin::NetworkKind;
    use licash_onchain::silent::{self, Keys};
    let eco = Eco::new().await;
    let secret = |b: u8| SecretKey::from_slice(&[b; 32]).unwrap();
    let payee = Keys::new(secret(0x71), secret(0x72), NetworkKind::Test);
    let to = payee.address().to_string();
    assert!(to.starts_with("tsp1"), "{to}");
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, &to, 1000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let payout = eco.client.payout(&quote).await.unwrap();
    assert_eq!(payout.address, to);
    pending(eco.follow(&payout).await, "not confirmed yet");
    let coin = eco.desk.fund(None, None);
    let claimed = eco.follow(&payout).await.unwrap();
    assert_eq!(claimed.state, PayoutState::Claimed);
    let claims = eco.client.payout_claims().unwrap();
    let claim = &claims[0];
    assert_eq!((claim.input.len(), claim.output.len()), (1, 1));
    assert_eq!(claim.output[0].value, Amount::from_sat(1000));
    // The payee finds it of the claim's tweak, as any spend's.
    let htlc = eco.desk.with(|t| t.htlc);
    let prevout = htlc.script_pubkey();
    let tweak = silent::tweak(claim, &[prevout.as_script()]).expect("a claim counted");
    let found = payee
        .scanner([])
        .scan(&tweak, &silent::taproot_outputs(claim));
    assert_eq!(found.len(), 1);
    // Asked again, the same claim: the share kept as first proven.
    eco.net.confirm(A, claims.clone());
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    assert_eq!(eco.client.payout_claims().unwrap(), vec![]);
    eco.desk.settle(claim, coin).await;
}

/// A provider answering a share not of its refund key: nothing claimed,
/// the payout failed, its lock refunded once expired.
#[tokio::test]
async fn a_payout_to_a_silent_payment_address_of_a_false_share_claims_nothing() {
    use bitcoin::NetworkKind;
    use licash_onchain::silent::Keys;
    let eco = Eco::new().await;
    eco.desk.false_share.store(true, Ordering::Relaxed);
    let secret = |b: u8| SecretKey::from_slice(&[b; 32]).unwrap();
    let to = Keys::new(secret(0x71), secret(0x72), NetworkKind::Test)
        .address()
        .to_string();
    let quote = eco
        .client
        .payout_quote(PROVIDER, A, &to, 1000, MAX_FEE, ONE_SAT)
        .await
        .unwrap();
    let payout = eco.client.payout(&quote).await.unwrap();
    let followed = eco.settled(&payout).await;
    failed(&followed, "share of the payee's scan key");
    eco.desk.fund(None, None);
    let after = eco.settled(&payout).await;
    failed(&after, "share");
    assert!(eco.client.payout_claims().unwrap().is_empty());
}

/// Cold storage of a tpub's segwit addresses: once the notes exceed its
/// threshold, a withdrawal of all but what it keeps is due to its first
/// address, one at a time; paid out, the next is another, and the coin is
/// found at the first, counted in its balance.
#[tokio::test]
async fn notes_past_the_threshold_are_withdrawn_to_cold_storage_never_to_an_address_twice() {
    use bitcoin::bip32::{Xpriv, Xpub};
    use licash_wallet::{ColdRules, ColdScript};
    let eco = Eco::new().await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &[0xc0; 32]).unwrap();
    let tpub = Xpub::from_priv(&secp, &master).to_string();
    assert!(tpub.starts_with("tpub"), "{tpub}");
    let rules = ColdRules {
        threshold: 2_000,
        keep: 1_000,
        max_fee_percent: 30.0,
    };
    let birthday = eco.view.height();
    // An xpub's kind of address is chosen.
    assert!(eco.client.set_cold(&tpub, None, rules, birthday).is_err());
    let cold = eco
        .client
        .set_cold(&tpub, Some(ColdScript::Wpkh), rules, birthday)
        .unwrap();
    assert_eq!((cold.next_index, cold.balance, cold.pending), (0, 0, None));
    assert!(cold.next.starts_with("bcrt1q"), "{}", cold.next);
    let due = eco.client.cold_due().unwrap().expect("due past 2,000");
    assert_eq!(
        (due.to.as_str(), due.amount, due.max_fee),
        (cold.next.as_str(), 2_000, 600)
    );
    let quote = eco
        .client
        .payout_quote(
            PROVIDER,
            &due.from,
            &due.to,
            due.amount,
            due.max_fee,
            ONE_SAT,
        )
        .await
        .unwrap();
    let payout = eco.client.payout(&quote).await.unwrap();
    // Under way: none other due, the next address another.
    let cold = eco.client.cold().unwrap().unwrap();
    assert_eq!(cold.pending.as_deref(), Some(payout.hash.as_str()));
    assert_eq!(cold.next_index, 1);
    assert_ne!(cold.next, due.to);
    assert_eq!(eco.client.cold_due().unwrap(), None);

    pending(eco.follow(&payout).await, "not confirmed yet");
    let coin = eco.desk.fund(None, None);
    assert_eq!(
        eco.follow(&payout).await.unwrap().state,
        PayoutState::Claimed
    );
    let claims = eco.client.payout_claims().unwrap();
    eco.net.confirm(A, claims.clone());
    let claimed = eco.view.height();
    assert_eq!(eco.follow(&payout).await.unwrap().state, PayoutState::Done);
    eco.desk.settle(&claims[0], coin).await;
    let cold = eco
        .client
        .scan_cold(&eco.view, 1_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((cold.balance, cold.coins, &cold.pending), (2_000, 1, &None));
    assert_eq!(cold.scanned, Some(eco.view.height()));
    // Looked in again: counted once.
    let again = eco
        .client
        .scan_cold(&eco.view, 1_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again, cold);
    // Below the threshold now: nothing due.
    assert_eq!(eco.client.cold_due().unwrap(), None);
    // Its block replaced while the wallet is blocks behind: looked in
    // again all the same, the coin gone.
    eco.net.reorg(A, claimed - 1);
    eco.mine(12);
    let gone = eco.client.scan_cold(&eco.view, 1).await.unwrap().unwrap();
    assert_eq!((gone.balance, gone.coins), (0, 0));
    assert_eq!(gone.scanned, Some(cold.scanned.unwrap() + 1));
    eco.client.clear_cold().unwrap();
    assert_eq!(eco.client.cold().unwrap(), None);
}
