//! Deposits on Bitcoin for wallets: a coin hash-locked to the provider
//! under the wallet's hash, paid on as a lock of the provider's notes to
//! the wallet once told of, the coin claimed with the preimage the
//! wallet's claim shows; nothing locked for a coin never told of, and the
//! coin left to its payer once the lock is refunded.

#[allow(dead_code)]
#[path = "../../licash-wallet/tests/net/mod.rs"]
mod net;

use std::sync::{Arc, Mutex};

use bitcoin::{
    hashes::Hash, key::Secp256k1, secp256k1::SecretKey, transaction, Amount, BlockHash, FeeRate,
    OutPoint, Transaction, TxIn, TxOut, Txid,
};
use licash::spend::{lock_hash, ChainProfile};
use licash_api::{swaps::DepositRequest, Code, Fee, Funding, Hex, ReceiveState};
use licash_swaps::{Chain, Config, DepositState, DepositTerms, Notice, Provider, RECEIVE_BLOCKS};
use licash_wallet::{Blocks, Wallet};
use net::{Fault, Link, Net, View};

const A: &str = "http://a.test";
const FEE: Fee = Fee { base: 1, ppm: 0 };
const TERMS: DepositTerms = DepositTerms {
    fee: Fee { base: 1, ppm: 0 },
    miner: 200,
    min: 100,
    max: 5_000,
    depth: 2,
    window: 6,
    timeout: 400,
    sweep: 10,
    max_open: 3,
};
/// What the provider holds at A to start with.
const HELD: u64 = 3_000;
/// Blocks by which the provider's lock expires before the coin times out,
/// at least: the refund request's confirmation (36), A's window (20),
/// reading the preimage, the provider's margin (12) and one, then the
/// sweep.
const LEAD: u32 = 36 + 20 + 1 + 12 + 1;
/// Blocks from the request to the coin's timeout.
const TIMEOUT: u32 = TERMS.window + TERMS.depth + RECEIVE_BLOCKS + LEAD + TERMS.sweep + 3;
/// The payer's refund key.
const REFUND: [u8; 32] = [0x77; 32];

/// Hub A's chain and a mempool: what is broadcast waits there until a test
/// mines it.
#[derive(Clone)]
struct Pool {
    net: Arc<Net>,
    view: View,
    txs: Arc<Mutex<Vec<Transaction>>>,
}

impl Pool {
    fn mine(&self) -> Vec<Transaction> {
        let txs: Vec<Transaction> = std::mem::take(&mut *self.txs.lock().unwrap());
        self.net.confirm(A, txs.clone());
        txs
    }

    fn waiting(&self) -> Vec<Transaction> {
        self.txs.lock().unwrap().clone()
    }
}

impl Blocks for Pool {
    fn height(&self) -> impl std::future::Future<Output = Result<u32, String>> + Send {
        Blocks::height(&self.view)
    }

    fn hash(
        &self,
        height: u32,
    ) -> impl std::future::Future<Output = Result<BlockHash, String>> + Send {
        self.view.hash(height)
    }

    fn filter(
        &self,
        hash: &BlockHash,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, String>> + Send {
        self.view.filter(hash)
    }

    fn block(
        &self,
        hash: &BlockHash,
    ) -> impl std::future::Future<Output = Result<bitcoin::Block, String>> + Send {
        self.view.block(hash)
    }
}

impl Chain for Pool {
    fn broadcast(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send {
        let mut txs = self.txs.lock().unwrap();
        let spends = |t: &Transaction| {
            t.input.iter().any(|i| {
                tx.input
                    .iter()
                    .any(|o| o.previous_output == i.previous_output)
            })
        };
        txs.retain(|t| !spends(t));
        txs.push(tx.clone());
        std::future::ready(Ok(()))
    }

    fn fee_rate(
        &self,
        _blocks: u16,
    ) -> impl std::future::Future<Output = Result<Option<FeeRate>, String>> + Send {
        std::future::ready(Ok(Some(FeeRate::from_sat_per_vb_u32(1))))
    }
}

/// A transaction paying `output` of a coin made up: the hub's chain checks
/// nothing.
fn made_up(output: TxOut) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0xf0; 32]), 3),
            ..Default::default()
        }],
        output: vec![output],
    }
}

fn refund_key() -> [u8; 32] {
    let secret = SecretKey::from_slice(&REFUND).unwrap();
    secret.x_only_public_key(&Secp256k1::new()).0.serialize()
}

struct Eco {
    net: Arc<Net>,
    _dir: tempfile::TempDir,
    provider: Provider<Link>,
    payee: Wallet<Link>,
    pool: Pool,
}

impl Eco {
    /// Hub A, a provider holding 3,000 there taking deposits on `terms`,
    /// and a payee at A.
    async fn new(terms: DepositTerms) -> Self {
        let net = Net::new();
        net.start(A, FEE);
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[0x50; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        wallet.add_hub(A).await.unwrap();
        wallet
            .receive(&net.pay(A, &wallet.address(), HELD))
            .unwrap();
        let provider = Provider::create(wallet, Config::default())
            .unwrap()
            .take_deposits(terms)
            .unwrap();
        let payee = Wallet::create(
            &dir.path().join("payee.sqlite"),
            &[0xd0; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        payee.add_hub(A).await.unwrap();
        let pool = Pool {
            net: net.clone(),
            view: net.view(A),
            txs: Arc::default(),
        };
        Self {
            net,
            _dir: dir,
            provider,
            payee,
            pool,
        }
    }

    fn height(&self) -> u32 {
        self.pool.view.height()
    }

    /// `blocks` mined, the provider's view of A following.
    async fn mine(&self, blocks: u32) {
        if blocks > 0 {
            self.net.mine(A, blocks, None);
        }
        self.provider.wallet().add_hub(A).await.unwrap();
    }

    /// The payee's request of a deposit of `amount` under the preimage
    /// `[seed; 32]`.
    fn request(&self, amount: u64, seed: u8) -> DepositRequest {
        DepositRequest {
            hub: self.payee.hubs().unwrap()[0].1.address,
            address: self.payee.address(),
            amount,
            hash: Hex(lock_hash(&[seed; 32]).to_vec()),
            refund: Hex(refund_key().to_vec()),
        }
    }

    /// The coin of the deposit under `hash` paying `value`, confirmed now:
    /// as its wallet tells of it.
    fn pay(&self, hash: &[u8; 32], value: u64) -> Funding {
        let deposit = self.provider.deposit_record(hash).unwrap().unwrap();
        let tx = made_up(TxOut {
            value: Amount::from_sat(value),
            script_pubkey: deposit.htlc().unwrap().script_pubkey(),
        });
        let txid = tx.compute_txid();
        self.net.confirm(A, vec![tx]);
        Funding {
            txid: txid.to_string(),
            vout: 0,
            height: self.height(),
        }
    }

    async fn follow(&self) {
        let pending = self.provider.follow_deposits(&self.pool).await.unwrap();
        assert!(pending.is_empty(), "{pending:?}");
    }

    fn state(&self, hash: &[u8; 32]) -> DepositState {
        self.provider.deposit_record(hash).unwrap().unwrap().state
    }

    fn held(&self) -> u64 {
        let balance = self.provider.wallet().balance().unwrap();
        balance
            .iter()
            .find(|b| b.hub == A)
            .map_or(0, |b| b.available)
    }

    fn alerts(&self) -> Vec<String> {
        let events = self.provider.events(0, 100).unwrap();
        events
            .iter()
            .filter_map(|e| match e.notice() {
                Some(Notice::Alert { message }) => Some(message),
                _ => None,
            })
            .collect()
    }

    /// The lock the provider tells the payee to claim.
    fn lock(&self, hash: &[u8; 32]) -> String {
        let status = self.provider.deposit_status(hash).unwrap().unwrap();
        assert_eq!(status.state, ReceiveState::Locked);
        hex::encode(status.lock().unwrap().unwrap().as_bytes())
    }

    /// A deposit of `amount` under the preimage `[seed; 32]`, paid and told
    /// of at depth: its hash.
    async fn funded(&self, amount: u64, seed: u8) -> [u8; 32] {
        let terms = self
            .provider
            .deposit(&self.request(amount, seed), None, &self.pool)
            .await
            .unwrap();
        let hash = lock_hash(&[seed; 32]);
        let funding = self.pay(&hash, terms.amount);
        self.mine(TERMS.depth - 1).await;
        let status = self
            .provider
            .deposit_funded(&hash, &funding, &self.pool)
            .await
            .unwrap();
        assert_eq!(status.state, ReceiveState::Locked);
        hash
    }
}

#[tokio::test]
async fn a_deposit_told_of_is_locked_to_the_wallet_and_its_coin_claimed_once_it_claims() {
    let eco = Eco::new(TERMS).await;
    // Its info tells wallets its terms.
    let deposits = eco.provider.info().unwrap().deposits.unwrap();
    assert_eq!(
        (deposits.miner, deposits.depth, deposits.timeout),
        (200, 2, 400)
    );
    let tip = eco.height();
    let request = eco.request(1_000, 5);
    let terms = eco
        .provider
        .deposit(&request, None, &eco.pool)
        .await
        .unwrap();
    let hash = lock_hash(&[5; 32]);
    // The amount, the fee and the claim's miners, timed out late enough to
    // force the preimage out on Bitcoin should A keep it, then claim.
    assert_eq!(terms.amount, 1_000 + 1 + 200);
    assert_eq!((terms.timeout, terms.fund_by), (tip + TIMEOUT, tip + 6));
    let deposit = eco.provider.deposit_record(&hash).unwrap().unwrap();
    let htlc = deposit.htlc().unwrap();
    assert_eq!(htlc.refund.serialize(), refund_key());
    assert_eq!(htlc.claim.serialize().to_vec(), terms.claim.0);
    assert_eq!(
        terms.address,
        htlc.address(bitcoin::Network::Regtest).to_string()
    );
    assert!(licash_swaps::holds_hash(&eco._dir.path().join("wallet.sqlite"), &hash).unwrap());
    // The same request again answers the same terms; another under its
    // hash is declined.
    let again = eco
        .provider
        .deposit(&request, None, &eco.pool)
        .await
        .unwrap();
    assert_eq!(again, terms);
    let other = DepositRequest {
        amount: 900,
        ..request.clone()
    };
    let declined = eco.provider.deposit(&other, None, &eco.pool).await;
    assert_eq!(declined.unwrap_err().code, Code::Declined);
    // Nothing is locked, nor set aside, until its coin is told of.
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Open);
    assert_eq!(eco.held(), HELD);
    let funding = eco.pay(&hash, terms.amount);
    // Not deep enough yet.
    let shallow = eco
        .provider
        .deposit_funded(&hash, &funding, &eco.pool)
        .await;
    assert_eq!(shallow.unwrap_err().code, Code::Invalid);
    eco.mine(1).await;
    let told_at = eco.height();
    let status = eco
        .provider
        .deposit_funded(&hash, &funding, &eco.pool)
        .await
        .unwrap();
    assert_eq!(status.state, ReceiveState::Locked);
    let deposit = eco.provider.deposit_record(&hash).unwrap().unwrap();
    assert_eq!(deposit.state, DepositState::Locked);
    // Within A's window, long before the coin times out.
    let expiry = deposit.expiry.unwrap();
    assert!(expiry <= told_at + 20 && expiry + LEAD + TERMS.sweep <= terms.timeout);
    assert!(eco.held() < HELD - 1_000, "{}", eco.held());
    // Told again, the same.
    let again = eco
        .provider
        .deposit_funded(&hash, &funding, &eco.pool)
        .await
        .unwrap();
    assert_eq!(again, status);
    // The payee claims, showing the provider the preimage, which claims
    // the coin.
    let lock = eco.lock(&hash);
    let received = eco.payee.claim(A, &lock, &[5; 32]).await.unwrap();
    assert_eq!(received.amount, 1_000);
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Paid);
    let status = eco.provider.deposit_status(&hash).unwrap().unwrap();
    assert_eq!(status.state, ReceiveState::Settled);
    let claim = eco.pool.waiting();
    assert_eq!(claim.len(), 1);
    let outpoint = OutPoint::new(funding.txid.parse().unwrap(), 0);
    assert_eq!(htlc.preimage_in(&claim[0], outpoint), Some([5; 32]));
    assert!(claim[0].output[0].value.to_sat() > terms.amount - 200);
    let fallback = eco.provider.wallet().fallback_address().unwrap();
    assert_eq!(claim[0].output[0].script_pubkey, fallback.script_pubkey());
    // Claimed once deep enough.
    eco.pool.mine();
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Paid);
    eco.mine(1).await;
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Swept);
    assert_eq!(eco.provider.open_deposits().unwrap(), 0);
    assert!(eco.alerts().is_empty());
}

#[tokio::test]
async fn a_coin_never_told_of_locks_nothing_and_the_deposit_is_given_up() {
    let eco = Eco::new(TERMS).await;
    let terms = eco
        .provider
        .deposit(&eco.request(1_000, 5), None, &eco.pool)
        .await
        .unwrap();
    let hash = lock_hash(&[5; 32]);
    eco.pay(&hash, terms.amount);
    eco.mine(TERMS.window + TERMS.depth + RECEIVE_BLOCKS).await;
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Canceled);
    assert!(eco.provider.wallet().locks().unwrap().is_empty());
    assert_eq!(eco.held(), HELD);
    // Its terms are not answered again.
    let again = eco
        .provider
        .deposit(&eco.request(1_000, 5), None, &eco.pool)
        .await;
    assert_eq!(again.unwrap_err().code, Code::Declined);
}

#[tokio::test]
async fn a_coin_of_another_amount_late_or_elsewhere_is_refused() {
    let eco = Eco::new(TERMS).await;
    let terms = eco
        .provider
        .deposit(&eco.request(1_000, 5), None, &eco.pool)
        .await
        .unwrap();
    let hash = lock_hash(&[5; 32]);
    let short = eco.pay(&hash, terms.amount - 1);
    eco.mine(TERMS.depth).await;
    let refused = eco.provider.deposit_funded(&hash, &short, &eco.pool).await;
    assert_eq!(refused.unwrap_err().code, Code::Invalid);
    // An output of the coin it does not have.
    let elsewhere = Funding { vout: 1, ..short };
    let refused = eco
        .provider
        .deposit_funded(&hash, &elsewhere, &eco.pool)
        .await;
    assert_eq!(refused.unwrap_err().code, Code::Invalid);
    // Confirmed after its window.
    eco.mine(TERMS.window).await;
    let late = eco.pay(&hash, terms.amount);
    eco.mine(TERMS.depth).await;
    let refused = eco.provider.deposit_funded(&hash, &late, &eco.pool).await;
    assert_eq!(refused.unwrap_err().code, Code::Declined);
    assert_eq!(eco.state(&hash), DepositState::Open);
    assert!(eco.provider.wallet().locks().unwrap().is_empty());
    // Of no deposit.
    let none = eco
        .provider
        .deposit_funded(&[9; 32], &late, &eco.pool)
        .await;
    assert_eq!(none.unwrap_err().code, Code::Declined);
}

#[tokio::test]
async fn a_lock_never_claimed_is_refunded_and_the_coin_left_to_its_payer() {
    let eco = Eco::new(TERMS).await;
    let hash = eco.funded(1_000, 5).await;
    let expiry = eco
        .provider
        .deposit_record(&hash)
        .unwrap()
        .unwrap()
        .expiry
        .unwrap();
    eco.mine(expiry - eco.height() + 1).await;
    for _ in 0..4 {
        eco.mine(1).await;
        eco.follow().await;
    }
    assert_eq!(eco.state(&hash), DepositState::Canceled);
    let status = eco.provider.deposit_status(&hash).unwrap().unwrap();
    assert_eq!(status.state, ReceiveState::Canceled);
    assert!(eco.pool.waiting().is_empty());
    // The provider holds what it held, but the hub's fees.
    assert!(eco.held() >= HELD - 2, "{}", eco.held());
}

#[tokio::test]
async fn a_coin_taken_back_after_the_lock_was_claimed_is_lost_and_alerted() {
    let eco = Eco::new(TERMS).await;
    let hash = eco.funded(1_000, 5).await;
    let deposit = eco.provider.deposit_record(&hash).unwrap().unwrap();
    let lock = eco.lock(&hash);
    eco.payee.claim(A, &lock, &[5; 32]).await.unwrap();
    // The provider follows no more until the coin timed out, and its payer
    // took it back.
    eco.mine(deposit.timeout + 1 - eco.height()).await;
    let (outpoint, _) = deposit.funding.unwrap();
    let refund = deposit
        .htlc()
        .unwrap()
        .refund_tx(
            outpoint,
            Amount::from_sat(deposit.pays),
            eco.payee_script(),
            FeeRate::from_sat_per_vb_u32(1),
            &SecretKey::from_slice(&REFUND).unwrap(),
        )
        .unwrap();
    eco.net.confirm(A, vec![refund]);
    eco.mine(0).await;
    eco.follow().await;
    assert_eq!(eco.state(&hash), DepositState::Lost);
    let alerts = eco.alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("is lost"), "{alerts:?}");
}

#[tokio::test]
async fn a_hub_neither_paying_nor_refunding_a_deposits_lock_is_alerted() {
    let eco = Eco::new(TERMS).await;
    let hash = eco.funded(1_000, 5).await;
    let expiry = eco
        .provider
        .deposit_record(&hash)
        .unwrap()
        .unwrap()
        .expiry
        .unwrap();
    // Expired at depth and A's reaction: A owes the refund, and withholds it.
    eco.mine(expiry + 1 + 2 - eco.height()).await;
    eco.net.fail(licash_api::REFUND, Fault::Lost);
    let pending = eco.provider.follow_deposits(&eco.pool).await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let alerts = eco.alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains("may keep the preimage"), "{alerts:?}");
    assert!(alerts[0].contains("claim the deposit's coin"), "{alerts:?}");
    assert_eq!(eco.state(&hash), DepositState::Locked);
}

#[tokio::test]
async fn deposits_are_declined_past_what_the_provider_holds_or_its_timeout() {
    let eco = Eco::new(TERMS).await;
    let declined = eco
        .provider
        .deposit(&eco.request(HELD, 5), None, &eco.pool)
        .await;
    assert_eq!(declined.unwrap_err().code, Code::Declined);
    let invalid = eco
        .provider
        .deposit(&eco.request(TERMS.max + 1, 5), None, &eco.pool)
        .await;
    assert_eq!(invalid.unwrap_err().code, Code::Invalid);
    // A's windows need more blocks than the provider gives a coin.
    let eco = Eco::new(DepositTerms {
        timeout: TIMEOUT - 1,
        ..TERMS
    })
    .await;
    let declined = eco
        .provider
        .deposit(&eco.request(1_000, 5), None, &eco.pool)
        .await;
    let problem = declined.unwrap_err();
    assert_eq!(problem.code, Code::Declined);
    assert!(problem.message.contains("time out"), "{}", problem.message);
}

#[tokio::test]
async fn deposits_told_of_once_too_little_is_left_lock_nothing() {
    let eco = Eco::new(TERMS).await;
    let first = eco
        .provider
        .deposit(&eco.request(2_000, 5), None, &eco.pool)
        .await
        .unwrap();
    let second = eco
        .provider
        .deposit(&eco.request(2_000, 6), None, &eco.pool)
        .await
        .unwrap();
    let (one, two) = (lock_hash(&[5; 32]), lock_hash(&[6; 32]));
    let paid_one = eco.pay(&one, first.amount);
    let paid_two = eco.pay(&two, second.amount);
    eco.mine(TERMS.depth).await;
    let status = eco
        .provider
        .deposit_funded(&one, &paid_one, &eco.pool)
        .await
        .unwrap();
    assert_eq!(status.state, ReceiveState::Locked);
    let status = eco
        .provider
        .deposit_funded(&two, &paid_two, &eco.pool)
        .await
        .unwrap();
    assert_eq!(status.state, ReceiveState::Canceled);
    assert_eq!(eco.state(&two), DepositState::Canceled);
    assert_eq!(eco.provider.wallet().locks().unwrap().len(), 1);
}

impl Eco {
    /// A script of the payee's on Bitcoin.
    fn payee_script(&self) -> bitcoin::ScriptBuf {
        self.payee.fallback_address().unwrap().script_pubkey()
    }
}
