//! Donations taken over Lightning for a wallet that is not there: a held
//! invoice of the provider's node, paid on to the wallet of a Licash code
//! in notes at its hub, then settled; canceled while nothing was paid.

#[allow(dead_code)]
#[path = "../../licash-wallet/tests/net/mod.rs"]
mod net;

use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use licash::spend::ChainProfile;
use licash_api::{Code, Fee};
use licash_lightning::{fake::Fake, HeldState, Node};
use licash_swaps::{
    Config, DonationState, DonationTerms, Notice, Provider, INVOICE_CLTV, METADATA, SETTLE_MARGIN,
};
use licash_wallet::{Response, State, Transport, Wallet};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use net::{Conduct, Fault, Link, Net};

const A: &str = "http://a.test";
/// The hub's fee on each payment.
const FEE: Fee = Fee { base: 1, ppm: 0 };
const TERMS: DonationTerms = DonationTerms {
    fee: Fee { base: 2, ppm: 0 },
    min: 10,
    max: 2_000,
    max_open: 3,
};
/// What the provider holds at A to start with.
const HELD: u64 = 1_000;
/// Where payers reach the provider.
const URL: &str = "https://swaps.test";

struct Eco {
    net: Arc<Net>,
    dir: tempfile::TempDir,
    node: Arc<Fake>,
    provider: Option<Provider<Link>>,
    payee: Wallet<Link>,
    /// The payee's code, as text.
    code: String,
}

impl Eco {
    /// Hub A, keeping payments to codes for their payees, a provider
    /// holding 1,000 there taking donations through its node, and a payee
    /// at A, offline but for collecting.
    async fn new() -> Self {
        let net = Net::new();
        net.start(A, FEE);
        net.conduct(A, Conduct::Keeps);
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
        let node = Arc::new(Fake::new());
        let provider = Provider::create(wallet, Config::default())
            .unwrap()
            .take_donations(node.clone(), TERMS, URL)
            .unwrap();
        let payee = Wallet::create(
            &dir.path().join("payee.sqlite"),
            &[0xd0; 32],
            ChainProfile::Core30DefaultRegtest,
            Link(net.clone()),
        )
        .unwrap();
        payee.add_hub(A).await.unwrap();
        let code = payee
            .payment_code(&[A.into()])
            .unwrap()
            .licash
            .unwrap()
            .to_string();
        let eco = Self {
            net,
            dir,
            node,
            provider: Some(provider),
            payee,
            code,
        };
        eco.mine(0);
        eco
    }

    fn provider(&self) -> &Provider<Link> {
        self.provider.as_ref().unwrap()
    }

    /// The provider, stopped and opened again over the same node.
    fn restart(&mut self) {
        self.restart_with(TERMS);
    }

    /// [`Self::restart`], taking donations on `terms`.
    fn restart_with(&mut self, terms: DonationTerms) {
        drop(self.provider.take());
        let wallet = Wallet::open(
            &self.dir.path().join("wallet.sqlite"),
            Link(self.net.clone()),
        )
        .unwrap();
        let provider = Provider::open(wallet, Config::default())
            .unwrap()
            .take_donations(self.node.clone(), terms, URL)
            .unwrap();
        self.provider = Some(provider);
    }

    fn height(&self) -> u32 {
        self.net.view(A).height()
    }

    /// `blocks` mined, the node following the hub's chain.
    fn mine(&self, blocks: u32) {
        if blocks > 0 {
            self.net.mine(A, blocks, None);
        }
        self.node.tip(self.height(), [0; 32]);
    }

    /// A donation of `sat`: its invoice and hash.
    async fn donate(&self, sat: u64) -> (Bolt11Invoice, [u8; 32]) {
        let request = self
            .provider()
            .donate(&self.code, sat * 1000, None)
            .await
            .unwrap();
        let invoice: Bolt11Invoice = request.parse().unwrap();
        let hash = invoice.payment_hash().to_byte_array();
        (invoice, hash)
    }

    /// The donation's invoice paid, its HTLCs expiring `blocks` from now.
    fn pay(&self, hash: [u8; 32], blocks: u32) {
        self.node.pay_held(hash, self.height() + blocks);
    }

    async fn follow(&self) {
        let pending = self.provider().follow_donations().await.unwrap();
        assert!(pending.is_empty(), "{pending:?}");
    }

    fn state(&self, hash: &[u8; 32]) -> DonationState {
        self.provider().donation(hash).unwrap().unwrap().state
    }

    fn held(&self) -> u64 {
        let balance = self.provider().wallet().balance().unwrap();
        balance
            .iter()
            .find(|b| b.hub == A)
            .map_or(0, |b| b.available)
    }

    /// What the payee collects at its hub now.
    async fn collected(&self) -> u64 {
        let inboxed = self.payee.collect_inbox().await.unwrap();
        inboxed.received.iter().map(|r| r.amount).sum()
    }

    fn alerts(&self) -> Vec<String> {
        let events = self.provider().events(0, 100).unwrap();
        events
            .iter()
            .filter_map(|e| match e.notice() {
                Some(Notice::Alert { message }) => Some(message),
                _ => None,
            })
            .collect()
    }

    /// Make the donation `hash` as old as `secs`.
    fn age(&self, hash: &[u8; 32], secs: i64) {
        let db = rusqlite::Connection::open(self.dir.path().join("wallet.sqlite")).unwrap();
        db.execute(
            "UPDATE provider_donations SET created_at = created_at - ?2 WHERE hash = ?1",
            rusqlite::params![hash, secs],
        )
        .unwrap();
    }
}

#[tokio::test]
async fn a_donation_paid_is_settled_once_its_payee_is_paid() {
    let eco = Eco::new().await;
    // Its info tells wallets where payers reach it, and its terms.
    let donations = eco.provider().info().unwrap().donations.unwrap();
    assert_eq!(
        (
            donations.url.as_str(),
            donations.fee,
            donations.min,
            donations.max
        ),
        (URL, TERMS.fee, 10, 2_000)
    );
    assert_eq!(
        eco.provider().donation_range(&eco.code).unwrap(),
        (10, 1_000)
    );
    let (invoice, hash) = eco.donate(100).await;
    // An invoice of the node, committing to the metadata LNURL-pay serves.
    assert_eq!(invoice.amount_milli_satoshis(), Some(100_000));
    let metadata = sha256::Hash::hash(METADATA.as_bytes());
    assert_eq!(
        invoice.description(),
        Bolt11InvoiceDescriptionRef::Hash(&lightning_invoice::Sha256(metadata))
    );
    assert_eq!(eco.node.held_cltv(hash), Some(INVOICE_CLTV.into()));
    // Its hash is reserved, as a swap's is.
    let swaps = eco.dir.path().join("wallet.sqlite");
    assert!(licash_swaps::holds_hash(&swaps, &hash).unwrap());
    // Nothing is paid until its invoice is.
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Open);
    assert_eq!(eco.provider().open_donations().unwrap(), 1);
    assert_eq!(eco.held(), HELD);
    eco.pay(hash, 40);
    eco.follow().await;
    assert_eq!(eco.node.held(hash), Some((HeldState::Settled, 100_000)));
    let donation = eco.provider().donation(&hash).unwrap().unwrap();
    assert_eq!(
        (donation.state, donation.amount),
        (DonationState::Settled, 98)
    );
    assert_eq!(eco.provider().open_donations().unwrap(), 0);
    // The payee collects it, the hub's fee paid of the provider's.
    assert_eq!(eco.held(), HELD - 98 - 1);
    assert_eq!(eco.collected().await, 98);
    // Followed again, never paid again.
    eco.follow().await;
    assert_eq!(eco.provider().wallet().sends().unwrap().len(), 1);
    assert_eq!(eco.held(), HELD - 98 - 1);
}

#[tokio::test]
async fn donations_are_asked_within_the_terms_and_what_the_provider_holds() {
    let eco = Eco::new().await;
    let provider = eco.provider();
    let refused = |r: Result<String, licash_api::Problem>| r.unwrap_err().code;
    assert_eq!(
        refused(provider.donate(&eco.code, 100_500, None).await),
        Code::Invalid
    );
    assert_eq!(
        refused(provider.donate(&eco.code, 9_000, None).await),
        Code::Invalid
    );
    // More than the provider holds at the code's hub.
    assert_eq!(
        refused(provider.donate(&eco.code, 1_001_000, None).await),
        Code::Invalid
    );
    assert_eq!(
        refused(provider.donate("licash1nonsense", 100_000, None).await),
        Code::Invalid
    );
    let mut foreign: licash_wallet::LicashCode = eco.code.parse().unwrap();
    foreign.network = ChainProfile::Core30Signet;
    assert_eq!(
        refused(provider.donate(&foreign.to_string(), 100_000, None).await),
        Code::Invalid
    );
    assert!(provider.donation_range(&foreign.to_string()).is_err());
    // A donation whose fee does not cover the hub's is never made.
    let mut cheap = Eco::new().await;
    drop(cheap.provider.take());
    let wallet = Wallet::open(
        &cheap.dir.path().join("wallet.sqlite"),
        Link(cheap.net.clone()),
    )
    .unwrap();
    let free = DonationTerms {
        fee: Fee { base: 0, ppm: 0 },
        ..TERMS
    };
    let provider = Provider::open(wallet, Config::default())
        .unwrap()
        .take_donations(cheap.node.clone(), free, URL)
        .unwrap();
    let refused = provider
        .donate(&cheap.code, 100_000, None)
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::Declined, "{refused:?}");
    cheap.provider = Some(provider);
    assert!(cheap
        .provider()
        .follow_donations()
        .await
        .unwrap()
        .is_empty());
    // A provider taking no donations declines them.
    let wallet = Wallet::create(
        &eco.dir.path().join("none.sqlite"),
        &[0x51; 32],
        ChainProfile::Core30DefaultRegtest,
        Link(eco.net.clone()),
    )
    .unwrap();
    let none = Provider::create(wallet, Config::default()).unwrap();
    assert_eq!(
        none.donate(&eco.code, 100_000, None)
            .await
            .unwrap_err()
            .code,
        Code::Declined
    );
    assert!(none.donation_terms().is_none());
    assert!(none.info().unwrap().donations.is_none());
    // Nor at a URL payers cannot reach over HTTP.
    let refused = none.take_donations(eco.node.clone(), TERMS, "swaps.test");
    assert!(refused.is_err());
}

#[tokio::test]
async fn a_donation_unpaid_or_never_made_an_invoice_of_is_canceled() {
    let eco = Eco::new().await;
    let (_, unpaid) = eco.donate(100).await;
    eco.follow().await;
    assert_eq!(eco.state(&unpaid), DonationState::Open);
    eco.age(&unpaid, 700);
    eco.follow().await;
    assert_eq!(eco.state(&unpaid), DonationState::Canceled);
    assert_eq!(eco.node.held(unpaid).unwrap().0, HeldState::Canceled);
    assert!(!eco.node.try_pay_held(unpaid, eco.height() + 40));
    // Recorded, then stopped before the node made its invoice: the payer
    // never had one.
    let unmade = [0x77; 32];
    let db = rusqlite::Connection::open(eco.dir.path().join("wallet.sqlite")).unwrap();
    db.execute(
        "INSERT INTO provider_donations (hash, preimage, code, sat, amount, state, created_at, updated_at)
         VALUES (?1, ?2, ?3, 100, 98, 'open', unixepoch(), unixepoch())",
        rusqlite::params![unmade, [0x78u8; 32], eco.code],
    )
    .unwrap();
    eco.follow().await;
    assert_eq!(eco.state(&unmade), DonationState::Open);
    eco.age(&unmade, 61);
    eco.follow().await;
    assert_eq!(eco.state(&unmade), DonationState::Canceled);
    // The node down when asked for an invoice: none made, none open.
    eco.node.down(true);
    assert_eq!(
        eco.provider()
            .donate(&eco.code, 100_000, None)
            .await
            .unwrap_err()
            .code,
        Code::Unavailable
    );
    eco.node.down(false);
    assert_eq!(eco.held(), HELD);
    assert!(eco.provider().wallet().sends().unwrap().is_empty());
}

#[tokio::test]
async fn a_donation_paid_too_close_to_its_expiry_is_canceled_unpaid() {
    let eco = Eco::new().await;
    let (_, hash) = eco.donate(100).await;
    // Less than the margin and the room to pay before the HTLCs expire.
    eco.pay(hash, SETTLE_MARGIN + 5);
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
    assert!(eco
        .provider()
        .wallet()
        .sent_by_key(&hash)
        .unwrap()
        .is_none());
    assert_eq!(eco.held(), HELD);
}

#[tokio::test]
async fn a_payment_never_offered_by_the_deadline_is_given_up_and_the_donation_canceled() {
    let eco = Eco::new().await;
    let (_, hash) = eco.donate(100).await;
    eco.pay(hash, 40);
    eco.net.fail(licash_api::OFFER, Fault::Lost);
    eco.follow().await;
    let sent = eco.provider().wallet().sent_by_key(&hash).unwrap().unwrap();
    assert_eq!(sent.state, State::Offered);
    assert_eq!(eco.state(&hash), DonationState::Open);
    // Before its deadline, it waits.
    eco.mine(40 - SETTLE_MARGIN - 1);
    eco.follow().await;
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    eco.mine(1);
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
    let sent = eco.provider().wallet().sent_by_key(&hash).unwrap().unwrap();
    assert!(matches!(sent.state, State::Abandoned(_)), "{sent:?}");
    // Its notes freed, and never paid again under it.
    assert_eq!(eco.held(), HELD);
    eco.provider().step().await.unwrap();
    eco.follow().await;
    assert_eq!(eco.provider().wallet().sends().unwrap().len(), 1);
    assert_eq!(eco.collected().await, 0);
}

/// A late payment the wallet fails to give up, unsigned all the same: its
/// payer's payment is neither taken nor given back until it is.
#[tokio::test]
async fn a_late_payment_not_given_up_leaves_the_donation_open() {
    let eco = Eco::new().await;
    let (_, hash) = eco.donate(100).await;
    eco.pay(hash, 40);
    eco.net.fail(licash_api::OFFER, Fault::Lost);
    eco.follow().await;
    let db = rusqlite::Connection::open(eco.dir.path().join("wallet.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TRIGGER failing BEFORE UPDATE OF abandoned ON sends
         BEGIN SELECT RAISE(ABORT, 'disk on fire'); END;",
    )
    .unwrap();
    eco.mine(40 - SETTLE_MARGIN);
    eco.follow().await;
    let sent = eco.provider().wallet().sent_by_key(&hash).unwrap().unwrap();
    assert_eq!(sent.state, State::Offered);
    assert_eq!(eco.state(&hash), DonationState::Open);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    // Given up once it can be: canceled, nothing taken.
    db.execute_batch("DROP TRIGGER failing").unwrap();
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Canceled);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Canceled);
    assert_eq!(eco.collected().await, 0);
}

#[tokio::test]
async fn a_payment_signed_by_the_deadline_is_settled_and_followed_until_released() {
    let mut eco = Eco::new().await;
    let (_, hash) = eco.donate(100).await;
    eco.pay(hash, 40);
    eco.net.fail(licash_api::RELEASE, Fault::Lost);
    eco.follow().await;
    let sent = eco.provider().wallet().sent_by_key(&hash).unwrap().unwrap();
    assert_eq!(sent.state, State::Signed);
    // Stopped, then started again: still followed, never paid again.
    eco.restart();
    eco.follow().await;
    assert_eq!(eco.provider().wallet().sends().unwrap().len(), 1);
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Accepted);
    // At its deadline, settled though its payment is not released yet.
    eco.mine(40 - SETTLE_MARGIN);
    eco.follow().await;
    assert_eq!(eco.node.held(hash).unwrap().0, HeldState::Settled);
    assert_eq!(eco.state(&hash), DonationState::Owed);
    assert_eq!(eco.provider().open_donations().unwrap(), 1);
    // The provider's step releases it: done.
    eco.provider().step().await.unwrap();
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Settled);
    assert_eq!(eco.provider().wallet().sends().unwrap().len(), 1);
    assert_eq!(eco.collected().await, 98);
    assert!(eco.alerts().is_empty());
}

#[tokio::test]
async fn a_donation_whose_invoice_is_canceled_after_paying_on_is_lost_and_alerted() {
    let eco = Eco::new().await;
    let (_, hash) = eco.donate(100).await;
    eco.pay(hash, 40);
    eco.net.fail(licash_api::RELEASE, Fault::Lost);
    eco.follow().await;
    // The node gives the HTLCs up on its own.
    eco.node.cancel(hash).await.unwrap();
    eco.follow().await;
    assert_eq!(eco.state(&hash), DonationState::Lost);
    let alerts = eco.alerts();
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert!(alerts[0].contains(&hex::encode(hash)), "{alerts:?}");
    eco.follow().await;
    assert_eq!(eco.alerts().len(), 1);
}

#[tokio::test]
async fn open_donations_are_capped() {
    let eco = Eco::new().await;
    let mut hashes = Vec::new();
    for _ in 0..TERMS.max_open {
        hashes.push(eco.donate(20).await.1);
    }
    let refused = eco
        .provider()
        .donate(&eco.code, 20_000, None)
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::Unavailable, "{refused:?}");
    // One ended, another may be made.
    eco.age(&hashes[0], 700);
    eco.follow().await;
    eco.donate(20).await;
}

/// From one source only so many donations are asked and not paid, the
/// rest of those open left to others: from another source, or none known,
/// more, and once one is no longer open, its place is free.
#[tokio::test]
async fn donations_asked_and_not_paid_from_one_source_are_bounded() {
    let mut eco = Eco::new().await;
    eco.restart_with(DonationTerms {
        max_open: 100,
        ..TERMS
    });
    let (one, other) = (b"ip 192.0.2.1".as_slice(), b"ip 192.0.2.2".as_slice());
    let ask = |source: Option<&'static [u8]>| eco.provider().donate(&eco.code, 20_000, source);
    let mut asked = Vec::new();
    for _ in 0..licash_swaps::PER_SOURCE {
        asked.push(ask(Some(one)).await.unwrap());
    }
    let refused = ask(Some(one)).await.unwrap_err();
    assert_eq!(refused.code, Code::Unavailable, "{refused:?}");
    assert!(refused.message.contains("source"), "{refused:?}");
    ask(Some(other)).await.unwrap();
    ask(None).await.unwrap();
    // One expired and canceled: its place is free.
    let invoice: Bolt11Invoice = asked[0].parse().unwrap();
    eco.age(&invoice.payment_hash().to_byte_array(), 700);
    eco.follow().await;
    ask(Some(one)).await.unwrap();
    assert_eq!(ask(Some(one)).await.unwrap_err().code, Code::Unavailable);
}

/// The test net, and a provider at [`PROVIDER`] answering its info as
/// `.1`.
#[derive(Clone)]
struct Via(Arc<Net>, licash_api::swaps::Info);

const PROVIDER: &str = "http://swaps.test";

impl Transport for Via {
    fn request(
        &self,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<Response, String>> + Send {
        let info = format!("{PROVIDER}{}", licash_api::swaps::SWAPS_INFO);
        let answer = match url == info {
            true => Ok(Response {
                status: 200,
                body: serde_json::to_vec(&self.1).unwrap(),
            }),
            false => self.0.serve(url, body),
        };
        std::future::ready(answer)
    }
}

/// The donation address of `wallet`'s code at [`PROVIDER`].
async fn donation(
    wallet: Wallet<Via>,
) -> Result<licash_wallet::DonationAddress, licash_wallet::Error> {
    let hubs: Vec<String> = wallet.hubs()?.into_iter().map(|(url, _)| url).collect();
    let code = wallet.donation_code(None, &hubs)?;
    wallet.donation_address(PROVIDER, &code).await
}

#[tokio::test]
async fn a_wallet_finds_its_static_donation_address_at_a_provider_taking_them() {
    let eco = Eco::new().await;
    let info = eco.provider().info().unwrap();
    let payee = |info: licash_api::swaps::Info| {
        let path = eco.dir.path().join("payee.sqlite");
        Wallet::open(&path, Via(eco.net.clone(), info)).unwrap()
    };
    let address = donation(payee(info.clone())).await.unwrap();
    // Its own code, at the provider's public URL, in an LNURL.
    let (_, url) = bitcoin::bech32::decode(&address.lnurl).unwrap();
    let url = String::from_utf8(url).unwrap();
    assert_eq!(url, format!("{URL}/v1/lnurlp/{}", eco.code));
    assert_eq!(address.lnurl, address.lnurl.to_uppercase());
    assert_eq!(
        (address.donations.fee, address.donations.min),
        (TERMS.fee, 10)
    );
    // It holds 1,000 at the code's hub.
    assert!(info.hubs[0].max >= TERMS.min, "{info:?}");
    assert!(address.stocked);
    // The provider's very URL serves it.
    assert_eq!(
        eco.provider().donation_range(&eco.code).unwrap(),
        (10, 1_000)
    );

    // Holding too little at the code's hubs: payers refused for now.
    let mut empty = info.clone();
    empty.hubs[0].max = 0;
    let address = donation(payee(empty)).await.unwrap();
    assert!(!address.stocked);
    // Swapping at none of the payee's hubs, or taking no donations: none.
    let mut elsewhere = info.clone();
    elsewhere.hubs.clear();
    let refused = donation(payee(elsewhere)).await;
    assert!(
        matches!(refused, Err(licash_wallet::Error::Invalid(_))),
        "{refused:?}"
    );
    let none = licash_api::swaps::Info {
        donations: None,
        receive: None,
        ..info
    };
    let refused = donation(payee(none)).await;
    assert!(
        matches!(refused, Err(licash_wallet::Error::Invalid(_))),
        "{refused:?}"
    );
}
