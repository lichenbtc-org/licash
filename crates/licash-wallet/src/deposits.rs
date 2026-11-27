//! Deposits: coins paid on Bitcoin for a hub's notes ([`licash_api::Deposit`]).
//!
//! The wallet draws a preimage and a refund key, records them with the
//! deposit it asks for, then asks the hub for its terms, and checks that
//! the address answered is that of a taproot output ([`Htlc`]) the hub
//! claims with the preimage, and the wallet takes back with its refund key
//! after the timeout. Once a payment of exactly the amount answered
//! confirms at depth, the hub locks notes of its own to the wallet, which
//! claims them with the preimage, as when paid over Lightning: the hub
//! learns the preimage that claims the coins. A deposit whose notes are
//! never claimed returns to its payer after its timeout
//! ([`Wallet::refund_deposit`]).
//!
//! A deposit's refund key derives from the seed, its hub's address and its
//! number there, the next of each hub's, and its preimage from those and
//! what is asked: the outputs' ephemeral key, drawn at random each time,
//! the notes and the payment. A wallet of the same seed that lost its file
//! so finds the deposits it asked for there by their refund keys, the hub
//! answering what was asked and its terms, and takes on those whose hash is
//! the one its seed gives for just that, until [`GAP`] numbers in a row are
//! unknown there ([`Wallet::find_deposits`]): a hub answering other notes
//! or another payment than were asked answers another hash. A number asked
//! again, its hub having hidden the first from such a wallet, is under
//! another hash, whose preimage claims nothing of the first.
//!
//! A deposit that returns a contract's reserve is paid by her contract's
//! close, perhaps with her hub gone, so its hash and address are of the
//! seed, the hub and the coin that opens the contract alone, with a small
//! attempt number for a coin opening again ([`Close`]), found on Bitcoin
//! without the hub among the wallet's coins
//! (`Wallet::find_close_payments`); its outputs' ephemeral key is of those
//! and the notes asked, which a hub so cannot answer fewer of. A coin opens
//! at most one contract that confirms, as each is spent whole in its
//! funding: two contracts' closes never pay one deposit, whatever a hub
//! hides from a wallet restored from its seed.
//!
//! A deposit may be asked of a swap provider instead, which pays it on
//! with a lock of its own notes at the hub (`deposits_via`): recorded
//! alike, its secrets drawn at random.

use bitcoin::{
    hashes::Hash,
    secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey},
    Amount, FeeRate, OutPoint, ScriptBuf, Transaction, Txid,
};
use licash::{
    address::Ephemeral,
    claim::Branch,
    crypto::{scalar_from_hash, tagged_hash, Point},
    spend::{lock_hash, ProposalId},
};
use licash_api::{CloseTerms, Code, DepositStatus, Depositing, Hex, Info, Receive, ReceiveState};
use licash_onchain::deposit::{close_claim_key, Htlc, CLOSE_WAIT};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, OptionalExtension, Row};

use crate::{each_at_most, hub_url, invalid, now, sql, unavailable, Error, Transport, Wallet};

/// Blocks a hub's tip may move between its info and its answer: the
/// timeout it answers may be that much later than its info promises.
pub(crate) const TIP_MARGIN: u32 = 6;

/// Numbers in a row a hub knows no deposit under, after which a wallet
/// looking for its deposits there stops: asks that never reached it
/// leave gaps.
pub const GAP: u32 = 20;

/// The refund key of the deposit numbered `number` at the hub of `address`,
/// of the wallet whose deposit seed is `seed`: what its hub knows it by.
pub(crate) fn refund_secret(
    seed: &[u8; 32],
    address: &[u8],
    number: u32,
) -> Result<SecretKey, Error> {
    let key = tagged_hash(
        "licash/deposit/refund",
        &[seed, address, &number.to_be_bytes()],
    );
    SecretKey::from_slice(&key).map_err(invalid)
}

/// The preimage of the deposit numbered `number` at the hub of `address`
/// that asks notes worth `amount` to outputs under `ephemeral` for a
/// payment of `pays`: another for any other of them.
fn preimage(
    seed: &[u8; 32],
    address: &[u8],
    number: u32,
    ephemeral: &Point,
    amount: u64,
    pays: u64,
) -> [u8; 32] {
    tagged_hash(
        "licash/deposit/preimage",
        &[
            seed,
            address,
            &number.to_be_bytes(),
            &ephemeral.0,
            &amount.to_be_bytes(),
            &pays.to_be_bytes(),
        ],
    )
}

/// The attempts at a deposit that returns a contract's reserve that one
/// coin may make at a hub: the opening it is for asked again, or again by
/// a wallet restored from its seed. A wallet looking for them on Bitcoin
/// looks for this many of each of its coins.
pub const CLOSE_ATTEMPTS: u8 = 8;

/// What a deposit that returns a contract's reserve derives from, besides
/// the seed and its hub's address: the coin that opens the contract, and
/// which of that coin's attempts at the hub it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Close {
    pub coin: OutPoint,
    pub attempt: u8,
}

impl Close {
    fn parts(&self) -> [u8; 37] {
        let mut parts = [0; 37];
        parts[..32].copy_from_slice(&self.coin.txid.to_byte_array());
        parts[32..36].copy_from_slice(&self.coin.vout.to_be_bytes());
        parts[36] = self.attempt;
        parts
    }

    /// Its refund key at the hub of `address`, of the wallet whose deposit
    /// seed is `seed`: what its hub knows it by.
    pub(crate) fn refund_secret(
        &self,
        seed: &[u8; 32],
        address: &[u8],
    ) -> Result<SecretKey, Error> {
        let key = tagged_hash(
            "licash/deposit/close/refund",
            &[seed, address, &self.parts()],
        );
        SecretKey::from_slice(&key).map_err(invalid)
    }

    /// Its preimage at the hub of `address`: of nothing its hub answers.
    pub(crate) fn preimage(&self, seed: &[u8; 32], address: &[u8]) -> [u8; 32] {
        tagged_hash(
            "licash/deposit/close/preimage",
            &[seed, address, &self.parts()],
        )
    }

    /// The ephemeral key of its outputs, worth `amount`, at the hub of
    /// `address`.
    fn ephemeral(&self, seed: &[u8; 32], address: &[u8], amount: u64) -> Result<Ephemeral, Error> {
        let key = tagged_hash(
            "licash/deposit/close/ephemeral",
            &[seed, address, &self.parts(), &amount.to_be_bytes()],
        );
        Ephemeral::from_scalar(scalar_from_hash(&key)).map_err(invalid)
    }
}

/// What a deposit's secrets derive from, besides the seed and its hub's
/// address.
#[derive(Clone, Copy, Debug)]
enum Origin {
    /// An ordinary deposit, by its number at its hub.
    Number(u32),
    /// One that returns a contract's reserve.
    Close(Close),
}

impl Origin {
    fn refund_secret(&self, seed: &[u8; 32], address: &[u8]) -> Result<SecretKey, Error> {
        match self {
            Origin::Number(number) => refund_secret(seed, address, *number),
            Origin::Close(close) => close.refund_secret(seed, address),
        }
    }
}

/// A deposit asked for, and where it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    /// Its hash, in hex.
    pub hash: String,
    pub hub: String,
    /// The notes it locks to the wallet; the payment is worth the hub's
    /// fee on top.
    pub amount: u64,
    /// What to pay, once the hub answered.
    pub terms: Option<DepositTerms>,
    /// The payment, once its hub saw it confirm: `txid:vout` and height.
    pub funding: Option<(OutPoint, u32)>,
    /// The lock of the hub's notes to the wallet, once paid: the id of
    /// their receipt (in hex).
    pub lock: Option<String>,
    pub state: DepositState,
    pub created_at: i64,
    /// Whether it returns a contract's reserve, which its payer takes back
    /// [`CLOSE_WAIT`] blocks after its payment, not at a height.
    pub close: bool,
    /// The swap provider it was asked of, in place of its hub
    /// ([`Wallet::deposit_through`]).
    pub provider: Option<String>,
}

impl Deposit {
    /// The height after which its payer may take its coins back: its
    /// timeout, or for a deposit that returns a contract's reserve a wait
    /// after its payment confirmed, none until the hub saw it. None if
    /// its terms were never answered.
    pub fn refund_height(&self) -> Option<u32> {
        match (self.close, &self.funding, &self.terms) {
            (true, Some((_, height)), _) => Some(
                height
                    .saturating_add(u32::from(CLOSE_WAIT))
                    .saturating_sub(1),
            ),
            (true, None, _) => None,
            (false, _, Some(terms)) => Some(terms.timeout),
            (false, _, None) => None,
        }
    }
}

/// A deposit that a contract's default close pays her reserve to
/// ([`Wallet::close_deposit`]): its script, for her Base to commit to, and
/// the fee the hub keeps of the reserve if it swaps it for notes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseDeposit {
    /// Its hash, in hex.
    pub hash: String,
    pub script: ScriptBuf,
    pub fee: u64,
}

/// Pay exactly `pays` to `address`, confirmed by block `fund_by`: the
/// coins are the payer's again after block `timeout`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositTerms {
    pub address: String,
    pub pays: u64,
    pub fund_by: u32,
    pub timeout: u32,
}

/// Where a deposit stands.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DepositState {
    /// Waiting for its hub's terms, its payment, its depth or the claim.
    Open,
    /// Its notes kept.
    Received,
    /// Refused or canceled, its notes never claimed, and why: a payment
    /// made returns after the timeout ([`Wallet::refund_deposit`]).
    Canceled(String),
    /// Taken back by the refund of this id.
    Refunded(Txid),
}

/// The deposit that returns a contract's reserve, under the hash and refund
/// key her seed gives, of the hub whose deposit root is `root`: its claim key
/// derived from it, its refund [`CLOSE_WAIT`] blocks after its payment.
pub(crate) fn close_htlc(root: &XOnlyPublicKey, hash: &[u8; 32], refund: &XOnlyPublicKey) -> Htlc {
    Htlc {
        hash: *hash,
        claim: close_claim_key(root, hash, refund),
        refund: *refund,
        timeout: 0,
        wait: Some(CLOSE_WAIT),
        sized: false,
    }
}

/// Whether a deposit's stored request (`body`) is of one that returns a
/// contract's reserve: one a stored request that does not read is not.
fn closes(body: &str) -> bool {
    serde_json::from_str::<licash_api::Deposit>(body).is_ok_and(|asked| asked.close.is_some())
}

pub(crate) fn hash_id(hash: &str) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(hash, &mut bytes)
        .map_err(|_| Error::Invalid(format!("not a deposit's hash: {hash}")))?;
    Ok(bytes)
}

/// A secret key drawn at random.
pub(crate) fn random_key() -> SecretKey {
    loop {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

pub(crate) fn x_only(key: &SecretKey) -> XOnlyPublicKey {
    key.x_only_public_key(&Secp256k1::new()).0
}

impl<T: Transport> Wallet<T> {
    /// Ask the hub at `url` for a deposit locking notes worth `amount` to
    /// this wallet: where to pay on Bitcoin, and how much, its fee on top.
    /// [`Wallet::follow_deposit`] claims the notes once the payment
    /// confirmed.
    pub async fn deposit(&self, url: &str, amount: u64) -> Result<Deposit, Error> {
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let deposits = info
            .deposits
            .as_ref()
            .ok_or_else(|| Error::Invalid(format!("hub {url} takes no deposits")))?;
        if amount < deposits.min || amount > deposits.max {
            return Err(Error::Invalid(format!(
                "hub {url} takes deposits of {} to {}",
                deposits.min, deposits.max
            )));
        }
        let pays = deposits
            .pays(amount)
            .ok_or_else(|| Error::Invalid(format!("a deposit of {amount} overflows")))?;
        let number = self.deposit_number(hub, &url, &info).await?;
        let origin = Origin::Number(number);
        let asked = self.draw_deposit(&url, &info, (amount, pays), origin, None)?;
        self.store.write(|tx| asked.keep(tx, hub))?;
        tracing::info!(hash = %hex::encode(asked.hash), %url, amount, "asking for a deposit");
        self.advance_deposit(&asked.hash).await
    }

    /// Ask the hub at `url` for a deposit paid exactly `pays` on Bitcoin,
    /// its fee in it: the notes it locks are what the fee leaves. To pay at
    /// once, in a transaction made with its address (a contract's funding
    /// paying its change in, say): recorded only with the terms its hub
    /// answered, checked. Refused if no notes within the hub's limits come,
    /// with its fee, to `pays` exactly.
    pub async fn deposit_paying(&self, url: &str, pays: u64) -> Result<Deposit, Error> {
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let deposits = info
            .deposits
            .as_ref()
            .ok_or_else(|| Error::Invalid(format!("hub {url} takes no deposits")))?;
        let amount = deposits
            .paid_by(pays)
            .filter(|a| (deposits.min..=deposits.max).contains(a))
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "hub {url} takes no deposit paid {pays} sat exactly, its fee in it"
                ))
            })?;
        self.deposit_answered(hub, &info, (amount, pays), None)
            .await
    }

    /// Ask the hub at `url` for the deposit that a contract's default close
    /// pays her reserve to, `pays` sat, to time out at block `timeout`
    /// where the contract's Base puts it: the notes it locks the most that
    /// payment covers, the rest, `fee`, the hub's if it swaps. Recorded only
    /// with the terms its hub answered, checked. The wallet asks for its
    /// lock, and claims the notes, once the close is paid
    /// ([`Wallet::follow_deposit`]); else takes the coins back
    /// [`CLOSE_WAIT`] blocks after the close paid it
    /// ([`Wallet::deposits_to_refund`]). Its secrets are of the seed, the
    /// hub and `coin`, the wallet's coin that opens the contract, and its
    /// address of those and the hub's published root alone, as is the key
    /// that claims it, so a wallet restored from its seed finds it again
    /// among its coins ([`Wallet::find_close_payments`]); `until` is the
    /// block the hub gives up watching for the close's payment.
    pub async fn close_deposit(
        &self,
        url: &str,
        coin: OutPoint,
        pays: u64,
        until: u32,
    ) -> Result<CloseDeposit, Error> {
        let url = hub_url(url)?;
        self.not_visited(&url)?;
        let (hub, info) = self.refresh(&url).await?;
        let deposits = info
            .deposits
            .as_ref()
            .ok_or_else(|| Error::Invalid(format!("hub {url} takes no deposits")))?;
        let amount = deposits
            .most_for(pays)
            .filter(|a| (deposits.min..=deposits.max).contains(a))
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "hub {url} takes no deposit of the notes {pays} sat pays for"
                ))
            })?;
        let close = CloseTerms { pays, until };
        let deposit = self
            .deposit_answered(hub, &info, (amount, pays), Some((coin, close)))
            .await?;
        let network = licash_onchain::network(self.network());
        let script = deposit
            .terms
            .as_ref()
            .and_then(|t| {
                t.address
                    .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
                    .ok()
                    .and_then(|a| a.require_network(network).ok())
            })
            .map(|a| a.script_pubkey())
            .ok_or_else(|| Error::Invalid(format!("hub {url} named no address to pay")))?;
        Ok(CloseDeposit {
            hash: deposit.hash,
            script,
            fee: pays - amount,
        })
    }

    /// Give up the deposit of `hash`, answered but never to be paid: the
    /// transaction to pay it given up unmade, `why`. Refused once its hub
    /// saw a payment to it, or the deposit is over. One made all the same
    /// returns after its timeout ([`Wallet::deposits_to_refund`]).
    pub fn give_up_deposit(&self, hash: &str, why: &str) -> Result<(), Error> {
        let key = hash_id(hash)?;
        let given_up = self.store.write(|tx| {
            Ok(tx.execute(
                "UPDATE deposits SET canceled = ?2
                 WHERE hash = ?1 AND lock IS NULL
                    AND NOT EXISTS (SELECT 1 FROM deposit_fundings f WHERE f.hash = deposits.hash)
                    AND done_at IS NULL AND canceled IS NULL AND refund IS NULL",
                params![key, why],
            )?)
        })?;
        if given_up == 0 {
            self.deposit_record(&key)?;
            return Err(Error::Invalid(format!(
                "deposit {hash} is paid or over: not given up"
            )));
        }
        tracing::info!(%hash, why, "deposit given up unpaid");
        Ok(())
    }

    /// Ask the hub `hub`, which says `info` of itself, for a deposit of
    /// notes worth `amount` for a payment of `pays`, to pay at once:
    /// recorded only with the terms it answered, checked, as none pays a
    /// deposit its hub never answered. One that returns a contract's
    /// reserve, `close`, of the coin that opens the contract.
    pub(crate) async fn deposit_answered(
        &self,
        hub: i64,
        info: &Info,
        (amount, pays): (u64, u64),
        close: Option<(OutPoint, CloseTerms)>,
    ) -> Result<Deposit, Error> {
        let url = self.reached(hub)?;
        let (origin, close) = match close {
            None => (
                Origin::Number(self.deposit_number(hub, &url, info).await?),
                None,
            ),
            Some((coin, terms)) => {
                let close = self.close_attempt(&url, info, coin).await?;
                (Origin::Close(close), Some(terms))
            }
        };
        let asked = self.draw_deposit(&url, info, (amount, pays), origin, close)?;
        let hash = asked.hash;
        tracing::info!(hash = %hex::encode(hash), %url, amount, "asking for a deposit");
        let terms: Depositing = self.post(&url, licash_api::DEPOSIT, &asked.body).await?;
        let htlc = self
            .check_terms(
                &url,
                &hash,
                &asked.refund_key,
                (amount, pays),
                close,
                &terms,
            )
            .await?;
        let network = licash_onchain::network(self.network());
        self.store.write(|tx| {
            asked.keep(tx, hub)?;
            keep_terms(tx, &hash, &htlc, &terms, network)
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, address = %terms.address, pays = terms.amount, "deposit terms");
        self.deposit_record(&hash)
    }

    /// Give up the deposit of `hash` its hub never answered: no address
    /// was named to pay, so nothing paid it. Refused once answered.
    pub fn abandon_deposit(&self, hash: &str) -> Result<(), Error> {
        let key = hash_id(hash)?;
        let given_up = self.store.write(|tx| {
            Ok(tx.execute(
                "UPDATE deposits SET canceled = 'abandoned before its hub answered'
                 WHERE hash = ?1 AND done_at IS NULL AND canceled IS NULL
                    AND NOT EXISTS (SELECT 1 FROM deposit_terms t WHERE t.hash = deposits.hash)",
                [key],
            )?)
        })?;
        if given_up == 0 {
            self.deposit_record(&key)?;
            return Err(Error::Invalid(format!(
                "deposit {hash} is answered or over: an address to pay was named"
            )));
        }
        tracing::info!(%hash, "deposit abandoned before its hub answered");
        Ok(())
    }

    /// A deposit of notes worth `amount`, for a payment of `pays`, to ask
    /// the hub at `url`, which says `info` of itself, for, derived of
    /// `origin`: one that returns a contract's reserve, as `close` says,
    /// of a coin.
    fn draw_deposit(
        &self,
        url: &str,
        info: &Info,
        (amount, pays): (u64, u64),
        origin: Origin,
        close: Option<CloseTerms>,
    ) -> Result<Asked, Error> {
        let keysets = info.keysets().map_err(|p| unavailable(url, p))?;
        let address = info.address.to_bytes();
        let seed = &self.keys.deposit;
        let refund_key = origin.refund_secret(seed, &address)?;
        let (preimage, ephemeral) = match (origin, &close) {
            // Drawn anew each time: a number asked twice is two hashes.
            (Origin::Number(number), None) => {
                let ephemeral = Ephemeral::random();
                let public = ephemeral.public();
                let preimage = preimage(seed, &address, number, &public, amount, pays);
                (preimage, ephemeral)
            }
            (Origin::Close(c), Some(_)) => (
                c.preimage(seed, &address),
                c.ephemeral(seed, &address, amount)?,
            ),
            _ => return Err(invalid("a contract's close is of a coin, no other deposit")),
        };
        let me = self.address();
        let (keyset, outputs) = keysets
            .iter()
            .find_map(|k| {
                let outputs = crate::outputs(k, &ephemeral, Branch::Pay, &[(&me, amount)]);
                Some((k, outputs.ok()?))
            })
            .ok_or_else(|| Error::Invalid(format!("hub {url} has no keyset making {amount}")))?;
        let hash = lock_hash(&preimage);
        let body = licash_api::Deposit {
            receive: Receive::new(keyset.id(), &ephemeral.public(), &outputs, &hash),
            refund: Hex(x_only(&refund_key).serialize().to_vec()),
            close,
        };
        Ok(Asked {
            hash,
            preimage,
            refund_key,
            amount,
            pays,
            body,
        })
    }
}

impl<T: Transport> Wallet<T> {
    /// The next number of a deposit at the hub `hub`, reached at `url`,
    /// saying `info` of itself, taken whether or not the deposit is then
    /// asked: once the deposits of the wallet's seed were looked for there.
    async fn deposit_number(&self, hub: i64, url: &str, info: &Info) -> Result<u32, Error> {
        if self.deposit_next(hub)?.is_none() {
            self.find_deposits_at(hub, url, info).await?;
        }
        self.store.write(|tx| {
            let taken: Option<i64> = tx
                .query_row(
                    "UPDATE hubs SET deposit_next = deposit_next + 1
                     WHERE id = ?1 AND deposit_next IS NOT NULL RETURNING deposit_next - 1",
                    [hub],
                    |r| r.get(0),
                )
                .optional()?;
            taken
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Error::Invalid(format!("hub {url}: no deposit number left")))
        })
    }

    /// The next number of a deposit at the hub `hub`: none until its
    /// deposits were looked for there.
    pub(crate) fn deposit_next(&self, hub: i64) -> Result<Option<u32>, Error> {
        self.store.read(|c| {
            Ok(
                c.query_row("SELECT deposit_next FROM hubs WHERE id = ?1", [hub], |r| {
                    r.get(0)
                })?,
            )
        })
    }

    /// The first attempt at a deposit that returns a contract's reserve
    /// that `coin` has not made at the hub at `url`, which says `info` of
    /// itself, as far as the wallet and the hub know: a hub hiding one
    /// only has the same coin's contract asked again under it, which the
    /// coin, spent whole, funds at most once.
    async fn close_attempt(&self, url: &str, info: &Info, coin: OutPoint) -> Result<Close, Error> {
        let address = info.address.to_bytes();
        for attempt in 0..CLOSE_ATTEMPTS {
            let close = Close { coin, attempt };
            let refund = close.refund_secret(&self.keys.deposit, &address)?;
            if self.deposit_kept(&refund)? {
                continue;
            }
            let key = x_only(&refund).serialize();
            match self
                .get::<DepositStatus>(url, &licash_api::deposit_state(&key))
                .await
            {
                Err(Error::Refused { problem, .. }) if problem.code == Code::UnknownLock => {
                    return Ok(close)
                }
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::Invalid(format!(
            "coin {coin} asked hub {url} for a contract's close {CLOSE_ATTEMPTS} times: \
             open with another coin"
        )))
    }

    /// Whether the wallet keeps a deposit under the refund key `refund`.
    fn deposit_kept(&self, refund: &SecretKey) -> Result<bool, Error> {
        self.store.read(|c| {
            let kept = c.query_row(
                "SELECT 1 FROM deposits WHERE refund_key = ?1 LIMIT 1",
                [refund.secret_bytes()],
                |_| Ok(()),
            );
            Ok(kept.optional()?.is_some())
        })
    }

    /// Look for the deposits the wallet's seed asked of the hub at `url`,
    /// by number from the first, until `GAP` in a row are unknown there:
    /// those it kept no record of, as a wallet restored from its seed,
    /// kept as the hub answers them, checked to be what the wallet's seed
    /// asked, then taken on as any other ([`Wallet::follow_deposit`],
    /// refunded if paid and never received). Those found; the next number
    /// after them from then on. Then those that return a contract's
    /// reserve, of each coin the wallet spent, by attempt until one is
    /// unknown there.
    pub async fn find_deposits(&self, url: &str) -> Result<Vec<Deposit>, Error> {
        let url = hub_url(url)?;
        let (hub, info) = self.refresh(&url).await?;
        self.find_deposits_at(hub, &url, &info).await
    }

    pub(crate) async fn find_deposits_at(
        &self,
        hub: i64,
        url: &str,
        info: &Info,
    ) -> Result<Vec<Deposit>, Error> {
        let address = info.address.to_bytes();
        let root = (info.deposits.as_ref())
            .and_then(|d| d.close_root)
            .and_then(|r| XOnlyPublicKey::from_slice(&r.0).ok());
        let (mut number, mut unknown, mut next) = (0u32, 0u32, 0u32);
        let mut found = Vec::new();
        // A number counts as known only by a deposit that is the wallet's:
        // a hub answering anything else to each is asked `GAP` times, not
        // without end. The numbers sure to be asked next, as many as are
        // left unknown before giving up, are asked at once, one round trip
        // rather than one each over Tor: the same numbers as one at a time.
        while unknown < GAP {
            let last = number
                .checked_add(GAP - unknown)
                .ok_or_else(|| Error::Invalid(format!("hub {url}: no deposit number left")))?;
            let address = &address;
            let mut window = each_at_most(usize::MAX, number..last, |n| async move {
                let origin = Origin::Number(n);
                Ok::<_, Error>((n, self.find_deposit(hub, url, address, origin, root).await?))
            })
            .await?;
            window.sort_unstable_by_key(|(n, _)| *n);
            for (n, one) in window {
                let known = match one {
                    Found::Kept => true,
                    Found::New(deposit) => {
                        found.push(*deposit);
                        true
                    }
                    Found::Unknown | Found::NotMine => false,
                };
                match known {
                    true => (unknown, next) = (0, n.saturating_add(1)),
                    false => unknown += 1,
                }
            }
            number = last;
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE hubs SET deposit_next = MAX(COALESCE(deposit_next, 0), ?2) WHERE id = ?1",
                params![hub, next],
            )?;
            Ok(())
        })?;
        if root.is_some() {
            for coin in self.silent_outpoints(true)? {
                for attempt in 0..CLOSE_ATTEMPTS {
                    let origin = Origin::Close(Close { coin, attempt });
                    match self.find_deposit(hub, url, &address, origin, root).await? {
                        Found::New(deposit) => found.push(*deposit),
                        Found::Kept | Found::NotMine => {}
                        Found::Unknown => break,
                    }
                }
            }
        }
        tracing::info!(%url, found = found.len(), next, "deposits looked for");
        Ok(found)
    }

    /// The deposit of `origin` the wallet's seed may have asked the hub
    /// `hub` at `url`, of `address`, for, whose deposit root is `root`:
    /// kept already, or as the hub answers it if this wallet's.
    async fn find_deposit(
        &self,
        hub: i64,
        url: &str,
        address: &[u8],
        origin: Origin,
        root: Option<XOnlyPublicKey>,
    ) -> Result<Found, Error> {
        let refund = origin.refund_secret(&self.keys.deposit, address)?;
        if self.deposit_kept(&refund)? {
            return Ok(Found::Kept);
        }
        let key = x_only(&refund).serialize();
        let status = match self.get(url, &licash_api::deposit_state(&key)).await {
            Ok(status) => status,
            Err(Error::Refused { problem, .. }) if problem.code == Code::UnknownLock => {
                return Ok(Found::Unknown)
            }
            Err(e) => return Err(e),
        };
        let drawn = Drawn {
            address,
            origin,
            refund,
        };
        match self.found_deposit(hub, url, drawn, status, root) {
            Ok(hash) => Ok(Found::New(Box::new(self.deposit_record(&hash)?))),
            Err(Error::Invalid(reason)) => {
                tracing::warn!(?origin, %url, %reason, "a deposit found not this wallet's");
                Ok(Found::NotMine)
            }
            Err(e) => Err(e),
        }
    }

    /// Keep the deposit of this wallet's seed `drawn` as the hub `hub` at
    /// `url` says it stands, `status`: what was asked and the terms
    /// answered kept only under the hash the seed gives for them, which a
    /// hub answering other notes, another payment or another kind of
    /// deposit than was asked does not answer. Its hash; refused as
    /// invalid otherwise.
    fn found_deposit(
        &self,
        hub: i64,
        url: &str,
        drawn: Drawn<'_>,
        status: DepositStatus,
        root: Option<XOnlyPublicKey>,
    ) -> Result<[u8; 32], Error> {
        let Drawn {
            address,
            origin,
            refund: refund_key,
        } = drawn;
        let seed = &self.keys.deposit;
        let wrong = |why: &str| Error::Invalid(format!("hub {url} found a deposit {why}"));
        let (Some(request), Some(terms)) = (status.request, status.terms) else {
            return Err(wrong("but not what was asked"));
        };
        let (_, ephemeral, hash) = request.receive.terms().map_err(invalid)?;
        let outputs = request.receive.outputs().map_err(invalid)?;
        let amount = outputs
            .iter()
            .try_fold(0u64, |sum, o| sum.checked_add(o.denomination()))
            .ok_or_else(|| wrong("of outputs overflowing"))?;
        let pays = terms.amount;
        let refund = x_only(&refund_key);
        let (preimage, htlc) = match (origin, &request.close, root) {
            // Of her keys and the hub's root, as when it was asked.
            (Origin::Close(c), Some(close), Some(root)) => {
                let mine = c.ephemeral(seed, address, amount)?.public();
                if ephemeral != mine || close.pays != pays {
                    return Err(wrong("of other notes or another payment than asked"));
                }
                (c.preimage(seed, address), close_htlc(&root, &hash, &refund))
            }
            (Origin::Close(_), Some(_), None) => {
                return Err(wrong("that returns a contract's reserve, no root named"))
            }
            (Origin::Number(number), None, _) => {
                let claim = XOnlyPublicKey::from_slice(&terms.claim.0)
                    .map_err(|_| wrong("claimed by no key"))?;
                let htlc = Htlc {
                    hash,
                    claim,
                    refund,
                    timeout: terms.timeout,
                    wait: None,
                    sized: false,
                };
                let preimage = preimage(seed, address, number, &ephemeral, amount, pays);
                (preimage, htlc)
            }
            _ => return Err(wrong("of another kind than asked")),
        };
        if hash != lock_hash(&preimage) || request.refund.0 != refund.serialize() {
            return Err(wrong("not as this wallet asked it"));
        }
        let network = licash_onchain::network(self.network());
        if htlc.address(network).to_string() != terms.address {
            return Err(wrong(&format!("at {}, not its terms", terms.address)));
        }
        let found = Asked {
            hash,
            preimage,
            refund_key,
            amount,
            pays,
            body: request,
        };
        self.store.write(|tx| {
            found.keep(tx, hub)?;
            keep_terms(tx, &hash, &htlc, &terms, network)
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, amount, "deposit found");
        Ok(hash)
    }
}

/// A deposit a wallet's seed may have asked the hub of `address` for, by
/// what it derives from, to check what the hub answers of it against.
struct Drawn<'a> {
    address: &'a [u8],
    origin: Origin,
    refund: SecretKey,
}

/// What a hub answers of a deposit a wallet's seed may have asked it for.
enum Found {
    /// The wallet keeps it already.
    Kept,
    /// Kept now, as its hub answered it.
    New(Box<Deposit>),
    /// The hub knows none under its refund key.
    Unknown,
    /// The hub answers one the seed never asked.
    NotMine,
}

/// A deposit drawn: what only the wallet knows of it, and what it asks.
struct Asked {
    hash: [u8; 32],
    preimage: [u8; 32],
    refund_key: SecretKey,
    amount: u64,
    /// What its payment is to be: the terms answered are held to it.
    pays: u64,
    body: licash_api::Deposit,
}

impl Asked {
    /// Record it, as asked of the hub `hub`.
    fn keep(&self, tx: &rusqlite::Transaction, hub: i64) -> Result<(), Error> {
        let body = serde_json::to_string(&self.body).map_err(invalid)?;
        tx.execute(
            "INSERT INTO deposits
                 (hash, hub, preimage, refund_key, amount, pays, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                self.hash,
                hub,
                self.preimage,
                self.refund_key.secret_bytes(),
                sql(self.amount)?,
                sql(self.pays)?,
                body,
                now()
            ],
        )?;
        Ok(())
    }
}

/// Record `terms`, checked to be those of `htlc`, as the hub's answer to
/// the deposit of `hash`.
pub(crate) fn keep_terms(
    tx: &rusqlite::Transaction,
    hash: &[u8; 32],
    htlc: &Htlc,
    terms: &Depositing,
    network: bitcoin::Network,
) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO deposit_terms (hash, claim_key, timeout_height, fund_by_height, address)
         SELECT ?1, ?2, ?3, ?4, ?5
         WHERE EXISTS (SELECT 1 FROM deposits WHERE hash = ?1 AND canceled IS NULL)
         ON CONFLICT (hash) DO UPDATE SET
            claim_key = excluded.claim_key, timeout_height = excluded.timeout_height,
            fund_by_height = excluded.fund_by_height, address = excluded.address",
        params![
            hash,
            htlc.claim.serialize(),
            terms.timeout,
            terms.fund_by,
            htlc.address(network).to_string(),
        ],
    )?;
    Ok(())
}

impl<T: Transport> Wallet<T> {
    /// Take the deposit of `hash` on: learn its hub's terms, then claim the
    /// notes its hub locks to the wallet once it is paid. Where it stands.
    pub async fn follow_deposit(&self, hash: &str) -> Result<Deposit, Error> {
        self.advance_deposit(&hash_id(hash)?).await
    }

    pub(crate) async fn advance_deposit(&self, hash: &[u8; 32]) -> Result<Deposit, Error> {
        let pending = |e: Error| match e {
            Error::Pending { .. } | Error::UnknownPayment(_) => e,
            e => Error::Pending {
                id: hex::encode(hash),
                reason: e.to_string(),
            },
        };
        self.advance_deposit_from(hash).await.map_err(pending)?;
        self.deposit_record(hash)
    }
}

impl<T: Transport> Wallet<T> {
    async fn advance_deposit_from(&self, hash: &[u8; 32]) -> Result<(), Error> {
        type Row = (String, [u8; 32], [u8; 32], (i64, i64), String, bool, bool);
        let row: Option<Row> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT r.url, d.preimage, d.refund_key, d.amount, d.pays, d.body,
                    EXISTS (SELECT 1 FROM deposit_terms t WHERE t.hash = d.hash),
                    d.done_at IS NULL AND d.canceled IS NULL AND d.refund IS NULL
                 FROM deposits d JOIN reach r ON r.hub = d.hub WHERE d.hash = ?1",
                [hash],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        (r.get(3)?, r.get(4)?),
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .optional()?)
        })?;
        let (url, preimage, refund_key, (amount, pays), body, answered, open) =
            row.ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))?;
        let refund = SecretKey::from_slice(&refund_key).map_err(invalid)?;
        // What its hub knows it by.
        let key = x_only(&refund).serialize();
        if !open {
            return Ok(());
        }
        if let Some(via) = self.store.read(|c| crate::deposits_via::via(c, hash))? {
            let asked = (preimage, &refund, (amount as u64, pays as u64));
            return self
                .advance_deposit_via(hash, (&url, &via), asked, &body, answered)
                .await;
        }
        // What was asked, which a deposit answered need not read again: of a
        // body it cannot, it is no contract's close.
        let parsed = serde_json::from_str::<licash_api::Deposit>(&body);
        if !answered {
            let body = parsed.as_ref().map_err(|e| invalid(e.to_string()))?;
            let asked = self
                .post::<Depositing>(&url, licash_api::DEPOSIT, body)
                .await;
            let terms = match asked {
                Ok(terms) => terms,
                // Refused before the hub named an address.
                Err(Error::Refused { problem, .. }) => {
                    return self.cancel_deposit(hash, &format!("refused: {problem}"));
                }
                Err(e) => return Err(e),
            };
            let asked = (amount as u64, pays as u64);
            let htlc = match self
                .check_terms(&url, hash, &refund, asked, body.close, &terms)
                .await
            {
                Ok(htlc) => htlc,
                Err(Error::Invalid(reason)) => return self.cancel_deposit(hash, &reason),
                Err(e) => return Err(e),
            };
            let network = licash_onchain::network(self.network());
            self.store
                .write(|tx| keep_terms(tx, hash, &htlc, &terms, network))?;
            let (address, pays) = (&terms.address, terms.amount);
            tracing::info!(hash = %hex::encode(hash), %url, %address, pays, "deposit terms");
        }
        let status: DepositStatus = self.get(&url, &licash_api::deposit_state(&key)).await?;
        if let Some(funding) = &status.funding {
            let txid: Txid = funding.txid.parse().map_err(|e| unavailable(&url, e))?;
            self.store.write(|tx| {
                tx.execute(
                    "INSERT INTO deposit_fundings (hash, txid, vout, height) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (hash) DO UPDATE SET
                        txid = excluded.txid, vout = excluded.vout, height = excluded.height",
                    params![hash, txid.to_byte_array(), funding.vout, funding.height],
                )?;
                Ok(())
            })?;
        }
        let lock = status.status.lock().map_err(|p| unavailable(&url, p))?;
        let lock: ProposalId = match (status.status.state, lock) {
            (ReceiveState::Open, _) => {
                // A contract's close is locked when the wallet asks, now it
                // is back and its payment seen, not at the block it was
                // paid in.
                let close = parsed.as_ref().is_ok_and(|body| body.close.is_some());
                if close && status.funding.is_some() {
                    self.post::<DepositStatus>(&url, &licash_api::deposit_lock(&key), &())
                        .await?;
                }
                return Ok(());
            }
            (ReceiveState::Canceled, _) => {
                return self.cancel_deposit(hash, "canceled by its hub");
            }
            (_, None) => return Err(unavailable(&url, "a deposit locked to no lock")),
            (_, Some(lock)) => lock,
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deposits SET lock = ?2 WHERE hash = ?1",
                params![hash, lock.as_bytes()],
            )?;
            Ok(())
        })?;
        // Its deposit's coin buys the notes: revealed only while the
        // wallet can still activate the lock, should the hub keep them.
        // A wallet that does not know the chain's height of itself could
        // not tell, and trusts its hub with them as with any notes.
        let (lock, least) = (hex::encode(lock.as_bytes()), amount as u64);
        let claimed = match self.tip()? {
            Some(_) => self.claim_protected(&url, &lock, &preimage, least).await,
            None => self.claim_paying(&url, &lock, &preimage, least).await,
        };
        match claimed {
            Ok(_) | Err(Error::AlreadyReceived) => {}
            // Refunded, too late to claim, or not a lock to this wallet.
            Err(Error::Invalid(reason)) => return self.cancel_deposit(hash, &reason),
            Err(Error::PaysNothing) => {
                return self.cancel_deposit(hash, "its lock pays this wallet nothing");
            }
            Err(e) => return Err(e),
        }
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deposits SET done_at = ?2 WHERE hash = ?1 AND done_at IS NULL",
                params![hash, now()],
            )?;
            Ok(())
        })?;
        tracing::info!(hash = %hex::encode(hash), %url, amount, "deposit received");
        Ok(())
    }
}

impl<T: Transport> Wallet<T> {
    /// The deposit `terms` answers for `hash`, which asked notes worth
    /// `amount` for a payment of `pays`, checked against that and what the
    /// hub at `url` says of its deposits: its address that of the hub's
    /// claim and the wallet's `refund`, its amount the payment asked, its
    /// timeout no later than the hub promises. A hub answering other
    /// terms gets nothing paid to them: the deposit is canceled unpaid.
    async fn check_terms(
        &self,
        url: &str,
        hash: &[u8; 32],
        refund: &SecretKey,
        (amount, pays): (u64, u64),
        close: Option<CloseTerms>,
        terms: &Depositing,
    ) -> Result<Htlc, Error> {
        let (_, info) = self.refresh(url).await?;
        let wrong = |why: String| Error::Invalid(format!("hub {url} answered a deposit {why}"));
        let deposits = info
            .deposits
            .ok_or_else(|| wrong("but takes none".into()))?;
        let height = info.locks.as_ref().map(|l| l.height);
        let height = height.ok_or_else(|| wrong("but follows no chain".into()))?;
        let htlc = match close {
            // Of her keys and the hub's root: the hub's word names no claim
            // key or timeout of it.
            Some(_) => {
                let root = deposits.close_root.ok_or_else(|| {
                    wrong(
                        "that returns a contract's reserve, but it publishes no deposit root"
                            .into(),
                    )
                })?;
                let root = XOnlyPublicKey::from_slice(&root.0)
                    .map_err(|_| wrong("under no root key".into()))?;
                close_htlc(&root, hash, &x_only(refund))
            }
            None => {
                let claim = XOnlyPublicKey::from_slice(&terms.claim.0)
                    .map_err(|_| wrong("claimed by no key".into()))?;
                Htlc {
                    hash: *hash,
                    claim,
                    refund: x_only(refund),
                    timeout: terms.timeout,
                    wait: None,
                    sized: false,
                }
            }
        };
        let network = licash_onchain::network(self.network());
        let address = terms
            .address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .ok()
            .and_then(|a| a.require_network(network).ok());
        if address.is_none_or(|a| a.script_pubkey() != htlc.script_pubkey()) {
            return Err(wrong(format!("at {}, not its terms", terms.address)));
        }
        match close {
            // Her contract's reserve exactly, for the most notes it covers.
            Some(close) => {
                if terms.amount != pays || close.pays != pays {
                    return Err(wrong(format!(
                        "of {} for {amount}, not as her contract's close",
                        terms.amount
                    )));
                }
            }
            None => {
                if terms.amount != pays {
                    return Err(wrong(format!("of {} for {amount}", terms.amount)));
                }
                let latest = height
                    .saturating_add(deposits.timeout)
                    .saturating_add(TIP_MARGIN);
                if terms.timeout > latest
                    || terms.fund_by.saturating_add(deposits.depth) > terms.timeout
                {
                    return Err(wrong(format!(
                        "timing out at block {}, paid by {}",
                        terms.timeout, terms.fund_by
                    )));
                }
            }
        }
        Ok(htlc)
    }

    pub(crate) fn cancel_deposit(&self, hash: &[u8; 32], reason: &str) -> Result<(), Error> {
        tracing::warn!(hash = %hex::encode(hash), reason, "deposit canceled");
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deposits SET canceled = ?2
                 WHERE hash = ?1 AND done_at IS NULL AND canceled IS NULL",
                params![hash, reason],
            )?;
            Ok(())
        })
    }

    /// Take back `funding`, the payment worth `value` of the deposit of
    /// `hash`, paying `to` all of it but the fee at `rate`: a transaction
    /// that confirms after the deposit's timeout, recorded as the
    /// deposit's refund. Again, at a higher rate, to replace it. Refused
    /// once its notes were received: the coins are its hub's.
    pub fn refund_deposit(
        &self,
        hash: &str,
        funding: OutPoint,
        value: Amount,
        to: ScriptBuf,
        rate: FeeRate,
    ) -> Result<Transaction, Error> {
        let hash = hash_id(hash)?;
        type Row = ([u8; 32], Option<[u8; 32]>, Option<u32>, bool, String);
        let row: Option<Row> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT d.refund_key, t.claim_key, t.timeout_height, d.done_at IS NOT NULL, d.body
                 FROM deposits d LEFT JOIN deposit_terms t ON t.hash = d.hash
                 WHERE d.hash = ?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?)
        })?;
        let (refund_key, claim, timeout, received, body) =
            row.ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))?;
        if received {
            return Err(Error::Invalid(
                "its notes were received: the coins are its hub's".into(),
            ));
        }
        let (Some(claim), Some(timeout)) = (claim, timeout) else {
            return Err(Error::Invalid(
                "its hub named no address: nothing was paid to it".into(),
            ));
        };
        let secret = SecretKey::from_slice(&refund_key).map_err(invalid)?;
        let htlc = Htlc {
            hash,
            claim: XOnlyPublicKey::from_slice(&claim).map_err(invalid)?,
            refund: x_only(&secret),
            timeout,
            // A close deposit waits after its payment, and names no height.
            wait: closes(&body).then_some(CLOSE_WAIT),
            sized: false,
        };
        let tx = htlc
            .refund_tx(funding, value, to, rate, &secret)
            .map_err(invalid)?;
        self.store.write(|t| {
            t.execute(
                "UPDATE deposits SET refund = ?2,
                     canceled = COALESCE(canceled, 'refunded by its owner')
                 WHERE hash = ?1",
                params![hash, bitcoin::consensus::serialize(&tx)],
            )?;
            Ok(())
        })?;
        let txid = tx.compute_txid();
        tracing::info!(hash = %hex::encode(hash), %txid, timeout, "deposit refund made");
        Ok(tx)
    }
}

impl<T: Transport> Wallet<T> {
    /// The deposits whose coins, if paid, may be taken back at `tip`
    /// ([`Wallet::refund_deposit`]): an address named, past their timeout,
    /// not taken back yet, and canceled, their notes never claimed, or
    /// still open with no lock to them ever seen, so never claimed (their
    /// hub gone, say): the preimage the hub would take the coins with was
    /// never sent, and no lock to them is made so late. Paid or not:
    /// [`Deposit::funding`] is the payment its hub saw, none for one it
    /// did not (made too late, say), which only its payer knows of.
    pub fn deposits_to_refund(&self, tip: u32) -> Result<Vec<Deposit>, Error> {
        let mut due = self.deposits()?;
        due.retain(|d| {
            let past = d.refund_height().is_some_and(|height| tip >= height);
            let never_locked = d.state == DepositState::Open && d.lock.is_none();
            past && (matches!(d.state, DepositState::Canceled(_)) || never_locked)
        });
        Ok(due)
    }

    /// The refund made of the deposit of `hash`, if one was: to hand the
    /// network again until it confirms.
    pub fn deposit_refund(&self, hash: &str) -> Result<Option<Transaction>, Error> {
        let key = hash_id(hash)?;
        let raw: Option<Option<Vec<u8>>> = self.store.read(|c| {
            Ok(
                c.query_row("SELECT refund FROM deposits WHERE hash = ?1", [key], |r| {
                    r.get(0)
                })
                .optional()?,
            )
        })?;
        let raw = raw.ok_or_else(|| Error::UnknownPayment(hash.to_owned()))?;
        raw.map(|tx| bitcoin::consensus::deserialize(&tx).map_err(invalid))
            .transpose()
    }

    /// The deposits asked for, newest first.
    pub fn deposits(&self) -> Result<Vec<Deposit>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "{} ORDER BY d.created_at DESC, d.rowid DESC",
                deposits(c)?
            ))?;
            let rows = stmt.query_map([], deposit_of)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The deposit of `hash`.
    pub fn deposit_of(&self, hash: &str) -> Result<Deposit, Error> {
        self.deposit_record(&hash_id(hash)?)
    }

    pub(crate) fn deposit_record(&self, hash: &[u8; 32]) -> Result<Deposit, Error> {
        self.store.read(|c| {
            let query = format!("{} WHERE d.hash = ?1", deposits(c)?);
            c.query_row(&query, [hash], deposit_of)
                .optional()?
                .ok_or_else(|| Error::UnknownPayment(hex::encode(hash)))
        })
    }

    /// The deposits under way, oldest first.
    pub(crate) fn open_deposits(&self) -> Result<Vec<[u8; 32]>, Error> {
        self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash FROM deposits
                 WHERE done_at IS NULL AND canceled IS NULL AND refund IS NULL
                 ORDER BY created_at, rowid",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }
}

/// The query of the deposits, read by [`deposit_of`]: with the provider
/// each was asked of, in a file whose wallet asked any of one.
fn deposits(c: &rusqlite::Connection) -> Result<String, Error> {
    let provider = match crate::deposits_via::kept(c)? {
        true => "(SELECT p.provider FROM deposit_providers p WHERE p.hash = d.hash)",
        false => "NULL",
    };
    Ok(format!(
        "SELECT d.hash, r.url, d.amount, t.address, t.timeout_height, d.pays,
            t.fund_by_height, f.txid, f.vout, f.height, d.done_at IS NOT NULL, d.canceled,
            d.refund, d.created_at, d.lock, d.body, {provider}
         FROM deposits d JOIN reach r ON r.hub = d.hub
         LEFT JOIN deposit_terms t ON t.hash = d.hash
         LEFT JOIN deposit_fundings f ON f.hash = d.hash"
    ))
}

fn deposit_of(r: &Row<'_>) -> rusqlite::Result<Deposit> {
    let terms = match (r.get(3)?, r.get(4)?, r.get(6)?) {
        (Some(address), Some(timeout), Some(fund_by)) => Some(DepositTerms {
            address,
            pays: r.get::<_, i64>(5)? as u64,
            fund_by,
            timeout,
        }),
        _ => None,
    };
    let funding = match (r.get::<_, Option<[u8; 32]>>(7)?, r.get(8)?, r.get(9)?) {
        (Some(txid), Some(vout), Some(height)) => Some((
            OutPoint {
                txid: Txid::from_byte_array(txid),
                vout,
            },
            height,
        )),
        _ => None,
    };
    let refunded = match r.get::<_, Option<Vec<u8>>>(12)? {
        Some(raw) => {
            let tx: Transaction = bitcoin::consensus::deserialize(&raw).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(12, rusqlite::types::Type::Blob, e.into())
            })?;
            Some(tx.compute_txid())
        }
        None => None,
    };
    let state = match (
        refunded,
        r.get::<_, bool>(10)?,
        r.get::<_, Option<String>>(11)?,
    ) {
        (Some(txid), _, _) => DepositState::Refunded(txid),
        (None, true, _) => DepositState::Received,
        (None, false, Some(reason)) => DepositState::Canceled(reason),
        (None, false, None) => DepositState::Open,
    };
    Ok(Deposit {
        hash: hex::encode(r.get::<_, [u8; 32]>(0)?),
        hub: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        terms,
        funding,
        lock: r.get::<_, Option<Vec<u8>>>(14)?.map(hex::encode),
        state,
        created_at: r.get(13)?,
        close: closes(&r.get::<_, String>(15)?),
        provider: r.get(16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [7; 32];
    const HUB: [u8; 99] = [9; 99];

    fn ephemeral(byte: u8) -> Point {
        let scalar = scalar_from_hash(&[byte; 32]);
        Ephemeral::from_scalar(scalar).unwrap().public()
    }

    #[test]
    fn a_deposits_preimage_is_of_all_that_is_asked_and_its_refund_key_of_its_number_alone() {
        let key = ephemeral(1);
        let asked = preimage(&SEED, &HUB, 3, &key, 3_000, 3_100);
        // Another for another seed, hub, number, key, notes or payment.
        let others = [
            preimage(&[8; 32], &HUB, 3, &key, 3_000, 3_100),
            preimage(&SEED, &[8; 99], 3, &key, 3_000, 3_100),
            preimage(&SEED, &HUB, 4, &key, 3_000, 3_100),
            preimage(&SEED, &HUB, 3, &ephemeral(2), 3_000, 3_100),
            preimage(&SEED, &HUB, 3, &key, 2_999, 3_100),
            preimage(&SEED, &HUB, 3, &key, 3_000, 3_101),
            // Notes and payment are told apart, not summed or joined.
            preimage(&SEED, &HUB, 3, &key, 3_100, 3_000),
            close().preimage(&SEED, &HUB),
        ];
        for (n, other) in others.iter().enumerate() {
            assert_ne!(*other, asked, "{n}");
        }
        // The refund key, by which its hub is asked after it, is of the
        // seed, the hub and the number, whatever is asked.
        let refund = refund_secret(&SEED, &HUB, 3).unwrap();
        assert_ne!(refund, refund_secret(&SEED, &HUB, 4).unwrap());
        assert_ne!(refund, refund_secret(&[8; 32], &HUB, 3).unwrap());
        assert_ne!(refund, refund_secret(&SEED, &[8; 99], 3).unwrap());
        // As a wallet restored from its seed must derive them again.
        assert_eq!(
            hex::encode(asked),
            "689f3c1e132cc351ac2f25b590954119721cea3bb32b36f3c60e167c16e68560"
        );
        assert_eq!(
            hex::encode(refund.secret_bytes()),
            "9eba18c9ca7247242b4c033fda6cdeccb09d4cf37115bed630f3b46814d985e1"
        );
    }

    fn close() -> Close {
        Close {
            coin: OutPoint {
                txid: Txid::from_byte_array([5; 32]),
                vout: 1,
            },
            attempt: 2,
        }
    }

    #[test]
    fn a_close_deposits_secrets_are_of_the_coin_that_opens_its_contract() {
        let other = |f: fn(&mut Close)| {
            let mut close = close();
            f(&mut close);
            close
        };
        // Found on Bitcoin with its hub gone, of nothing a hub answers:
        // another for another seed, hub, coin, output of it or attempt.
        let others = [
            other(|c| c.coin.txid = Txid::from_byte_array([6; 32])),
            other(|c| c.coin.vout = 2),
            other(|c| c.attempt = 3),
        ];
        let preimage = close().preimage(&SEED, &HUB);
        let refund = close().refund_secret(&SEED, &HUB).unwrap();
        for close in others {
            assert_ne!(preimage, close.preimage(&SEED, &HUB), "{close:?}");
            assert_ne!(refund, close.refund_secret(&SEED, &HUB).unwrap());
        }
        assert_ne!(preimage, close().preimage(&[8; 32], &HUB));
        assert_ne!(preimage, close().preimage(&SEED, &[8; 99]));
        // Never an ordinary deposit's refund key, which its hub knows it by.
        assert_ne!(
            refund.secret_bytes()[..],
            tagged_hash(
                "licash/deposit/refund",
                &[&SEED, &HUB, &close().parts()[..4]]
            )
        );
        // A hub answering fewer notes answers another key than her seed's.
        let key = close().ephemeral(&SEED, &HUB, 2_900).unwrap().public();
        assert_ne!(key, close().ephemeral(&SEED, &HUB, 2_899).unwrap().public());
        let next = other(|c| c.attempt = 3);
        assert_ne!(key, next.ephemeral(&SEED, &HUB, 2_900).unwrap().public());
        assert_eq!(
            hex::encode(preimage),
            "7908864f6fff1a63fa68c217e53aa27ae0cd31e3be4a8a7172dcb2687a0fe332"
        );
        assert_eq!(
            hex::encode(refund.secret_bytes()),
            "6115e1bc2177fc2cef78d5faa78a3786dacddc020598673ee851906f85c9c089"
        );
        assert_eq!(
            hex::encode(key.0),
            "02367bda212d8e386ee03a1b78342f0dbf9b4e0b51fdb0bcd4e5e1fd13bbc797a4"
        );
    }
}
