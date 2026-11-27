//! A Licash bridge: a Licash wallet of its own that pays and takes
//! Lightning payments for Nostr Wallet Connect clients, through a swap
//! provider, out of accounts it keeps for their owners, who pay into and
//! out of them in notes at its hub too (its `notes` module). Custodial: an account
//! is the bridge's word for what its wallet holds for someone.
//!
//! An account is a key ([`licash_api::bridge::Signed`]); its owner makes
//! NWC connections for it, each paying, receiving or both, within a
//! budget. Paying an invoice holds what it may cost out of the account
//! before the hub hears of it, and gives back what it did not cost once
//! the wallet's lock for it is paid or refunded. An invoice made for an
//! account credits it the notes its payment brings, once claimed. So the
//! accounts never hold more than the wallet does, short of what its hub
//! took of a refund.
//!
//! Run alone ([`Config::open`] false) it keeps one account, its owner's,
//! registered with the pairing code [`Bridge::init`] made. Open, anyone
//! may register one, within [`Config::max_balance`].

mod api;
pub mod lnurl;
mod notes;
pub mod nwc;
mod store;

pub use api::{router, MAX_SERVING};

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use licash_api::{
    bridge::{self, Activity, Connect, Connected, Direction, Info, Permission, State},
    Code, Problem,
};
use licash_wallet::{InvoiceState, Lock, LockState, ReceiveOffer, Transport, Wallet};
use lightning_invoice::Bolt11Invoice;
use nostr::prelude::{Keys, NostrWalletConnectUri, RelayUrl, SecretKey};
use rand_core::{OsRng, RngCore};

use store::{Link, Payment, Receipt, Store};

/// How long a payment is waited for before it is answered as under way.
pub const PAY_WAIT: Duration = Duration::from_secs(60);

/// The most activity an [`bridge::Account`] lists.
const ACTIVITY: u32 = 50;

/// Why the bridge did not do what it was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The request does not decode, or asks what cannot be.
    Invalid(String),
    /// Not a key the bridge knows, or not its to ask.
    Unauthorized(String),
    /// The connection may not do this.
    Restricted(String),
    /// The account holds too little.
    Insufficient(String),
    /// Beyond a connection's budget or the bridge's limits.
    Quota(String),
    NotFound(String),
    /// The payment failed: nothing was spent but a refund's fee.
    Failed(String),
    /// The payment is under way: asked again, it answers where it stands.
    Pending(String),
    /// The bridge's notes were exported: it pays nothing out.
    Frozen,
    /// The bridge, its wallet or its hub cannot serve now.
    Unavailable(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "invalid: {m}"),
            Self::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            Self::Restricted(m) => write!(f, "restricted: {m}"),
            Self::Insufficient(m) => write!(f, "insufficient balance: {m}"),
            Self::Quota(m) => write!(f, "over the limit: {m}"),
            Self::NotFound(m) => write!(f, "not found: {m}"),
            Self::Failed(m) => write!(f, "payment failed: {m}"),
            Self::Pending(m) => write!(f, "under way: {m}"),
            Self::Frozen => write!(f, "the bridge's notes were exported: it pays nothing out"),
            Self::Unavailable(m) => write!(f, "unavailable: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// As the management API answers it.
    pub fn problem(&self) -> Problem {
        let code = match self {
            Self::Invalid(_) => Code::Invalid,
            Self::Unavailable(_) => Code::Unavailable,
            _ => Code::Declined,
        };
        Problem::new(code, self.to_string())
    }
}

fn wallet_error(e: licash_wallet::Error) -> Error {
    use licash_wallet::Error as W;
    match e {
        W::Invalid(m) => Error::Invalid(m),
        W::Pending { reason, .. } => Error::Pending(reason),
        e @ (W::FeeRose { .. } | W::Refused { .. } | W::Abandoned { .. }) => {
            Error::Failed(e.to_string())
        }
        W::Insufficient { .. } => {
            Error::Unavailable("the bridge's wallet holds too little: tell its operator".into())
        }
        e => Error::Unavailable(e.to_string()),
    }
}

/// How a bridge runs.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// The hub its wallet pays and is paid through.
    pub hub: String,
    /// The swap provider it pays and is paid over Lightning through: hubs
    /// run no Lightning gateway. Without, it pays and is paid in notes
    /// alone.
    pub via: Option<String>,
    /// Whether anyone may register an account.
    pub open: bool,
    pub name: Option<String>,
    /// The relays its NWC service listens on.
    pub relays: Vec<String>,
    /// The most an account may hold, in msat.
    pub max_balance: Option<u64>,
    /// The most one payment may be, in msat.
    pub max_payment: Option<u64>,
    /// Where it is reached publicly, `https://domain`, if it serves
    /// Lightning Addresses there: at `name@domain`.
    pub public_url: Option<String>,
    /// Open, the most accounts it keeps, and registers in any hour, if
    /// bounded: anyone else is refused until then.
    pub max_accounts: Option<u64>,
    pub registrations_per_hour: Option<u64>,
}

/// What the bridge owes and holds, for its operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub accounts: usize,
    /// What the accounts hold, payments under way included, in msat.
    pub owed: u64,
    /// What its wallet holds at its hub, in sat.
    pub held: u64,
    pub frozen: bool,
}

/// A bridge over a wallet reaching its hub through `T`.
pub struct Bridge<T> {
    wallet: Wallet<T>,
    store: Store,
    config: Config,
    keys: Keys,
    /// The payments being made or followed now, by hash.
    paying: Mutex<HashSet<[u8; 32]>>,
    /// Held while its notes change hands other than by payments (unlinked)
    /// or are exported: never both at once.
    notes: tokio::sync::Mutex<()>,
    /// What its provider last said it takes to have it paid at its hub,
    /// once asked ([`Bridge::ask_provider`]).
    offer: Mutex<Option<ReceiveOffer>>,
    /// What the invoices being made now, not recorded yet, would credit
    /// each account, by its id: counted toward its cap meanwhile.
    invoicing: Mutex<HashMap<i64, u64>>,
    /// The NWC requests answered since it was opened ([`nwc::run`]).
    answering: nwc::Answering,
}

/// An invoice of `amount` to account `id` being made, counted toward its
/// cap ([`Bridge::admit_credit`]) until recorded or given up.
struct Invoicing<'a> {
    of: &'a Mutex<HashMap<i64, u64>>,
    id: i64,
    amount: u64,
}

impl Invoicing<'_> {
    fn uncount(&self, invoicing: &mut HashMap<i64, u64>) {
        if let Some(making) = invoicing.get_mut(&self.id) {
            *making = making.saturating_sub(self.amount);
            if *making == 0 {
                invoicing.remove(&self.id);
            }
        }
    }

    /// Record it by `record`, no longer counted as being made at once: no
    /// admission meanwhile counts it twice, or not at all.
    fn record<R>(self, record: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
        let mut invoicing = self.of.lock().unwrap_or_else(PoisonError::into_inner);
        let recorded = record();
        self.uncount(&mut invoicing);
        drop(invoicing);
        std::mem::forget(self);
        recorded
    }
}

impl Drop for Invoicing<'_> {
    fn drop(&mut self) {
        self.uncount(&mut self.of.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

/// What an invoice paying the bridge may ask, and through whom.
struct Receiving {
    /// The fee on its amount, asked on top.
    fee: licash_api::Fee,
    /// The least and the most it pays, in sat.
    min: u64,
    max: u64,
    /// The provider making it.
    via: String,
}

/// A payment being made or followed, for as long as it is held.
struct Turn<'a> {
    paying: &'a Mutex<HashSet<[u8; 32]>>,
    hash: [u8; 32],
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut paying = self.paying.lock().unwrap_or_else(PoisonError::into_inner);
        paying.remove(&self.hash);
    }
}

fn now() -> i64 {
    licash_store::now()
}

fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// A code to type: 16 hex digits.
fn pairing_code() -> String {
    hex::encode(&random()[..8])
}

fn same(a: &str, b: &str) -> bool {
    // Compared whole, at once: a guess learns nothing from how long.
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

fn key_hex(key: &str) -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(key, &mut bytes)
        .map_err(|_| Error::Invalid(format!("{key:?} is no key in hex")))?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};
    sha256::Hash::hash(bytes).to_byte_array()
}

fn decode(request: &str) -> Result<Bolt11Invoice, Error> {
    request
        .trim()
        .parse()
        .map_err(|_| Error::Invalid("not a BOLT11 invoice".into()))
}

impl<T: Transport> Bridge<T> {
    /// Make the wallet a bridge: its records, a Nostr key for its NWC
    /// service and a pairing code for its owner, which it answers.
    pub fn init(wallet: &Wallet<T>) -> Result<String, Error> {
        let pairing = pairing_code();
        Store::create(wallet.path(), &random(), &pairing)?;
        Ok(pairing)
    }

    /// The bridge `wallet` was made, run as `config` says.
    pub fn open(wallet: Wallet<T>, config: Config) -> Result<Self, Error> {
        let store = Store::open(wallet.path())?;
        let meta = store.read(store::meta)?;
        let secret = SecretKey::from_slice(&meta.nostr)
            .map_err(|_| Error::Unavailable("the bridge's Nostr key is corrupt".into()))?;
        Ok(Self {
            wallet,
            store,
            config,
            keys: Keys::new(secret),
            paying: Mutex::new(HashSet::new()),
            notes: tokio::sync::Mutex::new(()),
            offer: Mutex::new(None),
            invoicing: Mutex::new(HashMap::new()),
            answering: nwc::Answering::new(),
        })
    }

    /// The provider it pays and is paid over Lightning through.
    fn via(&self) -> Result<&str, Error> {
        (self.config.via.as_deref()).ok_or_else(|| {
            Error::Unavailable("the bridge names no swap provider to use Lightning through".into())
        })
    }

    /// What it takes to be paid: its provider's terms as it last said.
    fn receiving(&self) -> Result<Receiving, Error> {
        let via = self.via()?;
        let hub = &self.config.hub;
        let offer = self.offer.lock().unwrap_or_else(PoisonError::into_inner);
        let offer = offer.as_ref().ok_or_else(|| {
            Error::Unavailable(format!("provider {via} takes no payments at hub {hub}"))
        })?;
        Ok(Receiving {
            fee: offer.terms.fee,
            min: offer.terms.min,
            max: offer.max,
            via: via.to_owned(),
        })
    }

    /// Ask its provider again what it takes to have it paid: kept for
    /// [`Bridge::info`] and its Lightning Addresses. Its last answer is
    /// kept while it cannot be reached; holding too little at the hub now,
    /// its terms are kept with none to be paid at once, as it may hold
    /// more soon.
    async fn ask_provider(&self) -> Result<(), Error> {
        let Some(via) = &self.config.via else {
            return Ok(());
        };
        let asked = self.wallet.receive_offer(via, &self.config.hub).await;
        let offer = match asked {
            Ok(offer) => Some(offer),
            // It takes none there now.
            Err(e @ licash_wallet::Error::Invalid(_)) => {
                tracing::warn!(%via, "the provider: {e}");
                match self.wallet.provider_info(via).await {
                    Ok(info) => info.receive.map(|terms| ReceiveOffer {
                        info,
                        terms,
                        max: 0,
                    }),
                    Err(e) => {
                        tracing::debug!(%via, "the provider: {e}");
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                tracing::debug!(%via, "the provider: {e}");
                return Ok(());
            }
        };
        *self.offer.lock().unwrap_or_else(PoisonError::into_inner) = offer;
        Ok(())
    }

    pub fn wallet(&self) -> &Wallet<T> {
        &self.wallet
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The NWC requests it answered since it was opened.
    pub(crate) fn answering(&self) -> &nwc::Answering {
        &self.answering
    }

    /// The keys its NWC service answers as.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// What it says of itself.
    pub fn info(&self) -> Result<Info, Error> {
        let receive_fee = self.receiving()?.fee;
        Ok(Info {
            name: self.config.name.clone(),
            network: self.wallet.network().to_string(),
            hub: self.config.hub.clone(),
            nostr: self.keys.public_key().to_hex(),
            relays: self.config.relays.clone(),
            open: self.config.open,
            max_balance: self.config.max_balance,
            max_payment: self.config.max_payment,
            receive_fee,
            lightning_address: self.lightning_domain(),
        })
    }

    /// What it owes and holds.
    pub fn status(&self) -> Result<Status, Error> {
        let (accounts, owed, frozen) = self.store.read(|c| {
            let accounts = store::accounts(c)?;
            let mut owed = 0u64;
            for account in &accounts {
                owed = owed
                    .saturating_add(account.balance)
                    .saturating_add(store::reserved(c, account.id)?);
            }
            Ok((accounts.len(), owed, store::meta(c)?.frozen_at.is_some()))
        })?;
        let balance = self.wallet.balance().map_err(wallet_error)?;
        let held = balance.iter().map(|b| b.available + b.pending).sum();
        Ok(Status {
            accounts,
            owed,
            held,
            frozen,
        })
    }

    /// The code an owner registers with: a new one if `renew`, which
    /// hands the owner's account to whoever registers with it next. None
    /// once used, unless renewed.
    pub fn pairing(&self, renew: bool) -> Result<Option<String>, Error> {
        if !renew {
            return Ok(self.store.read(store::meta)?.pairing);
        }
        let pairing = pairing_code();
        self.store.write(|tx| {
            tx.execute("UPDATE bridge_meta SET pairing = ?1", [&pairing])?;
            Ok(())
        })?;
        Ok(Some(pairing))
    }

    /// Freeze it for good, then seal every note its wallet holds to `to`,
    /// an x-only key, and the refund of each lock of its payments under
    /// way, for the wallet of that key at this bridge to claim in a
    /// recovery of its own should the hub stop cooperating. Frozen first:
    /// it pays nothing out, takes no new invoice, nor unlinks, from then
    /// on; the invoices it made are still taken. Refused while a payment
    /// under way has no lock yet, its notes neither its own nor a lock's:
    /// exported once its lock is made, or it is decided. The same again
    /// exports the same notes, and those received meanwhile.
    pub async fn export(&self, to: &[u8; 32]) -> Result<licash_api::bridge::Exported, Error> {
        let at = now();
        self.store.write(|tx| {
            tx.execute(
                "UPDATE bridge_meta SET frozen_at = COALESCE(frozen_at, ?1)",
                [at],
            )?;
            Ok(())
        })?;
        let _notes = self.notes.lock().await;
        // Frozen, no payment starts: each under way is one of these, and
        // one whose lock stands keeps it. One whose lock is settled is
        // decided at the next round, its notes then free: a retry's may be
        // about to be made.
        let (pending, payouts) = self
            .store
            .read(|c| Ok((store::pending_payments(c)?, notes::pending(c)?)))?;
        if !payouts.is_empty() {
            return Err(Error::Unavailable(format!(
                "frozen, but {} payouts in notes are being made: exported once they are decided",
                payouts.len()
            )));
        }
        let mut unlocked = 0;
        for payment in &pending {
            let stands = (self.lock_for(payment)?)
                .is_some_and(|l| matches!(l.state, LockState::Requested | LockState::Locked));
            if !stands {
                unlocked += 1;
            }
        }
        if unlocked > 0 {
            return Err(Error::Unavailable(format!(
                "frozen, but {unlocked} payments are being made: exported once they are sent"
            )));
        }
        let source = self.keys.public_key().to_bytes();
        let sealed = self
            .wallet
            .export_notes(&source, to)
            .map_err(wallet_error)?;
        tracing::warn!(
            to = %hex::encode(to), notes = sealed.notes, amount = sealed.amount,
            locks = sealed.locks, locked = sealed.locked, "frozen, its notes exported"
        );
        Ok(licash_api::bridge::Exported {
            export: licash_api::Hex(sealed.sealed),
            notes: sealed.notes as u64,
            amount: sealed.amount,
            locks: sealed.locks as u64,
            locked: sealed.locked,
        })
    }

    /// Pay out again, if frozen: whether it was. Only once the wallet its
    /// notes were exported to discarded them, as two claims of a note
    /// void it in both.
    pub fn unfreeze(&self) -> Result<bool, Error> {
        self.store.write(|tx| {
            let n = tx.execute(
                "UPDATE bridge_meta SET frozen_at = NULL WHERE frozen_at IS NOT NULL",
                [],
            )?;
            Ok(n == 1)
        })
    }

    fn not_frozen(&self) -> Result<(), Error> {
        match self.store.read(store::meta)?.frozen_at {
            Some(_) => Err(Error::Frozen),
            None => Ok(()),
        }
    }

    /// Refused unless `key` holds the bridge's only account: its notes are
    /// every account's, so its holder exports them by its signature only
    /// where it is the one account. Accounts are never forgotten, so a
    /// bridge that was ever open keeps refusing, whatever it runs as now.
    pub(crate) fn sole_account(&self, key: &[u8; 32]) -> Result<(), Error> {
        self.account_id(key)?;
        let accounts: i64 = self
            .store
            .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM bridge_accounts", [], |r| r.get(0))?))?;
        if accounts != 1 {
            return Err(Error::Restricted(
                "a bridge of several accounts exports to its operator only".into(),
            ));
        }
        Ok(())
    }

    fn account_id(&self, key: &[u8; 32]) -> Result<i64, Error> {
        self.store
            .read(|c| store::account_of(c, key))?
            .map(|a| a.id)
            .ok_or_else(|| Error::Unauthorized("no account of this key: register first".into()))
    }
}

/// Accounts and their connections.
impl<T: Transport> Bridge<T> {
    /// Register `key`'s account: the same again if it has one. Alone, only
    /// with the pairing code, which hands the owner's account to `key`.
    pub fn register(
        &self,
        key: &[u8; 32],
        pairing: Option<&str>,
    ) -> Result<bridge::Account, Error> {
        let open = self.config.open;
        self.store.write(|tx| {
            if store::account_of(tx, key)?.is_some() {
                return Ok(());
            }
            let at = now();
            if open {
                let (accounts, lately): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COUNT(*) FILTER (WHERE created_at > ?1)
                     FROM bridge_accounts",
                    [at - 3600],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let (accounts, lately) = (accounts.unsigned_abs(), lately.unsigned_abs());
                if let Some(max) = self.config.max_accounts.filter(|max| accounts >= *max) {
                    return Err(Error::Quota(format!(
                        "the bridge keeps {max} accounts at most"
                    )));
                }
                let hourly = self.config.registrations_per_hour;
                if let Some(max) = hourly.filter(|max| lately >= *max) {
                    return Err(Error::Quota(format!(
                        "the bridge registers {max} accounts an hour at most: try later"
                    )));
                }
                tx.execute(
                    "INSERT INTO bridge_accounts (key, balance, created_at) VALUES (?1, 0, ?2)",
                    rusqlite::params![key, at],
                )?;
                return Ok(());
            }
            let expected = store::meta(tx)?.pairing;
            match (expected.as_deref(), pairing) {
                (Some(expected), Some(given)) if same(expected, given.trim()) => {}
                _ => return Err(Error::Unauthorized("not this bridge's pairing code".into())),
            }
            tx.execute("UPDATE bridge_meta SET pairing = NULL", [])?;
            // The owner's account, handed over, or made.
            let handed = tx.execute(
                "UPDATE bridge_accounts SET key = ?1
                 WHERE id = (SELECT MIN(id) FROM bridge_accounts)",
                [key],
            )?;
            if handed == 0 {
                tx.execute(
                    "INSERT INTO bridge_accounts (key, balance, created_at) VALUES (?1, 0, ?2)",
                    rusqlite::params![key, at],
                )?;
            }
            Ok(())
        })?;
        self.account(key)
    }

    /// `key`'s account as it stands.
    pub fn account(&self, key: &[u8; 32]) -> Result<bridge::Account, Error> {
        let id = self.account_id(key)?;
        let at = now();
        self.store.read(|c| {
            let account = store::account(c, id)?;
            let connections = store::links_of(c, id)?
                .iter()
                .map(|link| connection(c, link, at))
                .collect::<Result<_, _>>()?;
            let activity = activity(c, id, ACTIVITY)?;
            Ok(bridge::Account {
                balance: account.balance,
                reserved: store::reserved(c, id)?,
                connections,
                activity,
                lightning_address: match (&account.username, &self.lightning_domain()) {
                    (Some(name), Some(domain)) => Some(format!("{name}@{domain}")),
                    _ => None,
                },
            })
        })
    }

    /// A new NWC connection for `key`'s account, of a fresh key whose
    /// secret only the URI answered carries.
    pub fn connect(&self, key: &[u8; 32], connect: &Connect) -> Result<Connected, Error> {
        let account = self.account_id(key)?;
        let name = connect.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(Error::Invalid("a name of 1 to 64 characters".into()));
        }
        if connect.permissions.is_empty() {
            return Err(Error::Invalid(
                "a connection that may pay, receive or both".into(),
            ));
        }
        let relays = self
            .config
            .relays
            .iter()
            .map(|r| RelayUrl::parse(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Unavailable(format!("a relay of the bridge's: {e}")))?;
        if relays.is_empty() {
            return Err(Error::Unavailable("the bridge listens on no relay".into()));
        }
        let secret = Keys::generate();
        let link = Link {
            key: secret.public_key().to_bytes(),
            account,
            name: name.to_owned(),
            pay: connect.permissions.contains(&Permission::Pay),
            receive: connect.permissions.contains(&Permission::Receive),
            max_payment: connect.max_payment,
            budget: connect.budget,
            expires_at: connect.expires_at,
            revoked_at: None,
            created_at: now(),
        };
        let lud16 = self.store.write(|tx| {
            store::insert_link(tx, &link)?;
            Ok(store::account(tx, account)?.username)
        })?;
        let lud16 = match (lud16, &self.lightning_domain()) {
            (Some(name), Some(domain)) if link.receive => Some(format!("{name}@{domain}")),
            _ => None,
        };
        let uri = NostrWalletConnectUri::new(
            self.keys.public_key(),
            relays,
            secret.secret_key().clone(),
            lud16,
        );
        let connection = self.store.read(|c| connection(c, &link, now()))?;
        tracing::info!(name = %link.name, pay = link.pay, receive = link.receive, "connection made");
        Ok(Connected {
            connection,
            uri: uri.to_string(),
        })
    }

    /// Revoke the connection of `client`, `key`'s, for good.
    pub fn revoke(&self, key: &[u8; 32], client: &str) -> Result<bridge::Connection, Error> {
        let account = self.account_id(key)?;
        let client = key_hex(client)?;
        let link = self.store.write(|tx| {
            let link = store::link(tx, &client)?
                .filter(|l| l.account == account)
                .ok_or_else(|| Error::NotFound("no such connection of this account".into()))?;
            tx.execute(
                "UPDATE bridge_connections SET revoked_at = COALESCE(revoked_at, ?2) WHERE key = ?1",
                rusqlite::params![client, now()],
            )?;
            Ok(link)
        })?;
        self.store.read(|c| {
            let link = store::link(c, &link.key)?.expect("just revoked");
            connection(c, &link, now())
        })
    }

    /// The live connection of the client `key`.
    pub(crate) fn link(&self, key: &[u8; 32]) -> Result<Link, Error> {
        self.store
            .read(|c| store::link(c, key))?
            .filter(|link| link.live(now()))
            .ok_or_else(|| Error::Unauthorized("no such connection, or no longer".into()))
    }

    /// The balance of account `id`, in msat.
    pub(crate) fn balance_of(&self, id: i64) -> Result<u64, Error> {
        Ok(self.store.read(|c| store::account(c, id))?.balance)
    }

    /// The payments and invoices of account `id`, newest first, at most
    /// 1000.
    pub(crate) fn activity_of(&self, id: i64) -> Result<Vec<Activity>, Error> {
        self.store.read(|c| activity(c, id, 1000))
    }

    /// A payment or invoice of account `id`, by its hash.
    pub(crate) fn lookup(&self, id: i64, hash: &[u8; 32]) -> Result<Activity, Error> {
        self.store.read(|c| {
            if let Some(p) = store::payment(c, hash)?.filter(|p| p.account == id) {
                return Ok(outgoing(&p));
            }
            if let Some(r) = store::receipt(c, hash)?.filter(|r| r.account == id) {
                return Ok(incoming(&r));
            }
            Err(Error::NotFound("no such invoice of this account".into()))
        })
    }
}

fn connection(c: &rusqlite::Connection, link: &Link, at: i64) -> Result<bridge::Connection, Error> {
    let mut permissions = Vec::new();
    if link.pay {
        permissions.push(Permission::Pay);
    }
    if link.receive {
        permissions.push(Permission::Receive);
    }
    Ok(bridge::Connection {
        key: hex::encode(link.key),
        name: link.name.clone(),
        permissions,
        max_payment: link.max_payment,
        budget: link.budget,
        spent: store::spent(c, &link.key, link.period_start(at))?,
        expires_at: link.expires_at,
        revoked: link.revoked_at.is_some(),
        created_at: link.created_at,
    })
}

/// The newest `limit` payments and invoices of account `id`, newest first.
fn activity(c: &rusqlite::Connection, id: i64, limit: u32) -> Result<Vec<Activity>, Error> {
    let mut activity: Vec<Activity> = store::payments_of(c, id, limit)?
        .iter()
        .map(outgoing)
        .chain(store::receipts_of(c, id, limit)?.iter().map(incoming))
        .chain(notes::activity(c, id, limit)?)
        .collect();
    activity.sort_by_key(|a| std::cmp::Reverse(a.created_at));
    activity.truncate(limit as usize);
    Ok(activity)
}

fn outgoing(p: &Payment) -> Activity {
    Activity {
        direction: Direction::Outgoing,
        state: p.state,
        hash: hex::encode(p.hash),
        invoice: p.invoice.clone(),
        amount: p.amount,
        fee: p.fee(),
        connection: p.connection.map(hex::encode),
        description: decode(&p.invoice).ok().and_then(|i| match i.description() {
            lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(d) => Some(d.to_string()),
            lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(_) => None,
        }),
        preimage: p.preimage.map(hex::encode),
        failure: p.failure.clone(),
        created_at: p.created_at,
        settled_at: p.settled_at.filter(|_| p.state == State::Settled),
    }
}

fn incoming(r: &Receipt) -> Activity {
    Activity {
        direction: Direction::Incoming,
        state: r.state,
        hash: hex::encode(r.hash),
        invoice: r.invoice.clone(),
        amount: r.amount,
        fee: r.amount.saturating_sub(r.credits),
        connection: r.connection.map(hex::encode),
        description: r.description.clone(),
        preimage: None,
        failure: None,
        created_at: r.created_at,
        settled_at: r.settled_at.filter(|_| r.state == State::Settled),
    }
}

/// Paying out of accounts.
impl<T: Transport> Bridge<T> {
    /// Pay `invoice` out of `key`'s account, for at most `max_fee` msat on
    /// top if given, waiting for it up to [`PAY_WAIT`].
    pub async fn withdraw(
        &self,
        key: &[u8; 32],
        w: &bridge::Withdraw,
    ) -> Result<bridge::Payment, Error> {
        let account = self.account_id(key)?;
        let paid = self.pay(account, None, &w.invoice, w.max_fee).await?;
        let paid = self.wait(paid).await?;
        Ok(bridge::Payment {
            state: paid.state,
            hash: hex::encode(paid.hash),
            amount: paid.amount,
            fee: paid.fee(),
            preimage: paid.preimage.map(hex::encode),
            failure: paid.failure,
        })
    }

    /// Follow `payment` until it is decided or [`PAY_WAIT`] passed.
    pub(crate) async fn wait(&self, mut payment: Payment) -> Result<Payment, Error> {
        let started = tokio::time::Instant::now();
        while payment.state == State::Pending && started.elapsed() < PAY_WAIT {
            tokio::time::sleep(Duration::from_secs(1)).await;
            payment = self.follow_payment(&payment.hash).await?;
        }
        Ok(payment)
    }

    fn turn(&self, hash: [u8; 32]) -> Result<Turn<'_>, Error> {
        let mut paying = self.paying.lock().unwrap_or_else(PoisonError::into_inner);
        if !paying.insert(hash) {
            return Err(Error::Pending("this invoice is being paid now".into()));
        }
        Ok(Turn {
            paying: &self.paying,
            hash,
        })
    }

    /// Pay `request` out of account `id`, over the connection `link` if
    /// any, within its limits, for at most `max_fee` msat on top if given:
    /// where the payment stands once the hub was asked to make it. The same
    /// invoice again answers the same payment, or tries again a failed one.
    pub(crate) async fn pay(
        &self,
        id: i64,
        link: Option<&Link>,
        request: &str,
        max_fee: Option<u64>,
    ) -> Result<Payment, Error> {
        self.not_frozen()?;
        if let Some(link) = link {
            if !link.pay {
                return Err(Error::Restricted("this connection only receives".into()));
            }
        }
        let invoice = decode(request)?;
        let amount = invoice
            .amount_milli_satoshis()
            .filter(|msat| *msat > 0)
            .ok_or_else(|| Error::Invalid("an invoice of no amount".into()))?;
        if invoice.is_expired() {
            return Err(Error::Invalid("an expired invoice".into()));
        }
        if self.config.max_payment.is_some_and(|max| amount > max) {
            return Err(Error::Quota(format!(
                "the bridge pays {} msat at most at once",
                self.config.max_payment.unwrap_or_default()
            )));
        }
        let hash: [u8; 32] = *invoice.payment_hash().as_ref();
        let turn = self.turn(hash)?;
        if let Some(earlier) = self.store.read(|c| store::payment(c, &hash))? {
            if earlier.account != id {
                return Err(Error::Restricted("an invoice another account pays".into()));
            }
            match earlier.state {
                State::Failed => {}
                _ => {
                    drop(turn);
                    return self.follow_payment(&hash).await;
                }
            }
        }
        // Before its fee is quoted: the wallet may hold too little to quote.
        if self.balance_of(id)? < amount {
            return Err(Error::Insufficient(format!("{amount} msat asked")));
        }
        let hub = &self.config.hub;
        let via = self.via()?;
        // Its fee and the hub's on the lock to it, in all.
        let quote = (self.wallet.invoice_quote_via(via, hub, request, u64::MAX)).await;
        let quote = quote.map_err(wallet_error)?;
        let (fee, provider_fee) = (quote.costs(), quote.fee);
        if max_fee.is_some_and(|max| fee.saturating_mul(1000) > max) {
            return Err(Error::Quota(format!(
                "it costs {fee} sat on top, more than allowed"
            )));
        }
        let reserve = amount
            .div_ceil(1000)
            .checked_add(fee)
            .and_then(|sat| sat.checked_mul(1000))
            .ok_or_else(|| Error::Invalid("an amount out of range".into()))?;
        let at = now();
        let payment = self.store.write(|tx| {
            // Here too: frozen meanwhile, its notes may be exported.
            if store::meta(tx)?.frozen_at.is_some() {
                return Err(Error::Frozen);
            }
            if let Some(link) = link {
                let link = store::link(tx, &link.key)?
                    .filter(|l| l.live(at))
                    .ok_or_else(|| {
                        Error::Unauthorized("no such connection, or no longer".into())
                    })?;
                if link.max_payment.is_some_and(|max| reserve > max) {
                    return Err(Error::Quota(format!(
                        "{reserve} msat with fees, more than this connection pays at once"
                    )));
                }
                if let Some(budget) = link.budget {
                    let spent = store::spent(tx, &link.key, link.period_start(at))?;
                    if spent.saturating_add(reserve) > budget.amount {
                        return Err(Error::Quota(format!(
                            "{reserve} msat with fees, beyond this connection's budget: \
                             {spent} of {} spent",
                            budget.amount
                        )));
                    }
                }
            }
            store::credit(tx, id, -store::sql(reserve)?)?;
            let earlier = store::payment(tx, &hash)?;
            let payment = Payment {
                hash,
                account: id,
                connection: link.map(|l| l.key),
                invoice: request.trim().to_owned(),
                amount,
                reserved: reserve,
                state: State::Pending,
                preimage: None,
                failure: None,
                started_at: at,
                created_at: earlier.map_or(at, |e| e.created_at),
                settled_at: None,
            };
            store::put_payment(tx, &payment)?;
            Ok(payment)
        })?;
        tracing::info!(hash = %hex::encode(hash), amount, reserve, "paying");
        let paid = (self.wallet)
            .pay_invoice_via_within(via, hub, request, provider_fee, Some(fee))
            .await;
        self.conclude(&payment, paid)
    }

    /// The newest lock of the wallet's for `payment`'s latest attempt.
    fn lock_for(&self, payment: &Payment) -> Result<Option<Lock>, Error> {
        let locks = self.wallet.locks().map_err(wallet_error)?;
        Ok(locks.into_iter().find(|lock| {
            // Paying its invoice through the hub, or through a provider.
            lock.hash == payment.hash
                && (lock.invoice.is_some() || lock.via.is_some())
                && lock.created_at >= payment.started_at
        }))
    }

    /// Decide `payment` by what paying it came to: its lock paid or
    /// refunded, or no lock made.
    fn conclude(
        &self,
        payment: &Payment,
        paid: Result<Lock, licash_wallet::Error>,
    ) -> Result<Payment, Error> {
        let lock = match paid {
            Ok(lock) => Some(lock),
            Err(e) => match self.lock_for(payment)? {
                Some(lock) => Some(lock),
                None => {
                    let failure = wallet_error(e).to_string();
                    tracing::info!(hash = %hex::encode(payment.hash), %failure, "payment refused");
                    self.store.write(|tx| {
                        store::decide_payment(
                            tx,
                            &payment.hash,
                            State::Failed,
                            0,
                            None,
                            Some(&failure),
                        )
                    })?;
                    return self.payment(&payment.hash);
                }
            },
        };
        if let Some(lock) = lock {
            self.decide_by(payment, &lock)?;
        }
        self.payment(&payment.hash)
    }

    fn decide_by(&self, payment: &Payment, lock: &Lock) -> Result<(), Error> {
        let cost = |lock: &Lock| {
            lock.cost
                .unwrap_or(lock.amount + lock.fee)
                .saturating_mul(1000)
        };
        let hash = &payment.hash;
        let decided = match &lock.state {
            LockState::Paid(preimage) => self.store.write(|tx| {
                store::decide_payment(tx, hash, State::Settled, cost(lock), Some(*preimage), None)
            })?,
            LockState::Refunded | LockState::Abandoned(_) => {
                let failure = lock.failure.clone().unwrap_or_else(|| "not paid".into());
                let charged = lock.cost.unwrap_or(0).saturating_mul(1000);
                self.store.write(|tx| {
                    store::decide_payment(tx, hash, State::Failed, charged, None, Some(&failure))
                })?
            }
            _ => false,
        };
        if decided {
            tracing::info!(hash = %hex::encode(hash), state = ?lock.state, "payment decided");
        }
        Ok(())
    }

    fn payment(&self, hash: &[u8; 32]) -> Result<Payment, Error> {
        self.store
            .read(|c| store::payment(c, hash))?
            .ok_or_else(|| Error::NotFound("no such payment".into()))
    }

    /// Take the payment of `hash` on, unless it is being made now: follow
    /// its lock, or give it back if none was ever made.
    pub(crate) async fn follow_payment(&self, hash: &[u8; 32]) -> Result<Payment, Error> {
        let payment = self.payment(hash)?;
        if payment.state != State::Pending {
            return Ok(payment);
        }
        let Ok(_turn) = self.turn(*hash) else {
            return Ok(payment);
        };
        let payment = self.payment(hash)?;
        if payment.state != State::Pending {
            return Ok(payment);
        }
        match self.lock_for(&payment)? {
            Some(lock) => {
                let followed = self.wallet.follow_lock(&lock.id).await;
                let lock = match followed {
                    Ok(lock) => lock,
                    Err(e) => {
                        tracing::debug!(hash = %hex::encode(hash), "following a payment: {e}");
                        lock
                    }
                };
                self.decide_by(&payment, &lock)?;
                self.payment(hash)
            }
            // Recorded, then stopped before the wallet made a lock: no
            // one else makes it.
            None => self.conclude(
                &payment,
                Err(licash_wallet::Error::Invalid(
                    "stopped before it was sent".into(),
                )),
            ),
        }
    }
}

/// Getting paid into accounts.
impl<T: Transport> Bridge<T> {
    /// An invoice of `amount` msat crediting `key`'s account once paid,
    /// less its provider's fee on receiving.
    pub async fn top_up(&self, key: &[u8; 32], amount: u64) -> Result<bridge::Invoice, Error> {
        let account = self.account_id(key)?;
        let receipt = self
            .receive(account, None, amount, Some("Top-up"), None, None)
            .await?;
        Ok(bridge::Invoice {
            invoice: receipt.invoice,
            hash: hex::encode(receipt.hash),
            amount: receipt.amount,
            credits: receipt.credits,
            expires_at: receipt.expires_at,
        })
    }

    /// An invoice asking exactly `amount` msat that credits account `id`,
    /// over `link` if any, once paid. It says `description`, or commits to
    /// its hash if it cannot be a memo, or to `description_hash` if given;
    /// `zap` is the Nostr zap request it pays, if any.
    pub(crate) async fn receive(
        &self,
        id: i64,
        link: Option<&Link>,
        amount: u64,
        description: Option<&str>,
        description_hash: Option<[u8; 32]>,
        zap: Option<String>,
    ) -> Result<Receipt, Error> {
        self.not_frozen()?;
        if let Some(link) = link {
            if !link.receive {
                return Err(Error::Restricted("this connection only pays".into()));
            }
        }
        let invoicing = self.admit_credit(id, amount)?;
        let memo = description
            .filter(|_| description_hash.is_none())
            .filter(|d| licash_api::memo(d).is_ok_and(|memo| memo == *d));
        let committed = match (description_hash, description) {
            (Some(hash), _) => Some(hash),
            (None, Some(d)) if memo.is_none() => Some(sha256(d.as_bytes())),
            _ => None,
        };
        let hub = &self.config.hub;
        self.ask_provider().await?;
        let via = self.receiving()?.via;
        let asked = (self.wallet)
            .invoice_exact_through(&via, hub, amount, memo, committed)
            .await
            .map_err(wallet_error)?;
        let request = asked
            .request
            .ok_or_else(|| Error::Unavailable("its provider made no invoice yet".into()))?;
        let invoice = decode(&request)?;
        let created = invoice.duration_since_epoch().as_secs() as i64;
        let receipt = Receipt {
            hash: *invoice.payment_hash().as_ref(),
            account: id,
            connection: link.map(|l| l.key),
            invoice: request,
            amount,
            credits: asked.amount.saturating_mul(1000),
            description: description.map(str::to_owned),
            description_hash: committed,
            zap,
            state: State::Pending,
            created_at: now(),
            expires_at: created + invoice.expiry_time().as_secs() as i64,
            settled_at: None,
        };
        let record = || self.store.write(|tx| store::insert_receipt(tx, &receipt));
        match invoicing {
            Some(invoicing) => invoicing.record(record)?,
            None => record()?,
        }
        tracing::info!(hash = %hex::encode(receipt.hash), amount, "invoice made");
        Ok(receipt)
    }

    /// Admit an invoice of `amount` msat more to account `id` within the
    /// bridge's cap, if it has one: what the account holds, what its open
    /// invoices and those being made would credit it, and what its payments
    /// under way may return to it, `amount` with them, at most
    /// `max_balance`. Counted as being made until recorded or given up.
    fn admit_credit(&self, id: i64, amount: u64) -> Result<Option<Invoicing<'_>>, Error> {
        let Some(max) = self.config.max_balance else {
            return Ok(None);
        };
        let mut invoicing = self
            .invoicing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let held = self.store.read(|c| {
            let balance = store::account(c, id)?.balance;
            let incoming = store::incoming(c, id)?;
            let outgoing = store::outgoing(c, id)?;
            Ok(balance.saturating_add(incoming).saturating_add(outgoing))
        })?;
        let making = invoicing.get(&id).copied().unwrap_or(0);
        if held.saturating_add(making).saturating_add(amount) > max {
            return Err(Error::Quota(format!("an account holds {max} msat at most")));
        }
        let counted = invoicing.entry(id).or_default();
        *counted = counted.saturating_add(amount);
        Ok(Some(Invoicing {
            of: &self.invoicing,
            id,
            amount,
        }))
    }

    /// Take the invoice of `hash` on: claim its payment, crediting its
    /// account, once paid. Where it stands.
    pub(crate) async fn follow_receipt(&self, hash: &[u8; 32]) -> Result<Receipt, Error> {
        let followed = self.wallet.follow_invoice(&hex::encode(hash)).await;
        match followed {
            Ok(invoice) => {
                let settled = match invoice.state {
                    InvoiceState::Received => Some(Some(invoice.amount.saturating_mul(1000))),
                    InvoiceState::Canceled(_) => Some(None),
                    _ => None,
                };
                if let Some(settled) = settled {
                    if self
                        .store
                        .write(|tx| store::decide_receipt(tx, hash, settled))?
                    {
                        tracing::info!(hash = %hex::encode(hash), ?settled, "invoice decided");
                    }
                }
            }
            Err(e) => tracing::debug!(hash = %hex::encode(hash), "following an invoice: {e}"),
        }
        self.store
            .read(|c| store::receipt(c, hash))?
            .ok_or_else(|| Error::NotFound("no such invoice".into()))
    }

    /// Take every payment and invoice under way on: what was decided.
    pub async fn round(&self) -> Result<usize, Error> {
        self.ask_provider().await?;
        let (payments, receipts, payouts) = self.store.read(|c| {
            let payments = store::pending_payments(c)?;
            Ok((payments, store::pending_receipts(c)?, notes::pending(c)?))
        })?;
        let mut decided = 0;
        for send in payouts {
            match self.follow_payout(&send).await {
                Ok(p) if p.state != State::Pending => decided += 1,
                Ok(_) => {}
                Err(e) => tracing::warn!(send = %hex::encode(send), "a payout: {e}"),
            }
        }
        for payment in payments {
            match self.follow_payment(&payment.hash).await {
                Ok(p) if p.state != State::Pending => decided += 1,
                Ok(_) => {}
                Err(e) => tracing::warn!(hash = %hex::encode(payment.hash), "a payment: {e}"),
            }
        }
        let mut received = false;
        for receipt in receipts {
            match self.follow_receipt(&receipt.hash).await {
                Ok(r) if r.state != State::Pending => {
                    decided += 1;
                    received |= r.state == State::Settled;
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(hash = %hex::encode(receipt.hash), "an invoice: {e}"),
            }
        }
        if received {
            self.unlink_received().await;
        }
        Ok(decided)
    }
}

/// Runs [`Bridge::round`] every `every`, for good.
pub async fn rounds<T: Transport>(bridge: Arc<Bridge<T>>, every: Duration) {
    loop {
        if let Err(e) = bridge.round().await {
            tracing::warn!("a round: {e}");
        }
        tokio::time::sleep(every).await;
    }
}
