//! [`Wallet`]: the SDK's wallet as the apps use it.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{atomic::AtomicU32, Arc, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use bitcoin::{FeeRate, OutPoint};
use licash_nostr::{
    wallet::{hub_relays, hubs_announced, hubs_found, plans_with, Announcements},
    Route,
};
use licash_transport::Http;
use licash_wallet::{in_lane, DepositState, Lane, PartTo, PaymentCode, PaymentNote, Unlinking};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    chain::Chain, Activity, Balance, ChainError, ChainSource, Code, ContractTerms, Details,
    FoundHub, Holding, Hub, HubsFound, InvoiceQuote, Kind, LicashError, LightningInvoice, Linking,
    Network, NoteLine, Notes, NotesOf, NotesPaid, Onchain, Paid, PaidTo, PayOffer, PayQuote, Range,
    Rate, Scan, Scanned, State, TorClient,
};

/// The rate deposits are paid at, in sat/vB: above what nodes relay.
const DEPOSIT_RATE: u64 = 2;

/// The blocks a scan looks in at most, to report progress between.
const SCAN_BATCH: u32 = 144;

/// A day, in seconds.
const DAY: i64 = 86_400;

mod autobackup;
mod backup;
mod bridges;
mod codes;
mod cold;
mod contacts;
mod contracts;
mod donations;
mod exits;
mod fees;
mod moves;
mod payouts;
mod recoveries;
mod refunds;
mod safety;
mod samples;
mod shaping;
mod stats;
mod vias;

pub use bridges::{
    AppTerms, Bridge, BridgeAccount, BridgeApp, BridgeLine, BridgeTopUp, BudgetPeriod,
    ConnectedApp, ExportedNotes, ImportSource, ImportedNotes, TopUpRules,
};
pub use contacts::Contact;
pub use samples::BalanceSample;
pub use stats::{BalancePoint, Flow, HubAmount, StatEvent, Stats, Unlink, Way};

/// The tweaks of the next blocks to look in for payments on Bitcoin,
/// fetched ahead of a scan ([`Wallet::tweaks`]).
#[derive(uniffi::Object)]
pub struct Tweaks(licash_wallet::SilentTweaks);

/// A wallet, kept in a directory of its own.
#[derive(uniffi::Object)]
pub struct Wallet {
    runtime: tokio::runtime::Runtime,
    wallet: licash_wallet::Wallet<Http>,
    route: Route,
    /// The app's Tor client, kept alive while the wallet uses it: none
    /// unless over Tor.
    tor: Option<Arc<TorClient>>,
    dir: PathBuf,
    /// Held while paying and finishing what is under way: the payments to
    /// send to mailboxes change only under it.
    delivering: Mutex<()>,
    /// The plan of the last [`Wallet::pay_quote`], for [`Wallet::pay`]:
    /// for the code, by its text, and the amount it pays.
    planned: Mutex<Option<(String, licash_nostr::wallet::Plan)>>,
    /// The chain's height as last seen: 0 until seen.
    tip: AtomicU32,
    /// Held while opening contracts or carrying them on: one driver to
    /// each.
    contracting: Mutex<()>,
    /// Held while moving notes between hubs: an attempt finds the swap it
    /// recorded as the one new since it began, which another would spoil.
    moving: Mutex<()>,
    /// The times the blocks of the coins found claim, by height, as the
    /// light client told them: learned on each scan, kept in memory only.
    times: Mutex<HashMap<u32, i64>>,
    /// When the hubs were last asked what URLs they name
    /// ([`Wallet::ask_onions`]): never since it opened if none.
    onions_asked: Mutex<Option<Instant>>,
    /// The swap providers announced, as last looked for
    /// ([`Wallet::refresh_providers`]): quotes ask them without looking.
    announced: Announcements,
    /// The height each deposit to refund whose payment its hub never saw
    /// was last looked for at, by its hash: in memory only.
    refunds_looked: Mutex<HashMap<String, u32>>,
    /// The mailbox, its relays kept connected between looks
    /// ([`Wallet::collect`]): opened at the first.
    mailbox: Mutex<Option<licash_nostr::mailbox::Mailbox>>,
    /// Held while changing what the app keeps ([`Wallet::update_kept`]).
    keeping: Mutex<()>,
    /// The donation address last offered, for the app to keep once shown
    /// ([`Wallet::keep_donation_address`]): by its LNURL.
    offered: Mutex<Option<(String, donations::Pinned)>>,
    /// The Lightning Addresses of donations registered since opened
    /// ([`Wallet::keep_donation_address`]): each once.
    named: Mutex<std::collections::HashSet<String>>,
}

/// How long the hubs asked what URLs they name may take, all at once
/// ([`Wallet::ask_onions`]).
const ASK_URLS: Duration = Duration::from_secs(30);

/// How often the hubs are asked what URLs they name, at most
/// ([`Wallet::ask_onions`]).
const ASK_URLS_EVERY: Duration = Duration::from_secs(6 * 3600);

/// What the app keeps of a wallet besides the SDK's file.
#[derive(Default, Serialize, Deserialize)]
struct Kept {
    /// The chain's height when the wallet was made: none of its payments
    /// on Bitcoin can be older. Unknown (0), from the blocks of the day
    /// before its file was made.
    #[serde(default)]
    birthday: u32,
    /// The provider of the donation address shown, kept while it takes
    /// donations ([`donations::Pinned`]). One unreadable is none: it never
    /// costs the rest.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "donations::lenient"
    )]
    donations: Option<donations::Pinned>,
}

fn holding(b: licash_wallet::Balance) -> Holding {
    Holding {
        hub: b.hub,
        available: b.available,
        pending: b.pending,
    }
}

fn wallet_file(dir: &Path) -> PathBuf {
    dir.join("wallet.sqlite")
}

fn kept_file(dir: &Path) -> PathBuf {
    dir.join("app.json")
}

/// Whether `dir` holds a wallet.
#[uniffi::export]
pub fn wallet_exists(dir: String) -> bool {
    wallet_file(Path::new(&dir)).exists()
}

#[uniffi::export]
impl Wallet {
    /// A new wallet of `network` in `dir`, which holds none, made at the
    /// chain's height `birthday` (0 if unknown), reaching hubs and relays
    /// through `tor` if any.
    #[uniffi::constructor]
    pub fn create(
        dir: String,
        network: Network,
        birthday: u32,
        tor: Option<Arc<TorClient>>,
    ) -> Result<Arc<Self>, LicashError> {
        let dir = PathBuf::from(dir);
        if wallet_exists(dir.display().to_string()) {
            return Err(LicashError::invalid("a wallet is there already"));
        }
        std::fs::create_dir_all(&dir).map_err(LicashError::failed)?;
        let kept = Kept {
            birthday,
            ..Kept::default()
        };
        let kept = serde_json::to_vec(&kept).map_err(LicashError::failed)?;
        std::fs::write(kept_file(&dir), kept).map_err(LicashError::failed)?;
        let mut seed = [0; 32];
        OsRng.fill_bytes(&mut seed);
        Self::start(dir, tor, |path, http| {
            licash_wallet::Wallet::create(path, &seed, network.profile(), http)
        })
    }

    /// The wallet in `dir`, reaching hubs and relays through `tor` if any.
    #[uniffi::constructor]
    pub fn open(dir: String, tor: Option<Arc<TorClient>>) -> Result<Arc<Self>, LicashError> {
        Self::start(PathBuf::from(dir), tor, licash_wallet::Wallet::open)
    }

    pub fn network(&self) -> Network {
        Network::of(self.wallet.network())
    }

    /// Whether it reaches hubs and relays through Tor.
    pub fn tor(&self) -> bool {
        self.tor.is_some()
    }

    /// The chain's height when the wallet was made, or the first block it
    /// looks in for payments on Bitcoin: none of its coins is older. None
    /// until known: write it down with the recovery words, as restoring
    /// from them looks from there.
    pub fn birthday(&self) -> Option<u32> {
        Some(self.kept().birthday).filter(|b| *b > 0)
    }

    /// Renew notes a hub no longer unlinks since it restarted, paying them
    /// to the wallet itself, only if its fee on them is at most `ppm` parts
    /// per million of their value, or the hub charges at most 1 sat base,
    /// `ppm` millionths and 0.1 sat per output. Contract ceilings take
    /// precedence. 0 renews them only for free. 1000 until set, for as long
    /// as the wallet is open.
    pub fn set_renew_limit(&self, ppm: u32) {
        self.wallet.set_renew_limit(ppm);
    }

    /// The most it pays to renew notes ([`Wallet::set_renew_limit`]).
    pub fn renew_limit(&self) -> u32 {
        self.wallet.renew_limit()
    }
}

impl Wallet {
    /// The hubs the wallet's codes name, preferred first
    /// ([`licash_contracts::holder::code_hubs`]).
    pub(crate) fn code_hubs(&self) -> Result<Vec<String>, LicashError> {
        licash_contracts::holder::code_hubs(&self.wallet, self.wallet.path(), self.tip())
            .map_err(LicashError::failed)
    }

    /// The wallet's code, `amount` if given: in notes, else on Bitcoin if
    /// `onchain`.
    fn code(&self, amount: Option<u64>, onchain: bool) -> Result<Code, LicashError> {
        let mut code = match onchain {
            // Payers pay a silent payment address rather than the
            // fallback: only if a hub's tweaks find those payments.
            true => {
                let trusted = self.wallet.hubs()?;
                let tweaks = trusted.iter().any(|(_, info)| info.tweaks.is_some());
                self.wallet.onchain_code(tweaks)?
            }
            false => self.wallet.payment_code(&self.code_hubs()?)?,
        };
        code.amount = amount.filter(|a| *a > 0);
        Ok(Code {
            text: code.to_string(),
            qr: code.qr(),
            address: code
                .address
                .as_ref()
                .map(|a| a.assume_checked_ref().to_string()),
            silent: code.silent.as_ref().map(|s| s.to_string()),
        })
    }

    fn start(
        dir: PathBuf,
        tor: Option<Arc<TorClient>>,
        wallet: impl FnOnce(&Path, Http) -> Result<licash_wallet::Wallet<Http>, licash_wallet::Error>,
    ) -> Result<Arc<Self>, LicashError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(LicashError::failed)?;
        let (http, route) = match &tor {
            Some(client) => (Http::tor(client.tor()), Route::Tor(client.tor())),
            None => (Http::new(None).map_err(LicashError::failed)?, Route::Direct),
        };
        let wallet = wallet(&wallet_file(&dir), http)?;
        // Quotes read the providers' terms as last asked, by
        // `warm_providers` ahead of them: at once, asking nothing.
        wallet.keep_terms(licash_wallet::TERMS_FRESH);
        let wallet = Self {
            runtime,
            wallet,
            route,
            tor,
            dir,
            delivering: Mutex::new(()),
            planned: Mutex::new(None),
            tip: AtomicU32::new(0),
            contracting: Mutex::new(()),
            moving: Mutex::new(()),
            times: Mutex::new(HashMap::new()),
            onions_asked: Mutex::new(None),
            announced: Announcements::default(),
            refunds_looked: Mutex::new(HashMap::new()),
            mailbox: Mutex::new(None),
            keeping: Mutex::new(()),
            offered: Mutex::new(None),
            named: Mutex::default(),
        };
        wallet.onions();
        wallet.agree_fees();
        Ok(Arc::new(wallet))
    }

    /// Reach each hub trusted at the onion service it names as its own, if
    /// any, while over Tor: its own URL is asked if that one does not open.
    /// Of hubs only visited, or announced by others, none.
    fn onions(&self) {
        if self.tor.is_none() {
            return;
        }
        let hubs = match self.wallet.hubs() {
            Ok(hubs) => hubs,
            Err(e) => return tracing::warn!("reading the hubs for their onion services: {e}"),
        };
        let http = self.wallet.transport();
        for (url, info) in hubs {
            // The first it names that is taken. Naming none, it may not have
            // been asked since it named them: as it was.
            let onion = info
                .urls
                .iter()
                .find(|onion| http.set_onion(&url, Some(onion)));
            match onion {
                Some(onion) => tracing::debug!(%url, %onion, "reached at its onion service"),
                None if !info.urls.is_empty() => {
                    http.set_onion(&url, None);
                }
                None => {}
            }
        }
    }

    /// Over Tor, once open and every [`ASK_URLS_EVERY`] after at most:
    /// learn again what each hub trusted at an `https://` URL says of
    /// itself, for [`Wallet::onions`]. Its info kept may name no URLs, kept
    /// by earlier versions or before it named any, or others than it names
    /// now. All at once, in [`ASK_URLS`] at most: those not answering are
    /// asked again only next time.
    fn ask_onions(&self) {
        if self.tor.is_none() {
            return;
        }
        {
            let mut asked = self
                .onions_asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if asked.is_some_and(|at| now.saturating_duration_since(at) < ASK_URLS_EVERY) {
                return;
            }
            *asked = Some(now);
        }
        let hubs = self.wallet.hubs().unwrap_or_default();
        let asks = hubs
            .iter()
            .filter(|(url, _)| url.starts_with("https://") && !licash_nostr::onion(url))
            .map(|(url, _)| async move {
                if let Err(e) = self.wallet.add_hub(url).await {
                    tracing::info!(%url, "asking the hub what URLs it names: {e}");
                }
            });
        // Its timer made within the runtime: not on the caller's thread.
        let asked =
            async { tokio::time::timeout(ASK_URLS, futures_util::future::join_all(asks)).await };
        if self.runtime.block_on(asked).is_err() {
            tracing::info!("asking the hubs what URLs they name: not all answered in time");
        }
        self.onions();
    }

    /// Change what the app keeps by `change`, kept whole or not at all,
    /// one change at a time.
    fn update_kept(&self, change: impl FnOnce(&mut Kept)) -> Result<(), LicashError> {
        let _keeping = self.keeping.lock().unwrap_or_else(PoisonError::into_inner);
        let mut kept = self.kept();
        change(&mut kept);
        self.keep(&kept)
    }

    /// Keep `kept`, whole or not at all.
    fn keep(&self, kept: &Kept) -> Result<(), LicashError> {
        let bytes = serde_json::to_vec(kept).map_err(LicashError::failed)?;
        let new = self.dir.join("app.json.new");
        std::fs::write(&new, bytes).map_err(LicashError::failed)?;
        std::fs::rename(&new, kept_file(&self.dir)).map_err(LicashError::failed)
    }

    fn kept(&self) -> Kept {
        // Absent or unreadable, nothing is known: the conservative default.
        std::fs::read(kept_file(&self.dir))
            .ok()
            .and_then(|kept| serde_json::from_slice(&kept).ok())
            .unwrap_or_default()
    }
}

/// Hubs, and what the wallet holds.
#[uniffi::export]
impl Wallet {
    /// Trust the hub at `url`: take its notes, and pay through it. A host
    /// alone is reached over HTTPS, or HTTP for an onion service.
    pub fn add_hub(&self, url: String) -> Result<Hub, LicashError> {
        let _timed = crate::log::timed("add_hub");
        let url = self.hub_url(&url)?;
        let url = url.as_str();
        let info = self.operation(self.wallet.add_hub(url))?;
        self.onions();
        // Its URL as the wallet keeps it.
        let mut kept = self.wallet.hubs()?.into_iter();
        let kept = kept
            .find(|(_, i)| i.address == info.address)
            .map(|(url, _)| url);
        Ok(hub(&kept.unwrap_or_else(|| url.to_owned()), &info))
    }

    /// What the hub at `url` says of itself now, nothing kept and the hub
    /// not trusted: to tell before adding it whether it has room for a
    /// contract ([`crate::contract_room`]), as it says this minute. Refused
    /// as [`Wallet::add_hub`] refuses it.
    pub fn hub_says(&self, url: String) -> Result<Hub, LicashError> {
        let _timed = crate::log::timed("hub_says");
        let url = self.hub_url(&url)?;
        let info = self.operation(self.wallet.hub_info(&url))?;
        Ok(hub(&url, &info))
    }

    /// [`Wallet::add_hub`] again, for what the hub at `url` serves now,
    /// as the app asks by itself: not while it did not answer lately
    /// ([`Wallet::hub_resting_ms`]), unavailable at once instead.
    pub fn relearn_hub(&self, url: String) -> Result<Hub, LicashError> {
        if let Some(ms) = self.hub_resting_ms(url.clone()) {
            return Err(LicashError::Unavailable {
                reason: format!(
                    "it did not answer lately, asked again in {} s",
                    ms.div_ceil(1000)
                ),
            });
        }
        self.add_hub(url)
    }

    /// How much longer, in ms, what runs by itself passes over the hub at
    /// `url`, since it did not answer: none if it answered.
    pub fn hub_resting_ms(&self, url: String) -> Option<u64> {
        let rest = self.wallet.transport().resting(&url)?;
        Some(u64::try_from(rest.as_millis()).unwrap_or(u64::MAX))
    }

    /// How fast the hub at `url` answers, in ms: its fastest answer of the
    /// last minutes, a round trip on a circuit already open. None if it
    /// answered none lately.
    pub fn hub_answers_ms(&self, url: String) -> Option<u64> {
        let took = self.wallet.transport().answers_in(&url)?;
        Some(u64::try_from(took.as_millis()).unwrap_or(u64::MAX))
    }

    /// The hubs trusted, by URL.
    pub fn hubs(&self) -> Result<Vec<Hub>, LicashError> {
        let hubs = self.wallet.hubs()?;
        Ok(hubs.iter().map(|(url, info)| hub(url, info)).collect())
    }

    /// The hubs announced on Nostr, on the relays the hubs trusted name,
    /// that the wallet does not use, with what each says of itself: to add
    /// one without typing its URL. Each is at a URL that answered as the
    /// key announcing it.
    pub fn discover_hubs(&self) -> Result<Vec<FoundHub>, LicashError> {
        let _timed = crate::log::timed("discover_hubs");
        let relays = hub_relays(&self.wallet)?;
        if relays.is_empty() {
            return Err(LicashError::invalid(
                "no hub you use names relays to find other hubs on",
            ));
        }
        let found = hubs_announced(&self.wallet, &relays, &self.route);
        let found = self
            .runtime
            .block_on(found)
            .map_err(|e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason }))?;
        Ok(found
            .iter()
            .map(|h| FoundHub {
                name: h.name.clone(),
                hub: hub(&h.url, &h.info),
            })
            .collect())
    }

    /// Look for the swap providers announced on the relays the hubs
    /// trusted name, and keep them for a while, in memory: a quote then
    /// asks them without waiting on the relays (the providers themselves
    /// are still asked). How many were found: none if no hub names relays.
    /// The app calls it out of sight, every so often.
    pub fn refresh_providers(&self) -> Result<u32, LicashError> {
        let relays = hub_relays(&self.wallet)?;
        if relays.is_empty() {
            return Ok(0);
        }
        let started = Instant::now();
        let network = self.wallet.network().name();
        let found = self.announced.refresh(&relays, &self.route, network);
        let found = self
            .runtime
            .block_on(found)
            .map_err(|e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason }))?;
        tracing::info!(found, took = ?started.elapsed(), "swap providers looked for");
        Ok(u32::try_from(found).unwrap_or(u32::MAX))
    }

    /// Ask each swap provider kept ([`Wallet::refresh_providers`]) what it
    /// says of itself, waiting on each: the next quote then finds their
    /// connections open, kept a few minutes, rather than opening circuits
    /// to onion services for seconds as its owner waits. How many answered:
    /// none if none is kept. The app calls it out of sight, while in sight.
    pub fn warm_providers(&self) -> Result<u32, LicashError> {
        let relays = hub_relays(&self.wallet)?;
        if relays.is_empty() {
            return Ok(0);
        }
        let started = Instant::now();
        let warm = self.announced.warm(&self.wallet, &relays);
        let answered = self.runtime.block_on(warm)?;
        tracing::info!(answered, took = ?started.elapsed(), "swap providers asked ahead");
        Ok(u32::try_from(answered).unwrap_or(u32::MAX))
    }

    /// [`Wallet::discover_hubs`], on `relays` as well as on those the hubs
    /// trusted name, such as [`crate::default_relays`]: a wallet using no
    /// hub yet finds some. Told also how many more were announced that did
    /// not answer.
    pub fn find_hubs(&self, relays: Vec<String>) -> Result<HubsFound, LicashError> {
        let _timed = crate::log::timed("find_hubs");
        let mut asked = hub_relays(&self.wallet)?;
        for relay in relays {
            let relay = relay.trim().to_owned();
            if !relay.is_empty() && !asked.contains(&relay) {
                asked.push(relay);
            }
        }
        if asked.is_empty() {
            return Err(LicashError::invalid("no relays to find hubs on"));
        }
        let found = hubs_found(&self.wallet, &asked, &self.route);
        let found = self
            .runtime
            .block_on(found)
            .map_err(|e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason }))?;
        let onion_only = |f: &&licash_nostr::Found| {
            let urls = &f.announcement.urls;
            !urls.is_empty() && urls.iter().all(|u| licash_nostr::onion(u))
        };
        Ok(HubsFound {
            hubs: found
                .hubs
                .iter()
                .map(|h| FoundHub {
                    name: h.name.clone(),
                    hub: hub(&h.url, &h.info),
                })
                .collect(),
            silent: found.silent.len() as u32,
            silent_onion: found.silent.iter().filter(onion_only).count() as u32,
        })
    }

    pub fn balance(&self) -> Result<Balance, LicashError> {
        let mut balance = Balance::default();
        let held = self.wallet.balance()?;
        for at in &held {
            balance.notes += at.available;
            balance.notes_pending += at.pending;
        }
        let mut reserved = Vec::new();
        let aside = self.set_aside()?;
        let mut kept_aside = 0;
        for coin in self.wallet.silent_coins()? {
            match coin.spending {
                // Held for a challenge's fee: on Bitcoin, kept, not moving.
                Some(by) if aside.contains(&by) => {
                    balance.onchain += coin.value;
                    kept_aside += coin.value;
                }
                Some(by) => {
                    balance.moving += coin.value;
                    reserved.push((by, coin.value));
                }
                None => balance.onchain += coin.value,
            }
        }
        balance.moving += self.confirmed_moves(&reserved)?;
        balance.kept = self.kept_coins()?.iter().map(|(_, value)| value).sum();
        balance.kept += kept_aside;
        self.contracted(&mut balance, &held, &reserved)?;
        Ok(balance)
    }

    /// An address on Bitcoin of this wallet's, to cash notes out to: what
    /// the wallet's own payouts pay there stays on Bitcoin, unless moved
    /// into Licash with [`Wallet::move_largest_to_licash`].
    pub fn bitcoin_address(&self) -> Result<String, LicashError> {
        Ok(self.wallet.fallback_address()?.to_string())
    }

    /// The code to be paid at in notes, `amount` if given, at the few hubs
    /// it prefers of those trusted. Nothing on Bitcoin: that is
    /// [`Wallet::bitcoin_code`].
    pub fn payment_code(&self, amount: Option<u64>) -> Result<Code, LicashError> {
        self.code(amount, false)
    }

    /// The code to be paid at on Bitcoin, `amount` if given: an address
    /// any wallet pays, handed out and watched from then on, the next once
    /// it is paid, and the wallet's silent payment address while a hub's
    /// tweaks find payments to it.
    pub fn bitcoin_code(&self, amount: Option<u64>) -> Result<Code, LicashError> {
        self.code(amount, true)
    }

    /// The wallet's silent payment address alone, for wallets paying
    /// those only: found paid while a hub's tweaks find payments to it.
    pub fn silent_address(&self) -> String {
        self.wallet.silent_keys().address().to_string()
    }

    /// What `text`, scanned or pasted, is: a code to pay in notes if it
    /// can be, else a Lightning invoice if it is or names one, else an
    /// address on Bitcoin to pay out to if it is or names one.
    pub fn scanned(&self, text: String) -> Result<Scanned, LicashError> {
        let text = text.trim();
        let code = text.parse::<PaymentCode>();
        if let Ok(code) = &code {
            code.check(self.wallet.network())?;
            let hubs = self.wallet.hubs()?;
            let mut trusted = hubs
                .iter()
                .map(|(_, i)| licash_wallet::HubId::of(&i.address));
            let notes = code
                .licash
                .as_ref()
                .is_some_and(|licash| trusted.any(|id| licash.hubs.contains(&id)));
            if notes {
                return Ok(Scanned::Code {
                    amount: code.amount,
                    notes,
                });
            }
        }
        match self.wallet.read_invoice(text) {
            Ok(invoice) => {
                return Ok(Scanned::Invoice {
                    amount: invoice.amount,
                    description: invoice.description,
                })
            }
            // An invoice this wallet cannot pay: say why.
            Err(e) if code.is_err() && licash_wallet::Payable::read(text).is_ok() => {
                return Err(e.into())
            }
            Err(_) => {}
        }
        if let Ok(code) = code {
            // Its hubs not trusted, reached where it says, proving who
            // they are.
            if code
                .licash
                .as_ref()
                .is_some_and(|l| !l.locations.is_empty())
            {
                return Ok(Scanned::Visit {
                    amount: code.amount,
                });
            }
            // Its silent payment address first: paid out to as any, of
            // an output no one else learns is its.
            let silent = code.silent.map(|s| s.to_string());
            let address = code
                .address
                .as_ref()
                .map(|a| a.assume_checked_ref().to_string());
            if let Some(address) = silent.or(address) {
                return Ok(Scanned::Bitcoin {
                    address,
                    amount: code.amount,
                });
            }
            return Ok(Scanned::Code {
                amount: code.amount,
                notes: false,
            });
        }
        if serde_json::from_str::<licash_api::Payment>(text).is_ok() {
            return Ok(Scanned::Payment);
        }
        if let Some((_, payee)) = licash_wallet::lnurl_pay_target(text, self.wallet.network()) {
            return Ok(Scanned::Lnurl { payee });
        }
        Err(LicashError::invalid(
            "neither a Licash address, a Lightning invoice, a Lightning Address nor a payment",
        ))
    }

    /// What paying the Lightning invoice `text` costs the cheapest way,
    /// with the notes held now: through a swap provider
    /// ([`Wallet::invoice_offers`]).
    pub fn invoice_quote(&self, text: String) -> Result<InvoiceQuote, LicashError> {
        let _timed = crate::log::timed("invoice_quote");
        let offers = self.invoice_offers(text)?;
        let best = offers.into_iter().next();
        best.ok_or_else(|| LicashError::invalid(NO_PAYER))
    }

    /// Ask the swap provider announced that has the wallet paid over
    /// Lightning at a hub trusted for least for an invoice paying the
    /// wallet `amount` in notes, its fee on top for the payer. Followed by
    /// [`Wallet::follow_invoice`] while shown, and by [`Wallet::resume`]:
    /// its notes are taken once it is paid. Saying `memo` to its payer, if
    /// given: which the provider reads too.
    pub fn ask_invoice(
        &self,
        amount: u64,
        memo: Option<String>,
    ) -> Result<LightningInvoice, LicashError> {
        let _timed = crate::log::timed("ask_invoice");
        let memo = said(memo)?;
        match self.provider_invoice(amount, false, memo.as_deref())? {
            Some(asked) => self.invoice_now(asked),
            None => Err(LicashError::invalid(format!(
                "no swap provider takes {amount} sat over Lightning at a hub you trust now"
            ))),
        }
    }

    /// [`Wallet::ask_invoice`], for an invoice asking the payer `invoiced`,
    /// the provider's fee in it, as a shop asks a price: the wallet gets
    /// that less the fee. A sat short, rarely, where no amount and its fee
    /// rounded up come to it exactly.
    pub fn ask_invoice_for(
        &self,
        invoiced: u64,
        memo: Option<String>,
    ) -> Result<LightningInvoice, LicashError> {
        let _timed = crate::log::timed("ask_invoice_for");
        let memo = said(memo)?;
        match self.provider_invoice(invoiced, true, memo.as_deref())? {
            Some(asked) => self.invoice_now(asked),
            None => Err(LicashError::invalid(format!(
                "no swap provider takes an invoice of {invoiced} sat over Lightning at a hub \
                 you trust now"
            ))),
        }
    }

    /// Take on the invoice of `hash`, as [`Wallet::ask_invoice`] asked for
    /// it: have its hub make it, and take its notes once it is paid. Where
    /// it stands.
    pub fn follow_invoice(&self, hash: String) -> Result<LightningInvoice, LicashError> {
        let _timed = crate::log::timed("follow_invoice");
        // Each poll of one invoice on the same lane: no new circuit each.
        let lane = Lane::Of(licash::crypto::tagged_hash(
            "licash/mobile/invoice",
            &[hash.as_bytes()],
        ));
        let followed = self
            .runtime
            .block_on(in_lane(lane, self.wallet.follow_invoice(&hash)));
        self.invoice_now(followed)
    }

    /// What the wallet holds at each hub it trusts.
    pub fn holdings(&self) -> Result<Vec<Holding>, LicashError> {
        Ok(self.wallet.balance()?.into_iter().map(holding).collect())
    }

    /// What the wallet holds at hubs it only visited to pay a payee there,
    /// left over from a swap: none of its balance until the owner adds the
    /// hub ([`Wallet::add_hub`]). Hubs holding nothing are left out.
    pub fn visited(&self) -> Result<Vec<Holding>, LicashError> {
        let held = self.wallet.visited_balance()?.into_iter();
        let held = held.filter(|b| b.available > 0 || b.pending > 0);
        Ok(held.map(holding).collect())
    }

    /// How many notes of each denomination it can pay with, at each hub.
    pub fn notes(&self) -> Result<Vec<Notes>, LicashError> {
        let notes = self.wallet.notes()?.into_iter();
        Ok(notes
            .map(|n| Notes {
                hub: n.hub,
                denomination: n.denomination,
                count: n.count,
            })
            .collect())
    }

    /// What paying `amount`, or what it asks, to the payment code `code`
    /// costs at a hub it names that the wallet trusts and holds enough at:
    /// the fee [`Wallet::pay`] pays there as things stand. None if no such
    /// hub, a swap or a visit needed: [`Wallet::pay_quote`] tells, over
    /// the network. Asks nothing of the network.
    pub fn pay_fee(&self, code: String, amount: Option<u64>) -> Result<Option<u64>, LicashError> {
        let code: PaymentCode = code.trim().parse().map_err(LicashError::invalid)?;
        code.check(self.wallet.network())?;
        let (Some(licash), Some(amount)) = (&code.licash, amount.or(code.amount)) else {
            return Ok(None);
        };
        match self.wallet.hub_to_pay(licash, amount)? {
            Some(hub) => Ok(Some(self.wallet.send_fee(&hub, amount)?)),
            None => Ok(None),
        }
    }

    /// How paying `amount`, or what it asks, to the payment code `code` in
    /// notes goes, and all it costs: at a hub it names that the wallet
    /// trusts, else once a swap from another brings what it lacks there,
    /// else so at a hub the code says where to reach, visited, proving it
    /// is the one the code names. [`Wallet::pay`] pays it so.
    pub fn pay_quote(&self, code: String, amount: Option<u64>) -> Result<PayQuote, LicashError> {
        let _timed = crate::log::timed("pay_quote");
        let (text, mut plans) = self.plans(&code, amount)?;
        let plan = plans.remove(0);
        let quote = quoted(&plan);
        *self.planned.lock().unwrap_or_else(PoisonError::into_inner) = Some((text, plan));
        Ok(quote)
    }

    /// The ways [`Wallet::pay_quote`] chooses from of paying `code`: the
    /// one it picks first, then those through each other swap provider it
    /// could swap with instead. One, through no provider, when the wallet
    /// holds enough at a hub the code names.
    pub fn pay_offers(
        &self,
        code: String,
        amount: Option<u64>,
    ) -> Result<Vec<PayOffer>, LicashError> {
        let _timed = crate::log::timed("pay_offers");
        let (_, plans) = self.plans(&code, amount)?;
        Ok(plans
            .iter()
            .map(|plan| {
                let swap = plan.swap.as_ref();
                PayOffer {
                    provider: swap.map(|s| s.provider.url.clone()),
                    provider_name: swap.and_then(|s| s.provider.name.clone()),
                    known: swap.is_some_and(|s| s.provider.known),
                    quote: quoted(plan),
                }
            })
            .collect())
    }

    /// [`Wallet::pay_quote`], swapping through the provider at `provider`,
    /// one of [`Wallet::pay_offers`]: what [`Wallet::pay`] pays next.
    pub fn choose_pay_offer(
        &self,
        code: String,
        amount: Option<u64>,
        provider: String,
    ) -> Result<PayQuote, LicashError> {
        let (text, plans) = self.plans(&code, amount)?;
        let through = |plan: &licash_nostr::wallet::Plan| {
            let swap = plan.swap.as_ref();
            swap.is_some_and(|s| s.provider.url == provider)
        };
        let Some(plan) = plans.into_iter().find(through) else {
            return Err(LicashError::invalid(format!(
                "{provider} offers no swap for this payment now"
            )));
        };
        let quote = quoted(&plan);
        *self.planned.lock().unwrap_or_else(PoisonError::into_inner) = Some((text, plan));
        Ok(quote)
    }

    /// Pay `amount`, or what it asks, to the payment code `code`, in notes:
    /// as [`Wallet::pay_quote`] quoted it last, else at a hub it names that
    /// the wallet trusts and holds enough at. To the payee's mailbox, or
    /// for them to receive by hand. With `note` for the payee, and a code
    /// of this wallet's if `share` says which (0 its own, else that extra
    /// code's number, [`Wallet::codes`]), sealed for the payee alone: refused,
    /// nothing paid, at a hub that would not keep them with the payment
    /// ([`LicashError::NoteUnkept`]).
    pub fn pay(
        &self,
        code: String,
        amount: Option<u64>,
        note: Option<String>,
        share: Option<u32>,
    ) -> Result<Paid, LicashError> {
        let _timed = crate::log::timed("pay");
        let note = self.outgoing_note(note, share)?;
        self.paying(code, amount, &note, true)
    }

    /// [`Wallet::pay`], answered once its hub released the payment, kept
    /// there for the payee if [`Paid::kept`]: one it does not keep is sent
    /// to the payee's mailbox, and its change unlinked, right after, in
    /// the background. Neither delivered nor to hand over then, on its way
    /// to the mailbox: sent there again later ([`Wallet::resume`]) if no
    /// relay took it. Payments wait for it, as for a payment under way.
    pub fn pay_now(
        self: Arc<Self>,
        code: String,
        amount: Option<u64>,
        note: Option<String>,
        share: Option<u32>,
    ) -> Result<Paid, LicashError> {
        let _timed = crate::log::timed("pay_now");
        let note = self.outgoing_note(note, share)?;
        let paid = self.paying(code, amount, &note, false)?;
        let after = std::thread::Builder::new()
            .name("licash-paid".into())
            .spawn(move || {
                let _delivering = self.delivering();
                let started = Instant::now();
                self.deliver();
                self.unlink();
                tracing::info!(took = ?started.elapsed(), "after paying, mailed what was due and unlinked");
            });
        if let Err(e) = after {
            // Sent and unlinked on the next resume.
            tracing::warn!(%e, "after paying");
        }
        Ok(paid)
    }

    /// [`Wallet::collect`], answered once the payments are taken: their
    /// notes unlinked right after, in the background, as after
    /// [`Wallet::pay_now`]. Payments wait for it, as for a payment under
    /// way.
    pub fn collect_now(self: Arc<Self>) -> Result<Vec<Activity>, LicashError> {
        let _timed = crate::log::timed("collect_now");
        let _background = licash_wallet::Background::enter();
        let received = self.collecting()?;
        if !received.is_empty() {
            tracing::info!(payments = received.len(), "received");
            let after = std::thread::Builder::new()
                .name("licash-received".into())
                .spawn(move || {
                    let _delivering = self.delivering();
                    let started = Instant::now();
                    self.unlink();
                    tracing::info!(took = ?started.elapsed(), "after receiving, unlinked");
                });
            if let Err(e) = after {
                // Unlinked on the next resume.
                tracing::warn!(%e, "after receiving");
            }
        }
        Ok(received)
    }

    /// Whether the mailbox's relays pushed mail within `seconds`, waiting
    /// until they do: [`Wallet::collect_now`] then takes it. Pushed only
    /// once looked in ([`Wallet::collect_now`]) and kept connected: until
    /// then, `false` after `seconds`. A push since the last wake answers
    /// at once.
    pub fn wait_for_mail(&self, seconds: u32) -> bool {
        let arrivals = (self.mailbox.lock().unwrap_or_else(PoisonError::into_inner))
            .as_ref()
            .map(licash_nostr::mailbox::Mailbox::arrivals);
        let most = Duration::from_secs(seconds.into());
        // Its timer made within the runtime.
        self.runtime.block_on(async move {
            match arrivals {
                Some(arrivals) => tokio::time::timeout(most, arrivals.notified())
                    .await
                    .is_ok(),
                None => {
                    tokio::time::sleep(most).await;
                    false
                }
            }
        })
    }
}

impl Wallet {
    /// The URL a hub is reached at, as typed: a host alone over HTTPS, or
    /// HTTP for an onion service, which needs Tor.
    fn hub_url(&self, url: &str) -> Result<String, LicashError> {
        let url = url.trim();
        let host = url.split("://").nth(1).unwrap_or(url);
        let host = host.split(['/', ':']).next().unwrap_or(host);
        let onion = host.ends_with(".onion");
        if onion && self.tor.is_none() {
            return Err(LicashError::NeedsTor);
        }
        Ok(match url.contains("://") {
            true => url.to_owned(),
            false if onion => format!("http://{url}"),
            false => format!("https://{url}"),
        })
    }

    /// `run` to its end, as an operation the owner asked for: in a lane
    /// of its own, its requests on connections and Tor circuits no other
    /// operation's share ([`Lane::Operation`]). What runs by itself, in
    /// the background, on those of its hubs' instead, as it polls,
    /// [`licash_wallet`] taking each payment in a lane of its own.
    fn operation<F: std::future::Future>(&self, run: F) -> F::Output {
        self.runtime.block_on(in_lane(Lane::Operation, run))
    }

    /// The payments the wallet's hubs keep for it, and those in its
    /// mailbox, taken, each once, their notes still linked. Its hubs
    /// naming no relays, only those they keep.
    fn collecting(&self) -> Result<Vec<Activity>, LicashError> {
        let unavailable =
            |e| LicashError::from_any(e, |reason| LicashError::Unavailable { reason });
        if self
            .wallet
            .hubs()?
            .iter()
            .all(|(_, info)| info.relays.is_empty())
        {
            let inboxed = self.runtime.block_on(self.wallet.collect_inbox())?;
            for (hub, reason) in &inboxed.failed {
                tracing::warn!(%hub, %reason, "the payments kept at a hub not looked through");
            }
            return self.received_activities(&inboxed.received, &inboxed.codes);
        }
        let mut kept = self.mailbox.lock().unwrap_or_else(PoisonError::into_inner);
        let collect = licash_nostr::wallet::collect_kept(&self.wallet, &self.route, &mut kept);
        let collected = self.runtime.block_on(collect).map_err(unavailable)?;
        drop(kept);
        for (id, reason) in &collected.skipped {
            tracing::warn!(%id, %reason, "mail not taken");
        }
        for (at, reason) in &collected.failed {
            tracing::warn!(%at, %reason, "payments not looked for");
        }
        self.received_activities(&collected.received, &collected.codes)
    }

    /// The lines of the history of the payments `received`, and of those
    /// the wallet's extra codes took in `codes`, rather than what they paid
    /// on to it.
    fn received_activities(
        &self,
        received: &[licash_wallet::Received],
        codes: &licash_wallet::CodesCollected,
    ) -> Result<Vec<Activity>, LicashError> {
        let notes = self.wallet.payment_notes()?;
        let (at_codes, swept) = match codes.received.is_empty() && codes.swept.is_empty() {
            true => Default::default(),
            false => self.code_lines()?,
        };
        let taken: Vec<&String> = codes.received.iter().map(|(_, r)| &r.id).collect();
        let lines = received
            .iter()
            .filter(|r| !swept.contains(&r.id))
            .map(|r| received_activity(r, notes.get(&r.id)));
        let at_codes = at_codes.into_iter().filter(|a| taken.contains(&&a.id));
        Ok(lines.chain(at_codes).collect())
    }

    /// [`Wallet::pay`], answered once its hub released the payment, kept
    /// there for the payee if it does: one it does not keep mailed to the
    /// payee's mailbox and its change unlinked `now`, else neither, left
    /// to [`Wallet::deliver`] after.
    fn paying(
        &self,
        code: String,
        amount: Option<u64>,
        note: &PaymentNote,
        now: bool,
    ) -> Result<Paid, LicashError> {
        let text = code.trim().to_owned();
        let code: PaymentCode = text.parse().map_err(LicashError::invalid)?;
        let planned = self
            .planned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let planned = planned
            .filter(|(quoted, plan)| *quoted == text && Some(plan.amount) == amount.or(code.amount))
            .map(|(_, plan)| plan);
        if planned.is_none() {
            self.enough(&code, amount)?;
        }
        let _delivering = self.delivering();
        let paid = match &planned {
            Some(plan) => self.operation(licash_nostr::wallet::pay_planned(
                &self.wallet,
                &code,
                plan,
                note,
            )),
            None => self.operation(licash_nostr::wallet::pay(&self.wallet, &code, amount, note)),
        };
        let paid =
            paid.map_err(|e| LicashError::from_any(e, |reason| LicashError::Invalid { reason }))?;
        let kept = paid.paid.kept;
        let mailbox = code.licash.as_ref().is_some_and(|c| c.mailbox.is_some());
        // Not kept at its hub: to the payee's mailbox at once if `now`.
        let mailed = (now && mailbox && !kept).then(|| self.deliver_now(&paid.paid.id));
        if now {
            // Its change, linked to it until then.
            let unlinking = Instant::now();
            self.unlink();
            tracing::info!(took = ?unlinking.elapsed(), "unlinked after paying");
        }
        // No mailbox to reach, or not reached: to hand over, whether its
        // hub keeps it or not.
        let handover = match (mailbox, &mailed) {
            (false, _) | (true, Some(Err(_))) => {
                Some(serde_json::to_string(&paid.paid.payment).map_err(LicashError::failed)?)
            }
            _ => None,
        };
        Ok(Paid {
            id: paid.paid.id,
            amount: paid.amount,
            hub: paid.hub,
            kept,
            delivered: matches!(mailed, Some(Ok(_))),
            handover,
            undelivered: mailed.and_then(Result::err),
        })
    }

    /// The note of a payment: `text` if any, and the wallet's code `share`
    /// says, if any: 0 its own, as [`Wallet::payment_code`] writes it, else
    /// that extra code.
    fn outgoing_note(
        &self,
        text: Option<String>,
        share: Option<u32>,
    ) -> Result<PaymentNote, LicashError> {
        let from = match share {
            None => None,
            Some(0) => self.wallet.payment_code(&self.code_hubs()?)?.licash,
            Some(index) => self.wallet.extra_code(index, &self.code_hubs()?)?.licash,
        };
        Ok(PaymentNote { text, from })
    }

    /// Mail the payments due to their payees' mailboxes, payment `id`
    /// among them: whether it went, or why not.
    fn deliver_now(&self, id: &str) -> Result<(), String> {
        let delivered = licash_nostr::wallet::deliver(&self.wallet, || Ok(self.route.clone()));
        let delivered = self
            .runtime
            .block_on(delivered)
            .map_err(|e| format!("{e:#}"))?;
        for (paid, why) in &delivered.failed {
            tracing::warn!(id = %paid, %why, "a payment to mail to its payee, again later");
        }
        match delivered.failed.into_iter().find(|(paid, _)| paid == id) {
            Some((_, why)) => Err(why),
            None if delivered.mailed.iter().any(|(paid, _)| paid == id) => Ok(()),
            None => Err("it was not due".into()),
        }
    }
}

#[uniffi::export]
impl Wallet {
    /// Take the payment `payment` handed over: under a hub trusted, or any
    /// if `trust`, which it then is.
    pub fn receive(&self, payment: String, trust: bool) -> Result<Activity, LicashError> {
        let payment: licash_api::Payment = serde_json::from_str(payment.trim())
            .map_err(|_| LicashError::invalid("not a payment"))?;
        let received = match self.wallet.receive(&payment) {
            Err(licash_wallet::Error::UnknownHub(url)) if trust => {
                self.operation(self.wallet.add_hub(&url))?;
                self.wallet.receive(&payment)?
            }
            received => received?,
        };
        self.unlink();
        let note = self.wallet.payment_note(&received.id)?;
        Ok(received_activity(&received, note.as_ref()))
    }

    /// Take the payments in the wallet's mailbox, on the relays its hubs
    /// name: each once. Its relays stay connected, pushing the new mail:
    /// the next looks take what they pushed at once, asking them for all
    /// of it again every 30 s.
    pub fn collect(&self) -> Result<Vec<Activity>, LicashError> {
        let _timed = crate::log::timed("collect");
        let received = self.collecting()?;
        if !received.is_empty() {
            self.unlink();
        }
        Ok(received)
    }

    /// The mailbox relays whose answer to the last look asking them was
    /// all a look asks for, where newer mail, junk anyone may send, may
    /// hide an older payment: none before a look, or with no mailbox kept.
    pub fn mailbox_full(&self) -> Vec<String> {
        let kept = self.mailbox.lock().unwrap_or_else(PoisonError::into_inner);
        kept.as_ref()
            .map(|mailbox| mailbox.full())
            .unwrap_or_default()
    }

    /// How many payments made are still on their way to their payees:
    /// kept at their hubs, not yet collected, or to send to their
    /// mailboxes. While any are, [`Wallet::resume`] is called now and
    /// then, which mails those their payees did not collect in time.
    pub fn on_their_way(&self) -> Result<u32, LicashError> {
        Ok(u32::try_from(self.wallet.delivering()?).unwrap_or(u32::MAX))
    }

    /// Finish what was under way: payments, and moves to notes; and mail
    /// the payments due to their payees.
    pub fn resume(&self) -> Result<(), LicashError> {
        let _timed = crate::log::timed("resume");
        // What is left to do retried each round: a hub not answering
        // lately is not waited on again (as ends, refunds and the like).
        let _background = licash_wallet::Background::enter();
        let delivering = self.delivering();
        // Moves kept before their hub answered, by earlier versions: none
        // paid them, as no address was named, and a move asks anew.
        for deposit in self.wallet.deposits()? {
            if deposit.terms.is_none() && deposit.state == DepositState::Open {
                self.wallet.abandon_deposit(&deposit.hash)?;
            }
        }
        let resumed = self.runtime.block_on(self.wallet.resume())?;
        // What the hubs said of themselves since.
        self.onions();
        for (id, reason) in &resumed.abandoned {
            tracing::warn!(%id, %reason, "given up");
        }
        for (id, reason) in &resumed.pending {
            tracing::info!(%id, %reason, "still pending");
        }
        self.unlink();
        self.deliver();
        // Not under it: payments need not wait for the hubs asked.
        drop(delivering);
        self.ask_onions();
        Ok(())
    }
}

/// History, and Bitcoin.
#[uniffi::export]
impl Wallet {
    /// Everything paid and received, coins on Bitcoin not moved yet
    /// first, then the newest first.
    pub fn history(&self) -> Result<Vec<Activity>, LicashError> {
        let mut history = Vec::new();
        let me = self.wallet.address();
        let notes = self.wallet.payment_notes()?;
        // Exact-note normalization stays hidden. Explicit/background
        // optimizations are visible, including their fee and progress.
        let sends = self
            .wallet
            .sends()?
            .into_iter()
            .filter(|s| s.payee != me || s.is_optimization(&me));
        for sent in sends {
            let kind = if sent.is_optimization(&me) {
                Kind::Optimized
            } else {
                Kind::Sent
            };
            let (state, detail) = match sent.state {
                licash_wallet::State::Done => (State::Done, sent.hub),
                licash_wallet::State::Abandoned(why) => (State::Failed, why),
                _ => (State::Pending, sent.hub),
            };
            let memo = notes.get(&sent.id).and_then(|n| n.text.clone());
            history.push(Activity {
                id: sent.id,
                kind,
                state,
                amount: sent.amount,
                fee: sent.fee,
                detail,
                at: Some(sent.created_at),
                memo,
                from: None,
                code: None,
            });
        }
        let deposits = self.wallet.deposits()?;
        let invoices = self.wallet.invoices()?;
        // A move's notes, and an invoice's, are received under its lock:
        // shown as the move or the invoice.
        let locks = deposits.iter().filter_map(|d| d.lock.as_ref());
        let locks = locks.chain(invoices.iter().filter_map(|i| i.lock.as_ref()));
        let locks: Vec<&String> = locks.collect();
        let receipts = self.wallet.receipts()?.into_iter();
        let receipts = receipts.filter(|r| !locks.contains(&&r.id));
        history.extend(receipts.map(|r| received_activity(&r, notes.get(&r.id))));
        // An invoice is a payment once paid: its hub locked notes to it.
        let paid = invoices.iter().filter(|i| i.lock.is_some());
        history.extend(paid.map(invoice_activity));
        // A move its hub never answered moved nothing; one for a
        // contract's reserve, paid only once it closes, is part of the
        // contract until paid.
        let answered = deposits
            .iter()
            .filter(|d| d.terms.is_some() || d.state == DepositState::Open)
            .filter(|d| !(d.close && d.funding.is_none() && d.state == DepositState::Open));
        history.extend(answered.map(|d| {
            let mut activity = moved_activity(d);
            // Its refund made, not yet found in a block.
            if let DepositState::Refunded(txid) = &d.state {
                if !self.refund_found(*txid) {
                    activity.detail = format!("refund {txid} on its way");
                }
            }
            activity
        }));
        for lock in self.wallet.locks()? {
            let via = lock.via.as_ref().map(|v| &v.invoice);
            if let Some(invoice) = lock.invoice.as_ref().or(via) {
                history.push(lightning_activity(&lock, invoice));
            }
        }
        history.extend(payouts::activities(&self.wallet)?);
        history.extend(moves::activities(&self.wallet)?);
        history.extend(self.contract_activities()?);
        let times = self
            .times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let aside = self.set_aside()?;
        // A contract's money back: said as such, not as a payment.
        let returning = self.returning()?;
        for coin in self.wallet.silent_coins()? {
            let state = match coin.spending {
                Some(by) if !aside.contains(&by) => State::Pending,
                _ => State::Done,
            };
            let (kind, detail) = match returning.get(&coin.outpoint.txid) {
                Some(hub) => (Kind::Closed, hub.clone()),
                None => (Kind::Onchain, format!("block {}", coin.height)),
            };
            history.push(Activity {
                id: coin.outpoint.to_string(),
                kind,
                state,
                amount: coin.value,
                fee: 0,
                detail,
                // Its block's: until learned, with those under way first.
                at: times.get(&coin.height).copied(),
                memo: None,
                from: None,
                code: None,
            });
        }
        // A payment an extra code took, rather than what it paid on.
        let (at_codes, swept) = self.code_lines()?;
        history.retain(|a| a.kind != Kind::Received || !swept.contains(&a.id));
        history.extend(at_codes);
        // Her part of a coin a contract took, back as notes: not a payment.
        let contracts = licash_contracts::holder::list(self.wallet.path()).map_err(|e| {
            LicashError::Failed {
                reason: format!("{e:#}"),
            }
        })?;
        let funded = contracts
            .iter()
            .filter(|c| c.funded_received)
            .map(|c| (c.hub.as_str(), c.funded, c.created_at));
        let issued = stats::issued_receipts(&history, funded);
        for line in history.iter_mut().filter(|a| issued.contains(&a.id)) {
            line.kind = Kind::Funded;
        }
        history.sort_by_key(|a| (a.at.is_some(), std::cmp::Reverse(a.at)));
        Ok(history)
    }

    /// The notes the line of the history of `kind` and `id` spent, and
    /// those it made the wallet's: none for a line on Bitcoin alone, nor
    /// before its notes are locked or taken.
    pub fn notes_of(&self, kind: Kind, id: String) -> Result<NotesOf, LicashError> {
        let unknown = || LicashError::invalid(format!("nothing in the history is {id}"));
        let operations: Vec<String> = match kind {
            Kind::Sent | Kind::Received | Kind::Funded | Kind::Lightning | Kind::Optimized => {
                vec![id.clone()]
            }
            Kind::Moved => {
                let deposit = self.wallet.deposits()?.into_iter().find(|d| d.hash == id);
                deposit.ok_or_else(unknown)?.lock.into_iter().collect()
            }
            Kind::Invoice => {
                let invoice = self.wallet.invoices()?.into_iter().find(|i| i.hash == id);
                invoice.ok_or_else(unknown)?.lock.into_iter().collect()
            }
            Kind::Payout => {
                let payout = self.wallet.payouts()?.into_iter().find(|p| p.hash == id);
                payout.ok_or_else(unknown)?.lock.into_iter().collect()
            }
            // Its lock spends at one hub, the provider's lock it claims
            // makes notes at the other.
            Kind::Swap => {
                let swap = self.wallet.swaps()?.into_iter().find(|s| s.hash == id);
                let swap = swap.ok_or_else(unknown)?;
                swap.lock.into_iter().chain(swap.theirs).collect()
            }
            Kind::Onchain | Kind::Closed | Kind::Contract => Vec::new(),
        };
        let me = self.wallet.address();
        let mut notes = licash_wallet::OperationNotes::default();
        let mut paid = Vec::new();
        for operation in &operations {
            let of = self.wallet.operation_notes(operation)?;
            // Its notes spent are at its hub.
            if let Some(hub) = of.spent.first().map(|n| n.hub.clone()) {
                for part in self.wallet.operation_parts(operation)? {
                    let to = match &part.to {
                        PartTo::Payee(payee) if *payee == me => PaidTo::Itself,
                        PartTo::Payee(_) => PaidTo::Payee,
                        PartTo::Hub => PaidTo::Hub,
                        _ => PaidTo::Kept,
                    };
                    paid.push(NotesPaid {
                        to,
                        hub: hub.clone(),
                        amount: part.amount,
                        notes: part.notes,
                    });
                }
            }
            notes.spent.extend(of.spent);
            notes.made.extend(of.made);
        }
        let itself: Vec<String> = self
            .wallet
            .sends()?
            .into_iter()
            .filter(|s| s.payee == me)
            .map(|s| s.id)
            .collect();
        let line = |n: licash_wallet::NoteRecord| NoteLine {
            made_by_itself: itself.contains(&n.made_by),
            linking: match n.unlinked {
                Unlinking::Unlinked => Linking::Unlinked,
                Unlinking::StaysLinked => Linking::StaysLinked,
                _ => Linking::Linked,
            },
            id: n.id,
            hub: n.hub,
            amount: n.amount,
            made_by: n.made_by,
            spent_by: n.spent_by,
            gone: n.gone,
            added_at: n.added_at,
        };
        Ok(NotesOf {
            spent: notes.spent.into_iter().map(line).collect(),
            made: notes.made.into_iter().map(line).collect(),
            paid,
        })
    }

    /// More of the line of the history of `kind` and `id`: what it cost
    /// and where it stands on Bitcoin, as far as the wallet looked. A coin
    /// the wallet does not hold is one on its way, in no block yet.
    pub fn details(&self, kind: Kind, id: String) -> Result<Details, LicashError> {
        let unknown = || LicashError::invalid(format!("nothing in the history is {id}"));
        match kind {
            Kind::Sent | Kind::Optimized => {
                let sent = self.wallet.sends()?.into_iter().find(|s| s.id == id);
                let hub = sent.ok_or_else(unknown)?.hub;
                Ok(Details::Notes { hub })
            }
            Kind::Received | Kind::Funded => {
                let got = self.wallet.receipts()?.into_iter().find(|r| r.id == id);
                // Else one an extra code took.
                let got = match got {
                    Some(got) => Some(got),
                    None => (self.wallet.code_activity()?.into_iter())
                        .flat_map(|at| at.received)
                        .find(|r| r.id == id),
                };
                let hub = got.ok_or_else(unknown)?.hub;
                Ok(Details::Notes { hub })
            }
            Kind::Lightning => {
                let lock = self.wallet.locks()?.into_iter().find(|l| l.id == id);
                let lock = lock
                    .filter(|l| l.invoice.is_some() || l.via.is_some())
                    .ok_or_else(unknown)?;
                let (preimage, failure) = match &lock.state {
                    licash_wallet::LockState::Paid(p) => (Some(hex::encode(p)), None),
                    licash_wallet::LockState::Abandoned(why) => (None, Some(why.clone())),
                    _ => (None, lock.failure.clone()),
                };
                let (provider, invoice) = match lock.via {
                    Some(via) => (Some(via.provider), via.invoice),
                    None => (None, lock.invoice.unwrap_or_default()),
                };
                let expiry = provider.is_some().then_some(lock.expiry);
                // Only a provider's payment waits for its lock to expire.
                let under_way = matches!(
                    lock.state,
                    licash_wallet::LockState::Requested | licash_wallet::LockState::Locked
                );
                let refund_blocks = match (&provider, under_way) {
                    (Some(_), true) => (self.wallet.hubs()?.into_iter())
                        .find(|(url, _)| *url == lock.hub)
                        .map(|(_, info)| licash_wallet::refund_blocks(&info, lock.expiry)),
                    _ => None,
                };
                Ok(Details::Lightning {
                    hub: lock.hub,
                    invoice,
                    preimage,
                    failure,
                    provider,
                    expiry,
                    refund_blocks,
                })
            }
            Kind::Moved => {
                let deposit = self.wallet.deposits()?.into_iter().find(|d| d.hash == id);
                self.moved_details(deposit.ok_or_else(unknown)?)
            }
            Kind::Invoice => {
                let invoice = self.wallet.invoices()?.into_iter().find(|i| i.hash == id);
                let invoice = lightning_invoice(&invoice.ok_or_else(unknown)?, None);
                Ok(Details::Invoice {
                    hub: invoice.hub,
                    invoice: invoice.request,
                    asks: invoice.asks,
                    failure: invoice.reason,
                })
            }
            Kind::Payout => payouts::details(&self.wallet, &id, self.tip()),
            Kind::Swap => moves::details(&self.wallet, &id),
            Kind::Contract => self.contract_details(&id)?.ok_or_else(unknown),
            Kind::Onchain | Kind::Closed => {
                let outpoint: OutPoint = id.parse().map_err(|_| unknown())?;
                let mut coins = self.wallet.silent_coins()?.into_iter();
                let mut coin = coins.find(|c| c.outpoint == outpoint);
                // Held for a challenge's fee: no transaction moves it.
                let aside = self.set_aside()?;
                if let Some(c) = coin
                    .as_mut()
                    .filter(|c| c.spending.is_some_and(|by| aside.contains(&by)))
                {
                    c.spending = None;
                }
                let height = coin.as_ref().map(|c| c.height);
                let tx = Onchain {
                    txid: outpoint.txid.to_string(),
                    fee: None,
                    height,
                    confirmations: confirmations(height, self.wallet.silent_next()?),
                };
                Ok(Details::Coin {
                    tx,
                    vout: outpoint.vout,
                    change: coin.as_ref().is_some_and(|c| c.change),
                    moving: coin.and_then(|c| c.spending).map(|t| t.to_string()),
                })
            }
        }
    }

    /// Look for payments on Bitcoin in the next blocks of `chain`, and
    /// broadcast again the wallet's spends not in a block yet once caught
    /// up. Called until `next` passes `height`, once a hub is trusted. With
    /// the tweaks of every hub trusted serving them, of each block those
    /// any of them serves; without, of blocks no hub trusted serves tweaks
    /// of, for the fallback addresses and the coins held only.
    pub fn scan(&self, chain: Arc<dyn ChainSource>) -> Result<Scan, LicashError> {
        self.scan_with(chain, None)
    }

    /// The tweaks [`Wallet::scan_with`] looks in the next blocks with,
    /// asked of the hubs trusted serving them: none if no hub trusted
    /// serves them, or there is no block to look in. Changes nothing the
    /// wallet holds, so called alongside anything else: what makes a scan
    /// wait on the hubs, not holding up the rest while it does.
    pub fn tweaks(&self, chain: Arc<dyn ChainSource>) -> Result<Option<Arc<Tweaks>>, LicashError> {
        let _timed = crate::log::timed("tweaks");
        let _background = licash_wallet::Background::enter();
        let source = Chain(chain, self.wallet.network());
        let fetch = self.wallet.silent_tweaks(&source, SCAN_BATCH);
        let tweaks = self.runtime.block_on(fetch)?;
        Ok(tweaks.map(|t| Arc::new(Tweaks(t))))
    }

    /// [`Wallet::scan`], with the tweaks fetched `ahead` by
    /// [`Wallet::tweaks`]: not fetched again while still of the chain's
    /// blocks.
    pub fn scan_with(
        &self,
        chain: Arc<dyn ChainSource>,
        ahead: Option<Arc<Tweaks>>,
    ) -> Result<Scan, LicashError> {
        let _timed = crate::log::timed("scan");
        let _background = licash_wallet::Background::enter();
        if self.wallet.hubs()?.is_empty() {
            return Err(LicashError::invalid(
                "no hub trusted serves what finds payments on Bitcoin",
            ));
        }
        if self.wallet.silent_next()?.is_none() {
            // Recorded before any block is looked in.
            let from = self.first_block(chain.as_ref())?;
            self.learn_birthday(from)?;
            self.wallet.watch_silent(None, from)?;
            tracing::info!(from, "looking for payments on Bitcoin");
        }
        let source = Chain(chain.clone(), self.wallet.network());
        let ahead = ahead.map(|t| t.0.clone());
        let scan = self.wallet.scan_silent_trusted(&source, SCAN_BATCH, ahead);
        let (scanned, tweaked) = self.runtime.block_on(scan)?;
        self.saw(scanned.height);
        self.learn_times(chain.as_ref())?;
        if scanned.next > scanned.height {
            // The payments of moves through providers, for resuming to
            // tell them of.
            let found = self.wallet.find_deposit_payments(&source);
            match self.runtime.block_on(found) {
                Ok(pending) => {
                    for (hash, why) in pending {
                        tracing::info!(%hash, "a move's payment not looked for: {why}");
                    }
                }
                Err(e) => tracing::info!("the payments of moves: {e}"),
            }
            self.broadcast_again(chain.as_ref());
            self.refund_deposits(chain.as_ref(), scanned.height);
            // A wallet made before its birthday was kept, caught up: its
            // first block, from the time it was made.
            if self.kept().birthday == 0 {
                match self.first_block(chain.as_ref()) {
                    Ok(from) => self.learn_birthday(from)?,
                    Err(e) => tracing::debug!(%e, "the wallet's first block"),
                }
            }
        }
        Ok(Scan {
            from: self.kept().birthday,
            next: scanned.next,
            height: scanned.height,
            tweaks: tweaked,
            found: scanned.found.len() as u32,
            found_value: scanned.found.iter().map(|c| c.value).sum(),
        })
    }

    /// Learn from `chain` the times of the blocks of the coins found whose
    /// time is not known yet, for the history to place them among the rest.
    /// One the light client cannot tell is asked again on the next scan.
    fn learn_times(&self, chain: &dyn ChainSource) -> Result<(), LicashError> {
        let mut heights: Vec<u32> = self
            .wallet
            .silent_coins()?
            .iter()
            .map(|c| c.height)
            .collect();
        heights.sort_unstable();
        heights.dedup();
        let mut times = self.times.lock().unwrap_or_else(PoisonError::into_inner);
        for height in heights {
            if times.contains_key(&height) {
                continue;
            }
            match chain.time(height) {
                Ok(time) => {
                    times.insert(height, time);
                }
                Err(e) => tracing::debug!(height, "no time of the block: {e}"),
            }
        }
        Ok(())
    }

    /// Payments on Bitcoin on their way to the fallback addresses handed
    /// out, as `chain`'s peers relay them: in no block the wallet looked
    /// in yet. Shown, never spent: only a scan finds coins.
    pub fn incoming(&self, chain: Arc<dyn ChainSource>) -> Result<Vec<Activity>, LicashError> {
        let _timed = crate::log::timed("incoming");
        let _background = licash_wallet::Background::enter();
        let mut txs = Vec::new();
        for script in self.wallet.fallback_scripts()? {
            let raw = chain
                .unconfirmed(script.into_bytes())
                .map_err(|e| LicashError::failed(format!("the light client: {e}")))?;
            let mut rest = raw.as_slice();
            while !rest.is_empty() {
                let tx: bitcoin::Transaction =
                    bitcoin::consensus::Decodable::consensus_decode(&mut rest)
                        .map_err(|e| LicashError::failed(format!("a relayed transaction: {e}")))?;
                txs.push(tx);
            }
        }
        let paying = self.wallet.unconfirmed_payments(&txs)?;
        let returning = self.returning()?;
        Ok(paying
            .into_iter()
            .map(|(outpoint, value)| Activity {
                id: outpoint.to_string(),
                kind: match returning.contains_key(&outpoint.txid) {
                    true => Kind::Closed,
                    false => Kind::Onchain,
                },
                state: State::Pending,
                amount: value,
                fee: 0,
                detail: match returning.get(&outpoint.txid) {
                    Some(hub) => hub.clone(),
                    None => "waiting for a block".into(),
                },
                at: None,
                memo: None,
                from: None,
                code: None,
            })
            .collect())
    }

    /// Move the largest coin paid on Bitcoin, whole and alone, to notes,
    /// at a hub trusted that takes it, broadcasting through `chain`: the
    /// move, under way. The coins the wallet's own payouts paid, cashed
    /// out to it ([`Balance::kept`]), stay on Bitcoin.
    pub fn move_to_licash(&self, chain: Arc<dyn ChainSource>) -> Result<Activity, LicashError> {
        let mut keep: Vec<OutPoint> = self.kept_coins()?.into_iter().map(|(c, _)| c).collect();
        keep.extend(self.opening_coins()?);
        self.move_keeping(chain, &keep)
    }

    /// [`Wallet::move_to_licash`] of the largest of all the coins, those
    /// cashed out to the wallet too: but those paying for contracts being
    /// opened.
    pub fn move_largest_to_licash(
        &self,
        chain: Arc<dyn ChainSource>,
    ) -> Result<Activity, LicashError> {
        self.move_keeping(chain, &self.opening_coins()?)
    }
}

impl Wallet {
    /// The ways of paying `code`, trimmed as it was given, as
    /// [`licash_nostr::wallet::plans`] finds them: never none.
    fn plans(
        &self,
        code: &str,
        amount: Option<u64>,
    ) -> Result<(String, Vec<licash_nostr::wallet::Plan>), LicashError> {
        let text = code.trim().to_owned();
        let code: PaymentCode = text.parse().map_err(LicashError::invalid)?;
        code.check(self.wallet.network())?;
        let plans = plans_with(&self.wallet, &code, amount, &self.route, &self.announced);
        match self.operation(plans) {
            Ok(plans) => Ok((text, plans)),
            Err(e) => {
                // Lacking notes says the most: what is needed.
                self.enough(&code, amount)?;
                Err(LicashError::from_any(e, |reason| LicashError::Invalid {
                    reason,
                }))
            }
        }
    }

    /// What the wallet's coins held for a challenge's fee are held under,
    /// one for each of its contracts: the txid of no transaction
    /// ([`licash_contracts::holder::recovery::challenge_marker`]).
    fn set_aside(&self) -> Result<Vec<bitcoin::Txid>, LicashError> {
        let all = licash_contracts::holder::list(self.wallet.path()).map_err(|e| {
            LicashError::Failed {
                reason: format!("{e:#}"),
            }
        })?;
        Ok(all
            .iter()
            .map(|c| licash_contracts::holder::recovery::challenge_marker(&c.id))
            .collect())
    }

    /// The coins not spent that the claims of the wallet's payouts paid,
    /// with their values: cashed out to the wallet itself.
    fn kept_coins(&self) -> Result<Vec<(OutPoint, u64)>, LicashError> {
        let mut paid: Vec<bitcoin::Txid> = self
            .wallet
            .payouts()?
            .into_iter()
            .filter_map(|p| p.claim)
            .collect();
        // A contract's change too: it was paid from a coin kept, as a rule.
        paid.extend(self.fundings()?);
        if paid.is_empty() {
            return Ok(Vec::new());
        }
        let coins = self.wallet.silent_coins()?.into_iter();
        Ok(coins
            .filter(|c| c.spending.is_none() && paid.contains(&c.outpoint.txid))
            .map(|c| (c.outpoint, c.value))
            .collect())
    }

    /// What moves to notes hold once their payment is in a block and
    /// before their notes are received: no longer the wallet's coins, not
    /// yet its notes.
    fn confirmed_moves(&self, reserved: &[(bitcoin::Txid, u64)]) -> Result<u64, LicashError> {
        let mut receipts = None;
        let mut moving = 0;
        for deposit in self.wallet.deposits()? {
            let Some(terms) = deposit.terms.as_ref() else {
                continue;
            };
            if deposit.state != DepositState::Open {
                continue;
            }
            if let Some(lock) = &deposit.lock {
                let receipts = match &receipts {
                    Some(receipts) => receipts,
                    None => receipts.insert(self.wallet.receipts()?),
                };
                if receipts.iter().any(|r| &r.id == lock) {
                    continue;
                }
            }
            let Ok(address) = terms
                .address
                .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            else {
                continue;
            };
            let script = address.assume_checked().script_pubkey();
            let spends = self.wallet.silent_spends_paying(&script)?;
            if seen_paid(&deposit, reserved) || spends.iter().any(|s| s.height.is_some()) {
                moving += deposit.amount;
            }
        }
        Ok(moving)
    }

    fn move_keeping(
        &self,
        chain: Arc<dyn ChainSource>,
        keep: &[OutPoint],
    ) -> Result<Activity, LicashError> {
        let rate = FeeRate::from_sat_per_vb(DEPOSIT_RATE).expect("a rate");
        // Through the providers announced, the cheapest for the coin first;
        // else, none announced, at a hub trusted, as hubs of earlier
        // releases still take them (later ones refuse, naming providers).
        let mut providers = self.deposit_offers()?;
        let hubs = self.wallet.hubs()?.into_iter();
        let hub = hubs.filter_map(|(u, i)| Some((u, i.deposits?))).next();
        let least = match (providers.first(), &hub) {
            (Some((_, p)), _) => licash_wallet::least_deposited_through(&p.offer.terms, rate),
            (None, Some((_, offer))) => licash_wallet::least_deposited(offer, rate),
            (None, None) => {
                return Err(LicashError::invalid(
                    "no hub trusted takes coins on Bitcoin, nor a swap provider at one",
                ))
            }
        };
        // One coin, whole: coins are never joined, nor change left.
        let coin = (self.wallet.silent_coins()?.into_iter())
            .filter(|c| c.spending.is_none() && !keep.contains(&c.outpoint))
            .max_by_key(|c| c.value)
            .ok_or(LicashError::Insufficient {
                needed: least,
                available: 0,
            })?;
        providers.sort_by_key(|(_, p)| p.offer.terms.pays(coin.value).saturating_sub(coin.value));
        let mut moved = None;
        for (at, provider) in &providers {
            let asked = self
                .wallet
                .deposit_silent_through(&provider.url, at, coin.outpoint, rate);
            match self.operation(asked) {
                Ok(paying) => {
                    moved = Some(Ok(paying));
                    break;
                }
                Err(e) => {
                    tracing::info!(provider = %provider.url, %at, "not moving through it: {e:?}");
                    moved = Some(Err(e));
                }
            }
        }
        let (deposit, tx) = match (moved, hub) {
            (Some(Ok(paying)), _) => paying,
            // Why the last provider would not, not why a hub would not.
            (Some(Err(e)), _) => return Err(e.into()),
            (None, Some((hub, _))) => {
                self.operation(self.wallet.deposit_silent(&hub, coin.outpoint, rate))?
            }
            (None, None) => unreachable!("a provider or a hub, else returned above"),
        };
        if let Err(e) = chain.broadcast(bitcoin::consensus::serialize(&tx)) {
            // Relay may have succeeded before the response failed. Keep
            // the signed transaction and inputs; scanning retries it.
            return Err(LicashError::Unavailable {
                reason: format!(
                    "broadcast outcome unknown; transaction {} kept for retry: {e}",
                    tx.compute_txid()
                ),
            });
        }
        tracing::info!(hash = %deposit.hash, txid = %tx.compute_txid(), "moving to notes");
        Ok(moved_activity(&deposit))
    }
}

impl Wallet {
    /// Where an invoice taken on stands: as kept, with why, while its hub
    /// is yet to answer, which it is asked again until it does.
    fn invoice_now(
        &self,
        followed: Result<licash_wallet::Invoice, licash_wallet::Error>,
    ) -> Result<LightningInvoice, LicashError> {
        match followed {
            Ok(invoice) => Ok(lightning_invoice(&invoice, None)),
            Err(licash_wallet::Error::Pending { id, reason }) => {
                let mut invoices = self.wallet.invoices()?.into_iter();
                match invoices.find(|i| i.hash == id) {
                    Some(invoice) => Ok(lightning_invoice(&invoice, Some(reason))),
                    None => Err(LicashError::Pending { reason }),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// A move's terms, and its payment: the wallet's own transaction paying
    /// its address, unless its hub saw another pay it.
    fn moved_details(&self, deposit: licash_wallet::Deposit) -> Result<Details, LicashError> {
        let next = self.wallet.silent_next()?;
        let hubs = self.wallet.hubs()?.into_iter();
        let mut hubs = hubs.filter(|(url, _)| *url == deposit.hub);
        let depth = match deposit.provider {
            Some(_) => None,
            None => hubs.next().and_then(|(_, i)| i.deposits.map(|d| d.depth)),
        };
        let terms = deposit.terms.as_ref();
        // Checked against the network when the hub answered.
        let script = terms
            .and_then(|t| t.address.parse::<bitcoin::Address<_>>().ok())
            .map(|a| a.assume_checked().script_pubkey());
        let spends = match &script {
            Some(script) => self.wallet.silent_spends_paying(script)?,
            None => Vec::new(),
        };
        let funding = deposit.funding;
        let spend = spends
            .into_iter()
            .rev()
            .find(|s| funding.is_none_or(|(outpoint, _)| outpoint.txid == s.tx.compute_txid()));
        let payment = match (spend, funding) {
            (Some(spend), _) => {
                // Its hub may have seen it confirm before the wallet looked.
                let height = spend.height.or(funding.map(|(_, height)| height));
                Some(Onchain {
                    txid: spend.tx.compute_txid().to_string(),
                    fee: spend.fee,
                    height,
                    confirmations: confirmations(height, next),
                })
            }
            (None, Some((outpoint, height))) => Some(Onchain {
                txid: outpoint.txid.to_string(),
                fee: None,
                height: Some(height),
                confirmations: confirmations(Some(height), next),
            }),
            (None, None) => None,
        };
        let refund = match &deposit.state {
            DepositState::Refunded(txid) => Some(txid.to_string()),
            _ => None,
        };
        Ok(Details::Moved {
            pays: terms.map(|t| t.pays),
            address: terms.map(|t| t.address.clone()),
            fund_by: terms.map(|t| t.fund_by),
            timeout: terms.map(|t| t.timeout),
            hub: deposit.hub,
            hash: deposit.hash,
            provider: deposit.provider,
            payment,
            depth,
            refund,
        })
    }

    fn delivering(&self) -> MutexGuard<'_, ()> {
        self.delivering
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Mail the payments due to their payees' mailboxes, again later
    /// those no relay took ([`licash_nostr::wallet::deliver`]).
    fn deliver(&self) {
        let delivered = licash_nostr::wallet::deliver(&self.wallet, || Ok(self.route.clone()));
        match self.runtime.block_on(delivered) {
            Ok(delivered) => {
                for (id, relays) in &delivered.mailed {
                    tracing::info!(%id, relays, "a payment sent to its payee's mailbox");
                }
                for (id, why) in &delivered.failed {
                    tracing::warn!(%id, %why, "a payment to send to its payee's mailbox, again later");
                }
            }
            Err(e) => tracing::warn!(e = %format!("{e:#}"), "the payments due to mailboxes"),
        }
    }

    /// Refused as more than held if the code names hubs trusted, some
    /// holding notes, none enough to pay `amount` or what it asks and the
    /// fee: what is needed and held at the one holding most. Holding none,
    /// paying it says where to pay on Bitcoin instead.
    fn enough(&self, code: &PaymentCode, amount: Option<u64>) -> Result<(), LicashError> {
        code.check(self.wallet.network())?;
        let (Some(licash), Some(amount)) = (&code.licash, amount.or(code.amount)) else {
            return Ok(());
        };
        if code.amount.is_some_and(|asked| asked != amount)
            || self.wallet.hub_to_pay(licash, amount)?.is_some()
        {
            return Ok(());
        }
        let held = self.wallet.balance()?;
        let mut most: Option<(u64, u64)> = None;
        for (url, info) in self.wallet.hubs()? {
            if !licash
                .hubs
                .contains(&licash_wallet::HubId::of(&info.address))
            {
                continue;
            }
            let available = held
                .iter()
                .find(|b| b.hub == url)
                .map_or(0, |b| b.available);
            let needed = amount.saturating_add(info.fees.spending().at_most(amount));
            if most.is_none_or(|(_, a)| available > a) {
                most = Some((needed, available));
            }
        }
        match most {
            Some((needed, available)) if available > 0 => {
                Err(LicashError::Insufficient { needed, available })
            }
            _ => Ok(()),
        }
    }

    /// Unlink what can be: what is left stays linked until the next try.
    fn unlink(&self) {
        if let Err(e) = self.runtime.block_on(self.wallet.unlink()) {
            tracing::warn!(%e, "some notes stay linked for now");
        }
    }

    /// Keep `from`, the first block looked in, as the wallet's birthday if
    /// it had none: for the recovery words' restore, and the backup file.
    fn learn_birthday(&self, from: u32) -> Result<(), LicashError> {
        if self.kept().birthday != 0 || from == 0 {
            return Ok(());
        }
        self.update_kept(|kept| {
            if kept.birthday == 0 {
                kept.birthday = from;
                tracing::info!(from, "the wallet's first block kept");
            }
        })
    }

    /// The first block to look in for payments on Bitcoin: the chain's
    /// height when the wallet was made, if the app knew it. Else the first
    /// block claiming a time from a day before the wallet file was made
    /// on, a margin for block times and clocks: the app makes new seeds
    /// only, never paid before.
    fn first_block(&self, chain: &dyn ChainSource) -> Result<u32, LicashError> {
        let birthday = self.kept().birthday;
        if birthday > 0 {
            return Ok(birthday);
        }
        let since = self.wallet.created_at()? - DAY;
        let light = |e: ChainError| LicashError::failed(format!("the light client: {e}"));
        let height = chain.height().map_err(light)?;
        let (mut low, mut high) = (1, height + 1);
        while low < high {
            let mid = low + (high - low) / 2;
            if chain.time(mid).map_err(light)? < since {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(low)
    }

    fn broadcast_again(&self, chain: &dyn ChainSource) {
        let spends = match self.wallet.silent_spends() {
            Ok(spends) => spends,
            Err(e) => return tracing::warn!(%e, "the spends to broadcast again"),
        };
        for tx in spends {
            if let Err(e) = chain.broadcast(bitcoin::consensus::serialize(&tx)) {
                tracing::debug!(txid = %tx.compute_txid(), %e, "broadcasting again");
            }
        }
    }
}

fn hub(url: &str, info: &licash_api::Info) -> Hub {
    Hub {
        url: url.to_owned(),
        fee_base: info.fees.spend.base,
        fee_ppm: info.fees.spend.ppm,
        fee_output_msat: info.fees.output_msat,
        deposits: info.deposits.as_ref().map(|d| Range {
            min: d.min,
            max: d.max,
        }),
        silent: info.tweaks.is_some(),
        mailbox: !info.relays.is_empty(),
        lock_fee: rate(info.fees.lock),
        refund_fee: rate(info.fees.refund),
        deposit_fee: info.deposits.as_ref().map(|d| rate(d.fee)),
        // Of its least contract, all of it hers, over the fewest blocks.
        contracts: info.contracts.map(|c| ContractTerms {
            cap: u64::from(c.range.min_cap),
            price: c
                .range
                .price(c.range.min_cap, c.range.min_blocks, c.range.min_cap),
            blocks: c.range.min_blocks,
            mock: c.mock,
            range: Some(c.range.into()),
            funds: c.funds.map(u64::from),
            full: c.full,
        }),
    }
}

fn rate(fee: licash_api::Fee) -> Rate {
    Rate {
        base: fee.base,
        ppm: fee.ppm,
    }
}

/// `memo` as an invoice says it: none if blank.
fn said(memo: Option<String>) -> Result<Option<String>, LicashError> {
    memo.filter(|m| !m.trim().is_empty())
        .map(|m| licash_api::memo(&m).map_err(|p| LicashError::invalid(p.message)))
        .transpose()
}

/// Why no way to pay an invoice was found.
pub(crate) const NO_PAYER: &str =
    "no swap provider pays Lightning invoices from a hub you trust now";

/// The line of the history of `received`, saying what its `note` says.
fn received_activity(received: &licash_wallet::Received, note: Option<&PaymentNote>) -> Activity {
    let from = note.and_then(|n| n.from.clone()).map(|licash| PaymentCode {
        address: None,
        amount: None,
        silent: None,
        licash: Some(licash),
    });
    Activity {
        id: received.id.clone(),
        kind: Kind::Received,
        state: State::Done,
        amount: received.amount,
        fee: 0,
        detail: received.hub.clone(),
        at: Some(received.received_at),
        memo: note.and_then(|n| n.text.clone()),
        from: from.map(|code| code.to_string()),
        code: None,
    }
}

/// The line of the history of `lock`, paying `invoice`: what the invoice
/// asks, and the fee: the gateway's, or the provider's and the hub's, on
/// top once paid, or while under way; the hub's refund fee once refunded;
/// none if given up. A provider's payment that failed is under way until
/// its lock expires, and says so.
fn lightning_activity(lock: &licash_wallet::Lock, invoice: &str) -> Activity {
    use licash_wallet::LockState;
    let payable = licash_wallet::Payable::read(invoice).ok();
    let asked = payable.as_ref().map_or(lock.amount, |p| p.amount);
    let asked = asked.min(lock.amount);
    let expected = lock.amount - asked + lock.fee;
    let (state, detail, fee) = match &lock.state {
        LockState::Paid(_) => (
            State::Done,
            lock.hub.clone(),
            lock.cost.map_or(expected, |c| c.saturating_sub(asked)),
        ),
        LockState::Refunded => (
            State::Failed,
            lock.failure.clone().unwrap_or_else(|| "refunded".into()),
            lock.cost.unwrap_or(0),
        ),
        LockState::Abandoned(why) => (State::Failed, why.clone(), 0),
        LockState::Locked if lock.via.is_some() && lock.failure.is_some() => (
            State::Pending,
            format!(
                "not paid ({}): back after block {}",
                lock.failure.as_deref().unwrap_or_default(),
                lock.expiry
            ),
            expected,
        ),
        _ => (State::Pending, lock.hub.clone(), expected),
    };
    Activity {
        id: lock.id.clone(),
        kind: Kind::Lightning,
        state,
        amount: asked,
        fee,
        detail,
        at: Some(lock.created_at),
        memo: payable.and_then(|p| p.description),
        from: None,
        code: None,
    }
}

/// An invoice the wallet asked for, as it stands; `waiting`, why its hub
/// is yet to answer, if it is.
fn lightning_invoice(
    invoice: &licash_wallet::Invoice,
    waiting: Option<String>,
) -> LightningInvoice {
    use licash_wallet::InvoiceState;
    let (state, reason) = match &invoice.state {
        InvoiceState::Received => (State::Done, None),
        InvoiceState::Canceled(why) => (State::Failed, Some(why.clone())),
        _ => (State::Pending, waiting),
    };
    let request = invoice.request.clone();
    let asks = request.as_deref().map(licash_wallet::Payable::read);
    LightningInvoice {
        hash: invoice.hash.clone(),
        hub: invoice.hub.clone(),
        amount: invoice.amount,
        asks: asks.and_then(Result::ok).map(|p| p.amount),
        request,
        state,
        reason,
    }
}

/// The line of the history of an invoice paid to the wallet: its notes,
/// when they came, and no fee, which the payer pays.
fn invoice_activity(invoice: &licash_wallet::Invoice) -> Activity {
    let shown = lightning_invoice(invoice, None);
    Activity {
        id: shown.hash,
        kind: Kind::Invoice,
        state: shown.state,
        amount: shown.amount,
        fee: 0,
        detail: shown.reason.unwrap_or(shown.hub),
        at: Some(invoice.received_at.unwrap_or(invoice.created_at)),
        memo: invoice.memo.clone(),
        from: None,
        code: None,
    }
}

/// The blocks confirming a transaction in block `height`, the wallet
/// having looked in those before `next`.
fn confirmations(height: Option<u32>, next: Option<u32>) -> u32 {
    match (height, next) {
        (Some(height), Some(next)) => next.saturating_sub(height).max(1),
        (Some(_), None) => 1,
        (None, _) => 0,
    }
}

/// Whether `deposit` was paid in a block, as its hub saw, by a
/// transaction spending no coin of the wallet's still shown (`reserved`,
/// as moving or being opened): another's, such as a contract's F paying
/// its change in, or the wallet's own once a scan saw it.
fn seen_paid(deposit: &licash_wallet::Deposit, reserved: &[(bitcoin::Txid, u64)]) -> bool {
    let shown = |paid: &OutPoint| reserved.iter().any(|(by, _)| *by == paid.txid);
    deposit.funding.is_some_and(|(paid, _)| !shown(&paid))
}

fn moved_activity(deposit: &licash_wallet::Deposit) -> Activity {
    let (state, detail) = match &deposit.state {
        DepositState::Received => (State::Done, deposit.hub.clone()),
        DepositState::Canceled(why) => (State::Failed, why.clone()),
        DepositState::Refunded(txid) => (State::Failed, format!("refunded in {txid}")),
        _ => (State::Pending, deposit.hub.clone()),
    };
    let pays = deposit.terms.as_ref().map_or(deposit.amount, |t| t.pays);
    Activity {
        id: deposit.hash.clone(),
        kind: Kind::Moved,
        state,
        amount: deposit.amount,
        fee: pays.saturating_sub(deposit.amount),
        detail,
        at: Some(deposit.created_at),
        memo: None,
        from: None,
        code: None,
    }
}

/// What paying as `plan` says costs, as quoted.
fn quoted(plan: &licash_nostr::wallet::Plan) -> PayQuote {
    PayQuote {
        hub: plan.hub.clone(),
        amount: plan.amount,
        fee: plan.fees(),
        swap_from: plan.swap.as_ref().map(|s| s.from.clone()),
        swapped: plan.swap.as_ref().map_or(0, |s| s.provider.quote.amount),
        trusted: plan.trusted,
    }
}

/// The most an amount may be for it and `fee` on it to come to `total` at
/// most: none if the fee alone is more.
fn before_fee(fee: &licash_api::Fee, total: u64) -> u64 {
    let fits = |n: u64| n.checked_add(fee.due(n)).is_some_and(|t| t <= total);
    if !fits(0) {
        return 0;
    }
    // It and its fee only grow with it: the last that fits, found halving.
    let (mut low, mut high) = (0, total);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if fits(mid) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::{OutPoint, Txid};
    use licash_api::Fee;
    use licash_wallet::{Deposit, DepositState};

    use super::{before_fee, seen_paid};

    /// What the app goes by to gray a hub: open unless the hub says it
    /// is full or lends nothing of a contract, as hubs before any said
    /// either read. Under range-only terms its holder funds what the hub
    /// does not lend, so a loan short of the least cap is still room.
    #[test]
    fn a_hub_has_room_for_a_contract_unless_it_says_otherwise() {
        use crate::{contract_room, ContractRange, ContractTerms, HubRoom};
        let terms = ContractTerms {
            cap: 131_071,
            price: 23_000,
            blocks: 1_000,
            mock: false,
            range: None,
            funds: None,
            full: false,
        };
        assert_eq!(contract_room(terms), HubRoom::Open);
        let full = ContractTerms {
            full: true,
            ..terms
        };
        assert_eq!(contract_room(full), HubRoom::Full);
        let funds = |funds| ContractTerms {
            funds: Some(funds),
            ..terms
        };
        assert_eq!(contract_room(funds(0)), HubRoom::Unfunded);
        // Less than rounds her part up to a cap is lending nothing.
        assert_eq!(contract_room(funds(511)), HubRoom::Unfunded);
        assert_eq!(contract_room(funds(512)), HubRoom::Open);
        assert_eq!(contract_room(funds(131_071)), HubRoom::Open);
        // More than fits a hub's 32 bits is still room, not none.
        assert_eq!(contract_room(funds(u64::MAX)), HubRoom::Open);
        // Lending less than the smallest contract it opens: she funds the
        // rest.
        let ranged = ContractTerms {
            range: Some(ContractRange {
                min_cap: 262_143,
                max_cap: 1_048_575,
                min_blocks: 432,
                max_blocks: 52_560,
                per_coin: 2,
                reserve: 20_000,
                fee: 3_000,
                ppm_year: 10_000,
                ppm_year_funded: 0,
                year_blocks: 52_560,
            }),
            ..funds(131_071)
        };
        assert_eq!(contract_room(ranged), HubRoom::Open);
    }

    #[test]
    fn a_deposit_another_paid_moves_once_no_coin_shows_its_payment() {
        let f = Txid::from_byte_array([7; 32]);
        let mut deposit = Deposit {
            hash: "00".into(),
            hub: "http://hub.test".into(),
            amount: 976_000,
            terms: None,
            funding: None,
            lock: None,
            state: DepositState::Open,
            created_at: 0,
            close: false,
            provider: None,
        };
        // Its payment unseen: nothing moves yet.
        assert!(!seen_paid(&deposit, &[]));
        deposit.funding = Some((OutPoint::new(f, 1), 100));
        // Paid by F, the coin F spends gone: moving.
        assert!(seen_paid(&deposit, &[]));
        let other = Txid::from_byte_array([8; 32]);
        assert!(seen_paid(&deposit, &[(other, 5_000)]));
        // Its coin still shown as being opened: counted there, not twice.
        assert!(!seen_paid(&deposit, &[(f, 1_000_000)]));
    }

    #[test]
    fn an_amount_and_its_fee_come_to_the_total_or_a_sat_short() {
        let base = Fee { base: 3, ppm: 0 };
        assert_eq!(before_fee(&base, 503), 500);
        assert_eq!(before_fee(&base, 3), 0);
        assert_eq!(before_fee(&base, 2), 0);
        let rate = Fee { base: 0, ppm: 10 };
        assert_eq!(before_fee(&rate, 100_001), 100_000);
        // No amount and its fee, rounded up, come to 100,002: a sat short.
        assert_eq!(before_fee(&rate, 100_002), 100_000);
        assert_eq!(before_fee(&rate, 100_003), 100_001);
        let half = Fee {
            base: 1,
            ppm: 1_000_000,
        };
        assert_eq!(before_fee(&half, 11), 5);
        assert_eq!(before_fee(&Fee::default(), u64::MAX), u64::MAX);
        let both = Fee {
            base: 1_000,
            ppm: 2_500,
        };
        for total in [0, 999, 1_000, 1_001, 50_000, 1_000_000, 21_000_000_000] {
            let n = before_fee(&both, total);
            let came = n + both.due(n);
            assert!(came <= total || n == 0, "{total}: {n}");
            assert!(n == 0 || total - came <= 1, "{total}: {n} came to {came}");
            assert!((n + 1) + both.due(n + 1) > total, "{total}: {n}");
        }
    }
}
