//! The wallet's bridges ([`licash_wallet::bridges`]): accounts at NWC
//! bridges, each a wallet of its own at a hub that apps pay and are paid
//! through over Nostr Wallet Connect, the phone topping them up out of its
//! notes, by hand or by rules, and connecting apps. And the notes a frozen
//! bridge exported, for the phone's recoveries to claim should its hub
//! stop cooperating ([`licash_wallet::Wallet::import_notes`]).
//!
//! Bridges count in millisatoshis; what this shows is in satoshis, whole
//! ones down.

use licash_api::bridge::{self, Budget, Connect, Direction, Permission};
use licash_wallet::{AddedBridge, BridgeRules};

use super::Wallet;
use crate::{LicashError, State};

/// A bridge added ([`Wallet::add_bridge`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Bridge {
    pub url: String,
    pub name: Option<String>,
    /// The hub it pays and is paid through.
    pub hub: String,
    /// Whether anyone may keep an account there, or only its owner.
    pub open: bool,
    /// The most an account may hold, and one payment be, if bounded.
    pub max_balance: Option<u64>,
    pub max_payment: Option<u64>,
    /// Whether it serves Lightning Addresses ([`Wallet::bridge_address`]).
    pub addresses: bool,
    pub rules: Option<TopUpRules>,
    /// When added, in seconds since 1970.
    pub created_at: i64,
}

/// When to top up a bridge account, each round: once it holds less than
/// `below`, up to `up_to`, at most `daily` in any day, each top-up's
/// Lightning fee at most `max_fee` if given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TopUpRules {
    pub below: u64,
    pub up_to: u64,
    pub daily: u64,
    pub max_fee: Option<u64>,
}

/// The wallet's account at a bridge ([`Wallet::bridge_account`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BridgeAccount {
    pub balance: u64,
    /// Held for payments under way.
    pub reserved: u64,
    pub apps: Vec<BridgeApp>,
    /// Its payments and invoices, newest first.
    pub activity: Vec<BridgeLine>,
    pub lightning_address: Option<String>,
}

/// An app connected to a bridge account over NWC.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BridgeApp {
    /// Its key, in hex: what revokes it.
    pub key: String,
    pub name: String,
    pub pay: bool,
    pub receive: bool,
    pub max_payment: Option<u64>,
    /// What it may pay each `period`, and paid in this one.
    pub budget: Option<u64>,
    pub period: Option<BudgetPeriod>,
    pub spent: u64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
    pub created_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum BudgetPeriod {
    Daily,
    Weekly,
    Monthly,
    Yearly,
    /// Once, for good.
    Never,
}

/// What an app connected may do ([`Wallet::connect_app`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AppTerms {
    pub name: String,
    pub pay: bool,
    pub receive: bool,
    pub max_payment: Option<u64>,
    pub budget: Option<u64>,
    pub period: BudgetPeriod,
    pub expires_at: Option<i64>,
}

/// An app connected: the NWC URI to give it, shown once.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConnectedApp {
    pub uri: String,
    pub app: BridgeApp,
}

/// A payment or invoice of a bridge account.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BridgeLine {
    pub incoming: bool,
    pub state: State,
    pub amount: u64,
    pub fee: u64,
    /// The key of the app that made it, if one did.
    pub app: Option<String>,
    pub description: Option<String>,
    pub created_at: i64,
    pub settled_at: Option<i64>,
}

/// A top-up made, by hand or by the rules ([`Wallet::top_up_bridges`]):
/// what the account is credited once paid, or why it was not made.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct BridgeTopUp {
    pub url: String,
    pub credits: u64,
    pub error: Option<String>,
}

/// Notes a frozen bridge exported, imported ([`Wallet::import_notes`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImportedNotes {
    /// The Nostr key of the bridge, in hex.
    pub source: String,
    pub added: u32,
    pub amount: u64,
    /// Imported before.
    pub known: u32,
    /// Of a keyset the wallet never held, left out.
    pub unknown: u32,
    /// The refunds of the bridge's payments stuck, new, and what they are
    /// worth in sat: claimed once expired on Bitcoin.
    #[uniffi(default = 0)]
    pub locks: u32,
    #[uniffi(default = 0)]
    pub locked: u64,
}

/// A bridge's export ([`Wallet::export_bridge`]): imported, and the
/// export itself, in hex, to keep.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ExportedNotes {
    pub imported: ImportedNotes,
    pub export: String,
}

/// The notes imported of one bridge ([`Wallet::imported_notes`]).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ImportSource {
    pub source: String,
    pub notes: u32,
    pub amount: u64,
    /// Claimed by a recovery (notes and locks), and dropped from one for
    /// good.
    pub claimed: u32,
    pub dropped: u32,
    /// The refunds of its payments stuck, and what they are worth in sat.
    #[uniffi(default = 0)]
    pub locks: u32,
    #[uniffi(default = 0)]
    pub locked: u64,
}

#[uniffi::export]
impl Wallet {
    /// The bridges added, oldest first.
    pub fn bridges(&self) -> Result<Vec<Bridge>, LicashError> {
        Ok(self.wallet.bridges()?.iter().map(shown).collect())
    }

    /// Add the bridge at `url`, its account registered with the pairing
    /// code its operator gave if it keeps only its owner's.
    pub fn add_bridge(&self, url: String, pairing: Option<String>) -> Result<Bridge, LicashError> {
        let _timed = crate::log::timed("add_bridge");
        let pairing = pairing
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty());
        let added = self.operation(self.wallet.add_bridge(&url, pairing.as_deref()));
        Ok(shown(&added?.0))
    }

    /// Forget the bridge at `url`: its account stays there.
    pub fn remove_bridge(&self, url: String) -> Result<(), LicashError> {
        Ok(self.wallet.remove_bridge(&url)?)
    }

    /// Top the bridge at `url` up by `rules` each round, or no more.
    pub fn set_bridge_rules(
        &self,
        url: String,
        rules: Option<TopUpRules>,
    ) -> Result<(), LicashError> {
        let rules = rules.map(|r| BridgeRules {
            below: r.below,
            up_to: r.up_to,
            daily: r.daily,
            max_fee: r.max_fee,
        });
        Ok(self.wallet.set_bridge_rules(&url, rules)?)
    }

    /// The wallet's account at the bridge at `url`, as it says.
    pub fn bridge_account(&self, url: String) -> Result<BridgeAccount, LicashError> {
        let account = self.operation(self.wallet.bridge_account(&url))?;
        Ok(account_of(account))
    }

    /// Connect an app to the account at the bridge at `url`, on `terms`.
    pub fn connect_app(&self, url: String, terms: AppTerms) -> Result<ConnectedApp, LicashError> {
        let _timed = crate::log::timed("connect_app");
        let name = terms.name.trim().to_owned();
        if name.is_empty() {
            return Err(LicashError::invalid("an app is named"));
        }
        let permissions = (terms.pay.then_some(Permission::Pay).into_iter())
            .chain(terms.receive.then_some(Permission::Receive))
            .collect::<Vec<_>>();
        if permissions.is_empty() {
            return Err(LicashError::invalid("an app may pay, be paid, or both"));
        }
        let connect = Connect {
            name,
            permissions,
            max_payment: terms.max_payment.map(msat_of).transpose()?,
            budget: (terms.budget.map(msat_of).transpose()?).map(|amount| Budget {
                amount,
                period: period_of(terms.period),
            }),
            expires_at: terms.expires_at,
        };
        let connected = self.operation(self.wallet.bridge_connect(&url, &connect))?;
        Ok(ConnectedApp {
            uri: connected.uri,
            app: app_of(connected.connection),
        })
    }

    /// Revoke the app of key `key` at the bridge at `url`, for good.
    pub fn revoke_app(&self, url: String, key: String) -> Result<BridgeApp, LicashError> {
        Ok(app_of(
            self.operation(self.wallet.bridge_revoke(&url, &key))?,
        ))
    }

    /// Name the account's Lightning Address at the bridge at `url`, or
    /// none: the account as it then is.
    pub fn bridge_address(
        &self,
        url: String,
        name: Option<String>,
    ) -> Result<BridgeAccount, LicashError> {
        let name = name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
        let account = self.operation(self.wallet.bridge_username(&url, name.as_deref()))?;
        Ok(account_of(account))
    }

    /// Top the account at the bridge at `url` up by `amount`, out of the
    /// notes at the hub holding the most, its Lightning fee at most
    /// `max_fee` if given. The bridge's hub keeps its fee on receiving.
    pub fn top_up_bridge(
        &self,
        url: String,
        amount: u64,
        max_fee: Option<u64>,
    ) -> Result<BridgeTopUp, LicashError> {
        let _timed = crate::log::timed("top_up_bridge");
        let hub = self.richest()?;
        let topped = self.operation(self.wallet.top_up_bridge(&url, &hub, amount, max_fee))?;
        Ok(BridgeTopUp {
            url: topped.url,
            credits: topped.invoice.credits / 1000,
            error: None,
        })
    }

    /// Have the bridge at `url` pay `amount` of the account back to the
    /// wallet, at the hub holding the most: where its payment stands.
    pub fn withdraw_bridge(&self, url: String, amount: u64) -> Result<State, LicashError> {
        let _timed = crate::log::timed("withdraw_bridge");
        let hub = self.richest()?;
        let (_, payment) = self.operation(self.wallet.withdraw_bridge(&url, &hub, amount))?;
        Ok(state_of(payment.state))
    }

    /// Top up each bridge whose rules say so, out of the notes at the hub
    /// holding the most: none while no hub holds any.
    pub fn top_up_bridges(&self) -> Result<Vec<BridgeTopUp>, LicashError> {
        if !self.wallet.bridges()?.iter().any(|b| b.rules.is_some()) {
            return Ok(Vec::new());
        }
        let Ok(hub) = self.richest() else {
            return Ok(Vec::new());
        };
        let _timed = crate::log::timed("top_up_bridges");
        let _background = licash_wallet::Background::enter();
        let done = self.runtime.block_on(self.wallet.top_up_bridges(&hub))?;
        Ok((done.into_iter())
            .map(|(url, topped)| match topped {
                Ok(topped) => BridgeTopUp {
                    url,
                    credits: topped.invoice.credits / 1000,
                    error: None,
                },
                Err(e) => BridgeTopUp {
                    url,
                    credits: 0,
                    error: Some(e.to_string()),
                },
            })
            .collect())
    }

    /// Freeze the bridge at `url` for good and import its notes, for the
    /// wallet's recoveries to claim should its hub stop cooperating. It
    /// pays nothing out from then on, until its operator unfreezes it.
    pub fn export_bridge(&self, url: String) -> Result<ExportedNotes, LicashError> {
        let _timed = crate::log::timed("export_bridge");
        let (imported, export) = self.operation(self.wallet.export_bridge(&url))?;
        Ok(ExportedNotes {
            imported: imported_of(imported),
            export: hex::encode(export),
        })
    }

    /// Import the notes of a frozen bridge, its export in hex, as its
    /// operator gave it.
    pub fn import_notes(&self, export: String) -> Result<ImportedNotes, LicashError> {
        let export = hex::decode(export.trim())
            .map_err(|_| LicashError::invalid("not an export of notes"))?;
        Ok(imported_of(self.wallet.import_notes(&export)?))
    }

    /// The notes imported, by bridge.
    pub fn imported_notes(&self) -> Result<Vec<ImportSource>, LicashError> {
        let sources = self.wallet.imported_notes()?;
        Ok((sources.into_iter())
            .map(|s| ImportSource {
                source: s.source,
                notes: count(s.notes),
                amount: s.amount,
                claimed: count(s.claimed),
                dropped: count(s.void),
                locks: count(s.locks),
                locked: s.locked,
            })
            .collect())
    }

    /// Forget the notes imported of the bridge of key `source`, for it to
    /// be unfrozen: refused while a recovery claims them.
    pub fn discard_imported(&self, source: String) -> Result<u32, LicashError> {
        Ok(count(self.wallet.discard_imported(&source)?))
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

fn msat_of(sat: u64) -> Result<u64, LicashError> {
    sat.checked_mul(1000)
        .ok_or_else(|| LicashError::invalid("an amount out of range"))
}

fn shown(added: &AddedBridge) -> Bridge {
    let info = &added.info;
    Bridge {
        url: added.url.clone(),
        name: info.name.clone(),
        hub: info.hub.clone(),
        open: info.open,
        max_balance: info.max_balance.map(|m| m / 1000),
        max_payment: info.max_payment.map(|m| m / 1000),
        addresses: info.lightning_address.is_some(),
        rules: added.rules.map(|r| TopUpRules {
            below: r.below,
            up_to: r.up_to,
            daily: r.daily,
            max_fee: r.max_fee,
        }),
        created_at: added.created_at,
    }
}

fn account_of(account: bridge::Account) -> BridgeAccount {
    BridgeAccount {
        balance: account.balance / 1000,
        reserved: account.reserved / 1000,
        apps: account.connections.into_iter().map(app_of).collect(),
        activity: (account.activity.into_iter())
            .map(|a| BridgeLine {
                incoming: a.direction == Direction::Incoming,
                state: state_of(a.state),
                amount: a.amount / 1000,
                fee: a.fee / 1000,
                app: a.connection,
                description: a.description,
                created_at: a.created_at,
                settled_at: a.settled_at,
            })
            .collect(),
        lightning_address: account.lightning_address,
    }
}

fn app_of(c: bridge::Connection) -> BridgeApp {
    BridgeApp {
        pay: c.permissions.contains(&Permission::Pay),
        receive: c.permissions.contains(&Permission::Receive),
        max_payment: c.max_payment.map(|m| m / 1000),
        budget: c.budget.as_ref().map(|b| b.amount / 1000),
        period: c.budget.as_ref().map(|b| match b.period {
            bridge::Period::Daily => BudgetPeriod::Daily,
            bridge::Period::Weekly => BudgetPeriod::Weekly,
            bridge::Period::Monthly => BudgetPeriod::Monthly,
            bridge::Period::Yearly => BudgetPeriod::Yearly,
            bridge::Period::Never => BudgetPeriod::Never,
        }),
        spent: c.spent / 1000,
        key: c.key,
        name: c.name,
        expires_at: c.expires_at,
        revoked: c.revoked,
        created_at: c.created_at,
    }
}

fn period_of(period: BudgetPeriod) -> bridge::Period {
    match period {
        BudgetPeriod::Daily => bridge::Period::Daily,
        BudgetPeriod::Weekly => bridge::Period::Weekly,
        BudgetPeriod::Monthly => bridge::Period::Monthly,
        BudgetPeriod::Yearly => bridge::Period::Yearly,
        BudgetPeriod::Never => bridge::Period::Never,
    }
}

fn state_of(state: bridge::State) -> State {
    match state {
        bridge::State::Settled => State::Done,
        bridge::State::Pending => State::Pending,
        bridge::State::Failed | bridge::State::Expired => State::Failed,
    }
}

fn imported_of(imported: licash_wallet::Imported) -> ImportedNotes {
    ImportedNotes {
        source: imported.source,
        added: count(imported.added),
        amount: imported.amount,
        known: count(imported.known),
        unknown: count(imported.unknown),
        locks: count(imported.locks),
        locked: imported.locked,
    }
}
