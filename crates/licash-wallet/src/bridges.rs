//! Licash bridges ([`licash_api::bridge`]): Nostr Wallet Connect services
//! keeping an account for this wallet, which it tops up in Lightning
//! payments through its hubs, by hand or by rules, and connects apps to.
//!
//! The wallet's key at a bridge derives from its seed and the bridge's
//! Nostr key, so the same seed finds the same account again: added anew
//! after a restore, a bridge answers the account it kept. A bridge holds
//! its accounts' sats itself: custodial, as little as the rules keep there.

use licash::crypto::tagged_hash;
use licash_api::bridge::{
    self, Account, Connect, Connected, Connection, Empty, Exported, Info, Invoice, Payment,
    Register, Revoke, Signed, State, TopUp, Username, Withdraw,
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use crate::{Code, Error, Lock, LockState, Problem, Response, Transport, Wallet};

const COMPONENT: &str = "bridges";
const VERSION: i64 = 1;

/// No foreign keys, indexes or triggers, as the codes' tables.
const SCHEMA: &str = "
-- The bridges added, by URL: the Nostr key each answers as, which the
-- wallet's key there derives from, what it last said of itself as JSON,
-- and its top-up rules in sat, if any.
CREATE TABLE bridges (
    url TEXT PRIMARY KEY,
    nostr BLOB NOT NULL,
    info TEXT NOT NULL,
    below INTEGER,
    up_to INTEGER,
    daily INTEGER,
    max_fee INTEGER,
    created_at INTEGER NOT NULL
) STRICT;
-- The top-ups paid, recorded before paying: what the daily limit counts.
CREATE TABLE bridge_top_ups (
    hash BLOB PRIMARY KEY,
    url TEXT NOT NULL,
    amount INTEGER NOT NULL,
    lock TEXT,
    created_at INTEGER NOT NULL
) STRICT;
";

/// A day, in seconds: what [`BridgeRules::daily`] is a limit of.
const DAY: i64 = 86_400;

/// When to top up a bridge account, by [`Wallet::top_up_bridges`]: once it
/// holds less than `below` sat, up to `up_to`, at most `daily` sat in any
/// day, each payment's Lightning fee at most `max_fee` sat if given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeRules {
    pub below: u64,
    pub up_to: u64,
    pub daily: u64,
    pub max_fee: Option<u64>,
}

impl BridgeRules {
    fn check(&self) -> Result<(), Error> {
        if self.up_to == 0 || self.below > self.up_to {
            return Err(Error::Invalid(
                "top-up rules topping up to more than 0 sat, from below that".into(),
            ));
        }
        if self.daily == 0 {
            return Err(Error::Invalid(
                "top-up rules of a daily limit above 0 sat".into(),
            ));
        }
        Ok(())
    }
}

/// A bridge the wallet added ([`Wallet::add_bridge`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddedBridge {
    pub url: String,
    /// What it said of itself, last asked.
    pub info: Info,
    pub rules: Option<BridgeRules>,
    pub created_at: i64,
}

/// A top-up paid ([`Wallet::top_up_bridge`]): the bridge's invoice and
/// the wallet's lock paying it, which `resume` finishes if under way.
#[derive(Clone, Debug)]
pub struct BridgeTopUp {
    pub url: String,
    pub invoice: Invoice,
    pub lock: Lock,
}

/// A bridge's URL as the wallet keys it: http or https, no trailing slash.
fn bridge_url(url: &str) -> Result<String, Error> {
    let url = url.trim().trim_end_matches('/');
    if !(url.starts_with("http://") || url.starts_with("https://"))
        || url.contains(char::is_whitespace)
    {
        return Err(Error::Invalid(format!("not a bridge URL: {url}")));
    }
    Ok(url.to_owned())
}

fn nostr_key(info: &Info) -> Result<[u8; 32], Error> {
    let mut key = [0; 32];
    hex::decode_to_slice(&info.nostr, &mut key)
        .map_err(|_| Error::Invalid("a bridge naming no Nostr key".into()))?;
    Ok(key)
}

/// What the bridge at `url` answered at `path`: its body, or its problem.
fn answer<A: DeserializeOwned>(url: &str, path: &str, response: &Response) -> Result<A, Error> {
    let unavailable = |reason: String| Error::Unavailable {
        hub: url.to_owned(),
        reason,
    };
    if (200..300).contains(&response.status) {
        return serde_json::from_slice(&response.body)
            .map_err(|e| unavailable(format!("{path}: {e}")));
    }
    match serde_json::from_slice::<Problem>(&response.body) {
        Ok(problem) if problem.code == Code::Unavailable => Err(unavailable(problem.message)),
        Ok(problem) => Err(Error::Invalid(format!(
            "bridge {url} refused: {}",
            problem.message
        ))),
        Err(_) => Err(unavailable(format!("{path}: status {}", response.status))),
    }
}

fn component_version(c: &rusqlite::Connection) -> Result<Option<i64>, Error> {
    licash_store::component_version(c, COMPONENT).map_err(stored)
}

fn stored(e: licash_store::Error) -> Error {
    match e {
        licash_store::Error::Sqlite(e) => Error::Storage(e),
        e => Error::Setup(e.to_string()),
    }
}

/// Make the bridges' tables in `tx`, if none: refused if a later version
/// keeps them.
fn writable(tx: &Transaction) -> Result<(), Error> {
    match component_version(tx)? {
        Some(VERSION) => Ok(()),
        Some(_) => Err(Error::Invalid(
            "bridges, the wallet's file keeping them as a later version does".into(),
        )),
        None => licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(stored),
    }
}

type Row = (String, Vec<u8>, String, [Option<i64>; 4], i64);

fn added((url, _, info, rules, created_at): Row) -> Result<AddedBridge, Error> {
    let info = serde_json::from_str(&info).map_err(crate::invalid)?;
    let rules = match rules {
        [Some(below), Some(up_to), Some(daily), max_fee] => Some(BridgeRules {
            below: below as u64,
            up_to: up_to as u64,
            daily: daily as u64,
            max_fee: max_fee.map(|f| f as u64),
        }),
        _ => None,
    };
    Ok(AddedBridge {
        url,
        info,
        rules,
        created_at,
    })
}

const BRIDGE: &str =
    "SELECT url, nostr, info, below, up_to, daily, max_fee, created_at FROM bridges";

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        [r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?],
        r.get(7)?,
    ))
}

fn sql(sat: u64) -> Result<i64, Error> {
    i64::try_from(sat).map_err(|_| Error::Invalid("an amount out of range".into()))
}

impl<T: Transport> Wallet<T> {
    /// The bridges added, by URL.
    pub fn bridges(&self) -> Result<Vec<AddedBridge>, Error> {
        let rows: Vec<Row> = self.store.read(|c| {
            if component_version(c)? != Some(VERSION) {
                return Ok(Vec::new());
            }
            let mut stmt = c.prepare(&format!("{BRIDGE} ORDER BY url"))?;
            let rows = stmt.query_map([], row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        rows.into_iter().map(added).collect()
    }

    /// The bridge added at `url`.
    pub fn bridge(&self, url: &str) -> Result<AddedBridge, Error> {
        let url = bridge_url(url)?;
        let found: Option<Row> = self.store.read(|c| {
            if component_version(c)? != Some(VERSION) {
                return Ok(None);
            }
            Ok(
                c.query_row(&format!("{BRIDGE} WHERE url = ?1"), [&url], row)
                    .optional()?,
            )
        })?;
        let found = found
            .ok_or_else(|| Error::Invalid(format!("no bridge {url}: `bridge add` adds it")))?;
        added(found)
    }

    /// The wallet's secret key at the bridge answering as `nostr`.
    pub(crate) fn bridge_secret(&self, nostr: &[u8; 32]) -> [u8; 32] {
        tagged_hash("licash/bridge/account", &[&self.keys.bridges, nostr])
    }

    /// The wallet's key at the bridge answering as `nostr`, in hex: what
    /// the bridge knows its account by.
    pub fn bridge_key(&self, info: &Info) -> Result<String, Error> {
        let secret = licash::crypto::ScalarBytes(self.bridge_secret(&nostr_key(info)?))
            .to_scalar()
            .map_err(|_| Error::Setup("no bridge key from this seed".into()))?;
        Ok(hex::encode(licash::crypto::x_only_pub(&secret)))
    }

    async fn bridge_info(&self, url: &str) -> Result<Info, Error> {
        let response = self
            .transport
            .request(&format!("{url}{}", bridge::INFO), None)
            .await
            .map_err(|reason| Error::Unavailable {
                hub: url.to_owned(),
                reason,
            })?;
        answer(url, bridge::INFO, &response)
    }

    /// Ask the bridge added at `url`, or about to be as `info` says, at
    /// `path`, signed by the wallet's key there.
    async fn bridge_call<A: DeserializeOwned>(
        &self,
        url: &str,
        info: &Info,
        path: &str,
        request: &impl Serialize,
    ) -> Result<A, Error> {
        let request = serde_json::to_string(request).map_err(crate::invalid)?;
        let secret = self.bridge_secret(&nostr_key(info)?);
        let signed = Signed::sign(&secret, path, licash_store::now(), request)
            .map_err(|p| Error::Invalid(p.message))?;
        let body = serde_json::to_vec(&signed).map_err(crate::invalid)?;
        let response = self
            .transport
            .request(&format!("{url}{path}"), Some(body))
            .await
            .map_err(|reason| Error::Unavailable {
                hub: url.to_owned(),
                reason,
            })?;
        answer(url, path, &response)
    }

    /// Add the bridge at `url`, or learn again what it says of itself: its
    /// account registered, with the pairing code its operator gave if it
    /// keeps only its owner's. Refused if it is of another network, or
    /// answers as another bridge than the one added at `url`.
    pub async fn add_bridge(
        &self,
        url: &str,
        pairing: Option<&str>,
    ) -> Result<(AddedBridge, Account), Error> {
        let url = bridge_url(url)?;
        let info = self.bridge_info(&url).await?;
        let network = self.network().to_string();
        if info.network != network {
            return Err(Error::Invalid(format!(
                "bridge {url} is on {}, the wallet on {network}",
                info.network
            )));
        }
        let nostr = nostr_key(&info)?;
        let register = Register {
            pairing: pairing.map(str::to_owned),
        };
        let account: Account = self
            .bridge_call(&url, &info, bridge::REGISTER, &register)
            .await?;
        let json = serde_json::to_string(&info).map_err(crate::invalid)?;
        self.store.write(|tx| {
            writable(tx)?;
            let known: Option<Vec<u8>> = tx
                .query_row("SELECT nostr FROM bridges WHERE url = ?1", [&url], |r| {
                    r.get(0)
                })
                .optional()?;
            match known {
                Some(known) if known != nostr => Err(Error::Invalid(format!(
                    "bridge {url} answers as another bridge than the one added: \
                     `bridge remove` it first"
                ))),
                Some(_) => {
                    tx.execute(
                        "UPDATE bridges SET info = ?2 WHERE url = ?1",
                        params![url, json],
                    )?;
                    Ok(())
                }
                None => {
                    tx.execute(
                        "INSERT INTO bridges (url, nostr, info, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![url, nostr.to_vec(), json, licash_store::now()],
                    )?;
                    Ok(())
                }
            }
        })?;
        Ok((self.bridge(&url)?, account))
    }

    /// Forget the bridge at `url`, and its rules: its account stays at the
    /// bridge, found again by adding it anew.
    pub fn remove_bridge(&self, url: &str) -> Result<(), Error> {
        let url = self.bridge(url)?.url;
        self.store.write(|tx| {
            tx.execute("DELETE FROM bridges WHERE url = ?1", [&url])?;
            Ok(())
        })
    }

    /// Top up the bridge at `url` with `rules`, or never again if none.
    pub fn set_bridge_rules(&self, url: &str, rules: Option<BridgeRules>) -> Result<(), Error> {
        let url = self.bridge(url)?.url;
        if let Some(rules) = &rules {
            rules.check()?;
        }
        let values = match rules {
            Some(r) => [
                Some(sql(r.below)?),
                Some(sql(r.up_to)?),
                Some(sql(r.daily)?),
                r.max_fee.map(sql).transpose()?,
            ],
            None => [None; 4],
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE bridges SET below = ?2, up_to = ?3, daily = ?4, max_fee = ?5
                 WHERE url = ?1",
                params![url, values[0], values[1], values[2], values[3]],
            )?;
            Ok(())
        })
    }

    /// The wallet's account at the bridge at `url`, as it stands.
    pub async fn bridge_account(&self, url: &str) -> Result<Account, Error> {
        let added = self.bridge(url)?;
        self.bridge_call(&added.url, &added.info, bridge::ACCOUNT, &bridge::Empty {})
            .await
    }

    /// A new NWC connection of the wallet's account at `url`: its URI, for
    /// the app, carries its secret.
    pub async fn bridge_connect(&self, url: &str, connect: &Connect) -> Result<Connected, Error> {
        let added = self.bridge(url)?;
        self.bridge_call(&added.url, &added.info, bridge::CONNECT, connect)
            .await
    }

    /// Name the account's Lightning Address at `url` `name@`, its domain the
    /// bridge's, or none.
    pub async fn bridge_username(&self, url: &str, name: Option<&str>) -> Result<Account, Error> {
        let added = self.bridge(url)?;
        let named = Username {
            username: name.map(str::to_owned),
        };
        self.bridge_call(&added.url, &added.info, bridge::USERNAME, &named)
            .await
    }

    /// Freeze the bridge at `url` for good and import its notes, sealed to
    /// the wallet's key there, for the wallet's recoveries to claim should
    /// its hub stop cooperating ([`Wallet::import_notes`]): what was
    /// imported, and the export, to keep. Of a bridge for this wallet
    /// alone; it pays nothing out from then on, until unfrozen by its
    /// operator once the import is discarded.
    pub async fn export_bridge(&self, url: &str) -> Result<(crate::Imported, Vec<u8>), Error> {
        let added = self.bridge(url)?;
        let exported: Exported = self
            .bridge_call(&added.url, &added.info, bridge::EXPORT, &Empty {})
            .await?;
        let imported = self.import_notes(&exported.export.0)?;
        if imported.source != added.info.nostr {
            tracing::warn!(url = %added.url, "a bridge's export of another Nostr key");
        }
        Ok((imported, exported.export.0))
    }

    /// Revoke the NWC connection of key `client`, in hex, for good.
    pub async fn bridge_revoke(&self, url: &str, client: &str) -> Result<Connection, Error> {
        let added = self.bridge(url)?;
        let revoke = Revoke {
            key: client.trim().to_owned(),
        };
        self.bridge_call(&added.url, &added.info, bridge::REVOKE, &revoke)
            .await
    }

    /// Pay the bridge at `url` `amount` sat into the wallet's account
    /// there, through the hub at `hub`, its Lightning fee at most `max_fee`
    /// sat if given. The bridge's hub keeps its fee on receiving out of it.
    pub async fn top_up_bridge(
        &self,
        url: &str,
        hub: &str,
        amount: u64,
        max_fee: Option<u64>,
    ) -> Result<BridgeTopUp, Error> {
        self.top_up(url, hub, amount, max_fee, None).await
    }

    /// [`Wallet::top_up_bridge`]; if `recent`, the number of top-ups of
    /// the bridge in the last day its rules counted, refused if another was
    /// recorded meanwhile.
    async fn top_up(
        &self,
        url: &str,
        hub: &str,
        amount: u64,
        max_fee: Option<u64>,
        recent: Option<usize>,
    ) -> Result<BridgeTopUp, Error> {
        let added = self.bridge(url)?;
        let msat = amount
            .checked_mul(1000)
            .filter(|msat| *msat > 0)
            .ok_or_else(|| Error::Invalid("a top-up of more than 0 sat".into()))?;
        let invoice: Invoice = self
            .bridge_call(
                &added.url,
                &added.info,
                bridge::TOP_UP,
                &TopUp { amount: msat },
            )
            .await?;
        let decoded: lightning_invoice::Bolt11Invoice = invoice
            .invoice
            .parse()
            .map_err(|_| Error::Invalid(format!("bridge {} answered no invoice", added.url)))?;
        let hash: [u8; 32] = *decoded.payment_hash().as_ref();
        if decoded.amount_milli_satoshis() != Some(msat) || hex::encode(hash) != invoice.hash {
            return Err(Error::Invalid(format!(
                "bridge {} answered an invoice of another amount",
                added.url
            )));
        }
        // The bridge picks the invoice: one paid before, or that cannot be
        // paid, is refused before anything is recorded of it.
        if decoded.is_expired() {
            return Err(Error::Invalid(format!(
                "bridge {} answered an expired invoice",
                added.url
            )));
        }
        // Recorded first: a top-up the wallet stopped paying still counts.
        self.store.write(|tx| {
            let known: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM bridge_top_ups WHERE hash = ?1)",
                [hash.to_vec()],
                |r| r.get(0),
            )?;
            if known {
                return Err(Error::Invalid(format!(
                    "bridge {} answered the invoice of an earlier top-up",
                    added.url
                )));
            }
            if let Some(recent) = recent {
                let now: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM bridge_top_ups WHERE url = ?1 AND created_at > ?2",
                    params![added.url, licash_store::now() - DAY],
                    |r| r.get(0),
                )?;
                if now as usize != recent {
                    return Err(Error::Invalid(format!(
                        "another top-up of bridge {} meanwhile",
                        added.url
                    )));
                }
            }
            tx.execute(
                "INSERT INTO bridge_top_ups (hash, url, amount, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![hash.to_vec(), added.url, sql(amount)?, licash_store::now()],
            )?;
            Ok(())
        })?;
        let paid = self
            .pay_invoice_within(hub, &invoice.invoice, max_fee)
            .await;
        let lock = match paid {
            Ok(lock) => lock,
            Err(e) => {
                // A lock is recorded before its hub hears of it: none, and
                // nothing was sent, so the top-up never counts.
                let lock = self.locks()?.into_iter().find(|l| l.hash == hash);
                self.store.write(|tx| {
                    match &lock {
                        None => tx.execute(
                            "DELETE FROM bridge_top_ups WHERE hash = ?1",
                            [hash.to_vec()],
                        )?,
                        Some(lock) => tx.execute(
                            "UPDATE bridge_top_ups SET lock = ?2 WHERE hash = ?1",
                            params![hash.to_vec(), lock.id],
                        )?,
                    };
                    Ok(())
                })?;
                return Err(e);
            }
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE bridge_top_ups SET lock = ?2 WHERE hash = ?1",
                params![hash.to_vec(), lock.id],
            )?;
            Ok(())
        })?;
        Ok(BridgeTopUp {
            url: added.url,
            invoice,
            lock,
        })
    }

    /// Have the bridge at `url` pay `amount` sat out of the wallet's
    /// account there back to the wallet, at the hub at `hub`, whose fee on
    /// receiving the bridge pays on top. Where the bridge's payment stands;
    /// `resume` takes it at the hub once made.
    pub async fn withdraw_bridge(
        &self,
        url: &str,
        hub: &str,
        amount: u64,
    ) -> Result<(crate::Invoice, Payment), Error> {
        let added = self.bridge(url)?;
        let invoice = self.invoice(hub, amount).await?;
        let request = invoice
            .request
            .clone()
            .ok_or_else(|| Error::Invalid(format!("hub {hub} made no invoice yet")))?;
        let withdraw = Withdraw {
            invoice: request,
            max_fee: None,
        };
        let call = self.bridge_call(&added.url, &added.info, bridge::WITHDRAW, &withdraw);
        // The bridge answers once paid, which takes the wallet claiming
        // the payment meanwhile.
        let hash = invoice.hash.clone();
        let follow = async {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                match self.follow_invoice(&hash).await {
                    Ok(i) if i.state != crate::InvoiceState::Open => break,
                    _ => {}
                }
            }
        };
        let (mut call, mut follow) = (std::pin::pin!(call), std::pin::pin!(follow));
        let mut followed = false;
        let payment = std::future::poll_fn(|cx| {
            if let std::task::Poll::Ready(paid) = std::future::Future::poll(call.as_mut(), cx) {
                return std::task::Poll::Ready(paid);
            }
            if !followed && std::future::Future::poll(follow.as_mut(), cx).is_ready() {
                followed = true;
            }
            std::task::Poll::Pending
        })
        .await;
        Ok((invoice, payment?))
    }

    /// What the rules of the bridge `added` top it up by now, in sat, and
    /// how many top-ups of the last day they counted: none if no rules, or
    /// above them, or a top-up of the last day is under way or not
    /// credited yet. Each counts unless the wallet's lock paying it was
    /// given back, followed first if under way.
    async fn bridge_due(&self, added: &AddedBridge) -> Result<Option<(u64, usize)>, Error> {
        let Some(rules) = added.rules else {
            return Ok(None);
        };
        let since = licash_store::now() - DAY;
        let recent: Vec<(Vec<u8>, i64)> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash, amount FROM bridge_top_ups WHERE url = ?1 AND created_at > ?2",
            )?;
            let rows = stmt.query_map(params![added.url, since], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let account = self.bridge_account(&added.url).await?;
        let locks = self.locks()?;
        let mut spent = 0u64;
        for (hash, amount) in &recent {
            let hash: [u8; 32] = hash.as_slice().try_into().map_err(crate::invalid)?;
            let lock = locks.iter().find(|l| l.hash == hash).cloned();
            let lock = match lock {
                Some(l) if matches!(l.state, LockState::Requested | LockState::Locked) => {
                    Some(self.follow_lock(&l.id).await.unwrap_or(l))
                }
                lock => lock,
            };
            match lock.map(|l| l.state) {
                Some(LockState::Refunded | LockState::Abandoned(_)) => continue,
                Some(LockState::Requested | LockState::Locked) => return Ok(None),
                Some(LockState::Paid(_)) => {
                    let hash = hex::encode(hash);
                    let crediting = account
                        .activity
                        .iter()
                        .any(|a| a.hash == hash && a.state == State::Pending);
                    if crediting {
                        return Ok(None);
                    }
                }
                // Being paid by another process, or stopped before its
                // lock was made: counted.
                None => {}
            }
            spent = spent.saturating_add(*amount as u64);
        }
        // Payments under way are as good as spent.
        let balance = account.balance / 1000;
        if balance >= rules.below {
            return Ok(None);
        }
        let mut amount = rules.up_to - balance;
        amount = amount.min(rules.daily.saturating_sub(spent));
        if let Some(max) = added.info.max_balance {
            amount = amount.min((max / 1000).saturating_sub(balance));
        }
        Ok((amount > 0).then_some((amount, recent.len())))
    }

    /// Top up each bridge whose rules say so ([`BridgeRules`]), through
    /// the hub at `hub`: what each top-up came to, by bridge.
    pub async fn top_up_bridges(
        &self,
        hub: &str,
    ) -> Result<Vec<(String, Result<BridgeTopUp, Error>)>, Error> {
        let bridges = self.bridges()?;
        let mut done = Vec::new();
        for added in bridges.iter().filter(|b| b.rules.is_some()) {
            let topped = match self.bridge_due(added).await {
                Ok(Some((amount, recent))) => {
                    let max_fee = added.rules.and_then(|r| r.max_fee);
                    self.top_up(&added.url, hub, amount, max_fee, Some(recent))
                        .await
                }
                Ok(None) => continue,
                Err(e) => Err(e),
            };
            done.push((added.url.clone(), topped));
        }
        Ok(done)
    }
}
