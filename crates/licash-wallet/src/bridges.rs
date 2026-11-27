//! Licash bridges ([`licash_api::bridge`]): Nostr Wallet Connect services
//! keeping an account for this wallet, which it tops up in notes at the
//! bridge's hub, by hand or by rules, and connects apps to.
//!
//! The wallet's key at a bridge derives from its seed and the bridge's
//! Nostr key, so the same seed finds the same account again: added anew
//! after a restore, a bridge answers the account it kept. A bridge holds
//! its accounts' sats itself: custodial, as little as the rules keep there.

use licash::crypto::tagged_hash;
use licash_api::bridge::{
    self, Account, Connect, Connected, Connection, Deposit, Deposited, Empty, Exported, Info,
    PaidOut, Payout, Register, Revoke, Signed, State, Username,
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    Code, Error, LicashCode, LockState, PaymentNote, Problem, Response, Transport, Wallet,
};

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
-- Each is the payment of notes under the key `hash`, `lock` naming it once
-- the bridge credited it; or, of an earlier release, the lock `lock`
-- paying the bridge's invoice of payment hash `hash`.
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
/// day, each payment's fee at most `max_fee` sat if given.
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

/// A top-up paid ([`Wallet::top_up_bridge`]): the payment of its notes,
/// by its id in hex, and what the bridge credited, in msat, once it said:
/// told again before the next top-up of it if not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeTopUp {
    pub url: String,
    pub id: String,
    pub amount: u64,
    /// The hub's fee on the payment, on top.
    pub fee: u64,
    pub credited: Option<u64>,
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
    /// there, in notes at its hub, the hub's fee at most `max_fee` sat on
    /// top if given. Top-ups paid but not credited yet are told the bridge
    /// first.
    pub async fn top_up_bridge(
        &self,
        url: &str,
        amount: u64,
        max_fee: Option<u64>,
    ) -> Result<BridgeTopUp, Error> {
        let added = self.bridge(url)?;
        self.tell_deposits(&added).await?;
        self.top_up(&added, amount, max_fee, None).await
    }

    /// [`Wallet::top_up_bridge`]; if `recent`, the number of top-ups of
    /// the bridge in the last day its rules counted, refused if another was
    /// recorded meanwhile.
    async fn top_up(
        &self,
        added: &AddedBridge,
        amount: u64,
        max_fee: Option<u64>,
        recent: Option<usize>,
    ) -> Result<BridgeTopUp, Error> {
        if amount == 0 {
            return Err(Error::Invalid("a top-up of more than 0 sat".into()));
        }
        let url = &added.url;
        let ask = Deposit {
            amount,
            payment: None,
        };
        let to: Deposited = (self.bridge_call(url, &added.info, bridge::DEPOSIT, &ask)).await?;
        let code: LicashCode = to.code.parse()?;
        if code.network != self.network() {
            return Err(Error::Invalid(format!(
                "bridge {url} answered a code of another network"
            )));
        }
        // Its hub as the wallet knows it, by the code's: the bridge may
        // reach it at another URL.
        let hub = (self.hub_to_pay(&code, amount)?).ok_or_else(|| {
            Error::Invalid(format!(
                "a top-up of {amount} sat in notes at the bridge's hub, {}: the wallet uses it \
                 and holds that much there, its fee on top",
                to.hub
            ))
        })?;
        let key = self.bridge_key(&added.info)?;
        let note = PaymentNote {
            text: Some(crate::note_text(&bridge::deposit_note(&key))?),
            from: None,
        };
        if !self.notes_on()? {
            return Err(Error::Invalid(
                "a top-up, the wallet's file keeping notes as a later version does".into(),
            ));
        }
        let mut send = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut send);
        // Recorded first: a top-up the wallet stopped paying still counts.
        self.store.write(|tx| {
            if let Some(recent) = recent {
                let now: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM bridge_top_ups WHERE url = ?1 AND created_at > ?2",
                    params![url, licash_store::now() - DAY],
                    |r| r.get(0),
                )?;
                if now as usize != recent {
                    return Err(Error::Invalid(format!(
                        "another top-up of bridge {url} meanwhile"
                    )));
                }
            }
            tx.execute(
                "INSERT INTO bridge_top_ups (hash, url, amount, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![send.to_vec(), url, sql(amount)?, licash_store::now()],
            )?;
            Ok(())
        })?;
        let mailbox = Some(code.mailbox);
        let paid = self
            .send_once(
                &hub,
                &code.address,
                amount,
                mailbox,
                Some(send),
                Some(&note),
                max_fee,
            )
            .await;
        let paid = match paid {
            Ok(paid) => paid,
            Err(e) => {
                // A send is recorded before its hub hears of it: none, and
                // nothing was sent, so the top-up never counts.
                if self.sent_by_key(&send)?.is_none() {
                    self.store.write(|tx| {
                        tx.execute(
                            "DELETE FROM bridge_top_ups WHERE hash = ?1",
                            [send.to_vec()],
                        )?;
                        Ok(())
                    })?;
                }
                return Err(e);
            }
        };
        let fee = self.sent_by_key(&send)?.map_or(0, |sent| sent.fee);
        let credited = self.tell_deposit(added, &send, amount).await?;
        Ok(BridgeTopUp {
            url: url.clone(),
            id: paid.id,
            amount,
            fee,
            credited,
        })
    }

    /// Tell the bridge `added` of the top-up paid under `send`, of
    /// `amount` sat: what it credited, recorded, or none if it did not
    /// answer, to tell again.
    async fn tell_deposit(
        &self,
        added: &AddedBridge,
        send: &[u8; 32],
        amount: u64,
    ) -> Result<Option<u64>, Error> {
        let sent = self.sent_by_key(send)?;
        let Some(sent) = sent.filter(|sent| sent.state == crate::State::Done) else {
            return Ok(None);
        };
        let payment = self.payment(&sent.id)?;
        let deposit = Deposit {
            amount,
            payment: Some(payment),
        };
        let told: Result<Deposited, Error> = self
            .bridge_call(&added.url, &added.info, bridge::DEPOSIT, &deposit)
            .await;
        let credited = match told {
            Ok(Deposited {
                credited: Some(credited),
                ..
            }) => credited,
            Ok(_) => return Ok(None),
            Err(e) => {
                tracing::warn!(url = %added.url, id = %sent.id, "a top-up not credited yet: {e}");
                return Ok(None);
            }
        };
        self.store.write(|tx| {
            tx.execute(
                "UPDATE bridge_top_ups SET lock = ?2 WHERE hash = ?1",
                params![send.to_vec(), credited.id],
            )?;
            Ok(())
        })?;
        Ok(Some(credited.amount))
    }

    /// Tell the bridge `added` of the top-ups of it paid in notes, not
    /// credited yet: those of the last day.
    async fn tell_deposits(&self, added: &AddedBridge) -> Result<(), Error> {
        let since = licash_store::now() - DAY;
        let untold: Vec<(Vec<u8>, i64)> = self.store.read(|c| {
            if component_version(c)? != Some(VERSION) {
                return Ok(Vec::new());
            }
            let mut stmt = c.prepare(
                "SELECT hash, amount FROM bridge_top_ups
                 WHERE url = ?1 AND lock IS NULL AND created_at > ?2",
            )?;
            let rows = stmt.query_map(params![added.url, since], |r| Ok((r.get(0)?, r.get(1)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        for (send, amount) in untold {
            let send: [u8; 32] = send.as_slice().try_into().map_err(crate::invalid)?;
            let done = self
                .sent_by_key(&send)?
                .is_some_and(|sent| sent.state == crate::State::Done);
            if done {
                self.tell_deposit(added, &send, amount as u64).await?;
            }
        }
        Ok(())
    }

    /// Have the bridge at `url` pay `amount` sat out of the wallet's
    /// account there, in notes at its hub, its hub's fee on top out of the
    /// account too: what the wallet took of it, once paid.
    pub async fn withdraw_bridge(&self, url: &str, amount: u64) -> Result<PaidOut, Error> {
        let added = self.bridge(url)?;
        // At the hubs the wallet uses, the bridge's first should the wallet
        // reach it at the URL the bridge does: the bridge pays at its own.
        let mut hubs: Vec<String> = (self.hubs()?.into_iter()).map(|(url, _)| url).collect();
        let first = self.hub_urls(&added.info.hub)?;
        hubs.sort_by_key(|url| !first.contains(url));
        let code = (self.payment_code(&hubs)?.licash)
            .ok_or_else(|| Error::Invalid("no Licash code: the wallet uses no hub".into()))?;
        let mut id = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        let payout = Payout {
            id: hex::encode(id),
            amount,
            code: code.to_string(),
        };
        let paid: PaidOut = self
            .bridge_call(&added.url, &added.info, bridge::PAYOUT, &payout)
            .await?;
        // Kept by its hub too, for `collect_inbox`, should this fail.
        if let Some(payment) = &paid.payment {
            match self.receive(payment) {
                Ok(_) | Err(Error::AlreadyReceived) => {}
                Err(e) => tracing::warn!(url = %added.url, "a payout not taken yet: {e}"),
            }
        }
        Ok(paid)
    }

    /// What the rules of the bridge `added` top it up by now, in sat, and
    /// how many top-ups of the last day they counted: none if no rules, or
    /// above them, or a top-up of the last day is under way or not
    /// credited yet. Each counts unless it was given up before it was
    /// paid: its send, or the wallet's lock paying it in an earlier
    /// release, followed first if under way.
    async fn bridge_due(&self, added: &AddedBridge) -> Result<Option<(u64, usize)>, Error> {
        let Some(rules) = added.rules else {
            return Ok(None);
        };
        self.tell_deposits(added).await?;
        let since = licash_store::now() - DAY;
        type Recent = (Vec<u8>, i64, Option<String>);
        let recent: Vec<Recent> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT hash, amount, lock FROM bridge_top_ups WHERE url = ?1 AND created_at > ?2",
            )?;
            let rows = stmt.query_map(params![added.url, since], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let account = self.bridge_account(&added.url).await?;
        let locks = self.locks()?;
        let mut spent = 0u64;
        for (hash, amount, told) in &recent {
            let hash: [u8; 32] = hash.as_slice().try_into().map_err(crate::invalid)?;
            if let Some(sent) = self.sent_by_key(&hash)? {
                match sent.state {
                    crate::State::Abandoned(_) => continue,
                    // Paid, not credited yet: told again next time.
                    _ if told.is_none() => return Ok(None),
                    _ => {}
                }
                spent = spent.saturating_add(*amount as u64);
                continue;
            }
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
                // Being paid by another process, or stopped before it was
                // sent: counted.
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

    /// Top up each bridge whose rules say so ([`BridgeRules`]), as
    /// [`Wallet::top_up_bridge`]: what each top-up came to, by bridge.
    pub async fn top_up_bridges(&self) -> Result<Vec<(String, Result<BridgeTopUp, Error>)>, Error> {
        let bridges = self.bridges()?;
        let mut done = Vec::new();
        for added in bridges.iter().filter(|b| b.rules.is_some()) {
            let topped = match self.bridge_due(added).await {
                Ok(Some((amount, recent))) => {
                    let max_fee = added.rules.and_then(|r| r.max_fee);
                    self.top_up(added, amount, max_fee, Some(recent)).await
                }
                Ok(None) => continue,
                Err(e) => Err(e),
            };
            done.push((added.url.clone(), topped));
        }
        Ok(done)
    }
}
