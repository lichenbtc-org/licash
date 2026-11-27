//! Accounts paid into and out of in notes at the bridge's hub, for the
//! wallets keeping them there: no Lightning, no provider.
//!
//! A deposit is a payment of notes to the bridge, credited once, by its
//! id, to the account its payer's sealed note names
//! ([`bridge::deposit_note`]). Its hub sees the payment, and could hand it
//! in under an account of its own, but cannot seal a note: whoever hands
//! it in, only the account its payer named is credited, and a payment
//! naming none is the bridge's alone, for its operator to sort out.
//!
//! A payout is a payment of notes to a Licash code, made once under a send
//! key of its account's and the id it picked: what it may cost is taken
//! from the account first, and the wallet's send under that key decides
//! it, whatever the call making it returned.

use licash_api::bridge::{
    self, Activity, Credited, Deposit, Deposited, Direction, PaidOut, Payout, State,
};
use licash_wallet::{LicashCode, Transport};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::{key_hex, now, store, wallet_error, Bridge, Error};

const COMPONENT: &str = "bridge-notes";
const VERSION: i64 = 1;

const SCHEMA: &str = "
-- Notes paid into an account, by their payment's id: credited once.
CREATE TABLE bridge_deposits (
    id BLOB PRIMARY KEY CHECK (length(id) = 32),
    account INTEGER NOT NULL REFERENCES bridge_accounts (id),
    amount INTEGER NOT NULL CHECK (amount > 0),
    created_at INTEGER NOT NULL
);
-- Notes paid out of an account to `code`, made under the wallet's send key
-- `send`, of the account and the id `id` it picked: `reserved` is taken
-- from its balance while under way, and is what it cost once decided.
CREATE TABLE bridge_payouts (
    send BLOB PRIMARY KEY CHECK (length(send) = 32),
    id BLOB NOT NULL CHECK (length(id) = 32),
    account INTEGER NOT NULL REFERENCES bridge_accounts (id),
    code TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK (amount > 0),
    reserved INTEGER NOT NULL CHECK (reserved >= 0),
    state TEXT NOT NULL CHECK (state IN ('pending', 'settled', 'failed')),
    -- The wallet's payment, in hex, once made.
    payment TEXT,
    failure TEXT,
    created_at INTEGER NOT NULL,
    settled_at INTEGER
);
CREATE INDEX bridge_payouts_pending ON bridge_payouts (state) WHERE state = 'pending';
";

/// Make the tables in `tx`, if none: those of a bridge of an earlier
/// release start empty. Refused if a later version keeps them.
pub(crate) fn tables(tx: &Transaction<'_>) -> Result<(), Error> {
    let setup = |e: licash_store::Error| Error::Unavailable(format!("the bridge's records: {e}"));
    match licash_store::component_version(tx, COMPONENT).map_err(setup)? {
        Some(VERSION) => Ok(()),
        Some(v) => Err(Error::Unavailable(format!(
            "bridge notes records of version {v}, not {VERSION}: use the release that wrote them"
        ))),
        None => licash_store::component_in(tx, COMPONENT, VERSION, SCHEMA).map_err(setup),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Paying {
    id: [u8; 32],
    account: i64,
    amount: u64,
    reserved: u64,
    state: State,
    payment: Option<String>,
    failure: Option<String>,
    created_at: i64,
    settled_at: Option<i64>,
}

impl Paying {
    /// What the hub took on top, once made.
    fn fee(&self) -> u64 {
        match self.state {
            State::Settled => self.reserved.saturating_sub(self.amount),
            _ => 0,
        }
    }
}

const PAYING: &str = "SELECT id, account, amount, reserved, state, payment, failure, created_at,
    settled_at FROM bridge_payouts";

fn paying_row(r: &Row<'_>) -> rusqlite::Result<Paying> {
    let state: String = r.get(4)?;
    Ok(Paying {
        id: r.get(0)?,
        account: r.get(1)?,
        amount: r.get::<_, i64>(2)? as u64,
        reserved: r.get::<_, i64>(3)? as u64,
        state: match state.as_str() {
            "settled" => State::Settled,
            "failed" => State::Failed,
            _ => State::Pending,
        },
        payment: r.get(5)?,
        failure: r.get(6)?,
        created_at: r.get(7)?,
        settled_at: r.get(8)?,
    })
}

fn paying(c: &Connection, send: &[u8; 32]) -> Result<Option<Paying>, Error> {
    Ok(
        c.query_row(&format!("{PAYING} WHERE send = ?1"), [send], paying_row)
            .optional()?,
    )
}

/// The payouts under way.
pub(crate) fn pending(c: &Connection) -> Result<Vec<[u8; 32]>, Error> {
    let mut stmt = c.prepare("SELECT send FROM bridge_payouts WHERE state = 'pending'")?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// What the payouts under way of account `id` took from its balance.
pub(crate) fn reserved(c: &Connection, id: i64) -> Result<u64, Error> {
    let reserved: i64 = c.query_row(
        "SELECT COALESCE(SUM(reserved), 0) FROM bridge_payouts
         WHERE account = ?1 AND state = 'pending'",
        [id],
        |r| r.get(0),
    )?;
    Ok(reserved as u64)
}

/// The latest deposits and payouts of account `id`, at most `limit` of
/// each.
pub(crate) fn activity(c: &Connection, id: i64, limit: u32) -> Result<Vec<Activity>, Error> {
    let mut stmt = c.prepare(&format!(
        "{PAYING} WHERE account = ?1 ORDER BY created_at DESC LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![id, limit], paying_row)?;
    let mut activity = Vec::new();
    for p in rows {
        let p = p?;
        activity.push(Activity {
            direction: Direction::Outgoing,
            state: p.state,
            hash: hex::encode(p.id),
            invoice: String::new(),
            amount: p.amount,
            fee: p.fee(),
            connection: None,
            description: None,
            preimage: None,
            failure: p.failure.clone(),
            created_at: p.created_at,
            settled_at: p.settled_at.filter(|_| p.state == State::Settled),
        });
    }
    let mut stmt = c.prepare(
        "SELECT id, amount, created_at FROM bridge_deposits
         WHERE account = ?1 ORDER BY created_at DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![id, limit], |r| {
        Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, i64>(1)?, r.get(2)?))
    })?;
    for row in rows {
        let (id, amount, created_at) = row?;
        activity.push(Activity {
            direction: Direction::Incoming,
            state: State::Settled,
            hash: hex::encode(id),
            invoice: String::new(),
            amount: amount as u64,
            fee: 0,
            connection: None,
            description: None,
            preimage: None,
            failure: None,
            created_at,
            settled_at: Some(created_at),
        });
    }
    Ok(activity)
}

/// The key the wallet sends account `key`'s payout `id` under: of the
/// account too, so no account names another's.
fn send_key(key: &[u8; 32], id: &[u8; 32]) -> [u8; 32] {
    licash::crypto::tagged_hash("licash/bridge/payout", &[key, id])
}

fn msat(sat: u64) -> Result<u64, Error> {
    sat.checked_mul(1000)
        .filter(|msat| *msat > 0)
        .ok_or_else(|| Error::Invalid("an amount of more than 0 sat, in range".into()))
}

/// Paying into and out of accounts in notes.
impl<T: Transport> Bridge<T> {
    /// A deposit into `key`'s account ([`Deposit`]): where to pay it, or
    /// what its payment credited.
    pub async fn deposit(&self, key: &[u8; 32], deposit: &Deposit) -> Result<Deposited, Error> {
        let account = self.account_id(key)?;
        let hub = &self.config.hub;
        // At the URL its wallet reaches its hub at.
        let reached = self.wallet.hub_urls(hub).map_err(wallet_error)?;
        let code = (self.wallet.payment_code(&reached[..reached.len().min(1)]))
            .map_err(wallet_error)?
            .licash
            .ok_or_else(|| Error::Unavailable("the bridge has no code at its hub".into()))?;
        let mut deposited = Deposited {
            hub: hub.clone(),
            code: code.to_string(),
            credited: None,
        };
        let Some(payment) = &deposit.payment else {
            // Before paying: as an invoice of it would be.
            self.not_frozen()?;
            drop(self.admit_credit(account, msat(deposit.amount)?)?);
            return Ok(deposited);
        };
        // Taken first, whatever it says: the notes are the bridge's now.
        let received = self.wallet.receive_once(payment).map_err(wallet_error)?;
        let note = self
            .wallet
            .payment_note(&received.id)
            .map_err(wallet_error)?;
        let named = bridge::deposit_note(&hex::encode(key));
        if note.and_then(|n| n.text).as_deref() != Some(named.as_str()) {
            tracing::warn!(
                id = %received.id, amount = received.amount,
                "a deposit whose note names no account of its sender: credited to none"
            );
            return Err(Error::Unauthorized(
                "a payment whose note names another account, or none".into(),
            ));
        }
        let id = key_hex(&received.id)?;
        let amount = msat(received.amount)?;
        let at = now();
        let credited = self.store.write(|tx| {
            let earlier: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT account, amount FROM bridge_deposits WHERE id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match earlier {
                Some((of, amount)) if of == account => Ok((amount as u64, false)),
                Some(_) => Err(Error::Restricted("a deposit of another account".into())),
                None => {
                    tx.execute(
                        "INSERT INTO bridge_deposits (id, account, amount, created_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![id, account, store::sql(amount)?, at],
                    )?;
                    store::credit(tx, account, store::sql(amount)?)?;
                    Ok((amount, true))
                }
            }
        })?;
        let (amount, new) = credited;
        if new {
            tracing::info!(id = %received.id, amount, "deposit credited");
            self.unlink_received().await;
        }
        deposited.credited = Some(Credited {
            id: received.id,
            amount,
        });
        Ok(deposited)
    }

    /// Pay `payout` out of `key`'s account: where it stands once made,
    /// or tried. The same id again answers the same payout.
    pub async fn payout(&self, key: &[u8; 32], payout: &Payout) -> Result<PaidOut, Error> {
        let account = self.account_id(key)?;
        let id = key_hex(&payout.id)?;
        let send = send_key(key, &id);
        let turn = self.turn(send)?;
        if self.store.read(|c| paying(c, &send))?.is_some() {
            drop(turn);
            return self.follow_payout(&send).await;
        }
        self.not_frozen()?;
        let code: LicashCode =
            (payout.code.parse()).map_err(|_| Error::Invalid("not a Licash code".into()))?;
        if code.network != self.wallet.network() {
            return Err(Error::Invalid("a code of another network".into()));
        }
        // Paid at its hub: one the code's owner uses, else lost to them.
        let reached = self
            .wallet
            .hub_urls(&self.config.hub)
            .map_err(wallet_error)?;
        let ours = (self.wallet.hubs().map_err(wallet_error)?.into_iter())
            .find(|(url, _)| reached.contains(url))
            .map(|(_, info)| licash_wallet::HubId::of(&info.address));
        if !ours.is_some_and(|id| code.hubs.contains(&id)) {
            return Err(Error::Invalid(format!(
                "a code naming the bridge's hub, {}",
                self.config.hub
            )));
        }
        let amount = msat(payout.amount)?;
        if self.config.max_payment.is_some_and(|max| amount > max) {
            return Err(Error::Quota(format!(
                "the bridge pays {} msat at most at once",
                self.config.max_payment.unwrap_or_default()
            )));
        }
        let hub = &self.config.hub;
        let fee = (self.wallet.send_fee(hub, payout.amount)).map_err(wallet_error)?;
        let reserve = msat(payout.amount.saturating_add(fee))?;
        if self.balance_of(account)? < reserve {
            return Err(Error::Insufficient(format!(
                "{reserve} msat asked, fee included"
            )));
        }
        let at = now();
        self.store.write(|tx| {
            // Here too: frozen meanwhile, its notes may be exported.
            if store::meta(tx)?.frozen_at.is_some() {
                return Err(Error::Frozen);
            }
            store::credit(tx, account, -store::sql(reserve)?)?;
            tx.execute(
                "INSERT INTO bridge_payouts
                 (send, id, account, code, amount, reserved, state, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
                params![
                    send,
                    id,
                    account,
                    payout.code.trim(),
                    store::sql(amount)?,
                    store::sql(reserve)?,
                    at
                ],
            )?;
            Ok(())
        })?;
        tracing::info!(id = %payout.id, amount, reserve, "paying out");
        let paid = (self.wallet)
            .pay_code_keyed_within(hub, &code, payout.amount, send, Some(fee))
            .await;
        if let Err(e) = &paid {
            tracing::info!(id = %payout.id, "a payout not made yet: {e}");
        }
        self.decide_payout(&send).await?;
        drop(turn);
        self.paid_out(&send)
    }

    /// Take the payout made under `send` on, unless it is being made now.
    pub(crate) async fn follow_payout(&self, send: &[u8; 32]) -> Result<PaidOut, Error> {
        if let Ok(_turn) = self.turn(*send) {
            self.decide_payout(send).await?;
        }
        self.paid_out(send)
    }

    /// Decide the payout under `send` by the wallet's send under it: given
    /// back if none was made, or it was given up; settled once made.
    async fn decide_payout(&self, send: &[u8; 32]) -> Result<(), Error> {
        let Some(payout) = self.store.read(|c| paying(c, send))? else {
            return Err(Error::NotFound("no such payout".into()));
        };
        if payout.state != State::Pending {
            return Ok(());
        }
        let mut sent = self.wallet.sent_by_key(send).map_err(wallet_error)?;
        if let Some(made) = sent.as_ref().filter(|s| {
            matches!(
                s.state,
                licash_wallet::State::Offered | licash_wallet::State::Signed
            )
        }) {
            if let Err(e) = self.wallet.finish_send(&made.id).await {
                tracing::debug!(id = %hex::encode(payout.id), "a payout under way: {e}");
            }
            sent = self.wallet.sent_by_key(send).map_err(wallet_error)?;
        }
        let at = now();
        let decided = match sent {
            Some(sent) => match sent.state {
                licash_wallet::State::Done => {
                    let cost = msat(sent.amount.saturating_add(sent.fee))?;
                    Some((State::Settled, cost, Some(sent.id), None))
                }
                licash_wallet::State::Abandoned(why) => Some((State::Failed, 0, None, Some(why))),
                _ => None,
            },
            // Recorded, then stopped before the wallet made it: no one else
            // makes it.
            None => Some((State::Failed, 0, None, Some("never made".to_owned()))),
        };
        let Some((state, cost, payment, failure)) = decided else {
            return Ok(());
        };
        let state_name = match state {
            State::Settled => "settled",
            _ => "failed",
        };
        self.store.write(|tx| {
            let n = tx.execute(
                "UPDATE bridge_payouts SET state = ?2, reserved = ?3, payment = ?4, failure = ?5,
                    settled_at = ?6
                 WHERE send = ?1 AND state = 'pending'",
                params![send, state_name, store::sql(cost)?, payment, failure, at],
            )?;
            if n == 1 {
                let back = payout.reserved.saturating_sub(cost);
                store::credit(tx, payout.account, store::sql(back)?)?;
            }
            Ok(())
        })?;
        tracing::info!(id = %hex::encode(payout.id), ?state, cost, "payout decided");
        Ok(())
    }

    /// The payout under `send`, as answered.
    fn paid_out(&self, send: &[u8; 32]) -> Result<PaidOut, Error> {
        let p = (self.store.read(|c| paying(c, send))?)
            .ok_or_else(|| Error::NotFound("no such payout".into()))?;
        let payment = match &p.payment {
            Some(id) => Some(self.wallet.payment(id).map_err(wallet_error)?),
            None => None,
        };
        Ok(PaidOut {
            id: hex::encode(p.id),
            state: p.state,
            amount: p.amount,
            fee: p.fee(),
            payment,
            failure: p.failure,
        })
    }

    /// Unlink the notes just received, unless frozen: as exported then.
    pub(crate) async fn unlink_received(&self) {
        let _notes = self.notes.lock().await;
        let frozen = self.store.read(store::meta).map(|m| m.frozen_at.is_some());
        if matches!(frozen, Ok(false)) {
            if let Err(e) = self.wallet.unlink().await {
                tracing::warn!("unlinking the notes received: {e}");
            }
        }
    }
}
