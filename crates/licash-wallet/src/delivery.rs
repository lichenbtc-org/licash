//! How payments to payment codes reach their payees. The payer asks the
//! hub releasing a payment to keep it for its payee ([`licash_api::inbox`]),
//! who collects it there ([`Wallet::collect_inbox`]) and tells the payer,
//! through the hub, that it has it. Only a payment no payee said it has
//! within [`ACK_WITHIN`], or one its hub does not keep, is mailed to the
//! payee's mailbox on Nostr, which the application does: [`Wallet::due`]
//! names what to mail, [`Wallet::mailed`] records how it went.
//!
//! The hub cannot tell the payer a payee has a payment unless it does: the
//! ack derives from the receipt secret, which the hub does not know. A hub
//! that keeps nothing, or keeps it from the payee, only delays it by
//! [`ACK_WITHIN`].

use std::collections::BTreeMap;

use crate::PaymentNote;
use licash::{crypto::Point, spend::ProposalId};
use licash_api::{
    inbox::{
        self, Acknowledge, Acknowledged, Acknowledgment, Acks, AskAcks, Feed, Keep, Kept, Take,
        Taken,
    },
    Hex, Info, Payment,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::{
    answer, each_at_most, in_lane, invalid, now, payment_id, unavailable, Error, Lane, LicashCode,
    Paid, Received, Transport, Wallet,
};

/// How long a payment kept at its hub waits for its payee to say it has
/// it before it is mailed, in seconds.
pub const ACK_WITHIN: i64 = 60 * 60;

/// The longest wait before mailing again a payment whose mailing failed,
/// in seconds: from a minute, doubling with each failure.
const MAIL_AGAIN_WITHIN: i64 = 60 * 60;

/// Hubs looked at, at once.
const HUBS_AT_ONCE: usize = 4;

/// The most pages of a hub's inbox one collection looks through: a hub
/// answering more without end holds the wallet no longer.
pub const PAGES_AT_ONCE: usize = 16;

/// Whether `feed`, answered after entry `after`, moves the inbox on: at
/// most [`inbox::MAX_ENTRIES`] entries, each after the one before, the
/// first after `after`, and some if it says there are more.
fn advances(feed: &Feed, after: i64) -> bool {
    let mut last = u64::try_from(after).unwrap_or(0);
    feed.entries.len() <= inbox::MAX_ENTRIES
        && !(feed.more && feed.entries.is_empty())
        && feed.entries.iter().all(|entry| {
            let next = entry.seq > last;
            last = entry.seq;
            next
        })
}

/// Where a payment to a payment code stands in reaching its payee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Kept at its hub for its payee, which has not said it has it yet:
    /// mailed from `mail_at` on if the code names a mailbox.
    Kept { mail_at: i64 },
    /// Its payee said it has it.
    Collected,
    /// To mail to the payee's mailbox: failed `tries` times so far, the
    /// last for `error`.
    Mailing { tries: u32, error: Option<String> },
    /// Mailed to the payee's mailbox.
    Mailed,
    /// Neither collected nor mailed, the code naming no mailbox: the
    /// payment is to hand over ([`Wallet::payment`]).
    HandOver,
    /// Neither collected nor mailed in the days a hub keeps a payment: no
    /// longer tried. The payment may still be handed over.
    GivenUp,
}

/// A payment to mail to its payee's mailbox ([`Wallet::due`]).
#[derive(Clone, Debug)]
pub struct Due {
    /// The payment's id, to tell [`Wallet::mailed`].
    pub id: String,
    /// The payee's mailbox: an x-only Nostr key.
    pub mailbox: [u8; 32],
    /// The mailbox relays the payment's hub names.
    pub relays: Vec<String>,
    pub payment: Payment,
}

/// What [`Wallet::collect_inbox`] collected.
#[derive(Debug, Default)]
pub struct Inboxed {
    /// The payments taken.
    pub received: Vec<Received>,
    /// The hubs not looked through, or not to the end, and why: looked
    /// through again from there next time.
    pub failed: Vec<(String, String)>,
    /// How many hubs answered that they keep payments, their inboxes
    /// looked through to the end or not.
    pub served: usize,
    /// What the wallet's extra codes were paid, and paid on to it, first
    /// ([`Wallet::collect_codes`]).
    pub codes: crate::CodesCollected,
}

/// Record that send `id`, to the payee sharing receipt secret `shared`,
/// is to reach it as [`Wallet::pay_code`] says, mailed to `mailbox` if any.
pub(crate) fn record(
    tx: &Transaction,
    id: &ProposalId,
    mailbox: Option<[u8; 32]>,
    shared: &[u8; 32],
) -> Result<(), Error> {
    tx.execute(
        "INSERT INTO deliveries (send, mailbox, tag, key, ack) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id.as_bytes(),
            mailbox,
            inbox::tag(shared),
            inbox::key(shared),
            inbox::ack(shared, id)
        ],
    )?;
    Ok(())
}

/// What to ask the hub of send `id` to keep it with, if it is to.
pub(crate) fn keep(c: &Connection, id: &ProposalId) -> Result<Option<Keep>, Error> {
    let row: Option<([u8; inbox::TAG], [u8; 32], [u8; 32])> = c
        .query_row(
            "SELECT tag, key, ack FROM deliveries WHERE send = ?1",
            [id.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((tag, key, ack)) = row else {
        return Ok(None);
    };
    let note = crate::payment_note::sealed(c, id)?.filter(|(_, keep)| *keep);
    let keep = Keep {
        tag: Hex(tag.to_vec()),
        key: Hex(key.to_vec()),
        commitment: Hex(inbox::commitment(&ack).to_vec()),
        note: None,
    };
    Ok(Some(keep.with_note(note.map(|(sealed, _)| sealed))))
}

/// Record that send `id` is released, its hub keeping it for its payee if
/// `kept` says, unknown if none: when to mail it, set once. Whether its
/// hub keeps it.
pub(crate) fn released(
    tx: &Transaction,
    id: &ProposalId,
    kept: Option<bool>,
) -> Result<bool, Error> {
    let now = now();
    let (kept_at, mail_at) = match kept {
        Some(true) => (Some(now), now + ACK_WITHIN),
        Some(false) | None => (None, now),
    };
    tx.execute(
        "UPDATE deliveries SET kept_at = COALESCE(kept_at, ?2), mail_at = COALESCE(mail_at, ?3)
         WHERE send = ?1",
        params![id.as_bytes(), kept_at, mail_at],
    )?;
    let kept: Option<bool> = tx
        .query_row(
            "SELECT kept_at IS NOT NULL FROM deliveries WHERE send = ?1",
            [id.as_bytes()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(kept.unwrap_or(false))
}

/// Sends whose delivery is under way: released, neither abandoned, nor
/// collected, mailed or given up.
const UNDER_WAY: &str = "s.done_at IS NOT NULL AND s.abandoned IS NULL
    AND d.acked_at IS NULL AND d.mailed_at IS NULL AND d.given_up_at IS NULL";

/// Payments to payment codes, reaching their payees.
impl<T: Transport> Wallet<T> {
    /// Pay `amount` to the wallet of `code` at the hub at `url`, as
    /// [`Wallet::send`] does, asking the hub to keep the payment for its
    /// payee to collect there. Returned once released: [`Paid::kept`] says
    /// whether the hub keeps it. [`Wallet::due`] then names it to mail to
    /// the mailbox the code names, if any, unless the payee says it has it
    /// within [`ACK_WITHIN`], or at once if the hub does not keep it.
    pub async fn pay_code(&self, url: &str, code: &LicashCode, amount: u64) -> Result<Paid, Error> {
        self.send_with(url, &code.address, amount, Some(code.mailbox), None, None)
            .await
    }

    /// [`Wallet::pay_code`], with `note` for its payee
    /// ([`PaymentNote`]): a code in it must be one of this wallet's. A
    /// note saying anything is refused, before anything is paid, at a hub
    /// that keeps none with a payment ([`Error::NoteUnkept`]), its info
    /// asked again first: its payee could take the payment there without
    /// it.
    pub async fn pay_code_saying(
        &self,
        url: &str,
        code: &LicashCode,
        amount: u64,
        note: &PaymentNote,
    ) -> Result<Paid, Error> {
        self.pay_code_within(url, code, amount, note, None).await
    }

    /// [`Wallet::pay_code_saying`], refused as [`Error::FeeRose`], nothing
    /// paid, if its hub's fee would pass `max_fee`, as quoted: the fees
    /// it learns from a hub refusing the first offer included.
    pub async fn pay_code_within(
        &self,
        url: &str,
        code: &LicashCode,
        amount: u64,
        note: &PaymentNote,
        max_fee: Option<u64>,
    ) -> Result<Paid, Error> {
        let url = crate::hub_url(url)?;
        let note = self.note_for(&url, note).await?;
        let mailbox = Some(code.mailbox);
        let address = &code.address;
        (self.send_with(&url, address, amount, mailbox, Some(&note), max_fee)).await
    }

    /// [`Wallet::pay_code`] under `key`, once: no other payment is ever
    /// made under it, not even after this one is given up, nor again at
    /// fees changed meanwhile. The key is recorded with the payment, before
    /// its hub hears of it, so that a payer stopped at any point learns
    /// from [`Wallet::sent_by_key`] alone whether it paid, and decides by
    /// that rather than by what this returned.
    pub async fn pay_code_keyed(
        &self,
        url: &str,
        code: &LicashCode,
        amount: u64,
        key: [u8; 32],
    ) -> Result<Paid, Error> {
        self.pay_code_keyed_within(url, code, amount, key, None)
            .await
    }

    /// [`Wallet::pay_code_keyed`], refused as [`Error::FeeRose`], nothing
    /// paid, if its hub's fee would pass `max_fee`.
    pub async fn pay_code_keyed_within(
        &self,
        url: &str,
        code: &LicashCode,
        amount: u64,
        key: [u8; 32],
        max_fee: Option<u64>,
    ) -> Result<Paid, Error> {
        let url = crate::hub_url(url)?;
        if amount == 0 {
            return Err(Error::Invalid("nothing to pay".into()));
        }
        if let Some(sent) = self.sent_by_key(&key)? {
            return Err(Error::Invalid(format!(
                "payment {} was made under this key",
                sent.id
            )));
        }
        let mailbox = Some(code.mailbox);
        (self.send_once(
            &url,
            &code.address,
            amount,
            mailbox,
            Some(key),
            None,
            max_fee,
        ))
        .await
    }

    /// The payments to mail to their payees' mailboxes now: those whose
    /// payees did not say they have them in time, as their hubs tell,
    /// asked here. Those neither collected nor mailed in the days a hub
    /// keeps them are given up first. A hub that does not answer is asked
    /// again next time: its payments are not mailed early for it.
    pub async fn due(&self) -> Result<Vec<Due>, Error> {
        let now = now();
        self.store.write(|tx| {
            tx.execute(
                "UPDATE deliveries SET given_up_at = ?1
                 WHERE given_up_at IS NULL AND acked_at IS NULL AND mailed_at IS NULL
                   AND send IN (SELECT id FROM sends WHERE done_at < ?2)",
                params![now, now - inbox::KEPT_FOR],
            )?;
            Ok(())
        })?;
        self.ask_acks().await?;
        type Row = ([u8; 32], [u8; 32], String);
        let rows: Vec<Row> = self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT d.send, d.mailbox, h.info
                 FROM deliveries d JOIN sends s ON s.id = d.send JOIN hubs h ON h.id = s.hub
                 WHERE {UNDER_WAY} AND d.mailbox IS NOT NULL AND COALESCE(d.mail_at, 0) <= ?1
                 ORDER BY s.done_at"
            ))?;
            let rows = stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let mut due = Vec::new();
        for (id, mailbox, info) in rows {
            let id = hex::encode(id);
            let info: Info = serde_json::from_str(&info).map_err(invalid)?;
            if info.relays.is_empty() {
                self.mailed(&id, Err("its hub names no mailbox relays".into()))?;
                continue;
            }
            let payment = self.payment(&id)?;
            due.push(Due {
                id,
                mailbox,
                relays: info.relays,
                payment,
            });
        }
        Ok(due)
    }

    /// Record how mailing payment `id` ([`Wallet::due`]) went: to so many
    /// relays, or failed for a reason, to mail it again later.
    pub fn mailed(&self, id: &str, outcome: Result<usize, String>) -> Result<(), Error> {
        let id = payment_id(id)?;
        let now = now();
        self.store.write(|tx| {
            match &outcome {
                Ok(_) => tx.execute(
                    "UPDATE deliveries SET mailed_at = COALESCE(mailed_at, ?2), error = NULL
                     WHERE send = ?1",
                    params![id.as_bytes(), now],
                )?,
                Err(error) => tx.execute(
                    "UPDATE deliveries SET tries = tries + 1, error = ?2,
                        mail_at = ?3 + MIN(60 << MIN(tries, 6), ?4)
                     WHERE send = ?1 AND mailed_at IS NULL",
                    params![id.as_bytes(), error, now, MAIL_AGAIN_WITHIN],
                )?,
            };
            Ok(())
        })?;
        match outcome {
            Ok(relays) => tracing::info!(id = %hex::encode(id.as_bytes()), relays, "mailed"),
            Err(e) => tracing::info!(id = %hex::encode(id.as_bytes()), "not mailed: {e}"),
        }
        Ok(())
    }

    /// Ask the hubs of the payments they keep whether their payees said
    /// they have them, and record those they did: each payment by a
    /// request of its own, in a lane of its own ([`Lane::Fresh`]), so that
    /// the hub cannot tell which it keeps are one payer's.
    async fn ask_acks(&self) -> Result<(), Error> {
        type Row = (String, [u8; 32], [u8; 32], [u8; 32]);
        let rows: Vec<Row> = self.store.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT r.url, d.send, d.key, d.ack
                 FROM deliveries d JOIN sends s ON s.id = d.send JOIN reach r ON r.hub = s.hub
                 WHERE {UNDER_WAY} AND d.kept_at IS NOT NULL"
            ))?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        // Each payment kept, by its send, key and ack.
        type Asked = ([u8; 32], [u8; 32], [u8; 32]);
        let mut by_hub: BTreeMap<String, Vec<Asked>> = BTreeMap::new();
        for (url, send, key, ack) in rows {
            by_hub.entry(url).or_default().push((send, key, ack));
        }
        let acked = each_at_most(HUBS_AT_ONCE, by_hub, |(url, kept)| async move {
            let mut acked = Vec::new();
            for kept in kept.chunks(1) {
                let keys = kept.iter().map(|(_, key, _)| Hex(key.to_vec())).collect();
                let ask = AskAcks { keys };
                let asking = self.post(&url, inbox::ACKS, &ask);
                let asked: Result<Acks, Error> = in_lane(Lane::Fresh, asking).await;
                match asked {
                    Ok(told) if told.acks.len() == kept.len() => {
                        for ((send, _, ack), told) in kept.iter().zip(told.acks) {
                            match told {
                                Some(told) if told.0 == ack => acked.push(*send),
                                Some(_) => {
                                    tracing::warn!(%url, "a hub told an ack not the payee's")
                                }
                                None => {}
                            }
                        }
                    }
                    Ok(_) => {
                        tracing::warn!(%url, "a hub told other acks than asked");
                        break;
                    }
                    Err(e) => {
                        tracing::info!(%url, "acks not asked: {e}");
                        break;
                    }
                }
            }
            Ok::<_, Error>(acked)
        });
        let acked: Vec<[u8; 32]> = acked.await?.into_iter().flatten().collect();
        if acked.is_empty() {
            return Ok(());
        }
        let now = now();
        self.store.write(|tx| {
            for send in &acked {
                tx.execute(
                    "UPDATE deliveries SET acked_at = COALESCE(acked_at, ?2) WHERE send = ?1",
                    params![send, now],
                )?;
            }
            Ok(())
        })?;
        tracing::info!(payments = acked.len(), "collected by their payees");
        Ok(())
    }

    /// Where payment `id` stands in reaching its payee: none unless made
    /// by [`Wallet::pay_code`] and released.
    pub fn delivery(&self, id: &str) -> Result<Option<Delivery>, Error> {
        let id = payment_id(id)?;
        type Row = (
            bool,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            i64,
            Option<String>,
        );
        let row: Option<Row> = self.store.read(|c| {
            Ok(c.query_row(
                "SELECT d.mailbox IS NOT NULL, d.kept_at, d.mail_at, d.acked_at, d.mailed_at,
                    d.given_up_at, d.tries, d.error
                 FROM deliveries d JOIN sends s ON s.id = d.send
                 WHERE d.send = ?1 AND s.done_at IS NOT NULL AND s.abandoned IS NULL",
                [id.as_bytes()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .optional()?)
        })?;
        let Some((mailbox, kept, mail_at, acked, mailed, given_up, tries, error)) = row else {
            return Ok(None);
        };
        let mail_at = mail_at.unwrap_or(0);
        Ok(Some(match () {
            _ if acked.is_some() => Delivery::Collected,
            _ if mailed.is_some() => Delivery::Mailed,
            _ if given_up.is_some() => Delivery::GivenUp,
            _ if kept.is_some() && tries == 0 && mail_at > now() => Delivery::Kept { mail_at },
            _ if !mailbox => Delivery::HandOver,
            _ => Delivery::Mailing {
                tries: u32::try_from(tries).unwrap_or(u32::MAX),
                error,
            },
        }))
    }

    /// How many payments are still to reach their payees through
    /// [`Wallet::due`]: kept at their hubs awaiting their payees, or to
    /// mail. While any are, the application calls it now and then.
    pub fn delivering(&self) -> Result<usize, Error> {
        self.store.read(|c| {
            let count: i64 = c.query_row(
                &format!(
                    "SELECT count(*) FROM deliveries d JOIN sends s ON s.id = d.send
                     WHERE {UNDER_WAY}
                       AND (d.mailbox IS NOT NULL OR (d.kept_at IS NOT NULL AND d.mail_at > ?1))"
                ),
                [now()],
                |r| r.get(0),
            )?;
            Ok(count as usize)
        })
    }

    /// Take the payments the hubs the wallet trusts keep for it, each
    /// once, and tell their payers, through the hubs, that it has them.
    /// Each hub's inbox is looked through from where it was last, to the
    /// end; a hub that keeps no payments is skipped, and one that fails is
    /// looked through again from there next time. The wallet's extra
    /// codes are collected first ([`Wallet::collect_codes`]), what they
    /// pay on to the wallet taken with the rest.
    pub async fn collect_inbox(&self) -> Result<Inboxed, Error> {
        let codes = match self.collect_codes().await {
            Ok(codes) => codes,
            Err(e) => {
                tracing::warn!("extra codes not collected: {e}");
                crate::CodesCollected::default()
            }
        };
        let mut inboxed = self.collect_own_inbox().await?;
        inboxed.codes = codes;
        Ok(inboxed)
    }

    /// [`Wallet::collect_inbox`] of the wallet's own code alone.
    pub(crate) async fn collect_own_inbox(&self) -> Result<Inboxed, Error> {
        let hubs: Vec<(i64, String, i64)> = self.store.read(|c| {
            let mut stmt = c.prepare(
                "SELECT h.id, r.url, COALESCE(h.inbox_after, 0)
                 FROM hubs h JOIN reach r ON r.hub = h.id WHERE h.trusted = 1",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })?;
        let looked = each_at_most(HUBS_AT_ONCE, hubs, |(hub, url, after)| async move {
            let (mut received, mut served) = (Vec::new(), false);
            let failed = self
                .collect_at(hub, &url, after, &mut received, &mut served)
                .await;
            let failed = failed.err().map(|e| (url, e.to_string()));
            Ok::<_, Error>((received, failed, served))
        });
        let mut inboxed = Inboxed::default();
        for (received, failed, served) in looked.await? {
            inboxed.received.extend(received);
            inboxed.failed.extend(failed);
            inboxed.served += usize::from(served);
        }
        Ok(inboxed)
    }

    /// [`Wallet::collect_inbox`] at hub `hub`, at `url`, after entry
    /// `after`, adding the payments taken to `received`, and telling
    /// `served` once the hub answers that it keeps payments. Only a failure to
    /// reach the hub or keep a payment holds the inbox where it was: an
    /// entry whose payment is not the wallet's, or does not open, is
    /// passed, so that no payer stalls the wallet's inbox with one. At most
    /// [`PAGES_AT_ONCE`] pages are looked through, the rest next time.
    /// Each payment is taken by a request of its own, in a lane of its own
    /// ([`Lane::Fresh`]): the hub cannot tell those taken together are one
    /// payee's by the request or its connection.
    async fn collect_at(
        &self,
        hub: i64,
        url: &str,
        mut after: i64,
        received: &mut Vec<Received>,
        served: &mut bool,
    ) -> Result<(), Error> {
        let scan = self.owner.scan_key().clone();
        let mut refreshed = false;
        for _ in 0..PAGES_AT_ONCE {
            let Some(feed) = self.feed(url, after).await? else {
                return Ok(());
            };
            *served = true;
            if !advances(&feed, after) {
                return Err(unavailable(url, "its inbox answered entries out of order"));
            }
            let mine: Vec<(u64, [u8; 32])> = feed
                .entries
                .iter()
                .filter_map(|entry| {
                    let (ephemeral, tag) = entry.decode().ok()?;
                    let shared = scan.shared(&Point(ephemeral)).ok()?;
                    (inbox::tag(&shared) == tag).then_some((entry.seq, shared))
                })
                .collect();
            for asked in mine.chunks(1) {
                let take = self.take_at(url, asked, &scan, &mut refreshed, received);
                in_lane(Lane::Fresh, take).await?;
            }
            let Some(last) = feed.entries.last() else {
                return Ok(());
            };
            after = i64::try_from(last.seq).map_err(invalid)?;
            self.store.write(|tx| {
                tx.execute(
                    "UPDATE hubs SET inbox_after = MAX(COALESCE(inbox_after, 0), ?2) WHERE id = ?1",
                    params![hub, after],
                )?;
                Ok(())
            })?;
            if !feed.more {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Take the payments `asked` (by their entries and shared secrets) at
    /// the hub at `url`, adding those kept to `received`, and acknowledge
    /// them: its keysets fetched again once if `refreshed` says they were
    /// not yet.
    async fn take_at(
        &self,
        url: &str,
        asked: &[(u64, [u8; 32])],
        scan: &licash::address::ScanKey,
        refreshed: &mut bool,
        received: &mut Vec<Received>,
    ) -> Result<(), Error> {
        {
            {
                let payments = asked.iter().map(|(seq, shared)| Kept {
                    seq: *seq,
                    key: Hex(inbox::key(shared).to_vec()),
                });
                let take = Take {
                    payments: payments.collect(),
                };
                let taken: Taken = self.post(url, inbox::TAKE, &take).await?;
                if taken.payments.len() != asked.len() {
                    return Err(unavailable(url, "it answered other payments than asked"));
                }
                let mut acks = Vec::new();
                for ((_, shared), kept) in asked.iter().zip(taken.payments) {
                    let Some(kept) = kept else { continue };
                    let payment = kept.at(url);
                    let opened = match self.open_payment(&payment) {
                        // A keyset the hub added since the wallet last asked.
                        Err(Error::UnknownHub(_)) if !*refreshed => {
                            *refreshed = true;
                            self.refresh(url).await?;
                            self.open_payment(&payment)
                        }
                        opened => opened,
                    };
                    let opened = match opened {
                        Ok(opened) => opened,
                        Err(e @ Error::Storage(_)) => return Err(e),
                        Err(e) => {
                            tracing::info!(%url, "a payment kept, not taken: {e}");
                            continue;
                        }
                    };
                    let proposal = opened.signed.proposal();
                    let (keyset, at, ours) = (&opened.keyset, opened.url.clone(), &opened.ours);
                    match self.keep(keyset, at, proposal, ours, payment.note.as_ref()) {
                        Ok(taken) => received.push(taken),
                        Err(Error::AlreadyReceived) => {}
                        Err(e @ Error::Storage(_)) => return Err(e),
                        Err(e) => {
                            tracing::info!(%url, "a payment kept, not taken: {e}");
                            continue;
                        }
                    }
                    // Of the payment as it is, whatever entry it came by.
                    let secret = scan.shared(&proposal.ephemeral())?;
                    acks.push(Acknowledgment {
                        key: Hex(inbox::key(shared).to_vec()),
                        ack: Hex(inbox::ack(&secret, &proposal.id()).to_vec()),
                    });
                }
                if !acks.is_empty() {
                    let told = Acknowledge { acks };
                    let _: Acknowledged = self.post(url, inbox::ACK, &told).await?;
                }
            }
        }
        Ok(())
    }

    /// The entries of the inbox of the hub at `url` after `after`: none if
    /// the hub keeps no payments, answering that it serves no inbox.
    async fn feed(&self, url: &str, after: i64) -> Result<Option<Feed>, Error> {
        let path = inbox::feed(u64::try_from(after).unwrap_or(0));
        // Public, asked of every payee alike: on the lane of none.
        let feed = format!("{url}{path}");
        let asked = async { self.transport.request(&feed, None).await };
        let response = in_lane(Lane::Shared, asked)
            .await
            .map_err(|reason| unavailable(url, reason))?;
        let problem = serde_json::from_slice::<licash_api::Problem>(&response.body);
        if response.status == 404 && problem.is_err() {
            return Ok(None);
        }
        answer(url, &path, &response).map(Some)
    }
}
