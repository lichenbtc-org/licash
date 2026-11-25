//! The bridge's Nostr Wallet Connect service (NIP-47): requests of kind
//! 23194 from its connections' keys, answered in kind 23195, encrypted as
//! they came, NIP-44 v2 or NIP-04. Its kind 13194 info event names the
//! methods it serves and both ciphers.

use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use licash_api::bridge::{Direction, State};
use licash_wallet::Transport;
use nostr::nips::nip47::{
    ErrorCode, GetBalanceResponse, GetInfoResponse, ListTransactionsRequest, LookupInvoiceRequest,
    LookupInvoiceResponse, MakeInvoiceRequest, MakeInvoiceResponse, Method, NIP47Error,
    Nip47Ciphers, PayInvoiceRequest, PayInvoiceResponse, Request, RequestParams, Response,
    ResponseResult, TransactionState, TransactionType,
};
use nostr::prelude::{Event, EventBuilder, EventId, Filter, FinalizeEvent, Kind, Tag, Timestamp};
use nostr_sdk::prelude::{Client, ClientNotification, StreamExt};

use crate::{store::Link, Bridge, Error};

/// The methods served, as the info event names them.
pub const METHODS: [Method; 6] = [
    Method::PayInvoice,
    Method::MakeInvoice,
    Method::LookupInvoice,
    Method::ListTransactions,
    Method::GetBalance,
    Method::GetInfo,
];

/// Requests remembered as answered, against relays sending one twice.
const REMEMBERED: usize = 4096;

/// How much a request's time may be ahead of the bridge's, in seconds.
const AHEAD: u64 = 300;

fn code(e: &Error) -> ErrorCode {
    match e {
        Error::Invalid(_) => ErrorCode::Other,
        Error::Unauthorized(_) => ErrorCode::Unauthorized,
        Error::Restricted(_) | Error::Frozen => ErrorCode::Restricted,
        Error::Insufficient(_) => ErrorCode::InsufficientBalance,
        Error::Quota(_) => ErrorCode::QuotaExceeded,
        Error::NotFound(_) => ErrorCode::NotFound,
        Error::Failed(_) => ErrorCode::PaymentFailed,
        Error::Pending(_) | Error::Unavailable(_) => ErrorCode::Internal,
    }
}

/// What NIP-47 calls a network.
fn network(name: &str) -> &'static str {
    match name {
        "bitcoin" => "mainnet",
        "regtest" => "regtest",
        _ => "signet",
    }
}

/// The cipher a request came in: NIP-44 v2 if it says so, else NIP-04.
fn cipher_of(event: &Event) -> Nip47Ciphers {
    let nip44 = event.tags.iter().any(|tag| {
        let parts = tag.as_slice();
        parts.first().is_some_and(|k| k == "encryption")
            && parts
                .get(1)
                .is_some_and(|v| v.split_whitespace().any(|c| c == "nip44_v2"))
    });
    if nip44 {
        Nip47Ciphers::NIP44V2
    } else {
        Nip47Ciphers::NIP04
    }
}

/// The info event: the methods served and the ciphers taken.
pub fn info_event<T: Transport>(bridge: &Bridge<T>) -> anyhow::Result<Event> {
    let methods: Vec<String> = METHODS.iter().map(|m| m.to_string()).collect();
    Ok(
        EventBuilder::new(Kind::WalletConnectInfo, methods.join(" "))
            .tag(Tag::custom("encryption", ["nip44_v2 nip04"]))
            .finalize(bridge.keys())?,
    )
}

/// The answer to `event`, a request, if it is one to this bridge: signed
/// by it, encrypted to its client as it came.
pub async fn answer<T: Transport>(bridge: &Bridge<T>, event: &Event) -> Option<Event> {
    let me = bridge.keys().public_key();
    if event.kind != Kind::WalletConnectRequest
        || !event.tags.public_keys().any(|p| p == me)
        || event.verify().is_err()
        || event.is_expired()
        || event.created_at > Timestamp::now() + AHEAD
    {
        return None;
    }
    let cipher = cipher_of(event);
    let secret = bridge.keys().secret_key();
    let request = cipher
        .decrypt(secret, &event.pubkey, &event.content)
        .ok()
        .and_then(|plain| Request::from_json(plain).ok());
    let response = match request {
        Some(request) => respond(bridge, &event.pubkey.to_bytes(), request).await,
        // Not a request read as one: not answered as one.
        None => return None,
    };
    let content = cipher
        .encrypt(secret, &event.pubkey, &response.as_json())
        .ok()?;
    let mut builder = EventBuilder::new(Kind::WalletConnectResponse, content)
        .tag(Tag::public_key(event.pubkey))
        .tag(Tag::event(event.id));
    if cipher == Nip47Ciphers::NIP44V2 {
        builder = builder.tag(Tag::custom("encryption", ["nip44_v2"]));
    }
    builder.finalize(bridge.keys()).ok()
}

async fn respond<T: Transport>(
    bridge: &Bridge<T>,
    client: &[u8; 32],
    request: Request,
) -> Response {
    let method = request.method.clone();
    let answered = match bridge.link(client) {
        Ok(link) => serve(bridge, &link, request.params).await,
        Err(e) => Err(e),
    };
    match answered {
        Ok(result) => Response {
            result_type: method,
            error: None,
            result: Some(result),
        },
        Err(e) => {
            tracing::debug!(%method, "refused: {e}");
            Response {
                result_type: method,
                error: Some(NIP47Error {
                    code: code(&e),
                    message: e.to_string(),
                }),
                result: None,
            }
        }
    }
}

fn hash_of(hex: &str) -> Result<[u8; 32], Error> {
    let mut hash = [0; 32];
    hex::decode_to_slice(hex, &mut hash)
        .map_err(|_| Error::Invalid("a payment hash of 32 bytes in hex".into()))?;
    Ok(hash)
}

async fn serve<T: Transport>(
    bridge: &Bridge<T>,
    link: &Link,
    params: RequestParams,
) -> Result<ResponseResult, Error> {
    match params {
        RequestParams::GetInfo => {
            let mut methods = vec![Method::GetBalance, Method::GetInfo];
            methods.push(Method::LookupInvoice);
            methods.push(Method::ListTransactions);
            if link.pay {
                methods.push(Method::PayInvoice);
            }
            if link.receive {
                methods.push(Method::MakeInvoice);
            }
            Ok(ResponseResult::GetInfo(GetInfoResponse {
                alias: bridge.config().name.clone(),
                color: None,
                pubkey: None,
                network: Some(network(&bridge.wallet().network().to_string()).into()),
                block_height: None,
                block_hash: None,
                methods,
                notifications: Vec::new(),
            }))
        }
        RequestParams::GetBalance => Ok(ResponseResult::GetBalance(GetBalanceResponse {
            balance: bridge.balance_of(link.account)?,
        })),
        RequestParams::PayInvoice(PayInvoiceRequest {
            invoice, amount, ..
        }) => {
            let asks = crate::decode(&invoice)?.amount_milli_satoshis();
            if amount.is_some_and(|amount| Some(amount) != asks) {
                return Err(Error::Invalid(
                    "an amount for an invoice that asks another, or none".into(),
                ));
            }
            let paid = bridge.pay(link.account, Some(link), &invoice, None).await?;
            let paid = bridge.wait(paid).await?;
            match paid.state {
                State::Settled => Ok(ResponseResult::PayInvoice(PayInvoiceResponse {
                    preimage: hex::encode(paid.preimage.unwrap_or_default()),
                    fees_paid: Some(paid.fee()),
                })),
                State::Pending => Err(Error::Pending(
                    "not paid yet: ask with lookup_invoice later".into(),
                )),
                _ => Err(Error::Failed(
                    paid.failure.unwrap_or_else(|| "not paid".into()),
                )),
            }
        }
        RequestParams::MakeInvoice(MakeInvoiceRequest {
            amount,
            description,
            description_hash,
            ..
        }) => {
            let description_hash = description_hash
                .filter(|h| !h.is_empty())
                .map(|h| hash_of(&h))
                .transpose()?;
            let description = description.filter(|d| !d.is_empty());
            let receipt = bridge
                .receive(
                    link.account,
                    Some(link),
                    amount,
                    description.as_deref(),
                    description_hash,
                    None,
                )
                .await?;
            Ok(ResponseResult::MakeInvoice(MakeInvoiceResponse {
                invoice: receipt.invoice,
                payment_hash: Some(hex::encode(receipt.hash)),
                description: receipt.description,
                description_hash: receipt.description_hash.map(hex::encode),
                preimage: None,
                amount: Some(receipt.amount),
                created_at: Some(Timestamp::from_secs(receipt.created_at as u64)),
                expires_at: Some(Timestamp::from_secs(receipt.expires_at as u64)),
            }))
        }
        RequestParams::LookupInvoice(LookupInvoiceRequest {
            payment_hash,
            invoice,
        }) => {
            let hash = match (payment_hash, invoice) {
                (Some(hash), _) => hash_of(&hash)?,
                (None, Some(invoice)) => *crate::decode(&invoice)?.payment_hash().as_ref(),
                (None, None) => return Err(Error::Invalid("a payment hash or an invoice".into())),
            };
            let activity = bridge.lookup(link.account, &hash)?;
            Ok(ResponseResult::LookupInvoice(lookup(activity)))
        }
        RequestParams::ListTransactions(ListTransactionsRequest {
            from,
            until,
            limit,
            offset,
            unpaid,
            transaction_type,
        }) => {
            let all = bridge.activity_of(link.account)?;
            let listed = all
                .into_iter()
                .filter(|a| from.is_none_or(|from| a.created_at as u64 >= from.as_secs()))
                .filter(|a| until.is_none_or(|until| a.created_at as u64 <= until.as_secs()))
                .filter(|a| unpaid.unwrap_or(false) || a.state == State::Settled)
                .filter(|a| match transaction_type {
                    Some(TransactionType::Incoming) => a.direction == Direction::Incoming,
                    Some(TransactionType::Outgoing) => a.direction == Direction::Outgoing,
                    None => true,
                })
                .skip(offset.unwrap_or(0) as usize)
                .take(limit.unwrap_or(u64::MAX) as usize)
                .map(lookup)
                .collect();
            Ok(ResponseResult::ListTransactions(listed))
        }
        _ => Err(Error::Restricted(
            "a method this bridge does not serve".into(),
        )),
    }
}

fn lookup(a: licash_api::bridge::Activity) -> LookupInvoiceResponse {
    let invoice = crate::decode(&a.invoice).ok();
    LookupInvoiceResponse {
        transaction_type: Some(match a.direction {
            Direction::Incoming => TransactionType::Incoming,
            Direction::Outgoing => TransactionType::Outgoing,
        }),
        state: Some(match a.state {
            State::Pending => TransactionState::Pending,
            State::Settled => TransactionState::Settled,
            State::Failed => TransactionState::Failed,
            State::Expired => TransactionState::Expired,
        }),
        description_hash: invoice.as_ref().and_then(|i| match i.description() {
            lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(h) => Some(h.0.to_string()),
            lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(_) => None,
        }),
        expires_at: invoice.as_ref().map(|i| {
            Timestamp::from_secs(i.duration_since_epoch().as_secs() + i.expiry_time().as_secs())
        }),
        invoice: Some(a.invoice),
        description: a.description,
        preimage: a.preimage,
        payment_hash: a.hash,
        amount: a.amount,
        fees_paid: match a.direction {
            Direction::Outgoing => a.fee,
            Direction::Incoming => 0,
        },
        created_at: Timestamp::from_secs(a.created_at as u64),
        settled_at: a.settled_at.map(|at| Timestamp::from_secs(at as u64)),
        metadata: None,
    }
}

/// The requests answered lately, by id.
#[derive(Default)]
struct Answered {
    ids: HashSet<EventId>,
    order: VecDeque<EventId>,
}

impl Answered {
    /// False if `id` was answered already.
    fn first(&mut self, id: EventId) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > REMEMBERED {
            if let Some(old) = self.order.pop_front() {
                self.ids.remove(&old);
            }
        }
        true
    }
}

/// Serve NWC requests on the bridge's relays, for good: its info event
/// published, each request answered as it comes, alongside.
pub async fn run<T: Transport + 'static>(bridge: Arc<Bridge<T>>) -> anyhow::Result<()> {
    let relays = &bridge.config().relays;
    anyhow::ensure!(!relays.is_empty(), "no Nostr relay to serve NWC on");
    let client = Client::builder().build();
    for relay in relays {
        client.add_relay(relay.as_str()).await?;
    }
    client.connect().and_wait(Duration::from_secs(10)).await;
    let info = info_event(&bridge)?;
    if let Err(e) = client.send_event(&info).await {
        tracing::warn!("publishing the NWC info event: {e}");
    }
    let me = bridge.keys().public_key();
    // What comes from now on: a request older than a restart was given
    // up by its client.
    let filter = Filter::new()
        .kind(Kind::WalletConnectRequest)
        .pubkey(me)
        .since(Timestamp::now() - 60);
    let mut notifications = client.notifications();
    client.subscribe(filter).await?;
    tracing::info!(nostr = %me.to_hex(), relays = relays.len(), "serving NWC");
    let answered = Arc::new(Mutex::new(Answered::default()));
    let publishing = Arc::new(Mutex::new(HashSet::new()));
    let mut published = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        let notification = tokio::select! {
            notification = notifications.next() => match notification {
                Some(notification) => notification,
                None => break,
            },
            _ = tick.tick() => {
                publish_zaps(&bridge, &publishing);
                // Some relays drop replaceable events in time: published
                // again.
                if published.elapsed() > Duration::from_secs(3600) {
                    published = tokio::time::Instant::now();
                    let client = client.clone();
                    let info = info.clone();
                    tokio::spawn(async move { client.send_event(&info).await });
                }
                continue;
            }
        };
        let ClientNotification::Event { event, .. } = notification else {
            continue;
        };
        if event.kind != Kind::WalletConnectRequest {
            continue;
        }
        let first = answered
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .first(event.id);
        if !first {
            continue;
        }
        let (bridge, client) = (bridge.clone(), client.clone());
        tokio::spawn(async move {
            if let Some(response) = answer(&bridge, &event).await {
                if let Err(e) = client.send_event(&response).await {
                    tracing::warn!("answering an NWC request: {e}");
                }
            }
        });
    }
    anyhow::bail!("the Nostr relays' notifications ended")
}

/// Publish the zap receipts due, each once at a time, alongside: given up
/// on a day after its zap was paid.
fn publish_zaps<T: Transport + 'static>(
    bridge: &Arc<Bridge<T>>,
    publishing: &Arc<Mutex<HashSet<[u8; 32]>>>,
) {
    let receipts = match bridge.zap_receipts() {
        Ok(receipts) => receipts,
        Err(e) => {
            tracing::warn!("zap receipts: {e}");
            return;
        }
    };
    for zap in receipts {
        let first = publishing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(zap.hash);
        if !first {
            continue;
        }
        let (bridge, publishing) = (bridge.clone(), publishing.clone());
        tokio::spawn(async move {
            let sent = publish(&zap).await;
            let stale = licash_store::now() - zap.settled_at > 86_400;
            if sent || stale {
                if !sent {
                    tracing::warn!(hash = %hex::encode(zap.hash), "a zap receipt given up on");
                }
                if let Err(e) = bridge.zap_published(&zap.hash) {
                    tracing::warn!("a zap receipt published: {e}");
                }
            }
            publishing
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&zap.hash);
        });
    }
}

/// Whether a relay of those `zap` names took it.
async fn publish(zap: &crate::lnurl::ZapReceipt) -> bool {
    let client = Client::builder().build();
    for relay in &zap.relays {
        if let Err(e) = client.add_relay(relay.as_str()).await {
            tracing::debug!(%relay, "a zap receipt's relay: {e}");
        }
    }
    client.connect().and_wait(Duration::from_secs(5)).await;
    let sent = client.send_event(&zap.event).await;
    client.disconnect().await;
    match sent {
        Ok(output) => !output.success.is_empty(),
        Err(e) => {
            tracing::debug!("publishing a zap receipt: {e}");
            false
        }
    }
}
