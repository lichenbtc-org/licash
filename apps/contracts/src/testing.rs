//! One real mock opening shared by lifecycle fixtures. Its snapshots are
//! built through the public protocol, never hand-edited into funded state.
use std::{collections::VecDeque, sync::OnceLock};

use bitcoin::{
    absolute,
    hashes::Hash,
    key::TapTweak,
    secp256k1::{Keypair, Message, SecretKey, SECP256K1},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
};
use licash::spend::ChainProfile;
use licash_contract::{
    opening::{self, Context, Holder, Hub, Input, Out, Quote, Start, Trust},
    wire::{Envelope, Instance, Kind, Wanted},
};
use licash_wallet::{Response, Transport, Wallet};

/// A hub's data directory `dir`: its database made, holding no component
/// yet, for the hub's tables to be made in: made once.
pub(crate) fn hub_data(dir: &std::path::Path) -> std::path::PathBuf {
    let file = crate::hub_db(dir);
    if !file.exists() {
        drop(licash_store::create(&file, licash_store::Kind::Hub).unwrap());
    }
    dir.to_path_buf()
}

/// A file of a wallet's kind in `dir`, holding no wallet and no contracts
/// yet, for the holder's tables to be made in: made once.
pub(crate) fn wallet_file(dir: &std::path::Path) -> std::path::PathBuf {
    let file = dir.join("wallet.sqlite");
    if !file.exists() {
        drop(licash_store::create(&file, licash_store::Kind::Wallet).unwrap());
    }
    file
}

struct Offline;
impl Transport for Offline {
    async fn request(&self, _: &str, _: Option<Vec<u8>>) -> Result<Response, String> {
        Err("no network in a protocol fixture".into())
    }
}
pub(crate) struct Opened {
    pub seed: [u8; 32],
    pub holder: Vec<u8>,
    pub hub: Vec<u8>,
}
pub(crate) fn opened() -> &'static Opened {
    static OPENED: OnceLock<Opened> = OnceLock::new();
    OPENED.get_or_init(|| build(0))
}
/// As [`opened`], of graph id 7, as every hub quoted before
/// `graph::RETURNING`.
pub(crate) fn opened_before() -> &'static Opened {
    static OPENED: OnceLock<Opened> = OnceLock::new();
    OPENED.get_or_init(|| build(7))
}
/// As [`opened`], of a graph returning the hub its reserve on
/// `request_timeout` (`graph::RETURNING`), as hubs quote now.
pub(crate) fn opened_returning() -> &'static Opened {
    static OPENED: OnceLock<Opened> = OnceLock::new();
    OPENED.get_or_init(|| build(licash_contract::graph::RETURNING))
}
/// As [`opened`], of a graph carrying her claim and the hub's disclosure in
/// leaf envelopes ([`licash::recovery::LEAF_FROM`]).
pub(crate) fn opened_leaf() -> &'static Opened {
    static OPENED: OnceLock<Opened> = OnceLock::new();
    OPENED.get_or_init(|| build(licash::recovery::LEAF_FROM))
}
fn sign(tx: &mut Transaction, prevouts: &[TxOut], inputs: &[usize], key: &Keypair) {
    for &i in inputs {
        let hash = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), TapSighashType::Default)
            .unwrap();
        let key = key.tap_tweak(SECP256K1, None);
        let signature = SECP256K1.sign_schnorr_no_aux_rand(
            &Message::from_digest(hash.to_byte_array()),
            key.as_keypair(),
        );
        tx.input[i].witness = Witness::from_slice(&[signature.as_ref()]);
    }
}
/// An opening of graph id `id`.
fn build(id: u32) -> Opened {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Wallet::create(
        &dir.path().join("wallet.sqlite"),
        &[7; 32],
        ChainProfile::Core30DefaultRegtest,
        Offline,
    )
    .unwrap();
    let seed = wallet.contract_secrets().seed;
    let mut quote = Quote::from_base(&opening::testing::base(&[3; 32]));
    quote.cap = 131_071;
    quote.graph.id = id;
    quote.graph.bits = 17;
    quote.graph.reserve_alice = 20000;
    quote.graph.reserve_hub = 100000;
    quote.graph.deposit_units = 12;
    quote.graph.request_height = 360;
    quote.graph.close_height = 504;
    quote.fees.opening_fee_quote = 3000;
    quote.chain.max_headers = 1000;
    let wanted = Wanted {
        request_height: quote.graph.request_height,
        close_height: quote.graph.close_height,
        response_window: quote.graph.response_window,
    };
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[12; 32]).unwrap());
    let coin = TxOut {
        // Her reserve, the fee and her part of the contract: no change.
        value: Amount::from_sat(20000 + 3000 + 12),
        script_pubkey: ScriptBuf::new_p2tr(SECP256K1, key.x_only_public_key().0, None),
    };
    let ctx = Context {
        tip: 0,
        trust: Trust::mock(),
    };
    let (mut holder, first) = Holder::start(
        Start {
            seed,
            checkpoint: quote.chain.checkpoint.clone(),
            quote: quote.clone(),
            deposit: OutPoint {
                txid: Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            coin: coin.clone(),
            payout: coin.script_pubkey.clone(),
            wanted,
            funded: opening::testing::funded(),
            close: opening::testing::close(),
        },
        &ctx,
    )
    .unwrap();
    let mut hub = Hub::new(
        quote,
        opening::Bounds {
            lock: 2000,
            response_window: 8,
        },
        ScriptBuf::new_p2tr(
            SECP256K1,
            Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[13; 32]).unwrap())
                .x_only_public_key()
                .0,
            None,
        ),
    );
    // true is the holder's effect; false is the hub's.
    let mut queue: VecDeque<_> = first.into_iter().map(|o| (true, o)).collect();
    // Until she holds F whole, as the hub answers her signed consent.
    while let Some((alice, out)) = queue.pop_front() {
        if holder.wholly_funded() {
            break;
        }
        let (side, more) = match out {
            Out::Send(bytes) if alice => (false, hub.step(Input::Message(bytes), &ctx).unwrap()),
            Out::Send(bytes) => (true, holder.step(Input::Message(bytes), &ctx).unwrap()),
            Out::Serve { i } if alice => {
                let bytes = holder.instance(i).unwrap();
                let message = Envelope {
                    id: holder.id(),
                    kind: Kind::Instance,
                    body: Instance { i, bytes }.encode(),
                }
                .to_bytes();
                (false, hub.step(Input::Message(message), &ctx).unwrap())
            }
            Out::Keep { .. } if !alice => continue,
            Out::Fund {
                deposit,
                coin,
                mut outputs,
            } if !alice => {
                let hub_coin = TxOut {
                    value: Amount::from_sat(5000000),
                    script_pubkey: coin.script_pubkey.clone(),
                };
                let total: u64 = outputs.iter().map(|o| o.value.to_sat()).sum();
                outputs.push(TxOut {
                    value: Amount::from_sat(5_000_000 + coin.value.to_sat() - total - 100),
                    script_pubkey: hub.keys().party.public().payout_spk,
                });
                let funding = Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    input: vec![
                        TxIn {
                            previous_output: deposit,
                            ..Default::default()
                        },
                        TxIn {
                            previous_output: OutPoint {
                                txid: Txid::from_byte_array([8; 32]),
                                vout: 0,
                            },
                            ..Default::default()
                        },
                    ],
                    output: outputs,
                };
                (
                    false,
                    hub.step(
                        Input::Funded {
                            funding,
                            prevouts: vec![coin, hub_coin],
                        },
                        &ctx,
                    )
                    .unwrap(),
                )
            }
            Out::Sign {
                mut funding,
                prevouts,
                inputs,
            } => {
                sign(&mut funding, &prevouts, &inputs, &key);
                if alice {
                    (true, holder.step(Input::Signed(funding), &ctx).unwrap())
                } else {
                    (false, hub.step(Input::Signed(funding), &ctx).unwrap())
                }
            }
            Out::Broadcast(_) if !alice => continue,
            other => panic!("unexpected fixture effect {other:?}"),
        };
        queue.extend(more.into_iter().map(|out| (side, out)));
    }
    assert!(holder.wholly_funded());
    assert_eq!(hub.phase(), opening::HubPhase::Funded);
    Opened {
        seed,
        holder: holder.to_bytes(),
        hub: hub.to_bytes(),
    }
}
