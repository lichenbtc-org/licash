//! A hub service on a local port that can go down and come back, following
//! a regtest chain of its own, with a deposit gateway or an index of silent
//! payment tweaks if asked, and a payer outside any wallet.

pub mod bridge;
#[path = "../../../hub/tests/chain/mod.rs"]
mod chain;
#[path = "../../../hub/tests/esplora/mod.rs"]
mod esplora;
pub mod swaps;

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
    thread::JoinHandle,
};

use bitcoin::{
    hashes::Hash,
    key::TweakedPublicKey,
    secp256k1::{Secp256k1, SecretKey},
    OutPoint, ScriptBuf, Transaction, Txid,
};
use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, SignedProposal},
    claim::Branch,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{Output as SpendOutput, Proposal},
    unlink::Nonce,
};
use licash_api::{Fee, Payment};
use licash_hub::{Hub, Policy, Timing};
use licash_hub_service::{deposit, tweaks::Tweaks};

const MAX_POW: u32 = 6;

/// Blocks a deposit is refundable after it is asked for: its window,
/// depth, lock blocks, the lock's depth, downtime and sweep blocks.
pub const DEPOSIT_TIMEOUT: u32 = 10 + 2 + 6 + 1 + 2 + 6;

/// A Nostr relay in this process, and its URL. It probes for a free port
/// before binding it, which another socket may take in between: it is
/// tried again then.
pub fn relay(runtime: &tokio::runtime::Runtime) -> (nostr_sdk::prelude::MockRelay, String) {
    let mut failed = None;
    for _ in 0..5 {
        match runtime.block_on(nostr_sdk::prelude::MockRelay::run()) {
            Ok(relay) => {
                let url = runtime.block_on(relay.url()).to_string();
                return (relay, url);
            }
            Err(e) => failed = Some(e),
        }
    }
    panic!("no mock relay: {failed:?}");
}

/// Where the hub's deposit claims pay.
pub fn sweep() -> ScriptBuf {
    let key = SecretKey::from_slice(&[9; 32]).unwrap();
    let key = key.x_only_public_key(&Secp256k1::new()).0;
    ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(key))
}

/// The timing of the hub's locks: short, to expire them in a test.
const TIMING: Timing = Timing {
    window: 20,
    reaction: 2,
    min_depth: 1,
    max_headers: 4032,
    bury: 6,
    max_lag: 120,
};

/// The response window of a hub swapped from: a provider's lock at a hub of
/// [`TIMING`]'s window of 20 expires 32 blocks before the client's with
/// [`swaps::CONFIG`], and leaves room to claim it.
pub const SOURCE_WINDOW: u32 = 46;

pub struct Server {
    pub hub: Arc<Hub>,
    /// The deposit gateway, and the URL of the mock Esplora it follows.
    pub deposits: Option<(Arc<deposit::Gateway>, String)>,
    /// The index of silent payment tweaks, following the mock Esplora.
    tweaks: Option<Arc<Tweaks>>,
    /// The mailbox relays its info names.
    relays: Vec<String>,
    /// Where it keeps payments for their payees, if it does.
    inbox: Option<Arc<licash_hub_service::inbox::Inbox>>,
    backend: esplora::Shared,
    addr: SocketAddr,
    seed: PathBuf,
    running: Option<(tokio::sync::oneshot::Sender<()>, JoinHandle<()>)>,
    _dir: tempfile::TempDir,
}

impl Server {
    /// A hub charging `fee` on spends and in each branch of a lock, at
    /// height 3 of its chain.
    pub fn start(fee: Fee) -> Self {
        Self::started(fee, false, false, Vec::new())
    }

    /// [`Server::start`], taking deposits of 1000 to 4000 for a fee of
    /// 100, paid by block 10 after they are asked for, claimed to
    /// [`SWEEP`] and refundable [`DEPOSIT_TIMEOUT`] blocks after.
    pub fn with_deposits(fee: Fee) -> Self {
        Self::started(fee, true, false, Vec::new())
    }

    /// [`Server::with_deposits`], serving the silent payment tweaks of its
    /// chain from its height on, indexed each [`Server::round`].
    pub fn with_tweaks(fee: Fee) -> Self {
        Self::started(fee, true, true, Vec::new())
    }

    /// [`Server::start`], naming `relays` for its wallets' mailboxes.
    pub fn with_relays(fee: Fee, relays: Vec<String>) -> Self {
        Self::started(fee, false, false, relays)
    }

    /// [`Server::with_relays`], keeping the payments its wallets ask it to
    /// for their payees, as hubs do.
    pub fn keeping(fee: Fee, relays: Vec<String>) -> Self {
        let mut server = Self::with_relays(fee, relays);
        let path = server._dir.path().join("hub.sqlite");
        server.inbox = Some(Arc::new(
            licash_hub_service::inbox::Inbox::open(&path).unwrap(),
        ));
        server.down();
        server.up();
        server
    }

    /// [`Server::with_relays`], of a response window of [`SOURCE_WINDOW`]:
    /// a hub to swap from, to one of the usual window, through a provider
    /// that is not the hub swapped to.
    pub fn swapping_from(fee: Fee, relays: Vec<String>) -> Self {
        let timing = Timing {
            window: SOURCE_WINDOW,
            ..TIMING
        };
        Self::timed(fee, (false, false), relays, timing)
    }

    fn started(fee: Fee, deposits: bool, tweaks: bool, relays: Vec<String>) -> Self {
        Self::timed(fee, (deposits, tweaks), relays, TIMING)
    }

    fn timed(
        fee: Fee,
        (deposits, tweaks): (bool, bool),
        relays: Vec<String>,
        timing: Timing,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (seed, db) = (dir.path().join("seed"), dir.path().join("hub.sqlite"));
        Hub::init(&seed, &db, MAX_POW).unwrap();
        let policy = Policy {
            spend: fee,
            lock: fee,
            refund: fee,
            output_msat: 0,
            timing,
        };
        let hub = Arc::new(Hub::open(&seed, &db, policy).unwrap());
        let chain = chain::Chain::new();
        hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
        let backend = esplora::backend(chain);
        let deposits = deposits.then(|| {
            let url = esplora::serve(backend.clone());
            let config = deposit::Config {
                fee: Fee { base: 100, ppm: 0 },
                min: 1_000,
                max: 4_000,
                depth: 2,
                window: 10,
                lock_blocks: 6,
                downtime: 2,
                sweep_blocks: 6,
                min_fee_rate: bitcoin::FeeRate::from_sat_per_vb_u32(1),
                // As hubs took them before they took those of closes only.
                plain: true,
                ..deposit::Config::new(sweep())
            };
            let (source, path) = (url.parse().unwrap(), dir.path().join("hub.sqlite"));
            let profile = licash::spend::ChainProfile::Core30DefaultRegtest;
            let gateway = deposit::Gateway::open(hub.clone(), source, profile, config, &path);
            (Arc::new(gateway.unwrap()), url)
        });
        let tweaks = tweaks.then(|| {
            let path = dir.path().join("tweaks.sqlite");
            Arc::new(Tweaks::open(&path).unwrap())
        });
        let mut server = Self {
            hub,
            deposits,
            tweaks,
            relays,
            inbox: None,
            backend,
            addr: "127.0.0.1:0".parse().unwrap(),
            seed,
            running: None,
            _dir: dir,
        };
        server.mine(3, None);
        server.round();
        server.up();
        server
    }

    /// One round of the deposit gateway, if any, and the index of tweaks
    /// following it.
    pub fn round(&self) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if let Some((gateway, url)) = &self.deposits {
            runtime.block_on(gateway.round());
            if let Some(tweaks) = &self.tweaks {
                let source = url.parse().unwrap();
                let step = licash_hub_service::tweaks::step(tweaks, &source, None);
                runtime.block_on(step).unwrap();
            }
        }
    }

    /// Mine `blocks`, the first with an activation of `secret` if given,
    /// which the hub scans.
    pub fn mine(&self, blocks: u32, secret: Option<[u8; 32]>) {
        self.mine_with(blocks, secret, Vec::new());
    }

    /// [`Server::mine`], the first block with `txs`.
    fn mine_with(&self, blocks: u32, mut secret: Option<[u8; 32]>, mut txs: Vec<Transaction>) {
        let mut backend = self.backend.lock().unwrap();
        let ids: Vec<Txid> = txs.iter().map(Transaction::compute_txid).collect();
        backend.mempool.retain(|t| !ids.contains(&t.compute_txid()));
        let chain = &mut backend.chain;
        for _ in 0..blocks {
            let block = chain
                .mine_with(secret.take(), std::mem::take(&mut txs))
                .clone();
            self.hub.observe(chain.height(), &block).unwrap();
        }
        assert!(self.hub.synced(chain.height(), &chain.tip()).unwrap());
    }

    pub fn height(&self) -> u32 {
        self.backend.lock().unwrap().chain.height()
    }

    /// A payment of `sat` to `address` on Bitcoin, mined, from coins of
    /// the `n`th payer, of a script hash, which silent payments skip: what
    /// it pays.
    pub fn pay_onchain(&self, address: &str, sat: u64, n: u8) -> OutPoint {
        let address: bitcoin::Address<_> = address.parse().unwrap();
        let previous_output = OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        };
        let spent = ScriptBuf::new_p2wsh(&ScriptBuf::from_bytes(vec![0x51]).wscript_hash());
        self.backend
            .lock()
            .unwrap()
            .outside
            .insert(previous_output, spent);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output,
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(sat),
                script_pubkey: address.assume_checked().script_pubkey(),
            }],
        };
        let txid = tx.compute_txid();
        self.mine_with(1, None, vec![tx]);
        OutPoint { txid, vout: 0 }
    }

    /// A silent payment of `sat` to `to`, mined, from a key-hash coin of
    /// the `n`th payer: what it pays.
    pub fn pay_silent(&self, to: &str, sat: u64, n: u8) -> OutPoint {
        let to: licash_onchain::silent::SpAddress = to.parse().unwrap();
        let secp = Secp256k1::new();
        let sender = SecretKey::from_slice(&[n; 32]).unwrap();
        let key = bitcoin::CompressedPublicKey(sender.public_key(&secp));
        let previous_output = OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        };
        let spent = ScriptBuf::new_p2wpkh(&key.wpubkey_hash());
        self.backend
            .lock()
            .unwrap()
            .outside
            .insert(previous_output, spent);
        let paid = licash_onchain::silent::outputs(&[(sender, false)], &[previous_output], &[to]);
        let output = TweakedPublicKey::dangerous_assume_tweaked(paid.unwrap()[0]);
        let mut witness = bitcoin::Witness::new();
        witness.push([0x30; 71]);
        witness.push(key.to_bytes());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output,
                witness,
                ..Default::default()
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(sat),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(output),
            }],
        };
        let txid = tx.compute_txid();
        self.mine_with(1, None, vec![tx]);
        OutPoint { txid, vout: 0 }
    }

    /// The transactions sent to the chain, not mined yet.
    pub fn sent(&self) -> Vec<Transaction> {
        self.backend.lock().unwrap().mempool.clone()
    }

    /// Mine what was sent, in one block.
    pub fn confirm_sent(&self) {
        let sent = self.sent();
        self.mine_with(1, None, sent);
    }

    /// The mock Esplora's URL, as `--chain` takes it.
    pub fn esplora(&self) -> &str {
        &self.deposits.as_ref().expect("deposits").1
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Serve again, at the same address.
    pub fn up(&mut self) {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (bound, addr) = std::sync::mpsc::channel();
        let (hub, at) = (self.hub.clone(), self.addr);
        let deposits = self.deposits.as_ref().map(|(gateway, _)| gateway.clone());
        let tweaks = self.tweaks.clone();
        let relays = self.relays.clone();
        let inbox = self.inbox.clone();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = within(|| {
                    let socket = tokio::net::TcpSocket::new_v4()?;
                    socket.set_reuseaddr(true)?;
                    socket.bind(at)?;
                    socket.listen(64)
                });
                bound.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(
                    listener,
                    licash_hub_service::router(
                        hub,
                        licash_hub_service::Services {
                            deposits,
                            tweaks,
                            inbox,
                            relays,
                            contracts: None,
                            urls: Default::default(),
                            ingress: Default::default(),
                        },
                    ),
                )
                .with_graceful_shutdown(async {
                    stopped.await.ok();
                })
                .await
                .unwrap();
            });
        });
        self.addr = addr.recv().unwrap();
        self.running = Some((stop, thread));
    }

    pub fn down(&mut self) {
        let (stop, thread) = self.running.take().unwrap();
        stop.send(()).unwrap();
        thread.join().unwrap();
    }

    /// Served again as a new run of the hub, opened from its files: it no
    /// longer unlinks the notes it issued before. Of a hub without
    /// gateways, which would hold the run before.
    pub fn restarted(mut self) -> Self {
        assert!(self.deposits.is_none());
        if self.running.is_some() {
            self.down();
        }
        let policy = self.hub.info().policy;
        // The run before stops first: one runs on its files at a time.
        let before = Arc::into_inner(self.hub).expect("the only hold of the run before");
        drop(before);
        let db = self._dir.path().join("hub.sqlite");
        let hub = within(|| Hub::open(&self.seed, &db, policy));
        {
            let chain = &self.backend.lock().unwrap().chain;
            assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
        }
        self.hub = Arc::new(hub);
        self.up();
        self
    }

    /// A payment of `amount` to `to`, its fee paid, from notes the hub's
    /// keys made for someone outside any wallet.
    pub fn pay(&self, to: &Address, amount: u64) -> Payment {
        let text = std::fs::read_to_string(&self.seed).unwrap();
        let mut seed = [0; 32];
        hex::decode_to_slice(text.trim(), &mut seed).unwrap();
        let keys = IssuerKeys::from_seed(&seed, 0, MAX_POW).unwrap();
        let keyset = keys.keyset().unwrap();
        let info = self.hub.info();
        let mut total = amount;
        while amount + info.policy.spend.due(total) != total {
            total = amount + info.policy.spend.due(total);
        }
        let payer = OwnerKeys::from_seed(&[0xfa; 32]).unwrap();
        let inputs: Vec<(Note, Derivation)> = split(total)
            .into_iter()
            .map(|denom| mint(&keys, &keyset, &payer.address(), denom))
            .collect();
        let notes: Vec<Note> = inputs.iter().map(|(note, _)| note.clone()).collect();
        let ephemeral = Ephemeral::random();
        let to_hub = split(total - amount)
            .into_iter()
            .map(|d| (d, &info.address));
        let outputs = split(amount)
            .into_iter()
            .map(|d| (d, to))
            .chain(to_hub)
            .enumerate()
            .map(|(i, (d, to))| {
                let derivation = ephemeral.derive(to, d, Branch::Pay, i).unwrap();
                SpendOutput::from_derivation(&derivation).unwrap()
            })
            .collect();
        let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None).unwrap();
        let grant = self.hub.offer(&proposal, &notes).unwrap();
        let owners: Vec<_> = inputs
            .iter()
            .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()).unwrap())
            .collect();
        let grant = Authorization::Granted(Box::new(grant));
        let signed = SignedProposal::sign(&keyset, proposal, &notes, grant, &owners).unwrap();
        let unlock = self.hub.release(&signed, &notes).unwrap();
        Payment::new(&self.url(), &signed, &notes, &unlock)
    }
}

fn split(mut amount: u64) -> Vec<u64> {
    let mut denoms = Vec::new();
    for pow in (0..=MAX_POW).rev() {
        while amount >= 1 << pow {
            denoms.push(1 << pow);
            amount -= 1 << pow;
        }
    }
    denoms
}

fn mint(keys: &IssuerKeys, keyset: &Keyset, to: &Address, denom: u64) -> (Note, Derivation) {
    let d = Ephemeral::random()
        .derive(to, denom, Branch::Pay, 0)
        .unwrap();
    let output = SpendOutput::from_derivation(&d).unwrap();
    let proof = keys.prove_blinded(denom, output.blinded()).unwrap();
    let note = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: Nonce::new(keyset, &output).unwrap().commit().unwrap(),
        },
    )
    .unwrap();
    (note, d)
}

/// `licash-wallet --wallet <wallet> <args>`, `input` on its stdin.
pub fn wallet(wallet: &Path, args: &[&str], input: Option<&str>) -> Output {
    wallet_command(wallet, args, input, false)
}

pub fn wallet_command(wallet: &Path, args: &[&str], input: Option<&str>, collect: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_licash-wallet"));
    command
        .arg("--wallet")
        .arg(wallet)
        .args(args)
        .env_remove("LICASH_WALLET_PROXY")
        .env_remove("LICASH_WALLET_TOR")
        .env(
            "LICASH_WALLET_NO_COLLECT",
            if collect { "false" } else { "true" },
        )
        .env_remove("LICASH_WALLET_CHAIN")
        .env_remove("LICASH_WALLET_RENEW_PPM")
        .env_remove("LICASH_WALLET_LOG")
        .env_remove("RUST_LOG")
        // Its hubs follow regtest.
        .env("LICASH_WALLET_NETWORK", "regtest")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take().unwrap();
    if let Some(input) = input {
        use std::io::Write;
        let mut stdin = stdin;
        stdin.write_all(input.as_bytes()).unwrap();
    }
    child.wait_with_output().unwrap()
}

/// `attempt`'s value, tried again for a few seconds while it fails: the
/// port given up by the run before may be another test's connection's for
/// a moment, and its lock held by a process another test spawns, until
/// that process runs its program.
fn within<T, E: std::fmt::Debug>(mut attempt: impl FnMut() -> Result<T, E>) -> T {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match attempt() {
            Ok(value) => return value,
            Err(e) if std::time::Instant::now() > until => panic!("{e:?}"),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
}
