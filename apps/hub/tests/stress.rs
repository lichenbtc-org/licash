//! Payments at once through the hub service over HTTP: wallets in a ring,
//! each paying the next while it takes in what the last paid it. What
//! they measure (payments a second, each one's time) is printed; what they
//! check is that every payment lands once, and that the notes paid in
//! less the hub's fees are what the wallets hold after.
//!
//! The quick one runs with the rest. The sweep, many wallets at once to
//! find where the hub stops keeping up, is ignored:
//! `cargo test --release --manifest-path apps/Cargo.toml -p licash-hub-service --test stress -- --ignored --nocapture`.
//! `LICASH_STRESS_WALLETS` (comma separated) and `LICASH_STRESS_SENDS`
//! choose its sizes, `LICASH_STRESS_HUB_DIR` where the hub keeps its files.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use licash::spend::ChainProfile;
use licash_hub::{Hub, Policy};
use licash_hub_service::Services;
use licash_transport::Http;
use licash_wallet::Wallet;

/// The largest note the hub's keyset makes: 2^16 sat.
const NOTE_POW: u32 = 16;
/// What each payment pays, in sat.
const AMOUNT: u64 = 100;

/// A hub service on a port of its own, of `dir`: its URL and the hub.
async fn hub(dir: &Path) -> Result<(String, Arc<Hub>)> {
    let (seed, db) = (dir.join("seed"), dir.join("hub.sqlite"));
    Hub::init(&seed, &db, NOTE_POW)?;
    let hub = Arc::new(Hub::open(&seed, &db, Policy::default())?);
    // Regtest's genesis, for it to prove its identity there.
    let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
    hub.add_checkpoint(&licash::chain::Checkpoint::new(
        ChainProfile::Core30DefaultRegtest,
        0,
        bitcoin::consensus::serialize(&genesis)
            .try_into()
            .expect("80 bytes"),
        vec![genesis.time],
        None,
    )?)?;
    let app = licash_hub_service::router(hub.clone(), Services::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    // As the hub's binary serves it: each request's peer known. On a
    // runtime of its own, so that the wallets' work (theirs, on the test's
    // runtime) does not stall its threads: what is measured is the hub.
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = listener.into_std()?;
    std::thread::spawn(move || {
        // Its threads named, and kept, for [`hub_cpu`] to count.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name(HUB_THREADS)
            .thread_keep_alive(Duration::from_secs(3600))
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("a listener");
            axum::serve(listener, app).await
        })
    });
    Ok((url, hub))
}

/// The name of the threads the hub service runs on.
const HUB_THREADS: &str = "stress-hub";

/// The CPU time the hub service's threads took so far, on Linux: none
/// elsewhere.
fn hub_cpu() -> Option<Duration> {
    let mut ticks = 0u64;
    for task in std::fs::read_dir("/proc/self/task").ok()? {
        let stat = std::fs::read_to_string(task.ok()?.path().join("stat")).ok()?;
        // "pid (name) state ...": the name may hold spaces, not ')'.
        let (head, rest) = stat.rsplit_once(')')?;
        if !head.ends_with(HUB_THREADS) {
            continue;
        }
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // utime and stime, the 14th and 15th fields of the whole line.
        ticks += fields.get(11)?.parse::<u64>().ok()? + fields.get(12)?.parse::<u64>().ok()?;
    }
    // USER_HZ, 100 on every Linux the tests run on.
    Some(Duration::from_millis(ticks * 10))
}

/// A payment of `amount` to `to` at `hub` (seed file `seed`, reached at
/// `url`), its fee paid, from notes its keys made for someone outside any
/// wallet.
fn pay(
    hub: &Hub,
    seed: &Path,
    url: &str,
    to: &licash::address::Address,
    amount: u64,
) -> Result<licash_api::Payment> {
    use licash::address::{Ephemeral, OwnerKeys};
    use licash::authorization::{Authorization, SignedProposal};
    use licash::claim::Branch;
    use licash::note::{Evidence, IssuerKeys, Note};
    use licash::spend::{Output, Proposal};
    use licash::unlink::Nonce;

    let split = |mut amount: u64| {
        let mut denoms = Vec::new();
        while amount > 0 {
            let d = 1u64 << (63 - amount.leading_zeros());
            denoms.push(d);
            amount -= d;
        }
        denoms
    };
    let mut bytes = [0; 32];
    hex::decode_to_slice(std::fs::read_to_string(seed)?.trim(), &mut bytes)?;
    let keys = IssuerKeys::from_seed(&bytes, 0, NOTE_POW)?;
    let keyset = keys.keyset()?;
    let info = hub.info();
    let mut total = amount;
    while amount + info.policy.spend.due(total) != total {
        total = amount + info.policy.spend.due(total);
    }
    let payer = OwnerKeys::from_seed(&[0xfa; 32])?;
    let mut inputs = Vec::new();
    for denom in split(total) {
        let d = Ephemeral::random().derive(&payer.address(), denom, Branch::Pay, 0)?;
        let output = Output::from_derivation(&d)?;
        let proof = keys.prove_blinded(denom, output.blinded())?;
        let note = Note::from_parts(
            &keyset,
            *keyset.id(),
            d.message().clone(),
            proof.open_point(&keyset, &d)?,
            Evidence::Linked {
                dleq: proof.dleq(),
                blinding: *d.blinding(),
                commit: Nonce::new(&keyset, &output)?.commit()?,
            },
        )?;
        inputs.push((note, d));
    }
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
        .map(|(i, (d, to))| Output::from_derivation(&ephemeral.derive(to, d, Branch::Pay, i)?))
        .collect::<Result<Vec<_>, _>>()?;
    let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None)?;
    let grant = hub.offer(&proposal, &notes)?;
    let owners = inputs
        .iter()
        .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()))
        .collect::<Result<Vec<_>, _>>()?;
    let signed = SignedProposal::sign(
        &keyset,
        proposal,
        &notes,
        Authorization::Granted(Box::new(grant)),
        &owners,
    )?;
    let unlock = hub.release(&signed, &notes)?;
    Ok(licash_api::Payment::new(url, &signed, &notes, &unlock))
}

fn available(wallet: &Wallet<Http>) -> Result<u64> {
    Ok(wallet.balance()?.iter().map(|b| b.available).sum())
}

/// What a ring of payments measured.
#[derive(Debug)]
struct Ring {
    wallets: usize,
    payments: usize,
    failed: usize,
    elapsed: Duration,
    /// The CPU time the hub took for them, if told.
    hub_cpu: Option<Duration>,
    /// Each payment's time, sorted.
    times: Vec<Duration>,
}

impl Ring {
    fn rate(&self) -> f64 {
        self.payments as f64 / self.elapsed.as_secs_f64()
    }

    fn at(&self, q: f64) -> Duration {
        let i = ((self.times.len() as f64 - 1.0) * q).round() as usize;
        self.times.get(i).copied().unwrap_or_default()
    }

    fn show(&self) {
        // The hub's CPU a payment: what bounds a hub of N cores to N over
        // it a second, whatever else the machine runs.
        let cpu = match self.hub_cpu {
            Some(cpu) => format!(
                ", hub CPU {:.1} ms a payment",
                cpu.as_secs_f64() * 1000.0 / self.payments.max(1) as f64
            ),
            None => String::new(),
        };
        eprintln!(
            "{:>4} wallets: {:>5} payments ({} failed) in {:>6.2} s, {:>7.1}/s, p50 {:>4} ms, p99 {:>4} ms, max {:>5} ms{cpu}",
            self.wallets,
            self.payments,
            self.failed,
            self.elapsed.as_secs_f64(),
            self.rate(),
            self.at(0.5).as_millis(),
            self.at(0.99).as_millis(),
            self.times.last().copied().unwrap_or_default().as_millis(),
        );
    }
}

/// `wallets` wallets at one hub, each paid enough for `sends` payments of
/// [`AMOUNT`] and their fees, two at least, each paying the next that many times at once
/// with the others, each taking in what the last pays it as it comes.
/// Every payment that fails is counted, not retried.
async fn ring(wallets: usize, sends: usize) -> Result<Ring> {
    // One alone would pay itself, a payment it holds received already.
    ensure!(wallets >= 2, "a ring of {wallets} wallets");
    // The hub's files where `LICASH_STRESS_HUB_DIR` says, to measure it on
    // another disk (or none: /dev/shm); else in the temporary directory.
    let dir = match std::env::var_os("LICASH_STRESS_HUB_DIR") {
        Some(at) => tempfile::tempdir_in(at)?,
        None => tempfile::tempdir()?,
    };
    let (url, hub) = hub(dir.path()).await?;
    let fee = hub.info().policy.spend.due(AMOUNT);
    // The wallets' files in memory where it can be: theirs are on other
    // devices, their syncs not queued with the hub's on its disk.
    let shm = Path::new("/dev/shm");
    let held = match shm.is_dir() {
        true => tempfile::tempdir_in(shm)?,
        false => tempfile::tempdir()?,
    };
    let mut parties = Vec::new();
    for i in 0..wallets {
        let path = held.path().join(format!("w{i}.sqlite"));
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        let wallet = Wallet::create(
            &path,
            &seed,
            ChainProfile::Core30DefaultRegtest,
            Http::new(None)?,
        )?;
        wallet.add_hub(&url).await?;
        // Some over, for a change note's fee.
        let funds = sends as u64 * (AMOUNT + fee) * 2;
        let payment = pay(
            &hub,
            &dir.path().join("seed"),
            &url,
            &wallet.address(),
            funds,
        )?;
        wallet.receive(&payment)?;
        parties.push(wallet);
    }
    let paid_in: u64 = parties.iter().map(available).sum::<Result<u64>>()?;

    let (senders, inboxes): (Vec<_>, Vec<_>) = (0..wallets)
        .map(|_| tokio::sync::mpsc::unbounded_channel::<licash_api::Payment>())
        .unzip();
    let (start, cpu) = (Instant::now(), hub_cpu());
    let mut tasks = Vec::new();
    for (i, (wallet, mut inbox)) in parties.into_iter().zip(inboxes).enumerate() {
        let to = senders[(i + 1) % wallets].clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let mut times = Vec::new();
            let mut failed = 0;
            let mut received = 0;
            let payee = to_address(i + 1, wallets);
            for _ in 0..sends {
                while let Ok(p) = inbox.try_recv() {
                    wallet.receive(&p)?;
                    received += 1;
                }
                let at = Instant::now();
                match wallet.send(&url, &payee, AMOUNT).await {
                    Ok(paid) => {
                        times.push(at.elapsed());
                        let _ = to.send(paid.payment);
                    }
                    Err(e) => {
                        eprintln!("wallet {i}: a payment failed: {e}");
                        failed += 1;
                    }
                }
            }
            drop(to);
            anyhow::Ok((wallet, inbox, times, failed, received))
        }));
    }
    let mut done = Vec::new();
    for task in tasks {
        done.push(task.await??);
    }
    let elapsed = start.elapsed();
    let hub_cpu = hub_cpu()
        .zip(cpu)
        .map(|(after, before)| after.saturating_sub(before));
    // What is left in each inbox, now every payment is made.
    let mut times = Vec::new();
    let (mut failed, mut received, mut fees, mut held) = (0, 0, 0, 0);
    for (wallet, mut inbox, t, f, r) in done {
        received += r;
        while let Ok(p) = inbox.try_recv() {
            wallet.receive(&p)?;
            received += 1;
        }
        times.extend(t);
        failed += f;
        fees += wallet.sends()?.iter().map(|s| s.fee).sum::<u64>();
        held += available(&wallet)?;
    }
    times.sort();
    let payments = times.len();
    ensure!(
        received == payments,
        "{received} of {payments} payments received"
    );
    ensure!(
        held + fees == paid_in,
        "{held} held and {fees} in fees of {paid_in} paid in"
    );
    Ok(Ring {
        wallets,
        payments,
        failed,
        elapsed,
        hub_cpu,
        times,
    })
}

/// The address of the wallet [`ring`] makes `i`th (mod `wallets`).
fn to_address(i: usize, wallets: usize) -> licash::address::Address {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&((i % wallets) as u64 + 1).to_be_bytes());
    licash::address::OwnerKeys::from_seed(&seed)
        .expect("a seed")
        .address()
}

/// Eight wallets paying at once, ten payments each: every one lands
/// once, none fails, and no sat is made or lost.
#[tokio::test(flavor = "multi_thread")]
async fn wallets_paying_at_once_each_land_once_and_lose_nothing() -> Result<()> {
    let ring = ring(8, 10).await?;
    ring.show();
    ensure!(ring.failed == 0, "{ring:?}");
    ensure!(ring.payments == 80, "{ring:?}");
    Ok(())
}

/// Ever more wallets paying at once, to where the hub stops keeping up:
/// each size's rate and times printed, its payments checked as above.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "a long sweep: run with --ignored --nocapture"]
async fn a_sweep_of_wallets_paying_at_once() -> Result<()> {
    let sizes = std::env::var("LICASH_STRESS_WALLETS").unwrap_or_else(|_| "2,4,16,64,256".into());
    let sends: usize = match std::env::var("LICASH_STRESS_SENDS") {
        Ok(s) => s.parse().context("LICASH_STRESS_SENDS")?,
        Err(_) => 20,
    };
    for size in sizes.split(',') {
        let wallets: usize = size.trim().parse().context("LICASH_STRESS_WALLETS")?;
        ring(wallets, sends).await?.show();
    }
    Ok(())
}
