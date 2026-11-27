//! The `licash-hub` binary end to end: create, run, watch and stop a hub.

mod chain;

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use licash::{
    address::{Ephemeral, OwnerKeys},
    claim::Branch,
    spend::{self, ChainProfile, TimedTerms},
};
use licash_hub::{Hub, Policy};

fn hub(data: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_licash-hub"));
    command
        .arg("--data")
        .arg(data)
        .args(args)
        .env_remove("LICASH_HUB_SEED")
        .env_remove("LICASH_HUB_LISTEN")
        .env_remove("LICASH_HUB_NOTIFY")
        .env_remove("LICASH_HUB_NOTIFY_KINDS")
        .env_remove("LICASH_HUB_NAME")
        .env_remove("LICASH_HUB_NOSTR_RELAYS")
        .env_remove("LICASH_HUB_ANNOUNCE_URLS")
        .env_remove("LICASH_HUB_ONION")
        .env_remove("LICASH_HUB_SWAPS")
        .env_remove("LICASH_HUB_SWAPS_FROM")
        .env_remove("LICASH_HUB_ALLOW_UNBACKED_LOCKS")
        .env("RUST_LOG", "info");
    command
}

fn output(data: &Path, args: &[&str]) -> Output {
    hub(data, args).output().unwrap()
}

fn stdout(data: &Path, args: &[&str]) -> String {
    let out = output(data, args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A running hub, stopped if the test fails.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    Some(response)
}

fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn stats(data: &Path) -> serde_json::Value {
    serde_json::from_str(&stdout(data, &["status", "--json"])).unwrap()
}

#[test]
fn a_hub_is_created_run_watched_and_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    let created = output(&data, &["init", "--max-pow", "6"]);
    assert!(created.status.success(), "{created:?}");
    let message = String::from_utf8_lossy(&created.stderr);
    assert_eq!(
        message,
        format!("Hub created. Back up {}.\n", data.join("seed").display())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&data), 0o700);
        assert_eq!(mode(&data.join("seed")), 0o600);
    }
    let again = output(&data, &["init"]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("exists"));
    assert_eq!(stats(&data)["offers"], 0);
    assert_eq!(stats(&data)["events"], 0);
    // Read by a person: what it earned first, in sat, then what it did.
    let text = stdout(&data, &["status"]);
    assert_eq!(
        text,
        "income    0 sat\npayments  0 released\nlocks     0 open\n"
    );
    let text = stdout(&data, &["status", "--details"]);
    assert!(text.contains("0 issued, 0 spent, 0 unlinked\n"), "{text}");
    // Nothing retired, nothing a dispute cannot cite.
    assert_eq!(stdout(&data, &["audit", "--json"]), "[]\n");

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut running = Running(
        hub(
            &data,
            &[
                "run",
                "--listen",
                &listen,
                "--spend-fee-base",
                "3",
                "--mailbox-relay",
                "wss://one.example,ws://two.example",
            ],
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap(),
    );
    let health = until("health", || get(port, "/health"));
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(health.ends_with("ok"), "{health}");
    let info = get(port, licash_api::INFO).unwrap();
    let body = info.split("\r\n\r\n").nth(1).unwrap();
    let info: licash_api::Info = serde_json::from_str(body).unwrap();
    assert_eq!(info.fees.spend.base, 3);
    // What it is not told, it charges as by default: a sat and 100 ppm,
    // and a tenth of a sat for each note made for others.
    let usual = licash_api::Fee { base: 1, ppm: 100 };
    assert_eq!(info.fees.spend.ppm, usual.ppm);
    assert_eq!((info.fees.lock, info.fees.refund), (usual, usual));
    assert_eq!(info.fees.output_msat, 100);
    assert_eq!(info.keysets().unwrap().len(), 1);
    assert_eq!(info.relays, ["wss://one.example", "ws://two.example"]);

    let second = output(
        &data,
        &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
    );
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("another hub"));

    // Watched beside the running hub.
    assert_eq!(stats(&data)["events"], 1);
    let events = stdout(&data, &["events"]);
    let lines: Vec<serde_json::Value> = events
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["seq"], 1);
    assert_eq!(lines[0]["kind"], "started");
    assert!(stdout(&data, &["events", "--after", "1"]).is_empty());

    let pid = running.0.id().to_string();
    assert!(Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap()
        .success());
    let status = until("stop", || running.0.try_wait().unwrap());
    assert!(status.success());
    let mut logs = String::new();
    running
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .unwrap();
    assert!(
        logs.contains("serving") && logs.contains("stopped"),
        "{logs}"
    );
    assert!(!logs.contains('\x1b'), "colors in logs to a pipe: {logs}");
    // Stopped, it can start again.
    let port = free_port();
    let _running = Running(
        hub(&data, &["run", "--listen", &format!("127.0.0.1:{port}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    until("restart", || get(port, "/health"));
    assert_eq!(stats(&data)["events"], 2);
}

#[test]
fn failures_exit_nonzero_and_log_as_asked() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none");
    let out = output(&missing, &["--log", "json", "status"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let line: serde_json::Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(line["level"], "ERROR");
    assert!(line["fields"]["message"]
        .as_str()
        .unwrap()
        .contains("no hub database"));
    let data = dir.path().join("structured");
    let created = output(&data, &["--log", "json", "init", "--max-pow", "6"]);
    assert!(created.status.success(), "{created:?}");
    let line: serde_json::Value = serde_json::from_slice(&created.stderr).unwrap();
    assert_eq!(line["level"], "INFO");
    assert_eq!(line["fields"]["seed"], data.join("seed").to_str().unwrap());
    assert_eq!(line["fields"]["max_pow"], 6);
    // Running needs a hub: it never creates one.
    let out = output(&missing, &["run", "--listen", "127.0.0.1:0"]);
    assert!(!out.status.success());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.starts_with("error: "), "{error}");
    assert_eq!(error.lines().count(), 1, "{error}");
    assert!(!missing.exists());
    let out = output(&missing, &["init", "--max-pow", "63"]);
    assert!(!out.status.success());
    let out = output(&missing, &["run", "--spend-fee-ppm", "1000001"]);
    assert!(!out.status.success());
    let out = output(
        &missing,
        &["run", "--mailbox-relay", "https://relay.example"],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ws:// or wss://"));
    // A chain URL it cannot follow, its password unshown.
    for url in [
        "ftp://user:hunter2@node:8332",
        "http://user:hunter2@node:8332?x=1",
    ] {
        let out = output(&missing, &["run", "--chain", url]);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--chain") && !stderr.contains("hunter2"),
            "{stderr}"
        );
    }
    let poll = ["run", "--chain", "http://node:8332", "--chain-poll", "120"];
    let out = output(&missing, &poll);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--max-lag"));
    // Tweaks are of the chain it follows.
    let out = output(&missing, &["run", "--tweaks"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tweaks) needs --chain"));
    let out = output(&missing, &["run", "--tweaks-from", "1"]);
    assert_eq!(out.status.code(), Some(2));
    // Deposits are of the chain it follows, claimed to an address on it.
    let sweep = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    let out = output(&missing, &["run", "--deposit-sweep-address", sweep]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--deposit-sweep-address) needs --chain"),
        "{stderr}"
    );
    let chain = ["run", "--chain", "http://node:8332", "--network", "regtest"];
    let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let out = output(
        &missing,
        &[&chain[..], &["--deposit-sweep-address", mainnet]].concat(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not an address on"), "{stderr}");
    let out = output(
        &missing,
        &[&chain[..], &["--deposit-sweep-address", "bcrt1nope"]].concat(),
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("--deposit-sweep-address"));
    let out = output(&missing, &["run", "--deposit-min-fee-rate", "0"]);
    assert_eq!(out.status.code(), Some(2));
    // An announcement needs relays, URLs wallets can use, and the chain
    // that names its network.
    let relay = ["--nostr-relay", "ws://127.0.0.1:1"];
    for (args, says) in [
        (
            &["--announce-url", "https://hub.example"][..],
            "needs --nostr-relay",
        ),
        (&relay[..], "--announce-url"),
        (
            &[relay[0], relay[1], "--announce-url", "ftp://hub.example"][..],
            "ftp://",
        ),
        (
            &[relay[0], relay[1], "--announce-url", "https://hub.example"][..],
            "needs --chain",
        ),
    ] {
        let out = output(&missing, &[&["run"], args].concat());
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    // Swaps into the hub are of the chain it follows, from hubs it caps.
    let from = ["--swaps-from", "http://a.example=100"];
    for (args, says) in [
        (&from[..], "--swaps-from needs --swaps"),
        (&["--swaps-tor"][..], "--swaps-tor needs --swaps"),
        (&["--swaps"][..], "--swaps) needs --chain"),
        (
            &["--swaps", "--swaps-from", "http://a.example"][..],
            "URL=CAP",
        ),
        (
            &["--swaps", "--swaps-from", "a.example=1"][..],
            "not a hub URL",
        ),
        (
            &["--swaps", "--swaps-from", "http://a.example=-1"][..],
            "cap",
        ),
        (
            &["--swaps", "--swaps-margin", "2"][..],
            "--swaps-margin must exceed",
        ),
        (
            &["--swaps", "--swaps-min", "2", "--swaps-max", "1"][..],
            "--swaps-min must not exceed",
        ),
        (
            &["--swaps-no-contracts"][..],
            "--swaps-no-contracts needs --swaps",
        ),
        (
            &["--swaps-drain-via", "http://b.example"][..],
            "--swaps-drain-via needs --swaps",
        ),
        // Contracts protect the notes it takes in from other hubs, and none
        // opens on Bitcoin yet.
        (
            &["--swaps", from[0], from[1], "--chain", "http://127.0.0.1:1"][..],
            "none opens on bitcoin: --swaps-no-contracts runs it unprotected",
        ),
    ] {
        let out = output(&missing, &[&["run"], args].concat());
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    assert!(!missing.exists());
}

/// A payout wallet is of the contracts the hub opens, and a node's: its
/// URL refused before anything is opened, its password unshown.
#[test]
fn a_payout_wallet_needs_contracts_and_a_nodes_json_rpc() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none");
    let wallet = "http://user:hunter2@node:8332/wallet/cold";
    let out = output(&missing, &["run", "--contracts-payout-wallet", wallet]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--contracts"), "{stderr}");
    for (url, says) in [
        ("esplora+https://esplora.example/api", "not an Esplora API"),
        ("ftp://user:hunter2@node:8332", "unknown scheme"),
        ("http://user:hunter2@node:8332?x=1", "parameter"),
    ] {
        let args = ["run", "--contracts", "--contracts-payout-wallet", url];
        let out = output(&missing, &args);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--contracts-payout-wallet")
                && stderr.contains(says)
                && !stderr.contains("hunter2"),
            "{url}: {stderr}"
        );
    }
    assert!(!missing.exists());
}

/// The hub's witness key is of its seed, the same on every call; its
/// contracts are imported into witnesses off mainnet only, and into
/// witnesses named, never `none`.
#[test]
fn a_hubs_witness_key_is_of_its_seed_and_an_import_is_never_on_mainnet() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    assert!(output(&data, &["init", "--max-pow", "6"]).status.success());
    let key = stdout(&data, &["witness-key"]);
    assert_eq!(key.trim().len(), 64, "{key}");
    assert!(hex::decode(key.trim()).is_ok(), "{key}");
    assert_eq!(stdout(&data, &["witness-key"]), key);
    let other = dir.path().join("other");
    assert!(output(&other, &["init", "--max-pow", "6"]).status.success());
    assert_ne!(stdout(&other, &["witness-key"]), key);
    let set = "11".repeat(32);
    let witness = format!("https://127.0.0.1:1#{}", "22".repeat(32));
    let import = |network: &str| {
        let args = [
            "contracts-witness-import",
            "--network",
            network,
            "--contracts-witness-set",
            &set,
            "--contracts-witness",
            &witness,
        ];
        let out = output(&data, &args);
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    assert!(import("bitcoin").contains("refused on mainnet"));
    // Never beside a hub running on its ledger.
    {
        let _running = licash_hub::stopped(&data.join("hub.sqlite")).unwrap();
        assert!(import("regtest").contains("another hub is running"));
    }
    // Off mainnet, tried: its witness unreachable.
    assert!(import("regtest").contains("127.0.0.1:1"));
    let none = [
        "contracts-witness-import",
        "--network",
        "regtest",
        "--contracts-witnesses",
        "none",
    ];
    let out = output(&data, &none);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("into witnesses"));
}

/// The hub writes its standby's keys with its seed, never over a file. A
/// copy of its ledger with them and no seed names the hub's witness key,
/// and is refused what the seed alone does: creating a hub, writing keys,
/// taking the contracts over, and running without contracts to answer for.
#[test]
fn a_standby_runs_on_keys_its_hub_wrote_and_is_refused_what_its_seed_alone_does() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    assert!(output(&data, &["init", "--max-pow", "6"]).status.success());
    let keys = dir.path().join("standby.json");
    let keys = keys.to_str().unwrap();
    assert!(stdout(&data, &["standby-keys", keys]).contains("Wrote"));
    let failed = |data: &Path, args: &[&str]| {
        let out = output(data, args);
        assert!(!out.status.success(), "{args:?}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    assert!(failed(&data, &["standby-keys", keys]).contains("exists"));
    // The hub's data on another machine, all but its seed.
    let copy = dir.path().join("standby");
    std::fs::create_dir(&copy).unwrap();
    let into = copy.join("hub.sqlite");
    rusqlite::Connection::open(data.join("hub.sqlite"))
        .unwrap()
        .execute("VACUUM INTO ?1", [into.to_str().unwrap()])
        .unwrap();
    assert!(failed(&copy, &["witness-key"]).contains("seed"));
    let standby = ["--standby-keys", keys];
    fn with<'a>(keys: &[&'a str], args: &[&'a str]) -> Vec<&'a str> {
        [keys, args].concat()
    }
    assert_eq!(
        stdout(&copy, &with(&standby, &["witness-key"])),
        stdout(&data, &["witness-key"])
    );
    let set = "11".repeat(32);
    let witness = format!("https://127.0.0.1:1#{}", "22".repeat(32));
    let witnesses = [
        "--contracts-witness-set",
        &set,
        "--contracts-witness",
        &witness,
    ];
    let other = dir.path().join("other.json");
    for (args, what) in [
        (vec!["init", "--max-pow", "6"], "create a hub"),
        (
            vec!["standby-keys", other.to_str().unwrap()],
            "write a standby's keys",
        ),
        (
            [&["contracts-takeover"][..], &witnesses].concat(),
            "take the contracts over",
        ),
        (
            [
                &["contracts-witness-import", "--network", "regtest"][..],
                &witnesses,
            ]
            .concat(),
            "import contracts into witnesses",
        ),
    ] {
        let stderr = failed(&copy, &with(&standby, &args));
        assert!(stderr.contains(&format!("does not {what}")), "{stderr}");
    }
    assert!(!other.exists());
    // It answers the contracts' disputes, or runs nothing.
    let listen = format!("127.0.0.1:{}", free_port());
    let stderr = failed(&copy, &with(&standby, &["run", "--listen", &listen]));
    assert!(
        stderr.contains("needs --contracts and their witnesses"),
        "{stderr}"
    );
    // Another hub's keys open no ledger of this one.
    let theirs = dir.path().join("theirs");
    assert!(output(&theirs, &["init", "--max-pow", "6"])
        .status
        .success());
    let their_keys = dir.path().join("theirs.json");
    let their_keys = their_keys.to_str().unwrap();
    stdout(&theirs, &["standby-keys", their_keys]);
    let run = [
        &["run", "--listen", &listen, "--network", "regtest"][..],
        &["--chain", "http://127.0.0.1:1", "--contracts"],
        &witnesses,
    ]
    .concat();
    let stderr = failed(&copy, &with(&["--standby-keys", their_keys], &run));
    assert!(
        stderr.contains("the standby keys do not match the database"),
        "{stderr}"
    );
    // Its own open the ledger, as far as its node, which is not there.
    let stderr = failed(&copy, &with(&standby, &run));
    assert!(stderr.contains("responding only: a standby"), "{stderr}");
    assert!(stderr.contains("hub started"), "{stderr}");
    // Its keys or the seed, never both.
    let both = ["--seed", "seed", "--standby-keys", keys, "witness-key"];
    assert!(failed(&copy, &both).contains("cannot be used with"));
}

/// Give the hub at `data` an own lock under `hash`, which it may yet pay,
/// as for a deposit, a Lightning receipt or a swap: the lock's id.
fn own_lock(data: &Path, hash: [u8; 32]) -> String {
    let (seed, db) = (data.join("seed"), data.join("hub.sqlite"));
    let hub = Hub::open(&seed, &db, Policy::default()).unwrap();
    let mut chain = chain::Chain::new();
    hub.add_checkpoint(&chain.checkpoint(0)).unwrap();
    for _ in 0..3 {
        let block = chain.mine(None).clone();
        hub.observe(chain.height(), &block).unwrap();
    }
    assert!(hub.synced(chain.height(), &chain.tip()).unwrap());
    let checkpoint = hub.checkpoint().unwrap().commitment();
    let profile = ChainProfile::Core30DefaultRegtest;
    let terms = TimedTerms::new(profile, checkpoint, chain.height() + 20, 3, hash).unwrap();
    let e = Ephemeral::random();
    let payee = OwnerKeys::from_seed(&[3; 32]).unwrap().address();
    let pay =
        spend::Output::from_derivation(&e.derive(&payee, 4, Branch::Pay, 0).unwrap()).unwrap();
    let keyset = *hub.info().keysets[0].id();
    let lock = hub.lock_own(&keyset, e.public(), vec![pay], terms).unwrap();
    hex::encode(lock.proposal.id().as_bytes())
}

/// What the hub run with `args` logs, once it exited unsuccessfully.
fn refused(data: &Path, args: &[&str]) -> String {
    let mut running = Running(
        hub(data, args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let status = until("the hub exits", || running.0.try_wait().unwrap());
    assert!(!status.success());
    let mut stderr = String::new();
    let mut pipe = running.0.stderr.take().unwrap();
    pipe.read_to_string(&mut stderr).unwrap();
    stderr
}

/// The hub at `data` run with `args`, once it serves at `port`.
fn serving(data: &Path, port: u16, args: &[&str]) -> Running {
    let listen = format!("127.0.0.1:{port}");
    let running = Running(
        hub(data, &[&["run", "--listen", &listen], args].concat())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let health = until("health", || get(port, "/health"));
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    running
}

fn gateway_file(data: &Path, deposits: bool, hash: [u8; 32]) -> rusqlite::Connection {
    // Each of the version of its tables this hub reads.
    let (component, table, version) = if deposits {
        ("deposits", "deposits", 3)
    } else {
        ("lightning", "lightning_receipts", 2)
    };
    let conn = rusqlite::Connection::open(data.join("hub.sqlite")).unwrap();
    conn.execute_batch(&format!(
        "CREATE TABLE {table} (hash BLOB PRIMARY KEY, lock BLOB, state TEXT, done_at INTEGER);
         INSERT INTO schema_versions (component, version, created_at) VALUES ('{component}', {version}, 0);"
    ))
    .unwrap();
    conn.execute(
        &format!("INSERT INTO {table} (hash, state) VALUES (?1, 'locked')"),
        [hash],
    )
    .unwrap();
    conn
}

#[test]
fn disabled_gateways_refuse_outstanding_obligations_but_allow_idle_files() {
    for deposits in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("hub");
        stdout(&data, &["init", "--max-pow", "6"]);
        let (file, table, flag) = if deposits {
            ("hub.sqlite", "deposits", "--deposit-sweep-address")
        } else {
            ("hub.sqlite", "lightning_receipts", "--lnd")
        };
        let conn = gateway_file(&data, deposits, [6; 32]);
        let stderr = refused(
            &data,
            &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
        );
        assert!(
            stderr.contains(file) && stderr.contains(flag) && stderr.contains("1 obligations"),
            "{stderr}"
        );
        conn.execute(&format!("UPDATE {table} SET state = 'open'"), [])
            .unwrap();
        drop(serving(&data, free_port(), &[]));
        conn.execute(&format!("UPDATE {table} SET state = 'settled'"), [])
            .unwrap();
        if deposits {
            let stderr = refused(
                &data,
                &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
            );
            assert!(
                stderr.contains(file) && stderr.contains("1 obligations"),
                "{stderr}"
            );
        } else {
            drop(serving(&data, free_port(), &[]));
        }
        conn.execute(&format!("UPDATE {table} SET done_at = 1"), [])
            .unwrap();
        drop(serving(&data, free_port(), &[]));
        conn.execute(&format!("UPDATE {table} SET state = 'canceled'"), [])
            .unwrap();
        drop(serving(&data, free_port(), &[]));
    }
}

#[test]
fn disabled_gateways_detect_a_lock_made_before_the_gateway_recorded_it() {
    for deposits in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("hub");
        stdout(&data, &["init", "--max-pow", "6"]);
        let hash = [7; 32];
        own_lock(&data, hash);
        let conn = gateway_file(&data, deposits, hash);
        let table = if deposits {
            "deposits"
        } else {
            "lightning_receipts"
        };
        conn.execute(&format!("UPDATE {table} SET state = 'open'"), [])
            .unwrap();
        let stderr = refused(
            &data,
            &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
        );
        assert!(stderr.contains("1 obligations"), "{stderr}");
    }
}

#[test]
fn a_disabled_lightning_gateway_refuses_a_payment_out_still_pending() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let hash = [8; 32];
    let lock = hex::decode(own_lock(&data, hash)).unwrap();
    // No receipt table: the gateway only paid out.
    let conn = rusqlite::Connection::open(data.join("hub.sqlite")).unwrap();
    conn.execute(
        "INSERT INTO forwards (lock, hash, request, node, amount, state, created_at)
         VALUES (?1, ?2, 'lnbcrt1', 'node', 0, 'pending', 0)",
        rusqlite::params![lock, hash],
    )
    .unwrap();
    let listen = format!("127.0.0.1:{}", free_port());
    let stderr = refused(&data, &["run", "--listen", &listen]);
    assert!(
        stderr.contains("--lnd") && stderr.contains("1 obligations"),
        "{stderr}"
    );
    // Ended: nothing left for the gateway, the lock its own matter.
    conn.execute(
        "UPDATE forwards SET state = 'failed', reason = 'no route', resolved_at = 1",
        [],
    )
    .unwrap();
    drop(serving(&data, free_port(), &["--allow-unbacked-locks"]));
}

#[test]
fn unreadable_gateway_state_is_not_assumed_idle() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    // Tables of a version this hub does not read.
    let db = rusqlite::Connection::open(data.join("hub.sqlite")).unwrap();
    db.execute(
        "INSERT INTO schema_versions (component, version, created_at) VALUES ('deposits', 9, 0)",
        [],
    )
    .unwrap();
    drop(db);
    let stderr = refused(
        &data,
        &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
    );
    assert!(
        stderr.contains("cannot establish") && stderr.contains("hub.sqlite"),
        "{stderr}"
    );
    assert!(!data.join("lightning.sqlite").exists());
}

#[test]
fn a_data_directory_of_an_earlier_layout_is_refused_by_name_and_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    for file in [
        "deposits.sqlite",
        "lightning.sqlite",
        "inbox.sqlite",
        "openings.sqlite",
        "responses.sqlite",
    ] {
        let path = data.join(file);
        std::fs::write(&path, b"an earlier layout's file").unwrap();
        let stderr = refused(
            &data,
            &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
        );
        assert!(
            stderr.contains("earlier layout") && stderr.contains(file),
            "{file}: {stderr}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"an earlier layout's file");
        std::fs::remove_file(path).unwrap();
    }
    drop(serving(&data, free_port(), &[]));
}

#[test]
fn a_disabled_gateway_reads_real_receipts_in_wal_without_mutating_them() {
    use licash_hub_service::lightning::{fake::Fake, Config, Gateway};

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let live_hub = Arc::new(
        Hub::open(
            &data.join("seed"),
            &data.join("hub.sqlite"),
            Policy::default(),
        )
        .unwrap(),
    );
    let path = data.join("hub.sqlite");
    let _gateway =
        Gateway::open(live_hub, Arc::new(Fake::new()), Config::default(), &path).unwrap();
    let writer = rusqlite::Connection::open(&path).unwrap();
    // Keep the WAL connection, not a second running hub's ledger lock.
    drop(_gateway);
    writer.execute("INSERT INTO lightning_receipts (hash, body, amount, msat, state, created_at) VALUES (?1, '{}', 5, 5000, 'locked', 0)", [[8u8; 32]]).unwrap();
    let stderr = refused(
        &data,
        &["run", "--listen", &format!("127.0.0.1:{}", free_port())],
    );
    assert!(
        stderr.contains("hub.sqlite") && stderr.contains("1 obligations"),
        "{stderr}"
    );
    assert_eq!(
        writer
            .query_row("SELECT state FROM lightning_receipts", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
        "locked"
    );
}

#[test]
fn a_hub_refuses_to_run_with_own_locks_nothing_backs() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let hash = [5; 32];
    let lock = own_lock(&data, hash);
    // Its deposit, receipt or swap is recorded nowhere, as once the provider's
    // file was restored older than hub.sqlite: the hub would pay notes
    // nothing backs.
    let listen = format!("127.0.0.1:{}", free_port());
    let stderr = refused(&data, &["run", "--listen", &listen]);
    assert!(
        stderr.contains(&lock) && stderr.contains("--allow-unbacked-locks"),
        "{stderr}"
    );
    for file in ["deposits.sqlite", "lightning.sqlite", "swaps"] {
        assert!(!data.join(file).exists(), "{file}");
    }

    // Allowed, it runs, and alerts the operator.
    let running = serving(&data, free_port(), &["--allow-unbacked-locks"]);
    let events = stdout(&data, &["events"]);
    let alert = events.lines().find(|l| l.contains("\"alert\"")).unwrap();
    assert!(alert.contains(&lock), "{alert}");
    drop(running);

    // Presence of a backing record and whether its gateway still has
    // work are separate checks. An idle record needs no running gateway.
    let deposits = rusqlite::Connection::open(data.join("hub.sqlite")).unwrap();
    deposits.execute_batch("CREATE TABLE deposits (hash BLOB PRIMARY KEY, lock BLOB, state TEXT, done_at INTEGER); INSERT INTO schema_versions (component, version, created_at) VALUES ('deposits', 3, 0)").unwrap();
    let row = "INSERT INTO deposits (hash, state, done_at) VALUES (?1, 'settled', 1)";
    deposits.execute(row, [hash]).unwrap();
    drop(deposits);
    drop(serving(&data, free_port(), &[]));
}

#[test]
fn a_hub_provides_the_swaps_into_it_from_a_wallet_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let chain = ["--chain", "http://127.0.0.1:1", "--network", "regtest"];
    let swaps = ["--swaps", "--swaps-from", "http://a.example/=500"];
    let run = |port: u16, args: &[&str]| {
        let listen = format!("127.0.0.1:{port}");
        let args = [&["run", "--listen", &listen][..], &chain[..], args].concat();
        hub(&data, &args)
    };
    let port = free_port();
    let mut running = Running(
        run(port, &[&swaps[..], &["--swaps-fee-base", "7"]].concat())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    until("health", || get(port, "/health"));
    let body = |response: String| response.split("\r\n\r\n").nth(1).unwrap().to_owned();
    let info: licash_api::swaps::Info =
        serde_json::from_str(&body(get(port, licash_api::swaps::SWAPS_INFO).unwrap())).unwrap();
    let hub_info: licash_api::Info =
        serde_json::from_str(&body(get(port, licash_api::INFO).unwrap())).unwrap();
    // A wallet of its own, beside the hub's notes.
    assert_ne!(info.address, hub_info.address);
    assert_eq!(info.fee.base, 7);
    // Following no chain yet, the hub swaps nothing into itself.
    let own = info.hub(&hub_info.address).unwrap();
    assert_eq!(own.max, 0);
    let swaps_dir = data.join("swaps");
    assert!(swaps_dir.join("wallet.sqlite").exists());
    assert!(!swaps_dir.join("swaps.sqlite").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&swaps_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    let pid = running.0.id().to_string();
    let killed = Command::new("kill").args(["-TERM", &pid]).status();
    assert!(killed.unwrap().success());
    assert!(until("stop", || running.0.try_wait().unwrap()).success());
    let mut logs = String::new();
    let mut stderr = running.0.stderr.take().unwrap();
    stderr.read_to_string(&mut logs).unwrap();
    assert!(logs.contains("swap provider created"), "{logs}");
    // Contracts protect what it takes in from the hubs swapped from.
    assert!(logs.contains("keeping the contracts"), "{logs}");
    assert!(!logs.contains("Reckless"), "{logs}");

    // Started again on the same wallet, unprotected as told: warned of.
    // Without --swaps, no swaps served, the operator warned of them.
    let port = free_port();
    let unprotected = [&swaps[..], &["--swaps-no-contracts"]].concat();
    let mut again = Running(
        run(port, &unprotected)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    until("restart", || get(port, "/health"));
    let response = get(port, licash_api::swaps::SWAPS_INFO).unwrap();
    let same: licash_api::swaps::Info = serde_json::from_str(&body(response)).unwrap();
    assert_eq!(same.address, info.address);
    again.0.kill().unwrap();
    let mut logs = String::new();
    let mut stderr = again.0.stderr.take().unwrap();
    stderr.read_to_string(&mut logs).unwrap();
    assert!(
        logs.contains("Reckless") && !logs.contains("keeping the contracts"),
        "{logs}"
    );
    drop(again);
    let port = free_port();
    let mut off = Running(
        run(port, &[])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    until("run without swaps", || get(port, "/health"));
    let response = get(port, licash_api::swaps::SWAPS_INFO).unwrap();
    assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    off.0.kill().unwrap();
    let mut logs = String::new();
    off.0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .unwrap();
    assert!(logs.contains("--swaps is off"), "{logs}");
    // Nor at all while a swap into it is under way: its notes are backed
    // once the provider claims the client's lock.
    let db = rusqlite::Connection::open(swaps_dir.join("wallet.sqlite")).unwrap();
    db.execute(
        "INSERT INTO provider_swaps (id, hash, from_url, to_url, address, amount, fee, paid,
            expiry_from_height, expiry_height, state, created_at, updated_at, kind)
         VALUES (x'01', zeroblob(32), 'http://a.example', 'http://hub', x'03', 10, 1, 11,
            50, 40, 'locked', 0, 0, 'own')",
        [],
    )
    .unwrap();
    drop(db);
    let out = run(free_port(), &[]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--swaps is off") && stderr.contains("1 swaps"),
        "{stderr}"
    );

    // A file of an earlier layout beside its wallet is refused by name.
    std::fs::write(swaps_dir.join("swaps.sqlite"), b"an earlier provider's").unwrap();
    let out = run(free_port(), &swaps).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("earlier layout") && stderr.contains("swaps.sqlite"),
        "{stderr}"
    );
}

#[test]
fn an_onion_service_may_be_the_only_url_announced() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none");
    let onion = ["--nostr-relay", "ws://127.0.0.1:1", "--onion"];
    let chain = ["--chain", "http://node:8332"];
    for (args, says) in [
        (&onion[..], "needs --chain"),
        (
            &[&onion[..], &["--announce-url", "ftp://hub.example"]].concat(),
            "ftp://",
        ),
        // Checked before the hub opens, where this one stops.
        (&[&onion[..], &chain[..]].concat(), "open the hub"),
    ] {
        let out = output(&missing, &[&["run"], args].concat());
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(says), "{args:?}: {stderr}");
    }
    assert!(!missing.exists());
}

/// A JSON webhook on a thread: its `json://` URL, and the titles it took.
fn webhook() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("json://{}/hook", listener.local_addr().unwrap());
    let titles = Arc::new(Mutex::new(Vec::new()));
    let took = titles.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut reader = BufReader::new(stream.unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap();
                    }
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            took.lock()
                .unwrap()
                .push(body["title"].as_str().unwrap().to_owned());
            let mut stream = reader.into_inner();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .unwrap();
        }
    });
    (url, titles)
}

#[test]
fn the_operator_is_notified_of_starts_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let (url, titles) = webhook();
    let taken = || titles.lock().unwrap().clone();

    // Refused without quoting the URL, which holds the token.
    let out = output(&data, &["run", "--notify", "tgram://123:SecretPart"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("notification target 1") && stderr.contains("chat"),
        "{stderr}"
    );
    assert!(!stderr.contains("SecretPart"), "{stderr}");
    let help = hub(&data, &["run", "--help"])
        .env("LICASH_HUB_NOTIFY", "tgram://123:SecretPart/1")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(!String::from_utf8_lossy(&help.stdout).contains("SecretPart"));
    let out = output(
        &data,
        &["run", "--notify", &url, "--notify-kinds", "minted"],
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("double_spend"));

    let sent = stdout(&data, &["test-notify", "--notify", &url]);
    let shown = url.replace("/hook", "/***");
    assert_eq!(sent.trim(), format!("sent    {shown}"));
    assert_eq!(taken(), ["licash-hub: Test"]);
    let closed = format!("json://127.0.0.1:{}/hook", free_port());
    let out = output(
        &data,
        &["test-notify", "--notify", &format!("{url},{closed}")],
    );
    assert!(!out.status.success());
    let printed = String::from_utf8(out.stdout).unwrap();
    assert!(
        printed.contains(&format!("failed  {}", closed.replace("/hook", "/***"))),
        "{printed}"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("1 of 2 targets failed"));
    titles.lock().unwrap().clear();

    let port = free_port();
    let mut running = Running(
        hub(&data, &["run", "--listen", &format!("127.0.0.1:{port}")])
            .env("LICASH_HUB_NOTIFY", &url)
            .env("LICASH_HUB_NAME", "north")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // A new target hears of the start it was added for.
    until("started", || (!taken().is_empty()).then_some(()));
    assert_eq!(taken(), ["north: Hub started"]);
    assert!(data.join("notify.json").exists());
    let pid = running.0.id().to_string();
    assert!(Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap()
        .success());
    assert!(until("stop", || running.0.try_wait().unwrap()).success());
    assert_eq!(taken(), ["north: Hub started", "north: Hub stopped"]);
}

/// The hub watches what it pays out from its first run, pausing nothing
/// on what it never kept; a `payouts.json` that does not read pauses and
/// alerts, until the operator resumes.
#[test]
fn payments_out_are_watched_and_resumed_by_the_operator() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("hub");
    stdout(&data, &["init", "--max-pow", "6"]);
    let file = data.join("payouts.json");
    let kept =
        || -> serde_json::Value { serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap() };
    let clear = serde_json::json!({"baseline": [], "paused": null});
    let alerts = || {
        let events = stdout(&data, &["events"]);
        events.lines().filter(|l| l.contains("alert")).count()
    };

    // A hub that never ran the watch: kept at its first look, no alert.
    let running = serving(&data, free_port(), &[]);
    until("watched", || file.exists().then_some(()));
    assert_eq!(kept(), clear);
    assert_eq!(alerts(), 0);
    drop(running);

    // What does not read pauses, told once, and is not written over.
    std::fs::write(&file, b"{").unwrap();
    let running = serving(&data, free_port(), &[]);
    until("alerted", || (alerts() == 1).then_some(()));
    assert!(stdout(&data, &["events"]).contains("payouts.json does not read"));
    assert_eq!(std::fs::read(&file).unwrap(), b"{");
    // Resumed beside the running hub.
    let resumed = stdout(&data, &["resume-payouts"]);
    assert!(
        resumed.starts_with("Lightning payments out resumed. They were paused: payouts.json"),
        "{resumed}"
    );
    assert_eq!(kept(), clear);
    drop(running);
    assert_eq!(
        stdout(&data, &["resume-payouts"]).lines().next(),
        Some("Lightning payments out were not paused.")
    );
    assert_eq!(alerts(), 1);
}
