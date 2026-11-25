mod support;

use std::{path::Path, process::Output};

use licash::{address::Address, spend::lock_hash};
use licash_api::Fee;
use licash_hub_service::lightning::{fake::Outcome, HeldState};
use serde_json::Value;
use support::{bridge::Bridged, swaps::Swaps, sweep, wallet, Server, DEPOSIT_TIMEOUT};

const FEE: Fee = Fee { base: 1, ppm: 0 };

fn ok(output: Output) -> String {
    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn json(wallet_file: &Path, args: &[&str]) -> Value {
    let mut all = vec!["--json"];
    all.extend(args);
    serde_json::from_str(&ok(wallet(wallet_file, &all, None))).unwrap()
}

fn failed(output: Output, code: i32, says: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(code), "{stderr}");
    assert!(stderr.contains(says), "{stderr:?} lacks {says:?}");
}

/// A new wallet trusting `hub`, and its address.
fn party(dir: &Path, name: &str, hub: Option<&Server>) -> (std::path::PathBuf, String) {
    let file = dir.join(name).join("wallet.sqlite");
    let created = json(&file, &["init"]);
    let address = created["address"].as_str().unwrap().to_owned();
    if let Some(hub) = hub {
        let added = json(&file, &["add-hub", &hub.url()]);
        assert_eq!(added["fees"]["spend"]["base"], 1);
    }
    (file, address)
}

fn address(hex: &str) -> Address {
    Address::from_bytes(&hex::decode(hex).unwrap()).unwrap()
}

fn available(file: &Path) -> (u64, u64) {
    let balance = json(file, &["balance"]);
    let rows = balance.as_array().unwrap();
    rows.iter().fold((0, 0), |(a, p), row| {
        (
            a + row["available"].as_u64().unwrap(),
            p + row["pending"].as_u64().unwrap(),
        )
    })
}

/// A contract at `hub` in the wallet `file`, its F buried, as
/// `open-contract` leaves one: its hub held to `fees`.
fn contract_at(file: &Path, hub: &str, fees: &Value) {
    let fees: licash_api::Fees = serde_json::from_value(fees.clone()).unwrap();
    licash_contracts::holder::seed_contract(file, hub, &fees).unwrap();
}

/// Whether the wallet `file` holds the holder's contracts: made with the
/// first contract, and by no reading of them.
fn holds_contracts(file: &Path) -> bool {
    let db = rusqlite::Connection::open(file).unwrap();
    let n: i64 = db
        .query_row(
            "SELECT count(*) FROM schema_versions WHERE component = 'contracts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    n > 0
}

#[test]
fn a_hub_charging_more_than_its_contracts_opened_under_is_paid_once_its_fees_are_approved() {
    let hub = Server::start(FEE);
    let url = hub.url();
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let (bob, bob_at) = party(dir.path(), "bob", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at(&alice)), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let charged = json(&alice, &["hubs"])[0]["fees"].clone();

    // No contract: no hub is held to anything, and nothing is made.
    let asked = json(&alice, &["approve-fees", &url, "--yes"]);
    assert_eq!(asked["agreed"], Value::Null);
    assert_eq!(
        (&asked["raised"], &asked["approved"]),
        (&false.into(), &false.into())
    );
    assert_eq!(asked["charged"], charged);
    assert!(!holds_contracts(&alice));
    failed(
        wallet(&alice, &["approve-fees", "http://127.0.0.1:1"], None),
        1,
        "unknown hub",
    );

    // Her contract there opened while a payment was free.
    let mut agreed = charged.clone();
    agreed["spend"]["base"] = 0.into();
    contract_at(&alice, &url, &agreed);
    let refused = "charges more than agreed";
    failed(wallet(&alice, &["send", &bob_at, "10"], None), 1, refused);
    assert_eq!(available(&alice), (100, 0));
    let text = ok(wallet(&alice, &["hubs"], None));
    assert!(text.contains("more than agreed: approve-fees"), "{text}");
    // Shown, asked again: nothing agreed to yet.
    let shown = json(&alice, &["approve-fees", &url]);
    assert_eq!(
        (&shown["raised"], &shown["approved"]),
        (&true.into(), &false.into())
    );
    assert_eq!((&shown["charged"], &shown["agreed"]), (&charged, &agreed));
    let text = ok(wallet(&alice, &["approve-fees", &url], None));
    assert!(
        text.contains("--yes") && text.contains("charges  1 sat a payment"),
        "{text}"
    );
    failed(wallet(&alice, &["send", &bob_at, "10"], None), 1, refused);

    // Agreed to: paid, and kept beside the wallet.
    let approved = json(&alice, &["approve-fees", &url, "--yes"]);
    assert_eq!(approved["approved"], true);
    assert_eq!(
        (&approved["agreed_before"], &approved["agreed"]),
        (&agreed, &charged)
    );
    let payment = ok(wallet(&alice, &["send", &bob_at, "10"], None));
    assert_eq!(
        ok(wallet(&bob, &["receive"], Some(&payment))).trim(),
        "received 10 sat"
    );
    let again = json(&alice, &["approve-fees", &url, "--yes"]);
    assert_eq!(
        (&again["raised"], &again["approved"]),
        (&false.into(), &false.into())
    );
    let text = ok(wallet(&alice, &["hubs"], None));
    assert!(!text.contains("more than agreed"), "{text}");
}

/// The address of the wallet `file`.
fn alice_at(file: &Path) -> String {
    ok(wallet(file, &["address"], None)).trim().to_owned()
}

#[test]
fn owners_pay_and_get_paid_on_the_command_line() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let (bob, bob_at) = party(dir.path(), "bob", Some(&hub));
    assert_eq!(ok(wallet(&alice, &["address"], None)).trim(), alice_at);

    // Funded from outside, through a file; its notes unlinked at once.
    let funds = dir.path().join("funds.json");
    let payment = hub.pay(&address(&alice_at), 100);
    std::fs::write(&funds, serde_json::to_string(&payment).unwrap()).unwrap();
    let received = json(&alice, &["receive", funds.to_str().unwrap()]);
    assert_eq!(
        (received["amount"].as_u64(), received["unlinked"].as_u64()),
        (Some(100), Some(3))
    );
    assert_eq!(available(&alice), (100, 0));

    // Alice pays Bob; the payment goes from her stdout to his stdin.
    let sent = wallet(&alice, &["send", &bob_at, "30"], None);
    let id = String::from_utf8_lossy(&sent.stderr).trim().to_owned();
    let paid = ok(sent);
    let received = ok(wallet(&bob, &["receive"], Some(&paid)));
    assert_eq!(received.trim(), "received 30 sat");
    let receipts = json(&bob, &["received"]);
    assert_eq!(
        format!("payment {}", receipts[0]["id"].as_str().unwrap()),
        id
    );
    assert_eq!(receipts[0]["amount"], 30);
    assert_eq!(available(&alice), (69, 0));
    assert_eq!(available(&bob), (30, 0));
    let text = ok(wallet(&alice, &["balance"], None));
    assert_eq!(text, "balance  69 sat\n");
    let text = ok(wallet(&alice, &["balance", "--details"], None));
    assert!(
        text.starts_with("balance  69 sat\n") && text.contains(&format!("{}  69 sat", hub.url())),
        "{text}"
    );

    let history = json(&alice, &["history"]);
    let sent = &history[0];
    assert_eq!(
        (sent["amount"].as_u64(), sent["fee"].as_u64()),
        (Some(30), Some(1))
    );
    assert_eq!(
        (sent["state"].as_str(), sent["payee"].as_str()),
        (Some("done"), Some(bob_at.as_str()))
    );
    let again = ok(wallet(
        &alice,
        &["payment", sent["id"].as_str().unwrap()],
        None,
    ));
    assert_eq!(again, paid);

    failed(
        wallet(&bob, &["receive"], Some(&paid)),
        1,
        "received already",
    );
    failed(wallet(&bob, &["receive"], Some("{}")), 1, "not a payment");
    failed(
        wallet(&alice, &["send", &bob_at, "69"], None),
        1,
        "70 needed, 69 available",
    );
    failed(
        wallet(&alice, &["send", "00ff", "1"], None),
        1,
        "not an address",
    );
    failed(wallet(&alice, &["init"], None), 1, "");
    // A wallet trusts hubs of its network only.
    let signet = dir.path().join("signet").join("wallet.sqlite");
    let created = json(&signet, &["init", "--network", "signet"]);
    assert_eq!(created["network"], "signet");
    failed(
        wallet(&signet, &["add-hub", &hub.url()], None),
        1,
        "follows regtest",
    );
    assert_eq!(json(&signet, &["hubs"]), serde_json::json!([]));
    failed(
        wallet(&signet, &["init", "--network", "testnet3"], None),
        2,
        "",
    );
    failed(
        wallet(&dir.path().join("nobody"), &["balance"], None),
        1,
        "licash-wallet init",
    );

    // A hub not trusted yet, unless asked to.
    let (carol, carol_at) = party(dir.path(), "carol", None);
    let paid = serde_json::to_string(&hub.pay(&address(&carol_at), 8)).unwrap();
    failed(wallet(&carol, &["receive"], Some(&paid)), 1, "--trust");
    let received = ok(wallet(
        &carol,
        &["--json", "receive", "--trust"],
        Some(&paid),
    ));
    assert_eq!(
        serde_json::from_str::<Value>(&received).unwrap()["amount"],
        8
    );
    let hubs = json(&carol, &["hubs"]);
    assert_eq!(hubs[0]["url"].as_str(), Some(hub.url().as_str()));
}

#[test]
fn a_payment_while_its_hub_is_down_finishes_once_it_is_back() {
    let mut hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let (bob, bob_at) = party(dir.path(), "bob", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 64)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));

    hub.down();
    failed(
        wallet(&alice, &["send", &bob_at, "10"], None),
        75,
        "pending",
    );
    assert_eq!(available(&alice), (0, 64));
    failed(wallet(&alice, &["resume"], None), 75, "pending");
    assert_eq!(json(&alice, &["history"])[0]["state"], "offered");

    hub.up();
    let resumed = json(&alice, &["resume"]);
    let payment = serde_json::to_string(&resumed["paid"][0]["payment"]).unwrap();
    assert_eq!(
        ok(wallet(&bob, &["receive"], Some(&payment))).trim(),
        "received 10 sat"
    );
    assert_eq!(available(&alice), (53, 0));
    assert_eq!(json(&alice, &["history"])[0]["state"], "done");

    // Given up while its hub is down, the payment frees its notes.
    hub.down();
    failed(
        wallet(&alice, &["send", &bob_at, "10"], None),
        75,
        "pending",
    );
    let id = json(&alice, &["history"])[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(wallet(&alice, &["abandon", &id], None));
    assert_eq!(available(&alice), (53, 0));
    failed(wallet(&alice, &["abandon", &id], None), 1, "unsigned");
    hub.up();
    assert_eq!(json(&alice, &["resume"])["paid"], Value::Array(vec![]));
}

#[test]
fn notes_a_restarted_hub_no_longer_unlinks_are_renewed_within_the_fee_limit() {
    let mut hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let (bob, bob_at) = party(dir.path(), "bob", Some(&hub));
    // Received while its hub is down: linked until it is back, restarted.
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 64)).unwrap();
    hub.down();
    let received = ok(wallet(&alice, &["--json", "receive"], Some(&funds)));
    let received: Value = serde_json::from_str(&received).unwrap();
    assert_eq!(received["unlinked"], Value::Null);
    let _hub = hub.restarted();

    // A zero limit permits only free renewal. The default also accepts
    // the hub's modest schedule, despite 1 on 64 exceeding 1,000 ppm.
    let unlink = |ppm: &str| json(&alice, &["--renew-ppm", ppm, "unlink"])["unlinked"].clone();
    assert_eq!(unlink("0"), 0);
    assert_eq!(json(&alice, &["history"]), Value::Array(vec![]));
    let unlinked = json(&alice, &["unlink"])["unlinked"].clone();
    assert!(unlinked.as_u64().unwrap() > 0, "{unlinked}");
    let history = json(&alice, &["history"]);
    assert_eq!(history.as_array().unwrap().len(), 1, "{history}");
    let renewal = &history[0];
    assert_eq!(renewal["payee"], alice_at.as_str());
    assert_eq!(
        (renewal["amount"].as_u64(), renewal["fee"].as_u64()),
        (Some(63), Some(1))
    );
    assert_eq!(renewal["state"], "done");
    assert_eq!(available(&alice), (63, 0));
    assert_eq!(json(&alice, &["unlink"])["unlinked"], 0);

    // A payment's change is unlinked as it is made.
    let payment = ok(wallet(&alice, &["send", &bob_at, "10"], None));
    assert_eq!(
        ok(wallet(&bob, &["receive"], Some(&payment))).trim(),
        "received 10 sat"
    );
    assert_eq!(json(&alice, &["unlink"])["unlinked"], 0);
    assert_eq!(available(&alice), (52, 0));
}

#[test]
fn a_restored_backup_drops_the_notes_spent_since() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let (_, bob_at) = party(dir.path(), "bob", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let backup = dir.path().join("backup.sqlite");
    std::fs::copy(&alice, &backup).unwrap();

    ok(wallet(&alice, &["send", &bob_at, "60"], None));
    assert_eq!(available(&backup), (100, 0));
    // Consolidation consumed every original note. The hub proves it, and
    // the change it paid Alice comes back with it: the backup is what
    // Alice is, and does not count those old notes twice.
    let checked = json(&backup, &["check"]);
    assert_eq!(
        (&checked["dropped"], &checked["recovered"]),
        (&100.into(), &39.into())
    );
    assert_eq!(available(&backup), (39, 0));
    let checked = json(&backup, &["check"]);
    assert_eq!(
        (&checked["dropped"], &checked["recovered"]),
        (&0.into(), &0.into())
    );
    assert_eq!(available(&alice), (39, 0));

    // A fresh copy sees the change. Notes spent from it are dropped by
    // the first file too, whichever privately varied distribution was
    // chosen. Compare with the actual inputs, not a specific layout.
    std::fs::copy(&alice, &backup).unwrap();
    ok(wallet(&backup, &["send", &bob_at, "30"], None));
    let db = rusqlite::Connection::open(&backup).unwrap();
    let spent = db
        .query_row(
            "SELECT SUM(n.denom) FROM notes n JOIN sends s ON s.id = n.spent_by
             WHERE s.amount = 30",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as u64;
    assert!((31..=39).contains(&spent));
    // And the change the copy was paid comes back to the first file.
    let checked = json(&alice, &["check"]);
    assert_eq!(checked["dropped"], spent, "{checked}");
    assert_eq!(checked["recovered"], spent - 31, "{checked}");
    assert_eq!(available(&alice), (8, 0), "{checked}");
    assert_eq!(available(&backup), (8, 0));
}

#[test]
fn explicit_note_optimization_previews_its_fee_and_records_the_actual_operation() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 64)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let preview = json(&alice, &["optimize", &hub.url()]);
    assert_eq!(preview["optimized"], false);
    assert_eq!(preview["fee"], 1);
    assert_eq!(preview["notes_before"], 1);
    assert!((18..=24).contains(&preview["notes_after"].as_u64().unwrap()));
    assert_eq!(available(&alice), (64, 0));
    assert_eq!(json(&alice, &["history"]), Value::Array(vec![]));
    failed(
        wallet(&alice, &["optimize", &hub.url(), "--max-fee", "0"], None),
        1,
        "more than the limit",
    );
    let done = json(&alice, &["optimize", &hub.url(), "--max-fee", "1"]);
    assert_eq!(done["optimized"], true);
    assert_eq!(done["fee"], preview["fee"]);
    assert_eq!(done["notes_after"], preview["notes_after"]);
    assert_eq!(available(&alice), (63, 0));
    let history = json(&alice, &["history"]);
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["optimization"], true);
    assert_eq!(history[0]["amount"], 0);
    let text = ok(wallet(&alice, &["history"], None));
    assert!(text.contains("optimized notes"));
    assert!(text.contains("received  64 sat"), "{text}");
    assert_eq!(json(&alice, &["resume"])["paid"], Value::Array(vec![]));
}

#[test]
fn resume_automatically_shapes_rested_notes_without_handing_over_a_payment() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 64)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    assert_eq!(json(&alice, &["history"]), Value::Array(vec![]));
    let db = rusqlite::Connection::open(&alice).unwrap();
    db.execute("UPDATE notes SET unlinked_at = 1 WHERE unlinked = 1", [])
        .unwrap();
    let resumed = json(&alice, &["resume"]);
    assert_eq!(resumed["paid"], Value::Array(vec![]));
    assert_eq!(available(&alice), (63, 0));
    let history = json(&alice, &["history"]);
    assert_eq!(history.as_array().unwrap().len(), 1);
    assert_eq!(history[0]["optimization"], true);
    json(&alice, &["resume"]);
    assert_eq!(json(&alice, &["history"]).as_array().unwrap().len(), 1);
}

#[test]
fn a_lock_pays_on_its_preimage_or_returns_once_expired() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&hub));
    let (bob, bob_at) = party(dir.path(), "bob", Some(&hub));
    let funds = serde_json::to_string(&hub.pay(&address(&alice_at), 64)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));

    // Bob keeps a secret and hands Alice its hash.
    let secret = json(&bob, &["secret"]);
    let preimage = secret["preimage"].as_str().unwrap();
    let hash = secret["hash"].as_str().unwrap();
    let lock = json(&alice, &["lock", &bob_at, "10", hash]);
    let id = lock["id"].as_str().unwrap();
    assert_eq!(
        (lock["state"].as_str(), lock["amount"].as_u64()),
        (Some("locked"), Some(10))
    );
    // The latest expiry the hub admits at height 3: its window of 20, less
    // the depth of 1 and its reaction of 2.
    assert_eq!(
        (lock["fee"].as_u64(), lock["expiry"].as_u64()),
        (Some(1), Some(20))
    );
    assert_eq!(available(&alice), (0, 64));
    failed(
        wallet(&bob, &["claim", id, &"00".repeat(32)], None),
        1,
        "not the preimage",
    );
    let claimed = json(&bob, &["claim", id, preimage]);
    assert_eq!(
        (claimed["id"].as_str(), claimed["amount"].as_u64()),
        (Some(id), Some(10))
    );
    assert_eq!(available(&bob), (10, 0));
    let resumed = json(&alice, &["resume"]);
    let paid = &resumed["locks"][0];
    assert_eq!(
        (paid["state"].as_str(), paid["preimage"].as_str()),
        (Some("paid"), Some(preimage))
    );
    assert_eq!(available(&alice), (53, 0));

    // Unclaimed, a lock returns to its payer once expired, less the hub's
    // refund fee.
    let lock = json(&alice, &["lock", &bob_at, "10", hash, "--expiry", "8"]);
    let id = lock["id"].as_str().unwrap();
    hub.mine(6, None);
    failed(wallet(&bob, &["claim", id, preimage], None), 1, "too late");
    let resumed = json(&alice, &["resume"]);
    assert_eq!(resumed["locks"][0]["state"], "refunded");
    assert_eq!(available(&alice), (52, 0));
    let text = ok(wallet(&alice, &["locks"], None));
    assert!(
        text.contains("lock refunded  10 + 1 sat (10%)  until block 8")
            && text.contains("lock paid"),
        "{text}"
    );
    failed(
        wallet(&alice, &["lock", &bob_at, "1", "abc"], None),
        1,
        "not 32 bytes in hex",
    );
}

#[test]
fn owners_pay_invoices_and_get_paid_over_lightning() {
    let hub = Server::with_lightning(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    assert_eq!(json(&alice, &["hubs"])[0]["lightning"]["max_pay"], 100);

    // Paid 40 over Lightning, the gateway's fee on top, once the payer
    // pays the invoice and the wallet claims what the hub locks to it.
    let asked = wallet(&alice, &["invoice", "40"], None);
    let stderr = String::from_utf8_lossy(&asked.stderr).into_owned();
    let hash = stderr.trim().strip_prefix("invoice ").unwrap().to_owned();
    let request = ok(asked);
    let invoices = json(&alice, &["invoices"]);
    assert_eq!(
        (
            invoices[0]["state"].as_str(),
            invoices[0]["request"].as_str()
        ),
        (Some("open"), Some(request.trim()))
    );
    assert_eq!(json(&alice, &["resume"])["invoices"][0]["state"], "open");
    hub.pay_held(&hash);
    let resumed = json(&alice, &["resume"]);
    assert_eq!(resumed["invoices"][0]["state"], "received");
    assert_eq!(available(&alice), (40, 0));
    hub.round();
    let mut held = [0; 32];
    hex::decode_to_slice(&hash, &mut held).unwrap();
    assert_eq!(hub.node().held(held).unwrap().0, HeldState::Settled);
    let text = ok(wallet(&alice, &["invoices"], None));
    assert!(text.contains("invoice received  40 sat"), "{text}");
    failed(
        wallet(&alice, &["invoice", "101"], None),
        1,
        "takes 1 to 100",
    );
    // With a memo for its payer, listed with it: open, so its invoice says
    // it (the wallet cancels one that does not).
    let said = ok(wallet(
        &alice,
        &["invoice", "5", "--memo", " Pizza  night"],
        None,
    ));
    let listed = &json(&alice, &["invoices"])[0];
    assert_eq!(listed["request"].as_str(), Some(said.trim()));
    assert_eq!(
        (&listed["state"], &listed["memo"]),
        (&"open".into(), &"Pizza night".into())
    );
    let text = ok(wallet(&alice, &["invoices"], None));
    assert!(text.contains("\"Pizza night\""), "{text}");
    failed(
        wallet(&alice, &["invoice", "5", "--memo", "\u{7}"], None),
        1,
        "memo",
    );

    // Paying an invoice of 20 locks notes of 22 to the hub, its gateway's
    // fee on top, until the payment buys the preimage. The notes are made
    // exact by a payment to the wallet itself, for the hub's fee of 1.
    let preimage = [5; 32];
    let request = hub
        .node()
        .invoice(20_000, lock_hash(&preimage), 6, Outcome::Pay(preimage));
    let paid = ok(wallet(&alice, &["pay-invoice", &request], None));
    assert_eq!(
        paid,
        format!("paid 22 + 0 sat\npreimage {}\n", hex::encode(preimage))
    );
    assert_eq!(available(&alice), (17, 0));
    let locks = json(&alice, &["locks"]);
    assert_eq!(locks[0]["invoice"].as_str(), Some(request.as_str()));

    // A failed payment refunds its lock at once, less the hub's refund
    // fee.
    let reason = "FAILURE_REASON_NO_ROUTE";
    let request = hub
        .node()
        .invoice(10_000, lock_hash(&[6; 32]), 6, Outcome::Fail(reason.into()));
    failed(wallet(&alice, &["pay-invoice", &request], None), 1, reason);
    // The smaller change already holds exact notes for this lock: no
    // extra normalization payment, only the refund fee of 1.
    assert_eq!(available(&alice), (16, 0));
    let text = ok(wallet(&alice, &["locks"], None));
    assert!(
        text.contains(&format!("lock refunded ({reason})  12 + 0 sat")),
        "{text}"
    );

    // One under way past the wait is pending, and followed by resume.
    let preimage = [7; 32];
    let hash = lock_hash(&preimage);
    let request = hub.node().invoice(5_000, hash, 6, Outcome::Hang);
    failed(
        wallet(&alice, &["pay-invoice", &request, "--wait", "1"], None),
        75,
        "under way",
    );
    // Exact notes were at hand.
    assert_eq!(available(&alice), (9, 7));
    hub.node().resolve(hash, Outcome::Pay(preimage));
    let resumed = json(&alice, &["resume"]);
    assert_eq!(resumed["locks"][0]["state"], "paid");
    assert_eq!(available(&alice), (9, 0));

    failed(
        wallet(&alice, &["pay-invoice", "lnbcrt1nope"], None),
        1,
        "not a Lightning invoice",
    );
    let request = hub
        .node()
        .invoice(101_000, lock_hash(&[8; 32]), 6, Outcome::Hang);
    failed(
        wallet(&alice, &["pay-invoice", &request], None),
        1,
        "at most 100 sat",
    );
}

#[test]
fn hubs_announced_on_nostr_are_discovered_where_they_answer_as_the_announcer() {
    use licash_nostr::{Announcement, Announcer, Role, Route};
    let hub = Server::start(FEE);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = [relay];
    let announce = |secret: [u8; 32], urls: &[&str], network: &str| {
        let announcement = Announcement {
            urls: urls.iter().map(|u| u.to_string()).collect(),
            network: network.into(),
            name: Some(format!("hub {}", secret[0])),
        };
        runtime.block_on(async {
            let announcer = Announcer::new(&secret, Role::Hub, &relays, &Route::Direct)
                .await
                .unwrap();
            announcer.announce(&announcement).await.unwrap();
        });
    };
    announce(
        hub.hub.nostr_secret(),
        &["http://127.0.0.1:1", &hub.url()],
        "regtest",
    );
    // Another key announcing the hub's URL, a hub down, and one of
    // another network.
    announce([3; 32], &[&hub.url()], "regtest");
    announce([4; 32], &["http://127.0.0.1:1"], "regtest");
    announce([5; 32], &[&hub.url()], "bitcoin");

    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("none.sqlite");
    let args = ["discover", "--relay", &relays[0], "--network", "regtest"];
    let found = json(&nowhere, &args);
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    let named = hub.hub.advertise().unwrap().nostr.unwrap();
    assert_eq!(found[0]["key"], named);
    assert_eq!(found[0]["urls"], serde_json::json!([hub.url()]));
    assert_eq!(
        found[0]["name"],
        format!("hub {}", hub.hub.nostr_secret()[0])
    );
    assert_eq!(found[0]["fees"]["spend"]["base"], 1);
    assert!(!nowhere.exists());
    let text = ok(wallet(&nowhere, &args, None));
    assert!(
        text.starts_with(&format!("{}  1 sat  hub ", hub.url())),
        "{text}"
    );

    // Then trusted like any other.
    let (alice, _) = party(dir.path(), "alice", None);
    ok(wallet(
        &alice,
        &["add-hub", found[0]["urls"][0].as_str().unwrap()],
        None,
    ));
    assert_eq!(json(&alice, &["hubs"])[0]["url"], hub.url());
    // Without --network, of the wallet's.
    let found = json(&alice, &["discover", "--relay", &relays[0]]);
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found[0]["key"], named);

    failed(
        wallet(&nowhere, &["discover", "--relay", "ws://127.0.0.1:1"], None),
        1,
        "no Nostr relay answered",
    );
    failed(
        wallet(
            &nowhere,
            &[
                "--proxy",
                "http://127.0.0.1:1",
                "discover",
                "--relay",
                &relays[0],
            ],
            None,
        ),
        1,
        "socks5h://",
    );
}

#[test]
fn an_invoice_made_by_a_provider_pays_the_wallet_at_a_hub_without_a_gateway() {
    let hub = Server::start(FEE);
    let node = std::sync::Arc::new(licash_hub_service::lightning::fake::Fake::new());
    node.tip(hub.height(), [0; 32]);
    let swaps = Swaps::receiving(&[&hub], 1_000, node.clone());
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let provider = swaps.url();
    // Protected by a contract, or made by a provider: not both.
    let both = [
        "invoice",
        "100",
        "--via",
        &provider,
        "--chain",
        "http://chain.test",
    ];
    assert_eq!(wallet(&alice, &both, None).status.code(), Some(2));

    let asked = wallet(&alice, &["invoice", "100", "--via", &provider], None);
    let stderr = String::from_utf8_lossy(&asked.stderr).into_owned();
    let hash = stderr.trim().strip_prefix("invoice ").unwrap().to_owned();
    let request = licash_wallet::Payable::read(ok(asked).trim()).unwrap();
    // Its default fee of 2 and 0.5% on top.
    assert_eq!(request.amount, 103);
    let mut held = [0; 32];
    hex::decode_to_slice(&hash, &mut held).unwrap();
    let cltv = node.held_cltv(held).unwrap() as u32;
    node.pay_held(held, hub.height() + cltv);
    // Locked to Alice once the provider sees it paid: claimed on resuming.
    let mut state = String::new();
    for _ in 0..100 {
        let resumed = json(&alice, &["resume"]);
        state = resumed["invoices"][0]["state"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        if state == "received" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(state, "received");
    assert_eq!(available(&alice), (100, 0));
}

#[test]
fn notes_swap_between_hubs_through_a_provider() {
    let (a, b) = (Server::swapping_from(FEE, Vec::new()), Server::start(FEE));
    let swaps = Swaps::start(&[&a, &b], 200);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_at) = party(dir.path(), "alice", Some(&a));
    let added = ok(wallet(&alice, &["add-hub", &b.url()], None));
    assert_eq!(added.trim(), "trusted: it charges 1 sat a payment");
    let funds = serde_json::to_string(&a.pay(&address(&alice_at), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let provider = swaps.url();
    let swap = |amount: &str| {
        wallet(
            &alice,
            &["swap", amount, "--to", &b.url(), "--provider", &provider],
            None,
        )
    };

    // 20 at B for 20, the provider's fee of 1 + 1% and A's lock fee at A.
    let text = ok(swap("20"));
    assert_eq!(
        text.trim(),
        format!(
            "swapped 20 + 2 sat (10%) at {} for 20 sat at {}",
            a.url(),
            b.url()
        )
    );
    let listed = json(&alice, &["swaps"]);
    assert_eq!(
        (listed[0]["state"].as_str(), listed[0]["fee"].as_u64()),
        (Some("done"), Some(2))
    );
    let record = swaps.until(|r| r.stage == licash_swaps::Stage::Done);
    assert_eq!((record.amount, record.fee, record.paid), (20, 2, 22));
    assert_eq!((swaps.held(&a), swaps.held(&b)), (22, 200 - 20 - 1));
    ok(wallet(&alice, &["resume"], None));
    assert_eq!(available(&alice), (100 - 22 - 1 + 20, 0));

    // Beyond what the provider swaps: nothing is locked.
    failed(swap("151"), 1, "swaps 5 to");
    assert_eq!(json(&alice, &["swaps"]).as_array().unwrap().len(), 1);

    // The provider does not answer once Alice locked: pending until it does.
    swaps
        .refuse
        .store(true, std::sync::atomic::Ordering::Relaxed);
    failed(swap("10"), 75, "refused as asked");
    assert_eq!(json(&alice, &["swaps"])[0]["state"], "open");
    failed(wallet(&alice, &["resume"], None), 75, "refused as asked");
    swaps
        .refuse
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let resumed = json(&alice, &["resume"]);
    assert_eq!(resumed["swaps"][0]["state"], "done", "{resumed}");
    assert_eq!(resumed["swaps"][0]["amount"], 10);
    let text = ok(wallet(&alice, &["swaps"], None));
    assert!(text.contains("swap done  10 + 2 sat (20%)"), "{text}");
    swaps.until(|r| r.amount == 10 && r.stage == licash_swaps::Stage::Done);
}

#[test]
fn swap_providers_announced_on_nostr_are_discovered_where_they_answer() {
    use licash_nostr::{Announcement, Announcer, Role, Route};
    let (a, b) = (Server::start(FEE), Server::start(FEE));
    let swaps = Swaps::start(&[&a, &b], 200);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = [relay];
    let announce = |secret: [u8; 32], role: Role, url: String| {
        let announcement = Announcement {
            urls: vec![url],
            network: "regtest".into(),
            name: Some("swaps".into()),
        };
        runtime.block_on(async {
            let announcer = Announcer::new(&secret, role, &relays, &Route::Direct)
                .await
                .unwrap();
            announcer.announce(&announcement).await.unwrap();
        });
    };
    announce(
        swaps.provider.nostr_secret().unwrap(),
        Role::Swaps,
        swaps.url(),
    );
    // The hub announced as a hub, and another key announcing the provider.
    announce(a.hub.nostr_secret(), Role::Hub, a.url());
    announce([3; 32], Role::Swaps, swaps.url());

    let dir = tempfile::tempdir().unwrap();
    let nowhere = dir.path().join("none.sqlite");
    let args = [
        "discover",
        "--swaps",
        "--relay",
        &relays[0],
        "--network",
        "regtest",
    ];
    let found = json(&nowhere, &args);
    assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found[0]["urls"], serde_json::json!([swaps.url()]));
    assert_eq!(
        (found[0]["min"].as_u64(), found[0]["max"].as_u64()),
        (Some(5), Some(150))
    );
    // It locks only at B, where it holds 200 less the lock fee.
    let hubs = found[0]["hubs"].as_array().unwrap();
    let mut max: Vec<u64> = hubs.iter().map(|h| h["max"].as_u64().unwrap()).collect();
    max.sort();
    assert_eq!(max, [0, 150]);
    // Its lock at either hub, of a window of 20, expires 32 blocks before
    // the client's: 4 to confirm a refund request, 20, 1 to read the
    // preimage, its margin of 6 and 1.
    let margins: Vec<u64> = hubs.iter().map(|h| h["margin"].as_u64().unwrap()).collect();
    assert_eq!(
        (margins, found[0]["margin"].as_u64()),
        (vec![32, 32], Some(32))
    );
    let text = ok(wallet(&nowhere, &args, None));
    assert_eq!(
        text.trim(),
        format!("{}  1 sat + 1%  5 to 150 sat  2 hubs  swaps", swaps.url())
    );
}

/// Announce the swap provider at `url` on `relays` as the key of `secret`.
fn announce_provider(
    runtime: &tokio::runtime::Runtime,
    relays: &[String],
    secret: [u8; 32],
    url: String,
) {
    use licash_nostr::{Announcement, Announcer, Role, Route};
    let announcement = Announcement {
        urls: vec![url],
        network: "regtest".into(),
        name: None,
    };
    runtime.block_on(async {
        let announcer = Announcer::new(&secret, Role::Swaps, relays, &Route::Direct)
            .await
            .unwrap();
        announcer.announce(&announcement).await.unwrap();
    });
}

#[test]
fn a_swap_goes_through_a_provider_announced_one_used_before_first_then_the_cheapest() {
    use licash_nostr::{wallet::swap_providers, Route};
    use licash_wallet::SwapLimits;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = vec![relay];
    // Hubs naming the relay, where their wallets look for providers.
    let a = Server::swapping_from(FEE, relays.clone());
    let b = Server::with_relays(FEE, relays.clone());
    let terms = |base, margin| licash_swaps::Config {
        fee: Fee { base, ppm: 0 },
        margin,
        ..support::swaps::CONFIG
    };
    // For 20: 1, 2 (1 + 1%, rounded up), too much, too long locked: its
    // margin alone is the most the wallet allows.
    let cheap = Swaps::with(&[&a, &b], 200, 0x51, terms(1, 6));
    let usual = Swaps::start(&[&a, &b], 200);
    let greedy = Swaps::with(&[&a, &b], 200, 0x52, terms(500, 6));
    let slow_margin = SwapLimits::usual(20).margin;
    let slow = Swaps::with(&[&a, &b], 200, 0x53, terms(1, slow_margin));
    let announce = |secret, url| announce_provider(&runtime, &relays, secret, url);
    for swaps in [&cheap, &usual, &greedy, &slow] {
        announce(swaps.provider.nostr_secret().unwrap(), swaps.url());
    }
    // Another key announcing the cheapest: not where it answers as that key.
    announce([3; 32], cheap.url());

    let dir = tempfile::tempdir().unwrap();
    let funded = |name: &str| {
        let (file, at) = party(dir.path(), name, Some(&a));
        ok(wallet(&file, &["add-hub", &b.url()], None));
        let funds = serde_json::to_string(&a.pay(&address(&at), 100)).unwrap();
        ok(wallet(&file, &["receive"], Some(&funds)));
        file
    };
    let (alice, bob) = (funded("alice"), funded("bob"));
    let (from, to) = (a.url(), b.url());
    let found = |file: &Path, amount: u64| -> Vec<(String, u64, bool)> {
        runtime.block_on(async {
            let transport = licash_transport::Http::new(None).unwrap();
            let wallet = licash_wallet::Wallet::open(file, transport).unwrap();
            let limits = SwapLimits::usual(amount);
            let pair = (from.as_str(), to.as_str());
            let found = swap_providers(&wallet, &relays, &Route::Direct, pair, amount, limits);
            let found = found.await.unwrap().into_iter();
            found.map(|p| (p.url, p.quote.fee, p.known)).collect()
        })
    };
    assert_eq!(
        found(&alice, 20),
        [(cheap.url(), 1, false), (usual.url(), 2, false)]
    );
    // Beyond what any swaps.
    assert!(found(&alice, 151).is_empty());

    let swap = |file: &Path, amount: &str, more: &[&str]| {
        let mut args = vec!["swap", amount, "--to", &to];
        args.extend(more);
        wallet(file, &args, None)
    };
    let text = ok(swap(&alice, "20", &[]));
    let through = format!("through {}", cheap.url());
    assert_eq!(
        text.trim(),
        format!("swapped 20 + 1 sat (5%) at {from} for 20 sat at {to} {through}")
    );
    failed(
        swap(&alice, "151", &[]),
        1,
        "no provider announced swaps 151",
    );
    assert_eq!(json(&alice, &["swaps"]).as_array().unwrap().len(), 1);

    // Bob swapped through the dearer one: he goes through it again.
    ok(swap(&bob, "20", &["--provider", &usual.url()]));
    assert_eq!(
        found(&bob, 20),
        [(usual.url(), 2, true), (cheap.url(), 1, false)]
    );
    let text = ok(swap(&bob, "20", &[]));
    assert!(
        text.trim().ends_with(&format!("through {}", usual.url())),
        "{text}"
    );
    drop((greedy, slow));
}

#[test]
fn a_provider_is_found_though_a_hub_was_last_asked_many_blocks_before() {
    use licash_nostr::{wallet::swap_providers, Route};
    use licash_wallet::SwapLimits;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = vec![relay];
    let a = Server::swapping_from(FEE, relays.clone());
    let b = Server::with_relays(FEE, relays.clone());
    let swaps = Swaps::start(&[&a, &b], 200);
    announce_provider(
        &runtime,
        &relays,
        swaps.provider.nostr_secret().unwrap(),
        swaps.url(),
    );
    let dir = tempfile::tempdir().unwrap();
    let (alice, at) = party(dir.path(), "alice", Some(&a));
    ok(wallet(&alice, &["add-hub", &b.url()], None));
    let funds = serde_json::to_string(&a.pay(&address(&at), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    // Both chains grow, as quick blocks do while a wallet is not looking,
    // and the wallet asks B again, not A: A's last word is behind B's by
    // more than a swap's room.
    a.mine(20, None);
    b.mine(20, None);
    ok(wallet(&alice, &["add-hub", &b.url()], None));

    let found = runtime.block_on(async {
        let transport = licash_transport::Http::new(None).unwrap();
        let wallet = licash_wallet::Wallet::open(&alice, transport).unwrap();
        let pair = (a.url(), b.url());
        let pair = (pair.0.as_str(), pair.1.as_str());
        let found = swap_providers(
            &wallet,
            &relays,
            &Route::Direct,
            pair,
            20,
            SwapLimits::usual(20),
        );
        found.await.unwrap()
    });
    // It asked A again, and so found the provider.
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].url, swaps.url());
}

#[test]
fn a_payment_at_a_hub_holding_too_little_swaps_there_first_within_its_fees() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = vec![relay];
    let a = Server::swapping_from(FEE, relays.clone());
    let b = Server::with_relays(FEE, relays.clone());
    let swaps = Swaps::start(&[&a, &b], 200);
    let secret = swaps.provider.nostr_secret().unwrap();
    announce_provider(&runtime, &relays, secret, swaps.url());
    let dir = tempfile::tempdir().unwrap();
    // Alice holds 100 at A and trusts B; Bob's code names B alone.
    let (alice, alice_at) = party(dir.path(), "alice", Some(&a));
    ok(wallet(&alice, &["add-hub", &b.url()], None));
    let funds = serde_json::to_string(&a.pay(&address(&alice_at), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let (bob, _) = party(dir.path(), "bob", Some(&b));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    let pay = |amount: &str, more: &[&str]| {
        let mut args = vec!["pay", &code, amount];
        args.extend(more);
        wallet(&alice, &args, None)
    };
    let swapped = |file: &Path| json(file, &["swaps"]).as_array().unwrap().len();

    // 30 at B swaps 31 there first, B's fee of 1 on top: the provider's
    // fee of 2, A's of 1 on the lock and B's, 4 in all. Refused unless
    // allowed, nothing locked.
    let (from, to, provider) = (a.url(), b.url(), swaps.url());
    let swapping = format!("paying 30 at {to} swaps 31 from {from} through {provider} first");
    failed(
        pay("30", &[]),
        1,
        "A swap is needed to send 30 sat; fee up to 4 sat (13%): pay again with --max-fee 4",
    );
    failed(
        pay("30", &["--max-fee", "3"]),
        1,
        "fee up to 4 sat (13%) exceeds --max-fee 3",
    );
    assert_eq!((swapped(&alice), available(&alice)), (0, (100, 0)));
    let output = pay("30", &["--max-fee", "4", "--json"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains(&swapping));
    let paid: Value = serde_json::from_str(&ok(output)).unwrap();
    assert_eq!(
        (paid["amount"].as_u64(), paid["hub"].as_str()),
        (Some(30), Some(to.as_str()))
    );
    let listed = json(&alice, &["swaps"]);
    assert_eq!(
        (&listed[0]["state"], &listed[0]["amount"], &listed[0]["fee"]),
        (&"done".into(), &31.into(), &2.into())
    );
    // Hers is done once she claimed the provider's lock; her change at A
    // comes back once it claimed hers.
    swaps.until(|r| r.stage == licash_swaps::Stage::Done);
    ok(wallet(&alice, &["resume"], None));
    assert_eq!(available(&alice), (100 - 4 - 30, 0));
    assert_eq!(json(&bob, &["mailbox"])["received"][0]["amount"], 30);

    // The provider does not answer once Alice locked: nothing paid, and
    // nothing more while the swap is under way.
    let refuse = |on| swaps.refuse.store(on, std::sync::atomic::Ordering::Relaxed);
    refuse(true);
    let under_way = format!("nothing paid: a swap to {to} is under way");
    failed(pay("20", &["--max-fee", "10"]), 1, &under_way);
    assert_eq!(json(&alice, &["swaps"])[0]["state"], "open");
    failed(pay("20", &[]), 1, &under_way);
    failed(pay("20", &["--max-fee", "10"]), 1, &under_way);
    assert_eq!(swapped(&alice), 2);
    // Once it is done, at B with what it brought, swapping nothing.
    refuse(false);
    assert_eq!(json(&alice, &["resume"])["swaps"][0]["state"], "done");
    ok(pay("20", &[]));
    assert_eq!(swapped(&alice), 2);
    assert_eq!(json(&bob, &["mailbox"])["received"][0]["amount"], 20);

    // Beyond what any provider swaps: refused as before.
    failed(pay("500", &["--max-fee", "100"]), 1, "no hub it names");
    assert_eq!(swapped(&alice), 2);
}

#[test]
fn what_paying_at_a_hub_not_added_leaves_there_is_shown_apart_until_added() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let relays = vec![relay];
    let a = Server::swapping_from(FEE, relays.clone());
    let b = Server::with_relays(FEE, relays.clone());
    let swaps = Swaps::start(&[&a, &b], 200);
    let secret = swaps.provider.nostr_secret().unwrap();
    announce_provider(&runtime, &relays, secret, swaps.url());
    let dir = tempfile::tempdir().unwrap();
    // Alice holds 100 at A alone; Bob's code names B, saying where it is.
    let (alice, alice_at) = party(dir.path(), "alice", Some(&a));
    let funds = serde_json::to_string(&a.pay(&address(&alice_at), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funds)));
    let (bob, _) = party(dir.path(), "bob", Some(&b));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();

    // 3 at B: the provider swaps no less than its 5 there, 1 left past the
    // payment and B's fee.
    let output = wallet(&alice, &["pay", &code, "3", "--max-fee", "20"], None);
    let said = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        said.contains(&format!("{} is not a hub you added", b.url())),
        "{said}"
    );
    ok(output);
    // Its lock at A done once the provider takes it.
    swaps.until(|r| r.stage == licash_swaps::Stage::Done);
    ok(wallet(&alice, &["resume"], None));
    assert_eq!(json(&bob, &["mailbox"])["received"][0]["amount"], 3);
    let (held, _) = available(&alice);
    assert!(held < 100 - 3, "{held}");
    let text = ok(wallet(&alice, &["balance"], None));
    let apart = format!(
        "not counted  1 sat at {} (hub not added: add-hub to count it)",
        b.url()
    );
    assert!(
        text.contains(&apart) && text.starts_with(&format!("balance  {held} sat\n")),
        "{text}"
    );

    // Added, it counts.
    ok(wallet(&alice, &["add-hub", &b.url()], None));
    assert_eq!(available(&alice), (held + 1, 0));
    let text = ok(wallet(&alice, &["balance"], None));
    assert!(
        !text.contains("not added") && text.starts_with(&format!("balance  {} sat\n", held + 1)),
        "{text}"
    );
}

#[test]
fn a_tor_client_of_its_own_keeps_its_state_next_to_the_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", None);
    // Commands that reach no hub do not reach Tor either.
    let balance = json(&alice, &["--tor", "balance"]);
    assert_eq!(balance, serde_json::json!([]));
    assert!(alice.parent().unwrap().join("tor").is_dir());
    // Tor through the wallet's own client or through a proxy, not both.
    let args = ["--tor", "--proxy", "socks5h://127.0.0.1:9050", "balance"];
    failed(wallet(&alice, &args, None), 2, "cannot be used with");
}

/// A regtest address to take coins back to.
const BACK_TO: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

#[test]
fn owners_deposit_on_bitcoin_and_take_back_what_was_never_received() {
    let hub = Server::with_deposits(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let asked_at = hub.height();
    let hubs = json(&alice, &["hubs"]);
    assert_eq!(
        (
            hubs[0]["deposits"]["min"].as_u64(),
            hubs[0]["deposits"]["timeout"].as_u64()
        ),
        (Some(1_000), Some(DEPOSIT_TIMEOUT.into()))
    );
    let text = ok(wallet(&alice, &["hubs"], None));
    assert!(text.contains("deposits 1,000 to 4,000 sat"), "{text}");

    // Asked for 2000 in notes: pay 2100 on Bitcoin, the hub's fee on top.
    let asked = wallet(&alice, &["deposit", "2000"], None);
    let stderr = String::from_utf8_lossy(&asked.stderr).into_owned();
    assert!(stderr.contains("pay exactly 2100 sat"), "{stderr}");
    let hash = stderr.trim().strip_prefix("deposit ").unwrap();
    let hash = hash.split(':').next().unwrap().to_owned();
    let uri = ok(asked).trim().to_owned();
    let (address, amount) = uri
        .strip_prefix("bitcoin:")
        .and_then(|rest| rest.split_once("?amount="))
        .unwrap();
    assert!(address.starts_with("bcrt1p"), "{uri}");
    assert_eq!(amount, "0.000021");
    // Listed, the hub's fee in it says what it is of the deposit.
    let text = ok(wallet(&alice, &["deposits"], None));
    let terms = format!("pay 2,000 + 100 sat (5%) to {address} by block ");
    assert!(text.contains(&terms), "{text}");
    let deposits = json(&alice, &["deposits"]);
    assert_eq!(
        (deposits[0]["hash"].as_str(), deposits[0]["state"].as_str()),
        (Some(&hash[..]), Some("open"))
    );
    assert_eq!(deposits[0]["terms"]["uri"], uri);
    assert_eq!(deposits[0]["terms"]["timeout"], asked_at + DEPOSIT_TIMEOUT);

    // Paid, then at depth: the hub locks its notes, which resume claims.
    hub.pay_onchain(address, 2_100, 1);
    hub.round();
    assert_eq!(json(&alice, &["resume"])["deposits"][0]["state"], "open");
    hub.mine(1, None);
    hub.round();
    assert_eq!(
        json(&alice, &["resume"])["deposits"][0]["state"],
        "received"
    );
    assert_eq!(available(&alice), (2_000, 0));
    let text = ok(wallet(&alice, &["deposits"], None));
    assert!(text.contains("deposit received  2,000 sat"), "{text}");
    // The hub claims the coins, which are no longer the payer's.
    hub.round();
    hub.round();
    let sent = hub.sent();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].output[0].script_pubkey, sweep());
    hub.confirm_sent();
    let refund = |hash: &str| {
        let args = ["refund", hash, "--to", BACK_TO, "--chain", hub.esplora()];
        wallet(&alice, &args, None)
    };
    failed(refund(&hash), 1, "its notes were received");

    // Asked for 1500, paid a block after the last it could confirm in:
    // canceled, the payment refunded once its timeout passed.
    let late: Value =
        serde_json::from_str(&ok(wallet(&alice, &["--json", "deposit", "1500"], None))).unwrap();
    let late_hash = late["hash"].as_str().unwrap();
    let terms = &late["terms"];
    let fund_by = terms["fund_by"].as_u64().unwrap() as u32;
    let timeout = terms["timeout"].as_u64().unwrap() as u32;
    hub.mine(fund_by - hub.height(), None);
    hub.round();
    let paid = hub.pay_onchain(terms["address"].as_str().unwrap(), 1_600, 2);
    hub.mine(2, None);
    hub.round();
    let resumed = json(&alice, &["resume"]);
    assert_eq!(
        resumed["deposits"][0]["state"],
        "canceled (canceled by its hub)"
    );
    assert_eq!(available(&alice), (2_000, 0));
    failed(
        refund(late_hash),
        1,
        &format!("refundable after block {timeout}"),
    );
    hub.mine(timeout - hub.height(), None);
    let txid = ok(refund(late_hash)).trim().to_owned();
    let sent = hub.sent();
    let back = sent.iter().find(|t| t.compute_txid().to_string() == txid);
    let back = back.unwrap_or_else(|| panic!("{txid} not sent: {sent:?}"));
    assert_eq!(back.input[0].previous_output, paid);
    assert_eq!(back.lock_time.to_consensus_u32(), timeout);
    let to: bitcoin::Address<_> = BACK_TO.parse().unwrap();
    assert_eq!(
        back.output[0].script_pubkey,
        to.assume_checked().script_pubkey()
    );
    // At the chain's estimate within 6 blocks, 2 sat/vB.
    let fee = 1_600 - back.output[0].value.to_sat();
    let rate = bitcoin::FeeRate::from_sat_per_vb_u32(2);
    assert_eq!(fee, rate.fee_wu(back.weight()).unwrap().to_sat());
    let deposits = json(&alice, &["deposits"]);
    assert_eq!(deposits[0]["state"], format!("refunded ({txid})"));
    // Once mined, nothing is left to take back.
    hub.confirm_sent();
    failed(refund(late_hash), 1, "nothing unspent pays");
}

#[test]
fn owners_pay_payment_codes_through_mailboxes_or_by_hand() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::with_relays(FEE, vec![relay]);
    let plain = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));

    // Bob's code names his hub and his mailbox on its relays; as a QR
    // code, in upper case. His code on Bitcoin, his silent payment address
    // and a fallback address, names no hub.
    let code = json(&bob, &["code"]);
    assert_eq!(
        (code["mailbox"].as_bool(), code["onchain"].as_bool()),
        (Some(true), Some(false))
    );
    let text = code["code"].as_str().unwrap().to_owned();
    assert!(text.starts_with("licash:tlicash1q"), "{text}");
    let onchain = ok(wallet(&bob, &["code", "--qr", "--onchain"], None));
    let onchain = onchain.trim();
    assert!(
        onchain.starts_with("BITCOIN:BCRT1P")
            && onchain.contains("?SP=TSP1Q")
            && !onchain.contains("LICASH"),
        "{onchain}"
    );
    let qr = ok(wallet(&bob, &["code", "--qr"], None)).trim().to_owned();
    assert!(qr.starts_with("LICASH:TLICASH1Q"), "{qr}");

    // Alice pays it: sent to his mailbox, nothing to hand over. Of her
    // three notes received, it is well within what the relay takes.
    let output = wallet(&alice, &["--json", "pay", &qr, "30"], None);
    let diagnostic = String::from_utf8_lossy(&output.stderr).into_owned();
    let paid: Value = serde_json::from_str(&ok(output)).unwrap();
    assert_eq!(
        diagnostic,
        format!("payment {}\n", paid["id"].as_str().unwrap())
    );
    assert_eq!(
        (paid["amount"].as_u64(), paid["relays"].as_u64()),
        (Some(30), Some(1))
    );
    assert_eq!(available(&alice), (69, 0));
    let got = json(&bob, &["mailbox"]);
    assert_eq!(got["received"][0]["amount"], 30);
    assert_eq!(available(&bob), (30, 0));
    // Each payment is taken once.
    assert_eq!(json(&bob, &["mailbox"])["received"], serde_json::json!([]));
    assert_eq!(ok(wallet(&bob, &["mailbox"], None)).trim(), "nothing new");

    // What the code asks for, unless told otherwise; more than she holds
    // and its fee is not paid: the code says nothing of Bitcoin.
    assert!(!text.contains('?'), "{text}");
    let asking = format!("{text}?amount=20");
    let output = wallet(&alice, &["pay", &asking], None);
    let handed = match too_large_to_mail(&output) {
        None => {
            assert!(
                output.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                ok(output),
                "sent to mailbox  20 sat\nfee              up to 1 sat (5%)\n"
            );
            None
        }
        Some(said) => {
            assert!(
                said.ends_with(
                    "payment ready  20 sat\nfee            up to 1 sat (5%)\n\
                     Hand the payment to the recipient.\n"
                ),
                "{said}"
            );
            Some(ok(output))
        }
    };
    failed(
        wallet(&alice, &["pay", &asking, "21"], None),
        1,
        "asks for 20, not 21",
    );
    failed(
        wallet(&alice, &["pay", &text], None),
        1,
        "the code does not say",
    );
    let unpaid = wallet(&alice, &["pay", &qr, "49"], None);
    failed(unpaid.clone(), 1, "holding 49 and the fee");
    assert!(!String::from_utf8_lossy(&unpaid.stderr).contains("on Bitcoin"));
    match handed {
        None => assert_eq!(json(&bob, &["mailbox"])["received"][0]["amount"], 20),
        Some(payment) => {
            let received = ok(wallet(&bob, &["--json", "receive"], Some(&payment)));
            let received: Value = serde_json::from_str(&received).unwrap();
            assert_eq!(received["amount"], 20);
        }
    }

    // Technical identity is available when asked, not in the default result.
    let detailed = wallet(&alice, &["pay", &text, "1", "--details"], None);
    let said = String::from_utf8_lossy(&detailed.stderr).into_owned();
    let id = said.lines().next().unwrap();
    assert_eq!(id.strip_prefix("payment ").unwrap().len(), 64);
    match too_large_to_mail(&detailed) {
        None => {
            assert_eq!(said, format!("{id}\n"));
            assert_eq!(
                ok(detailed),
                format!(
                    "sent to mailbox  1 sat\nfee              up to 1 sat (100%)\nhub              {}\n",
                    hub.url()
                )
            );
        }
        Some(said) => {
            assert!(
                said.ends_with(
                    "payment ready  1 sat\nfee            up to 1 sat (100%)\n\
                     Hand the payment to the recipient.\n"
                ),
                "{said}"
            );
            let payment = ok(detailed);
            let received = ok(wallet(&bob, &["--json", "receive"], Some(&payment)));
            let received: Value = serde_json::from_str(&received).unwrap();
            assert_eq!(received["amount"], 1);
        }
    }

    // Carol's hub names no relays: her code has no mailbox, and the
    // payment is handed over. Alice trusts it, and pays there.
    let (carol, _) = party(dir.path(), "carol", Some(&plain));
    let code = json(&carol, &["code"]);
    assert_eq!(code["mailbox"], false);
    failed(
        wallet(&alice, &["pay", code["code"].as_str().unwrap(), "5"], None),
        1,
        "no hub it names",
    );
    json(&alice, &["add-hub", &plain.url()]);
    let funding = serde_json::to_string(&plain.pay(&address(&alice_address), 10)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let output = wallet(&alice, &["pay", code["code"].as_str().unwrap(), "5"], None);
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("payment ready  5 sat\nfee            up to 1 sat (20%)"),
        "{said}"
    );
    assert!(
        said.contains("Hand the payment to the recipient."),
        "{said}"
    );
    let payment = ok(output);
    let received = ok(wallet(&carol, &["--json", "receive"], Some(&payment)));
    let received: Value = serde_json::from_str(&received).unwrap();
    assert_eq!(received["amount"], 5);
    failed(
        wallet(&carol, &["mailbox"], None),
        1,
        "no hub trusted names mailbox relays",
    );
}

/// What the payer said of `paid`, a payment to a mailbox, if it was too
/// large to mail and is to be handed over: shaping may make a payment of
/// many notes larger than the relay takes. None if it was not.
fn too_large_to_mail(paid: &Output) -> Option<String> {
    let said = String::from_utf8_lossy(&paid.stderr).into_owned();
    let warned = said
        .split_once("warning: not sent to the payee's mailbox (too large to mail, ")?
        .1;
    let kb: usize = warned.split(' ').next().unwrap().parse().unwrap();
    assert!(kb > 64, "{said}");
    assert!(
        warned.contains("event size (")
            && warned.contains("exceeds maximum allowed size (65536 bytes)"),
        "{said}"
    );
    Some(said)
}

/// Time passes for the payments `file` delivers: `by` seconds.
fn later(file: &Path, by: i64) {
    let db = rusqlite::Connection::open(file).unwrap();
    db.execute_batch(&format!(
        "UPDATE deliveries SET kept_at = kept_at - {by}, mail_at = mail_at - {by};
         UPDATE sends SET created_at = created_at - {by}, done_at = done_at - {by};"
    ))
    .unwrap();
}

#[test]
fn payments_to_codes_are_kept_at_the_hub_and_mailed_only_if_not_collected_within_the_hour() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();

    // Alice pays: kept at the hub, not yet collected, nothing mailed.
    let output = wallet(&alice, &["pay", &code, "30"], None);
    let said = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        said.contains("Kept at the hub, not yet collected"),
        "{said}"
    );
    assert_eq!(
        ok(output),
        "kept at hub      30 sat\nfee              up to 1 sat (3.3%)\n"
    );
    assert_eq!(available(&alice), (69, 0));
    let delivered = json(&alice, &["deliver"]);
    assert_eq!(delivered["mailed"], serde_json::json!([]));
    assert_eq!(delivered["delivering"], 1);

    // Bob collects it there: Alice hears so through the hub, and mails
    // nothing, even once the hour is over.
    let got = json(&bob, &["collect"]);
    assert_eq!(got["received"][0]["amount"], 30);
    assert_eq!(available(&bob), (30, 0));
    assert_eq!(json(&bob, &["mailbox"])["received"], serde_json::json!([]));
    later(&alice, 3_601);
    let delivered = json(&alice, &["deliver"]);
    assert_eq!(delivered["mailed"], serde_json::json!([]));
    assert_eq!(delivered["delivering"], 0);
    assert_eq!(
        ok(wallet(&alice, &["deliver"], None)).trim(),
        "nothing to deliver"
    );

    // One he does not collect within the hour is mailed to his mailbox.
    let paid = json(&alice, &["pay", &code, "20"]);
    assert_eq!(
        (paid["amount"].as_u64(), paid["kept"].as_bool()),
        (Some(20), Some(true))
    );
    assert!(json(&alice, &["deliver"])["mailed"]
        .as_array()
        .unwrap()
        .is_empty());
    later(&alice, 3_601);
    let delivered = json(&alice, &["deliver"]);
    match delivered["failed"][0]["reason"].as_str() {
        // Shaping may make a payment of many notes larger than the relay
        // takes: not mailed, still kept at the hub for him.
        Some(why) if why.starts_with("too large to mail, ") => {
            assert_eq!(delivered["failed"][0]["id"], paid["id"]);
            assert!(
                why.contains("exceeds maximum allowed size (65536 bytes)"),
                "{why}"
            );
            assert_eq!(delivered["mailed"], serde_json::json!([]));
            assert_eq!(delivered["delivering"], 1);
        }
        _ => {
            assert_eq!(delivered["mailed"][0]["id"], paid["id"]);
            assert_eq!(delivered["mailed"][0]["relays"], 1);
            assert_eq!(delivered["delivering"], 0);
        }
    }
    // Taken once, from his mailbox or the hub.
    let got = json(&bob, &["mailbox"]);
    assert_eq!(got["received"].as_array().unwrap().len(), 1, "{got}");
    assert_eq!(got["received"][0]["amount"], 20);
    assert_eq!(json(&bob, &["mailbox"])["received"], serde_json::json!([]));
    assert_eq!(available(&bob), (50, 0));
}

#[test]
fn a_payment_to_a_code_tells_its_payee_a_note_and_who_paid() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay.clone()]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    let alices = json(&alice, &["code"])["code"].as_str().unwrap().to_owned();

    let args = [
        "pay",
        &code,
        "30",
        "--note",
        " for the  pizza",
        "--share-code",
    ];
    let paid = json(&alice, &args);
    assert_eq!(paid["kept"], true);
    let got = json(&bob, &["collect"]);
    let received = &got["received"][0];
    assert_eq!(received["note"], "for the pizza");
    let from = received["from"].as_str().unwrap();
    assert!(alices.ends_with(from), "{alices} {from}");
    let listed = ok(wallet(&bob, &["received"], None));
    assert!(listed.contains("\"for the pizza\"  from "), "{listed}");
    assert_eq!(json(&alice, &["history"])[0]["note"], "for the pizza");
    // A note says nothing more than words.
    failed(
        wallet(&alice, &["pay", &code, "5", "--note", "a\u{202e}b"], None),
        1,
        "reordering",
    );

    // A hub keeping no payments keeps no note: refused, nothing paid.
    let plain = Server::with_relays(FEE, vec![relay]);
    let (carol, carol_address) = party(dir.path(), "carol", Some(&plain));
    let (dave, _) = party(dir.path(), "dave", Some(&plain));
    let funding = serde_json::to_string(&plain.pay(&address(&carol_address), 100)).unwrap();
    ok(wallet(&carol, &["receive"], Some(&funding)));
    let code = json(&dave, &["code"])["code"].as_str().unwrap().to_owned();
    failed(
        wallet(&carol, &["pay", &code, "30", "--note", "hi"], None),
        1,
        "keeps no note with a payment",
    );
    assert_eq!(available(&carol), (100, 0));
}

#[test]
fn an_extra_code_is_paid_apart_from_the_wallets_own_and_paid_on_to_it() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    assert!(ok(wallet(&bob, &["codes"], None)).contains("no extra codes"));

    let made = json(&bob, &["new-code", " Bob  online"]);
    assert_eq!(
        (made["index"].as_u64(), made["label"].as_str()),
        (Some(1), Some("Bob online"))
    );
    let extra = made["code"].as_str().unwrap().to_owned();
    let shown = json(&bob, &["code", "--extra", "1"]);
    assert_eq!(shown["code"], extra.as_str());
    assert_eq!(shown["mailbox"], false);
    let own = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    assert_ne!(own, extra);

    // Alice tells it who pays: an extra code of her own, not her wallet's.
    json(&alice, &["new-code", "Alice online"]);
    let alices = json(&alice, &["code", "--extra", "1"])["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let args = ["pay", &extra, "30", "--note", "hi", "--share-extra", "1"];
    // No mailbox named: printed to hand over too, though kept at the hub.
    let handover = json(&alice, &args);
    assert!(handover["signed"].is_string(), "{handover}");

    let got = json(&bob, &["collect"]);
    let at = &got["at_codes"][0];
    assert_eq!(
        (at["code"].as_u64(), at["amount"].as_u64()),
        (Some(1), Some(30))
    );
    assert_eq!(at["note"], "hi");
    assert!(alices.ends_with(at["from"].as_str().unwrap()), "{at}");
    // Paid on to Bob's own code, less the hub's fee, and taken.
    let moved = got["received"][0]["amount"].as_u64().unwrap();
    assert!(moved < 30 && moved > 0, "{got}");
    assert_eq!(available(&bob), (moved, 0));
    let listed = json(&bob, &["codes"]);
    let first = &listed["codes"][0];
    assert_eq!(
        (first["received"].as_u64(), first["fees"].as_u64()),
        (Some(30), Some(30 - moved))
    );
    assert!(json(&bob, &["collect"])["at_codes"]
        .as_array()
        .unwrap()
        .is_empty());
    failed(
        wallet(&bob, &["code", "--extra", "2"], None),
        1,
        "no extra code 2",
    );
}

#[test]
fn paying_a_code_does_not_wait_for_older_payments_to_be_mailed() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    let older = json(&alice, &["pay", &code, "30"]);
    later(&alice, 3_601);

    // The next payment stays on the hub path even with overdue mail.
    assert_eq!(json(&alice, &["pay", &code, "20"])["kept"], true);
    let db = rusqlite::Connection::open(&alice).unwrap();
    let mailed: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM deliveries WHERE mailed_at IS NOT NULL OR tries > 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mailed, 0, "pay must not contact relays for older receipts");

    // A delivery run still mails the overdue receipt, not the new one.
    let delivered = json(&alice, &["deliver"]);
    assert_eq!(delivered["mailed"][0]["id"], older["id"]);
    assert_eq!(delivered["delivering"], 1);
}

#[test]
fn a_wallet_watching_collects_what_it_is_paid_and_mails_what_is_due() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    let paid = json(&alice, &["pay", &code, "30"]);
    later(&alice, 3_601);

    let watching = |file: &Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_licash-wallet"))
            .args([
                "--wallet",
                file.to_str().unwrap(),
                "--json",
                "watch",
                "--every",
                "1",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
    };
    // Stopped if it says too little: its output ends.
    let watchdog = |child: &std::process::Child| {
        let pid = child.id().to_string();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid])
                .status();
        });
    };
    // Each says what it did, a line each: Alice mails it, Bob takes it.
    let lines = |child: &mut std::process::Child, n: usize| {
        use std::io::BufRead;
        let out = std::io::BufReader::new(child.stdout.take().unwrap());
        let lines: Vec<Value> = out
            .lines()
            .take(n)
            .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
            .collect();
        child.kill().unwrap();
        child.wait().unwrap();
        lines
    };
    let mut alice_watching = watching(&alice);
    watchdog(&alice_watching);
    let said = lines(&mut alice_watching, 1);
    assert_eq!(said[0]["mailed"]["id"], paid["id"]);
    let mut bob_watching = watching(&bob);
    watchdog(&bob_watching);
    let said = lines(&mut bob_watching, 1);
    assert_eq!(said[0]["received"]["amount"], 30);
    assert_eq!(available(&bob), (30, 0));
}

#[test]
fn a_short_command_collects_in_the_background_for_the_next_history() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (_relay, relay) = support::relay(&runtime);
    let hub = Server::keeping(FEE, vec![relay]);
    let dir = tempfile::tempdir().unwrap();
    let (alice, alice_address) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let funding = serde_json::to_string(&hub.pay(&address(&alice_address), 100)).unwrap();
    ok(wallet(&alice, &["receive"], Some(&funding)));
    let code = json(&bob, &["code"])["code"].as_str().unwrap().to_owned();
    assert_eq!(json(&alice, &["pay", &code, "30"])["kept"], true);
    assert_eq!(json(&bob, &["received"]), serde_json::json!([]));

    let result = support::wallet_command(&bob, &["--json", "address"], None, true);
    assert!(serde_json::from_str::<Value>(&ok(result)).unwrap()["address"].is_string());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let history = ok(wallet(&bob, &["history"], None));
        let unlinked: i64 = rusqlite::Connection::open(&bob)
            .unwrap()
            .query_row("SELECT count(*) FROM notes WHERE unlinked = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        if history.contains("received  30 sat") && unlinked > 0 {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "{history}");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn a_background_collection_failure_is_warned_on_the_next_command() {
    let hub = Server::start(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    ok(support::wallet_command(&alice, &["history"], None, true));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    // Use the opt-in helper only after the detached worker has written its
    // warning, so a second background run cannot mask the first one's result.
    let status = alice.with_extension("sqlite.collect");
    let saved = || {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open(&status)
            .is_ok_and(|file| file.try_lock().is_ok() && file.metadata().is_ok_and(|m| m.len() > 0))
    };
    while !saved() {
        assert!(std::time::Instant::now() < deadline, "no saved warning");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let result = support::wallet_command(&alice, &["collect"], None, true);
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("warning: background collection failed"),
        "{:?}",
        result.stderr
    );
}

#[test]
fn a_foreground_command_skips_a_busy_collector() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", None);
    let status = alice.with_extension("sqlite.collect");
    let mut options = std::fs::File::options();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(status).unwrap();
    lock.try_lock().unwrap();

    let (sent, received) = std::sync::mpsc::channel();
    let command = std::thread::spawn(move || {
        let output = support::wallet_command(&alice, &["--json", "address"], None, true);
        sent.send(output).ok();
    });
    let output = received.recv_timeout(std::time::Duration::from_secs(5));
    drop(lock);
    command.join().unwrap();
    let result = output.expect("the foreground command waited for the collector");
    assert!(result.stderr.is_empty(), "{:?}", result.stderr);
    assert!(serde_json::from_str::<Value>(&ok(result)).unwrap()["address"].is_string());
}

/// The fallback and silent payment addresses of `file`'s code.
fn on_bitcoin(file: &Path) -> (String, String, String) {
    let text = json(file, &["code", "--onchain"])["code"]
        .as_str()
        .unwrap()
        .to_owned();
    let code: licash_wallet::PaymentCode = text.parse().unwrap();
    let address = code.address.unwrap().assume_checked().to_string();
    (address, code.silent.unwrap().to_string(), text)
}

fn values(coins: &Value) -> Vec<u64> {
    let mut values: Vec<u64> = coins
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["value"].as_u64().unwrap())
        .collect();
    values.sort();
    values
}

/// A wallet of a new seed made with a chain to read looks for its coins
/// from the chain's tip: no earlier block holds any. On Mutinynet a first
/// scan from the first block its hubs served tweaks of took 40 minutes.
/// Made without one, or the chain not answering, it looks from there as
/// before.
#[test]
fn a_new_wallet_made_with_a_chain_looks_for_its_coins_from_its_tip() {
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let chain = hub.esplora().to_owned();
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let (fallback, sp, _) = on_bitcoin(&bob);
    hub.pay_onchain(&fallback, 3_000, 1);
    hub.pay_silent(&sp, 2_500, 2);
    hub.round();
    let scan = |file: &Path| -> Value {
        let all = ["--json", "onchain", "--chain", &chain, "scan"];
        serde_json::from_str(&ok(wallet(file, &all, None))).unwrap()
    };
    let carol = dir.path().join("carol").join("wallet.sqlite");
    let created = json(&carol, &["init", "--chain", &chain]);
    assert_eq!(created["from"], hub.height());
    ok(wallet(&carol, &["add-hub", &hub.url()], None));
    let dave = dir.path().join("dave").join("wallet.sqlite");
    let unknown = wallet(
        &dave,
        &["--json", "init", "--chain", "http://127.0.0.1:9"],
        None,
    );
    let stderr = String::from_utf8_lossy(&unknown.stderr).into_owned();
    let created: Value = serde_json::from_str(&ok(unknown)).unwrap();
    assert_eq!(created["from"], Value::Null);
    assert!(stderr.contains("no chain tip"), "{stderr}");
    ok(wallet(&dave, &["add-hub", &hub.url()], None));
    for file in [&carol, &dave] {
        let (_, sp, _) = on_bitcoin(file);
        hub.pay_silent(&sp, 1_500, 3);
    }
    hub.round();
    let (carols, daves) = (scan(&carol), scan(&dave));
    assert_eq!(values(&carols["found"]), [1_500]);
    assert_eq!(values(&daves["found"]), [1_500]);
    let fetched = |scanned: &Value| scanned["fetched"].as_u64().unwrap();
    assert!(fetched(&carols) < fetched(&daves), "{carols} {daves}");
}

/// A chain of another network than the wallet's, as `LICASH_WALLET_CHAIN`
/// may name: its tip kept would hide every block of the wallet's own. None
/// kept, warned; a chain not a URL refused, no wallet made.
#[test]
fn a_new_wallet_keeps_no_tip_of_another_networks_chain() {
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let chain = hub.esplora().to_owned();
    let erin = dir.path().join("erin").join("wallet.sqlite");
    let args = ["--json", "init", "--network", "signet", "--chain", &chain];
    let made = wallet(&erin, &args, None);
    let stderr = String::from_utf8_lossy(&made.stderr).into_owned();
    let created: Value = serde_json::from_str(&ok(made)).unwrap();
    assert_eq!(created["from"], Value::Null);
    assert!(
        stderr.contains("a chain of regtest, not signet"),
        "{stderr}"
    );
    // No hub serving tweaks, nothing kept: the block to look from asked.
    failed(
        wallet(&erin, &["onchain", "--chain", &chain, "scan"], None),
        1,
        "--from",
    );
    let frank = dir.path().join("frank").join("wallet.sqlite");
    failed(
        wallet(&frank, &["init", "--chain", "nowhere"], None),
        1,
        "--chain",
    );
    assert!(!frank.exists());
}

/// A wallet made with a chain, paid at its fallback address before it
/// trusts a hub: found from its tip, without tweaks.
#[test]
fn a_new_wallet_made_with_a_chain_finds_its_fallback_coin_before_any_hub() {
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let chain = hub.esplora().to_owned();
    hub.mine(3, None);
    let gina = dir.path().join("gina").join("wallet.sqlite");
    let created = json(&gina, &["init", "--chain", &chain]);
    assert_eq!(created["from"], hub.height());
    let (fallback, _, _) = on_bitcoin(&gina);
    hub.pay_onchain(&fallback, 3_000, 1);
    let all = ["--json", "onchain", "--chain", &chain, "scan"];
    let scanned: Value = serde_json::from_str(&ok(wallet(&gina, &all, None))).unwrap();
    assert_eq!(values(&scanned["found"]), [3_000]);
}

#[test]
fn coins_paid_on_bitcoin_are_found_spent_and_moved_to_notes() {
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let (bob, _) = party(dir.path(), "bob", Some(&hub));
    let chain = hub.esplora().to_owned();
    let onchain = |file: &Path, args: &[&str]| {
        let mut all = vec!["onchain", "--chain", &chain];
        all.extend(args);
        wallet(file, &all, None)
    };
    let scan = |file: &Path| -> Value {
        let all = ["--json", "onchain", "--chain", &chain, "scan"];
        serde_json::from_str(&ok(wallet(file, &all, None))).unwrap()
    };
    failed(wallet(&alice, &["onchain", "scan"], None), 1, "--chain");
    assert_eq!(json(&alice, &["onchain", "coins"]), serde_json::json!([]));

    // Paid at her fallback address and at her silent payment address.
    let (fallback, sp, _) = on_bitcoin(&alice);
    assert!(fallback.starts_with("bcrt1p"), "{fallback}");
    hub.pay_onchain(&fallback, 3_000, 1);
    hub.pay_silent(&sp, 2_500, 2);
    hub.round();
    let scanned = scan(&alice);
    assert_eq!(values(&scanned["found"]), [2_500, 3_000]);
    assert_eq!(scanned["next"], hub.height() + 1);
    assert_eq!(scan(&alice)["found"], serde_json::json!([]));
    let coins = ok(wallet(&alice, &["onchain", "coins"], None));
    assert!(coins.ends_with("total  5,500 sat\n"), "{coins}");
    // The address paid gives way to the next.
    assert_ne!(on_bitcoin(&alice).0, fallback);

    // She pays Bob's code on Bitcoin, at his silent payment address: he
    // finds it, she her change.
    let (_, _, code) = on_bitcoin(&bob);
    failed(onchain(&alice, &["send", &code]), 1, "an AMOUNT or --all");
    let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    failed(
        onchain(&alice, &["send", mainnet, "1000"]),
        1,
        "not an address on regtest",
    );
    let sent = ok(onchain(&alice, &["send", &code, "1500", "--fee-rate", "2"]));
    let txid = sent.trim();
    let spend = hub
        .sent()
        .into_iter()
        .find(|t| t.compute_txid().to_string() == txid);
    let spend = spend.unwrap_or_else(|| panic!("{txid} not sent"));
    // The larger coin pays it.
    assert_eq!(spend.input.len(), 1);
    assert!(spend.output.iter().all(|o| o.script_pubkey.is_p2tr()));
    let fee = 3_000 - spend.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let rate = bitcoin::FeeRate::from_sat_per_vb_u32(2);
    assert_eq!(fee, rate.fee_wu(spend.weight()).unwrap().to_sat());
    hub.confirm_sent();
    hub.round();
    assert_eq!(values(&scan(&bob)["found"]), [1_500]);
    let scanned = scan(&alice);
    assert_eq!(scanned["spent"].as_array().unwrap().len(), 1);
    let change = 3_000 - 1_500 - fee;
    assert_eq!(values(&scanned["found"]), [change]);
    assert_eq!(scanned["found"][0]["change"], true);

    // Coins are never joined: a send no one coin pays is refused.
    failed(
        onchain(&alice, &["send", &code, "3000"]),
        1,
        "coins are never joined",
    );

    // The largest coin moved to notes, whole and alone, the deposit's fee
    // and the hub's on top: once at depth, resume takes them.
    let moved: Value =
        serde_json::from_str(&ok(onchain(&alice, &["--json", "move", "--fee-rate", "1"]))).unwrap();
    assert_eq!(moved["state"], "open");
    let amount = moved["amount"].as_u64().unwrap();
    let deposit = hub
        .sent()
        .into_iter()
        .find(|t| t.compute_txid().to_string() == moved["txid"].as_str().unwrap());
    let deposit = deposit.unwrap();
    assert_eq!((deposit.input.len(), deposit.output.len()), (1, 1));
    assert_eq!(deposit.output[0].value.to_sat(), amount + 100);
    let fee = 2_500 - amount - 100;
    let rate = bitcoin::FeeRate::from_sat_per_vb_u32(1);
    assert_eq!(fee, rate.fee_wu(deposit.weight()).unwrap().to_sat());
    // Her change, too little to move alone, stays.
    failed(
        onchain(&alice, &["move"]),
        1,
        &format!("{change} available"),
    );
    hub.confirm_sent();
    hub.round();
    hub.mine(1, None);
    hub.round();
    assert_eq!(
        json(&alice, &["resume"])["deposits"][0]["state"],
        "received"
    );
    assert_eq!(available(&alice), (amount, 0));
    assert_eq!(scan(&alice)["spent"].as_array().unwrap().len(), 1);
    assert_eq!(values(&json(&alice, &["onchain", "coins"])), [change]);
}

/// Cold storage set by a tpub of segwit addresses: shown with its next
/// address, looked for in the chain's blocks from its birthday, cleared.
#[test]
fn cold_storage_is_set_shown_looked_for_and_cleared() {
    use bitcoin::bip32::{Xpriv, Xpub};
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let chain = hub.esplora().to_owned();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &[0xc0; 32]).unwrap();
    let tpub = Xpub::from_priv(&secp, &master).to_string();
    failed(wallet(&alice, &["cold", "show"], None), 1, "cold set");
    let set = [
        "cold",
        "set",
        &tpub,
        "--threshold",
        "100000",
        "--keep",
        "5000",
    ];
    failed(wallet(&alice, &set, None), 1, "--birthday or --chain");
    let mut chosen = set.to_vec();
    chosen.extend(["--birthday", "0"]);
    failed(wallet(&alice, &chosen, None), 1, "wpkh or tr");
    chosen.extend(["--script", "tr"]);
    let shown = json(&alice, &chosen);
    assert_eq!(shown["script"], "tr");
    assert_eq!(shown["next_index"], 0);
    assert!(
        shown["next"].as_str().unwrap().starts_with("bcrt1p"),
        "{shown}"
    );
    assert_eq!(shown["scanned"], serde_json::Value::Null);
    let looked = json(&alice, &["cold", "--chain", &chain, "show"]);
    assert_eq!(looked["scanned"], hub.height());
    assert_eq!(
        (looked["balance"].as_u64(), looked["coins"].as_u64()),
        (Some(0), Some(0))
    );
    // Nothing due under the threshold: nothing withdrawn.
    let ran = json(&alice, &["cold", "--chain", &chain, "run"]);
    assert_eq!(ran["withdrawn"], serde_json::Value::Null);
    ok(wallet(&alice, &["cold", "clear"], None));
    failed(wallet(&alice, &["cold", "show"], None), 1, "cold set");
}

/// The coins listed with a chain to read are looked for first: no scan
/// asked for, as the app looks while idle.
#[test]
fn coins_listed_with_a_chain_are_looked_for_first() {
    let hub = Server::with_tweaks(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let chain = hub.esplora().to_owned();
    let (_, sp, _) = on_bitcoin(&alice);
    hub.pay_silent(&sp, 2_500, 1);
    hub.round();
    // Without a chain, only what was found before.
    assert_eq!(json(&alice, &["onchain", "coins"]), serde_json::json!([]));
    let coins = json(&alice, &["onchain", "--chain", &chain, "coins"]);
    assert_eq!(values(&coins), [2_500]);
    assert_eq!(json(&alice, &["onchain", "coins"]), coins);
}

#[test]
fn coins_paid_at_a_fallback_address_are_found_with_no_hub_serving_tweaks() {
    let hub = Server::with_deposits(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let chain = hub.esplora().to_owned();
    let scan = |args: &[&str]| {
        let mut all = vec!["--json", "onchain", "--chain", &chain, "scan"];
        all.extend(args);
        wallet(&alice, &all, None)
    };
    // No hub's tweaks to start from: she names the block.
    failed(scan(&[]), 1, "--from");
    let from = (hub.height() + 1).to_string();

    // Paid at her fallback address and at her silent payment address: the
    // first found only.
    let (fallback, sp, _) = on_bitcoin(&alice);
    hub.pay_onchain(&fallback, 3_000, 1);
    hub.pay_silent(&sp, 2_500, 2);
    hub.round();
    let scanned: Value = serde_json::from_str(&ok(scan(&["--from", &from]))).unwrap();
    assert_eq!(values(&scanned["found"]), [3_000]);
    assert_eq!(scanned["tweaks"], false);
    assert_eq!(scanned["next"], hub.height() + 1);
    let again: Value = serde_json::from_str(&ok(scan(&[]))).unwrap();
    assert_eq!(again["found"], serde_json::json!([]));
    let coins = ok(wallet(&alice, &["onchain", "coins"], None));
    assert!(coins.ends_with("total  3,000 sat\n"), "{coins}");
}

/// A hub's address and deposit root are in `hubs --json`, to be kept with the
/// seed; `recover` takes them by the hub's URL as the file records it, or
/// named alone, and finds the wallet no payment of a contract's default where
/// it paid none.
#[test]
fn recover_takes_a_hubs_address_and_deposit_root_by_url_or_by_name() {
    let hub = Server::with_deposits(FEE);
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let hubs = json(&alice, &["hubs"]);
    let url = hubs[0]["url"].as_str().unwrap().to_owned();
    let address = hubs[0]["address"].as_str().unwrap().to_owned();
    let root = hubs[0]["deposits"]["close_root"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(root.len(), 64, "{root}");
    assert!(!address.is_empty());
    let chain = hub.esplora().to_owned();
    let none = "no payment to the wallet's close deposits found";
    let by_url = ["recover", "--hub", &url, "--chain", &chain];
    assert!(ok(wallet(&alice, &by_url, None)).contains(none));
    let named = [
        "recover",
        "--hub-address",
        &address,
        "--claim-root",
        &root,
        "--chain",
        &chain,
    ];
    assert!(ok(wallet(&alice, &named, None)).contains(none));
    assert_eq!(json(&alice, &named), serde_json::json!([]));
    // A hub the file does not record, a root that is not one, both ways of
    // naming a hub at once, or neither: refused.
    let unknown = ["recover", "--hub", "http://other.test", "--chain", &chain];
    failed(
        wallet(&alice, &unknown, None),
        1,
        "no hub the wallet's file records",
    );
    let bad_root = [
        "recover",
        "--hub-address",
        &address,
        "--claim-root",
        "zz",
        "--chain",
        &chain,
    ];
    failed(wallet(&alice, &bad_root, None), 1, "--claim-root");
    let both = [
        "recover",
        "--hub",
        &url,
        "--hub-address",
        &address,
        "--chain",
        &chain,
    ];
    assert!(!wallet(&alice, &both, None).status.success());
    assert!(!wallet(&alice, &["recover", "--chain", &chain], None)
        .status
        .success());
}

#[test]
fn owners_top_up_a_bridge_and_connect_apps_on_the_command_line() {
    let hub = Server::with_lightning(FEE);
    let bridged = Bridged::start(&hub);
    let url = bridged.url();
    let dir = tempfile::tempdir().unwrap();
    let (alice, _) = party(dir.path(), "alice", Some(&hub));
    let asked = wallet(&alice, &["invoice", "80"], None);
    let stderr = String::from_utf8_lossy(&asked.stderr).into_owned();
    hub.pay_held(stderr.trim().strip_prefix("invoice ").unwrap());
    assert_eq!(
        json(&alice, &["resume"])["invoices"][0]["state"],
        "received"
    );

    // Its owner's alone: only with the code its operator was given.
    failed(
        wallet(&alice, &["bridge", "add", &url], None),
        1,
        "pairing code",
    );
    let added = json(
        &alice,
        &["bridge", "add", &url, "--pairing", &bridged.pairing],
    );
    assert_eq!(added["account"]["balance"], 0);
    assert_eq!(json(&alice, &["bridge", "list"])[0]["url"], url.as_str());

    // 30 paid in, the hub's 1 on receiving out of it.
    let topped = json(&alice, &["bridge", "top-up", "30"]);
    assert_eq!(topped["invoice"]["credits"], 29_000);
    let mut balance = Value::Null;
    for _ in 0..50 {
        hub.round();
        balance = json(&alice, &["bridge", "show"])["balance"].clone();
        if balance == 29_000 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(balance, 29_000);
    assert_eq!(bridged.bridge.status().unwrap().owed, 29_000);

    let connected = json(&alice, &["bridge", "connect", "Stacker News", "--receive"]);
    let uri = connected["uri"].as_str().unwrap();
    assert!(uri.starts_with("nostr+walletconnect://"), "{uri}");
    assert_eq!(
        connected["connection"]["permissions"],
        serde_json::json!(["receive"])
    );
    failed(
        wallet(&alice, &["bridge", "connect", "Nothing"], None),
        1,
        "--pay, --receive",
    );
    let text = ok(wallet(&alice, &["bridge", "show"], None));
    assert!(text.contains("Stacker News (receives)"), "{text}");
    assert!(text.contains("Balance  29 sat"), "{text}");

    // Below 40, up to 50, but 45 a day, 30 of it topped up already.
    let ruled = json(
        &alice,
        &[
            "bridge", "rules", "--below", "40", "--up-to", "50", "--daily", "45",
        ],
    );
    assert_eq!(ruled["rules"]["below"], 40);
    let run = json(&alice, &["bridge", "run"]);
    assert_eq!(run["invoice"]["amount"], 15_000);
    let host = url.strip_prefix("http://").unwrap();
    let named = json(&alice, &["bridge", "address", "Alice"]);
    assert_eq!(named["lightning_address"], format!("alice@{host}"));
    failed(wallet(&alice, &["bridge", "address", "no way"], None), 1, "a-z");
    let key = connected["connection"]["key"].as_str().unwrap();
    let revoked = json(&alice, &["bridge", "revoke", key]);
    assert_eq!(revoked["revoked"], true);
}
