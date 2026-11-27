//! The standby's entrypoint (`standby.sh`): what it restores at a start,
//! and what it never restores over, with stand-ins for Litestream and the
//! hub.

use std::path::{Path, PathBuf};
use std::process::Output;

/// A data directory and the stand-ins: Litestream restores a "ledger"
/// naming the replica (or fails, `FAIL` set), the hub prints the ledger it
/// starts on and its arguments.
struct Bench {
    dir: tempfile::TempDir,
}

impl Bench {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("data")).unwrap();
        let bin = |name: &str, body: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        // restore -o OUT URL
        bin(
            "litestream",
            "[ -n \"$HANG\" ] && sleep 30\n[ -n \"$FAIL\" ] && exit 1\n[ -e \"$3\" ] && exit 2\necho \"replica of $4\" > \"$3\"\n",
        );
        bin(
            "hub",
            "cat \"$LICASH_HUB_DATA/hub.sqlite\"\necho \"args: $*\"\n",
        );
        Self { dir }
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn write(&self, name: &str, body: &str) {
        std::fs::write(self.data().join(name), body).unwrap();
    }

    fn has(&self, name: &str) -> bool {
        self.data().join(name).exists()
    }

    fn start(&self, fail: bool) -> Output {
        self.start_with(fail, &[])
    }

    fn start_with(&self, fail: bool, more: &[&str]) -> Output {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("standby.sh");
        let mut command = std::process::Command::new("bash");
        command
            .arg(script)
            .args(["run", "--chain", "x"])
            .args(more)
            .env("LICASH_HUB_DATA", self.data())
            .env("LICASH_STANDBY_REPLICA", "file:///replica/hub")
            .env("LICASH_LITESTREAM", self.dir.path().join("litestream"))
            .env("LICASH_HUB", self.dir.path().join("hub"))
            .env("LICASH_STANDBY_RESTORE_TIMEOUT", "1")
            .env_remove("FAIL")
            .env_remove("HANG");
        if fail {
            command.env("FAIL", "1");
        }
        if more.contains(&"hang") {
            command.env("HANG", "1");
        }
        command.output().unwrap()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const RESTORED: &str = "replica of file:///replica/hub\nargs: run --chain x\n";

#[test]
fn a_first_start_restores_the_replica_and_marks_it_restored() {
    let bench = Bench::new();
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), RESTORED);
    assert!(bench.has("standby-restored"));
    assert!(!bench.has("hub.sqlite.restoring"));
    // Its replica unreachable on a first start: nothing to start on.
    let bench = Bench::new();
    let o = bench.start(true);
    assert!(!o.status.success());
    assert!(!bench.has("hub.sqlite") && !bench.has("standby-restored"));
}

#[test]
fn the_hub_runs_on_the_directory_it_restores() {
    let bench = Bench::new();
    let o = bench.start_with(false, &["--data", "elsewhere"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert!(!bench.has("hub.sqlite"));
    let o = bench.start_with(false, &["--data=elsewhere"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
}

#[test]
fn a_ledger_it_restored_is_restored_again_its_old_log_gone() {
    let bench = Bench::new();
    bench.write("standby-restored", "");
    bench.write("hub.sqlite", "older\n");
    bench.write("hub.sqlite-wal", "of the older");
    bench.write("hub.sqlite-shm", "of the older");
    bench.write("notify.json", "{\"cursors of the older\": 9}");
    // Left by restores interrupted.
    bench.write("hub.sqlite.restoring", "half");
    std::fs::create_dir(bench.data().join("hub.sqlite.restoring.tmp")).unwrap();
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), RESTORED);
    assert!(!bench.has("hub.sqlite-wal") && !bench.has("hub.sqlite-shm"));
    assert!(!bench.has("hub.sqlite.restoring") && !bench.has("hub.sqlite.restoring.tmp"));
    assert!(!bench.has("notify.json"));
    // The replica unreachable: started on the one restored before, and
    // why kept for the hub to alert of.
    bench.write("hub.sqlite-wal", "of the newer");
    bench.write("notify.json", "{}");
    let o = bench.start(true);
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).starts_with("replica of"));
    assert!(bench.has("hub.sqlite-wal") && bench.has("notify.json"));
    assert!(err(&o).contains("not restored"), "{}", err(&o));
    let why = std::fs::read_to_string(bench.data().join("standby-unrestored")).unwrap();
    assert!(why.contains("exited 1"), "{why}");
    // Restored again: its alert gone.
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert!(!bench.has("standby-unrestored"));
    // Its replica hanging: given up on in time, as one unreachable.
    let at = std::time::Instant::now();
    let o = bench.start_with(false, &["hang"]);
    assert!(at.elapsed() < std::time::Duration::from_secs(20));
    assert!(o.status.success(), "{}", err(&o));
    let why = std::fs::read_to_string(bench.data().join("standby-unrestored")).unwrap();
    assert!(why.contains("exited 124"), "{why}");
}

#[test]
fn a_ledger_it_acted_on_is_never_restored_over() {
    let bench = Bench::new();
    bench.write("standby-restored", "");
    bench.write("standby-acted", "812 ab\n");
    bench.write("hub.sqlite", "its own\n");
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "its own\nargs: run --chain x\n");
    assert!(err(&o).contains("acted"), "{}", err(&o));
    // A restore failed before it acted alerts no more.
    bench.write("standby-unrestored", "exited 1\n");
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert!(!bench.has("standby-unrestored"));
    // Gone: it refuses to start on any other.
    std::fs::remove_file(bench.data().join("hub.sqlite")).unwrap();
    let o = bench.start(false);
    assert!(!o.status.success());
    assert!(!bench.has("hub.sqlite"));
}

#[test]
fn a_ledger_it_did_not_restore_is_left_as_it_is() {
    let bench = Bench::new();
    bench.write("hub.sqlite", "an earlier standby's\n");
    bench.write("hub.sqlite-wal", "its log");
    let o = bench.start(false);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "an earlier standby's\nargs: run --chain x\n");
    assert!(bench.has("hub.sqlite-wal"));
    assert!(!bench.has("standby-restored"));
    assert!(err(&o).contains("touch"), "{}", err(&o));
}
