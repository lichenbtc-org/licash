//! A real proof whose segments another process proves too
//! (`LICASH_R0_WORKERS`, `licash-r0 range-prove`), on the CPU: a batch of
//! the hub's header chain, the statement's tests' (`export_chained_inputs`,
//! docs/r0.md). Minutes each where a proof is made whole, so run by name:
//!
//! ```sh
//! cargo test --release --test fanout -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

const PROVER: &str = env!("CARGO_BIN_EXE_licash-r0");

/// The first batch of the chain the statement's tests export, made by this
/// checkout's code.
fn batch() -> &'static Path {
    static EXPORTED: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    let (_, batch) = EXPORTED.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out = Command::new(env!("CARGO"))
            .current_dir(&root)
            .env("LICASH_HP_INPUTS", dir.path())
            .env_remove("LICASH_HP_GRAPH")
            .args(["test", "--locked", "--release", "--manifest-path"])
            .arg(root.join("regtest/Cargo.toml"))
            .args(["-p", "licash-hp", "--test", "statement", "--"])
            .arg("export_chained_inputs")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "the export: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let batch = dir.path().join("batch-1.bin");
        (dir, batch)
    });
    batch
}

/// The chain program kept in this checkout, by its image id.
fn program() -> String {
    let kept = Path::new(env!("CARGO_MANIFEST_DIR")).join("../hp-guest/chain.id");
    std::fs::read_to_string(kept).unwrap().trim().to_owned()
}

/// `chain-prove` of the batch in `work`, its segments of 2^16 cycles (13 of
/// them), `workers` proving beside this process.
fn prove(work: &Path, workers: &str) -> Output {
    Command::new(PROVER)
        .arg("chain-prove")
        .arg(batch())
        .arg(work)
        .arg(program())
        .env("LICASH_SEGMENT_PO2", "16")
        .env("LICASH_R0_WORKERS", workers)
        // A CPU takes half a minute a segment and as long to join two,
        // where a GPU takes seconds: no job is given up as too long here.
        .env("LICASH_R0_WORKER_TIMEOUT", "7200")
        .output()
        .unwrap()
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The receipt `work` keeps verifies as the chain program's on the batch:
/// `chain-prove` run again checks it, and proves nothing.
fn verifies(work: &Path) {
    assert!(work.join("receipt").exists());
    let again = prove(work, "");
    let log = said(&again);
    assert!(again.status.success(), "{log}");
    assert!(log.contains("proven already"), "{log}");
}

#[test]
#[ignore = "proves on the CPU for minutes"]
fn a_proof_is_made_of_what_a_worker_and_this_machine_prove() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    let out = prove(&work, &format!("'{PROVER}' range-prove"));
    let log = said(&out);
    println!("{log}");
    assert!(out.status.success(), "{log}");
    // Segments proved by the worker, joined with those proved here.
    assert!(log.contains("fanout: segments 0..12 proved by"), "{log}");
    assert!(log.contains("proved and lifted"), "{log}");
    assert!(!log.contains("set aside"), "{log}");
    verifies(&work);
}

#[test]
#[ignore = "proves on the CPU for minutes"]
fn a_range_of_other_segments_is_set_aside_and_the_proof_made_here() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    // A worker that proves one segment fewer than it was handed: a
    // receipt that verifies, of another range.
    let short = format!(r#"sh -c '"$0" range-prove "$1" "$2" "$(($3 - 1))"' '{PROVER}'"#);
    let out = prove(&work, &short);
    let log = said(&out);
    println!("{log}");
    assert!(out.status.success(), "{log}");
    assert!(log.contains("fanout: segments 0..12 proved by"), "{log}");
    assert!(log.contains("the range 0..12 is set aside"), "{log}");
    assert!(!log.contains("does not verify"), "{log}");
    verifies(&work);
}

/// A prover started by a shell, proving the batch: its process, and the
/// shell.
fn started(dir: &Path, with_parent: bool) -> (rustix::process::Pid, std::process::Child) {
    use std::io::{BufRead, BufReader};
    let mut shell = Command::new("sh");
    shell
        .arg("-c")
        .arg(r#""$@" >/dev/null 2>&1 & echo $!; wait"#)
        .arg("sh")
        .arg(PROVER)
        .arg("chain-prove")
        .arg(batch())
        .arg(dir.join("work"))
        .arg(program())
        .env("LICASH_SEGMENT_PO2", "16")
        .env_remove("LICASH_R0_WITH_PARENT")
        .stdout(std::process::Stdio::piped());
    if with_parent {
        shell.env("LICASH_R0_WITH_PARENT", "1");
    }
    let mut shell = shell.spawn().unwrap();
    let mut pid = String::new();
    BufReader::new(shell.stdout.take().unwrap())
        .read_line(&mut pid)
        .unwrap();
    let pid = rustix::process::Pid::from_raw(pid.trim().parse().unwrap()).unwrap();
    // Proving by now.
    std::thread::sleep(std::time::Duration::from_secs(3));
    (pid, shell)
}

/// Whether the process `pid` runs still.
fn runs(pid: rustix::process::Pid) -> bool {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid.as_raw_nonzero()));
    status.is_ok_and(|s| !s.contains("State:\tZ"))
}

#[test]
#[cfg(target_os = "linux")]
fn a_prover_told_so_does_not_outlive_the_process_that_ran_it() {
    let dir = tempfile::tempdir().unwrap();
    let (prover, mut shell) = started(dir.path(), true);
    assert!(runs(prover));
    shell.kill().unwrap();
    shell.wait().unwrap();
    let stopped = (0..50).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        !runs(prover)
    });
    assert!(stopped, "the prover runs on without its parent");
    // Not told, it proves on, as a proof started by hand does.
    let dir = tempfile::tempdir().unwrap();
    let (prover, mut shell) = started(dir.path(), false);
    shell.kill().unwrap();
    shell.wait().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let ran = runs(prover);
    let _ = rustix::process::kill_process(prover, rustix::process::Signal::KILL);
    assert!(ran, "a prover not told stopped with its parent");
}
