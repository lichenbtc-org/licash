//! `licash-r0-remote`, the worker that proves a job on another machine over
//! SSH (docs/r0.md), with an `ssh` that runs what it is asked on this
//! machine and a prover that proves nothing.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REMOTE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/licash-r0-remote");

fn script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A machine to prove on, and a job for it: an `ssh` that says how it was
/// called (`called`) and runs its last argument here, and `prover`, run
/// there as `licash-r0` would be.
struct Machine {
    dir: tempfile::TempDir,
    job: PathBuf,
}

impl Machine {
    fn new(prover: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let job = dir.path().join("job-00003-00005");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&job).unwrap();
        for kept in ["segment-00003", "segment-00004", "executed"] {
            std::fs::write(job.join(kept), kept).unwrap();
        }
        let called = dir.path().join("called");
        script(
            &bin.join("ssh"),
            &format!(
                "for a; do last=$a; done\nprintf '%s\\n' \"$@\" > '{}'\nexec sh -c \"$last\"",
                called.display()
            ),
        );
        script(&bin.join("prover"), prover);
        Machine { dir, job }
    }

    fn run(&self, args: &[&str]) -> Output {
        let bin = self.dir.path().join("bin");
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        Command::new(REMOTE)
            .args(args)
            .arg(&self.job)
            .args(["3", "5"])
            .env("PATH", path)
            .env("LICASH_R0_REMOTE", bin.join("prover"))
            // Where the machine keeps a job while it proves it.
            .env("TMPDIR", self.dir.path().join("bin"))
            .output()
            .unwrap()
    }

    /// The directories of jobs left on the machine.
    fn left(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("bin"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().path().is_dir())
            .count()
    }
}

/// A prover that leaves, as the range of a job, the segments it was handed
/// and the bounds it was asked.
const PROVES: &str = r#"[ "$1" = range-prove ] || exit 9
echo "proving $3..$4 there"
cat "$2/segment-00003" "$2/segment-00004" "$2/executed" > "$2/range"
echo " $3 $4" >> "$2/range""#;

#[test]
fn a_job_is_carried_to_the_machine_and_its_range_brought_back() {
    let machine = Machine::new(PROVES);
    let out = machine.run(&["-p", "2222", "root@gpu-1"]);
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{said}");
    // What the prover said there is said here, and is no part of the range.
    assert!(said.contains("proving 3..5 there"), "{said}");
    let range = std::fs::read_to_string(machine.job.join("range")).unwrap();
    assert_eq!(range, "segment-00003segment-00004executed 3 5\n");
    assert!(!machine.job.join("range.part").exists());
    // Its ssh options and destination are ssh's, before the command.
    let called = std::fs::read_to_string(machine.dir.path().join("called")).unwrap();
    let called: Vec<&str> = called.lines().collect();
    let at = called.iter().position(|a| *a == "root@gpu-1").unwrap();
    assert_eq!(called[at - 2..at], ["-p", "2222"]);
    assert!(called.contains(&"BatchMode=yes"));
    assert_eq!(machine.left(), 0);
}

#[test]
fn a_machine_that_fails_leaves_no_range() {
    let machine = Machine::new("echo 'no GPU' >&2; exit 1");
    let out = machine.run(&["root@gpu-1"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no GPU"));
    assert!(!machine.job.join("range").exists());
    assert_eq!(machine.left(), 0);
    // Nor one that ends well and proved nothing.
    let machine = Machine::new("exit 0");
    let out = machine.run(&["root@gpu-1"]);
    assert!(!out.status.success());
    assert!(!machine.job.join("range").exists());
    // A range left by an earlier attempt is not this one's.
    std::fs::write(machine.job.join("range"), "stale").unwrap();
    let out = machine.run(&["root@gpu-1"]);
    assert!(!out.status.success());
    assert!(!machine.job.join("range").exists());
}

#[test]
fn it_is_called_with_a_destination_and_a_job() {
    let out = Command::new(REMOTE)
        .args(["job", "0", "4"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let machine = Machine::new(PROVES);
    let out = Command::new(REMOTE)
        .arg("root@gpu-1")
        .arg(&machine.job)
        .args(["0", "x; reboot"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
