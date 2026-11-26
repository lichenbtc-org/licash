//! A proof's segments proved by other machines too: rented by the hour when
//! many proofs are due at once, where this machine alone proves one at a
//! time (docs/r0.md).
//!
//! `LICASH_R0_WORKERS` names them, a command each (one a line, or `;`
//! between them). A worker is handed a job: a directory of a run of
//! segments ([`CHUNK`] at most) and what their execution made, its first
//! segment and the one after its last. It leaves their join there as
//! `range`, as `licash-r0 range-prove <dir> <from> <to>` does on the machine
//! it runs on: a worker is that command, or one that carries the directory
//! to another machine, runs it there and brings `range` back.
//!
//! This machine proves too, from the last segment back, and whatever a
//! worker leaves: one that fails, takes too long
//! (`LICASH_R0_WORKER_TIMEOUT`, in seconds) or returns what does not verify
//! has its job handed to another, and after [`FAILURES`] in a row is asked
//! no more. With no worker named, nothing here runs but this machine's
//! proving, a segment after another.
//!
//! **What a worker is trusted with.** Not the proof: a range is verified as
//! it arrives and the whole receipt when joined, so a worker can delay a
//! proof, never forge one. It reads what it proves: a segment holds the
//! memory of the guest, the statement's input with it.

use std::collections::VecDeque;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};

use crate::probe;
use crate::resumable::{keep, range_path, segment_path};

/// The most segments of a job: what a worker lost proves again, and one
/// join here for each job.
pub const CHUNK: usize = 16;

/// A worker that failed this many jobs in a row is asked no more.
pub const FAILURES: usize = 2;

/// The most bytes of a range read: a succinct receipt is about 220 kB.
const RANGE_BYTES: u64 = 4 << 20;

/// How long a job may take, unless `LICASH_R0_WORKER_TIMEOUT` says: a GPU
/// proves [`CHUNK`] segments in a minute or two.
const TIMEOUT: Duration = Duration::from_secs(600);

/// The workers `LICASH_R0_WORKERS` names, if any.
pub fn workers() -> Result<Vec<String>> {
    Ok(named(
        &std::env::var("LICASH_R0_WORKERS").unwrap_or_default(),
    ))
}

fn named(value: &str) -> Vec<String> {
    value
        .split(['\n', ';'])
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

fn timeout() -> Result<Duration> {
    match std::env::var("LICASH_R0_WORKER_TIMEOUT") {
        Ok(seconds) => {
            Ok(Duration::from_secs(seconds.parse().context(
                "LICASH_R0_WORKER_TIMEOUT must be a number of seconds",
            )?))
        }
        Err(_) => Ok(TIMEOUT),
    }
}

/// `pending`, in order, cut in jobs: runs of segments that follow one
/// another, `size` at most.
fn jobs(pending: &[usize], size: usize) -> VecDeque<(usize, usize)> {
    let mut jobs: VecDeque<(usize, usize)> = VecDeque::new();
    for &i in pending {
        match jobs.back_mut() {
            Some((from, to)) if *to == i && i - *from < size => *to = i + 1,
            _ => jobs.push_back((i, i + 1)),
        }
    }
    jobs
}

/// The jobs no one has, and how many are being proved: by a worker, or a
/// segment here.
#[derive(Default)]
struct Queue {
    jobs: VecDeque<(usize, usize)>,
    running: usize,
}

struct Shared {
    queue: Mutex<Queue>,
    changed: Condvar,
    /// This machine failed: no job is started, and those running are
    /// stopped.
    stop: AtomicBool,
}

impl Shared {
    /// The next job for a worker, from the first segments on: none once
    /// every job is done, or none is to be started.
    fn take(&self) -> Option<(usize, usize)> {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(job) = q.jobs.pop_front() {
                q.running += 1;
                return Some(job);
            }
            if q.running == 0 {
                return None;
            }
            q = self.changed.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The next segment for this machine, the last of the last job, the
    /// rest of that job left to the workers.
    fn take_one(&self) -> Option<usize> {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if let Some((from, to)) = q.jobs.pop_back() {
                if to - from > 1 {
                    q.jobs.push_back((from, to - 1));
                }
                q.running += 1;
                return Some(to - 1);
            }
            if q.running == 0 {
                return None;
            }
            q = self.changed.wait(q).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// What was taken is done, or given back as `again`.
    fn done(&self, again: Option<(usize, usize)>) {
        let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
        q.running -= 1;
        if let Some(job) = again {
            q.jobs.push_front(job);
        }
        self.changed.notify_all();
    }
}

fn job_dir(dir: &Path, from: usize, to: usize) -> PathBuf {
    dir.join(format!("job-{from:05}-{to:05}"))
}

/// The segments `from..to` of `dir` proved by `worker`: the range it left,
/// within `limit`, unless `stop` is set first.
fn job(
    dir: &Path,
    worker: &str,
    (from, to): (usize, usize),
    limit: Duration,
    stop: &AtomicBool,
) -> Result<Vec<u8>> {
    let job = job_dir(dir, from, to);
    let _ = std::fs::remove_dir_all(&job);
    std::fs::create_dir_all(&job)?;
    let give = |name: &Path| -> Result<()> {
        let name = name.file_name().context("a file of the work directory")?;
        let (kept, given) = (dir.join(name), job.join(name));
        // The same disk: a link costs nothing.
        if std::fs::hard_link(&kept, &given).is_err() {
            std::fs::copy(&kept, &given)
                .with_context(|| format!("{} for the job", kept.display()))?;
        }
        Ok(())
    };
    for i in from..to {
        give(&segment_path(dir, i))?;
    }
    give(Path::new("executed"))?;
    if dir.join("assumptions").exists() {
        give(Path::new("assumptions"))?;
    }
    // In a process group of its own: stopped, so is whatever it started
    // (a shell's pipeline, its `ssh`).
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!("{worker} \"$@\""))
        .arg("sh")
        .arg(&job)
        .arg(from.to_string())
        .arg(to.to_string())
        .process_group(0)
        .spawn()
        .with_context(|| format!("run {worker}"))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let late = started.elapsed() >= limit;
        if late || stop.load(Ordering::Relaxed) {
            let group = format!("-{}", child.id());
            let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
            let _ = child.kill();
            let _ = child.wait();
            match late {
                true => bail!("no answer in {} s", limit.as_secs()),
                false => bail!("stopped"),
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    ensure!(status.success(), "{status}");
    let range = job.join("range");
    let size = std::fs::metadata(&range).context("it left no range")?.len();
    ensure!(size <= RANGE_BYTES, "a range of {size} bytes");
    let bytes = std::fs::read(&range)?;
    let _ = std::fs::remove_dir_all(&job);
    Ok(bytes)
}

/// The segments `pending` of the work directory `dir` proved: by `workers`
/// in jobs, each range they return kept in `dir` once `accept` takes it,
/// and by `here`, a segment at a time, this machine's proving. With no
/// worker, by `here` alone, in order.
pub fn run(
    dir: &Path,
    pending: &[usize],
    workers: &[String],
    accept: &(dyn Fn(&[u8]) -> Result<()> + Sync),
    here: &mut dyn FnMut(usize) -> Result<()>,
) -> Result<()> {
    if workers.is_empty() {
        return pending.iter().try_for_each(|i| here(*i));
    }
    run_within(dir, pending, workers, timeout()?, accept, here)
}

fn run_within(
    dir: &Path,
    pending: &[usize],
    workers: &[String],
    limit: Duration,
    accept: &(dyn Fn(&[u8]) -> Result<()> + Sync),
    here: &mut dyn FnMut(usize) -> Result<()>,
) -> Result<()> {
    let shared = Shared {
        queue: Mutex::new(Queue {
            jobs: jobs(pending, CHUNK),
            running: 0,
        }),
        changed: Condvar::new(),
        stop: AtomicBool::new(false),
    };
    // This machine's first, the last of all, before a worker takes its job:
    // the segment the proof's journal is in is proved here.
    let mut mine = shared.take_one();
    std::thread::scope(|scope| {
        for worker in workers {
            let shared = &shared;
            scope.spawn(move || {
                let mut failed = 0;
                while let Some((from, to)) = shared.take() {
                    let started = Instant::now();
                    let range = job(dir, worker, (from, to), limit, &shared.stop).and_then(|b| {
                        accept(&b)?;
                        keep(&range_path(dir, from, to), &b)
                    });
                    match range {
                        Ok(()) => {
                            failed = 0;
                            shared.done(None);
                            println!(
                                "fanout: segments {from}..{to} proved by {worker} in {:.1} s",
                                started.elapsed().as_secs_f64()
                            );
                        }
                        Err(e) => {
                            failed += 1;
                            let _ = std::fs::remove_dir_all(job_dir(dir, from, to));
                            shared.done(Some((from, to)));
                            println!("fanout: segments {from}..{to} not proved by {worker}: {e:#}");
                            if failed >= FAILURES {
                                println!("fanout: {worker} is asked no more");
                                break;
                            }
                        }
                    }
                }
            });
        }
        let mut result = Ok(());
        while let Some(i) = mine.take().or_else(|| shared.take_one()) {
            result = here(i);
            if result.is_err() {
                // Its segment is not given back: the proof fails, and the
                // workers' jobs with it.
                shared.stop.store(true, Ordering::Relaxed);
                shared.done(None);
                break;
            }
            shared.done(None);
        }
        result
    })
}

/// `licash-r0 range-prove`: a job proved on this machine, on its GPU
/// through the CUDA build if one is usable, else on the CPU.
pub fn range_command(dir: &Path, from: &str, to: &str) -> Result<()> {
    let bound = |s: &str| s.parse::<usize>().context("a segment's number");
    let (from, to) = (bound(from)?, bound(to)?);
    if let Some(cuda) = probe::cuda_build().filter(|_| probe::gpu_usable()) {
        let status = Command::new(&cuda)
            .arg("range-prove")
            .arg(dir)
            .arg(from.to_string())
            .arg(to.to_string())
            .status()
            .context("run the CUDA prover")?;
        ensure!(status.success(), "the GPU prover failed: {status}");
        return Ok(());
    }
    crate::resumable::prove_range(dir, from, to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A work directory of `n` segments executed, none proved.
    fn work(n: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..n {
            keep(&segment_path(dir.path(), i), b"segment").unwrap();
        }
        keep(&dir.path().join("executed"), b"executed").unwrap();
        dir
    }

    /// A worker that leaves the segments it was handed as its range, if
    /// each is in its job with what their execution made.
    const HONEST: &str = r#"sh -c 'for i in $(seq $2 $(($3 - 1))); do test -f "$1/segment-$(printf %05d $i)" || exit 1; done; test -f "$1/executed" && echo "$2 $3" > "$1/range"' sh"#;

    /// A worker that never answers: a shell waiting on what it started,
    /// which says it is alive in the file it is given for as long as it is.
    fn silent(alive: &Path) -> String {
        format!(
            "sh -c 'while :; do date +%s%N > {}; sleep 0.05; done | cat' sh",
            alive.display()
        )
    }

    /// Whether what a [`silent`] worker started is stopped: its file
    /// changes no more.
    fn stopped(alive: &Path) -> bool {
        let read = || std::fs::read(alive).unwrap_or_default();
        let before = read();
        std::thread::sleep(Duration::from_millis(400));
        before == read()
    }

    /// The segments `dir`'s ranges hold, each range saying its own bounds.
    fn ranged(dir: &Path) -> BTreeSet<usize> {
        let mut held = BTreeSet::new();
        for (from, to) in crate::resumable::ranges(dir).unwrap() {
            let said = std::fs::read_to_string(range_path(dir, from, to)).unwrap();
            assert_eq!(said, format!("{from} {to}\n"));
            held.extend(from..to);
        }
        held
    }

    fn all(pending: &[usize]) -> BTreeSet<usize> {
        pending.iter().copied().collect()
    }

    /// `run_within` on `dir`, this machine taking `pace` a segment: the
    /// segments it proved.
    fn proved(
        dir: &Path,
        pending: &[usize],
        workers: &[&str],
        limit: Duration,
        accept: &(dyn Fn(&[u8]) -> Result<()> + Sync),
        pace: Duration,
    ) -> BTreeSet<usize> {
        let workers: Vec<String> = workers.iter().map(|w| w.to_string()).collect();
        let mut local = BTreeSet::new();
        let mut here = |i: usize| -> Result<()> {
            std::thread::sleep(pace);
            assert!(local.insert(i), "segment {i} proved twice here");
            Ok(())
        };
        run_within(dir, pending, &workers, limit, accept, &mut here).unwrap();
        local
    }

    const LONG: Duration = Duration::from_secs(60);
    const SLOW: Duration = Duration::from_millis(100);

    #[test]
    fn workers_are_named_a_line_or_between_semicolons() {
        assert!(named("").is_empty());
        assert!(named(" \n ; ").is_empty());
        assert_eq!(
            named("ssh a licash-r0 range-prove; worker b\n worker c \n"),
            ["ssh a licash-r0 range-prove", "worker b", "worker c"]
        );
    }

    #[test]
    fn jobs_are_runs_of_segments_that_follow_one_another() {
        let pending: Vec<usize> = (0..40).collect();
        assert_eq!(jobs(&pending, 16), [(0, 16), (16, 32), (32, 40)]);
        // Those proved already cut the runs.
        assert_eq!(jobs(&[0, 1, 2, 5, 6, 9], 16), [(0, 3), (5, 7), (9, 10)]);
        assert_eq!(jobs(&[3, 4, 5, 6, 7], 2), [(3, 5), (5, 7), (7, 8)]);
        assert!(jobs(&[], 16).is_empty());
    }

    #[test]
    fn with_no_worker_this_machine_proves_each_segment_in_order() {
        let dir = work(5);
        let mut order = Vec::new();
        let mut here = |i: usize| -> Result<()> {
            order.push(i);
            Ok(())
        };
        run(dir.path(), &[0, 1, 3, 4], &[], &|_| Ok(()), &mut here).unwrap();
        assert_eq!(order, [0, 1, 3, 4]);
        assert!(crate::resumable::ranges(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn workers_prove_ranges_and_this_machine_the_segments_left() {
        let dir = work(40);
        let pending: Vec<usize> = (0..40).collect();
        let ok = |_: &[u8]| -> Result<()> { Ok(()) };
        let local = proved(dir.path(), &pending, &[HONEST, HONEST], LONG, &ok, SLOW);
        let ranged = ranged(dir.path());
        // Every segment once: in a range, or proved here.
        assert!(!ranged.is_empty());
        assert!(ranged.is_disjoint(&local));
        assert_eq!(&ranged | &local, all(&pending));
        // This machine from the last segment back.
        assert!(local.contains(&39));
        // No job is left behind.
        let left = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                let name = e.as_ref().unwrap().file_name();
                name.to_str().unwrap().starts_with("job-")
            })
            .count();
        assert_eq!(left, 0);
    }

    #[test]
    fn a_worker_that_fails_leaves_its_segments_to_the_others() {
        // Alone, it leaves them all to this machine, asked no more after
        // its failures.
        let dir = work(40);
        let pending: Vec<usize> = (0..40).collect();
        let ok = |_: &[u8]| -> Result<()> { Ok(()) };
        let nothing = Duration::ZERO;
        let local = proved(dir.path(), &pending, &["false"], LONG, &ok, nothing);
        assert_eq!(local, all(&pending));
        assert!(ranged(dir.path()).is_empty());
        // One that exits well and leaves no range is no better.
        let local = proved(dir.path(), &pending, &["true"], LONG, &ok, nothing);
        assert_eq!(local, all(&pending));
        // Beside one that proves, every segment is proved all the same.
        let dir = work(40);
        let local = proved(dir.path(), &pending, &["false", HONEST], LONG, &ok, SLOW);
        assert_eq!(&ranged(dir.path()) | &local, all(&pending));
    }

    #[test]
    fn a_range_that_is_not_accepted_is_not_kept() {
        let dir = work(40);
        let pending: Vec<usize> = (0..40).collect();
        let refuse = |_: &[u8]| -> Result<()> { bail!("its receipt does not verify") };
        let local = proved(
            dir.path(),
            &pending,
            &[HONEST],
            LONG,
            &refuse,
            Duration::ZERO,
        );
        assert_eq!(local, all(&pending));
        assert!(crate::resumable::ranges(dir.path()).unwrap().is_empty());
        // Nor one larger than a receipt is.
        let large = r#"sh -c 'head -c 5000000 /dev/zero > "$1/range"' sh"#;
        let ok = |_: &[u8]| -> Result<()> { Ok(()) };
        let local = proved(dir.path(), &pending, &[large], LONG, &ok, Duration::ZERO);
        assert_eq!(local, all(&pending));
        assert!(crate::resumable::ranges(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn a_worker_that_does_not_answer_is_stopped() {
        let dir = work(40);
        let pending: Vec<usize> = (0..40).collect();
        let ok = |_: &[u8]| -> Result<()> { Ok(()) };
        let started = Instant::now();
        let limit = Duration::from_millis(300);
        let alive = dir.path().join("alive");
        let worker = silent(&alive);
        let local = proved(dir.path(), &pending, &[&worker], limit, &ok, SLOW / 10);
        assert_eq!(local, all(&pending));
        assert!(started.elapsed() < Duration::from_secs(30));
        // And what it had started with it.
        assert!(alive.exists());
        assert!(stopped(&alive));
    }

    #[test]
    fn this_machines_failure_fails_the_proof_and_stops_the_workers() {
        let dir = work(40);
        let pending: Vec<usize> = (0..40).collect();
        let alive = dir.path().join("alive");
        let workers = [silent(&alive)];
        let mut here = |_: usize| -> Result<()> {
            // Once the worker runs.
            while !alive.exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            bail!("out of memory")
        };
        let started = Instant::now();
        let ok = |_: &[u8]| -> Result<()> { Ok(()) };
        let e = run_within(dir.path(), &pending, &workers, LONG, &ok, &mut here).unwrap_err();
        assert!(e.to_string().contains("out of memory"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(30));
        assert!(stopped(&alive));
    }
}
