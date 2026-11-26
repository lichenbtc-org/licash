//! The hub's prover of its statement: `licash-r0` (`LICASH_HP_PROVER`
//! names another), one proof at a time, on the GPU if the container has
//! one, else on the CPU (r0/host).
//!
//! The hub commits to a proof when it responds to a claim: its assertion
//! must confirm before her `respond_timeout`, `w_a` blocks after the
//! response. So it responds only to what its prover can still prove in
//! time ([`Prover::admit`]): a claim it withholds a response from is paid
//! what she asks by her timeout, as a response it can't assert in time
//! would be, less the fees, and without delaying the proofs it did commit
//! to. Contested at once by many holders, it spends its prover on the
//! largest stakes.
//!
//! Its speed is measured, not assumed: at startup the prover is probed
//! (its device, its Groth16 setup, its memory) and, once per device,
//! benchmarked (`licash-r0 bench`, kept in `hp-proofs/bench.json`). Until
//! then, or if anything is missing, the hub is not ready to prove, and
//! responds to no claim: its operator is alerted.
//!
//! Each proof's work is in `hp-proofs/<id>/`: its input, frozen once it
//! first holds (the journal depends on Base alone, so a proof of it holds
//! for the contract whatever blocks followed), the prover's own work,
//! carried on across restarts, its log, and `proof.json`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context as _, Result};
use licash::recovery::{Evidence, COMPACT_FROM};
use licash::spend::ChainProfile;

/// Cycles the statement takes for each header of an input, and for each
/// other byte (its filing, evidence and transactions): measured with
/// `licash-r0 hp-exec` on the statement's test inputs, 15 headers and
/// 33.6 kB (67.7 M cycles), then 3,000 headers more (151.6 M). Of the
/// programs before the compact filing's, which hash each header in
/// software and more than once.
pub(super) const HEADER_CYCLES: u64 = 28_000;
/// Of the program that decides the compact filing, which hashes each
/// header once, on the zkVM's accelerator: 3,000 headers more took 28.2 M
/// cycles on 73.0 M (9.4 k each), 10 k with a margin of its own.
pub(super) const COMPACT_HEADER_CYCLES: u64 = 10_000;
/// Of the program of note format v5, whose notes are 32 bytes less for
/// the same work: the benchmark's answered input (`r0/host/bench.bin`), 15
/// headers and 26.1 kB more of which 2.0 kB of a spend's body cited by its
/// signatures, took 50.7 M cycles (51.7 M under the program of v4, of its
/// like 3.6 kB longer); the statement's input of funded notes, 20.7 kB,
/// 40.6 M; and of 32 notes each cited from a spend of one output, 34.4 kB
/// of which 7.8 kB of bodies, 56.1 M. Read 5% over, 5% under and 1% over.
pub(super) const BYTE_CYCLES: u64 = 2_200;

/// Cycles each byte of a spend's body costs where the spend is cited by
/// its owners' signatures ([`Evidence::Signed`]): hashed to its id and read
/// at the inputs relied on alone. 32 spends of the largest bodies took
/// 10.7 M cycles more than as many of the least, for 534.6 kB more of
/// bodies (20 a byte): 40 with a margin.
pub(super) const BODY_BYTE_CYCLES: u64 = 40;

/// The bytes of `evidence`'s spends cited by their signatures that are
/// their bodies, which cost [`BODY_BYTE_CYCLES`] a byte, not
/// [`BYTE_CYCLES`].
pub(super) fn body_bytes(evidence: &[Evidence]) -> u64 {
    (evidence.iter())
        .map(|e| match e {
            Evidence::Signed { body, .. } => body.len() as u64,
            _ => 0,
        })
        .sum()
}

/// Cycles a chained statement takes beyond its filing, signatures and the
/// headers it reads itself: the openings of the blocks the exit and the
/// claim's judgment read (32 levels of hashes each, 70 at most; 0.3 M
/// measured with a handful), the receipt's journal, and its resolution.
pub(super) const OPENING_CYCLES: u64 = 1_000_000;

/// What resolving the receipt a statement verifies costs: a recursion proof,
/// as a join is, which each segment's seconds count ([`Speed`]): one more
/// segment's cycles (2^18, a GPU's).
pub(super) const RESOLVE_CYCLES: u64 = 262_144;

/// The headers after the chain's receipt that a chained statement reads
/// itself, at most: the blocks that carry the work asked on the last one,
/// whose depth is the network's floor and a day's more at the most
/// (`terms::MAX_EXTRA_WORK`), and a few.
pub(super) const TAIL_HEADERS: u64 = 160;

/// Cycles each header costs the chain program, measured with `chain-exec`: 12.5 k
/// on 1,504 headers, 14 k with a margin.
pub(super) const CHAIN_HEADER_CYCLES: u64 = 14_000;

/// The cycles of a batch of `blocks` headers of the chain: its headers, and
/// the segments that make a batch's fixed cost (measured 0.2 M) and its
/// resolution.
pub(super) fn chain_batch_cycles(blocks: u32) -> u64 {
    CHAIN_HEADER_CYCLES * u64::from(blocks) + 500_000 + RESOLVE_CYCLES
}

/// The cycles of each header of a contract of graph `graph`, by the program
/// it was opened under: that of the compact filing's id on
/// ([`COMPACT_FROM`]), the one before's below.
pub(super) fn header_cycles(graph: u32) -> u64 {
    match graph >= COMPACT_FROM {
        true => COMPACT_HEADER_CYCLES,
        false => HEADER_CYCLES,
    }
}

/// Cycles the check of her request's signatures takes under a v4 Base,
/// beyond its keys' bytes: the answered input under a v4 Base took 5.8 M
/// cycles more for 1,570 bytes more (73.4 M). Counted for every contract.
pub(super) const SIGNATURE_CYCLES: u64 = 3_000_000;

/// What the benchmark may be off by on a real proof.
pub(super) const MARGIN: f64 = 1.3;

/// Not seen in this many polls, a contract's proof is no longer needed:
/// its assertion confirmed, or her timeout paid her. A poll that failed
/// for a contract is no reason to drop its proof.
const FORGET_POLLS: u64 = 10;

/// After a prover failure, or a failed probe, how long until it is tried
/// again.
const RETRY: Duration = Duration::from_secs(60);
const REPROBE: Duration = Duration::from_secs(15 * 60);

use super::chain::HubChain;
use super::Alert;

/// The prover's speed, as benchmarked: the cycles a segment holds, the
/// seconds a segment takes (proved, lifted and joined), and those of the
/// wrap every proof ends with.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Speed {
    pub device: String,
    pub segment_cycles: u64,
    pub segment: f64,
    pub tail: f64,
}

impl Speed {
    fn from_json(v: &serde_json::Value) -> Option<Self> {
        Some(Self {
            device: v["device"].as_str()?.to_owned(),
            segment_cycles: v["segment_cycles"].as_u64().filter(|c| *c > 0)?,
            segment: v["segment"].as_f64()?,
            tail: v["tail"].as_f64()?,
        })
    }

    /// This speed with each proof taking `by` times as long: what the
    /// operator says of its prover ([`Prover::scale`]).
    fn scaled(&self, by: f64) -> Self {
        Self {
            segment: self.segment * by,
            tail: self.tail * by,
            ..self.clone()
        }
    }

    /// The seconds a proof of `cycles` takes, with the margin.
    pub fn seconds(&self, cycles: u64) -> f64 {
        let segments = cycles.div_ceil(self.segment_cycles) as f64;
        MARGIN * (segments * self.segment + self.tail)
    }
}

/// Whether the hub may respond to a claim ([`Prover::admit`]).
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Admission {
    Admit,
    /// Not yet: the prover is being probed, or the claim was first seen on
    /// this poll.
    Wait,
    /// Not: why.
    Withhold(String),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Readiness {
    Ready(Speed),
    NotReady(String),
}

fn not_ready(why: &str) -> String {
    format!(
        "the hub's prover is not ready, so it responds to no contested claim (her timeout \
         pays her what she claims): {why}"
    )
}

/// The cycles of a statement's input of `headers` headers of `per_header`
/// cycles each ([`header_cycles`]) and `other` bytes besides.
pub(super) fn cycles(per_header: u64, headers: u64, other: u64) -> u64 {
    per_header * headers + BYTE_CYCLES * other
}

/// [`cycles`] of an input of which `bodies` of the `other` bytes are spends'
/// bodies ([`body_bytes`]).
pub(super) fn cycles_with_bodies(per_header: u64, headers: u64, other: u64, bodies: u64) -> u64 {
    let bodies = bodies.min(other);
    cycles(per_header, headers, other - bodies) + BODY_BYTE_CYCLES * bodies
}

/// The cycles of the largest proof of an exit a contract commits the hub
/// to: of each of its `headers`, from its checkpoint to its close, and of
/// its Base (`base` bytes), its publication (`publication` bytes at most),
/// as much evidence again and its exit's transactions (8 kB), and of her
/// request's signatures.
///
/// Of a chained contract ([`licash::recovery::chained`]) not of its age: the
/// headers it reads itself, the work it asks on the last block of its exit,
/// and what its openings and their receipt's resolution take.
pub(super) fn worst_cycles(headers: u32, publication: u32, base: usize, graph: u32) -> u64 {
    let other = base as u64 + 2 * u64::from(publication) + 8_192;
    if licash::recovery::chained(graph) {
        let tail = cycles(header_cycles(graph), TAIL_HEADERS, other);
        return tail + SIGNATURE_CYCLES + OPENING_CYCLES + RESOLVE_CYCLES;
    }
    cycles(header_cycles(graph), u64::from(headers), other) + SIGNATURE_CYCLES
}

/// The cycles of the statement's input `bytes` (`HubInput::to_bytes`):
/// Base, then the exit's headers; of a contract of graph `graph`. The
/// bodies of the spends it cites by their signatures count as such, if it
/// reads as an input; all its bytes as others' if not.
pub(super) fn input_cycles(bytes: &[u8], graph: u32) -> u64 {
    let bodies = licash_hp::HubInput::from_bytes(bytes).map_or(0, |i| body_bytes(&i.evidence));
    let word = |at: usize| {
        bytes.get(at..at + 4).map_or(0, |w| {
            u32::from_be_bytes(w.try_into().unwrap_or_default()) as usize
        })
    };
    let headers = word(4 + word(0)) as u64;
    let other = (bytes.len() as u64).saturating_sub(80 * headers);
    let chained = match licash::recovery::chained(graph) && !bytes.is_empty() {
        true => OPENING_CYCLES + RESOLVE_CYCLES,
        false => 0,
    };
    cycles_with_bodies(header_cycles(graph), headers, other, bodies) + chained
}

/// The target time between blocks of `profile`, in seconds.
pub(super) fn spacing(profile: ChainProfile) -> f64 {
    f64::from(profile.block_seconds())
}

/// A proof to plan: the last tip at which it must exist (its assertion
/// broadcast then confirms in time), the height from which it can be made
/// (its response and disclosure buried), and its seconds left.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Work {
    pub deadline: u32,
    pub release: u32,
    pub seconds: f64,
}

/// Which of `jobs` the one prover makes in time, made earliest deadline
/// first (then by id) from `tip`, a block every `spacing` seconds: a job
/// that would finish late is left out, and takes no time from those after.
pub(super) fn plan(jobs: &[([u8; 32], Work)], tip: u32, spacing: f64) -> HashMap<[u8; 32], bool> {
    let mut order: Vec<_> = jobs.iter().collect();
    order.sort_by_key(|(id, w)| (w.deadline, *id));
    let mut t = 0.0;
    let mut fits = HashMap::new();
    for (id, w) in order {
        let start = f64::max(t, f64::from(w.release.saturating_sub(tip)) * spacing);
        let end = start + w.seconds;
        let by = f64::from((w.deadline + 1).saturating_sub(tip)) * spacing;
        let fit = w.deadline >= tip && end <= by;
        if fit {
            t = end;
        }
        fits.insert(*id, fit);
    }
    fits
}

/// A proof the hub committed to: its response is on chain.
#[derive(Clone, Debug)]
struct Job {
    program: [u8; 32],
    deadline: u32,
    release: u32,
    cycles: u64,
    /// Its input, once frozen: until then it can't be made.
    frozen: bool,
    proven: bool,
    seen: u64,
    /// While failing: when to try again.
    retry: Option<Instant>,
}

/// A claim the hub would respond to, if its prover has room: what
/// responding saves it, and its proof's cycles.
#[derive(Clone, Debug)]
struct Candidate {
    stake: u64,
    cycles: u64,
    first: u64,
    seen: u64,
    deadline: u32,
    release: u32,
}

#[derive(Default)]
struct State {
    readiness: Option<Readiness>,
    jobs: HashMap<[u8; 32], Job>,
    candidates: HashMap<[u8; 32], Candidate>,
    /// The job being proved, since when.
    running: Option<([u8; 32], Instant)>,
    /// Set to stop the running job: no longer needed.
    cancel: bool,
    /// Polls of every contract completed.
    polls: u64,
    tip: u32,
    /// The programs contracts opened under before that the probe found
    /// not installed: their contracts' claims are withheld.
    uninstalled: Vec<[u8; 32]>,
    /// The programs the probe found installed, once probed: the claims of
    /// a contract under any other are withheld, whatever program this
    /// build knows it by.
    installed: Option<Vec<[u8; 32]>>,
    /// After a failed batch of the header chain: when to try again.
    chain_retry: Option<Instant>,
    /// What the operator scales each proof's estimate by
    /// ([`Prover::scale`]): 1 unless told.
    scale: Option<f64>,
    /// Whether the operator was told that proofs committed to are made in
    /// time only by the machines it counts on beside the hub's own.
    renting: bool,
}

struct Inner {
    dir: PathBuf,
    command: String,
    /// The program contracts open under: benchmarked.
    program: [u8; 32],
    /// Those contracts opened under before, proven with still.
    before: Vec<[u8; 32]>,
    spacing: f64,
    /// The hub's header chain, whose batches it proves when no dispute's
    /// proof can run: none for a program that reads every header.
    chain: Option<Arc<HubChain>>,
    /// The chain program its batches are proven with.
    chain_program: Option<[u8; 32]>,
    state: Mutex<State>,
    wake: Condvar,
    alert: OnceLock<Arc<Alert>>,
}

/// Those of `programs` that `probe` doesn't install.
fn uninstalled(probe: &serde_json::Value, programs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let installed = |id: &[u8; 32]| {
        let id = hex::encode(id);
        probe["programs"]
            .as_array()
            .is_some_and(|p| p.iter().any(|p| p.as_str() == Some(&id)))
    };
    programs
        .iter()
        .filter(|id| !installed(id))
        .copied()
        .collect()
}

/// The programs `probe` installs.
fn installed(probe: &serde_json::Value) -> Vec<[u8; 32]> {
    let ids = probe["programs"].as_array().into_iter().flatten();
    let id = |p: &serde_json::Value| <[u8; 32]>::try_from(hex::decode(p.as_str()?).ok()?).ok();
    ids.filter_map(id).collect()
}

/// The hub's one prover: see the module.
pub(super) struct Prover(Arc<Inner>);

impl Prover {
    /// The prover of `data`'s contracts, which open under `program`, and
    /// opened under `before` before, on a chain of a block every
    /// `spacing` seconds: probed and benchmarked, then proving, on a
    /// thread of its own.
    ///
    /// With `chain`, the hub's header chain and the chain program its
    /// batches are proven with, whose receipts the statement verifies.
    pub fn start(
        data: &Path,
        program: [u8; 32],
        before: &[[u8; 32]],
        spacing: f64,
        chain: Option<(Arc<HubChain>, [u8; 32])>,
    ) -> Self {
        let command = std::env::var("LICASH_HP_PROVER").unwrap_or_else(|_| "licash-r0".into());
        Self::start_with(data, command, program, before, spacing, chain)
    }

    fn start_with(
        data: &Path,
        command: String,
        program: [u8; 32],
        before: &[[u8; 32]],
        spacing: f64,
        chain: Option<(Arc<HubChain>, [u8; 32])>,
    ) -> Self {
        let (chain, chain_program) = match chain {
            Some((chain, program)) => (Some(chain), Some(program)),
            None => (None, None),
        };
        let inner = Arc::new(Inner {
            dir: data.join("hp-proofs"),
            command,
            program,
            before: before.to_vec(),
            spacing,
            chain,
            chain_program,
            state: Mutex::default(),
            wake: Condvar::new(),
            alert: OnceLock::new(),
        });
        let worker = inner.clone();
        std::thread::Builder::new()
            .name("hub prover".into())
            .spawn(move || worker.run())
            .expect("a thread for the prover");
        Self(inner)
    }

    /// Tell the operator through `f` from now on: the prover's not ready,
    /// fails, or has no room.
    pub fn alert_with(&self, f: Arc<Alert>) {
        let _ = self.0.alert.set(f);
        // Found not ready before: told now.
        let readiness = self.0.state().readiness.clone();
        if let Some(Readiness::NotReady(why)) = readiness {
            self.0.alert(&not_ready(&why));
        }
    }

    pub fn alert(&self, message: &str) {
        self.0.alert(message);
    }

    /// That the program `base` names reads a statement's input of it:
    /// executed on one before the hub signs anything of its contract. A
    /// program that can't read its own Base proves nothing of its contract,
    /// and each claim of it would be paid all it asks.
    pub async fn reads(&self, base: &licash::base::Base) -> Result<()> {
        let inner = self.0.clone();
        let bytes = base.to_bytes();
        let program = base.parts().recipe.program;
        tokio::task::spawn_blocking(move || inner.reads(&bytes, &program)).await?
    }

    /// How many proofs of the smallest contract's statement (the
    /// benchmark's input, 15 headers) the prover makes in `blocks`: what
    /// bounds the exits it can contest at once. None until it is ready.
    pub fn defendable(&self, blocks: u32) -> Option<u64> {
        let speed = self.0.state().speed()?;
        let seconds = speed.seconds(cycles(HEADER_CYCLES, 15, 33_600));
        Some((f64::from(blocks) * self.0.spacing / seconds) as u64)
    }

    /// The seconds proofs of each of `cycles`, made one after another,
    /// take, and the seconds the prover has in `blocks`; why not if it
    /// isn't ready.
    pub fn room(&self, cycles: &[u64], blocks: u32) -> Result<(f64, f64), String> {
        let s = self.0.state();
        let speed = match (s.speed(), &s.readiness) {
            (Some(speed), _) => speed,
            (None, Some(Readiness::NotReady(why))) => return Err(why.clone()),
            (None, _) => return Err("it is being probed".into()),
        };
        drop(s);
        let need = cycles.iter().map(|c| speed.seconds(*c)).sum();
        Ok((need, f64::from(blocks) * self.0.spacing))
    }

    /// Plan with each proof taking `by` times what the prover's benchmark
    /// says, from now on: as the hub admits openings ([`Prover::room`]),
    /// responds to claims ([`Prover::admit`]) and orders its proofs. Above
    /// 1 for a prover slower than its benchmark; below 1 for one that
    /// proves with machines beside its own, rented when it needs them
    /// (docs/hub.md), which no benchmark measures: its operator answers for
    /// them, and is told when they are needed ([`Prover::polled`]). Set
    /// once.
    pub fn scale(&self, by: f64) {
        self.0.state().scale.get_or_insert(by);
    }

    /// A prover of `speed`, ready, proving nothing, on a chain of a
    /// block every 600 s.
    #[cfg(test)]
    pub(super) fn ready_at(dir: &Path, speed: Speed) -> Self {
        let inner = Arc::new(Inner {
            dir: dir.to_owned(),
            command: "false".into(),
            program: [0; 32],
            before: Vec::new(),
            spacing: 600.0,
            chain: None,
            chain_program: None,
            state: Mutex::default(),
            wake: Condvar::new(),
            alert: OnceLock::new(),
        });
        inner.state().readiness = Some(Readiness::Ready(speed));
        Self(inner)
    }

    #[cfg(test)]
    pub(super) fn not_ready(&self, why: &str) {
        self.0.state().readiness = Some(Readiness::NotReady(why.into()));
    }

    /// The work directory of `id`'s proof.
    pub fn dir(&self, id: &[u8; 32]) -> PathBuf {
        self.0.dir.join(crate::hex_id(id))
    }

    /// The input of `id`'s proof, frozen as `input` unless it was before:
    /// its bytes. A statement that verifies a receipt of the chain program
    /// freezes it with `input`, before it: the proof is made of that receipt
    /// alone, whatever the chain proves later.
    pub fn freeze(&self, id: &[u8; 32], input: &[u8], receipt: Option<&Path>) -> Result<Vec<u8>> {
        let dir = self.dir(id);
        let path = dir.join("input.bin");
        if let Ok(frozen) = std::fs::read(&path) {
            return Ok(frozen);
        }
        std::fs::create_dir_all(&dir)?;
        if let Some(receipt) = receipt {
            let part = dir.join("chain.part");
            std::fs::copy(receipt, &part)?;
            std::fs::File::open(&part)?.sync_all()?;
            std::fs::rename(&part, dir.join("chain.receipt"))?;
        }
        let part = dir.join("input.part");
        std::fs::write(&part, input)?;
        std::fs::File::open(&part)?.sync_all()?;
        std::fs::rename(&part, &path)?;
        Ok(input.to_vec())
    }

    /// The frozen input of `id`'s proof, if it is.
    pub fn frozen(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        std::fs::read(self.dir(id).join("input.bin")).ok()
    }

    /// The seal of `id`'s proof, once made: its `proof.json`, set aside
    /// (and made again) if it isn't of `program`.
    pub fn proof(&self, id: &[u8; 32], program: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let out = self.dir(id).join("proof.json");
        let bytes = match std::fs::read(&out) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let read = || -> Result<Vec<u8>> {
            let json: serde_json::Value = serde_json::from_slice(&bytes)?;
            let image = json["image_id"].as_str().context("no image id")?;
            anyhow::ensure!(image == hex::encode(program), "a proof of program {image}");
            Ok(hex::decode(json["seal"].as_str().context("no seal")?)?)
        };
        match read() {
            Ok(seal) => Ok(Some(seal)),
            Err(e) => {
                self.reject(id, &format!("{e:#}"))?;
                Ok(None)
            }
        }
    }

    /// Set aside `id`'s `proof.json`, which does not verify, to make it
    /// again.
    pub fn reject(&self, id: &[u8; 32], why: &str) -> Result<()> {
        let dir = self.dir(id);
        std::fs::rename(dir.join("proof.json"), dir.join("proof.rejected"))?;
        self.alert(&format!(
            "contract {}: the prover's proof was rejected ({why}): proving again",
            crate::hex_id(id)
        ));
        if let Some(job) = self.0.state().jobs.get_mut(id) {
            job.proven = false;
        }
        self.0.wake.notify_all();
        Ok(())
    }

    /// The hub responded to `id`'s claim: its proof is to be made before
    /// `deadline`, from `release`, of `cycles` (its frozen input's, once it
    /// is). Called on each poll while it is needed: whether the plan makes
    /// it in time (always, once made or while the prover is not ready).
    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        &self,
        id: &[u8; 32],
        program: [u8; 32],
        deadline: u32,
        release: u32,
        cycles: u64,
        frozen: bool,
        proven: bool,
        tip: u32,
    ) -> bool {
        let mut s = self.0.state();
        s.tip = s.tip.max(tip);
        let seen = s.polls;
        s.candidates.remove(id);
        let job = s.jobs.entry(*id).or_insert(Job {
            program,
            deadline,
            release,
            cycles,
            frozen,
            proven,
            seen,
            retry: None,
        });
        job.deadline = deadline;
        job.release = release;
        job.cycles = cycles;
        job.frozen = frozen;
        job.proven = proven;
        job.seen = seen;
        let fits = match s.speed() {
            Some(speed) if !proven => plan(&s.committed(&speed), s.tip, self.0.spacing)[id],
            _ => true,
        };
        drop(s);
        self.0.wake.notify_all();
        fits
    }

    /// Whether the hub may respond to `id`'s claim, opened under
    /// `program`, which saves it `stake` sat if proved, and whose proof of
    /// `cycles` it would make before `deadline`, from `release`: its
    /// prover is ready and installs `program`, the claim was seen
    /// on a poll before this one (all the proofs committed to are known
    /// then, and its stake against the others'), and its proof fits with
    /// those committed to and those of larger stakes, none of which it
    /// would make late. Why not, if not.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        &self,
        id: &[u8; 32],
        program: &[u8; 32],
        stake: u64,
        cycles: u64,
        deadline: u32,
        release: u32,
        tip: u32,
    ) -> Admission {
        let mut s = self.0.state();
        s.tip = s.tip.max(tip);
        let polls = s.polls;
        let first = s.candidates.get(id).map_or(polls, |c| c.first);
        s.candidates.insert(
            *id,
            Candidate {
                stake,
                cycles,
                first,
                seen: polls,
                deadline,
                release,
            },
        );
        let speed = match (s.speed(), &s.readiness) {
            (Some(speed), _) => speed,
            (None, Some(Readiness::NotReady(why))) => {
                return Admission::Withhold(format!("the prover is not ready: {why}"))
            }
            (None, _) => return Admission::Wait,
        };
        let lacking = s.installed.as_ref().is_some_and(|i| !i.contains(program));
        if lacking || s.uninstalled.contains(program) {
            let program = hex::encode(program);
            return Admission::Withhold(format!("its program, {program}, is not installed"));
        }
        if first == polls {
            return Admission::Wait;
        }
        let mut before = s.committed(&speed);
        let larger = s.candidates.iter().filter(|(other, o)| {
            *other != id && o.seen + 1 >= polls && (o.stake, *id) > (stake, **other)
        });
        let larger: Vec<_> = larger
            .map(|(other, o)| {
                let work = Work {
                    deadline: o.deadline,
                    release: o.release,
                    seconds: speed.seconds(o.cycles),
                };
                (*other, work)
            })
            .collect();
        before.extend(larger);
        let fitted = plan(&before, s.tip, self.0.spacing);
        let mut with = before;
        let work = Work {
            deadline,
            release,
            seconds: speed.seconds(cycles),
        };
        with.push((*id, work));
        let fits = plan(&with, s.tip, self.0.spacing);
        if !fits[id] {
            return Admission::Withhold(format!(
                "its proof (about {:.0} min) would not be made in time",
                work.seconds / 60.0
            ));
        }
        if fitted.iter().any(|(other, fit)| *fit && !fits[other]) {
            return Admission::Withhold(
                "its proof would delay one committed to, or of a larger stake".into(),
            );
        }
        Admission::Admit
    }

    /// A poll of every contract is over: forget the proofs and claims no
    /// longer seen, and stop proving one of them. The operator is told,
    /// once, when the proofs committed to are made in time only at the
    /// speed it scaled the prover to ([`Prover::scale`]): by the machines
    /// it is to rent now.
    pub fn polled(&self) {
        let mut s = self.0.state();
        s.polls += 1;
        let polls = s.polls;
        let live = |seen: u64| seen + FORGET_POLLS >= polls;
        s.jobs.retain(|_, j| live(j.seen));
        s.candidates.retain(|_, c| live(c.seen));
        if let Some((id, _)) = s.running {
            if !s.jobs.contains_key(&id) {
                s.cancel = true;
            }
        }
        let rent = s.to_rent(self.0.spacing);
        let told = std::mem::replace(&mut s.renting, rent.is_some());
        drop(s);
        if let (Some(message), false) = (rent, told) {
            self.0.alert(&message);
        }
    }
}

impl State {
    /// The speed the hub plans with, once its prover is ready: the one
    /// measured, as its operator scales it ([`Prover::scale`]).
    fn speed(&self) -> Option<Speed> {
        match &self.readiness {
            Some(Readiness::Ready(speed)) => Some(speed.scaled(self.scale.unwrap_or(1.0))),
            _ => None,
        }
    }

    /// What to tell the operator if, of the proofs committed to that the
    /// plan makes in time, the hub's own prover alone would make some
    /// late: they count on the machines its operator scaled it for.
    fn to_rent(&self, spacing: f64) -> Option<String> {
        let (Some(Readiness::Ready(own)), Some(planned)) = (&self.readiness, self.speed()) else {
            return None;
        };
        let planned = plan(&self.committed(&planned), self.tip, spacing);
        let alone = self.committed(own);
        let fits = plan(&alone, self.tip, spacing);
        let late = alone.iter().filter(|(id, _)| planned[id] && !fits[id]);
        let (count, first) = late.fold((0, u32::MAX), |(count, first), (_, work)| {
            (count + 1, first.min(work.deadline))
        });
        (count > 0).then(|| {
            format!(
                "{count} of the {} proofs the hub committed to are made in time only by the \
                 machines it counts on beside its own prover (--contracts-proof-scale {}): rent \
                 them now and name them in LICASH_R0_WORKERS (docs/hub.md); the first is due \
                 by block {first}",
                alone.len(),
                self.scale.unwrap_or(1.0)
            )
        })
    }

    /// The proofs committed to and not made, with their seconds left.
    fn committed(&self, speed: &Speed) -> Vec<([u8; 32], Work)> {
        self.jobs
            .iter()
            .filter(|(_, j)| !j.proven)
            .map(|(id, j)| {
                let mut seconds = speed.seconds(j.cycles);
                if let Some((running, since)) = self.running {
                    if running == *id {
                        seconds = (seconds - since.elapsed().as_secs_f64()).max(0.0);
                    }
                }
                let work = Work {
                    deadline: j.deadline,
                    release: j.release,
                    seconds,
                };
                (*id, work)
            })
            .collect()
    }
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn alert(&self, message: &str) {
        match self.alert.get() {
            Some(alert) => alert(message),
            None => tracing::error!("alert: {message}"),
        }
    }

    fn set_readiness(&self, readiness: Readiness) {
        let before = self.state().readiness.replace(readiness.clone());
        match &readiness {
            Readiness::Ready(speed) => tracing::info!(
                device = %speed.device,
                segment_cycles = speed.segment_cycles,
                segment_s = speed.segment,
                tail_s = speed.tail,
                "the hub's prover is ready"
            ),
            Readiness::NotReady(why) if before != Some(readiness.clone()) => {
                self.alert(&not_ready(why))
            }
            _ => {}
        }
        self.wake.notify_all();
    }

    /// That `program` reads a statement's input of the Base of `bytes`
    /// (`hp-reads`).
    fn reads(&self, bytes: &[u8], program: &[u8; 32]) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let digest = licash::crypto::tagged_hash("licash/hub/reads", &[bytes]);
        let path = self
            .dir
            .join(format!("reads-{}.base", hex::encode(&digest[..8])));
        std::fs::write(&path, bytes)?;
        let out = self
            .command()
            .arg("hp-reads")
            .arg(&path)
            .arg(hex::encode(program))
            .output();
        let _ = std::fs::remove_file(&path);
        let out = out.with_context(|| format!("{} doesn't run", self.command))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Its error, not the guest's panic before it.
            let why = stderr.find("Error:").map_or(&*stderr, |at| &stderr[at..]);
            bail!("{}", why.trim().replace('\n', " "));
        }
        Ok(())
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(&self.command);
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Probe, then benchmark unless measured on this device before. The
    /// probe executes the program contracts open under on the benchmark's
    /// input, which the prover's own library made: one built before a change
    /// of format leaves the prover not ready, and no contract opened.
    fn ready(&self) -> Result<Speed> {
        let program = hex::encode(self.program);
        let out = self
            .command()
            .arg("probe")
            .arg(&program)
            .output()
            .with_context(|| format!("no prover: {} doesn't run", self.command))?;
        if !out.status.success() {
            bail!(
                "{} probe: {}",
                self.command,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let probe: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let mut problems: Vec<String> = probe["problems"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter_map(|p| p.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if !uninstalled(&probe, &[self.program]).is_empty() {
            problems.push(format!(
                "the program contracts open under, {program}, is not installed"
            ));
        }
        if let Some(chain) = self.chain_program {
            if !uninstalled(&probe, &[chain]).is_empty() {
                problems.push(format!(
                    "the chain program its statement verifies, {}, is not installed",
                    hex::encode(chain)
                ));
            }
        }
        if !problems.is_empty() {
            bail!("{}", problems.join("; "));
        }
        // Those before missing: their contracts' claims alone withheld.
        let missing = uninstalled(&probe, &self.before);
        if !missing.is_empty() && self.state().uninstalled != missing {
            let ids: Vec<_> = missing.iter().map(hex::encode).collect();
            self.alert(&format!(
                "the hub's prover lacks programs contracts opened under before ({}): \
                 it responds to no contested claim of their contracts",
                ids.join(", ")
            ));
        }
        self.state().uninstalled = missing;
        self.state().installed = Some(installed(&probe));
        let device = probe["device"].as_str().unwrap_or("cpu").to_owned();
        if device == "cpu" {
            tracing::warn!("the hub's prover has no GPU: it proves on the CPU, hours a proof");
        }
        std::fs::create_dir_all(&self.dir)?;
        let kept = self.dir.join("bench.json");
        let measured = std::fs::read(&kept)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .and_then(|v| Speed::from_json(&v));
        if let Some(speed) = measured.filter(|s| s.device == device) {
            return Ok(speed);
        }
        tracing::warn!(%device, "benchmarking the hub's prover: minutes");
        let log = std::fs::File::create(self.dir.join("bench.log"))?;
        let status = self
            .command()
            .arg("bench")
            .arg(&kept)
            .arg(&program)
            .stdout(log.try_clone()?)
            .stderr(log)
            .status()?;
        if !status.success() {
            bail!("its benchmark failed ({status}): see hp-proofs/bench.log");
        }
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&kept)?)?;
        Speed::from_json(&v).context("its benchmark's report")
    }

    fn run(self: Arc<Self>) {
        loop {
            match self.ready() {
                Ok(speed) => {
                    self.set_readiness(Readiness::Ready(speed));
                    self.prove_all();
                }
                Err(e) => {
                    self.set_readiness(Readiness::NotReady(format!("{e:#}")));
                    std::thread::sleep(REPROBE);
                }
            }
        }
    }

    /// The next proof to make: the first that fits the plan, else the
    /// earliest still live. None if there is none to make now.
    fn next(&self, s: &State) -> Option<([u8; 32], [u8; 32])> {
        let speed = s.speed()?;
        let now = Instant::now();
        let runnable = |j: &Job| {
            j.frozen && !j.proven && j.deadline >= s.tip && j.retry.is_none_or(|r| r <= now)
        };
        let jobs: Vec<_> = s
            .committed(&speed)
            .into_iter()
            .filter(|(id, _)| runnable(&s.jobs[id]))
            .collect();
        let fits = plan(&jobs, s.tip, self.spacing);
        let mut order: Vec<_> = jobs
            .iter()
            .map(|(id, w)| (!fits[id], w.deadline, *id))
            .collect();
        order.sort();
        let (_, _, id) = order.first()?;
        Some((*id, s.jobs[id].program))
    }

    /// Make the proofs committed to, one at a time, for as long as the
    /// hub runs.
    fn prove_all(&self) {
        loop {
            let (id, program) = {
                let mut s = self.state();
                let mut chained = false;
                // What the disputes asked of the header chain when its batch
                // was last looked for.
                let demanded = || self.chain.as_ref().map(|chain| chain.demanded());
                let mut seen = None;
                loop {
                    if let Some(next) = self.next(&s) {
                        break next;
                    }
                    // Nothing to contest: the header chain's batches, once.
                    // The lock is not held while one runs, so the next
                    // check is of what was committed meanwhile.
                    if self.chain.is_some() && !chained {
                        chained = true;
                        drop(s);
                        seen = demanded();
                        self.background();
                        s = self.state();
                        continue;
                    }
                    chained = false;
                    // Not waited for if a dispute asked for more since: a
                    // wake meanwhile, before this waits, would be lost.
                    if demanded() == seen {
                        s = self
                            .wake
                            .wait_timeout(s, RETRY)
                            .unwrap_or_else(PoisonError::into_inner)
                            .0;
                    }
                }
            };
            let ok = self.prove(&id, &program);
            let mut s = self.state();
            s.running = None;
            s.cancel = false;
            if let Some(job) = s.jobs.get_mut(&id) {
                match ok {
                    Ok(true) => {
                        job.proven = true;
                        job.retry = None;
                    }
                    // Stopped: no longer needed.
                    Ok(false) => {}
                    Err(e) => {
                        let first = job.retry.is_none();
                        job.retry = Some(Instant::now() + RETRY);
                        drop(s);
                        let message = format!(
                            "contract {}: the prover failed, trying again (see hp-proofs/{}/prover.log): {e:#}",
                            crate::hex_id(&id),
                            crate::hex_id(&id)
                        );
                        match first {
                            true => self.alert(&message),
                            false => tracing::error!("{message}"),
                        }
                    }
                }
            }
        }
    }

    /// The next batch of the header chain, if one is due and the prover is
    /// free of disputes: proven, or stopped (to carry on from the segments it
    /// kept) the moment a dispute's proof can run. Whether it ran.
    fn background(&self) -> bool {
        let (Some(chain), Some(program)) = (&self.chain, self.chain_program) else {
            return false;
        };
        if self.state().chain_retry.is_some_and(|r| r > Instant::now()) {
            return false;
        }
        let pending = match chain.next_batch() {
            Ok(Some(pending)) => pending,
            Ok(None) => return false,
            Err(e) => {
                tracing::error!("the header chain's next batch: {e:#}");
                self.state().chain_retry = Some(Instant::now() + RETRY);
                return false;
            }
        };
        let ran = (|| -> Result<bool> {
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(pending.work.join("prover.log"))?;
            let mut command = self.command();
            command
                .arg("chain-prove")
                .arg(&pending.input)
                .arg(&pending.work)
                .arg(hex::encode(program));
            if let Some(receipt) = &pending.assume {
                command.arg("--assume").arg(receipt);
            }
            let mut child = command
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()
                .with_context(|| format!("run {}", self.command))?;
            let started = Instant::now();
            tracing::info!(
                through = pending.through,
                "proving a batch of the hub's header chain"
            );
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success(), "{status}");
                    chain.done(&pending)?;
                    tracing::info!(
                        through = pending.through,
                        seconds = started.elapsed().as_secs(),
                        "a batch of the hub's header chain proved"
                    );
                    return Ok(true);
                }
                // A batch a dispute waits for is not stopped for another's
                // proof: that dispute could not start without it.
                let dispute = {
                    let s = self.state();
                    s.cancel || (!pending.demanded && self.next(&s).is_some())
                };
                if dispute {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::info!("a batch of the header chain stopped for a dispute's proof");
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        })();
        if let Err(e) = ran {
            self.state().chain_retry = Some(Instant::now() + RETRY);
            tracing::error!(
                through = pending.through,
                "a batch of the hub's header chain failed, trying again \
                 (see {}/prover.log): {e:#}",
                pending.work.display()
            );
        }
        true
    }

    /// Prove `id`'s frozen input with `program`: whether it was proved, or
    /// stopped as no longer needed.
    fn prove(&self, id: &[u8; 32], program: &[u8; 32]) -> Result<bool> {
        let dir = self.dir.join(crate::hex_id(id));
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("prover.log"))?;
        let mut command = self.command();
        command
            .arg("hp-prove")
            .arg(dir.join("input.bin"))
            .arg(&dir)
            .arg(hex::encode(program));
        // the receipt of the chain its statement verifies, frozen with it
        let chain = dir.join("chain.receipt");
        if chain.exists() {
            command.arg("--assume").arg(&chain);
        }
        let mut child = command
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .with_context(|| format!("run {}", self.command))?;
        let started = Instant::now();
        self.state().running = Some((*id, started));
        tracing::warn!(id = %crate::hex_id(id), "proving the hub's statement");
        loop {
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    bail!("{status}");
                }
                anyhow::ensure!(dir.join("proof.json").exists(), "it left no proof");
                tracing::info!(
                    id = %crate::hex_id(id),
                    seconds = started.elapsed().as_secs(),
                    "the hub's statement proved"
                );
                return Ok(true);
            }
            if self.state().cancel {
                let _ = child.kill();
                let _ = child.wait();
                tracing::info!(id = %crate::hex_id(id), "a proof no longer needed: stopped");
                return Ok(false);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(deadline: u32, release: u32, seconds: f64) -> Work {
        Work {
            deadline,
            release,
            seconds,
        }
    }

    #[test]
    fn the_plan_makes_proofs_earliest_deadline_first_and_leaves_out_those_late() {
        // A block every 600 s from tip 100.
        let jobs = [
            ([1; 32], work(110, 100, 3_000.0)),
            ([2; 32], work(105, 100, 3_000.0)),
            // Late whatever: left out, taking no time from the next.
            ([3; 32], work(106, 100, 9_000.0)),
            ([4; 32], work(112, 100, 1_200.0)),
        ];
        let fits = plan(&jobs, 100, 600.0);
        // [2] by 3,000 s of 3,600; [1] by 6,000 of 6,600; [4] by 7,200 of 7,800.
        assert_eq!(
            [
                fits[&[1; 32]],
                fits[&[2; 32]],
                fits[&[3; 32]],
                fits[&[4; 32]]
            ],
            [true, true, false, true]
        );
        // One can't start before its release; one past its deadline is late.
        let fits = plan(
            &[
                ([5; 32], work(110, 106, 3_100.0)),
                ([6; 32], work(99, 90, 1.0)),
            ],
            100,
            600.0,
        );
        assert_eq!((fits[&[5; 32]], fits[&[6; 32]]), (false, false));
        let fits = plan(&[([5; 32], work(110, 105, 3_000.0))], 100, 600.0);
        assert!(fits[&[5; 32]]);
    }

    #[test]
    fn a_proofs_seconds_are_its_segments_and_the_wrap_with_the_margin() {
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 250_000,
            segment: 3.0,
            tail: 100.0,
        };
        assert_eq!(speed.seconds(500_001), MARGIN * (3.0 * 3.0 + 100.0));
        // The benchmark's answered input, 27,309 bytes of which 15 headers
        // and 2,044 of a body, under the program of note format v5: 50.7 M
        // measured, read 5% over.
        let read = |bytes: u64| {
            cycles_with_bodies(COMPACT_HEADER_CYCLES, 15, bytes - 15 * 80, 2_044) as f64
        };
        let estimated = read(27_309) / 50_667_588.0;
        assert!((1.0..1.06).contains(&estimated), "{estimated}");
        // The statement's answered input of funded notes, 20,714 bytes, the
        // same body: 40.6 M, read 5% under.
        let estimated = read(20_714) / 40_620_898.0;
        assert!((0.94..1.0).contains(&estimated), "{estimated}");
    }

    /// The bodies of spends cited by their signatures are hashed, not read:
    /// the statement's input of 32 notes each cited from a spend of the
    /// largest body, 504,486 bytes of which 477,824 of bodies, took 65.4 M
    /// cycles, and of each cited from a spend of the least, 34,438 bytes of
    /// which 7,776, 56.1 M. Read over, never under; as bytes like others,
    /// 17 times over.
    #[test]
    fn a_spends_body_cited_by_signatures_costs_its_hashing() {
        let read = |bytes: u64, bodies: u64| {
            cycles_with_bodies(COMPACT_HEADER_CYCLES, 15, bytes - 15 * 80, bodies) as f64
        };
        for (bytes, bodies, measured) in [
            (504_486, 477_824, 65_425_267.0),
            (34_438, 7_776, 56_071_660.0),
        ] {
            let estimated = read(bytes, bodies);
            assert!((1.0..1.4).contains(&(estimated / measured)), "{estimated}");
        }
        assert!(read(504_486, 0) > 15.0 * 65_425_267.0);
        // Bodies are at most the bytes they are of.
        assert_eq!(read(34_438, 10_000_000), read(34_438, 34_438 - 15 * 80));
        // An input that does not read counts all its bytes as others'.
        let mut bytes = Vec::new();
        bytes.extend(3u32.to_be_bytes());
        bytes.extend([7; 3]);
        bytes.extend(0u32.to_be_bytes());
        bytes.extend([1; 10]);
        assert_eq!(
            input_cycles(&bytes, COMPACT_FROM),
            cycles(COMPACT_HEADER_CYCLES, 0, bytes.len() as u64)
        );
    }

    /// The largest proof a contract of the hub citing spends by their
    /// signatures commits it to ([`licash::recovery::SIGNED_FROM`]) is a
    /// chained one's, and bounds the most evidence a claim may need: 65.4 M
    /// measured with every spend's body the largest.
    #[test]
    fn a_contract_citing_by_signatures_bounds_its_worst_evidence() {
        use licash::recovery::{BOUND_BASE_FROM, SIGNED_FROM};
        let worst = |graph| worst_cycles(105_120, 64_000, 4_000, graph);
        assert_eq!(worst(SIGNED_FROM), worst(BOUND_BASE_FROM));
        assert!(worst(SIGNED_FROM) > 65_425_267);
        assert_eq!(
            worst(SIGNED_FROM),
            worst_cycles(1, 64_000, 4_000, SIGNED_FROM)
        );
    }

    #[test]
    fn a_chained_contracts_worst_proof_is_not_of_its_age() {
        use licash::recovery::{CHAINED_FROM, LEAN_FROM};
        let publication = 64_000;
        let lean = |headers| worst_cycles(headers, publication, 4_000, LEAN_FROM);
        let chained = |headers| worst_cycles(headers, publication, 4_000, CHAINED_FROM);
        // a half year and two years of signet's blocks cost a chained contract
        // the same, which a lean one's cost grows with
        assert_eq!(chained(26_280), chained(105_120));
        assert!(lean(105_120) > 3 * lean(26_280) / 2);
        assert!(lean(26_280) > chained(26_280));
        // and what it costs is the filing's, with the tail and the openings
        let filing = BYTE_CYCLES * (4_000 + 2 * publication as u64 + 8_192);
        assert_eq!(
            chained(1),
            filing
                + COMPACT_HEADER_CYCLES * TAIL_HEADERS
                + SIGNATURE_CYCLES
                + OPENING_CYCLES
                + RESOLVE_CYCLES
        );
        // a statement's input counts its tail's headers and the same extras
        let mut bytes = Vec::new();
        bytes.extend(3u32.to_be_bytes());
        bytes.extend([7; 3]);
        bytes.extend(2u32.to_be_bytes());
        bytes.extend([0; 160]);
        let other = bytes.len() as u64 - 160;
        assert_eq!(
            input_cycles(&bytes, CHAINED_FROM),
            cycles(COMPACT_HEADER_CYCLES, 2, other) + OPENING_CYCLES + RESOLVE_CYCLES
        );
        // a batch of a day's blocks, on a network of 144 a day
        assert_eq!(
            chain_batch_cycles(144),
            14_000 * 144 + 500_000 + RESOLVE_CYCLES
        );
    }

    #[test]
    fn an_inputs_cycles_count_its_headers() {
        let mut bytes = Vec::new();
        bytes.extend(3u32.to_be_bytes());
        bytes.extend([7; 3]);
        bytes.extend(2u32.to_be_bytes());
        bytes.extend([0; 160]);
        bytes.extend([1; 10]);
        let other = bytes.len() as u64 - 160;
        assert_eq!(input_cycles(&bytes, 8), cycles(HEADER_CYCLES, 2, other));
        assert_eq!(
            input_cycles(&bytes, COMPACT_FROM),
            cycles(COMPACT_HEADER_CYCLES, 2, other)
        );
        assert_eq!(input_cycles(&[], 8), 0);
    }

    fn ready(dir: &Path, speed: Speed) -> Prover {
        Prover::ready_at(dir, speed)
    }

    /// A proof of 1 M cycles takes 1,300 s with the margin; one of 2 M,
    /// 2,600. From tip 100, a deadline of 110 leaves 6,600 s.
    #[test]
    fn admission_keeps_the_proofs_committed_to_and_prefers_larger_stakes() {
        let dir = tempfile::tempdir().unwrap();
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 1_000_000,
            segment: 1_000.0,
            tail: 0.0,
        };
        let p = ready(dir.path(), speed);
        // Not before a poll saw it.
        assert_eq!(
            p.admit(&[1; 32], &[0; 32], 10, 2_000_000, 110, 100, 100),
            Admission::Wait
        );
        p.polled();
        assert_eq!(
            p.admit(&[1; 32], &[0; 32], 10, 2_000_000, 110, 100, 100),
            Admission::Admit
        );
        p.commit(&[1; 32], [0; 32], 110, 100, 2_000_000, true, false, 100);
        // Two more claims, one of a larger stake: room for one of them.
        let _ = p.admit(&[2; 32], &[0; 32], 5, 2_000_000, 110, 100, 100);
        let _ = p.admit(&[3; 32], &[0; 32], 50, 2_000_000, 110, 100, 100);
        p.polled();
        let small = p.admit(&[2; 32], &[0; 32], 5, 2_000_000, 110, 100, 100);
        assert!(
            matches!(&small, Admission::Withhold(w) if w.contains("larger stake")),
            "{small:?}"
        );
        assert_eq!(
            p.admit(&[3; 32], &[0; 32], 50, 2_000_000, 110, 100, 100),
            Admission::Admit
        );
        p.commit(&[3; 32], [0; 32], 110, 100, 2_000_000, false, false, 100);
        // Seen later, it would not be in time now.
        let late = p.admit(&[2; 32], &[0; 32], 5, 2_000_000, 111, 101, 100);
        assert!(
            matches!(&late, Admission::Withhold(w) if w.contains("in time")),
            "{late:?}"
        );
        // A proof made frees its room.
        p.commit(&[1; 32], [0; 32], 110, 100, 2_000_000, true, true, 100);
        assert_eq!(
            p.admit(&[2; 32], &[0; 32], 5, 2_000_000, 111, 101, 100),
            Admission::Admit
        );
    }

    /// The prover above, whose operator counts on machines that make each
    /// proof in half the time: it responds to three claims where alone it
    /// would to two, and its operator is told, once, that one of the proofs
    /// it committed to is in time only with them.
    #[test]
    fn a_scaled_prover_responds_for_the_machines_its_operator_counts_on() {
        let dir = tempfile::tempdir().unwrap();
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 1_000_000,
            segment: 1_000.0,
            tail: 0.0,
        };
        let p = ready(dir.path(), speed);
        let told: Arc<Mutex<Vec<String>>> = Arc::default();
        let kept = told.clone();
        p.alert_with(Arc::new(move |m| kept.lock().unwrap().push(m.to_owned())));
        assert_eq!(p.room(&[2_000_000], 11), Ok((2_600.0, 6_600.0)));
        p.scale(0.5);
        // Set once.
        p.scale(4.0);
        assert_eq!(p.room(&[2_000_000], 11), Ok((1_300.0, 6_600.0)));
        let claims = [[1; 32], [2; 32], [3; 32]];
        for id in &claims {
            let _ = p.admit(id, &[0; 32], 10, 2_000_000, 110, 100, 100);
        }
        p.polled();
        for id in &claims {
            assert_eq!(
                p.admit(id, &[0; 32], 10, 2_000_000, 110, 100, 100),
                Admission::Admit
            );
        }
        // Two of them alone need none of those machines.
        for id in &claims[..2] {
            assert!(p.commit(id, [0; 32], 110, 100, 2_000_000, true, false, 100));
        }
        p.polled();
        assert!(told.lock().unwrap().is_empty());
        assert!(p.commit(&claims[2], [0; 32], 110, 100, 2_000_000, true, false, 100));
        p.polled();
        p.polled();
        {
            let told = told.lock().unwrap();
            assert_eq!(told.len(), 1, "{told:?}");
            assert!(told[0].starts_with("1 of the 3 proofs"), "{}", told[0]);
            assert!(
                told[0].contains("--contracts-proof-scale 0.5"),
                "{}",
                told[0]
            );
            assert!(told[0].contains("due by block 110"), "{}", told[0]);
        }
        // Told again once it needs them anew.
        p.commit(&claims[0], [0; 32], 110, 100, 2_000_000, true, true, 100);
        p.polled();
        assert_eq!(told.lock().unwrap().len(), 1);
        p.commit(&[4; 32], [0; 32], 110, 100, 2_000_000, true, false, 100);
        p.polled();
        assert_eq!(told.lock().unwrap().len(), 2);
        // More than even those machines make is withheld as ever.
        for id in [[5; 32], [6; 32], [7; 32]] {
            let _ = p.admit(&id, &[0; 32], 10, 2_000_000, 110, 100, 100);
        }
        p.polled();
        let admitted = [[5; 32], [6; 32], [7; 32]]
            .iter()
            .filter(|id| p.admit(id, &[0; 32], 10, 2_000_000, 110, 100, 100) == Admission::Admit)
            .count();
        assert_eq!(admitted, 2);
    }

    /// Many holders close at once, all claiming more than they are owed:
    /// the hub responds to the claims of the largest stakes its prover can
    /// prove in time, whatever order it found them in, and proves those
    /// earliest deadline first. (Claims owed in full never get here: the
    /// hub lets them pay without a proof.)
    #[test]
    fn a_mass_exit_proves_the_largest_stakes_in_time_earliest_deadline_first() {
        let dir = tempfile::tempdir().unwrap();
        // 2 M cycles: 2,600 s with the margin.
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 1_000_000,
            segment: 1_000.0,
            tail: 0.0,
        };
        let p = ready(dir.path(), speed);
        // Claim i saves 10 i sat; its deadlines are spread over 110 to
        // 117, from tip 100: 10,800 s at most, four proofs.
        let deadline = |i: u8| 110 + u32::from(i) * 3 % 8;
        let found = [3u8, 7, 1, 8, 5, 2, 6, 4];
        let admit = |i: u8| {
            let stake = 10 * u64::from(i);
            p.admit(&[i; 32], &[0; 32], stake, 2_000_000, deadline(i), 100, 100)
        };
        for i in found {
            assert_eq!(admit(i), Admission::Wait);
        }
        p.polled();
        let mut answered = Vec::new();
        for i in found {
            match admit(i) {
                Admission::Admit => {
                    p.commit(
                        &[i; 32],
                        [0; 32],
                        deadline(i),
                        100,
                        2_000_000,
                        true,
                        false,
                        100,
                    );
                    answered.push(i);
                }
                Admission::Withhold(why) => assert!(
                    why.contains("larger stake") || why.contains("in time"),
                    "{i}: {why}"
                ),
                Admission::Wait => panic!("{i} seen a poll before"),
            }
        }
        answered.sort();
        assert_eq!(answered, [5, 6, 7, 8]);
        // Proved earliest deadline first: 110, 112, 115, 117.
        let mut proved = Vec::new();
        loop {
            let next = p.0.next(&p.0.state());
            let Some((id, _)) = next else { break };
            proved.push(id[0]);
            p.commit(
                &id,
                [0; 32],
                deadline(id[0]),
                100,
                2_000_000,
                true,
                true,
                100,
            );
        }
        assert_eq!(proved, [8, 6, 7, 5]);
    }

    #[test]
    fn the_exits_defendable_are_the_smallest_proofs_a_window_holds() {
        let dir = tempfile::tempdir().unwrap();
        // About 1,000 s with the margin.
        let segment = 1_000.0 / MARGIN / 335.0;
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: cycles(HEADER_CYCLES, 15, 33_600).div_ceil(335),
            segment,
            tail: 0.0,
        };
        let p = ready(dir.path(), speed);
        // Signet's 39 blocks: 23,400 s.
        assert_eq!(p.defendable(39), Some(23));
        p.0.state().readiness = Some(Readiness::NotReady("no GPU".into()));
        assert_eq!(p.defendable(39), None);
    }

    #[test]
    fn a_prover_not_ready_admits_nothing_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let p = ready(
            dir.path(),
            Speed {
                device: "cpu".into(),
                segment_cycles: 1,
                segment: 1.0,
                tail: 1.0,
            },
        );
        p.0.state().readiness = Some(Readiness::NotReady("no GPU".into()));
        p.polled();
        let e = p.admit(&[1; 32], &[0; 32], 1, 1, 110, 100, 100);
        assert!(
            matches!(&e, Admission::Withhold(w) if w.contains("no GPU")),
            "{e:?}"
        );
    }

    #[test]
    fn contracts_no_longer_seen_are_forgotten_and_their_proof_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 1,
            segment: 1.0,
            tail: 1.0,
        };
        let p = ready(dir.path(), speed);
        p.commit(&[1; 32], [0; 32], 110, 100, 1, true, false, 100);
        p.0.state().running = Some(([1; 32], Instant::now()));
        for _ in 0..FORGET_POLLS {
            p.polled();
        }
        assert!(!p.0.state().cancel);
        p.polled();
        let s = p.0.state();
        assert!(s.jobs.is_empty() && s.cancel);
    }

    #[test]
    fn an_input_is_frozen_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = ready(
            dir.path(),
            Speed {
                device: "cpu".into(),
                segment_cycles: 1,
                segment: 1.0,
                tail: 1.0,
            },
        );
        assert_eq!(p.frozen(&[1; 32]), None);
        assert_eq!(p.freeze(&[1; 32], b"first", None).unwrap(), b"first");
        assert_eq!(p.freeze(&[1; 32], b"later", None).unwrap(), b"first");
        assert_eq!(p.frozen(&[1; 32]).as_deref(), Some(&b"first"[..]));
    }

    #[test]
    fn a_proof_of_another_program_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let p = ready(
            dir.path(),
            Speed {
                device: "cpu".into(),
                segment_cycles: 1,
                segment: 1.0,
                tail: 1.0,
            },
        );
        let d = p.dir(&[1; 32]);
        std::fs::create_dir_all(&d).unwrap();
        let json = |image: &str| format!(r#"{{"image_id":"{image}","seal":"0102"}}"#);
        std::fs::write(d.join("proof.json"), json(&hex::encode([0; 32]))).unwrap();
        assert_eq!(p.proof(&[1; 32], &[0; 32]).unwrap(), Some(vec![1, 2]));
        assert_eq!(p.proof(&[1; 32], &[9; 32]).unwrap(), None);
        assert!(d.join("proof.rejected").exists() && !d.join("proof.json").exists());
    }

    /// A prover of `script`'s, in `dir`, for program [7; 32].
    fn fake(dir: &Path, script: &str) -> Prover {
        fake_with(dir, script, None)
    }

    /// [`fake`], with a header chain it proves the batches of, by the chain
    /// program [9; 32].
    fn fake_with(dir: &Path, script: &str, chain: Option<Arc<HubChain>>) -> Prover {
        let path = dir.join("prover.sh");
        std::fs::write(&path, format!("#!/bin/sh\nset -e\n{script}")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Prover::start_with(
            dir,
            path.display().to_string(),
            [7; 32],
            &[],
            600.0,
            chain.map(|chain| (chain, [9; 32])),
        )
    }

    fn until(what: &str, f: impl Fn() -> bool) {
        let start = Instant::now();
        while !f() {
            assert!(start.elapsed() < Duration::from_secs(20), "{what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn readiness(p: &Prover) -> Option<Readiness> {
        p.0.state().readiness.clone()
    }

    /// A contract's Base is read by the program it names, `hp-reads <base>
    /// <program>`, its bytes kept only as long: refused with the prover's
    /// reason if the program doesn't read it.
    #[tokio::test]
    async fn a_base_its_program_does_not_read_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = licash_contract::opening::testing::base(&[3; 32]);
        let program = hex::encode(base.parts().recipe.program);
        let script = format!(
            r#"echo "$@" >> "$(dirname "$0")/calls"
case "$1" in
hp-reads) cmp -s "$2" "$(dirname "$0")/expected" && [ "$3" = {program} ] && exit 0
  echo 'thread panicked: the statement'"'"'s input' >&2
  echo 'Error: it does not read the input this build'"'"'s library makes' >&2; exit 1 ;;
esac
"#
        );
        std::fs::write(dir.path().join("expected"), base.to_bytes()).unwrap();
        let p = fake(dir.path(), &script);
        p.reads(&base).await.unwrap();
        // Another Base, or the same of another program: not read.
        let mut parts = base.parts().clone();
        parts.nonce = [9; 32];
        let other = licash::base::Base::new(parts).unwrap();
        let e = p.reads(&other).await.unwrap_err().to_string();
        assert_eq!(
            e,
            "Error: it does not read the input this build's library makes"
        );
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        let reads: Vec<_> = calls
            .lines()
            .filter(|l| l.starts_with("hp-reads"))
            .collect();
        assert_eq!(reads.len(), 2, "{calls}");
        assert!(reads.iter().all(|l| l.ends_with(&program)), "{calls}");
        let kept = std::fs::read_dir(p.0.dir.clone()).unwrap();
        assert!(
            kept.flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with("reads-")),
            "a Base left behind"
        );
    }

    /// Probed, benchmarked once, then each proof committed to made once its
    /// input is frozen, by `hp-prove <input> <dir> <program>`.
    #[test]
    fn a_ready_prover_is_benchmarked_once_and_makes_the_proofs_committed_to() {
        let dir = tempfile::tempdir().unwrap();
        let id = hex::encode([7u8; 32]);
        let script = format!(
            r#"echo "$@" >> "$(dirname "$0")/calls"
case "$1" in
probe) echo '{{"device":"cuda","programs":["{id}"],"problems":[]}}' ;;
bench) echo '{{"device":"cuda","segment_cycles":1000000,"segment":1.0,"tail":60.0}}' > "$2" ;;
hp-prove) echo "{{\"image_id\":\"$4\",\"seal\":\"0a0b\"}}" > "$3/proof.json" ;;
esac
"#
        );
        let p = fake(dir.path(), &script);
        until("ready", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        let Some(Readiness::Ready(speed)) = readiness(&p) else {
            unreachable!()
        };
        assert_eq!(
            (speed.device.as_str(), speed.segment_cycles),
            ("cuda", 1_000_000)
        );
        // Committed to, not frozen: not proved.
        assert!(p.commit(&[1; 32], [7; 32], 110, 100, 1_000, false, false, 100));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(p.proof(&[1; 32], &[7; 32]).unwrap(), None);
        p.freeze(&[1; 32], b"input", None).unwrap();
        p.commit(&[1; 32], [7; 32], 110, 100, 1_000, true, false, 100);
        until("proved", || p.dir(&[1; 32]).join("proof.json").exists());
        until("its seal", || {
            p.proof(&[1; 32], &[7; 32]).unwrap() == Some(vec![10, 11])
        });
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        let input = p.dir(&[1; 32]).join("input.bin");
        let lines: Vec<_> = calls.lines().collect();
        assert_eq!(lines[0], format!("probe {id}"));
        assert!(
            lines[1].starts_with("bench ") && lines[1].ends_with(&id),
            "{calls}"
        );
        assert_eq!(
            lines[2],
            format!(
                "hp-prove {} {} {id}",
                input.display(),
                p.dir(&[1; 32]).display()
            )
        );
        // Measured on this device before: not benchmarked again.
        drop(p);
        std::fs::remove_file(dir.path().join("calls")).unwrap();
        let p = fake(dir.path(), &script);
        until("ready again", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        assert_eq!(calls, format!("probe {id}\n"));
    }

    /// A hub's header chain of 20 blocks the node has, a dispute asking
    /// for the first 8 of them proven.
    async fn chained(dir: &Path, batch: Option<u32>) -> Arc<HubChain> {
        use super::super::chain::fixtures::{genesis, Node};
        let (chain, _) = HubChain::open(
            &crate::testing::hub_data(dir),
            [9; 32],
            licash::spend::ChainProfile::Core30DefaultRegtest,
        )
        .unwrap();
        let chain = match batch {
            Some(blocks) => chain.with_batch(blocks),
            None => chain,
        };
        chain.begin(&genesis()).unwrap();
        chain.follow(&Node::new(20), 20).await.unwrap();
        Arc::new(chain)
    }

    const CHAIN_SCRIPT: &str = r#"echo "$@" >> "$(dirname "$0")/calls"
case "$1" in
probe) echo '{"device":"cuda","programs":["0707070707070707070707070707070707070707070707070707070707070707","0909090909090909090909090909090909090909090909090909090909090909"],"problems":[]}' ;;
bench) echo '{"device":"cuda","segment_cycles":1000000,"segment":1.0,"tail":60.0}' > "$2" ;;
chain-prove)
    [ -e "$(dirname "$0")/slow" ] && sleep 60
    echo receipt > "$3/receipt" ;;
hp-prove) echo "{\"image_id\":\"$4\",\"seal\":\"0a0b\"}" > "$3/proof.json" ;;
esac
"#;

    /// With no dispute to prove, the prover proves the header chain's batches
    /// the hub's chain makes due, each resuming the receipt before it.
    #[tokio::test]
    async fn a_prover_proves_the_header_chains_batches_when_no_dispute_is_to_be_proven() {
        let dir = tempfile::tempdir().unwrap();
        let chain = chained(dir.path(), None).await;
        let p = fake_with(dir.path(), CHAIN_SCRIPT, Some(chain.clone()));
        until("ready", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        // nothing is due until a dispute needs a receipt
        std::thread::sleep(Duration::from_millis(300));
        assert!(chain.receipt_through(1).is_none());
        chain.demand(8);
        p.0.wake.notify_all();
        until("the first batch", || chain.receipt_through(8).is_some());
        chain.demand(15);
        p.0.wake.notify_all();
        until("the second batch", || chain.receipt_through(15).is_some());
        let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
        let program = hex::encode([9u8; 32]);
        let batches: Vec<_> = calls
            .lines()
            .filter(|l| l.starts_with("chain-prove"))
            .collect();
        assert_eq!(batches.len(), 2, "{calls}");
        assert!(batches[0].ends_with(&program), "{calls}");
        assert!(!batches[0].contains("--assume"), "{calls}");
        // the first receipt's file: 9 blocks, of the chain through block 8
        let first = dir
            .path()
            .join("header-chain")
            .join(hex::encode([9u8; 32]))
            .join("receipt-9");
        let kept = chain.receipt_through(15).unwrap();
        assert_eq!(tip_of(&kept), 15);
        assert!(
            batches[1].ends_with(&format!("--assume {}", first.display())),
            "{calls}"
        );
        // the program it needs is among those it requires installed
        assert!(p.0.chain_program == Some([9; 32]));
    }

    fn tip_of(r: &super::super::chain::Receipt) -> u32 {
        r.journal.tip_height()
    }

    /// A dispute's proof can run: a batch nobody waits for (a day of blocks
    /// since the last receipt) is stopped, and proven again after it, from the
    /// segments it kept.
    #[tokio::test]
    async fn a_dispute_stops_a_batch_nobody_waits_for_which_is_proven_after() {
        let dir = tempfile::tempdir().unwrap();
        // a day is 5 blocks here, and 20 are behind
        let chain = chained(dir.path(), Some(5)).await;
        std::fs::write(dir.path().join("slow"), b"").unwrap();
        let p = fake_with(dir.path(), CHAIN_SCRIPT, Some(chain.clone()));
        until("ready", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        let calls = || std::fs::read_to_string(dir.path().join("calls")).unwrap_or_default();
        until("the batch under way", || calls().contains("chain-prove"));
        assert!(chain.receipt_through(1).is_none());
        // a dispute whose input is frozen: it runs first
        p.freeze(&[1; 32], b"input", None).unwrap();
        p.commit(&[1; 32], [7; 32], 110, 100, 1_000, true, false, 100);
        until("the dispute proved", || {
            p.dir(&[1; 32]).join("proof.json").exists()
        });
        assert!(chain.receipt_through(1).is_none(), "{}", calls());
        // no longer slow: the batch is made again, and done
        std::fs::remove_file(dir.path().join("slow")).unwrap();
        p.0.wake.notify_all();
        until("the batch proven", || chain.receipt_through(1).is_some());
        let proving: Vec<_> = calls()
            .lines()
            .filter(|l| l.starts_with("chain-prove"))
            .map(str::to_owned)
            .collect();
        assert!(proving.len() >= 2, "stopped and made again: {proving:?}");
    }

    /// A batch a dispute waits for is proven before another dispute's proof
    /// runs: that dispute can't start without it, and would wait for the
    /// others' as well.
    #[tokio::test]
    async fn a_batch_a_dispute_waits_for_is_not_stopped_for_another() {
        let dir = tempfile::tempdir().unwrap();
        let chain = chained(dir.path(), None).await;
        std::fs::write(dir.path().join("slow"), b"").unwrap();
        // slow for a moment, not for good
        let script = CHAIN_SCRIPT.replace("sleep 60", "sleep 2");
        let p = fake_with(dir.path(), &script, Some(chain.clone()));
        until("ready", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        chain.demand(8);
        p.0.wake.notify_all();
        let calls = || std::fs::read_to_string(dir.path().join("calls")).unwrap_or_default();
        until("the batch under way", || calls().contains("chain-prove"));
        p.freeze(&[1; 32], b"input", None).unwrap();
        p.commit(&[1; 32], [7; 32], 110, 100, 1_000, true, false, 100);
        until("the dispute proved", || {
            p.dir(&[1; 32]).join("proof.json").exists()
        });
        assert!(chain.receipt_through(8).is_some(), "the batch came first");
        let proving = calls()
            .lines()
            .filter(|l| l.starts_with("chain-prove"))
            .count();
        assert_eq!(proving, 1, "never stopped: {}", calls());
    }

    /// A program contracts opened under before, not installed: the prover
    /// is ready, and withholds only the claims of its contracts.
    #[test]
    fn a_prover_withholds_only_the_claims_of_programs_it_lacks() {
        let probe = |ids: &[[u8; 32]]| serde_json::json!({ "programs": ids.iter().map(hex::encode).collect::<Vec<_>>() });
        let before = [[8; 32], [9; 32]];
        assert!(uninstalled(&probe(&[[7; 32], [8; 32], [9; 32]]), &before).is_empty());
        assert_eq!(uninstalled(&probe(&[[7; 32], [9; 32]]), &before), [[8; 32]]);
        assert_eq!(uninstalled(&serde_json::json!({}), &before), before);
        let dir = tempfile::tempdir().unwrap();
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 250_000,
            segment: 3.0,
            tail: 100.0,
        };
        let p = Prover::ready_at(dir.path(), speed);
        p.0.state().uninstalled = vec![[8; 32]];
        let admit = |id: u8, program: [u8; 32]| p.admit(&[id; 32], &program, 1, 1_000, 900, 10, 0);
        let Admission::Withhold(why) = admit(1, [8; 32]) else {
            panic!("admitted")
        };
        assert!(why.contains(&hex::encode([8; 32])), "{why}");
        assert!(matches!(admit(2, [9; 32]), Admission::Wait));
        assert!(matches!(admit(3, [7; 32]), Admission::Wait));
    }

    /// A contract under a program the probe found missing, though this
    /// build names it nowhere: its claims withheld too, not proved late.
    #[test]
    fn a_prover_withholds_the_claims_of_any_program_not_installed() {
        let probe =
            serde_json::json!({ "programs": [hex::encode([7; 32]), "zz", hex::encode([1; 3])] });
        assert_eq!(installed(&probe), [[7; 32]]);
        let dir = tempfile::tempdir().unwrap();
        let speed = Speed {
            device: "cuda".into(),
            segment_cycles: 250_000,
            segment: 3.0,
            tail: 100.0,
        };
        let p = Prover::ready_at(dir.path(), speed);
        p.0.state().installed = Some(installed(&probe));
        let admit = |id: u8, program: [u8; 32]| p.admit(&[id; 32], &program, 1, 1_000, 900, 10, 0);
        let Admission::Withhold(why) = admit(1, [6; 32]) else {
            panic!("admitted")
        };
        assert!(why.contains(&hex::encode([6; 32])), "{why}");
        assert!(matches!(admit(2, [7; 32]), Admission::Wait));
    }

    /// A probe's problems, or a program not installed, and it is not ready:
    /// told once, and claims withheld.
    #[test]
    fn a_prover_with_problems_is_not_ready_and_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let p = fake(
            dir.path(),
            r#"echo '{"device":"cpu","programs":[],"problems":["memory: 2 GB"]}'"#,
        );
        until("probed", || readiness(&p).is_some());
        let Some(Readiness::NotReady(why)) = readiness(&p) else {
            panic!("ready")
        };
        assert!(
            why.contains("memory: 2 GB") && why.contains("is not installed"),
            "{why}"
        );
        let told: Arc<Mutex<Vec<String>>> = Arc::default();
        let kept = told.clone();
        p.alert_with(Arc::new(move |m| kept.lock().unwrap().push(m.to_owned())));
        assert!(told.lock().unwrap()[0].contains("responds to no contested claim"));
        p.polled();
        let e = p.admit(&[1; 32], &[0; 32], 1, 1, 110, 100, 100);
        assert!(
            matches!(&e, Admission::Withhold(w) if w.contains("memory")),
            "{e:?}"
        );
    }

    /// A failing prover is alerted once, and tried again.
    #[test]
    fn a_prover_that_fails_is_alerted() {
        let dir = tempfile::tempdir().unwrap();
        let id = hex::encode([7u8; 32]);
        let p = fake(
            dir.path(),
            &format!(
                r#"case "$1" in
probe) echo '{{"device":"cuda","programs":["{id}"],"problems":[]}}' ;;
bench) echo '{{"device":"cuda","segment_cycles":1,"segment":1.0,"tail":1.0}}' > "$2" ;;
*) exit 3 ;;
esac
"#
            ),
        );
        let told: Arc<Mutex<Vec<String>>> = Arc::default();
        let kept = told.clone();
        p.alert_with(Arc::new(move |m| kept.lock().unwrap().push(m.to_owned())));
        until("ready", || {
            matches!(readiness(&p), Some(Readiness::Ready(_)))
        });
        p.freeze(&[1; 32], b"input", None).unwrap();
        p.commit(&[1; 32], [7; 32], 110, 100, 1, true, false, 100);
        until("alerted", || !told.lock().unwrap().is_empty());
        assert!(told.lock().unwrap()[0].contains("the prover failed"));
        assert_eq!(p.proof(&[1; 32], &[7; 32]).unwrap(), None);
    }
}
