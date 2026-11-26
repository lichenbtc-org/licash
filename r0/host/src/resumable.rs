//! A succinct proof carried on across runs, a segment at a time. Each
//! segment, proved and lifted, is kept in a work directory, and so is the
//! join of those before it: a run stopped anywhere (killed, out of memory,
//! the phone restarted) carries on where it stopped when run again. The
//! segments wait on disk, not in memory, one at a time in memory proved.
//!
//! The same proof as [`risc0_zkvm::Prover::prove_with_opts`] with
//! [`risc0_zkvm::ProverOpts::succinct`]: lift each segment's receipt, join
//! them in order, then resolve each assumption the guest made (a receipt of
//! another program it verified, `env::verify`) with the succinct receipt the
//! host gave for it, as `composite_to_succinct` does.
//!
//! Other machines may prove segments too ([`crate::fanout`]): each a run of
//! them, joined, kept here as a range (`range-<from>-<to>`) beside the
//! segments this one lifted, and joined with them in order. What they
//! return is verified as it arrives and the whole receipt at the end, as
//! ever: a range that does not fit is set aside and its segments proved
//! here.

use std::collections::BTreeMap;
use std::fs::{create_dir_all, read, read_to_string, remove_dir_all, remove_file, rename, write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::sha::{Digestible, Impl, Sha256};
use risc0_zkvm::{
    compute_image_id, get_prover_server, AssumptionReceipt, ExecutorImpl, InnerAssumptionReceipt,
    InnerReceipt, MaybePruned, Output, ProverOpts, ProverServer, Receipt, ReceiptClaim, Segment,
    SegmentRef, SuccinctReceipt, VerifierContext,
};

type Lifted = SuccinctReceipt<ReceiptClaim>;

/// A segment written to the work directory, read back to be proved.
struct OnDisk(PathBuf);

impl SegmentRef for OnDisk {
    fn resolve(&self) -> Result<Segment> {
        let bytes = read(&self.0).with_context(|| format!("{}", self.0.display()))?;
        Ok(bincode::deserialize(&bytes)?)
    }
}

/// What the execution the work directory proves made, kept once all its
/// segments are: their number, the journal and the user cycles. The
/// guest's execution is not the same each run (the random bytes it is
/// handed differ), so the segments of one only are joined: never
/// executed again once kept.
struct Executed {
    segments: usize,
    journal: Vec<u8>,
    user_cycles: u64,
}

/// The assumptions the guest made, with the receipts that prove them,
/// kept beside `executed` (written before it, so an `executed` whose
/// assumptions are missing is never carried on). A work directory
/// without the file is one of a guest with none, as every one was before
/// this prover resolved any.
fn assumptions_path(dir: &Path) -> PathBuf {
    dir.join("assumptions")
}

type Made = Vec<(risc0_zkvm::Assumption, AssumptionReceipt)>;

fn kept_assumptions(dir: &Path) -> Result<Made> {
    match read(assumptions_path(dir)) {
        Ok(bytes) => Ok(bincode::deserialize(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// The succinct receipt that proves `assumption`, as `resolve` takes it. A
/// proof that is not succinct is refused: it is the only kind the
/// recursion resolves.
fn proving(
    assumption: &AssumptionReceipt,
) -> Result<risc0_zkvm::SuccinctReceipt<risc0_zkvm::Unknown>> {
    match assumption {
        AssumptionReceipt::Proven(InnerAssumptionReceipt::Succinct(s)) => Ok(s.clone()),
        AssumptionReceipt::Proven(_) => {
            bail!("an assumption is proven by a succinct receipt alone")
        }
        AssumptionReceipt::Unresolved(a) => {
            bail!("no receipt was given for the assumption {:?}", a.claim)
        }
    }
}

/// `bytes` to `path` whole or not at all.
pub fn keep(path: &Path, bytes: &[u8]) -> Result<()> {
    let part = path.with_extension("part");
    write(&part, bytes)?;
    std::fs::File::open(&part)?.sync_all()?;
    rename(&part, path)?;
    Ok(())
}

/// What the work directory proves: refused if it was another proof's.
fn claim_dir(
    dir: &Path,
    image: &str,
    input: &[u8],
    assumptions: &[Receipt],
    po2: Option<u32>,
) -> Result<()> {
    create_dir_all(dir)?;
    let mut what = format!(
        "image {image}\ninput {}\npo2 {}\n",
        hex::encode(Impl::hash_bytes(input).as_bytes()),
        po2.map_or("default".into(), |p| p.to_string())
    );
    // The receipts it assumes are part of what it proves, by the claim each
    // makes (its program and its journal); none adds no line, so a directory of
    // a proof without any is as it was.
    for receipt in assumptions {
        let claim = receipt.claim().context("an assumed receipt's claim")?;
        what.push_str(&format!("assumes {}\n", claim.digest()));
    }
    let meta = dir.join("proving");
    match read_to_string(&meta) {
        Ok(had) => ensure!(
            had == what,
            "{} holds another proof's work (its program, input or segment size): \
             use another directory",
            dir.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => keep(&meta, what.as_bytes())?,
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn lifted_path(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("lifted-{i:05}"))
}

pub(crate) fn segment_path(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("segment-{i:05}"))
}

/// Where the join of the segments `from..to` is kept, proved by another
/// machine.
pub(crate) fn range_path(dir: &Path, from: usize, to: usize) -> PathBuf {
    dir.join(format!("range-{from:05}-{to:05}"))
}

/// The ranges kept in `dir`: the first segment of each, with the one after
/// its last.
pub(crate) fn ranges(dir: &Path) -> Result<BTreeMap<usize, usize>> {
    let mut kept = BTreeMap::new();
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let bounds = name
            .to_str()
            .and_then(|n| n.strip_prefix("range-"))
            .and_then(|n| n.split_once('-'));
        // A range half written (`.part`) is none.
        if let Some((Ok(from), Ok(to))) = bounds.map(|(f, t)| (f.parse(), t.parse())) {
            kept.insert(from, to);
        }
    }
    Ok(kept)
}

/// Whether one of `ranges` holds segment `i`.
fn within(ranges: &BTreeMap<usize, usize>, i: usize) -> bool {
    ranges
        .range(..=i)
        .next_back()
        .is_some_and(|(_, to)| i < *to)
}

/// The work of `dir` but what says what it proves: that of an execution
/// cut short, or of another.
fn forget(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let work = [
            "segment-",
            "lifted-",
            "range-",
            "joined",
            "resolved",
            "assumptions",
            "executed",
            "receipt",
        ];
        if work.iter().any(|w| name.starts_with(w)) {
            remove_file(&path)?;
        }
        // What another machine was proving of it ([`crate::fanout`]).
        if name.starts_with("job-") {
            remove_dir_all(&path)?;
        }
    }
    Ok(())
}

/// Execute `bin` on `input` in `dir`, every segment written there, then
/// what it made: refused unless its journal is `expected`.
fn execute(
    bin: &[u8],
    name: &str,
    input: &[u8],
    assumptions: &[Receipt],
    expected: &[u8],
    dir: &Path,
    po2: Option<u32>,
) -> Result<Executed> {
    let start = Instant::now();
    forget(dir)?;
    let session = ExecutorImpl::from_elf(super::env_with(input, po2, assumptions)?, bin)?
        .run_with_callback(|segment| -> Result<Box<dyn SegmentRef>> {
            let path = segment_path(dir, segment.index as usize);
            keep(&path, &bincode::serialize(&segment)?)?;
            Ok(Box::new(OnDisk(path)))
        })?;
    let journal = session.journal.clone().unwrap_or_default().bytes;
    ensure!(journal == expected, "journal");
    ensure!(
        session.mmr_assumptions.is_empty(),
        "{name} makes assumptions of a kind this prover does not resolve"
    );
    // Every assumption must have been proven by the host: one left
    // unresolved would stay in the receipt's claim.
    for (_, receipt) in &session.assumptions {
        proving(receipt)?;
    }
    keep(
        &assumptions_path(dir),
        &bincode::serialize(&session.assumptions)?,
    )?;
    let executed = Executed {
        segments: session.segments.len(),
        journal,
        user_cycles: session.user_cycles,
    };
    let kept = (executed.segments, &executed.journal, executed.user_cycles);
    keep(&dir.join("executed"), &bincode::serialize(&kept)?)?;
    println!(
        "{name}: executed in {:.1} s, {} user cycles, {} segments; work in {}",
        start.elapsed().as_secs_f64(),
        executed.user_cycles,
        executed.segments,
        dir.display()
    );
    Ok(executed)
}

/// What the execution kept in `dir` made, if one was.
fn kept_execution(dir: &Path) -> Result<Option<Executed>> {
    match read(dir.join("executed")) {
        Ok(bytes) => {
            let (segments, journal, user_cycles) = bincode::deserialize(&bytes)?;
            Ok(Some(Executed {
                segments,
                journal,
                user_cycles,
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// What the execution kept in `dir` made, if one was and each of its
/// segments is there: lifted, in a range, or to prove.
fn executed(dir: &Path) -> Result<Option<Executed>> {
    let Some(executed) = kept_execution(dir)? else {
        return Ok(None);
    };
    let ranges = ranges(dir)?;
    let whole = (0..executed.segments).all(|i| {
        lifted_path(dir, i).exists() || within(&ranges, i) || segment_path(dir, i).exists()
    });
    Ok(whole.then_some(executed))
}

fn rss() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .map(|l| l.split_whitespace().nth(1).unwrap_or("?").to_string())
            .unwrap_or_else(|| "?".into())
    };
    format!("rss {} kB, peak {} kB", field("VmRSS:"), field("VmHWM:"))
}

/// Prove `bin` on `input`, its journal `expected`, in segments of 2^`po2`
/// cycles, carrying on the work kept in `dir`: the verified succinct
/// receipt, also written to `dir/receipt`. The guest may verify the receipts
/// `assumptions` (of other programs, each the succinct receipt of an
/// unconditional proof): the proof is unconditional once each is resolved,
/// before it is wrapped.
pub fn prove(
    bin: &[u8],
    name: &str,
    input: &[u8],
    assumptions: &[Receipt],
    expected: &[u8],
    dir: &Path,
    po2: Option<u32>,
) -> Result<Receipt> {
    let id = compute_image_id(bin)?;
    claim_dir(dir, &id.to_string(), input, assumptions, po2)?;
    let start = Instant::now();
    let executed = match executed(dir)? {
        Some(executed) => {
            let lifted = (0..executed.segments).filter(|i| lifted_path(dir, *i).exists());
            println!(
                "{name}: carried on, {} of {} segments lifted already; work in {}",
                lifted.count(),
                executed.segments,
                dir.display()
            );
            executed
        }
        None => execute(bin, name, input, assumptions, expected, dir, po2)?,
    };
    ensure!(executed.journal == expected, "journal");
    let n = executed.segments;
    let made = kept_assumptions(dir)?;

    let prover = get_prover_server(&ProverOpts::succinct())?;
    let ctx = VerifierContext::default();
    let mut proved = 0;
    let mut here = |i: usize| -> Result<()> {
        let t = Instant::now();
        let up = lift(prover.as_ref(), &ctx, dir, i, n, &made, &executed.journal)?;
        keep(&lifted_path(dir, i), &bincode::serialize(&up)?)?;
        let _ = remove_file(segment_path(dir, i));
        proved += 1;
        println!(
            "{name}: segment {}/{n} proved and lifted in {:.1} s ({})",
            i + 1,
            t.elapsed().as_secs_f64(),
            rss()
        );
        Ok(())
    };
    // The segments neither lifted here nor in a range another machine
    // proved.
    let pending = || -> Result<Vec<usize>> {
        let ranges = ranges(dir)?;
        Ok((0..n)
            .filter(|i| !lifted_path(dir, *i).exists() && !within(&ranges, *i))
            .collect())
    };
    // What another machine proved is kept only where it fits. A range that
    // verifies and is not of the segments it was asked for (its proof
    // stands, of something else) is set aside before anything is joined
    // with it, and its segments, still kept, are proved here.
    let set_aside = |ranges: &[(usize, usize)]| -> Result<()> {
        for (from, to) in ranges {
            println!("{name}: the range {from}..{to} is set aside, its segments proved here");
            remove_file(range_path(dir, *from, *to))?;
        }
        for joined in ["joined", "resolved"] {
            match remove_file(dir.join(joined)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    };
    let mut workers = crate::fanout::workers()?;
    loop {
        crate::fanout::run(dir, &pending()?, &workers, &accept, &mut here)?;
        let misfits = misfits(dir, n, id)?;
        if misfits.is_empty() {
            break;
        }
        set_aside(&misfits)?;
        workers.clear();
    }
    let mut acc = finish(prover.as_ref(), name, dir, n, &made, &executed.journal)?;
    if let Err(e) = acc.verify(id) {
        // Not this machine's proving alone: once more without what the
        // others proved, whatever it is that does not hold of it.
        let kept: Vec<_> = ranges(dir)?.into_iter().collect();
        if kept.is_empty() {
            return Err(e).context("the joined receipt");
        }
        println!("{name}: the joined receipt does not verify: {e}");
        set_aside(&kept)?;
        crate::fanout::run(dir, &pending()?, &[], &accept, &mut here)?;
        acc = finish(prover.as_ref(), name, dir, n, &made, &executed.journal)?;
        acc.verify(id).context("the joined receipt")?;
    }
    let out = dir.join("receipt");
    keep(&out, &bincode::serialize(&acc)?)?;
    println!(
        "{name}: succinct receipt, {proved} of {n} segments proved this run, in {:.1} s ({}); \
         written {}",
        start.elapsed().as_secs_f64(),
        rss(),
        out.display()
    );
    Ok(acc)
}

/// Segment `i` of the `n` kept in `dir`, proved and lifted, the execution's
/// `journal` and the assumptions it `made` in the last one's claim.
fn lift(
    prover: &dyn ProverServer,
    ctx: &VerifierContext,
    dir: &Path,
    i: usize,
    n: usize,
    made: &Made,
    journal: &[u8],
) -> Result<Lifted> {
    let segment = OnDisk(segment_path(dir, i)).resolve()?;
    let mut receipt = prover.prove_segment(ctx, &segment)?;
    drop(segment);
    // The last segment's claim carries the journal's digest and the
    // assumptions the guest made, which the recursion resolves one by
    // one: as `prove_session` merges them in, before the lift.
    if i + 1 == n && !made.is_empty() {
        let output = Output {
            journal: MaybePruned::Pruned(journal.to_vec().digest()),
            assumptions: made
                .iter()
                .map(|(assumption, _)| assumption.clone())
                .collect::<Vec<_>>()
                .into(),
        };
        // `merge_with` is the zkVM's own, and private to it: the output
        // replaces the segment's pruned one only if it is the same
        // output, by digest.
        let output: MaybePruned<Option<Output>> = Some(output).into();
        ensure!(
            output.digest() == receipt.claim.output.digest(),
            "the final segment's output is not the journal and assumptions the execution made"
        );
        receipt.claim.output = output;
    }
    prover.lift(&receipt)
}

/// A range as another machine returned it ([`crate::fanout`]): a succinct
/// receipt that verifies, of a claim that can be read. Whether it is of
/// the segments it was asked for is seen as it is joined ([`follows`]) and
/// by the whole receipt.
fn accept(bytes: &[u8]) -> Result<()> {
    let range: Lifted = bincode::deserialize(bytes).context("not a succinct receipt")?;
    range
        .verify_integrity_with_context(&VerifierContext::default())
        .context("its receipt does not verify")?;
    range
        .claim
        .as_value()
        .map_err(|e| anyhow::anyhow!("its claim: {e}"))?;
    Ok(())
}

/// The states a part starts and ends in, by their digests.
fn states(part: &Lifted) -> Result<(risc0_zkvm::sha::Digest, risc0_zkvm::sha::Digest)> {
    let claim = part
        .claim
        .as_value()
        .map_err(|e| anyhow::anyhow!("a part's claim: {e}"))?;
    Ok((claim.pre.digest(), claim.post.digest()))
}

/// Whether `part` carries on from where `before` stopped: the state it
/// starts in is the one `before` ends in.
fn follows(before: &Lifted, part: &Lifted) -> Result<bool> {
    Ok(states(before)?.1 == states(part)?.0)
}

/// A part to join: the range it is, if one, and the states it starts and
/// ends in.
type Part = (
    Option<(usize, usize)>,
    (risc0_zkvm::sha::Digest, risc0_zkvm::sha::Digest),
);

/// The ranges at a join that does not hold, of `parts` in order: a
/// part must start in the state the one before it ends in, the first in
/// `start`. Either side of such a join may be the one that is not what it
/// should be, so both are named, if ranges: a segment lifted here is what
/// it is.
fn unfit(parts: &[Part], start: risc0_zkvm::sha::Digest) -> Vec<(usize, usize)> {
    let mut unfit = Vec::new();
    let mut before: Option<&Part> = None;
    for part in parts {
        let expected = before.map_or(start, |(_, (_, post))| *post);
        if part.1 .0 != expected {
            for range in [before.and_then(|b| b.0), part.0].into_iter().flatten() {
                if !unfit.contains(&range) {
                    unfit.push(range);
                }
            }
        }
        before = Some(part);
    }
    unfit
}

/// The ranges kept in `dir` that do not fit where they are to be joined
/// ([`unfit`]), each of the `n` segments lifted or in a range: the program
/// `id`'s execution starts in the state `id` is the digest of.
fn misfits(dir: &Path, n: usize, id: risc0_zkvm::sha::Digest) -> Result<Vec<(usize, usize)>> {
    let ranges = ranges(dir)?;
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    let mut at = 0;
    while at < n {
        let (range, path) = match ranges.get(&at) {
            Some(to) => (Some((at, *to)), range_path(dir, at, *to)),
            None => (None, lifted_path(dir, at)),
        };
        let part: Lifted = bincode::deserialize(&read(&path)?)?;
        parts.push((range, states(&part)?));
        at = range.map_or(at + 1, |(_, to)| to);
    }
    Ok(unfit(&parts, id))
}

/// The succinct receipt of the `n` segments proved in `dir`, each lifted
/// or in a range: joined in order, each assumption resolved, of `journal`.
/// To verify.
fn finish(
    prover: &dyn ProverServer,
    name: &str,
    dir: &Path,
    n: usize,
    made: &Made,
    journal: &[u8],
) -> Result<Receipt> {
    // Joined in order, the running join kept after each: a segment lifted
    // here, or the range another machine proved from it on.
    let joined_path = dir.join("joined");
    let load = |path: &Path| -> Result<Lifted> { Ok(bincode::deserialize(&read(path)?)?) };
    let ranges = ranges(dir)?;
    let part = |from: usize| match ranges.get(&from) {
        Some(to) => (range_path(dir, from, *to), *to),
        None => (lifted_path(dir, from), from + 1),
    };
    let (mut through, mut acc): (usize, Lifted) = match read(&joined_path) {
        Ok(bytes) => bincode::deserialize(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (first, to) = part(0);
            (to - 1, load(&first)?)
        }
        Err(e) => return Err(e.into()),
    };
    while through + 1 < n {
        let t = Instant::now();
        let (path, to) = part(through + 1);
        let next = load(&path)?;
        ensure!(
            follows(&acc, &next)?,
            "{} does not carry on from the segments before it",
            path.display()
        );
        acc = prover.join(&acc, &next)?;
        through = to - 1;
        keep(&joined_path, &bincode::serialize(&(through, &acc))?)?;
        println!(
            "{name}: joined {}/{n} in {:.1} s ({})",
            through + 1,
            t.elapsed().as_secs_f64(),
            rss()
        );
    }

    // Each assumption resolved in the order the guest made them, the
    // running result kept after each: a succinct receipt per assumption, one
    // recursion proof each.
    let resolved_path = dir.join("resolved");
    let (mut done, mut acc): (usize, Lifted) = match read(&resolved_path) {
        Ok(bytes) => bincode::deserialize(&bytes)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, acc),
        Err(e) => return Err(e.into()),
    };
    while done < made.len() {
        let t = Instant::now();
        acc = prover.resolve(&acc, &proving(&made[done].1)?)?;
        done += 1;
        keep(&resolved_path, &bincode::serialize(&(done, &acc))?)?;
        println!(
            "{name}: assumption {done}/{} resolved in {:.1} s ({})",
            made.len(),
            t.elapsed().as_secs_f64(),
            rss()
        );
    }

    Ok(Receipt::new(InnerReceipt::Succinct(acc), journal.to_vec()))
}

/// A job of [`crate::fanout`], on the machine it was handed to: the
/// segments `from..to` kept in `dir` with what their execution made
/// (`executed`, `assumptions`), each proved and lifted, then joined, their
/// join kept as `dir/range`. Run again after a stop, it proves only the
/// segments it had not lifted.
pub fn prove_range(dir: &Path, from: usize, to: usize) -> Result<()> {
    let executed = kept_execution(dir)?.context("the job says nothing of its execution")?;
    ensure!(
        from < to && to <= executed.segments,
        "segments {from}..{to} of {}",
        executed.segments
    );
    let made = kept_assumptions(dir)?;
    let prover = get_prover_server(&ProverOpts::succinct())?;
    let ctx = VerifierContext::default();
    let start = Instant::now();
    let mut acc: Option<Lifted> = None;
    for i in from..to {
        let path = lifted_path(dir, i);
        let up = match read(&path) {
            Ok(bytes) => bincode::deserialize(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let t = Instant::now();
                let n = executed.segments;
                let up = lift(prover.as_ref(), &ctx, dir, i, n, &made, &executed.journal)?;
                keep(&path, &bincode::serialize(&up)?)?;
                // Said as it goes: a job no one waits for any more stops
                // at the next, its output closed.
                println!(
                    "range: segment {}/{n} proved and lifted in {:.1} s ({})",
                    i + 1,
                    t.elapsed().as_secs_f64(),
                    rss()
                );
                up
            }
            Err(e) => return Err(e.into()),
        };
        acc = Some(match acc {
            None => up,
            Some(before) => prover.join(&before, &up)?,
        });
    }
    let range = acc.context("a range of no segment")?;
    keep(&dir.join("range"), &bincode::serialize(&range)?)?;
    println!(
        "range: segments {from}..{to} proved and joined in {:.1} s ({})",
        start.elapsed().as_secs_f64(),
        rss()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_work_directory_is_one_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        claim_dir(&work, "program", b"input", &[], Some(18)).unwrap();
        // The same proof carries on.
        claim_dir(&work, "program", b"input", &[], Some(18)).unwrap();
        for (image, input, po2) in [
            ("program", &b"input"[..], Some(19)),
            ("program", b"input", None),
            ("program", b"other", Some(18)),
            ("other", b"input", Some(18)),
        ] {
            let e = claim_dir(&work, image, input, &[], po2).unwrap_err();
            assert!(format!("{e}").contains("another proof's work"), "{e}");
        }
    }

    #[test]
    fn an_execution_is_carried_on_only_whole() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path();
        assert!(executed(work).unwrap().is_none());
        let kept = (3usize, vec![1u8, 2], 99u64);
        keep(&work.join("executed"), &bincode::serialize(&kept).unwrap()).unwrap();
        keep(&lifted_path(work, 0), b"lifted").unwrap();
        keep(&segment_path(work, 2), b"segment").unwrap();
        // Segment 1 neither lifted nor kept: executed again.
        assert!(executed(work).unwrap().is_none());
        keep(&segment_path(work, 1), b"segment").unwrap();
        let carried = executed(work).unwrap().unwrap();
        assert_eq!(
            (carried.segments, carried.journal, carried.user_cycles),
            (3, vec![1, 2], 99)
        );
        // Forgotten but what it proves.
        keep(&work.join("proving"), b"image").unwrap();
        keep(&work.join("joined"), b"joined").unwrap();
        forget(work).unwrap();
        let left: Vec<_> = std::fs::read_dir(work)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["proving"]);
    }

    fn assumed(journal: &[u8]) -> Receipt {
        let claim = ReceiptClaim::ok(risc0_zkvm::sha::Digest::ZERO, journal.to_vec());
        Receipt::new(
            InnerReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim)),
            journal.to_vec(),
        )
    }

    #[test]
    fn a_work_directory_is_the_proof_of_what_it_assumes() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        let (a, b) = (assumed(b"one"), assumed(b"two"));
        claim_dir(
            &work,
            "program",
            b"input",
            std::slice::from_ref(&a),
            Some(18),
        )
        .unwrap();
        claim_dir(
            &work,
            "program",
            b"input",
            std::slice::from_ref(&a),
            Some(18),
        )
        .unwrap();
        // another receipt assumed, or none, or more, is another proof
        for other in [vec![b.clone()], vec![], vec![a.clone(), b]] {
            let e = claim_dir(&work, "program", b"input", &other, Some(18)).unwrap_err();
            assert!(format!("{e}").contains("another proof's work"), "{e}");
        }
    }

    #[test]
    fn a_directory_without_assumptions_is_of_a_guest_that_made_none() {
        let dir = tempfile::tempdir().unwrap();
        // work kept before this prover resolved any carries on as it did
        assert!(kept_assumptions(dir.path()).unwrap().is_empty());
        keep(
            &assumptions_path(dir.path()),
            &bincode::serialize(&Made::new()).unwrap(),
        )
        .unwrap();
        assert!(kept_assumptions(dir.path()).unwrap().is_empty());
        // and the assumptions and their resolution are the work forgotten with the rest
        keep(&dir.path().join("resolved"), b"resolved").unwrap();
        keep(&dir.path().join("proving"), b"image").unwrap();
        forget(dir.path()).unwrap();
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["proving"]);
    }

    #[test]
    fn an_assumption_is_resolved_by_a_succinct_receipt_alone() {
        use risc0_zkvm::Assumption;
        let claim = Assumption {
            claim: risc0_zkvm::sha::Digest::ZERO,
            control_root: risc0_zkvm::sha::Digest::ZERO,
        };
        let e = proving(&AssumptionReceipt::Unresolved(claim)).unwrap_err();
        assert!(format!("{e}").contains("no receipt was given"), "{e}");
        let claim = MaybePruned::<risc0_zkvm::Unknown>::Pruned(risc0_zkvm::sha::Digest::ZERO);
        let fake = InnerAssumptionReceipt::Fake(risc0_zkvm::FakeReceipt::new(claim));
        let e = proving(&AssumptionReceipt::Proven(fake)).unwrap_err();
        assert!(format!("{e}").contains("succinct receipt alone"), "{e}");
    }

    #[test]
    fn a_range_another_machine_proved_holds_its_segments() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path();
        let kept = (6usize, vec![1u8, 2], 99u64);
        keep(&work.join("executed"), &bincode::serialize(&kept).unwrap()).unwrap();
        keep(&lifted_path(work, 0), b"lifted").unwrap();
        keep(&range_path(work, 1, 4), b"range").unwrap();
        keep(&segment_path(work, 5), b"segment").unwrap();
        assert_eq!(ranges(work).unwrap(), BTreeMap::from([(1, 4)]));
        // Segment 4 neither lifted, in a range, nor kept: executed again.
        assert!(executed(work).unwrap().is_none());
        keep(&segment_path(work, 4), b"segment").unwrap();
        assert_eq!(executed(work).unwrap().unwrap().segments, 6);
        // A range half written is none.
        write(work.join("range-00004-00006.part"), b"half").unwrap();
        assert_eq!(ranges(work).unwrap(), BTreeMap::from([(1, 4)]));
        let held = ranges(work).unwrap();
        let within: Vec<usize> = (0..6).filter(|i| within(&held, *i)).collect();
        assert_eq!(within, [1, 2, 3]);
        // Forgotten with the rest, and the jobs handed out.
        create_dir_all(work.join("job-00004-00006")).unwrap();
        write(work.join("job-00004-00006/segment-00004"), b"segment").unwrap();
        keep(&work.join("proving"), b"image").unwrap();
        forget(work).unwrap();
        let left: Vec<_> = std::fs::read_dir(work)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["proving"]);
    }

    #[test]
    fn a_range_that_does_not_fit_its_neighbours_is_named() {
        let state = |b: u8| risc0_zkvm::sha::Digest::from([b; 32]);
        let lifted = |pre, post| (None, (state(pre), state(post)));
        let range = |from, to, pre, post| (Some((from, to)), (state(pre), state(post)));
        let none: Vec<(usize, usize)> = Vec::new();
        // Each starts where the one before ends, the first where the
        // program does.
        let fit = [
            range(0, 2, 0, 2),
            lifted(2, 3),
            range(3, 5, 3, 5),
            lifted(5, 6),
        ];
        assert_eq!(unfit(&fit, state(0)), none);
        // A range of other segments, between segments lifted here: it alone.
        let other = [lifted(0, 1), range(1, 3, 7, 9), lifted(3, 4)];
        assert_eq!(unfit(&other, state(0)), [(1, 3)]);
        // One that stops short: the join after it does not hold, and the
        // range after it may as well be the one that is not what it says.
        let short = [range(0, 2, 0, 1), range(2, 4, 2, 4), lifted(4, 5)];
        assert_eq!(unfit(&short, state(0)), [(0, 2), (2, 4)]);
        // The first of another execution.
        let first = [range(0, 2, 8, 2), lifted(2, 3)];
        assert_eq!(unfit(&first, state(0)), [(0, 2)]);
        // Segments lifted here that do not carry on are no range's fault:
        // the join says so.
        assert_eq!(unfit(&[lifted(0, 1), lifted(5, 6)], state(0)), none);
    }

    #[test]
    fn a_range_is_accepted_only_if_it_is_a_receipt() {
        let e = accept(b"not a receipt").unwrap_err();
        assert!(format!("{e:#}").contains("not a succinct receipt"), "{e:#}");
        assert!(accept(&[]).is_err());
    }

    #[test]
    fn kept_files_are_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lifted-00000");
        keep(&path, b"one").unwrap();
        keep(&path, b"two").unwrap();
        assert_eq!(read(&path).unwrap(), b"two");
        assert!(!path.with_extension("part").exists());
    }
}
