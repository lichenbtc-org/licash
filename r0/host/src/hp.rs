//! The Hub's statement guest (`r0/hp-guest`) on exported inputs
//! (`licash_hp::HubInput::to_bytes`): execute, or prove and export the
//! Groth16 seal the holder's garbling opens to. Each command also runs
//! `licash_hp::check` natively, and a guest that disagrees with it is an
//! error.
//!
//! A proof is made in a work directory, a stage at a time, each kept
//! there: the succinct receipt (itself a segment at a time,
//! [`crate::resumable`]), its `identity_p254` seal, the Groth16 wrap
//! ([`crate::groth16`]), the export. Run again after any stop, it carries
//! on where it stopped.

use std::fs::{create_dir_all, read, remove_dir_all};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use licash_hp::HubInput;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    compute_image_id, default_executor, get_prover_server, Groth16Receipt,
    Groth16ReceiptVerifierParameters, InnerReceipt, ProverOpts, Receipt,
};

use crate::probe;
use crate::resumable::keep;

const NAME: &str = "hp";

/// Segment sizes on a GPU, the largest first: 2^18 cycles takes about 3 GB
/// of its memory, 2^17 half that.
pub const GPU_PO2: [u32; 2] = [18, 17];

/// The segment size on a CPU: 2^19 cycles takes about 4.6 GB of memory,
/// and is faster than 2^18.
pub const CPU_PO2: u32 = 19;

/// The journal the library computes for this input, or its refusal. Of a
/// chained contract's input, with the chain program its own receipt's journal
/// names: the guest is built with one id, and refuses an input whose receipt
/// is of another, which the library does not (so `hp-exec` says so).
pub(crate) fn expected(bytes: &[u8]) -> Result<Vec<u8>> {
    let input = HubInput::from_bytes(bytes)?;
    match &input.chain {
        None => Ok(licash_hp::check(&input)?.to_vec()),
        Some(chain) => {
            let id = *chain
                .journal
                .first_chunk::<32>()
                .context("the chain's journal")?;
            let program = licash_hp::Program {
                id,
                verify: &|_, _| {},
            };
            Ok(licash_hp::check_on(&input, &program)?.to_vec())
        }
    }
}

/// The receipts the guest may verify, read from `paths`.
pub fn receipts(paths: &[String]) -> Result<Vec<Receipt>> {
    paths
        .iter()
        .map(|path| {
            let bytes = read(path).with_context(|| format!("the receipt {path}"))?;
            bincode::deserialize(&bytes).with_context(|| format!("the receipt {path}"))
        })
        .collect()
}

pub fn exec(path: &str, program: Option<&str>, assume: &[String]) -> Result<()> {
    let bytes = read(path)?;
    let bin = probe::program(program)?;
    let expected = expected(&bytes);
    let t = Instant::now();
    let env = super::env_with(&bytes, super::segment_override()?, &receipts(assume)?)?;
    let run = default_executor().execute(env, &bin);
    let ms = t.elapsed().as_millis();
    match (run, expected) {
        (Ok(s), Ok(j)) => {
            ensure!(
                s.journal.bytes == j,
                "the guest's journal differs from the library's"
            );
            let cycles: u64 = s.segments.iter().map(|g| g.cycles as u64).sum();
            println!(
                "{NAME}: journal {}, {} input bytes, {cycles} cycles, {} segments, {ms} ms",
                hex::encode(&j),
                bytes.len(),
                s.segments.len()
            );
        }
        (Err(g), Err(e)) => {
            // Refused once read, not for want of reading it.
            let why = format!("{g:#}");
            ensure!(
                why.contains(crate::reads::REFUSED),
                "the guest does not read what the library reads: {why}"
            );
            println!("{NAME}: no proof, as the library refuses: {e}")
        }
        (Ok(_), Err(e)) => bail!("the guest proved what the library refuses: {e}"),
        (Err(e), Ok(_)) => bail!("the guest refused what the library proves: {e}"),
    }
    Ok(())
}

/// Prove the input at `path` with `program` in `work`, and export the
/// proof to `work/proof.json`: on the GPU through the CUDA build if one is
/// usable (a smaller segment size if the larger fails), else on the CPU.
/// The Groth16 wrap runs on the CPU either way. `assume` are the receipts of
/// other programs the guest verifies, each resolved before the wrap.
pub fn prove(path: &str, work: &Path, program: Option<&str>, assume: &[String]) -> Result<()> {
    let bytes = read(path)?;
    let bin = probe::program(program)?;
    let expected = expected(&bytes)?;
    create_dir_all(work)?;
    let out = work.join("proof.json");
    if out.exists() {
        // Kept from a run on this input and program, or none to take.
        super::check_export(&bin, &expected, &read(&out)?).with_context(|| {
            format!(
                "{}: remove the work directory to prove again",
                out.display()
            )
        })?;
        println!("{NAME}: proven already: {}", out.display());
        return Ok(());
    }
    let start = Instant::now();
    if !work.join("p254").exists() {
        let receipts = receipts(assume)?;
        on_device("hp-stark", path, work, program, assume, |po2| {
            stark(&bin, &bytes, &receipts, &expected, work, po2)
        })?;
    }
    let succinct: Receipt = bincode::deserialize(&read(work.join("receipt"))?)?;
    let claim = succinct
        .inner
        .succinct()
        .context("a succinct receipt")?
        .claim
        .clone();
    let p254 = read(work.join("p254"))?;
    let seal = crate::groth16::wrap(&probe::groth16_dir(), &p254, &work.join("groth16"))?;
    let groth16 = Groth16Receipt::new(
        seal.to_vec(),
        claim,
        Groth16ReceiptVerifierParameters::default().digest(),
    );
    let receipt = Receipt::new(InnerReceipt::Groth16(groth16), succinct.journal.bytes);
    keep(&out, &super::export(&bin, &receipt, &expected)?)?;
    let _ = remove_dir_all(work.join("groth16"));
    println!(
        "{NAME}: verified and exported {} ({:.1} s this run)",
        out.display(),
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

/// `cpu` at the CPU's segment size (a GPU's largest if other machines prove
/// segments too, [`crate::fanout`]: theirs are GPUs), or, if a CUDA build is beside this one
/// and a GPU usable, that build's `command` (`hp-stark`, `chain-stark`) on
/// `path` and `work`, at the largest segment size that fits (a smaller one if
/// it fails, each attempt a process of its own).
pub fn on_device(
    command: &str,
    path: &str,
    work: &Path,
    program: Option<&str>,
    assume: &[String],
    cpu: impl FnOnce(u32) -> Result<()>,
) -> Result<()> {
    let Some(cuda) = probe::cuda_build().filter(|_| probe::gpu_usable()) else {
        let po2 = match crate::fanout::workers()?.is_empty() {
            true => CPU_PO2,
            false => GPU_PO2[0],
        };
        return cpu(super::segment_override()?.unwrap_or(po2));
    };
    let sizes = super::segment_override()?.map_or(GPU_PO2.to_vec(), |p| vec![p]);
    let mut failed = None;
    for po2 in sizes {
        let mut run = Command::new(&cuda);
        run.arg(command).arg(path).arg(work).arg(po2.to_string());
        run.args(program);
        for receipt in assume {
            run.arg("--assume").arg(receipt);
        }
        let status = run.status().context("run the CUDA prover")?;
        if status.success() {
            return Ok(());
        }
        println!("{NAME}: the GPU failed at segments of 2^{po2}: {status}");
        failed = Some(status);
    }
    match failed {
        Some(status) => bail!("the GPU prover failed: {status}"),
        None => Ok(()),
    }
}

/// The succinct receipt of `bin` on `bytes` (verifying `assumptions`) in
/// segments of 2^`po2`, kept as `work/receipt`, then its `identity_p254`
/// seal, kept as `work/p254`, on this build's device.
pub fn stark(
    bin: &[u8],
    bytes: &[u8],
    assumptions: &[Receipt],
    expected: &[u8],
    work: &Path,
    po2: u32,
) -> Result<()> {
    let succinct = succinct(NAME, bin, bytes, assumptions, expected, work, po2)?;
    let t = Instant::now();
    let inner = succinct.inner.succinct().context("a succinct receipt")?;
    let ident = get_prover_server(&ProverOpts::succinct())?.identity_p254(inner)?;
    keep(&work.join("p254"), &ident.get_seal_bytes())?;
    println!(
        "{NAME}: identity_p254 in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The succinct receipt of `bin` on `bytes` that `work/receipt` keeps, made
/// (resumably) if it is not there, its journal `expected`.
pub fn succinct(
    name: &str,
    bin: &[u8],
    bytes: &[u8],
    assumptions: &[Receipt],
    expected: &[u8],
    work: &Path,
    po2: u32,
) -> Result<Receipt> {
    let id = compute_image_id(bin)?;
    let kept = work.join("receipt");
    let succinct: Receipt = match read(&kept) {
        Ok(b) => bincode::deserialize(&b)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let device = if cfg!(feature = "cuda") {
                "cuda"
            } else {
                "cpu"
            };
            let dir = work.join(format!("stark-{device}-{po2}"));
            let r =
                crate::resumable::prove(bin, name, bytes, assumptions, expected, &dir, Some(po2))?;
            keep(&kept, &bincode::serialize(&r)?)?;
            // Its segments' work, and that of sizes that failed before.
            for entry in std::fs::read_dir(work)? {
                let path = entry?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with("stark-") {
                    let _ = remove_dir_all(&path);
                }
            }
            r
        }
        Err(e) => return Err(e.into()),
    };
    check_receipt(&succinct, id, expected)?;
    Ok(succinct)
}

/// `receipt`, kept in a work directory, is `id`'s and proves `expected`.
pub fn check_receipt(
    receipt: &Receipt,
    id: risc0_zkvm::sha::Digest,
    expected: &[u8],
) -> Result<()> {
    receipt.verify(id).context("the kept receipt")?;
    ensure!(receipt.journal.bytes == expected, "journal");
    Ok(())
}

/// `hp-stark`, the CUDA build's part of [`prove`].
pub fn stark_command(
    path: &str,
    work: &Path,
    po2: &str,
    program: Option<&str>,
    assume: &[String],
) -> Result<()> {
    let bytes = read(path)?;
    let bin = probe::program(program)?;
    let expected = expected(&bytes)?;
    let po2 = super::segment_limit(Some(po2))?.context("a segment size")?;
    stark(&bin, &bytes, &receipts(assume)?, &expected, work, po2)
}
