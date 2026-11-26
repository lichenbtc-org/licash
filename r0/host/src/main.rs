//! licash-r0: packs, executes and proves the Hub's statement guest
//! (`r0/hp-guest`, `licash_hp::check`).
//!
//!   licash-r0 pack <elf> <out.bin>         pack an ELF with the zkOS kernel; prints the image id
//!   licash-r0 id <program.bin>             a packed program's image id
//!   licash-r0 hp-exec <input.bin> [program]
//!                                          execute an input; prints journal and cycles
//!   licash-r0 hp-prove <input.bin> <work-dir> [program]
//!                                          prove, wrap in Groth16, verify and export to
//!                                          work-dir/proof.json, carried on across runs
//!   licash-r0 probe [program]              what this machine proves with, as JSON; with a
//!                                          program, whether it proves the benchmark's input
//!   licash-r0 hp-reads <base.bin> [program]
//!                                          whether a program reads a statement's input of a Base
//!   licash-r0 bench <out.json> [program]   how fast it proves, as JSON
//!   licash-r0 range-prove <job-dir> <from> <to>
//!                                          prove the segments of a job another machine
//!                                          hands this one (`LICASH_R0_WORKERS` there)
//!
//! A program is a packed guest's path, or an image id kept in the programs
//! directory ([`probe::share`]); by default the checkout's `r0/guests/hp.bin`
//! (built by r0/build-guest.sh).
//!
//! The export is JSON: the image id, the journal and the 256-byte Groth16
//! seal (`lichen_babe::risc0::proof_from_seal`'s input), all hex.
//!
//! Built with the `cuda` feature (as `licash-r0-cuda`), it proves on the
//! GPU. The CPU build proves through such a build beside it when it finds a
//! usable GPU, and on the CPU otherwise: one command, whichever the device.

mod bench;
mod chain;
mod fanout;
mod groth16;
mod hp;
mod probe;
mod reads;
mod resumable;

use std::fs::{read, write};

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::{compute_image_id, ExecutorEnv, Receipt};

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|c| {
            let mut w = [0u8; 4];
            w[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(w)
        })
        .collect()
}

/// The guest's environment for `input`, in segments of 2^`po2` cycles (or
/// the zkVM's default). The segment size does not change what is proven.
fn env_for(input: &[u8], po2: Option<u32>) -> Result<ExecutorEnv<'static>> {
    env_with(input, po2, &[])
}

/// [`env_for`] with the receipts `assumptions`, which the guest may
/// verify (`env::verify`) of other programs.
fn env_with(
    input: &[u8],
    po2: Option<u32>,
    assumptions: &[Receipt],
) -> Result<ExecutorEnv<'static>> {
    let mut env = ExecutorEnv::builder();
    if let Some(po2) = po2 {
        env.segment_limit_po2(po2);
    }
    for receipt in assumptions {
        env.add_assumption(receipt.clone());
    }
    // What a profile build of the guest prints (`r0/build-guest.sh hp-profile`).
    env.stdout(std::io::stdout());
    env.write(&(input.len() as u32))?.write_slice(&words(input));
    env.build()
}

/// `LICASH_SEGMENT_PO2`, a segment size for measurements, if set.
fn segment_limit(value: Option<&str>) -> Result<Option<u32>> {
    let Some(value) = value else { return Ok(None) };
    let po2 = value
        .parse::<u32>()
        .context("LICASH_SEGMENT_PO2 must be an integer")?;
    ensure!(
        (13..=20).contains(&po2),
        "LICASH_SEGMENT_PO2 must be 13..20"
    );
    Ok(Some(po2))
}

fn segment_override() -> Result<Option<u32>> {
    segment_limit(std::env::var("LICASH_SEGMENT_PO2").ok().as_deref())
}

/// The export of a Groth16 `receipt` of `bin`, verified, its journal
/// `expected`. The consumer must still compare the journal to its own
/// opening and verify the proof.
fn export(bin: &[u8], receipt: &Receipt, expected: &[u8]) -> Result<Vec<u8>> {
    let id = compute_image_id(bin)?;
    receipt.verify(id)?;
    ensure!(receipt.journal.bytes == expected, "journal");
    let groth16 = receipt
        .inner
        .groth16()
        .context("a Groth16 receipt is required")?;
    ensure!(groth16.seal.len() == 256, "a Groth16 seal is 256 bytes");
    let data = serde_json::json!({
        "image_id": id.to_string(),
        "journal": hex::encode(&receipt.journal.bytes),
        "seal": hex::encode(&groth16.seal),
    });
    Ok(serde_json::to_vec_pretty(&data)?)
}

/// That `kept`, an export of an earlier run ([`export`]), is of `bin` and
/// proves `expected`: it is never taken for the proof of another input.
fn check_export(bin: &[u8], expected: &[u8], kept: &[u8]) -> Result<()> {
    let kept: serde_json::Value = serde_json::from_slice(kept).context("the kept proof")?;
    ensure!(
        kept["image_id"].as_str() == Some(&compute_image_id(bin)?.to_string()),
        "the kept proof is of another program"
    );
    ensure!(
        kept["journal"].as_str() == Some(&hex::encode(expected)),
        "the kept proof is of another input"
    );
    Ok(())
}

/// `args` as `count` positionals, then at most one program, then any number of
/// `--assume <receipt>`: the receipts of other programs the guest verifies.
fn with_assumptions<'a>(
    args: &[&'a str],
    count: usize,
) -> Result<(Vec<&'a str>, Option<&'a str>, Vec<String>)> {
    let mut positional = Vec::new();
    let mut assume = Vec::new();
    let mut rest = args.iter().copied();
    while let Some(arg) = rest.next() {
        match arg {
            "--assume" => assume.push(rest.next().context("--assume needs a receipt")?.to_string()),
            _ => positional.push(arg),
        }
    }
    ensure!(
        positional.len() == count || positional.len() == count + 1,
        "usage: <{count} arguments> [program] [--assume <receipt>]..."
    );
    let program = positional.get(count).copied();
    positional.truncate(count);
    Ok((positional, program, assume))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["pack", elf, out] => {
            let bin =
                risc0_binfmt::ProgramBinary::new(&read(elf)?, risc0_zkos_v1compat::V1COMPAT_ELF)
                    .encode();
            write(out, &bin)?;
            println!("{}", compute_image_id(&bin)?);
            Ok(())
        }
        // A packed program's image id: those kept in r0/programs are
        // named by theirs.
        ["id", bin] => {
            println!("{}", compute_image_id(&read(bin)?)?);
            Ok(())
        }
        ["hp-exec", rest @ ..] => {
            let (input, program, assume) = with_assumptions(rest, 1)?;
            hp::exec(input[0], program, &assume)
        }
        ["hp-prove", rest @ ..] => {
            let (args, program, assume) = with_assumptions(rest, 2)?;
            hp::prove(args[0], args[1].as_ref(), program, &assume)
        }
        // The CUDA build's part of hp-prove: the succinct receipt and its
        // identity_p254 seal, in segments of 2^po2.
        ["hp-stark", rest @ ..] => {
            let (args, program, assume) = with_assumptions(rest, 3)?;
            hp::stark_command(args[0], args[1].as_ref(), args[2], program, &assume)
        }
        ["chain-exec", rest @ ..] => {
            let (args, program, assume) = with_assumptions(rest, 1)?;
            chain::exec(args[0], program, &assume)
        }
        // A batch of the chain program (`licash_chain::Batch::to_bytes`):
        // its succinct receipt, kept as <work-dir>/receipt, which the next
        // batch and the statements of chained contracts verify. No Groth16:
        // nothing outside the zkVM reads it.
        ["chain-prove", rest @ ..] => {
            let (args, program, assume) = with_assumptions(rest, 2)?;
            chain::prove(args[0], args[1].as_ref(), program, &assume)
        }
        // For measurements: a receipt of the batch's journal that proves
        // nothing, which `hp-exec` runs a chained statement against.
        ["chain-fake", batch, out] => chain::fake(batch, out),
        // The CUDA build's part of chain-prove.
        ["chain-stark", rest @ ..] => {
            let (args, program, assume) = with_assumptions(rest, 3)?;
            chain::stark_command(args[0], args[1].as_ref(), args[2], program, &assume)
        }
        ["bench", out, program @ ..] if program.len() <= 1 => {
            bench::bench(out.as_ref(), program.first().copied())
        }
        // The CUDA build's part of bench.
        ["bench-stark", dir, po2, program @ ..] if program.len() <= 1 => {
            let po2 = segment_limit(Some(po2))?.context("a segment size")?;
            bench::stark(dir.as_ref(), po2, program.first().copied()).map(drop)
        }
        ["hp-reads", base, program @ ..] if program.len() <= 1 => {
            reads::reads(base, program.first().copied())
        }
        ["probe", program @ ..] if program.len() <= 1 => {
            println!("{}", serde_json::to_string(&probe::probe(program.first().copied()))?);
            Ok(())
        }
        // A job of another machine's proof (`fanout`), on the GPU if one is
        // usable: the join of its segments, left as <job-dir>/range.
        ["range-prove", dir, from, to] => fanout::range_command(dir.as_ref(), from, to),
        // The CUDA build's own check of its GPU, for the CPU build's probe.
        ["probe-gpu"] => probe::gpu(),
        _ => bail!("usage: licash-r0 pack <elf> <out.bin> | id <program.bin> | hp-exec <input.bin> [program] [--assume <receipt>].. | hp-prove <input.bin> <work-dir> [program] [--assume <receipt>].. | chain-prove <batch.bin> <work-dir> [--assume <receipt>] | range-prove <job-dir> <from> <to> | hp-reads <base.bin> [program] | probe [program] | bench <out.json> [program]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_takes_a_program_and_the_receipts_its_guest_verifies() {
        let args = |a: &[&'static str]| with_assumptions(a, 2);
        assert_eq!(
            args(&["in", "work"]).unwrap(),
            (vec!["in", "work"], None, vec![])
        );
        assert_eq!(
            args(&["in", "work", "id", "--assume", "a", "--assume", "b"]).unwrap(),
            (vec!["in", "work"], Some("id"), vec!["a".into(), "b".into()])
        );
        assert_eq!(
            args(&["in", "work", "--assume", "a"]).unwrap().2,
            vec!["a".to_string()]
        );
        for bad in [
            &["in"][..],
            &["a", "b", "c", "d"],
            &["in", "work", "--assume"],
        ] {
            assert!(args(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_proof_kept_is_taken_for_its_own_program_and_input_alone() {
        // Any program kept: the tracked ones, whichever they are now.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../programs");
        let first = std::fs::read_dir(dir).unwrap().next().unwrap().unwrap();
        let bin = &std::fs::read(first.path()).unwrap()[..];
        let id = compute_image_id(bin).unwrap();
        let kept = |id: &str, journal: &str| {
            serde_json::json!({"image_id": id, "journal": journal, "seal": ""})
                .to_string()
                .into_bytes()
        };
        let own = kept(&id.to_string(), &hex::encode([1u8, 2]));
        check_export(bin, &[1, 2], &own).unwrap();
        // Another input, another program, or no proof at all.
        assert!(check_export(bin, &[1, 3], &own).is_err());
        let other = kept(&"0".repeat(64), &hex::encode([1u8, 2]));
        assert!(check_export(bin, &[1, 2], &other).is_err());
        assert!(check_export(bin, &[1, 2], b"not json").is_err());
    }

    #[test]
    fn segmentation_is_optional_and_bounded() {
        assert_eq!(segment_limit(None).unwrap(), None);
        for po2 in ["13", "17", "18", "20"] {
            assert_eq!(
                segment_limit(Some(po2)).unwrap(),
                Some(po2.parse().unwrap())
            );
        }
        for value in ["", "12", "21", "invalid", "-1"] {
            assert!(segment_limit(Some(value)).is_err());
        }
    }
}
