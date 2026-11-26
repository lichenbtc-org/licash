//! Whether a program reads what this build's library makes. The hub asks
//! before it opens a contract, of the contract's own Base (`licash-r0
//! hp-reads <base.bin> [program]`), and at startup, of the benchmark's
//! input (`licash-r0 probe <program>`). A program built before a change of
//! the format of notes, spends or Bases reads neither, and a contract
//! opened under it is one the hub can't prove anything of: each claim of
//! it would be paid all it asks.

use std::fs::read;

use anyhow::{anyhow, bail, ensure, Context, Result};
use licash::base::Base;
use licash::recovery::chained;
use licash_hp::{headers::ChainProof, HubInput, RequestKeys};
use licash_statement::{checksum_digits, Exit, Request, Respond, SlotSpend};
use risc0_zkvm::{default_executor, ExecutorEnv, Receipt};

use crate::probe;

/// What the statement's guest panics with when it can't decode its input,
/// and when its statement doesn't hold of an input it read
/// (`r0/hp-guest/src/main.rs`, as every kept program was built).
const UNREAD: &str = "the statement's input";
pub(crate) const REFUSED: &str = "the Hub's statement";
/// What the zkVM says when the guest verifies a receipt it isn't given: a
/// chained contract's statement does, past reading its input.
const UNRESOLVED: &str = "no receipt found to resolve assumption";

/// An input of `base` that the statement reads and refuses: an exit of
/// nothing, no evidence, her request's keys all zeros, and of a chained
/// contract a proof of no chain.
pub fn input_of(base: Base) -> HubInput {
    let digits = |bytes| vec![[0; 20]; 2 * bytes + checksum_digits(bytes)];
    let chain = chained(base.parts().graph.id).then(|| ChainProof {
        journal: Vec::new(),
        tip: Vec::new(),
        openings: Vec::new(),
    });
    HubInput {
        base,
        exit: Exit {
            headers: Vec::new(),
            request: Request {
                funding: Vec::new(),
                tx: Vec::new(),
                header: [0; 80],
                index: 0,
                path: Vec::new(),
                coinbase: Vec::new(),
                coinbase_path: Vec::new(),
                reserved: [0; 32],
            },
            publish: SlotSpend {
                tx: Vec::new(),
                header: [0; 80],
                index: 0,
                path: Vec::new(),
                coinbase: Vec::new(),
                coinbase_path: Vec::new(),
            },
            respond: Respond {
                tx: Vec::new(),
                header: [0; 80],
                index: 0,
                path: Vec::new(),
                coinbase: Vec::new(),
                coinbase_path: Vec::new(),
                reserved: [0; 32],
            },
            disclosure: None,
        },
        evidence: Vec::new(),
        keys: RequestKeys::new(digits(4), digits(32)).expect("keys of their lengths"),
        invalid: 0,
        chain,
    }
}

/// The guest's environment for `input`, verifying `receipts`, its output
/// not forwarded: the probe prints its report on stdout.
fn env(input: &[u8], receipts: &[Receipt]) -> Result<ExecutorEnv<'static>> {
    let mut env = ExecutorEnv::builder();
    for receipt in receipts {
        env.add_assumption(receipt.clone());
    }
    env.write(&(input.len() as u32))?
        .write_slice(&crate::words(input));
    env.build()
}

/// That `bin` reads `bytes`, an input this library reads: it does if it
/// proves something of it, or refuses it once read. One that panics
/// decoding it, or fails otherwise, does not.
pub fn reads_input(bin: &[u8], bytes: &[u8]) -> Result<()> {
    HubInput::from_bytes(bytes).map_err(|e| anyhow!("this library reads no such input: {e:?}"))?;
    let Err(e) = default_executor().execute(env(bytes, &[])?, bin) else {
        return Ok(());
    };
    let why = format!("{e:#}");
    if why.contains(REFUSED) || why.contains(UNRESOLVED) {
        return Ok(());
    }
    if why.contains(UNREAD) {
        bail!("it does not read the input this build's library makes");
    }
    bail!("it fails on it: {why}")
}

/// That `bin` decides the input `bytes` as this library does, the
/// receipts it verifies `receipts`: proves it with the library's journal,
/// or, of an input the library refuses, refuses it once read.
pub fn decides(bin: &[u8], bytes: &[u8], receipts: &[Receipt]) -> Result<()> {
    let run = default_executor().execute(env(bytes, receipts)?, bin);
    match (run, crate::hp::expected(bytes)) {
        (Ok(s), Ok(j)) => ensure!(s.journal.bytes == j, "its journal is not the library's"),
        (Ok(_), Err(e)) => bail!("it proves what the library refuses: {e}"),
        (Err(e), Ok(_)) => bail!("it does not prove what the library proves: {e:#}"),
        (Err(e), Err(_)) => {
            let why = format!("{e:#}");
            ensure!(why.contains(REFUSED), "it does not read it: {why}");
        }
    }
    Ok(())
}

/// `hp-reads`: that `program` reads a statement's input of the Base whose
/// bytes are at `path`.
pub fn reads(path: &str, program: Option<&str>) -> Result<()> {
    let bytes = read(path).with_context(|| format!("the Base at {path}"))?;
    let base = Base::from_bytes(&bytes).map_err(|e| anyhow!("not a Base: {e}"))?;
    let bin = probe::program(program)?;
    reads_input(&bin, &input_of(base).to_bytes())
        .context("the program reads no statement's input of this Base")?;
    println!("hp: the program reads a statement's input of this Base");
    Ok(())
}

/// The probe's: that `program` proves the benchmark's input, which this
/// build's library made and proves, as the library does.
pub fn proves_bench(program: &str) -> Result<()> {
    let bin = probe::program(Some(program))?;
    let bytes = crate::bench::input()?;
    crate::hp::expected(&bytes).context("this build's library proves no benchmark")?;
    decides(&bin, &bytes, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn kept(name: &str) -> Vec<u8> {
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(name)).unwrap()
    }

    /// The program signet's and Mutinynet's contracts open under, as
    /// `apps/contracts` pins it (`SIGNET`): read from its source, so that
    /// this follows the pin.
    fn signet() -> String {
        let source = String::from_utf8(kept("../../apps/contracts/src/lib.rs")).unwrap();
        let at = source
            .find("pub const SIGNET: [u8; 32] =")
            .expect("the pin");
        let rest = &source[at..];
        let start = rest.find("hex!(\"").expect("its id") + 6;
        let id = rest[start..start + 64].to_owned();
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()), "{id}");
        id
    }

    /// The programs contracts opened before [`signet`] are played under,
    /// as `apps/contracts` keeps them (`SIGNET_BEFORE`), read from its source.
    fn signet_before() -> Vec<String> {
        let source = String::from_utf8(kept("../../apps/contracts/src/lib.rs")).unwrap();
        let at = source
            .find("pub const SIGNET_BEFORE:")
            .expect("the programs before");
        let rest = &source[at..];
        let list = &rest[rest.find('=').expect("their list")..];
        let list = &list[..list.find("];").expect("their end")];
        // each `hex!("…")`, quoted
        list.split('"')
            .skip(1)
            .step_by(2)
            .map(|id| {
                assert!(
                    id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()),
                    "{id}"
                );
                id.to_owned()
            })
            .collect()
    }

    /// The inputs the statement's tests export (`export_inputs`,
    /// `export_worst_inputs`, `export_chained_inputs`, docs/r0.md), made by
    /// this checkout's code, of contracts on `graph` (`LICASH_HP_GRAPH`) if
    /// named, with the chained input's receipt of the chain, which proves
    /// nothing (`chain-fake`), as `hp-exec` counts one. Of a graph named,
    /// the chained input alone.
    fn exported(graph: Option<u32>) -> (tempfile::TempDir, Vec<Receipt>) {
        let dir = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut export = std::process::Command::new(env!("CARGO"));
        export
            .current_dir(&root)
            .env("LICASH_HP_INPUTS", dir.path())
            .args(["test", "--locked", "--release", "--manifest-path"])
            .arg(root.join("regtest/Cargo.toml"))
            .args(["-p", "licash-hp", "--test", "statement", "--"]);
        match graph {
            Some(graph) => export
                .env("LICASH_HP_GRAPH", graph.to_string())
                .arg("export_chained_inputs"),
            None => export.env_remove("LICASH_HP_GRAPH").arg("export_"),
        };
        let out = export.output().unwrap();
        assert!(
            out.status.success(),
            "the export: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let receipt = dir.path().join("chain-2.bin");
        let batch = dir.path().join("batch-2.bin");
        crate::chain::fake(batch.to_str().unwrap(), receipt.to_str().unwrap()).unwrap();
        let receipts = crate::hp::receipts(&[receipt.display().to_string()]).unwrap();
        (dir, receipts)
    }

    /// The exported inputs of no rest output, each with whether it is chained.
    const PLAIN: [(&str, bool); 6] = [
        ("answered", false),
        ("unanswered", false),
        ("answered-funded", false),
        ("worst", false),
        ("worst-alone", false),
        ("answered-chained", true),
    ];

    fn bench_base() -> Base {
        HubInput::from_bytes(&kept("bench.bin")).unwrap().base
    }

    /// The pinned program proves the benchmark's input, which this
    /// library made and reads (`bench::tests`), as the library does: a
    /// change of format with no new program fails here, and at a hub's
    /// startup.
    #[test]
    fn the_pinned_program_proves_what_the_library_makes() {
        proves_bench(&signet()).unwrap();
    }

    /// The pinned program decides each input the statement's tests export
    /// ([`exported`]) as the library does: none it can't read, nor one it
    /// decides otherwise.
    #[test]
    fn the_pinned_program_decides_what_the_current_code_exports() {
        let (dir, receipts) = exported(None);
        let pinned = probe::program(Some(&signet())).unwrap();
        let path = |name: &str| dir.path().join(format!("{name}.bin"));
        for (name, chained) in PLAIN.into_iter().chain([("answered-rest", false)]) {
            let bytes = std::fs::read(path(name)).unwrap();
            let receipts = if chained { &receipts[..] } else { &[] };
            decides(&pinned, &bytes, receipts).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        }
        // What it proves and refuses, both: unanswered is refused.
        assert!(crate::hp::expected(&std::fs::read(path("unanswered")).unwrap()).is_err());
        assert!(crate::hp::expected(&std::fs::read(path("answered")).unwrap()).is_ok());
        // A contract of a rest output, proved.
        assert!(crate::hp::expected(&std::fs::read(path("answered-rest")).unwrap()).is_ok());
    }

    /// Each program contracts opened before the pinned one are played
    /// under decides their contracts as this checkout's library does, on
    /// the graph ids exported by default and, chained, on the one they
    /// opened on (14, `licash::recovery::SIGNED_FROM`, whose contracts no
    /// program decides but on their chain): the hub decides with the
    /// library and proves with the program, so a program deciding otherwise
    /// is a response the hub cannot prove. A contract of a rest output,
    /// which none of them was built for, each refuses.
    #[test]
    fn the_programs_before_decide_their_contracts_as_the_current_code() {
        let before = signet_before();
        assert!(!before.is_empty());
        let programs: Vec<_> = before
            .iter()
            .map(|id| probe::program(Some(id)).unwrap())
            .collect();
        for graph in [None, Some(licash::recovery::SIGNED_FROM)] {
            let (dir, receipts) = exported(graph);
            let path = |name: &str| dir.path().join(format!("{name}.bin"));
            for (id, program) in before.iter().zip(&programs) {
                for (name, chained) in PLAIN
                    .into_iter()
                    .filter(|(_, chained)| graph.is_none() || *chained)
                {
                    let bytes = std::fs::read(path(name)).unwrap();
                    let receipts = if chained { &receipts[..] } else { &[] };
                    decides(program, &bytes, receipts)
                        .unwrap_or_else(|e| panic!("{id} on {graph:?}, {name}: {e:#}"));
                }
                if graph.is_none() {
                    let rested = std::fs::read(path("answered-rest")).unwrap();
                    assert!(decides(program, &rested, &[]).is_err(), "{id}");
                }
            }
        }
    }

    /// An input of any Base, chained or not, is one the library reads
    /// and refuses; the pinned program reads it, and another program, the
    /// chain's, does not.
    #[test]
    fn the_pinned_program_reads_an_input_of_a_base_and_another_does_not() {
        let pinned = probe::program(Some(&signet())).unwrap();
        let chain_id = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../hp-guest/chain.id"),
        )
        .unwrap();
        let chain = probe::program(Some(chain_id.trim())).unwrap();
        let base = bench_base();
        let mut parts = base.parts().clone();
        assert!(!chained(parts.graph.id));
        parts.graph.id = licash::recovery::SIGNED_FROM;
        let signed = Base::new(parts).unwrap();
        for base in [base, signed] {
            let bytes = input_of(base).to_bytes();
            let read = HubInput::from_bytes(&bytes).unwrap();
            assert!(licash_hp::check(&read).is_err());
            reads_input(&pinned, &bytes).unwrap();
            let e = reads_input(&chain, &bytes).unwrap_err();
            assert!(e.to_string().contains("fails on it"), "{e:#}");
        }
        // Nor does any program read what the library doesn't.
        let e = reads_input(&pinned, b"not an input").unwrap_err();
        assert!(e.to_string().contains("this library"), "{e:#}");
    }
}
