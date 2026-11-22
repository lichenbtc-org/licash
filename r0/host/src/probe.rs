//! What this machine proves with: its device, the programs kept, the
//! Groth16 setup, and the memory it may use. The hub reads it at startup
//! (`licash-r0 probe`), to tell its operator what is missing before a
//! contract needs a proof.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// The memory the Groth16 wrap takes, with some room: about 7.7 GB.
pub const MIN_MEMORY: u64 = 8_500_000_000;

/// Where the installed programs and Groth16 setup are:
/// `LICASH_R0_SHARE`, else `../share/licash-r0` beside this program.
pub fn share() -> PathBuf {
    if let Some(dir) = std::env::var_os("LICASH_R0_SHARE") {
        return dir.into();
    }
    let exe = std::env::current_exe().unwrap_or_default();
    let bin = exe.parent().unwrap_or(Path::new("."));
    bin.join("../share/licash-r0")
}

pub fn groth16_dir() -> PathBuf {
    share().join("groth16")
}

/// The packed program `program` names: a path to one, else an image id
/// kept installed or in this checkout's `r0/programs`. None: the
/// checkout's own build, `r0/guests/hp.bin`.
pub fn program(program: Option<&str>) -> Result<Vec<u8>> {
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let path = match program {
        None => checkout.join("guests/hp.bin"),
        Some(p) if p.len() == 64 && p.bytes().all(|c| c.is_ascii_hexdigit()) => {
            let installed = share().join(format!("programs/{p}.bin"));
            match installed.exists() {
                true => installed,
                false => checkout.join(format!("programs/{p}.bin")),
            }
        }
        Some(p) => PathBuf::from(p),
    };
    std::fs::read(&path).with_context(|| format!("no packed program at {}", path.display()))
}

/// The CUDA build beside this one, if any.
pub fn cuda_build() -> Option<PathBuf> {
    if cfg!(feature = "cuda") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let cuda = exe.with_file_name("licash-r0-cuda");
    cuda.exists().then_some(cuda)
}

/// Whether the CUDA build beside this one runs and finds a usable GPU:
/// it does not start without the driver's library.
pub fn gpu_usable() -> bool {
    if cfg!(feature = "cuda") {
        return gpu().is_ok();
    }
    let Some(cuda) = cuda_build() else {
        return false;
    };
    Command::new(cuda)
        .arg("probe-gpu")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The CUDA build's check of its GPU: a context made on device 0.
pub fn gpu() -> Result<()> {
    #[cfg(feature = "cuda")]
    {
        let made = std::panic::catch_unwind(|| {
            drop(risc0_zkp::hal::cuda::CudaHalPoseidon2::new());
        });
        anyhow::ensure!(made.is_ok(), "no usable CUDA device");
        Ok(())
    }
    #[cfg(not(feature = "cuda"))]
    anyhow::bail!("built without CUDA")
}

/// The memory this process may use, in bytes: the least of the machine's
/// and its control group's limit (a container's).
pub fn memory() -> Option<u64> {
    let total = std::fs::read_to_string("/proc/meminfo").ok().and_then(|m| {
        let line = m.lines().find(|l| l.starts_with("MemTotal:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    });
    let limit = [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok());
    match (total, limit) {
        (Some(t), Some(l)) => Some(t.min(l)),
        (t, l) => t.or(l),
    }
}

/// The image ids of the programs installed.
fn programs() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir(share().join("programs")) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = dir
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            Some(name.strip_suffix(".bin")?.to_owned())
        })
        .collect();
    ids.sort();
    ids
}

/// The probe's report: `device` ("cuda" or "cpu"), `programs` (image
/// ids), `memory` (bytes, if known) and `problems`, what keeps it from
/// proving: none when ready. With `program`, installed, a problem too if
/// it doesn't prove the benchmark's input, made by this build's library,
/// as the library does: built before a change of format, it would prove
/// nothing of a contract opened under it.
pub fn probe(program: Option<&str>) -> Value {
    let device = match gpu_usable() {
        true => "cuda",
        false => "cpu",
    };
    let mut problems = Vec::new();
    let setup = groth16_dir();
    let missing: Vec<_> = crate::groth16::FILES
        .iter()
        .filter(|f| !setup.join(f).exists())
        .collect();
    if !missing.is_empty() {
        problems.push(format!(
            "no Groth16 setup at {} (missing {missing:?}): x86-64 images only",
            setup.display()
        ));
    }
    let programs = programs();
    if programs.is_empty() {
        problems.push(format!(
            "no programs in {}",
            share().join("programs").display()
        ));
    }
    if let Some(program) = program.filter(|p| programs.iter().any(|q| q == p)) {
        if let Err(e) = crate::reads::proves_bench(program) {
            problems.push(format!(
                "the program {program} does not prove the statement this build makes \
                 ({e:#}): install the program of this build (docs/r0.md)"
            ));
        }
    }
    let memory = memory();
    if memory.is_some_and(|m| m < MIN_MEMORY) {
        problems.push(format!(
            "{} MB of memory, short of the {} MB the Groth16 wrap takes",
            memory.unwrap_or(0) / 1_000_000,
            MIN_MEMORY / 1_000_000
        ));
    }
    json!({
        "device": device,
        "programs": programs,
        "memory": memory,
        "problems": problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_is_a_path_or_a_kept_image_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bin");
        std::fs::write(&path, b"packed").unwrap();
        assert_eq!(program(Some(path.to_str().unwrap())).unwrap(), b"packed");
        // The program contracts open under on signet, kept in the checkout.
        let signet = "1808247519df8436457abfb21a7a5173e0b9948db0b75ee3dce0e93bc9443658";
        assert!(!program(Some(signet)).unwrap().is_empty());
        let unknown = "00".repeat(32);
        assert!(program(Some(&unknown)).is_err());
    }

    #[test]
    fn the_memory_is_known_on_linux() {
        assert!(memory().is_some_and(|m| m > 0));
    }
}
