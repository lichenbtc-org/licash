//! A witness's entries, in a SQLite database that only grows: one row a
//! slot, never updated or deleted (its triggers refuse either), each
//! committed to disk before it is answered.

use std::{path::Path, sync::Mutex};

use anyhow::{bail, ensure, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::{message, slot, valid, verify, Entry, Read, Status, Write, FORMAT, MAX_BODY};

const SCHEMA: &str = "
CREATE TABLE meta (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    format INTEGER NOT NULL,
    set_id BLOB NOT NULL CHECK (length(set_id) = 32),
    hub_key BLOB NOT NULL CHECK (length(hub_key) = 32),
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    contract BLOB NOT NULL CHECK (length(contract) = 32),
    slot TEXT NOT NULL,
    body BLOB NOT NULL,
    sig BLOB NOT NULL,
    at INTEGER NOT NULL,
    UNIQUE (contract, slot)
) STRICT;
CREATE TRIGGER meta_kept BEFORE UPDATE ON meta BEGIN SELECT RAISE(ABORT, 'a witness is never changed'); END;
CREATE TRIGGER meta_never_deleted BEFORE DELETE ON meta BEGIN SELECT RAISE(ABORT, 'a witness is never changed'); END;
CREATE TRIGGER log_kept BEFORE UPDATE ON log BEGIN SELECT RAISE(ABORT, 'an entry is never changed'); END;
CREATE TRIGGER log_never_deleted BEFORE DELETE ON log BEGIN SELECT RAISE(ABORT, 'an entry is never deleted'); END;
";

/// A witness's database.
pub struct Store(Mutex<Connection>);

fn connect(path: &Path, flags: OpenFlags) -> Result<Connection> {
    let c = Connection::open_with_flags(path, flags)
        .with_context(|| format!("open {}", path.display()))?;
    // An entry answered is on disk: a witness that lost one it acknowledged
    // would let the hub sign another.
    c.pragma_update(None, "journal_mode", "WAL")?;
    c.pragma_update(None, "synchronous", "FULL")?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(c)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl Store {
    /// Make a witness of the set `set_id` for the hub of x-only key
    /// `hub_key` at `path`, which must not exist.
    pub fn create(path: &Path, set_id: &[u8; 32], hub_key: &[u8; 32]) -> Result<()> {
        ensure!(!path.exists(), "{} exists", path.display());
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let mut c = connect(path, flags)?;
        let tx = c.transaction()?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO meta (one, format, set_id, hub_key, created_at) VALUES (1, ?1, ?2, ?3, ?4)",
            params![FORMAT, set_id, hub_key, now()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The witness at `path`: refused unless of [`FORMAT`].
    pub fn open(path: &Path) -> Result<Self> {
        ensure!(path.exists(), "no witness at {}", path.display());
        let c = connect(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        check_format(&c)?;
        Ok(Self(Mutex::new(c)))
    }

    /// A witness at `to`, which must not exist, holding what the witness
    /// whose database (or a backup of it, [`Store::backup`]) is at `from`
    /// holds: how a witness lost is replaced, from one that survives.
    pub fn copy(from: &Path, to: &Path) -> Result<()> {
        ensure!(!to.exists(), "{} exists", to.display());
        let source = connect(from, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        check_format(&source)?;
        let mut copy = Connection::open(to)?;
        rusqlite::backup::Backup::new(&source, &mut copy)?.run_to_completion(
            256,
            std::time::Duration::ZERO,
            None,
        )?;
        drop(copy);
        drop(Self::open(to)?);
        Ok(())
    }

    /// A consistent copy of this witness at `to`, which must not exist,
    /// while it serves.
    pub fn backup(&self, to: &Path) -> Result<()> {
        ensure!(!to.exists(), "{} exists", to.display());
        let c = self.conn();
        let mut copy = Connection::open(to)?;
        rusqlite::backup::Backup::new(&c, &mut copy)?.run_to_completion(
            256,
            std::time::Duration::ZERO,
            None,
        )?;
        Ok(())
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn status(&self) -> Result<Status> {
        status(&self.conn())
    }

    /// What it holds of `slot` of `contract`.
    pub fn read(&self, contract: &[u8; 32], slot: &str) -> Result<Read> {
        read(&self.conn(), contract, slot)
    }

    /// Keep `write` unless its slot holds an entry: what the slot then
    /// holds. Refused (the error said to the hub) where its signature is
    /// not the hub's, its slot is none, it is too large, or it is a
    /// response's or assertion's of a contract not enrolled.
    pub fn write(&self, write: &Write) -> Result<std::result::Result<Read, String>> {
        let mut c = self.conn();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = status(&tx)?;
        let Write {
            contract,
            slot,
            entry,
        } = write;
        if !valid(contract, slot) {
            return Ok(Err(format!("no slot {slot:?} for this contract")));
        }
        if entry.body.len() > MAX_BODY {
            return Ok(Err(format!("an entry of more than {MAX_BODY} bytes")));
        }
        let signed = message(&status.set_id, contract, slot, &entry.body);
        if !verify(&status.hub_key, &signed, &entry.sig) {
            return Ok(Err("not signed by this witness's hub for this set".into()));
        }
        let decision = matches!(slot.as_str(), slot::RESPOND | slot::ASSERT);
        if decision && entry_of(&tx, contract, slot::ENROLL)?.is_none() {
            return Ok(Err("the contract is not enrolled in this witness".into()));
        }
        tx.execute(
            "INSERT INTO log (contract, slot, body, sig, at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (contract, slot) DO NOTHING",
            params![contract, slot, entry.body, entry.sig, now()],
        )?;
        let read = read(&tx, contract, slot)?;
        tx.commit()?;
        Ok(Ok(read))
    }
}

fn check_format(c: &Connection) -> Result<()> {
    let format: Option<u32> = c
        .query_row("SELECT format FROM meta", [], |r| r.get(0))
        .optional()
        .context("not a witness's database")?;
    match format {
        Some(FORMAT) => Ok(()),
        Some(other) => bail!("a witness of format {other}: this one knows {FORMAT} only"),
        None => bail!("a witness's database never made"),
    }
}

fn status(c: &Connection) -> Result<Status> {
    let (format, set_id, hub_key): (u32, [u8; 32], [u8; 32]) =
        c.query_row("SELECT format, set_id, hub_key FROM meta", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    let sequence: i64 = c.query_row("SELECT count(*) FROM log", [], |r| r.get(0))?;
    let sequence = u64::try_from(sequence)?;
    Ok(Status {
        format,
        set_id,
        hub_key,
        sequence,
        seal: entry_of(c, &crate::SEALED, slot::SEAL)?,
    })
}

fn entry_of(c: &Connection, contract: &[u8; 32], slot: &str) -> Result<Option<Entry>> {
    Ok(c.query_row(
        "SELECT body, sig FROM log WHERE contract = ?1 AND slot = ?2",
        params![contract, slot],
        |r| {
            Ok(Entry {
                body: r.get(0)?,
                sig: r.get(1)?,
            })
        },
    )
    .optional()?)
}

fn read(c: &Connection, contract: &[u8; 32], slot: &str) -> Result<Read> {
    Ok(Read {
        status: status(c)?,
        enrolled: entry_of(c, contract, slot::ENROLL)?.is_some(),
        entry: entry_of(c, contract, slot)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{signed, SEALED};

    const SECRET: [u8; 32] = [7; 32];
    const SET: [u8; 32] = [3; 32];

    fn witness(dir: &Path) -> Store {
        let path = dir.join("witness.sqlite");
        Store::create(&path, &SET, &crate::public_key(&SECRET).unwrap()).unwrap();
        Store::open(&path).unwrap()
    }

    fn write(contract: [u8; 32], slot: &str, body: &[u8]) -> Write {
        signed(&SECRET, &SET, &contract, slot, body.to_vec()).unwrap()
    }

    /// A decision is kept only for a contract enrolled, once: a second
    /// write of its slot is answered with the first.
    #[test]
    fn an_entry_is_written_once_and_only_for_a_contract_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let w = witness(dir.path());
        assert_eq!(w.status().unwrap().sequence, 0);
        let refused = w.write(&write([1; 32], slot::RESPOND, b"first")).unwrap();
        assert!(refused.unwrap_err().contains("not enrolled"));
        w.write(&write([1; 32], slot::ENROLL, b""))
            .unwrap()
            .unwrap();
        let first = w
            .write(&write([1; 32], slot::RESPOND, b"first"))
            .unwrap()
            .unwrap();
        assert!(first.enrolled);
        assert_eq!(first.entry.as_ref().unwrap().body, b"first");
        let again = w
            .write(&write([1; 32], slot::RESPOND, b"other"))
            .unwrap()
            .unwrap();
        assert_eq!(again.entry, first.entry);
        assert_eq!(again.status.sequence, 2);
        // Another slot, another contract: their own.
        let assert = w
            .write(&write([1; 32], slot::ASSERT, b"pi1"))
            .unwrap()
            .unwrap();
        assert_eq!(assert.entry.unwrap().body, b"pi1");
        let other = w.read(&[2; 32], slot::RESPOND).unwrap();
        assert!(!other.enrolled && other.entry.is_none());
        assert_eq!(other.status.sequence, 3);
    }

    /// Only the hub's signature, for this set, slot and contract, is kept.
    #[test]
    fn a_write_not_the_hubs_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let w = witness(dir.path());
        let forged = signed(&[8; 32], &SET, &[1; 32], slot::ENROLL, vec![]).unwrap();
        assert!(w.write(&forged).unwrap().is_err());
        let other_set = signed(&SECRET, &[4; 32], &[1; 32], slot::ENROLL, vec![]).unwrap();
        assert!(w.write(&other_set).unwrap().is_err());
        let mut moved = write([1; 32], slot::ENROLL, b"");
        moved.contract = [2; 32];
        assert!(w.write(&moved).unwrap().is_err());
        assert!(w.write(&write([1; 32], slot::SEAL, b"")).unwrap().is_err());
        assert!(w.write(&write([1; 32], "other", b"")).unwrap().is_err());
        let large = write([1; 32], slot::ENROLL, &vec![0; MAX_BODY + 1]);
        assert!(w.write(&large).unwrap().is_err());
        assert_eq!(w.status().unwrap().sequence, 0);
        w.write(&write(SEALED, slot::SEAL, b"seal"))
            .unwrap()
            .unwrap();
        assert_eq!(w.status().unwrap().seal.unwrap().body, b"seal");
    }

    /// What it keeps is never rewritten, even from SQL; a copy of it holds
    /// the same; a store of another format is refused.
    #[test]
    fn the_log_only_grows_and_a_copy_holds_it_all() {
        let dir = tempfile::tempdir().unwrap();
        let w = witness(dir.path());
        w.write(&write([1; 32], slot::ENROLL, b""))
            .unwrap()
            .unwrap();
        w.write(&write([1; 32], slot::RESPOND, b"first"))
            .unwrap()
            .unwrap();
        {
            let c = w.conn();
            assert!(c.execute("UPDATE log SET body = x'00'", []).is_err());
            assert!(c.execute("DELETE FROM log", []).is_err());
            assert!(c
                .execute("UPDATE meta SET set_id = zeroblob(32)", [])
                .is_err());
        }
        let backup = dir.path().join("backup.sqlite");
        w.backup(&backup).unwrap();
        assert!(w.backup(&backup).is_err());
        let copy = dir.path().join("copy.sqlite");
        Store::copy(&backup, &copy).unwrap();
        let copied = Store::open(&copy).unwrap();
        assert_eq!(copied.status().unwrap(), w.status().unwrap());
        assert_eq!(
            copied.read(&[1; 32], slot::RESPOND).unwrap(),
            w.read(&[1; 32], slot::RESPOND).unwrap()
        );
        drop(copied);
        let c = Connection::open(&copy).unwrap();
        c.execute_batch("DROP TRIGGER meta_kept; UPDATE meta SET format = 2;")
            .unwrap();
        drop(c);
        let refused = Store::open(&copy).err().unwrap().to_string();
        assert!(refused.contains("format 2"), "{refused}");
        assert!(Store::create(&copy, &SET, &[0; 32]).is_err());
    }
}
