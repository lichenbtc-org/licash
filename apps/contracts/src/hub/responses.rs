//! One-time answers shared by the daemon and the operator. The request is
//! committed before signing; a restart can only sign for that same request
//! (its `b` and `E`, however its witness writes them).
//! With it, the evidence the hub decided her claim on: its response, its
//! disclosure and its proof all cite that evidence, whatever the ledger
//! learns after.

use std::path::Path;

use anyhow::{ensure, Context, Result};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::Transaction;
use licash_store::Kind;
use rusqlite::{params, Connection, OptionalExtension};

/// The component the pins are, and its version.
const COMPONENT: &str = "responses";
const VERSION: i64 = 1;

/// Per opening, or per assertion's tag: the request committed before
/// signing, the evidence its decision was made on, and once signed its
/// response. A pin is never rewritten: what is pinned first is what the
/// hub answers on.
const SCHEMA: &str = "
CREATE TABLE response_pins (
    id BLOB PRIMARY KEY,
    request BLOB NOT NULL,
    response BLOB,
    evidence BLOB
) STRICT;
";

pub(super) struct Responses(Connection);

/// Whether `request` is the request `pinned`: the same transaction, by
/// txid, signing the same `b` and `E` as its script reads them. Its
/// witness may differ, and still be valid: a digit written another way
/// (Bitcoin takes a 15 written as 16, which whoever mines it may write),
/// her signatures made again. Read so, a request confirmed again after a
/// reorg is answered with what was pinned, not refused.
fn same_request(pinned: &Transaction, request: &Transaction) -> bool {
    if pinned.compute_wtxid() == request.compute_wtxid() {
        return true;
    }
    let read = licash_contract::graph::HubProves::requested_b;
    pinned.compute_txid() == request.compute_txid()
        && matches!((read(pinned), read(request)), (Ok(a), Ok(b)) if a == b)
}

impl Responses {
    /// The pins in the hub's data directory `data`, made if none were.
    pub fn open(data: &Path) -> Result<Self> {
        let mut c = licash_store::open(&crate::hub_db(data), Kind::Hub)?;
        licash_store::component(&mut c, COMPONENT, VERSION, SCHEMA)?;
        Ok(Self(c))
    }

    /// The evidence `evidence` (its bytes) pinned for `request` of opening
    /// `id`, unless some was pinned first: what is pinned. `request` must
    /// be validated before this call.
    pub fn pin(&self, id: &[u8; 32], request: &Transaction, evidence: &[u8]) -> Result<Vec<u8>> {
        self.0.execute(
            "INSERT INTO response_pins (id, request, evidence) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![id, serialize(request), evidence],
        )?;
        let (pinned, evidence): (Vec<u8>, Option<Vec<u8>>) = self.0.query_row(
            "SELECT request, evidence FROM response_pins WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pinned: Transaction = deserialize(&pinned).context("pinned request")?;
        ensure!(
            same_request(&pinned, request),
            "request witness differs from the one-time signing pin; refusing to sign again"
        );
        Ok(evidence.unwrap_or_default())
    }

    /// The evidence pinned for opening `id`, if any was: empty bytes for
    /// none (a response of version 1).
    pub fn evidence(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let row: Option<Option<Vec<u8>>> = self
            .0
            .query_row(
                "SELECT evidence FROM response_pins WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(row.map(Option::unwrap_or_default))
    }

    /// The answer signed for `id`, if one was.
    pub fn response(&self, id: &[u8; 32]) -> Result<Option<Transaction>> {
        let row: Option<Option<Vec<u8>>> = self
            .0
            .query_row(
                "SELECT response FROM response_pins WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        row.flatten()
            .map(|b| deserialize(&b).context("pinned response"))
            .transpose()
    }

    /// The proof `proof` (its bytes) pinned for the assertion `id` of
    /// `request`, in its evidence, unless one was pinned first or its
    /// answer was signed before proofs were pinned: what is pinned, none
    /// then. `request` must be validated before this call.
    pub fn pin_proof(
        &self,
        id: &[u8; 32],
        request: &Transaction,
        proof: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.0.execute(
            "INSERT INTO response_pins (id, request) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![id, serialize(request)],
        )?;
        self.0.execute(
            "UPDATE response_pins SET evidence = ?2
             WHERE id = ?1 AND evidence IS NULL AND response IS NULL",
            params![id, proof],
        )?;
        let (pinned, proof): (Vec<u8>, Option<Vec<u8>>) = self.0.query_row(
            "SELECT request, evidence FROM response_pins WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pinned: Transaction = deserialize(&pinned).context("pinned request")?;
        ensure!(
            same_request(&pinned, request),
            "request witness differs from the one-time signing pin; refusing to sign again"
        );
        Ok(proof)
    }

    /// `request` must be validated before this call. Its `b` and `E`, not
    /// its txid alone, bind the one-time signatures ([`same_request`]).
    /// No signing in a SQL
    /// transaction: the pin must survive even a stopped signer.
    pub fn answer(
        &self,
        id: &[u8; 32],
        request: &Transaction,
        sign: impl FnOnce() -> Result<Transaction>,
    ) -> Result<Transaction> {
        self.0.execute(
            "INSERT INTO response_pins (id, request) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![id, serialize(request)],
        )?;
        let (pinned, response): (Vec<u8>, Option<Vec<u8>>) = self.0.query_row(
            "SELECT request, response FROM response_pins WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pinned: Transaction = deserialize(&pinned).context("pinned request")?;
        ensure!(
            same_request(&pinned, request),
            "request witness differs from the one-time signing pin; refusing to sign again"
        );
        if let Some(response) = response {
            return deserialize(&response).context("pinned response");
        }
        let response = sign()?;
        self.0.execute(
            "UPDATE response_pins SET response = ?2 WHERE id = ?1 AND response IS NULL",
            params![id, serialize(&response)],
        )?;
        let kept: Vec<u8> = self.0.query_row(
            "SELECT response FROM response_pins WHERE id = ?1",
            [id],
            |r| r.get(0),
        )?;
        ensure!(
            kept == serialize(&response),
            "a different response was pinned"
        );
        Ok(response)
    }

    /// The evidence (or proof) `evidence` pinned for `request` of `id` in
    /// place of what was, which the hub's witnesses agreed on before: the
    /// one decision the hub signs ([`super::witness`]), the local pin
    /// written older or otherwise. Refused once its answer is signed, or
    /// for another request.
    pub fn adopt(&self, id: &[u8; 32], request: &Transaction, evidence: &[u8]) -> Result<()> {
        self.0.execute(
            "INSERT INTO response_pins (id, request) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![id, serialize(request)],
        )?;
        let (pinned, response): (Vec<u8>, Option<Vec<u8>>) = self.0.query_row(
            "SELECT request, response FROM response_pins WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let pinned: Transaction = deserialize(&pinned).context("pinned request")?;
        ensure!(
            same_request(&pinned, request),
            "the witnesses' decision is of another request than the one pinned"
        );
        ensure!(response.is_none(), "its answer is signed already");
        self.0.execute(
            "UPDATE response_pins SET evidence = ?2 WHERE id = ?1 AND response IS NULL",
            params![id, evidence],
        )?;
        Ok(())
    }

    /// The request pinned for `id`, if any.
    pub fn request(&self, id: &[u8; 32]) -> Result<Option<Transaction>> {
        let row: Option<Vec<u8>> = self
            .0
            .query_row(
                "SELECT request FROM response_pins WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        row.map(|b| deserialize(&b).context("pinned request"))
            .transpose()
    }

    /// Whether nothing is pinned.
    pub fn is_empty(&self) -> Result<bool> {
        let n: i64 = self
            .0
            .query_row("SELECT count(*) FROM response_pins", [], |r| r.get(0))?;
        Ok(n == 0)
    }

    #[cfg(test)]
    fn contains(&self, id: &[u8; 32]) -> Result<bool> {
        Ok(self
            .0
            .query_row(
                "SELECT 1 FROM response_pins WHERE id = ?1",
                [id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction, TxIn, Witness};

    fn request(byte: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                witness: Witness::from_slice(&[&[byte]]),
                ..Default::default()
            }],
            output: vec![],
        }
    }

    #[test]
    fn a_restart_returns_the_pinned_answer_without_signing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        let r = request(1);
        let answer = request(2);
        assert!(!pins.contains(&[1; 32])?);
        assert_eq!(pins.answer(&[1; 32], &r, || Ok(answer.clone()))?, answer);
        drop(pins);
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        assert_eq!(
            pins.answer(&[1; 32], &r, || panic!("signed twice"))?,
            answer
        );
        Ok(())
    }

    #[test]
    fn the_pin_survives_a_failed_signer_and_rejects_another_witness() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        let r = request(1);
        let other = request(2);
        assert_eq!(r.compute_txid(), other.compute_txid());
        assert!(pins
            .answer(&[1; 32], &r, || anyhow::bail!("stopped"))
            .is_err());
        drop(pins);
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        let err = pins
            .answer(&[1; 32], &other, || panic!("signed another claim"))
            .unwrap_err();
        assert!(err.to_string().contains("witness differs"));
        assert_eq!(pins.answer(&[1; 32], &r, || Ok(other.clone()))?, other);
        Ok(())
    }

    #[test]
    fn another_connection_obeys_the_same_pin_and_another_opening_is_independent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let a = Responses::open(&crate::testing::hub_data(dir.path()))?;
        let b = Responses::open(&crate::testing::hub_data(dir.path()))?;
        a.answer(&[1; 32], &request(1), || Ok(request(3)))?;
        assert!(b
            .answer(&[1; 32], &request(2), || panic!("signed twice"))
            .is_err());
        assert_eq!(
            b.answer(&[2; 32], &request(2), || Ok(request(4)))?,
            request(4)
        );
        Ok(())
    }

    #[test]
    fn a_newer_pin_format_is_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let data = crate::testing::hub_data(dir.path());
        drop(Responses::open(&data)?);
        let c = Connection::open(crate::hub_db(&data))?;
        c.execute(
            "UPDATE schema_versions SET version = 3 WHERE component = 'responses'",
            [],
        )?;
        drop(c);
        assert!(Responses::open(&data)
            .err()
            .unwrap()
            .to_string()
            .contains("version 3"));
        Ok(())
    }

    /// A real request of the shared mock opening, claiming `b` with `E`
    /// all 0xff (its digits 15, each written `[15]`).
    fn real_request(b: u32) -> Transaction {
        use licash_contract::{
            keys::HolderKeys,
            opening::{Context, Holder, Trust},
        };
        let saved = crate::testing::opened();
        let ctx = Context {
            tip: 0,
            trust: Trust::mock(),
        };
        let holder = Holder::load(&saved.holder, &saved.seed, &ctx).unwrap();
        let keys = HolderKeys::derive(&saved.seed, &holder.id());
        holder
            .signed()
            .unwrap()
            .request(&keys, b, &[0xff; 32])
            .unwrap()
    }

    /// `r` with each digit of 15 written `to`, as the script reads it.
    fn rewritten(r: &Transaction, to: &[u8]) -> Transaction {
        let mut tx = r.clone();
        let items: Vec<Vec<u8>> = tx.input[0]
            .witness
            .iter()
            .map(|i| if i == [15] { to.to_vec() } else { i.to_vec() })
            .collect();
        tx.input[0].witness = items.into();
        tx
    }

    /// Mined again with its digits written otherwise (a reorg, a miner's
    /// choice), her request is the one pinned: answered with the pinned
    /// response, its evidence and proof the pinned ones. Another `b`, by
    /// the same txid, is refused.
    #[test]
    fn a_request_written_otherwise_is_answered_as_pinned_and_another_b_refused() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        let r = real_request(3072);
        let again = rewritten(&r, &[16]);
        assert_eq!(again.compute_txid(), r.compute_txid());
        assert_ne!(again.compute_wtxid(), r.compute_wtxid());
        assert_eq!(pins.pin(&[1; 32], &r, b"first")?, b"first");
        assert_eq!(pins.pin(&[1; 32], &again, b"later")?, b"first");
        let answer = request(2);
        assert_eq!(pins.answer(&[1; 32], &r, || Ok(answer.clone()))?, answer);
        assert_eq!(
            pins.answer(&[1; 32], &again, || panic!("signed twice"))?,
            answer
        );
        assert_eq!(
            pins.pin_proof(&[2; 32], &r, b"proof")?,
            Some(b"proof".to_vec())
        );
        assert_eq!(
            pins.pin_proof(&[2; 32], &again, b"other")?,
            Some(b"proof".to_vec())
        );
        let other = real_request(2048);
        assert_eq!(other.compute_txid(), r.compute_txid());
        assert!(pins.pin(&[1; 32], &other, b"first").is_err());
        assert!(pins
            .answer(&[1; 32], &other, || panic!("signed another claim"))
            .is_err());
        assert!(pins.pin_proof(&[2; 32], &other, b"proof").is_err());
        Ok(())
    }

    /// Evidence is pinned once, with the request.
    #[test]
    fn evidence_is_pinned_once() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        assert_eq!(pins.evidence(&[1; 32])?, None);
        assert_eq!(pins.pin(&[1; 32], &request(1), b"first")?, b"first");
        assert_eq!(pins.pin(&[1; 32], &request(1), b"later")?, b"first");
        assert!(pins.pin(&[1; 32], &request(9), b"first").is_err());
        assert_eq!(pins.evidence(&[1; 32])?, Some(b"first".to_vec()));
        Ok(())
    }

    /// An assertion's proof is pinned once, before it is signed; one signed
    /// before proofs were pinned (a request alone pinned, then its answer)
    /// keeps its answer and pins none.
    #[test]
    fn a_proof_is_pinned_once_and_not_after_its_answer() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let pins = Responses::open(&crate::testing::hub_data(dir.path()))?;
        assert_eq!(pins.response(&[1; 32])?, None);
        assert_eq!(
            pins.pin_proof(&[1; 32], &request(1), b"first")?,
            Some(b"first".to_vec())
        );
        assert_eq!(
            pins.pin_proof(&[1; 32], &request(1), b"later")?,
            Some(b"first".to_vec())
        );
        assert!(pins.pin_proof(&[1; 32], &request(9), b"first").is_err());
        assert_eq!(
            pins.answer(&[1; 32], &request(1), || Ok(request(3)))?,
            request(3)
        );
        assert_eq!(pins.response(&[1; 32])?, Some(request(3)));

        pins.answer(&[2; 32], &request(1), || Ok(request(4)))?;
        assert_eq!(pins.pin_proof(&[2; 32], &request(1), b"late")?, None);
        assert_eq!(pins.response(&[2; 32])?, Some(request(4)));
        Ok(())
    }
}
