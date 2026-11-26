//! The hub's contract witnesses: what it keeps of each one-time signature
//! apart from its own database, which a restore or a copy of the hub can
//! roll back or fork ([`licash_witness`]).
//!
//! Before it signs a contract's response or assertion with its one-time
//! key, the hub writes what it signs (a [`Decision`]) to every witness of
//! its set, in a fixed order (by pin): the first keeps whatever reached it
//! first, which the hub then writes to the others and signs, or nothing if
//! any refuses, is unreachable, or holds another. Two copies of a hub, or
//! one restored older, so never sign two answers of one contract.
//!
//! Each witness is checked as it answers: of the set configured, for this
//! hub's key, of a sequence never below what it showed before
//! (`witness_seen`), sealed as the others. The hub's database is bound to
//! one set (`witness_bound`), by its first contract's seal (`genesis`) or
//! by an import of the contracts it signed before it had witnesses
//! ([`Witnesses::import`]): never inferred from a seal or a marker absent.

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use bitcoin::hashes::Hash as _;
use licash::spend::ChainProfile;
use licash_store::Kind;
use licash_witness::{
    client::{Client, Refused},
    slot, Entry, Read, Status, Write, FORMAT, SEALED,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// The component the hub's witness state is, and its version.
const COMPONENT: &str = "witnesses";
const VERSION: i64 = 1;

/// The set the hub's database is bound to, and how: `genesis`, `import`,
/// or `adopted` (sealed already as the hub first spoke to it). One row,
/// never rewritten. And each witness's sequence, by pin, as last seen: one
/// lower is a witness rolled back.
const SCHEMA: &str = "
CREATE TABLE witness_bound (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    set_id BLOB NOT NULL CHECK (length(set_id) = 32),
    how TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
CREATE TABLE witness_seen (
    pin BLOB PRIMARY KEY CHECK (length(pin) = 32),
    set_id BLOB NOT NULL CHECK (length(set_id) = 32),
    sequence INTEGER NOT NULL
) STRICT;
";

/// The version of what the hub writes in its witnesses' entries: another
/// is refused, never read as this one.
const BODY: u32 = 1;

/// How many times a witness is asked before it counts as unreachable.
const ATTEMPTS: u32 = 3;

/// What the hub decided to sign with one of a contract's one-time keys,
/// as its witnesses keep it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    /// Its response to the request of txid `request`, of `b` and `E`
    /// (`e`): `owed`, its `b′`, on `evidence` (as pinned, bytes).
    Respond {
        #[serde(with = "hex::serde")]
        request: [u8; 32],
        b: u32,
        #[serde(with = "hex::serde")]
        e: [u8; 32],
        owed: u32,
        #[serde(with = "hex::serde")]
        evidence: Vec<u8>,
    },
    /// Its assertion, of π1's digits `digits` of the proof `proof` (as
    /// pinned, bytes), against the request of txid `request`.
    Assert {
        #[serde(with = "hex::serde")]
        request: [u8; 32],
        #[serde(with = "hex::serde")]
        digits: Vec<u8>,
        #[serde(with = "hex::serde")]
        proof: Vec<u8>,
    },
    /// Never to be signed: the hub may have signed it with what it no
    /// longer knows.
    Burnt,
}

#[derive(Serialize, Deserialize)]
struct Body {
    v: u32,
    #[serde(flatten)]
    decision: Decision,
}

#[derive(Deserialize)]
struct Versioned {
    v: u32,
}

impl Decision {
    fn to_body(&self) -> Vec<u8> {
        let body = Body {
            v: BODY,
            decision: self.clone(),
        };
        serde_json::to_vec(&body).expect("a decision serializes")
    }

    fn from_body(body: &[u8]) -> Result<Self> {
        let v: Versioned = serde_json::from_slice(body).context("a witness's entry")?;
        ensure!(
            v.v == BODY,
            "a witness's entry of version {}: this hub reads {BODY} only",
            v.v
        );
        let body: Body = serde_json::from_slice(body).context("a witness's entry")?;
        Ok(body.decision)
    }
}

/// A seal: how the set came to hold all the hub had to give it.
fn seal(how: &str, digest: Option<[u8; 32]>) -> Vec<u8> {
    let mut seal = serde_json::json!({ "v": BODY, "seal": how });
    if let Some(digest) = digest {
        seal["digest"] = hex::encode(digest).into();
    }
    serde_json::to_vec(&seal).expect("a seal serializes")
}

/// The witnesses the hub signs one-time answers by: none (regtest and
/// signet only), or a set.
pub struct Witnesses(Option<Set>);

struct Set {
    id: [u8; 32],
    /// In the order they are written, by pin.
    members: Vec<Client>,
    secret: [u8; 32],
    key: [u8; 32],
}

fn open(data: &Path) -> Result<Connection> {
    let mut c = licash_store::open(&crate::hub_db(data), Kind::Hub)?;
    licash_store::component(&mut c, COMPONENT, VERSION, SCHEMA)?;
    Ok(c)
}

/// Two witnesses of the set hold two decisions of one slot: nothing of it
/// is signed, ever, unlike a witness unreachable or refusing, mended.
#[derive(Debug)]
struct Disagreement(String);

impl std::fmt::Display for Disagreement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Disagreement {}

/// Whether `e` is of witnesses that disagree ([`Disagreement`]).
pub(super) fn disagreed(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<Disagreement>())
}

/// The set the hub's database is bound to, if any.
fn bound(data: &Path) -> Result<Option<[u8; 32]>> {
    Ok(open(data)?
        .query_row("SELECT set_id FROM witness_bound", [], |r| r.get(0))
        .optional()?)
}

/// How the hub's database came to be bound, if it is.
fn bound_how(data: &Path) -> Result<Option<String>> {
    Ok(open(data)?
        .query_row("SELECT how FROM witness_bound", [], |r| r.get(0))
        .optional()?)
}

fn bind(data: &Path, set_id: &[u8; 32], how: &str) -> Result<()> {
    let c = open(data)?;
    c.execute(
        "INSERT INTO witness_bound (one, set_id, how, created_at) VALUES (1, ?1, ?2, ?3)
         ON CONFLICT DO NOTHING",
        params![set_id, how, crate::now()],
    )?;
    let kept: [u8; 32] = c.query_row("SELECT set_id FROM witness_bound", [], |r| r.get(0))?;
    ensure!(kept == *set_id, "the hub is bound to another witness set");
    Ok(())
}

impl Witnesses {
    /// No witnesses: the hub's database alone keeps its one-time answers,
    /// as before witnesses. Refused on mainnet ([`Witnesses::admit`]).
    pub fn none() -> Self {
        Self(None)
    }

    /// The witnesses `members` of the set `set_id`, written with the hub's
    /// witness key `secret`. Refused for none, or one pinned twice.
    pub fn of(set_id: [u8; 32], mut members: Vec<Client>, secret: [u8; 32]) -> Result<Self> {
        ensure!(!members.is_empty(), "a witness set of no witness");
        ensure!(set_id != [0; 32], "a witness set's id is not all zeros");
        members.sort_by_key(Client::pin);
        let pins = members.windows(2).any(|w| w[0].pin() == w[1].pin());
        ensure!(!pins, "a witness pinned twice");
        let key = licash_witness::public_key(&secret)?;
        Ok(Self(Some(Set {
            id: set_id,
            members,
            secret,
            key,
        })))
    }

    /// How many witnesses it has.
    pub fn count(&self) -> usize {
        self.0.as_ref().map_or(0, |s| s.members.len())
    }

    /// Whether the hub may play contracts on `profile` with these
    /// witnesses and its database in `data`: not with none on mainnet, nor
    /// with fewer than two; not with none, or another set, where its
    /// database is bound to one.
    pub fn admit(&self, profile: ChainProfile, data: &Path) -> Result<()> {
        let mainnet = profile == ChainProfile::Core30Mainnet;
        ensure!(
            !mainnet || self.count() >= 2,
            "contracts on mainnet need two witnesses at least (--contracts-witness)"
        );
        match (bound(data)?, &self.0) {
            (Some(_), None) => bail!(
                "the hub's contracts are witnessed: --contracts-witnesses none would let it \
                 sign again what they keep"
            ),
            (Some(bound), Some(set)) => ensure!(
                bound == set.id,
                "the hub's contracts are witnessed by the set {}, not {}",
                hex::encode(bound),
                hex::encode(set.id)
            ),
            (None, _) => {}
        }
        ensure!(
            !mainnet || bound_how(data)?.as_deref() != Some("import"),
            "the hub's contracts were imported into its witnesses, as off mainnet only: \
             a mainnet hub's are witnessed from its first"
        );
        Ok(())
    }

    /// Enroll contract `id` in every witness, before the hub signs its
    /// funding: no witness keeps a decision of a contract never enrolled.
    /// `fresh` says whether the hub never signed a one-time answer, nor a
    /// funding: then, the set unsealed, it is sealed as the hub's first.
    pub(super) async fn enroll(
        &self,
        data: &Path,
        id: &[u8; 32],
        fresh: impl FnOnce() -> Result<bool>,
    ) -> Result<()> {
        let Some(set) = &self.0 else { return Ok(()) };
        set.ready(data, fresh).await?;
        let enroll = set.signed(id, slot::ENROLL, Vec::new())?;
        for member in &set.members {
            let read = set.put(data, member, &enroll).await?;
            ensure!(
                read.enrolled,
                "witness {} did not enroll the contract",
                member.url()
            );
        }
        Ok(())
    }

    /// What the hub signs in `slot` of contract `id`: `ours`, unless its
    /// witnesses hold another, then theirs. An error where any refuses,
    /// cannot be reached, never enrolled the contract, or holds another
    /// than the first: then nothing is signed.
    pub(super) async fn authorize(
        &self,
        data: &Path,
        id: &[u8; 32],
        slot: &str,
        ours: &Decision,
    ) -> Result<Decision> {
        let Some(set) = &self.0 else {
            return Ok(ours.clone());
        };
        set.ready(data, || Ok(false)).await?;
        let mut kept: Option<Entry> = None;
        for member in &set.members {
            let write = match &kept {
                Some(entry) => Write {
                    contract: *id,
                    slot: slot.to_owned(),
                    entry: entry.clone(),
                },
                None => set.signed(id, slot, ours.to_body())?,
            };
            let read = set.put(data, member, &write).await?;
            ensure!(
                read.enrolled,
                "witness {} never enrolled the contract",
                member.url()
            );
            let entry = read
                .entry
                .with_context(|| format!("witness {} kept nothing", member.url()))?;
            match &kept {
                None => kept = Some(entry),
                Some(first) if first.body == entry.body => {}
                Some(_) => {
                    return Err(Disagreement(format!(
                        "the witnesses disagree on the contract's {slot}: witness {} holds \
                         another than the first. Nothing is signed, ever: her timeout pays her \
                         what she claims",
                        member.url()
                    ))
                    .into())
                }
            }
        }
        Decision::from_body(&kept.context("no witness")?.body)
    }

    /// What the witnesses hold in `slot` of contract `id`, as they hold it
    /// alike, without writing: none where none does. An error where any
    /// cannot be read, or two hold others.
    pub(super) async fn recover(
        &self,
        data: &Path,
        id: &[u8; 32],
        slot: &str,
    ) -> Result<Option<Decision>> {
        let Some(set) = &self.0 else { return Ok(None) };
        set.ready(data, || Ok(false)).await?;
        let mut found: Option<Entry> = None;
        for member in &set.members {
            let read = set.ask(data, member, id, slot).await?;
            let Some(entry) = read.entry else { continue };
            match &found {
                None => found = Some(entry),
                Some(first) if first.body == entry.body => {}
                Some(_) => {
                    return Err(Disagreement(format!(
                        "the witnesses disagree on the contract's {slot}: nothing is signed, ever"
                    ))
                    .into())
                }
            }
        }
        found.map(|e| Decision::from_body(&e.body)).transpose()
    }

    /// Give a hub's witnesses, all unsealed, what it signed before it had
    /// them, its database in `data` (the hub stopped): each contract
    /// enrolled, and each answer it signed or may have (`to_import`).
    /// Then the set is sealed, and the hub's database bound to it: what
    /// was imported. Refused once bound, or a seal written: an import that
    /// failed before its seal is run again.
    pub async fn import(&self, data: &Path) -> Result<Imported> {
        let set = self.0.as_ref().context("an import needs witnesses")?;
        ensure!(
            bound(data)?.is_none(),
            "the hub's contracts are imported into its witnesses already"
        );
        let (ids, decided) = to_import(data)?;
        // The seal this import writes last, of all it writes.
        let mut digest = sha2::Sha256::new();
        for id in &ids {
            digest.update(id);
        }
        let mut bodies = Vec::with_capacity(decided.len());
        for (id, name, decision) in &decided {
            let body = decision.to_body();
            digest.update(id);
            digest.update(name.as_bytes());
            digest.update(&body);
            bodies.push(body);
        }
        let seal = seal("import", Some(digest.finalize().into()));
        // A witness sealed otherwise holds another hub's contracts, or
        // these as they were; all sealed, this import is done. Some sealed
        // with this very seal: a run of it stopped as it sealed, run again.
        let mut sealed = 0;
        for member in &set.members {
            match set.status(data, member).await?.seal {
                None => {}
                Some(kept) if kept.body == seal => sealed += 1,
                Some(_) => bail!(
                    "witness {} is sealed: its set holds the hub's contracts already",
                    member.url()
                ),
            }
        }
        ensure!(
            sealed < set.members.len(),
            "the witnesses are sealed with the hub's contracts already: start the hub"
        );
        for id in &ids {
            let enroll = set.signed(id, slot::ENROLL, Vec::new())?;
            for member in &set.members {
                set.put(data, member, &enroll).await?;
            }
        }
        for ((id, name, _), body) in decided.iter().zip(bodies) {
            let write = set.signed(id, name, body)?;
            for member in &set.members {
                let read = set.put(data, member, &write).await?;
                let kept = read.entry.context("kept nothing")?;
                ensure!(
                    kept.body == write.entry.body,
                    "witness {} holds another {name} for contract {}: not imported",
                    member.url(),
                    hex::encode(id)
                );
            }
        }
        set.seal_all(data, &seal).await?;
        bind(data, &set.id, "import")?;
        Ok(Imported {
            enrolled: ids.len(),
            answers: decided
                .iter()
                .filter(|(_, _, d)| *d != Decision::Burnt)
                .count(),
            burnt: decided
                .iter()
                .filter(|(_, _, d)| *d == Decision::Burnt)
                .count(),
        })
    }
}

/// What an import gave a hub's witnesses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imported {
    /// Contracts enrolled: every one the hub's database holds.
    pub enrolled: usize,
    /// Answers the hub signed, kept as it signed them.
    pub answers: usize,
    /// Answers the hub may have signed with what it no longer knows: kept
    /// never to be signed.
    pub burnt: usize,
}

/// A decision of a contract's slot, to import.
type Decided = ([u8; 32], &'static str, Decision);

/// What the hub's database in `data` gives its witnesses as they are
/// imported: every opening's id, and of each answer (`respond`, `assert`)
/// it signed, what it signed it with, as its cache of it and its pin
/// read; of each it may have signed (marked so, nothing pinned), or
/// signed with what it no longer knows, [`Decision::Burnt`]. An answer
/// pinned but not signed is not: what is pinned is written as any, once
/// the hub runs again.
fn to_import(data: &Path) -> Result<(Vec<[u8; 32]>, Vec<Decided>)> {
    let store = super::store::Store::open(data)?;
    let pins = super::responses::Responses::open(data)?;
    let ids = store.all_ids()?;
    let mut decided = Vec::new();
    for id in &ids {
        // b and b′ as the contract's payout counts the words signed, as the
        // hub decides them.
        let base = || -> Result<_> {
            let row = store.row(id)?.context("a contract of no row")?;
            licash_contract::opening::Hub::peek(&row.state)
                .map(|hub| hub.base)
                .with_context(|| format!("contract {}'s state", hex::encode(id)))
        };
        let txid = |pin: &[u8; 32]| -> Result<_> {
            let request = pins
                .request(pin)?
                .context("an answer of no request pinned")?;
            let (b, e) = licash_contract::graph::requested(&base()?, &request)?;
            Ok((request.compute_txid().to_byte_array(), b, e))
        };
        let respond = match pins.response(id)? {
            Some(response) => {
                let (request, b, e) = txid(id)?;
                Some(Decision::Respond {
                    request,
                    b,
                    e,
                    owed: licash_contract::graph::responded(&base()?, &response)?,
                    evidence: pins.evidence(id)?.unwrap_or_default(),
                })
            }
            None => (store.began_signing(id, slot::RESPOND)? && pins.evidence(id)?.is_none())
                .then_some(Decision::Burnt),
        };
        let tag = super::dispute::tagged(id, b"assert");
        let assert = match pins.response(&tag)? {
            Some(_) => {
                let proof = pins.evidence(&tag)?.filter(|p| !p.is_empty());
                let decoded =
                    proof.and_then(|p| Some((lichen_babe::statement::proof_from_bytes(&p)?, p)));
                match decoded {
                    Some((decoded, proof)) => Some(Decision::Assert {
                        request: txid(&tag)?.0,
                        digits: licash_contract::dispute::asserted_digits(&decoded),
                        proof,
                    }),
                    // Signed before proofs were pinned: what it signed is
                    // cached, and played as it is, but never signed again.
                    None => Some(Decision::Burnt),
                }
            }
            None => (store.began_signing(id, slot::ASSERT)? && pins.evidence(&tag)?.is_none())
                .then_some(Decision::Burnt),
        };
        decided.extend(respond.map(|d| (*id, slot::RESPOND, d)));
        decided.extend(assert.map(|d| (*id, slot::ASSERT, d)));
    }
    Ok((ids, decided))
}

impl Set {
    fn signed(&self, id: &[u8; 32], slot: &str, body: Vec<u8>) -> Result<Write> {
        licash_witness::signed(&self.secret, &self.id, id, slot, body)
    }

    /// Whether an entry kept in `slot` of `contract` is the hub's.
    fn check_entry(&self, contract: &[u8; 32], slot: &str, entry: &Entry) -> Result<()> {
        let message = licash_witness::message(&self.id, contract, slot, &entry.body);
        ensure!(
            licash_witness::verify(&self.key, &message, &entry.sig),
            "a witness holds an entry the hub never signed"
        );
        Ok(())
    }

    /// Whether `member` says what a witness of this set says, at a
    /// sequence not below the last it showed: kept then as the last.
    fn check(&self, data: &Path, member: &Client, status: &Status) -> Result<()> {
        let url = member.url();
        ensure!(
            status.format == FORMAT,
            "witness {url} is of format {}: this hub knows {FORMAT}",
            status.format
        );
        ensure!(
            status.set_id == self.id,
            "witness {url} is of the set {}, not {}",
            hex::encode(status.set_id),
            hex::encode(self.id)
        );
        ensure!(
            status.hub_key == self.key,
            "witness {url} keeps another hub's entries"
        );
        if let Some(seal) = &status.seal {
            self.check_entry(&SEALED, slot::SEAL, seal)?;
        }
        let pin = member.pin();
        let c = open(data)?;
        let seen: Option<i64> = c
            .query_row(
                "SELECT sequence FROM witness_seen WHERE pin = ?1 AND set_id = ?2",
                params![pin, self.id],
                |r| r.get(0),
            )
            .optional()?;
        let sequence = i64::try_from(status.sequence)?;
        if let Some(seen) = seen {
            ensure!(
                sequence >= seen,
                "witness {url} holds {sequence} entries, fewer than the {seen} it held: \
                 restored older, it is not trusted. Make it again from a witness that \
                 survives (licash-witness clone)"
            );
        }
        c.execute(
            "INSERT INTO witness_seen (pin, set_id, sequence) VALUES (?1, ?2, ?3)
             ON CONFLICT (pin) DO UPDATE SET sequence = max(sequence, excluded.sequence)",
            params![pin, self.id, sequence],
        )?;
        Ok(())
    }

    async fn status(&self, data: &Path, member: &Client) -> Result<Status> {
        let status = again(|| member.status()).await?;
        self.check(data, member, &status)?;
        Ok(status)
    }

    /// `member` asked to keep `write`: what it keeps, checked.
    async fn put(&self, data: &Path, member: &Client, write: &Write) -> Result<Read> {
        let read = again(|| member.write(write)).await?;
        self.checked(data, member, &write.contract, &write.slot, read)
    }

    async fn ask(&self, data: &Path, member: &Client, id: &[u8; 32], slot: &str) -> Result<Read> {
        let read = again(|| member.read(id, slot)).await?;
        self.checked(data, member, id, slot, read)
    }

    fn checked(
        &self,
        data: &Path,
        member: &Client,
        contract: &[u8; 32],
        slot: &str,
        read: Read,
    ) -> Result<Read> {
        self.check(data, member, &read.status)?;
        if let Some(entry) = &read.entry {
            self.check_entry(contract, slot, entry)?;
        }
        Ok(read)
    }

    /// Write `seal` to every witness, each to hold it.
    async fn seal_all(&self, data: &Path, seal: &[u8]) -> Result<()> {
        let write = self.signed(&SEALED, slot::SEAL, seal.to_vec())?;
        for member in &self.members {
            let read = self.put(data, member, &write).await?;
            let kept = read.entry.context("kept no seal")?;
            ensure!(
                kept.body == seal,
                "witness {} is sealed otherwise",
                member.url()
            );
        }
        Ok(())
    }

    /// Whether every witness can be relied on now: each as [`Set::check`],
    /// all sealed alike. A hub's database bound to none is bound as they
    /// are sealed, or, unsealed and `fresh` (it never signed), sealed as
    /// the hub's first.
    async fn ready(&self, data: &Path, fresh: impl FnOnce() -> Result<bool>) -> Result<()> {
        let mut seals = Vec::with_capacity(self.members.len());
        for member in &self.members {
            seals.push(self.status(data, member).await?.seal.map(|s| s.body));
        }
        let bound = bound(data)?;
        if let Some(bound) = bound {
            ensure!(bound == self.id, "the hub is bound to another witness set");
        }
        let first = seals[0].clone();
        if first.is_some() && seals.iter().all(|s| *s == first) {
            if bound.is_none() {
                bind(data, &self.id, "adopted")?;
            }
            return Ok(());
        }
        let unsealed: Vec<&str> = self
            .members
            .iter()
            .zip(&seals)
            .filter(|(_, s)| s.is_none())
            .map(|(m, _)| m.url())
            .collect();
        if bound.is_some() || seals.iter().flatten().any(|s| *s != seal("genesis", None)) {
            bail!(
                "the witnesses are not sealed alike (unsealed: {unsealed:?}): a witness lost \
                 is made again from one that survives (licash-witness clone), never anew"
            );
        }
        ensure!(
            fresh()?,
            "the hub signed contracts before it had witnesses: import them, the hub \
             stopped (licash-hub contracts-witness-import)"
        );
        self.seal_all(data, &seal("genesis", None)).await?;
        bind(data, &self.id, "genesis")
    }
}

/// `op` until it answers, [`ATTEMPTS`] times at most: an error it gives
/// for good (a witness's refusal) at once.
async fn again<T, F: std::future::Future<Output = Result<T>>>(op: impl Fn() -> F) -> Result<T> {
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(t) => return Ok(t),
            Err(e) if attempt >= ATTEMPTS || e.downcast_ref::<Refused>().is_some() => {
                return Err(e)
            }
            Err(_) => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests;
