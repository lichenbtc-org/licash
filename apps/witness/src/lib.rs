//! A witness of a Licash hub's one-time contract signatures.
//!
//! A hub signs each contract's response and assertion with a one-time key:
//! two different messages signed with one give her the hub's outputs. The
//! hub keeps what it is about to sign in its own database, which a restore
//! or a second copy of the hub can roll back or fork. A witness keeps it
//! apart, in a database of its own that only grows: one entry, written
//! once, for each contract and slot (`respond`, `assert`), each signed by
//! the hub's witness key. The hub signs only what every witness of its set
//! holds the same, so two copies of a hub never both sign, and a hub
//! restored older finds what it decided before.
//!
//! A witness holds no key of the hub's or of any contract: it checks the
//! hub's signature on what it is asked to keep, and keeps nothing else.
//! It is reached over TLS with a certificate of its own, which the hub
//! pins ([`client::Client`]).
//!
//! It also keeps which copy of the hub leads: an entry for each epoch
//! taken over ([`slot::LEADER`]), naming the copy that took it. A
//! witness enrolls no contract for a copy writing at an older epoch than
//! the newest it holds, so that a copy superseded opens none; what it
//! decides of the contracts open is kept as ever, first come.
//!
//! Here: what witnesses and hubs say to each
//! other, the witness's store ([`store::Store`]) and its service
//! ([`server`]).

use bitcoin::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod client;
pub mod server;
pub mod store;

/// The format of a witness's store and of what it says: another is
/// refused, by the witness opening its store and by the hub reading it.
pub const FORMAT: u32 = 1;

/// The largest entry a witness keeps, in bytes: a response's evidence
/// (64 000 bytes at most, `licash_hub::MAX_EVIDENCE_BYTES`) and what is
/// around it, with room.
pub const MAX_BODY: usize = 256 * 1024;

/// The contract a set's seal is kept under: no contract's id.
pub const SEALED: [u8; 32] = [0; 32];

/// What a contract's entries are kept as.
pub mod slot {
    /// That the hub may sign for the contract: written before it signs
    /// the contract's funding, and needed for any other entry.
    pub const ENROLL: &str = "enroll";
    /// What the hub signs its response with.
    pub const RESPOND: &str = "respond";
    /// What the hub signs its assertion with.
    pub const ASSERT: &str = "assert";
    /// The set's seal, under [`super::SEALED`]: written once the set holds
    /// all the hub had to give it (on a hub's first contract, or once
    /// imported), the same in every witness of a set.
    pub const SEAL: &str = "seal";
    /// The copy of the hub that took an epoch over, under
    /// [`super::leader_id`] of it: its instance, 32 bytes.
    pub const LEADER: &str = "leader";
}

/// What the contract ids of epochs begin with: no contract's.
const LEADERS: [u8; 24] = *b"licash-witness/leader/v1";

/// The contract an epoch's leader is kept under: [`LEADERS`], then the
/// epoch, big-endian, so that the newest sorts last.
pub fn leader_id(epoch: u64) -> [u8; 32] {
    let mut id = [0; 32];
    id[..24].copy_from_slice(&LEADERS);
    id[24..].copy_from_slice(&epoch.to_be_bytes());
    id
}

/// The epoch `contract` keeps the leader of, if it is one's: from 1.
pub fn epoch_of(contract: &[u8; 32]) -> Option<u64> {
    let epoch = u64::from_be_bytes(contract[24..].try_into().expect("8 bytes"));
    (contract[..24] == LEADERS && epoch > 0).then_some(epoch)
}

/// Whether `slot` is one kept for `contract`.
pub fn valid(contract: &[u8; 32], slot: &str) -> bool {
    let epoch = epoch_of(contract).is_some();
    match slot {
        slot::SEAL => *contract == SEALED,
        slot::ENROLL | slot::RESPOND | slot::ASSERT => *contract != SEALED && !epoch,
        slot::LEADER => epoch,
        _ => false,
    }
}

/// An entry as kept: what the hub wrote, and its signature over it
/// ([`message`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(with = "hex::serde")]
    pub body: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sig: Vec<u8>,
}

/// A witness as it is: of which set, for which hub, how many entries it
/// has kept (its sequence, which never falls), and its set's seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub format: u32,
    #[serde(with = "hex::serde")]
    pub set_id: [u8; 32],
    /// The x-only key of the hub whose entries it keeps.
    #[serde(with = "hex::serde")]
    pub hub_key: [u8; 32],
    pub sequence: u64,
    pub seal: Option<Entry>,
    /// The newest epoch's leader, if any epoch was taken over: absent of
    /// a witness that keeps none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader: Option<Leader>,
}

/// Who took `epoch` over: [`slot::LEADER`] of [`leader_id`] of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leader {
    pub epoch: u64,
    pub entry: Entry,
}

/// What a witness holds of a contract's slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Read {
    pub status: Status,
    /// Whether the contract is enrolled.
    pub enrolled: bool,
    pub entry: Option<Entry>,
}

/// An entry to keep, unless one is kept in its slot: the witness answers
/// with what it keeps there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Write {
    #[serde(with = "hex::serde")]
    pub contract: [u8; 32],
    pub slot: String,
    pub entry: Entry,
    /// The epoch its writer leads at, 0 for none: an enrollment at one
    /// older than the witness's newest is refused. Not signed: an entry
    /// is forwarded as first kept, whatever epoch carries it.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub epoch: u64,
}

fn is_zero(epoch: &u64) -> bool {
    *epoch == 0
}

/// What the hub signs for an entry of `body` in `slot` of `contract`, in
/// the set `set_id`: never valid in another set, slot or contract.
pub fn message(set_id: &[u8; 32], contract: &[u8; 32], slot: &str, body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"licash-witness/entry/v1");
    h.update(set_id);
    h.update(contract);
    h.update([u8::try_from(slot.len()).expect("a slot's name is short")]);
    h.update(slot.as_bytes());
    h.update(body);
    h.finalize().into()
}

/// The hub's witness key of secret `secret`, x-only.
pub fn public_key(secret: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let keypair = Keypair::from_seckey_slice(&Secp256k1::new(), secret)?;
    Ok(keypair.x_only_public_key().0.serialize())
}

/// A BIP 340 signature over `message` with `secret`.
pub fn sign(secret: &[u8; 32], message: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_seckey_slice(&secp, secret)?;
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(*message), &keypair);
    Ok(sig.serialize().to_vec())
}

/// Whether `sig` is `key`'s over `message`.
pub fn verify(key: &[u8; 32], message: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (
        XOnlyPublicKey::from_slice(key),
        schnorr::Signature::from_slice(sig),
    ) else {
        return false;
    };
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &Message::from_digest(*message), &key)
        .is_ok()
}

/// A write of `body` to `slot` of `contract` in `set_id`, signed with
/// `secret`.
pub fn signed(
    secret: &[u8; 32],
    set_id: &[u8; 32],
    contract: &[u8; 32],
    slot: &str,
    body: Vec<u8>,
) -> anyhow::Result<Write> {
    let sig = sign(secret, &message(set_id, contract, slot, &body))?;
    Ok(Write {
        contract: *contract,
        slot: slot.to_owned(),
        entry: Entry { body, sig },
        epoch: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_signed_for_its_set_contract_and_slot_alone() {
        let secret = [7; 32];
        let key = public_key(&secret).unwrap();
        let w = signed(&secret, &[1; 32], &[2; 32], slot::RESPOND, b"b".to_vec()).unwrap();
        let ok = |set, contract, slot: &str, body: &[u8]| {
            verify(&key, &message(set, contract, slot, body), &w.entry.sig)
        };
        assert!(ok(&[1; 32], &[2; 32], slot::RESPOND, b"b"));
        assert!(!ok(&[9; 32], &[2; 32], slot::RESPOND, b"b"));
        assert!(!ok(&[1; 32], &[9; 32], slot::RESPOND, b"b"));
        assert!(!ok(&[1; 32], &[2; 32], slot::ASSERT, b"b"));
        assert!(!ok(&[1; 32], &[2; 32], slot::RESPOND, b"c"));
        assert!(!verify(
            &public_key(&[8; 32]).unwrap(),
            &message(&[1; 32], &[2; 32], slot::RESPOND, b"b"),
            &w.entry.sig
        ));
        assert!(!verify(&key, &[0; 32], b"short"));
    }

    #[test]
    fn a_slot_belongs_to_contracts_or_to_the_seal() {
        assert!(valid(&[1; 32], slot::RESPOND));
        assert!(valid(&[1; 32], slot::ENROLL));
        assert!(!valid(&[1; 32], slot::SEAL));
        assert!(valid(&SEALED, slot::SEAL));
        assert!(!valid(&SEALED, slot::ASSERT));
        assert!(!valid(&[1; 32], "other"));
    }
}
