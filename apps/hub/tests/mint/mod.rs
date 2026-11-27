//! Notes paid to an address at a hub, minted as its issuer: how a test
//! funds a wallet without a payment in.

use std::path::Path;

use licash::{
    address::{Address, Ephemeral, OwnerKeys},
    authorization::{Authorization, SignedProposal},
    claim::Branch,
    note::{Derivation, Evidence, IssuerKeys, Keyset, Note},
    spend::{Output as SpendOutput, Proposal},
    unlink::Nonce,
};
use licash_api::Payment;
use licash_hub::Hub;

/// Notes of `amount` paid to `to` at `hub`, of the seed at `seed` and its
/// largest denomination `2^max_pow`, served at `url`: its spend fee paid
/// on top.
pub fn pay(
    hub: &Hub,
    (seed, max_pow): (&Path, u32),
    url: &str,
    to: &Address,
    amount: u64,
) -> Payment {
    let text = std::fs::read_to_string(seed).unwrap();
    let mut seed = [0; 32];
    hex::decode_to_slice(text.trim(), &mut seed).unwrap();
    let keys = IssuerKeys::from_seed(&seed, 0, max_pow).unwrap();
    let keyset = keys.keyset().unwrap();
    let info = hub.info();
    let mut total = amount;
    while amount + info.policy.spend.due(total) != total {
        total = amount + info.policy.spend.due(total);
    }
    let payer = OwnerKeys::from_seed(&[0xfa; 32]).unwrap();
    let inputs: Vec<(Note, Derivation)> = split(total, max_pow)
        .into_iter()
        .map(|denom| mint(&keys, &keyset, &payer.address(), denom))
        .collect();
    let notes: Vec<Note> = inputs.iter().map(|(note, _)| note.clone()).collect();
    let ephemeral = Ephemeral::random();
    let to_hub = split(total - amount, max_pow)
        .into_iter()
        .map(|d| (d, &info.address));
    let outputs = split(amount, max_pow)
        .into_iter()
        .map(|d| (d, to))
        .chain(to_hub)
        .enumerate()
        .map(|(i, (d, to))| {
            let derivation = ephemeral.derive(to, d, Branch::Pay, i).unwrap();
            SpendOutput::from_derivation(&derivation).unwrap()
        })
        .collect();
    let proposal = Proposal::new(&keyset, &notes, ephemeral.public(), outputs, None).unwrap();
    let grant = hub.offer(&proposal, &notes).unwrap();
    let owners: Vec<_> = inputs
        .iter()
        .map(|(_, d)| d.ownership().owner_secret(payer.spend_secret()).unwrap())
        .collect();
    let grant = Authorization::Granted(Box::new(grant));
    let signed = SignedProposal::sign(&keyset, proposal, &notes, grant, &owners).unwrap();
    let unlock = hub.release(&signed, &notes).unwrap();
    Payment::new(url, &signed, &notes, &unlock)
}

fn split(mut amount: u64, max_pow: u32) -> Vec<u64> {
    let mut denoms = Vec::new();
    for pow in (0..=max_pow).rev() {
        while amount >= 1 << pow {
            denoms.push(1 << pow);
            amount -= 1 << pow;
        }
    }
    denoms
}

fn mint(keys: &IssuerKeys, keyset: &Keyset, to: &Address, denom: u64) -> (Note, Derivation) {
    let d = Ephemeral::random()
        .derive(to, denom, Branch::Pay, 0)
        .unwrap();
    let output = SpendOutput::from_derivation(&d).unwrap();
    let proof = keys.prove_blinded(denom, output.blinded()).unwrap();
    let note = Note::from_parts(
        keyset,
        *keyset.id(),
        d.message().clone(),
        proof.open_point(keyset, &d).unwrap(),
        Evidence::Linked {
            dleq: proof.dleq(),
            blinding: *d.blinding(),
            commit: Nonce::new(keyset, &output).unwrap().commit().unwrap(),
        },
    )
    .unwrap();
    (note, d)
}
