//! What the hub's statement reads of Bitcoin (`licash_statement::Exit`),
//! from the blocks that carry the exit: `request` in its block with its
//! witness and the funding it spends ([`request`]), `respond` likewise
//! ([`respond`]), and a slot's spender in its block by the txid tree
//! ([`slot_spend`]). Pure: an L2's hub fetches the blocks however it
//! follows the chain.

use anyhow::{ensure, Context, Result};
use licash_statement::{Carrier, Request, Respond, SlotSpend};
use lichen_btc::bitcoin::consensus::serialize;
use lichen_btc::bitcoin::hashes::{sha256d, Hash as _};
use lichen_btc::bitcoin::{Block, Transaction, Txid, Witness};

/// The Merkle path of the leaf at `index` among `leaves` (internal
/// order), siblings from the leaves up; a level's odd last node pairs
/// with itself.
pub fn merkle_path(leaves: &[[u8; 32]], mut index: usize) -> Vec<[u8; 32]> {
    let mut level = leaves.to_vec();
    let mut path = vec![];
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        path.push(level[index ^ 1]);
        level = level
            .chunks(2)
            .map(|p| sha256d::Hash::hash(&[p[0], p[1]].concat()).to_byte_array())
            .collect();
        index /= 2;
    }
    path
}

/// A transaction's non-witness serialization (its txid's).
pub fn bare(t: &Transaction) -> Vec<u8> {
    let mut t = t.clone();
    t.input.iter_mut().for_each(|i| i.witness = Witness::new());
    serialize(&t)
}

/// A block's header, as the statement reads it.
pub fn header(block: &Block) -> [u8; 80] {
    serialize(&block.header)
        .try_into()
        .expect("an 80-byte header")
}

fn position(block: &Block, txid: &Txid) -> Result<usize> {
    block
        .txdata
        .iter()
        .position(|t| t.compute_txid() == *txid)
        .context("the transaction is not in the block")
}

fn txids(block: &Block) -> Vec<[u8; 32]> {
    block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect()
}

/// Transaction `txid` in `block`, with its witness, by the witness tree:
/// the statement's `respond`.
pub fn respond(block: &Block, txid: &Txid) -> Result<Respond> {
    let index = position(block, txid)?;
    ensure!(index > 0, "a coinbase is no link");
    let coinbase = &block.txdata[0];
    // the witness tree: the coinbase's leaf is zero
    let wtxids: Vec<[u8; 32]> = std::iter::once([0u8; 32])
        .chain(
            block.txdata[1..]
                .iter()
                .map(|t| t.compute_wtxid().to_byte_array()),
        )
        .collect();
    let reserved: [u8; 32] = coinbase
        .input
        .first()
        .and_then(|i| i.witness.nth(0))
        .and_then(|w| w.try_into().ok())
        .unwrap_or([0; 32]);
    Ok(Respond {
        tx: serialize(&block.txdata[index]),
        header: header(block),
        index: index as u32,
        path: merkle_path(&wtxids, index),
        coinbase: bare(coinbase),
        coinbase_path: merkle_path(&txids(block), 0),
        reserved,
    })
}

/// `request` (`txid`) in `block`, with its witness, and the contract's
/// `funding`, whose output 0 it spends.
pub fn request(funding: &Transaction, block: &Block, txid: &Txid) -> Result<Request> {
    let r = respond(block, txid)?;
    Ok(Request {
        funding: bare(funding),
        tx: r.tx,
        header: r.header,
        index: r.index,
        path: r.path,
        coinbase: r.coinbase,
        coinbase_path: r.coinbase_path,
        reserved: r.reserved,
    })
}

/// Transaction `txid` in `block`, a slot's spender, her publication or
/// the hub's disclosure, as the contract's `carrier` reads it: by the txid
/// tree (its non-witness serialization) for nulldata, by the witness tree
/// (as [`respond`]) for a leaf's envelope.
pub fn slot_spend(block: &Block, txid: &Txid, carrier: Carrier) -> Result<SlotSpend> {
    if carrier == Carrier::Leaf {
        let r = respond(block, txid)?;
        return Ok(SlotSpend {
            tx: r.tx,
            header: r.header,
            index: r.index,
            path: r.path,
            coinbase: r.coinbase,
            coinbase_path: r.coinbase_path,
            reserved: Some(r.reserved),
        });
    }
    let index = position(block, txid)?;
    let ids = txids(block);
    Ok(SlotSpend {
        tx: bare(&block.txdata[index]),
        header: header(block),
        index: index as u32,
        path: merkle_path(&ids, index),
        coinbase: bare(&block.txdata[0]),
        coinbase_path: merkle_path(&ids, 0),
        reserved: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lichen_btc::bitcoin::block::{Header, Version as BlockVersion};
    use lichen_btc::bitcoin::transaction::Version;
    use lichen_btc::bitcoin::{
        absolute, Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, TxIn, TxMerkleNode, TxOut,
    };

    fn tx(inputs: &[OutPoint], witness: &[&[u8]], outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: inputs
                .iter()
                .map(|op| TxIn {
                    previous_output: *op,
                    witness: Witness::from_slice(witness),
                    ..Default::default()
                })
                .collect(),
            output: outputs,
        }
    }

    fn out(value: u64, script: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script),
        }
    }

    /// A block of `txs` after a coinbase committing to their witnesses.
    fn block(txs: Vec<Transaction>) -> Block {
        let coinbase = tx(&[OutPoint::null()], &[&[0u8; 32]], vec![out(0, vec![0x51])]);
        let mut block = Block {
            header: Header {
                version: BlockVersion::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: std::iter::once(coinbase).chain(txs).collect(),
        };
        let root = block.witness_root().unwrap();
        let commitment = Block::compute_witness_commitment(&root, &[0u8; 32]);
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend(commitment.to_byte_array());
        block.txdata[0].output.push(out(0, script));
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    /// The statement reads each transaction in its block as the chain
    /// has it: the request with its funding, a response, a publication's
    /// bytes; not one of another block.
    #[test]
    fn the_statement_reads_an_exits_transactions_in_their_blocks() {
        let to = |b: u8| licash_statement::btc::OutPoint {
            txid: [b; 32],
            vout: 0,
        };
        let deposit = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 0,
        };
        let funding = tx(
            &[deposit],
            &[&[1u8; 64]],
            vec![out(10_000, vec![0x51, 0x20])],
        );
        let request_tx = tx(
            &[OutPoint {
                txid: funding.compute_txid(),
                vout: 0,
            }],
            &[b"b and E", &[2u8; 64]],
            vec![out(9_000, vec![0x51])],
        );
        let slot = OutPoint {
            txid: request_tx.compute_txid(),
            vout: 2,
        };
        let published = tx(
            &[slot],
            &[&[3u8; 65]],
            vec![out(
                0,
                licash_statement::claim_script(b"the claim").unwrap(),
            )],
        );
        let filler = tx(
            &[OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 1,
            }],
            &[&[4u8; 33]],
            vec![out(1, vec![0x51])],
        );
        let b = block(vec![filler, request_tx.clone(), published.clone()]);
        let r = request(&funding, &b, &request_tx.compute_txid()).unwrap();
        let witness = r
            .spending(&licash_statement::btc::OutPoint {
                txid: deposit.txid.to_byte_array(),
                vout: 0,
            })
            .unwrap();
        assert_eq!(witness[0], b"b and E");
        let s = slot_spend(&b, &published.compute_txid(), Carrier::Nulldata).unwrap();
        let slot_op = slot;
        let slot = licash_statement::btc::OutPoint {
            txid: slot.txid.to_byte_array(),
            vout: 2,
        };
        assert_eq!(s.carrying(&slot).unwrap(), b"the claim");
        // in an envelope, by the witness tree: read under a leaf carrier
        // alone, its nulldata none
        let script = licash_statement::envelope_script(&[0x4b; 32], &[0xab; 2000]).unwrap();
        let mut revealed = tx(&[slot_op], &[&[3u8; 65]], vec![out(500, vec![0x51])]);
        revealed.input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xc7; 32]),
                vout: 0,
            },
            witness: Witness::from_slice(&[&[6u8; 64][..], &script, &[0xc0u8; 33]]),
            ..Default::default()
        });
        let b3 = block(vec![revealed.clone()]);
        let leaf = slot_spend(&b3, &revealed.compute_txid(), Carrier::Leaf).unwrap();
        assert_eq!(leaf.carrying(&slot).unwrap(), vec![0xab; 2000]);
        assert_eq!(leaf.txid(), Some(revealed.compute_txid().to_byte_array()));
        let bare = slot_spend(&b3, &revealed.compute_txid(), Carrier::Nulldata).unwrap();
        assert_eq!(bare.carrying(&slot).unwrap(), Vec::<u8>::new());
        // the response, spending the request's output 0
        let respond_tx = tx(
            &[OutPoint {
                txid: request_tx.compute_txid(),
                vout: 0,
            }],
            &[b"b'", &[5u8; 64]],
            vec![out(8_000, vec![0x51])],
        );
        let b2 = block(vec![respond_tx.clone()]);
        let r2 = respond(&b2, &respond_tx.compute_txid()).unwrap();
        assert_eq!(
            r2.spending(&request_tx.compute_txid().to_byte_array())
                .unwrap()[0],
            b"b'"
        );
        // another block's
        let mut wrong = r2.clone();
        wrong.header = header(&b);
        assert!(wrong
            .spending(&request_tx.compute_txid().to_byte_array())
            .is_none());
        assert!(respond(&b2, &request_tx.compute_txid()).is_err());
        assert!(s.carrying(&to(1)).is_none());
    }
}
