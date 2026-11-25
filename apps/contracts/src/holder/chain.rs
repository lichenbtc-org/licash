//! What a holder reads of Bitcoin and hands it, and the fate of her F.

use std::collections::HashMap;
use std::future::Future;

use anyhow::{anyhow, Result};
use bitcoin::block::Header;
use bitcoin::{Amount, Block, BlockHash, FeeRate, OutPoint, Transaction, Txid};
use licash::chain::Checkpoint;
use licash_contract::opening::{Fate, Holder};
use licash_wallet::Blocks;

/// The best chain as the holder's wallet sees it, and the network.
pub trait Chain: Blocks {
    /// The checkpoint at block `height` of the best chain: its header,
    /// and the times of the blocks before it.
    fn checkpoint(&self, height: u32) -> impl Future<Output = Result<Checkpoint, String>> + Send;

    /// Hand `tx` to the network; one it has already is no error.
    fn broadcast(&self, tx: &Transaction) -> impl Future<Output = Result<(), String>> + Send;

    /// Whether `txid` is in the network's mempool, as far as the chain
    /// can tell: none where it cannot, as by default.
    fn in_mempool(&self, txid: &Txid) -> impl Future<Output = Result<Option<bool>, String>> + Send {
        let _ = txid;
        async { Ok(None) }
    }

    /// Hand `txs`, a child after its parents, to the network as one
    /// package where the chain takes packages: a parent paying less than
    /// the mempool takes alone relays with its child. By default, each in
    /// turn.
    fn broadcast_package(
        &self,
        txs: &[Transaction],
    ) -> impl Future<Output = Result<(), String>> + Send {
        async move {
            for tx in txs {
                self.broadcast(tx).await?;
            }
            Ok(())
        }
    }

    /// The rate a transaction confirms at within `blocks`, as the chain
    /// estimates it: by default, from the chain alone, as a light client
    /// reads it (`fee_rate_of` of its last `RATE_BLOCKS` blocks).
    fn fee_rate(
        &self,
        blocks: u16,
    ) -> impl Future<Output = Result<Option<FeeRate>, String>> + Send {
        let _ = blocks;
        async move {
            let tip = self.height().await?;
            let mut rates = Vec::new();
            for height in tip.saturating_sub(RATE_BLOCKS - 1)..=tip {
                let block = self.block(&self.hash(height).await?).await?;
                rates.extend(fee_rate_of(&block, height));
            }
            Ok(rates.into_iter().max())
        }
    }

    /// The header of block `height` of the best chain: its block's, by
    /// default, which a chain that keeps headers answers at less cost.
    fn header(&self, height: u32) -> impl Future<Output = Result<Header, String>> + Send {
        async move {
            let hash = self.hash(height).await?;
            let block = self.block(&hash).await?;
            if block.block_hash() != hash {
                return Err(format!("block {hash} does not match its header"));
            }
            Ok(block.header)
        }
    }
}

/// The blocks the default [`Chain::fee_rate`] reads.
pub const RATE_BLOCKS: u32 = 3;

/// The rate the transactions of `block`, at `height`, paid on average: its
/// coinbase's fees over their size. Its subsidy halves every 210 000
/// blocks, or 150 on a regtest chain (of its proof of work's limit). None
/// for a block of nothing but its coinbase, or one claiming less than its
/// subsidy.
pub fn fee_rate_of(block: &Block, height: u32) -> Option<FeeRate> {
    let (coinbase, others) = block.txdata.split_first()?;
    let regtest = block.header.bits.to_consensus() == 0x207f_ffff;
    let interval = if regtest { 150 } else { 210_000 };
    let subsidy = match height / interval {
        epochs @ 0..64 => Amount::from_sat((50 * 100_000_000) >> epochs),
        _ => Amount::ZERO,
    };
    let paid: Amount = coinbase.output.iter().map(|o| o.value).sum();
    let fees = paid.checked_sub(subsidy)?;
    let weight: u64 = others.iter().map(|tx| tx.weight().to_wu()).sum();
    (weight > 0).then(|| FeeRate::from_sat_per_kwu(fees.to_sat() * 1_000 / weight))
}

/// Where `holder`'s F stands on `chain`, its inputs looked up in the
/// blocks from `since` to the tip, only those whose filter (where the
/// chain serves them) matches a coin they spend: none before she knows F.
/// Once live, with the block F is in, its height and hash: while the
/// chain keeps that block, F stays buried.
pub async fn fate(
    holder: &Holder,
    chain: &impl Chain,
    since: u32,
) -> Result<Option<(Fate, Option<(u32, BlockHash)>)>> {
    let Some(funding) = holder.funding() else {
        return Ok(None);
    };
    let txid = funding.tx.compute_txid();
    let inputs: Vec<OutPoint> = funding.tx.input.iter().map(|i| i.previous_output).collect();
    let scripts: Vec<&[u8]> = (funding.prevouts.iter())
        .map(|o| o.script_pubkey.as_bytes())
        .collect();
    let tip = chain.height().await.map_err(|e| anyhow!(e))?;
    let tip_hash = chain.hash(tip).await.map_err(|e| anyhow!(e))?;
    let mut spent: HashMap<OutPoint, (Txid, u32)> = HashMap::new();
    let mut found = None;
    for height in since..=tip {
        let hash = chain.hash(height).await.map_err(|e| anyhow!(e))?;
        // A filter that matches none of the coins F spends: no block of
        // them, F's or another's.
        if let Some(filter) = chain.filter(&hash).await.map_err(|e| anyhow!(e))? {
            if !bitcoin::bip158::BlockFilter::new(&filter)
                .match_any(&hash, scripts.iter().copied())?
            {
                continue;
            }
        }
        let block = chain.block(&hash).await.map_err(|e| anyhow!(e))?;
        anyhow::ensure!(
            block.block_hash() == hash,
            "block {hash} does not match its header"
        );
        for tx in &block.txdata {
            for input in &tx.input {
                if inputs.contains(&input.previous_output) {
                    let depth = tip - height + 1;
                    let by = tx.compute_txid();
                    if by == txid {
                        found = Some((height, hash));
                    }
                    spent.insert(input.previous_output, (by, depth));
                }
            }
        }
    }
    // Block by block, a reorganization meanwhile mixes the chains: a fate
    // of neither. Looked at again next time.
    still_best(chain, tip, tip_hash).await?;
    let fate = match holder.fate(|o| Ok::<_, std::convert::Infallible>(spent.get(&o).copied())) {
        Ok(fate) => fate,
        Err(e) => match e {},
    };
    Ok(fate.map(|fate| (fate, found.filter(|_| fate == Fate::Live))))
}

/// Refused unless the block of `hash` at `height` is still the best
/// chain's: what was read of it since is of one chain.
async fn still_best(chain: &impl Chain, height: u32, hash: BlockHash) -> Result<()> {
    let now = chain.hash(height).await.map_err(|e| anyhow!(e))?;
    anyhow::ensure!(
        now == hash,
        "the chain was reorganized while its blocks were read: block {height} is {now}, was {hash}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, ScriptBuf, TxIn, TxOut, Witness};

    fn block(coinbase: u64, others: usize, regtest: bool) -> Block {
        let tx = |value: u64, witness: usize| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                witness: Witness::from_slice(&[vec![0; witness]]),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut txdata = vec![tx(coinbase, 0)];
        txdata.extend((0..others).map(|_| tx(1_000, 400)));
        let network = match regtest {
            true => bitcoin::Network::Regtest,
            false => bitcoin::Network::Bitcoin,
        };
        Block {
            header: bitcoin::constants::genesis_block(network).header,
            txdata,
        }
    }

    /// A chain whose block at every height is `now`, changed at will.
    struct Drifting(std::sync::Mutex<BlockHash>);

    impl Blocks for Drifting {
        async fn height(&self) -> Result<u32, String> {
            Ok(7)
        }
        async fn hash(&self, _: u32) -> Result<BlockHash, String> {
            Ok(*self.0.lock().unwrap())
        }
        async fn filter(&self, _: &BlockHash) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn block(&self, _: &BlockHash) -> Result<Block, String> {
            Err("not asked".into())
        }
    }

    impl Chain for Drifting {
        async fn checkpoint(&self, _: u32) -> Result<Checkpoint, String> {
            Err("not asked".into())
        }
        async fn broadcast(&self, _: &Transaction) -> Result<(), String> {
            Err("not asked".into())
        }
    }

    #[tokio::test]
    async fn a_chain_reorganized_while_it_was_read_is_refused() {
        let (a, b) = (
            BlockHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([1; 32])),
            BlockHash::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([2; 32])),
        );
        let chain = Drifting(std::sync::Mutex::new(a));
        still_best(&chain, 7, a).await.unwrap();
        *chain.0.lock().unwrap() = b;
        let e = still_best(&chain, 7, a).await.unwrap_err().to_string();
        assert!(e.contains("reorganized"), "{e}");
    }

    #[test]
    fn a_blocks_fee_rate_is_its_coinbases_fees_over_its_other_transactions_size() {
        // Mainnet's fifth subsidy, 3.125 BTC, and 10 000 sat of fees.
        let mined = block(312_500_000 + 10_000, 2, false);
        let weight = mined.txdata[1].weight().to_wu() * 2;
        let rate = fee_rate_of(&mined, 900_000).unwrap();
        assert_eq!(rate.to_sat_per_kwu(), 10_000 * 1_000 / weight);
        // A regtest's at 300 blocks, 12.5 BTC: its fees alone.
        let regtest = fee_rate_of(&block(1_250_000_000 + 10_000, 2, true), 300).unwrap();
        assert_eq!(regtest, rate);
        // Its coinbase alone, or claiming less than its subsidy: none.
        assert_eq!(fee_rate_of(&block(312_500_000, 0, false), 900_000), None);
        assert_eq!(fee_rate_of(&block(300_000_000, 2, false), 900_000), None);
    }
}
