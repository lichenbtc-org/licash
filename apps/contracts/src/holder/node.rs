//! A node or an Esplora API as a holder's chain.

use bitcoin::{BlockHash, Transaction};
use licash::chain::Checkpoint;
use licash_chain_client::Source;
use licash_wallet::Blocks;

use super::Chain;

/// A node or an Esplora API, as a holder's chain.
pub struct Node(pub Source);

fn text(e: anyhow::Error) -> String {
    format!("{e:#}")
}

impl Blocks for Node {
    async fn height(&self) -> Result<u32, String> {
        Ok(self.0.tip().await.map_err(text)?.height)
    }

    async fn hash(&self, height: u32) -> Result<BlockHash, String> {
        self.0.hash(height).await.map_err(text)
    }

    async fn filter(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        self.0.filter(hash).await.map_err(text)
    }

    async fn block(&self, hash: &BlockHash) -> Result<bitcoin::Block, String> {
        self.0.block(hash).await.map_err(text)
    }
}

impl Chain for Node {
    async fn checkpoint(&self, height: u32) -> Result<Checkpoint, String> {
        self.0.checkpoint(height).await.map_err(text)
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<(), String> {
        self.0.broadcast(tx).await.map(|_| ()).map_err(text)
    }

    /// The node's mempool, or Esplora's mempool and chain.
    async fn in_mempool(&self, txid: &bitcoin::Txid) -> Result<Option<bool>, String> {
        self.0.holds(txid).await.map(Some).map_err(text)
    }

    async fn broadcast_package(&self, txs: &[Transaction]) -> Result<(), String> {
        self.0
            .broadcast_package(txs)
            .await
            .map(|_| ())
            .map_err(text)
    }

    /// The node's or Esplora's estimate.
    async fn fee_rate(&self, blocks: u16) -> Result<Option<bitcoin::FeeRate>, String> {
        self.0.fee_rate(blocks).await.map_err(text)
    }

    /// The node's header alone, not its block's.
    async fn header(&self, height: u32) -> Result<bitcoin::block::Header, String> {
        let hash = self.0.hash(height).await.map_err(text)?;
        self.0.header(&hash).await.map_err(text)
    }
}
