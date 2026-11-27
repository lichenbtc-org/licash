//! The receipts of the Lightning gateway a hub of an earlier release ran
//! (`lightning_receipts` in its `hub.sqlite`), read only. Hubs convert
//! nothing now: providers pay and receive over Lightning for their own
//! notes. What such a gateway recorded still reserves its hashes, backs the
//! own locks it made, and, while it owes anything, stops the hub
//! (`check_gateway_idle` in `main.rs`).

use std::{collections::HashSet, path::Path};

use crate::peer;

/// The component the receipts' table is, and its version.
pub(crate) const COMPONENT: &str = "lightning";
pub(crate) const VERSION: i64 = 2;

/// Which of `hashes` the receipts in the hub's database at `db` hold, if a
/// gateway ever ran there.
pub fn holding(db: &Path, hashes: &[[u8; 32]]) -> anyhow::Result<HashSet<[u8; 32]>> {
    peer::recorded_in(
        db,
        COMPONENT,
        "SELECT 1 FROM lightning_receipts WHERE hash = ?1",
        hashes,
    )
}
