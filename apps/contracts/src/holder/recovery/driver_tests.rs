//! Lifecycle tests after selection, on an explicit mock statement and a
//! synthetic chain. The real graph's signatures and amounts are retained.
use super::*;
use bitcoin::{block, hashes::Hash as _, Block, BlockHash, Network, ScriptBuf};
use licash::spend::ChainProfile;
use licash_contract::opening::{Hub, Trust};
use licash_wallet::{Blocks, Response as HttpResponse};
use std::{collections::BTreeMap, sync::Mutex};

struct Offline;
impl Transport for Offline {
    async fn request(&self, _: &str, _: Option<Vec<u8>>) -> Result<HttpResponse, String> {
        Err("no network in a driver test".into())
    }
}
struct Ledger {
    blocks: Mutex<BTreeMap<u32, Block>>,
    sent: Mutex<Vec<Transaction>>,
    /// Told apart, the blocks of each branch.
    branch: std::sync::atomic::AtomicU32,
}
impl Ledger {
    fn new() -> Self {
        Self {
            blocks: Mutex::new(BTreeMap::from([(
                0,
                bitcoin::blockdata::constants::genesis_block(Network::Regtest),
            )])),
            sent: Mutex::new(vec![]),
            branch: Default::default(),
        }
    }
    /// The blocks above `height` replaced by none, for others to be mined.
    fn reorg(&self, height: u32) {
        self.blocks.lock().unwrap().retain(|&h, _| h <= height);
        self.branch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn mine(&self, tx: Option<Transaction>) -> u32 {
        let mut blocks = self.blocks.lock().unwrap();
        let (&height, previous) = blocks.last_key_value().unwrap();
        let tx = tx.unwrap_or(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut next = Block {
            header: block::Header {
                prev_blockhash: previous.block_hash(),
                time: previous.header.time + 600,
                nonce: self.branch.load(std::sync::atomic::Ordering::SeqCst),
                ..previous.header
            },
            txdata: vec![tx],
        };
        next.header.merkle_root = next.compute_merkle_root().unwrap();
        blocks.insert(height + 1, next);
        height + 1
    }
    fn to(&self, height: u32) {
        while *self.blocks.lock().unwrap().last_key_value().unwrap().0 < height {
            self.mine(None);
        }
    }
    fn last(&self) -> Transaction {
        self.sent.lock().unwrap().last().unwrap().clone()
    }
}
impl Blocks for Ledger {
    async fn height(&self) -> Result<u32, String> {
        Ok(*self.blocks.lock().unwrap().last_key_value().unwrap().0)
    }
    async fn hash(&self, height: u32) -> Result<BlockHash, String> {
        self.blocks
            .lock()
            .unwrap()
            .get(&height)
            .map(Block::block_hash)
            .ok_or("no block".into())
    }
    async fn filter(&self, _: &BlockHash) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    async fn block(&self, hash: &BlockHash) -> Result<Block, String> {
        self.blocks
            .lock()
            .unwrap()
            .values()
            .find(|b| b.block_hash() == *hash)
            .cloned()
            .ok_or("no block".into())
    }
}
impl Chain for Ledger {
    async fn checkpoint(&self, _: u32) -> Result<licash::chain::Checkpoint, String> {
        Err("selection already completed".into())
    }
    async fn broadcast(&self, tx: &Transaction) -> Result<(), String> {
        self.sent.lock().unwrap().push(tx.clone());
        Ok(())
    }
}

/// A contract opened, its hub's and her machines loaded, no recovery yet,
/// on a chain of its genesis alone.
struct World {
    dir: tempfile::TempDir,
    wallet: Wallet<Offline>,
    holder: Holder,
    hub: Hub,
    keys: HolderKeys,
    store: Store,
    chain: Ledger,
    id: [u8; 32],
}
impl World {
    fn new() -> Self {
        use super::super::store::New;
        let dir = tempfile::tempdir().unwrap();
        let wallet = Wallet::create(
            &dir.path().join("wallet.sqlite"),
            &[7; 32],
            ChainProfile::Core30DefaultRegtest,
            Offline,
        )
        .unwrap();
        let saved = crate::testing::opened();
        assert_eq!(wallet.contract_secrets().seed, saved.seed);
        let ctx = Context {
            tip: 0,
            trust: Trust::mock(),
        };
        let holder = Holder::load(&saved.holder, &saved.seed, &ctx).unwrap();
        let hub = Hub::load(&saved.hub, &ctx).unwrap();
        let id = holder.id();
        let keys = HolderKeys::derive(&saved.seed, &id);
        let store = Store::open(&crate::testing::wallet_file(dir.path())).unwrap();
        let o = holder.signed().unwrap();
        let deposit = o.base.deposit_outpoint();
        store
            .insert(&New {
                id,
                hub: "http://hub.example",
                mock: true,
                deposit: OutPoint {
                    txid: Txid::from_byte_array(deposit.txid),
                    vout: deposit.index,
                },
                value: 60000,
                price: 23000,
                cap: o.base.parts().cap,
                assert_height: o.base.parts().graph.request_height,
                close_height: o.base.parts().graph.close_height,
                since: 0,
                state: &saved.holder,
            })
            .unwrap();
        Self {
            dir,
            wallet,
            holder,
            hub,
            keys,
            store,
            chain: Ledger::new(),
            id,
        }
    }
    /// Her publication, as it reads: its claim, then her fee coin.
    fn p(&self) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::from_sat(20000),
                    script_pubkey: dispute::fee_script(&self.keys.party.payment).unwrap(),
                },
            ],
        }
    }
    /// Her request of 4096, in the genesis block, as the chain reads.
    fn r(&self) -> Transaction {
        let o = self.holder.signed().unwrap();
        o.request(&self.keys, 4096, &[22; 32]).unwrap()
    }
    /// Her recovery at `stage` with `state`, irrevocable.
    fn start(&self, stage: Stage, state: &State) {
        let bytes = state.encode();
        (self.store)
            .start_recovery(&self.id, FORMAT, stage.as_str(), &bytes)
            .unwrap();
        assert!(self
            .store
            .save_recovery(
                &self.id,
                (stage.as_str(), &bytes),
                stage.as_str(),
                true,
                &bytes
            )
            .unwrap());
    }
    fn state(&self) -> State {
        State::decode(&self.store.recovery(&self.id).unwrap().unwrap()).unwrap()
    }
    /// Her state edited by `edit`, at the stage it is at.
    fn edit(&self, edit: impl FnOnce(&mut State)) {
        let row = self.store.recovery(&self.id).unwrap().unwrap();
        let mut state = State::decode(&row).unwrap();
        edit(&mut state);
        assert!(self
            .store
            .save_recovery(
                &self.id,
                (&row.stage, &row.state),
                &row.stage,
                true,
                &state.encode()
            )
            .unwrap());
    }
    async fn advance(&self) -> Vec<Recovery> {
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        advance(
            &self.wallet,
            &self.chain,
            &self.dir.path().join("wallet.sqlite"),
            rate,
        )
        .await
        .unwrap()
    }
    fn tip(&self) -> u32 {
        *self
            .chain
            .blocks
            .lock()
            .unwrap()
            .last_key_value()
            .unwrap()
            .0
    }
}

/// `tx` with its first input's witness told apart from any made anew,
/// its txid the same.
fn marked(tx: &Transaction) -> Transaction {
    let mut tx = tx.clone();
    let mut items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    items.push(vec![0xee; 3]);
    tx.input[0].witness = Witness::from_slice(&items);
    tx
}

async fn lifecycle(amount: u32, altered: bool, answer: bool, reorged: bool) {
    let w = World::new();
    let World {
        dir,
        wallet,
        holder,
        hub,
        keys: _,
        store,
        chain,
        id,
    } = &w;
    let id = *id;
    let o = holder.signed().unwrap();
    let ho = hub.signed().unwrap();
    let response = ho.respond(hub.keys(), amount).unwrap();
    let contest = o.contest(&w.keys).unwrap();
    let proof = lichen_babe::statement::mock_prove(&licash_contract::graph::journal(&o.base));
    let assertion = ho.assert(hub.keys(), &proof).unwrap();
    chain.mine(Some(response.clone()));
    // She contested: only a contested response is proven.
    chain.mine(Some(contest.clone()));
    let state = State {
        amount: 4096,
        reduced: Some(amount),
        r: Some(w.r()),
        r_height: Some(0),
        response: Some(response),
        response_height: Some(1),
        contest: Some(contest),
        contest_height: Some(2),
        p: Some(w.p()),
        from: Some(2),
        ..State::default()
    };
    w.start(Stage::Contested, &state);
    // A fee payout awaited, of no payout of the wallet's: nothing waits on
    // it, the stage and the rest of the state as they were.
    expect_fee(
        &dir.path().join("wallet.sqlite"),
        &id,
        FeeFor::Challenge,
        "cd",
    )
    .unwrap();
    let row = store.recovery(&id).unwrap().unwrap();
    assert_eq!(row.stage, Stage::Contested.as_str());
    let expected = State::decode(&row).unwrap();
    assert_eq!(expected.challenge_payout.as_deref(), Some("cd"));
    assert_eq!(expected.fee_payout, None);
    assert_eq!(expected.r, state.r);
    let rate = FeeRate::from_sat_per_vb(2).unwrap();
    let needs = fee_needs(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
        .await
        .unwrap();
    // No coin of hers for a challenge, none under way: one to pay out.
    assert_eq!(
        needs,
        vec![FeeNeed {
            id,
            purpose: FeeFor::Challenge,
            amount: challenge_reserve(rate),
            by: None,
        }]
    );
    let mut mined = assertion.clone();
    if altered {
        let mut witness: Vec<_> = mined.input[0].witness.iter().map(|v| v.to_vec()).collect();
        witness[0] = vec![];
        witness[1] = vec![];
        mined.input[0].witness = Witness::from_slice(&witness);
    }
    let asserted_at = chain.mine(Some(mined.clone()));
    let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
        .await
        .unwrap();
    let observed = State::decode(&store.recovery(&id).unwrap().unwrap()).unwrap();
    assert_eq!(observed.verified, Some(!altered));
    let initial = if altered {
        Stage::Challenging
    } else {
        Stage::Asserted
    };
    assert_eq!(progressed[0].stage, initial, "{progressed:?}");
    let pinned = observed.assertion.clone();
    advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
        .await
        .unwrap();
    assert_eq!(
        State::decode(&store.recovery(&id).unwrap().unwrap())
            .unwrap()
            .assertion,
        pinned,
        "retry must not select a different assertion or amount"
    );
    let paid_at = if altered {
        let challenge = observed_challenge(store, &id);
        let mut challenged_at = chain.mine(Some(challenge.clone()));
        let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
            .await
            .unwrap();
        assert_eq!(progressed[0].stage, Stage::Challenged, "{progressed:?}");
        if reorged {
            // The assertion's block and her challenge's replaced, the
            // assertion in a later one: her challenge the same again,
            // nothing revealed anew.
            // Told apart from one made anew: kept, not made again.
            w.edit(|s| s.challenge = Some(marked(&challenge)));
            let tip = w.tip();
            chain.reorg(asserted_at - 1);
            chain.mine(None);
            chain.mine(Some(mined.clone()));
            chain.to(tip);
            let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
                .await
                .unwrap();
            assert_eq!(progressed[0].stage, Stage::Challenging, "{progressed:?}");
            assert_eq!(observed_challenge(store, &id), marked(&challenge));
            challenged_at = chain.mine(Some(challenge.clone()));
            let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
                .await
                .unwrap();
            assert_eq!(progressed[0].stage, Stage::Challenged, "{progressed:?}");
        }
        if answer {
            // Pi2/Pi3 are not signed. Even if a miner alters them, the hub
            // retains its original proof and can answer the challenge.
            let i = ho.kept[0];
            let bytes = holder.instance(i).unwrap();
            let tx = ho
                .answer(&assertion, None, &challenge, i, &bytes)
                .unwrap()
                .unwrap();
            chain.mine(Some(tx))
        } else {
            let delay = blocks(presign(&o.set, "failure").unwrap().tx.input[0].sequence).unwrap();
            chain.to(challenged_at + delay - 1);
            let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
                .await
                .unwrap();
            assert_eq!(progressed[0].stage, Stage::TimingOut, "{progressed:?}");
            chain.mine(Some(chain.last()))
        }
    } else {
        let delay = blocks(presign(&o.set, "success").unwrap().tx.input[0].sequence).unwrap();
        chain.to(asserted_at + delay - 1);
        let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
            .await
            .unwrap();
        assert_eq!(progressed[0].stage, Stage::Succeeding, "{progressed:?}");
        chain.mine(Some(chain.last()))
    };
    let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
        .await
        .unwrap();
    if amount == 0 && !altered {
        // A corrected zero leaves her nothing of the payout to collect.
        let done = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
            .await
            .unwrap();
        assert_eq!(done[0].stage, Stage::Done, "{progressed:?} {done:?}");
        assert_eq!(done[0].received, Some(0));
        return;
    }
    if progressed[0].stage != Stage::Sweeping {
        assert!(
            matches!(progressed[0].stage, Stage::Paid | Stage::TimedOut),
            "{progressed:?}"
        );
        chain.to(progressed[0]
            .next_at
            .unwrap_or(paid_at + 6)
            .saturating_sub(1));
        let progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
            .await
            .unwrap();
        assert_eq!(progressed[0].stage, Stage::Sweeping, "{progressed:?}");
    }
    let sweep = chain.last();
    if reorged {
        // The payout's block replaced, the payout in a later one: found
        // there again, and the same sweep posted.
        let pinned = w.state();
        assert_eq!(pinned.sweep.as_ref(), Some(&sweep));
        let payout = pinned.payout.clone().unwrap();
        // Told apart from one made anew: kept, not made again.
        w.edit(|s| s.sweep = Some(marked(&sweep)));
        let tip = w.tip();
        chain.reorg(paid_at - 1);
        chain.mine(None);
        let again = chain.mine(Some(payout.clone()));
        // As long as the chain she saw, at least: no sign till then.
        chain.to(tip);
        let mut progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
            .await
            .unwrap();
        let state = State::decode(&store.recovery(&id).unwrap().unwrap()).unwrap();
        assert_eq!(state.payout_height, Some(again), "{progressed:?}");
        assert_eq!(state.payout, Some(payout));
        if progressed[0].stage != Stage::Sweeping {
            chain.to(progressed[0].next_at.unwrap() - 1);
            progressed = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
                .await
                .unwrap();
        }
        assert_eq!(progressed[0].stage, Stage::Sweeping, "{progressed:?}");
        assert_eq!(chain.last(), marked(&sweep));
        assert_eq!(w.state().sweep, Some(marked(&sweep)));
    }
    assert!(sweep.output[0].value >= sweep.output[0].script_pubkey.minimal_non_dust());
    let received = sweep.output[0].value.to_sat();
    chain.mine(Some(sweep));
    let done = advance(wallet, chain, &dir.path().join("wallet.sqlite"), rate)
        .await
        .unwrap();
    assert_eq!(done[0].stage, Stage::Done, "{done:?}");
    assert_eq!(done[0].corrected, Some(amount as u64));
    assert_eq!(done[0].received, Some(received));
    assert_eq!(done[0].claimed, 4096);
    assert_eq!(
        State::decode(&store.recovery(&id).unwrap().unwrap())
            .unwrap()
            .reduced,
        Some(amount)
    );
}

/// Her timeout in a block, then that block replaced by one of the hub's
/// answer: followed as answered, her payout forgotten.
#[tokio::test]
async fn a_timeout_a_reorganization_swaps_for_the_hubs_answer_is_followed_as_answered() {
    let w = World::new();
    let o = w.holder.signed().unwrap();
    let ho = w.hub.signed().unwrap();
    let response = ho.respond(w.hub.keys(), 4096).unwrap();
    w.start(
        Stage::Requested,
        &State {
            amount: 4096,
            r: Some(w.r()),
            r_height: Some(0),
            p: Some(w.p()),
            p_height: Some(0),
            from: Some(0),
            ..State::default()
        },
    );
    let delay = blocks(presign(&o.set, "request_timeout").unwrap().tx.input[0].sequence).unwrap();
    w.chain.to(delay - 1);
    let progressed = w.advance().await;
    assert_eq!(progressed[0].stage, Stage::TimingOut, "{progressed:?}");
    let paid_at = w.chain.mine(Some(w.chain.last()));
    let progressed = w.advance().await;
    assert_eq!(progressed[0].stage, Stage::TimedOut, "{progressed:?}");
    let tip = w.tip() + 1;
    w.chain.reorg(paid_at - 1);
    w.chain.mine(Some(response.clone()));
    w.chain.to(tip);
    let progressed = w.advance().await;
    // Offline she cannot check what it responded on, and her window gone
    // she contests it.
    assert_eq!(progressed[0].stage, Stage::Contesting, "{progressed:?}");
    let state = w.state();
    assert_eq!((state.payout, state.payout_name), (None, None));
    assert_eq!(state.response_height, Some(paid_at));
    assert_eq!(state.response, Some(response));
}

/// A reorganization deeper than her scan looks back puts the hub's
/// assertion below where she scanned to, her request's answer standing:
/// found all the same.
#[tokio::test]
async fn an_assertion_a_reorganization_puts_below_her_scan_is_found() {
    let w = World::new();
    let o = w.holder.signed().unwrap();
    let ho = w.hub.signed().unwrap();
    let response = ho.respond(w.hub.keys(), 4096).unwrap();
    let contest = o.contest(&w.keys).unwrap();
    let proof = lichen_babe::statement::mock_prove(&licash_contract::graph::journal(&o.base));
    let assertion = ho.assert(w.hub.keys(), &proof).unwrap();
    w.chain.mine(Some(response.clone()));
    w.chain.mine(Some(contest.clone()));
    w.start(
        Stage::Contested,
        &State {
            amount: 4096,
            reduced: Some(4096),
            r: Some(w.r()),
            r_height: Some(0),
            response: Some(response),
            response_height: Some(1),
            contest: Some(contest),
            contest_height: Some(2),
            p: Some(w.p()),
            from: Some(2),
            ..State::default()
        },
    );
    assert_eq!(w.advance().await[0].stage, Stage::Contested);
    // As far as she waits for it, her contest's timeout not yet due.
    let due = 2 + blocks(presign(&o.set, "contest_timeout").unwrap().tx.input[0].sequence).unwrap();
    let tip = due - 2;
    assert!(tip > 3 + OVERLAP + 1, "a timeout of {due} leaves no room");
    w.chain.to(tip);
    assert_eq!(w.advance().await[0].stage, Stage::Contested);
    assert!(
        w.state().from > Some(3 + OVERLAP),
        "scanned past where it lands"
    );
    w.chain.reorg(2);
    let asserted_at = w.chain.mine(Some(assertion));
    w.chain.to(tip);
    let progressed = w.advance().await;
    assert_eq!(progressed[0].stage, Stage::Asserted, "{progressed:?}");
    assert_eq!(w.state().assertion_height, Some(asserted_at));
}

/// Her claim answered `amount` and proven, P confirmed with her fee coin
/// worth `fee`: the hub's `success` (no fee coin of hers) mined instead
/// of hers, then advanced until her sweep is posted, if any. What she
/// was at last, and the sweep.
async fn the_hub_pays_success(amount: u32, fee: u64) -> (World, Recovery, Option<Transaction>) {
    let w = World::new();
    let o = w.holder.signed().unwrap();
    let ho = w.hub.signed().unwrap();
    let response = ho.respond(w.hub.keys(), amount).unwrap();
    let contest = o.contest(&w.keys).unwrap();
    let proof = lichen_babe::statement::mock_prove(&licash_contract::graph::journal(&o.base));
    let assertion = ho.assert(w.hub.keys(), &proof).unwrap();
    let mut p = w.p();
    p.output[1].value = Amount::from_sat(fee);
    w.chain.mine(Some(response.clone()));
    w.chain.mine(Some(contest.clone()));
    w.start(
        Stage::Contested,
        &State {
            amount: 4096,
            reduced: Some(amount),
            r: Some(w.r()),
            r_height: Some(0),
            response: Some(response),
            response_height: Some(1),
            contest: Some(contest),
            contest_height: Some(2),
            p: Some(p),
            p_height: Some(0),
            from: Some(2),
            ..State::default()
        },
    );
    let asserted_at = w.chain.mine(Some(assertion));
    assert_eq!(w.advance().await[0].stage, Stage::Asserted);
    let delay = blocks(presign(&o.set, "success").unwrap().tx.input[0].sequence).unwrap();
    w.chain.to(asserted_at + delay - 1);
    assert_eq!(w.advance().await[0].stage, Stage::Succeeding);
    // The hub's, its own fee coin paying it: none of hers spent.
    let hubs = o.finish("success", vec![]).unwrap();
    let paid_at = w.chain.mine(Some(hubs.clone()));
    let mut progressed = w.advance().await.remove(0);
    if progressed.stage != Stage::Sweeping && !progressed.stage.over() {
        w.chain
            .to(progressed.next_at.unwrap_or(paid_at + 6).saturating_sub(1));
        progressed = w.advance().await.remove(0);
    }
    assert_eq!(w.state().payout, Some(hubs));
    let sweep = (progressed.stage == Stage::Sweeping).then(|| w.chain.last());
    (w, progressed, sweep)
}

/// The hub's terminal paying her, not hers: the fee coin P left her for
/// it is swept with her payout, not left on an address her wallet never
/// looks at (1,338 sat of a Mutinynet claim were).
#[tokio::test]
async fn the_fee_coin_left_by_the_hubs_terminal_is_swept_with_her_payout() {
    let (w, progressed, sweep) = the_hub_pays_success(4096, 4096).await;
    assert_eq!(progressed.stage, Stage::Sweeping, "{progressed:?}");
    let sweep = sweep.unwrap();
    let p = w.state().p.unwrap();
    let fee_coin = OutPoint {
        txid: p.compute_txid(),
        vout: 1,
    };
    assert_eq!(sweep.input.last().unwrap().previous_output, fee_coin);
    assert!(sweep.output[0].value.to_sat() > 4096, "{sweep:?}");
    let received = sweep.output[0].value.to_sat();
    w.chain.mine(Some(sweep));
    let done = w.advance().await.remove(0);
    assert_eq!(done.stage, Stage::Done, "{done:?}");
    assert_eq!(done.received, Some(received));
}

/// Owed nothing, the hub's terminal pays her nothing: her fee coin is
/// swept alone, and the sweep followed as any.
#[tokio::test]
async fn her_fee_coin_alone_is_swept_when_the_hubs_terminal_pays_her_nothing() {
    let (w, progressed, sweep) = the_hub_pays_success(0, 4096).await;
    assert_eq!(progressed.stage, Stage::Sweeping, "{progressed:?}");
    let sweep = sweep.unwrap();
    assert_eq!(sweep.input.len(), 1);
    assert_eq!(
        sweep.input[0].previous_output.txid,
        w.state().p.unwrap().compute_txid()
    );
    let received = sweep.output[0].value.to_sat();
    assert!(received < 4096 && received > 3_000, "{received}");
    // The payout's block replaced, the payout in a later one: the same
    // sweep posted again, as a block may hold it.
    w.edit(|s| s.sweep = Some(marked(&sweep)));
    let payout = w.state().payout.unwrap();
    let paid_at = w.state().payout_height.unwrap();
    let tip = w.tip();
    w.chain.reorg(paid_at - 1);
    w.chain.mine(None);
    w.chain.mine(Some(payout));
    w.chain.to(tip);
    let mut progressed = w.advance().await.remove(0);
    if progressed.stage != Stage::Sweeping {
        w.chain.to(progressed.next_at.unwrap() - 1);
        progressed = w.advance().await.remove(0);
    }
    assert_eq!(progressed.stage, Stage::Sweeping, "{progressed:?}");
    assert_eq!(w.state().sweep, Some(marked(&sweep)));
    w.chain.mine(Some(sweep));
    let done = w.advance().await.remove(0);
    assert_eq!(done.stage, Stage::Done, "{done:?}");
    assert_eq!(done.received, Some(received));
}

/// A fee coin worth more than its input's fee but too little to sweep
/// alone: nothing posted, done as before, not stuck trying.
#[tokio::test]
async fn a_fee_coin_too_small_to_sweep_alone_is_left_and_the_recovery_done() {
    let (_w, progressed, sweep) = the_hub_pays_success(0, 400).await;
    assert_eq!(progressed.stage, Stage::Done, "{progressed:?}");
    assert_eq!(sweep, None);
    assert_eq!(progressed.received, Some(0));
}

fn observed_challenge(store: &Store, id: &[u8; 32]) -> Transaction {
    State::decode(&store.recovery(id).unwrap().unwrap())
        .unwrap()
        .challenge
        .unwrap()
}

#[tokio::test]
async fn hub_receipts_collect_the_selected_amount_including_zero() {
    lifecycle(0, false, false, false).await;
    lifecycle(4096, false, false, false).await;
}
#[tokio::test]
async fn an_invalid_assertion_pays_the_claim_when_no_answer_arrives() {
    lifecycle(15, true, false, false).await;
}
#[tokio::test]
async fn a_payout_whose_block_leaves_the_chain_is_found_again_and_swept_alike() {
    lifecycle(4096, false, false, true).await;
    lifecycle(15, true, false, true).await;
}
#[tokio::test]
#[ignore = "reconstructs garbled instances; run in release mode"]
async fn a_retained_hub_receipt_answers_a_challenge_and_collects() {
    // Not 15: corrected to that, her payout rounds down to no output of
    // hers, nothing to collect.
    lifecycle(4096, true, true, false).await;
}

fn signed() -> (Opening, HolderKeys) {
    signed_of(crate::testing::opened())
}

fn signed_of(saved: &crate::testing::Opened) -> (Opening, HolderKeys) {
    let ctx = Context {
        tip: 0,
        trust: Trust::mock(),
    };
    let holder = Holder::load(&saved.holder, &saved.seed, &ctx).unwrap();
    let keys = HolderKeys::derive(&saved.seed, &holder.id());
    (holder.signed().unwrap(), keys)
}

/// `request` pays her all her reserve but the dust limit (at most half
/// the hub's), for her forced close's fees, at the vout after its slot; where the hub's proof stands
/// she gets that much less of her reserve, and the hub's is as before.
#[test]
fn a_request_pays_her_purse_of_her_reserve_and_each_ends_with_what_it_would() {
    let (o, keys) = signed();
    let g = &o.base.parts().graph;
    let (r_a, r_h, dust) = (g.reserve_alice, g.reserve_hub, g.dust);
    let purse = o.babe.purse().unwrap().to_sat();
    assert_eq!(purse, (r_a - dust).min(r_h / 2));
    let r = o.request(&keys, 4096, &[22; 32]).unwrap();
    assert_eq!(r.output.len(), 4);
    // Her claim's slot just before it, where the statement reads it.
    assert_eq!(r.output[PURSE_VOUT as usize - 1].value.to_sat(), 330);
    let mine = dispute::fee_script(&keys.party.payment).unwrap();
    assert_eq!(r.output[PURSE_VOUT as usize].value.to_sat(), purse);
    assert_eq!(r.output[PURSE_VOUT as usize].script_pubkey, mine);
    let value = o.babe.value().to_sat();
    let bits = (g.low_bits..g.bits).count();
    let paid = |name: &str| {
        let p = presign(&o.set, name).unwrap();
        // What the links before it took of the contract, her purse too.
        (p.tx.output.clone(), value - p.prevout.value.to_sat())
    };
    // Her claim stands: both reserves less what the links took, her purse
    // among it, which she has.
    for name in ["request_timeout", "contest_timeout", "failure"] {
        let (outs, taken) = paid(name);
        assert_eq!(outs[bits].value.to_sat(), r_a + r_h - taken, "{name}");
    }
    // The hub's response stands, uncontested or proven: her reserve less
    // her purse, to her payout script; the hub's less the links' floors
    // alone.
    for name in ["respond_timeout", "success", "wrongly_challenged_0"] {
        let (outs, taken) = paid(name);
        assert_eq!(outs[bits].value.to_sat(), r_a - purse, "{name}");
        assert_eq!(outs[bits].script_pubkey, o.babe.core().pubs[0].payout_spk);
        assert_eq!(
            outs[bits + 1].value.to_sat(),
            r_h - (taken - purse),
            "{name}"
        );
    }
}

/// From graph id `RETURNING` on, a hub that never responds pays her claim
/// and her request's fees but keeps the rest of its reserve:
/// `request_timeout` pays her bits as before, all her reserve, her purse
/// refunded, to her reserve output, and the hub its reserve less what the
/// links took, her purse among it; the other exits pay as before.
#[test]
fn a_silent_hub_of_a_returning_graph_pays_her_claim_and_gets_its_reserve_back() {
    let (o, _) = signed_of(crate::testing::opened_returning());
    let g = &o.base.parts().graph;
    assert_eq!(g.id, licash_contract::graph::RETURNING);
    let (r_a, r_h) = (g.reserve_alice, g.reserve_hub);
    let purse = o.babe.purse().unwrap().to_sat();
    let value = o.babe.value().to_sat();
    let bits = (g.low_bits..g.bits).count();
    let paid = |name: &str| {
        let p = presign(&o.set, name).unwrap();
        (p.tx.clone(), value - p.prevout.value.to_sat())
    };
    let (timeout, taken) = paid("request_timeout");
    let (responded, _) = paid("contest_timeout");
    assert_eq!(timeout.output[..bits], responded.output[..bits]);
    assert_eq!(timeout.output[bits].value.to_sat(), r_a);
    assert_eq!(
        timeout.output[bits].script_pubkey,
        responded.output[bits].script_pubkey
    );
    let pubs = &o.babe.core().pubs;
    // With the bits below `low_bits`, the hub's as on every exit.
    let below = (1u64 << g.low_bits) - 1;
    assert_eq!(timeout.output[bits + 1].value.to_sat(), r_h - taken + below);
    assert_eq!(timeout.output[bits + 1].script_pubkey, pubs[1].payout_spk);
    assert_eq!(timeout.output.len(), bits + 2);
    // Hers to sweep: her bits and her reserve output, as on any exit she
    // signed.
    let core = o.babe.core();
    let owned = core
        .owned(&timeout, &o.holder.b_key, Role::User, 4096, Role::User)
        .unwrap();
    let reserve = owned
        .iter()
        .find(|out| out.leaf == "alice_reserve")
        .unwrap();
    assert_eq!(reserve.out.value.to_sat(), r_a);
    assert!(taken > purse);
    // Her claim stands on the others: both reserves, as before.
    for name in ["contest_timeout", "failure"] {
        let (tx, taken) = paid(name);
        assert_eq!(tx.output[bits].value.to_sat(), r_a + r_h - taken, "{name}");
    }
}

/// A contract opened under graph id 7 (as every one opened before
/// `RETURNING`) still loads, the holder's and the hub's, their stored signatures
/// checked against the graph they were signed under: its `request_timeout` pays her both reserves.
#[test]
fn a_contract_of_an_earlier_graph_id_loads_and_pays_as_it_was_signed() {
    let saved = crate::testing::opened_before();
    let (o, _) = signed_of(saved);
    let g = &o.base.parts().graph;
    assert_eq!(g.id, 7);
    let ctx = Context {
        tip: 0,
        trust: Trust::mock(),
    };
    let hub = Hub::load(&saved.hub, &ctx).unwrap();
    assert_eq!(hub.phase(), licash_contract::opening::HubPhase::Funded);
    let p = presign(&o.set, "request_timeout").unwrap();
    let bits = (g.low_bits..g.bits).count();
    let taken = o.babe.value().to_sat() - p.prevout.value.to_sat();
    assert_eq!(
        p.tx.output[bits].value.to_sat(),
        g.reserve_alice + g.reserve_hub - taken
    );
}

/// A contract the hub signed under another graph (opened before `request`
/// paid her purse, say): no forced close, as its request would be invalid.
#[test]
fn a_request_the_hub_signed_under_another_graph_is_refused() {
    let (mut o, keys) = signed();
    let respond = o.offer.sigs["respond"].clone();
    o.offer.sigs.insert("request".into(), respond);
    let refused = o.request(&keys, 4096, &[22; 32]).unwrap_err();
    assert!(
        format!("{refused:#}").contains("opened under an older protocol"),
        "{refused:#}"
    );
}

/// What each transaction of a dispute weighs, as the chain would see it,
/// from the graph's own builders: the table `docs/r0.md` quotes, and
/// bounds that keep it from growing unnoticed. The publication's claim is
/// not here (its size is its filing's), nor the hub's disclosure (1 024
/// bytes of nulldata).
#[test]
fn a_dispute_is_made_of_transactions_of_known_size() {
    let (o, keys) = signed();
    let w = World::new();
    let ho = w.hub.signed().unwrap();
    let proof = lichen_babe::statement::mock_prove(&licash_contract::graph::journal(&o.base));
    let r = o.request(&keys, 4096, &[22; 32]).unwrap();
    let respond = ho.respond(w.hub.keys(), 2048).unwrap();
    let contest = o.contest(&keys).unwrap();
    let assertion = ho.assert(w.hub.keys(), &proof).unwrap();
    let challenge = o.challenge(&keys, &assertion).unwrap();
    // Each terminal with its fee coin, as its poster broadcasts it.
    let fee = |name: &str| {
        let p = presign(&o.set, name).unwrap();
        let coin = TxOut {
            value: DUST,
            script_pubkey: dispute::fee_script(&keys.party.payment).unwrap(),
        };
        dispute::add_fee(
            o.finish(name, vec![]).unwrap(),
            p.prevout.clone(),
            (OutPoint::null(), coin),
            &keys.party.payment,
        )
        .unwrap()
    };
    let table: Vec<(&str, usize, usize)> = vec![
        ("request", r.vsize(), 2_300),
        ("respond", respond.vsize(), 600),
        ("contest", contest.vsize(), 300),
        ("assert", assertion.vsize(), 8_000),
        ("challenge_assert", challenge.vsize(), 21_500),
        ("respond_timeout", fee("respond_timeout").vsize(), 800),
        ("contest_timeout", fee("contest_timeout").vsize(), 800),
        ("request_timeout", fee("request_timeout").vsize(), 800),
        ("success", fee("success").vsize(), 800),
        ("failure", fee("failure").vsize(), 800),
    ];
    for (name, vsize, most) in table {
        eprintln!("{name:>18}: {vsize:>6} vB");
        assert!(vsize <= most, "{name} weighs {vsize} vB, more than {most}");
    }
    // Each terminal weighs no more than her reserve counts for it, with the
    // margin her fee coin is made at, of this graph and of the widest: its
    // payout's outputs added, the rest's too, each like the others.
    let mut g = o.base.parts().graph.clone();
    let paid = (g.low_bits..g.bits).count();
    let mut widest = 0;
    for name in [
        "respond_timeout",
        "contest_timeout",
        "request_timeout",
        "success",
        "failure",
    ] {
        let mut tx = fee(name);
        widest = widest.max(tx.vsize() as u64);
        let counted = licash_contract::reserve::terminal_vsize(&g);
        assert!(
            TIMEOUT_FEE_MARGIN * tx.vsize() as u64 <= counted,
            "{name} of {paid} outputs"
        );
        let output = tx.output[0].clone();
        for _ in paid..(31 - g.low_bits as usize + 1) {
            tx.output.insert(0, output.clone());
        }
        let mut wide = g.clone();
        wide.bits = 31;
        let counted = licash_contract::reserve::terminal_vsize(&wide);
        assert!(
            TIMEOUT_FEE_MARGIN * tx.vsize() as u64 <= counted,
            "{name} of 31 bits and a rest"
        );
    }
    // The widest exactly as counted of as many outputs, a bit fewer and a
    // rest's, at her margin.
    g.bits -= 1;
    let counted = licash_contract::reserve::terminal_vsize(&g);
    assert_eq!(TIMEOUT_FEE_MARGIN * widest, counted);
}

/// A claim its statement would find wrong, and owe nothing, is told so
/// before anything of it is published.
#[tokio::test]
async fn a_claim_its_statement_would_owe_nothing_is_told_before_it_is_filed() {
    let w = World::new();
    let o = w.holder.signed().unwrap();
    let request = Request {
        amount: 4096,
        claim_digest: [22; 32],
    };
    let refused = owed_whole(&w.chain, &o.base, &request, &[1, 2, 3], w.tip())
        .await
        .unwrap();
    let why = refused.unwrap_err();
    assert!(why.contains("would owe her claim nothing"), "{why}");
}
