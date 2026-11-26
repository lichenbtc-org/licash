//! The hub's terms for contracts, on each network it offers them on.

use anyhow::{bail, ensure, Result};
use licash::base::{ChainTerms, Fees, GraphTerms, Limits, Recipe};
use licash::chain::Checkpoint;
use licash::note::Keyset;
use licash::recovery::{CHAINED_FROM, COMPACT_FROM, LEAF_FROM, LEAN_FROM, SIGNED_FROM};
use licash::spend::ChainProfile;
use licash_contract::graph::RETURNING;
use licash_contract::opening::{Bounds, Floors, Quote};

/// The most blocks the hub's collateral is locked for.
pub const LOCK: u32 = 1_000;

/// The headers a contract's budget reaches past its close, beyond the blocks
/// its collateral is locked for. Her request is spent by the hub's
/// response, and her publication of her claim stays valid until the hub's
/// default confirms, after the close: a claim judged on a chain cut short
/// there could never be proven. The slack covers the checkpoint's age, the
/// hub's default confirming, and the work buried on top of the publication.
pub const HEADER_SLACK: u32 = 144;

/// The blocks `quote`'s collateral is locked for: its header budget
/// ([`HEADER_SLACK`] more) less the slack.
pub fn lock_of(quote: &Quote) -> u32 {
    quote.chain.max_headers.saturating_sub(HEADER_SLACK)
}

/// The notes a contract of the fixed terms protects, in sat: the least
/// cap ([`licash_api::MIN_CAP`]).
pub const CAP: u32 = licash_api::MIN_CAP;

/// The holder's reserve, from her deposit.
pub const RESERVE_ALICE: u64 = 20_000;

/// The hub's fee for an opening, from her deposit, unless its operator
/// sets another ([`Timing::with_opening_fee`]): half a year's interest at
/// 20% on its own 100 000 sat reserve, which it locks in every contract,
/// whoever funds its cap.
pub const OPENING_FEE: u64 = 10_000;

/// The hub's reserve in F, from its wallet.
const RESERVE_HUB: u64 = 100_000;

/// What the hub's wallet keeps besides a contract's collateral and its
/// reserve, for F's fee and those of the hub's exits, in sat.
const FUNDING_MARGIN: u64 = 50_000;

/// The highest step of the hub's surcharge ([`Timing::at_step`]): its fee
/// 16 times its own, short of its most contracts.
pub const MAX_STEP: u32 = 4;

/// The step of the hub's surcharge with `live` of its most `max`
/// contracts live: none below half, then one more at each eighth more,
/// up to [`MAX_STEP`]. None once all are: it opens no more.
pub fn step(live: usize, max: usize) -> Option<u32> {
    if live >= max {
        return None;
    }
    let eighths = (live as u128 * 8 / max as u128) as u32;
    Some(eighths.saturating_sub(3).min(MAX_STEP))
}

/// The most F's and the graph's transactions pay, in sat per 1 000 vB.
pub(super) const MAX_RATE_SAT_PER_KVB: u64 = 10_000;

/// The most F's and the graph's transactions pay, in sat/vB.
pub fn quote_ceiling() -> f64 {
    MAX_RATE_SAT_PER_KVB as f64 / 1_000.0
}

/// The most notes a contract may protect, in sat: of a 31-bit graph
/// ([`licash_api::MAX_CAP`]).
pub const MAX_CAP: u32 = licash_api::MAX_CAP;

/// The largest cap the hub's wallet funds with `balance` sat: its graph's
/// payout, which pays exactly the cap ([`licash_api::is_cap`]); its
/// reserve; and `FUNDING_MARGIN`. None if not even the least is funded.
pub fn fundable(balance: u64) -> Option<u32> {
    let left = balance.checked_sub(RESERVE_HUB + FUNDING_MARGIN)?;
    licash_api::cap_at_most(left)
}

/// The caps and durations a hub lets holders choose besides its fixed
/// terms ([`CAP`] sat over [`LOCK`] blocks), as its operator sets them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    /// The most a contract protects, in sat: [`CAP`] to [`MAX_CAP`],
    /// taken down to a cap ([`licash_api::cap_at_most`]).
    pub max_cap: u32,
    /// The most blocks one lasts: [`LOCK`] at least.
    pub max_blocks: u32,
    /// Millionths of the part of its cap the hub funds a contract costs
    /// for each year it lasts, over the fixed price
    /// ([`licash_api::rate`]), of the fixed terms too.
    pub ppm_year: u32,
    /// Millionths of the part its holder funds herself, likewise.
    pub ppm_year_funded: u32,
}

/// The hub's timing on a network: the windows, delays and depths of its
/// quote, and its bounds; the terms holders may choose, if any.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    profile: ChainProfile,
    /// Blocks the holder has to challenge the hub's proof.
    challenge_window: u16,
    /// Blocks each party's own outputs wait to be spent.
    to_self_delay: u16,
    /// Blocks deep F, a request and a publication are taken as final.
    depth: u32,
    /// Blocks it has to respond to her request, at least.
    response_window: u16,
    /// The fewest blocks a contract chosen lasts: her deadlines leave
    /// time to recover in after a quote a few blocks old.
    min_blocks: u32,
    /// The blocks the fixed terms last ([`LOCK`] where the proof's window
    /// is signet's).
    lock: u32,
    /// The terms holders may choose, if any.
    range: Option<Range>,
    /// The step of the hub's surcharge: its fee, of its fixed terms and
    /// rate alike, `2^step` times its own.
    step: u32,
    /// Blocks of work its statement reads on top of her request's
    /// response, at least the network's floor ([`Timing::with_work_depth`]).
    work_depth: u32,
    /// The hub's own fee for an opening, before its surcharge.
    opening_fee: u64,
    /// Whether it quotes graphs that carry her claim and its disclosure
    /// in nulldata outputs where the program reads leaf envelopes too
    /// ([`Timing::with_nulldata`]).
    nulldata: bool,
}

/// The most blocks of work a hub may ask for beyond its network's floor:
/// a day's, which its windows and her deadlines lengthen by.
pub const MAX_EXTRA_WORK: u32 = 144;

impl Timing {
    /// The hub's timing on `profile`: on regtest, a test's few blocks; on
    /// signet, the least its floors allow ([`Quote::check`]), a day to
    /// answer and to wait, 3 blocks deep, and 12 blocks at least to
    /// respond to a request, for the publication to confirm 3 deep in
    /// them. Mutinynet's are signet's, counted in blocks as on every network
    /// but regtest, but for what its quicker blocks cannot hold: the hub's
    /// proof takes as long in hours as on signet, so its assert window is
    /// 20 times the blocks (`assert_window`), and the fewest blocks a
    /// contract lasts and the fixed terms' as many more. None elsewhere
    /// yet. Holders choose their terms within `range`, if any, the fixed
    /// terms among them.
    pub fn of(profile: ChainProfile, range: Option<Range>) -> Result<Self> {
        let (challenge_window, to_self_delay, depth, response_window, min_blocks, lock) =
            match profile {
                ChainProfile::Core30DefaultRegtest => (6, 6, 1, 2, 200, LOCK),
                // Four days: her deadlines 180 blocks before the close, her
                // day to contest a response before them.
                ChainProfile::Core30Signet => (144, 144, 3, 12, 576, LOCK),
                // Signet's, and the 912 blocks more its assert window has.
                ChainProfile::Mutinynet => (144, 144, 3, 12, 576 + 912, LOCK + 912),
                // Mainnet waits for windows set from a measured proof time and
                // a real proof played on Bitcoin; its hub reserve must then
                // cover the hub's answer to a challenge at some 25 sat/vB,
                // about 520 000 sat, not RESERVE_HUB's 100 000. And her reserve
                // must afford a forced close of the widest filing at its floor
                // (`licash_contract::reserve::reserve_for`: some 170 000 sat at
                // 10 sat/vB of the least cap, 182 000 of the largest, the hub's
                // at least twice that, her purse being at
                // most half of it), not RESERVE_ALICE's 20 000: quotes below
                // the floor are refused (`Quote::check`).
                _ => bail!("the hub offers no contracts on {profile} yet"),
            };
        if let Some(r) = range {
            ensure!(
                (CAP..=MAX_CAP).contains(&r.max_cap),
                "a contract's cap of {} sat at most: not {CAP} to {MAX_CAP}",
                r.max_cap
            );
            ensure!(
                r.max_blocks >= lock,
                "contracts of {} blocks at most: not {lock} at least",
                r.max_blocks
            );
        }
        let range = range.map(|r| Range {
            max_cap: licash_api::cap_at_most(u64::from(r.max_cap)).unwrap_or(CAP),
            ..r
        });
        Ok(Self {
            profile,
            challenge_window,
            to_self_delay,
            depth,
            response_window,
            min_blocks,
            lock,
            range,
            step: 0,
            work_depth: Floors::of(profile).work_depth,
            opening_fee: OPENING_FEE,
            nulldata: false,
        })
    }

    /// These terms, quoting graphs that carry her claim and the hub's
    /// disclosure in nulldata outputs ([`SIGNED_FROM`]) where the program
    /// trusted reads leaf envelopes ([`LEAF_FROM`]) too: as hubs before
    /// those did, so that both are played.
    pub fn with_nulldata(self) -> Self {
        Self {
            nulldata: true,
            ..self
        }
    }

    /// These terms, the hub's own fee for an opening `fee` sat, of the
    /// fixed terms and those chosen alike: what it charges for what it
    /// brings, its part of the cap priced by its rate besides.
    pub fn with_opening_fee(self, fee: u64) -> Self {
        Self {
            opening_fee: fee,
            ..self
        }
    }

    /// These terms, its statement reading `depth` blocks of work on top
    /// of her request's response, from the network's floor to
    /// [`MAX_EXTRA_WORK`] more: the more a private chain must carry to
    /// fool it, so the more value the hub's contracts may protect. Its
    /// assertion window and the fewest blocks a contract lasts grow as
    /// much, so that its prover has as long as at the floor.
    pub fn with_work_depth(self, depth: u32) -> Result<Self> {
        let floor = Floors::of(self.profile).work_depth;
        ensure!(
            (floor..=floor + MAX_EXTRA_WORK).contains(&depth),
            "{depth} blocks of work: not {floor} to {}",
            floor + MAX_EXTRA_WORK
        );
        Ok(Self {
            work_depth: depth,
            ..self
        })
    }

    /// Blocks of work asked beyond the network's floor.
    fn extra_work(&self) -> u32 {
        self.work_depth - Floors::of(self.profile).work_depth
    }

    /// Blocks from her request's response to its assertion's deadline,
    /// grown by the work asked beyond the floor.
    fn assert_window(&self) -> u16 {
        let extra = u16::try_from(self.extra_work()).expect("MAX_EXTRA_WORK fits");
        assert_window(self.profile) + extra
    }

    /// The fewest blocks a contract chosen lasts, grown by the work asked
    /// beyond the floor.
    fn min_blocks(&self) -> u32 {
        self.min_blocks + self.extra_work()
    }

    /// These terms, the hub's fee surcharged `step` steps
    /// ([`MAX_STEP`] at most): `2^step` times its own, as its contracts
    /// fill up ([`step`]).
    pub fn at_step(self, step: u32) -> Self {
        Self {
            step: step.min(MAX_STEP),
            ..self
        }
    }

    /// What the hub's fee is multiplied by, at its step.
    fn surcharge(&self) -> u32 {
        1 << self.step
    }

    /// The hub's fee for an opening, surcharged at its step.
    fn opening_fee(&self) -> u64 {
        self.opening_fee.saturating_mul(u64::from(self.surcharge()))
    }

    /// The terms holders may choose, if any, as the hub's info says them.
    pub fn range(&self) -> Option<licash_api::ContractRange> {
        self.range.map(|r| licash_api::ContractRange {
            min_cap: CAP,
            max_cap: r.max_cap,
            min_blocks: self.min_blocks(),
            max_blocks: r.max_blocks,
            // No bound on the cap by her coin: what she pays prices the hub's
            // part. Announced as none for wallets that read it as a bound.
            per_coin: u32::MAX,
            reserve: RESERVE_ALICE,
            fee: self.opening_fee(),
            ppm_year: r.ppm_year.saturating_mul(self.surcharge()),
            ppm_year_funded: r.ppm_year_funded.saturating_mul(self.surcharge()),
            year_blocks: self.profile.blocks_a_year(),
        })
    }

    /// The pricing of the hub's terms, chosen or fixed alike: its range's,
    /// or, offering the fixed terms only, its fixed fee and no interest.
    fn pricing(&self) -> licash_api::ContractRange {
        self.range().unwrap_or(licash_api::ContractRange {
            min_cap: CAP,
            max_cap: CAP,
            min_blocks: self.lock,
            max_blocks: self.lock,
            per_coin: 1,
            reserve: RESERVE_ALICE,
            fee: self.opening_fee(),
            ppm_year: 0,
            ppm_year_funded: 0,
            year_blocks: self.profile.blocks_a_year(),
        })
    }

    /// Refused unless a holder may ask for `cap` sat over `blocks`: the
    /// fixed terms, or terms within the hub's range, its cap any it
    /// pays exactly ([`licash_api::is_cap`]).
    pub fn allows(&self, cap: u32, blocks: u32) -> Result<()> {
        if (cap, blocks) == (CAP, self.lock) {
            return Ok(());
        }
        let Some(range) = self.range() else {
            bail!(
                "the hub offers contracts of {CAP} sat over {} blocks only",
                self.lock
            );
        };
        ensure!(
            range.allows_cap(cap),
            "a cap of {cap} sat: not one of {} to {} (its payout's rest, past 2^n - 1 sat, \
             none or {} sat at least)",
            range.min_cap,
            range.max_cap,
            licash_api::MIN_REST
        );
        ensure!(
            (range.min_blocks..=range.max_blocks).contains(&blocks),
            "{blocks} blocks: not {} to {}",
            range.min_blocks,
            range.max_blocks
        );
        Ok(())
    }

    /// What the hub's opening fee is for `cap` sat over `blocks`,
    /// `funded` of them funded by its holder: the fixed one, and its
    /// rates by the year on its part and on hers, all surcharged at its
    /// step, as its info says them ([`licash_api::ContractRange::fee`]).
    fn fee(&self, cap: u32, blocks: u32, funded: u32) -> u64 {
        self.pricing().fee(cap, blocks, funded).total()
    }

    /// What opening a contract of `cap` sat over `blocks`, `funded` of
    /// them hers, costs its holder, from her deposit: her reserve and the
    /// hub's fee.
    pub fn price(&self, cap: u32, blocks: u32, funded: u32) -> u64 {
        self.pricing().price(cap, blocks, funded)
    }

    /// How far beyond `quote` a holder may ask: the close its headers
    /// reach at most, and the hub's least response window.
    pub fn bounds(&self, quote: &Quote) -> Bounds {
        Bounds {
            lock: lock_of(quote),
            response_window: self.response_window,
        }
    }

    /// That the hub's locks, living `window` blocks at most
    /// (`--lock-window`), give a swap provider time to force its contract
    /// closed: it reads that window as the blocks the hub may take to
    /// respond ([`licash::route::Hop::window`]), so one below the
    /// contracts' least response window leaves its lead too short to be
    /// refunded in.
    pub fn covers_locks(&self, window: u32) -> Result<()> {
        ensure!(
            window >= u32::from(self.response_window),
            "a lock window of {window} blocks, below the contracts' response window of {}",
            self.response_window
        );
        Ok(())
    }

    /// The hub's fixed quote on `keyset` at `checkpoint`, of [`CAP`] sat
    /// over [`LOCK`] blocks: the one asked for without terms.
    /// The blocks the hub's prover has for a proof its quotes commit it
    /// to: the assert window less its response's burial, the block the
    /// assertion confirms in and the deadline margin (2).
    pub fn proof_blocks(&self) -> u32 {
        u32::from(self.assert_window())
            .saturating_sub(self.work_depth)
            .saturating_sub(1 + 2)
    }

    pub fn quote(&self, keyset: Keyset, checkpoint: Checkpoint) -> Quote {
        self.quote_for(keyset, checkpoint, CAP, self.lock, 0)
    }

    /// The blocks the fixed terms last: [`LOCK`], and the blocks more its
    /// proof's window has where that is longer than signet's.
    pub fn lock(&self) -> u32 {
        self.lock
    }

    /// The id of the graphs it quotes: those of the compact filing if the
    /// program contracts open under decides it, else the last before.
    fn graph_id(&self) -> u32 {
        match crate::trust(self.profile) {
            Ok(t) if t.chained.is_some() && t.own_claims && t.leaf && !self.nulldata => LEAF_FROM,
            Ok(t) if t.chained.is_some() && t.own_claims => SIGNED_FROM,
            Ok(t) if t.chained.is_some() => CHAINED_FROM,
            Ok(t) if t.lean => LEAN_FROM,
            Ok(t) if t.compact => COMPACT_FROM,
            _ => RETURNING,
        }
    }

    /// The hub's quote on `keyset` at `checkpoint` of `cap` sat over
    /// `blocks`, `funded` of them by its holder: a graph of 1-sat units
    /// whose payout pays the cap exactly ([`licash_api::payout_bits`], and
    /// one output of the rest), 17 bits at least, its headers reaching the
    /// close, its challenge 12 blocks, her reserve 20 000 sat and its fee
    /// 3 000 and its rates, its graph returning the hub its reserve if it
    /// never responds ([`RETURNING`]). Of [`CAP`] and [`LOCK`], none
    /// funded, the fixed quote.
    pub fn quote_for(
        &self,
        keyset: Keyset,
        checkpoint: Checkpoint,
        cap: u32,
        blocks: u32,
        funded: u32,
    ) -> Quote {
        let bits = licash_api::payout_bits(cap);
        let floors = Floors::of(self.profile);
        let (instances, kept) = match self.profile {
            ChainProfile::Core30DefaultRegtest => (4, 2),
            _ => (78, 10),
        };
        Quote {
            keyset,
            cap,
            graph: GraphTerms {
                id: self.graph_id(),
                unit_sats: 1,
                bits: bits.max(licash_api::payout_bits(CAP)),
                low_bits: 9,
                deposit_units: funded,
                close_height: 0,
                reserve_alice: RESERVE_ALICE,
                reserve_hub: RESERVE_HUB,
                to_self_delay: self.to_self_delay,
                commit_fee: 1_000,
                presign_fee: 1_000,
                dust: 330,
                delta: 6,
                delta_prime: 6,
                deadline_margin: 2,
                response_window: 0,
                request_height: 0,
                publication_window: floors.publication_window,
                contest_window: floors.contest_window,
                assert_window: self.assert_window(),
                challenge_window: self.challenge_window,
                answer_window: 12,
            },
            recipe: Recipe {
                graph_version: 2,
                program: [0; 32],
                instances,
                kept,
            },
            chain: ChainTerms {
                checkpoint,
                funding_depth: self.depth,
                work_depth: self.work_depth,
                max_headers: blocks.saturating_add(HEADER_SLACK),
            },
            limits: limits(),
            fees: Fees {
                max_rate_sat_per_kvb: MAX_RATE_SAT_PER_KVB,
                opening_fee_quote: self.fee(cap, blocks, funded),
            },
        }
    }
}

/// The limits the hub quotes: its statement reads any spend a proposal may
/// be ([`licash::base::MIN_AUTHORIZATIONS`]), so that whatever its ledger
/// retired notes for, it can cite against a claim of one.
fn limits() -> Limits {
    Limits {
        max_transaction_bytes: 100_000,
        max_publication_bytes: 64_000,
        max_authorizations: 128,
        max_source_inputs: 128,
    }
}

/// Blocks from her request's response to its assertion's deadline: the
/// response buried at its work depth, then the hub's proof made and its
/// assertion confirmed. Regtest's proof is the mock authority's, made at
/// once; elsewhere `hp-prove` took about 3.4 hours on a CPU (some 21
/// signet blocks), so 48 leave as many again for a slow prover or blocks.
/// Mutinynet's blocks come 20 times as quick, and a proof takes the hours
/// it takes: 960. It is the one window counted in time, not in blocks.
fn assert_window(profile: ChainProfile) -> u16 {
    match profile {
        ChainProfile::Core30DefaultRegtest => 12,
        ChainProfile::Mutinynet => 960,
        _ => 48,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use licash_contract::opening::Hub;
    use licash_contract::wire::Writer;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_quoted_limits_read_every_spend_the_hub_retires_notes_for() {
        let quoted = limits();
        assert!(quoted.max_authorizations >= licash::base::MIN_AUTHORIZATIONS);
        assert!(quoted.max_authorizations as usize >= licash::spend::MAX_INPUTS);
    }

    #[test]
    fn a_wallet_funds_the_widest_graph_it_holds_with_its_reserve_and_margin() {
        let narrowest = u64::from(CAP) + RESERVE_HUB + FUNDING_MARGIN;
        assert_eq!(fundable(narrowest), Some(CAP));
        assert_eq!(fundable(narrowest - 1), None);
        assert_eq!(fundable(0), None);
        // Half a bitcoin: all of it but the reserve and margin.
        assert_eq!(fundable(50_000_000), Some(49_850_000));
        // a rest of under 512 sat: down to the 17 bits
        assert_eq!(fundable(narrowest + 511), Some(CAP));
        assert_eq!(fundable(narrowest + 512), Some(CAP + 512));
        assert_eq!(fundable(u64::MAX), Some(MAX_CAP));
    }

    /// A hub's opening at Funded, of a mock opening on regtest: its keyset
    /// and checkpoint.
    fn funded() -> &'static [u8] {
        &crate::testing::opened().hub
    }

    fn digest(q: &Quote) -> String {
        let mut w = Writer(Vec::new());
        w.quote(q);
        hex::encode(Sha256::digest(&w.0))
    }

    /// The quote every app asking without terms of its own opens on:
    /// byte for byte as the hub quotes it, on each network. A hub letting
    /// holders choose prices the fixed terms by its rate as well, at 1% a
    /// year 24 sat more; one that doesn't, at its fixed fee alone (pinned at
    /// 3 000 sat, the default once, its bytes unchanged since). Regtest's
    /// mock decides the lean filing, so it quotes the graph of its id (10);
    /// signet's program reads the exit on the hub's header chain and owes a claim
    /// of the same contract no evidence against another, and quotes 14 (its
    /// hub cites spends by their signatures).
    #[test]
    fn the_fixed_quote_is_pinned() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset, parts.chain.checkpoint);
        let pinned = [
            (
                None,
                [
                    "8fae26f6c05403f2c15e693b79a73b8818b5e1462cff187b2d399910b3b34d6c",
                    "ce437f59f881e2c6ba564cf5847da678d8f8fd9ac0e8633f8468ec72cc15e1f9",
                ],
                3_000,
            ),
            (
                Some(RANGE),
                [
                    "18a3661c82de2e094636b000c485c17380dc8ce9914af6729cfc2c8087703a37",
                    "440d6f591159a77d7531a4080e983498dae5a10888ac0a29bc403f135882320e",
                ],
                3_024,
            ),
        ];
        for (range, [regtest_digest, signet_digest], fee) in pinned {
            let quoted = |profile| {
                let timing = Timing::of(profile, range).unwrap().with_opening_fee(3_000);
                let quote = timing.quote(keyset.clone(), checkpoint.clone());
                assert_eq!(quote.fees.opening_fee_quote, fee);
                assert_eq!((quote.cap, quote.graph.bits), (CAP, 17));
                assert_eq!(quote.graph.deposit_units, 0);
                (digest(&quote), timing.bounds(&quote))
            };
            let (regtest, bounds) = quoted(ChainProfile::Core30DefaultRegtest);
            assert_eq!(regtest, regtest_digest);
            assert_eq!((bounds.lock, bounds.response_window), (1_000, 2));
            let (signet, bounds) = quoted(ChainProfile::Core30Signet);
            assert_eq!(signet, signet_digest);
            let at = Timing::of(ChainProfile::Core30Signet, range)
                .unwrap()
                .with_opening_fee(3_000);
            let graph = at.quote(keyset.clone(), checkpoint.clone()).graph.id;
            assert_eq!(graph, licash::recovery::SIGNED_FROM);
            // Regtest quotes the graph its mock reads, leaf envelopes, and
            // the signets' told to.
            let regtest = Timing::of(ChainProfile::Core30DefaultRegtest, range).unwrap();
            let graph = regtest.quote(keyset.clone(), checkpoint.clone()).graph.id;
            assert_eq!(graph, licash::recovery::LEAF_FROM);
            let graph = (regtest
                .with_nulldata()
                .quote(keyset.clone(), checkpoint.clone()))
            .graph
            .id;
            assert_eq!(graph, licash::recovery::SIGNED_FROM);
            assert_eq!((bounds.lock, bounds.response_window), (1_000, 12));
        }
    }

    /// A graph of the compact filing is quoted where the program trusted
    /// decides it, and only there: under one that doesn't, her claim would
    /// be owed nothing.
    #[test]
    fn a_hub_quotes_the_compact_filing_only_under_a_program_that_decodes_it() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        for profile in [
            ChainProfile::Core30DefaultRegtest,
            ChainProfile::Core30Signet,
            ChainProfile::Mutinynet,
        ] {
            let trust = crate::trust(profile).unwrap();
            let timing = Timing::of(profile, None).unwrap();
            let quote = timing.quote(parts.keyset.clone(), parts.chain.checkpoint.clone());
            let compact = quote.graph.id >= COMPACT_FROM;
            assert_eq!(compact, trust.compact, "{profile}");
            // No program that decodes only the legacy filing is the one
            // contracts open under.
            assert!(!crate::programs_before(profile).contains(&trust.program));
        }
    }

    /// Up to 100 M sat (67 108 863, a size) over half a year, at 1% a year.
    const RANGE: Range = Range {
        max_cap: 100_000_000,
        max_blocks: 26_280,
        ppm_year: 10_000,
        ppm_year_funded: 0,
    };

    /// Her publication of her claim may land until the hub's default
    /// confirms after the close, the claim's work buried on it: whatever
    /// close the bounds allow, the quote's headers reach past both.
    #[test]
    fn the_header_budget_outlasts_the_latest_close_the_bounds_allow() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset.clone(), parts.chain.checkpoint.clone());
        // A tip as far past the checkpoint as a quote is still taken at.
        let skew = 12;
        for profile in [
            ChainProfile::Core30DefaultRegtest,
            ChainProfile::Core30Signet,
            ChainProfile::Mutinynet,
        ] {
            let timing = Timing::of(profile, None).unwrap();
            let quote = timing.quote(keyset.clone(), checkpoint.clone());
            let bounds = timing.bounds(&quote);
            assert_eq!(bounds.lock, timing.lock(), "{profile:?}");
            let close = checkpoint.height() + skew + bounds.lock;
            let budget = checkpoint.height() + quote.chain.max_headers;
            let after = u32::from(quote.graph.publication_window) + quote.chain.work_depth;
            assert!(
                budget >= close + after,
                "{profile:?}: {budget} < {close} + {after}"
            );
        }
    }

    #[test]
    fn a_quote_chosen_is_as_wide_as_its_cap_and_as_long_as_its_blocks() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset.clone(), parts.chain.checkpoint.clone());
        let timing = Timing::of(ChainProfile::Core30Signet, Some(RANGE)).unwrap();
        let fixed = timing.quote(keyset.clone(), checkpoint.clone());
        let quote =
            |cap, blocks| timing.quote_for(keyset.clone(), checkpoint.clone(), cap, blocks, 0);

        // 16 777 215 sat for half a year, 83 886 sat of interest over the
        // opening fee, of a 24-bit graph its headers reaching the close.
        let chosen = quote(16_777_215, 26_280);
        assert_eq!(chosen.cap, 16_777_215);
        assert_eq!(chosen.graph.bits, 24);
        assert_eq!(chosen.chain.max_headers, 26_280 + HEADER_SLACK);
        assert_eq!(lock_of(&chosen), 26_280);
        assert_eq!(chosen.fees.opening_fee_quote, OPENING_FEE + 83_886);
        assert_eq!(chosen.graph.deposit_units, 0);
        // Half of it hers: interest on the hub's half only, her part in
        // the graph's deposit.
        let half = timing.quote_for(
            keyset.clone(),
            checkpoint.clone(),
            16_777_215,
            26_280,
            8_388_607,
        );
        assert_eq!(half.fees.opening_fee_quote, OPENING_FEE + 41_943);
        assert_eq!(half.graph.deposit_units, 8_388_607);
        assert_eq!(
            timing.price(16_777_215, 26_280, 8_388_607),
            20_000 + OPENING_FEE + 41_943
        );
        assert_eq!(timing.bounds(&chosen).lock, 26_280);
        // But for those, as the fixed quote is.
        let mut same = chosen.clone();
        same.cap = fixed.cap;
        same.graph.bits = fixed.graph.bits;
        same.chain.max_headers = fixed.chain.max_headers;
        same.fees.opening_fee_quote = fixed.fees.opening_fee_quote;
        assert_eq!(digest(&same), digest(&fixed));

        // Each 2^n - 1 of n bits, its graph's payout all ones, and any
        // other cap of as many as its binary outputs pay at most, its rest
        // one output more: the hub locks what it protects, 17 bits to 31.
        let base = |q: &Quote| {
            licash::base::Base::new(licash::base::Parts {
                cap: q.cap,
                graph: GraphTerms {
                    bits: q.graph.bits,
                    ..parts.graph.clone()
                },
                ..parts.clone()
            })
        };
        for n in 17..=31u8 {
            let q = quote(((1u64 << n) - 1) as u32, 1_000);
            assert_eq!(q.graph.bits, n);
            assert_eq!(base(&q).unwrap().parts().pool().unwrap(), q.cap);
        }
        for (cap, bits) in [
            (200_000, 17),
            (1_000_000, 19),
            (CAP + 512, 17),
            (MAX_CAP, 31),
        ] {
            let q = quote(cap, 1_000);
            assert_eq!(q.graph.bits, bits, "{cap}");
            let base = base(&q).unwrap();
            assert_eq!(
                base.parts().pool().unwrap(),
                cap,
                "the pool the cap exactly"
            );
            assert_eq!(
                base.parts().graph_value().unwrap(),
                u64::from(cap) + 120_000
            );
        }
    }

    /// Past half its most contracts, the hub's fee doubles at each eighth
    /// more, up to 16 times; it opens none once all are live.
    #[test]
    fn the_fee_doubles_at_each_eighth_past_half_the_most_contracts() {
        let steps: Vec<_> = (0..=32).map(|live| step(live, 32)).collect();
        assert_eq!(&steps[..16], &[Some(0); 16]);
        assert_eq!(&steps[16..20], &[Some(1); 4]);
        assert_eq!(&steps[20..24], &[Some(2); 4]);
        assert_eq!(&steps[24..28], &[Some(3); 4]);
        assert_eq!(&steps[28..32], &[Some(4); 4]);
        assert_eq!(steps[32], None);
        assert_eq!((step(0, 1), step(1, 1), step(5, 0)), (Some(0), None, None));
        assert_eq!(step(usize::MAX - 1, usize::MAX), Some(MAX_STEP));
    }

    /// At each step, the quote, the price and the range wallets price
    /// with agree: the hub's fee and rate surcharged alike, her reserve
    /// not.
    #[test]
    fn a_surcharged_quote_costs_what_the_info_says() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset, parts.chain.checkpoint);
        let timing = Timing::of(ChainProfile::Core30Signet, Some(RANGE)).unwrap();
        for step in 0..=MAX_STEP + 1 {
            let at = timing.at_step(step);
            let m = 1u64 << step.min(MAX_STEP);
            let range = at.range().unwrap();
            assert_eq!((range.reserve, range.fee), (RESERVE_ALICE, OPENING_FEE * m));
            assert_eq!(u64::from(range.ppm_year), 10_000 * m);
            for (cap, blocks, funded) in [
                (CAP, LOCK, 0),
                (16_777_215, 26_280, 0),
                (16_777_215, 26_280, 8_388_607),
            ] {
                let quote = at.quote_for(keyset.clone(), checkpoint.clone(), cap, blocks, funded);
                let fee = quote.fees.opening_fee_quote;
                assert_eq!(at.price(cap, blocks, funded), RESERVE_ALICE + fee);
                assert_eq!(range.price(cap, blocks, funded), RESERVE_ALICE + fee);
            }
            let chosen = at.quote_for(keyset.clone(), checkpoint.clone(), 16_777_215, 26_280, 0);
            let year = licash_api::YEAR_BLOCKS;
            let interest = licash_api::rate(10_000 * m as u32, 16_777_215, 26_280, year);
            assert_eq!(chosen.fees.opening_fee_quote, OPENING_FEE * m + interest);
        }
        // Step 0, the quote as it always was.
        let quote = |t: Timing| digest(&t.quote(keyset.clone(), checkpoint.clone()));
        assert_eq!(quote(timing.at_step(0)), quote(timing));
        assert_ne!(quote(timing.at_step(1)), quote(timing));
    }

    /// The operator's fee for an opening is the one quoted, announced and
    /// surcharged, of the fixed terms and those chosen alike; by default,
    /// the quote as it always was.
    #[test]
    fn the_operators_opening_fee_is_the_one_quoted_and_announced() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset, parts.chain.checkpoint);
        let quote = |t: Timing| digest(&t.quote(keyset.clone(), checkpoint.clone()));
        for range in [None, Some(RANGE)] {
            let timing = Timing::of(ChainProfile::Core30Signet, range).unwrap();
            assert_eq!(quote(timing.with_opening_fee(OPENING_FEE)), quote(timing));
            for (fee, step) in [(0, 0), (50_000, 0), (50_000, 2), (u64::MAX, MAX_STEP)] {
                let at = timing.with_opening_fee(fee).at_step(step);
                let fee = fee.saturating_mul(1 << step);
                let fixed = at.quote_for(keyset.clone(), checkpoint.clone(), CAP, LOCK, 0);
                let interest = fixed.fees.opening_fee_quote.checked_sub(fee).unwrap();
                assert_eq!(
                    at.price(CAP, LOCK, 0),
                    RESERVE_ALICE.saturating_add(fee + interest)
                );
                assert_eq!(at.range().map(|r| r.fee), range.map(|_| fee));
            }
        }
    }

    /// Work asked beyond the floor lengthens the assertion window and the
    /// shortest contract by as much, the prover's time unchanged; at the
    /// floor, the quote is as it always was.
    #[test]
    fn more_work_lengthens_the_assertion_window_by_as_much() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset, parts.chain.checkpoint);
        for profile in [
            ChainProfile::Core30DefaultRegtest,
            ChainProfile::Core30Signet,
            ChainProfile::Mutinynet,
        ] {
            let timing = Timing::of(profile, Some(RANGE)).unwrap();
            let floor = Floors::of(profile).work_depth;
            let quote = |t: &Timing| t.quote(keyset.clone(), checkpoint.clone());
            let at_floor = timing.with_work_depth(floor).unwrap();
            assert_eq!(digest(&quote(&at_floor)), digest(&quote(&timing)));
            let deeper = timing.with_work_depth(floor + MAX_EXTRA_WORK).unwrap();
            let (base, more) = (quote(&timing), quote(&deeper));
            assert_eq!(more.chain.work_depth, floor + MAX_EXTRA_WORK);
            assert_eq!(
                u32::from(more.graph.assert_window),
                u32::from(base.graph.assert_window) + MAX_EXTRA_WORK
            );
            more.check(profile).unwrap();
            assert_eq!(deeper.proof_blocks(), timing.proof_blocks());
            let (shortest, longer) = (timing.range().unwrap(), deeper.range().unwrap());
            assert_eq!(longer.min_blocks, shortest.min_blocks + MAX_EXTRA_WORK);
            for wrong in [floor.saturating_sub(1), floor + MAX_EXTRA_WORK + 1] {
                if wrong != floor {
                    assert!(timing.with_work_depth(wrong).is_err(), "{profile} {wrong}");
                }
            }
        }
    }

    #[test]
    fn holders_choose_within_the_hubs_range_whatever_their_coin() {
        let fixed = Timing::of(ChainProfile::Core30Signet, None).unwrap();
        assert!(fixed.range().is_none());
        assert!(fixed.allows(CAP, LOCK).is_ok());
        let error = fixed.allows(CAP, LOCK - 1).unwrap_err();
        assert!(error.to_string().contains("only"), "{error}");

        let timing = Timing::of(ChainProfile::Core30Signet, Some(RANGE)).unwrap();
        let range = timing.range().unwrap();
        // Its largest cap the operator's.
        assert_eq!((range.min_cap, range.max_cap), (CAP, 100_000_000));
        assert_eq!((range.min_blocks, range.max_blocks), (576, 26_280));
        // No bound by her coin: announced as none, for wallets that read one.
        assert_eq!(
            (range.per_coin, range.reserve, range.fee, range.ppm_year),
            (u32::MAX, 20_000, OPENING_FEE, 10_000)
        );
        assert!(timing.allows(CAP, LOCK).is_ok());
        assert!(timing.allows(67_108_863, 26_280).is_ok());
        assert!(timing.allows(100_000_000, 26_280).is_ok());
        assert!(timing.allows(1_048_575, 576).is_ok());
        assert!(timing.allows(15_000_000, LOCK).is_ok());
        assert!(timing.allows(1_048_575 + 512, LOCK).is_ok());
        for (cap, blocks) in [
            (CAP - 1, LOCK),
            (CAP + 1, LOCK),
            (1_048_576, LOCK),
            (1_048_575 + 511, LOCK),
            (100_000_001, LOCK),
            (134_217_727, LOCK),
            (CAP, 575),
            (CAP, 26_281),
        ] {
            assert!(timing.allows(cap, blocks).is_err(), "{cap} {blocks}");
        }

        // Out of bounds, refused as the hub starts.
        let wider = |r: Range| Timing::of(ChainProfile::Core30Signet, Some(r)).is_err();
        assert!(wider(Range {
            max_cap: MAX_CAP + 1,
            ..RANGE
        }));
        assert!(wider(Range {
            max_cap: CAP - 1,
            ..RANGE
        }));
        assert!(wider(Range {
            max_blocks: LOCK - 1,
            ..RANGE
        }));
    }

    /// Mutinynet's terms are signet's blocks but for its proof's window,
    /// which is counted in time: 960 of its blocks are as many hours as
    /// signet's 48, and the fixed contract and the shortest chosen are as
    /// many blocks longer. Its interest counts a year of its own blocks.
    #[test]
    fn mutinynets_terms_are_signets_in_blocks_but_for_the_proofs_window_and_its_year() {
        let parts = Hub::peek(funded()).unwrap().base.parts().clone();
        let (keyset, checkpoint) = (parts.keyset, parts.chain.checkpoint);
        let signet = Timing::of(ChainProfile::Core30Signet, Some(RANGE)).unwrap();
        let mutinynet = Timing::of(ChainProfile::Mutinynet, Some(RANGE)).unwrap();
        let (s, m) = (
            signet.quote(keyset.clone(), checkpoint.clone()),
            mutinynet.quote(keyset, checkpoint),
        );
        m.check(ChainProfile::Mutinynet).unwrap();
        let windows = |q: &Quote| {
            let (g, c) = (&q.graph, &q.chain);
            let (challenge, delay) = (g.challenge_window, g.to_self_delay);
            (challenge, delay, g.publication_window, c.funding_depth)
        };
        assert_eq!(windows(&m), windows(&s));
        assert_eq!((s.graph.assert_window, m.graph.assert_window), (48, 960));
        assert!(
            f64::from(mutinynet.proof_blocks()) * 30.0 >= f64::from(signet.proof_blocks()) * 600.0
        );
        let longer = 960 - 48;
        assert_eq!(mutinynet.lock(), signet.lock() + longer);
        let (a, b) = (signet.range().unwrap(), mutinynet.range().unwrap());
        assert_eq!(b.min_blocks, a.min_blocks + longer);
        assert_eq!((a.year_blocks, b.year_blocks), (52_560, 1_051_200));
        for timing in [&signet, &mutinynet] {
            let range = timing.range().unwrap();
            assert!(timing.allows(CAP, timing.lock()).is_ok());
            assert!(timing.allows(CAP, range.min_blocks).is_ok());
            assert!(timing.allows(CAP, range.min_blocks - 1).is_err());
        }
        // The same half year of interest, in 20 times the blocks.
        assert_eq!(
            a.fee(16_777_215, 26_280, 0),
            b.fee(16_777_215, 26_280 * 20, 0)
        );
        assert!(Timing::of(
            ChainProfile::Mutinynet,
            Some(Range {
                max_blocks: mutinynet.lock() - 1,
                ..RANGE
            })
        )
        .is_err());
    }

    /// A lock window as long as the contracts' response window or longer
    /// is admitted, one shorter refused; the hub service's default (144)
    /// covers every network's.
    #[test]
    fn the_lock_window_must_cover_the_contracts_response_window() {
        let signet = Timing::of(ChainProfile::Core30Signet, None).unwrap();
        assert!(signet.covers_locks(12).is_ok());
        assert!(signet.covers_locks(144).is_ok());
        let short = signet.covers_locks(11).unwrap_err();
        assert!(
            format!("{short}").contains("response window of 12"),
            "{short}"
        );
        // The hub service's default lock window, 144 blocks.
        for profile in [
            ChainProfile::Core30DefaultRegtest,
            ChainProfile::Core30Signet,
            ChainProfile::Mutinynet,
        ] {
            let timing = Timing::of(profile, None).unwrap();
            assert!(timing.covers_locks(144).is_ok(), "{profile}");
        }
    }
}
