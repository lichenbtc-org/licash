//! What a holder's reserve pays for a forced close: her request R and her
//! publication P as one package (P spends R's anchor, so R's fee waits on
//! it), and the fee coin her later terminals are paid from.
//!
//! Her reserve is what R hands her (the claim slot, the anchor and her
//! purse, [`graph::purse`]) and no more: a wrong fee rate or a bug can't
//! spend beyond it. So the rate a forced close pays at most is a function
//! of the contract's terms and of the notes it files, and a quote whose
//! reserve affords too low a rate for the filing the protocol allows is
//! one a forced close may not get confirmed at.

use licash::{base::GraphTerms, claim::MAX_ITEMS, recovery::Format};
use lichen_btc::bitcoin::Amount;

use crate::graph::{self, SLOT};

/// R's virtual size: fixed by the protocol, a one-time signature of `b`
/// and of `E` (measured on regtest, 2,154 vB).
pub const R_VSIZE: u64 = 2_160;

/// A terminal with its fee coin, but for its payout's outputs (measured:
/// 668 vB with 8 of them, the widest of the terminals, `success` and
/// `respond_timeout`).
pub const TERMINAL_FIXED_VSIZE: u64 = 324;

/// Each output of a terminal's payout, a P2TR output.
pub const PAYOUT_OUTPUT_VSIZE: u64 = 43;

/// The margin the holder puts on a terminal's vsize, making its fee coin:
/// her `TIMEOUT_FEE_MARGIN`.
const TERMINAL_MARGIN: u64 = 2;

/// The vsize of the widest terminal her fee coin pays in a graph of `g`'s
/// terms, with the margin the holder puts on it: the coin holds this many
/// sat for each sat/vB of the rate it was made at. Its payout pays an
/// output for each of the graph's bits from `low_bits`, and one of a rest,
/// counted whether the cap has one or not (the graph's terms do not say).
pub fn terminal_vsize(g: &GraphTerms) -> u64 {
    let outputs = u64::from(g.bits.saturating_sub(g.low_bits)) + 1;
    TERMINAL_MARGIN * (TERMINAL_FIXED_VSIZE + PAYOUT_OUTPUT_VSIZE * outputs)
}

/// The value of R's anchor, which P spends.
const ANCHOR: Amount = Amount::from_sat(330);

/// P's vsize, of a filing of `notes` settled notes: its transaction and the
/// filing's own header, and each note's bytes, in a nulldata output, so a
/// vB a byte (measured: 7 granted notes took 4,859 vB in the legacy format,
/// 3,113 in the compact, of note format v3; a granted note of v4 is 64
/// bytes more, its seal 96 bytes and its mask 32 where its DLEQ proof was
/// 64; and of v5, whose message has no nonce, 32 bytes less in the compact
/// filing and 96 in the legacy, which repeats it).
pub fn publication_vsize(format: Format, notes: u32) -> u64 {
    let (fixed, each) = match format {
        Format::Legacy => (526, 587),
        Format::Compact | Format::Lean => (520, 403),
    };
    fixed + each * u64::from(notes)
}

/// What the package of R and P of `notes` settled notes, and her fee coin,
/// weigh in all, in vB, in a graph of `g`'s terms.
pub fn forced_close_vsize(g: &GraphTerms, notes: u32) -> u64 {
    R_VSIZE + publication_vsize(Format::at(g.id), notes) + terminal_vsize(g)
}

/// The rate in sat per 1,000 vB her reserve affords a forced close of a
/// filing of `notes` settled notes, all of what R hands her spent on it
/// (the fee coin included, as it is made at the rate).
pub fn affordable_rate(g: &GraphTerms, notes: u32) -> u64 {
    let purse = graph::purse(
        Amount::from_sat(g.reserve_alice),
        Amount::from_sat(g.reserve_hub),
        Amount::from_sat(g.dust),
    );
    let budget = (purse.unwrap_or(Amount::ZERO))
        .checked_add(SLOT + ANCHOR)
        .unwrap_or(Amount::MAX);
    let vsize = forced_close_vsize(g, notes);
    budget.to_sat().saturating_mul(1_000) / vsize
}

/// [`affordable_rate`] of the most notes a claim files, the filing the
/// protocol allows: what a quote's reserve is held to.
pub fn affordable_rate_at_most(g: &GraphTerms) -> u64 {
    affordable_rate(g, MAX_ITEMS as u32)
}

/// The least reserve of her that affords `rate` sat per 1,000 vB at the
/// most notes, in a graph of `g`'s terms (its reserves aside): the purse,
/// and the dust limit it leaves her. Her purse is at most half of the
/// hub's reserve ([`graph::purse`]), which must be twice it at least.
pub fn reserve_for(g: &GraphTerms, rate: u64) -> u64 {
    let vsize = forced_close_vsize(g, MAX_ITEMS as u32);
    let budget = rate.saturating_mul(vsize).div_ceil(1_000);
    budget
        .saturating_sub((SLOT + ANCHOR).to_sat())
        .saturating_add(g.dust)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::opening::{testing, Quote};
    use licash::spend::ChainProfile;

    fn terms(id: u32, reserve_alice: u64, reserve_hub: u64) -> GraphTerms {
        let mut g = Quote::from_base(&testing::base(&[3; 32])).graph;
        g.id = id;
        g.dust = 330;
        g.reserve_alice = reserve_alice;
        g.reserve_hub = reserve_hub;
        g
    }

    /// Terms of any size, as a quote may say, size a reserve without
    /// overflowing: at most all there is.
    #[test]
    fn a_reserve_of_any_terms_is_sized_without_overflowing() {
        let mut g = terms(0, u64::MAX, u64::MAX);
        g.dust = u64::MAX;
        assert_eq!(reserve_for(&g, u64::MAX), u64::MAX);
        g.dust = 1;
        reserve_for(&g, u64::MAX);
        affordable_rate(&g, 1);
        g.bits = u8::MAX;
        g.low_bits = 0;
        affordable_rate(&g, 1);
    }

    #[test]
    fn a_forced_close_weighs_its_request_its_publication_and_its_fee_coin() {
        assert_eq!(publication_vsize(Format::Legacy, 7), 4_859 - 7 * 32);
        assert_eq!(publication_vsize(Format::Compact, 7), 3_117 + 7 * (64 - 32));
        let (legacy, compact) = (terms(0, 0, 0), terms(9, 0, 0));
        assert_eq!(
            forced_close_vsize(&compact, 7),
            R_VSIZE + 3_341 + terminal_vsize(&compact)
        );
        // The compact filing weighs less by what it saves a note.
        assert_eq!(
            forced_close_vsize(&legacy, 32) - forced_close_vsize(&compact, 32),
            6 + 32 * 184
        );
    }

    /// The widest terminal, with the holder's margin, of a payout of an
    /// output for each bit from `low_bits` and one of a rest: of the
    /// least cap (17 bits), and of the largest (31 bits, or 30 and a
    /// rest, as many outputs).
    #[test]
    fn a_terminal_weighs_its_payouts_outputs() {
        let mut g = terms(9, 0, 0);
        g.low_bits = 9;
        g.bits = 17;
        assert_eq!(terminal_vsize(&g), 2 * (324 + 9 * 43));
        g.bits = 31;
        assert_eq!(terminal_vsize(&g), 2 * (324 + 23 * 43));
        // A graph a bit wider weighs one output more.
        g.bits = 18;
        assert_eq!(terminal_vsize(&g), 2 * (324 + 10 * 43));
        // Of no bits from `low_bits`, the rest's alone.
        g.bits = 9;
        assert_eq!(terminal_vsize(&g), 2 * (324 + 43));
    }

    /// Today's quote, 20 000 sat of hers to 100 000 of the hub's: what R
    /// hands her is her purse, the slot and the anchor.
    #[test]
    fn a_reserve_affords_what_r_hands_her_over_the_package() {
        let g = terms(9, 20_000, 100_000);
        assert_eq!(
            affordable_rate(&g, 7),
            (19_670 + 330 + 330) * 1_000 / (2_160 + 3_341 + terminal_vsize(&g))
        );
        // More notes, a lower rate; the widest filing, the least.
        assert!(affordable_rate(&g, 32) < affordable_rate(&g, 7));
        assert_eq!(affordable_rate_at_most(&g), affordable_rate(&g, 32));
        // The purse is half the hub's reserve at most: a larger reserve of
        // hers than that buys no rate.
        let capped = terms(9, 400_000, 100_000);
        assert_eq!(
            affordable_rate(&capped, 32),
            (50_000 + 660) * 1_000 / forced_close_vsize(&capped, 32)
        );
        // None of the purse if the reserve is dust.
        assert!(affordable_rate(&terms(9, 400, 100_000), 7) < 1_000);
    }

    #[test]
    fn the_reserve_for_a_rate_affords_it() {
        for id in [8, 9] {
            for rate in [1_000, 10_000, 25_000] {
                let alice = reserve_for(&terms(id, 0, 0), rate);
                // Her purse is half the hub's reserve at most.
                let g = terms(id, alice, 2 * alice);
                let afforded = affordable_rate_at_most(&g);
                assert!(afforded >= rate, "{afforded} of {rate} at {id}");
                assert!(afforded < rate + 1_000, "{afforded} of {rate} at {id}");
                // One sat less affords less.
                assert!(affordable_rate_at_most(&terms(id, alice - 1, 2 * alice)) <= afforded);
            }
        }
        // 10 sat/vB at the widest compact filing, of a graph of the least
        // cap: about 170 k sat of hers (160 k at note format v3, a note 32 vB
        // less; 180 k at v4, 32 more), 12 k more of the largest.
        let mut g = terms(9, 0, 0);
        g.bits = 17;
        assert_eq!(reserve_for(&g, 10_000), 161_990 + 10 * 32 * 32 - 2_580);
        g.bits = 31;
        assert_eq!(reserve_for(&g, 10_000), 161_990 + 10 * 32 * 32 + 9_460);
    }

    /// A quote must afford the floor on mainnet; the test networks ask none.
    #[test]
    fn a_quote_must_afford_its_networks_floor() {
        let mut quote = Quote::from_base(&testing::base(&[3; 32]));
        quote.graph.id = 9;
        // Mainnet's other floors, to isolate the reserve's.
        quote.graph.challenge_window = 144;
        quote.graph.contest_window = 144;
        quote.graph.publication_window = 6;
        quote.graph.to_self_delay = 144;
        quote.chain.funding_depth = 3;
        quote.chain.work_depth = 6;
        quote.graph.dust = 330;
        quote.graph.reserve_alice = 20_000;
        quote.graph.reserve_hub = 100_000;
        assert!(quote.check(ChainProfile::Core30Signet).is_ok());
        let error = quote.check(ChainProfile::Core30Mainnet).unwrap_err();
        assert!(
            error.to_string().contains("forced close 1.2 sat/vB"),
            "{error}"
        );
        quote.graph.reserve_alice = reserve_for(&quote.graph, 10_000);
        quote.graph.reserve_hub = 2 * quote.graph.reserve_alice;
        assert!(quote.check(ChainProfile::Core30Mainnet).is_ok());
        quote.graph.reserve_alice -= 1_000;
        assert!(quote.check(ChainProfile::Core30Mainnet).is_err());
    }
}
