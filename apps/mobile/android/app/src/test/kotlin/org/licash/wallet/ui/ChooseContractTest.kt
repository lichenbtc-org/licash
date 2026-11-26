package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.ContractFit

class ChooseContractTest {
    @Test
    fun durations_are_whole_days_within_the_range() {
        assertEquals(432u, blocksAt(400f, 432u, 52_560u))
        assertEquals(26_208u, blocksAt(26_250f, 432u, 52_560u))
        assertEquals(26_352u, blocksAt(26_300f, 432u, 52_560u))
        assertEquals(52_560u, blocksAt(52_560f, 432u, 52_560u))
        assertEquals(1_000u, blocksAt(1_000f, 200u, 1_000u))
        assertEquals(200u, blocksAt(-5f, 200u, 1_000u))
    }

    // A coin of 1,000,000 sat at a hub allowing 4 times the coin, as
    // contractFit: her part 970,000 sat, a cap of it or of what she asks
    // past it, up to 4,000,000.
    private fun fake(least: ULong): ContractFit? =
        maxOf(least, 970_000uL).takeIf { it <= 4_000_000uL }?.let { ContractFit(cap = it, funded = 970_000uL) }

    @Test
    fun the_cap_offered_is_her_part_or_what_she_asks_else_the_largest_allowed() {
        val most = 4_000_000uL
        // Her part only, the hub adding nothing.
        assertEquals(970_000uL, intentFit(1_000_000uL, 0uL, Intent.FITS, most, ::fake)?.cap)
        // Half again the coin: the hub funding the rest.
        assertEquals(1_500_000uL, intentFit(1_000_000uL, 0uL, Intent.BOTH, most, ::fake)?.cap)
        // Asked any cap: that one.
        assertEquals(2_345_678uL, fitFor(2_345_678uL, most, ::fake)?.cap)
        // Past the largest allowed: the largest.
        assertEquals(most, fitFor(9_000_000uL, most, ::fake)?.cap)
        assertEquals(most, intentFit(1_000_000uL, 2_000_000uL, Intent.RECEIVE, most, ::fake)?.cap)
        // Below her part: her part.
        assertEquals(970_000uL, fitFor(5uL, most, ::fake)?.cap)
        assertNull(fitFor(1_000_000uL, most) { null })
    }

    @Test
    fun what_she_holds_at_the_hub_counts_toward_the_cover_suggested() {
        val most = 4_000_000uL
        // A small coin, 400,000 sat held there unprotected: half again both.
        assertEquals(1_050_000uL, intentFit(300_000uL, 400_000uL, Intent.BOTH, most, ::fake)?.cap)
        assertEquals(970_000uL, intentFit(300_000uL, 400_000uL, Intent.FITS, most, ::fake)?.cap)
    }

    @Test
    fun the_cover_asked_is_any_she_slides_to_in_thousands() {
        assertEquals(970_000uL, capAt(0f, 970_000uL, 4_000_000uL))
        assertEquals(4_000_000uL, capAt(9e9f, 970_000uL, 4_000_000uL))
        assertEquals(1_235_000uL, capAt(1_234_567f, 970_000uL, 4_000_000uL))
        // Its ends as they are, though not of a thousand.
        assertEquals(970_123uL, capAt(970_200f, 970_123uL, 4_000_000uL))
        assertEquals(131_071uL, capAt(5f, 131_071uL, 131_071uL))
    }

    // 3,000 sat and a sat of interest per 1,000 sat of the hub's part.
    private fun price(cap: ULong, funded: ULong) = 23_000uL + (cap - funded) / 1_000uL

    private val least = 131_071uL
    private val largest = 1_048_575uL

    // Any cap of `sat` at least, as contractCapAtLeast: none past the largest.
    private fun capAtLeast(sat: ULong): ULong? = maxOf(sat, least).takeIf { it <= largest }

    @Test
    fun with_no_coin_she_cashes_out_what_she_holds_unprotected_the_hub_adding_the_rest() {
        // A contract of her part, of `least` at least, as contractFit.
        val absorbing = { coin: ULong, atLeast: ULong ->
            val part = coin - 23_000uL
            val cap = maxOf(part, atLeast, least)
            // less the interest on the hub's part
            val funded = part - (cap - part) / 1_000uL
            ContractFit(cap, funded).takeIf { cap <= largest && funded in 1uL..cap }
        }
        // 200,000 sat held unprotected, all of it moved but 7,000 for the cash-out's fees:
        // her part of it, not half again it as mostly the hub's.
        assertEquals(7_000uL, cashOutRoom(200_000uL))
        assertEquals(3_000uL, cashOutRoom(3_000uL))
        val own = cashOutOwn(least, largest, 200_000uL, ::price, absorbing)
        assertEquals(170_000uL to 193_000uL, own?.let { it.cap to it.coin })
        assertEquals(300_000uL, cashOutFirst(least, largest, 200_000uL, ::price, ::capAtLeast, absorbing)?.cap)
        // Too little for the smallest: what it takes, a little of hers.
        val small = price(least, FIXED_PART) + FIXED_PART
        assertEquals(least to small, cashOutOwn(least, largest, 5_000uL, ::price, absorbing)?.let { it.cap to it.coin })
        // More than the largest takes: the largest, all hers.
        val most = cashOutOwn(least, largest, 5_000_000uL, ::price, absorbing)
        assertEquals(price(largest, largest) + largest, most?.coin)
        // Nothing missing, or none taking it: none.
        assertNull(cashOutOwn(least, largest, 0uL, ::price, absorbing))
        assertNull(cashOutOwn(least, largest, 200_000uL, ::price) { _, _ -> null })
        assertNull(cashOutOwn(least, least - 1uL, 200_000uL, ::price, absorbing))
    }

    @Test
    fun with_no_coin_she_cashes_out_one_paying_for_what_she_holds() {
        // 300,000 sat held unprotected: half again is 450,000, the hub funding nearly all of it.
        val any = { coin: ULong, atLeast: ULong -> ContractFit(cap = atLeast, funded = coin - price(atLeast, FIXED_PART)) }
        assertEquals(
            CashOutFirst(450_000uL, price(450_000uL, FIXED_PART) + FIXED_PART, FIXED_PART),
            cashOutFirst(least, largest, 300_000uL, ::price, ::capAtLeast, any),
        )
        // More than the largest: the largest.
        assertEquals(largest, cashOutFirst(least, largest, 5_000_000uL, ::price, ::capAtLeast, any)?.cap)
        // A hub bounding the cap by 2 times the coin: the least, else none.
        val bounded = { coin: ULong, atLeast: ULong ->
            atLeast.takeIf { it <= 2uL * coin || it == least }?.let { ContractFit(it, 1uL) }
        }
        assertEquals(least, cashOutFirst(least, largest, 300_000uL, ::price, ::capAtLeast, bounded)?.cap)
        assertNull(cashOutFirst(least, largest, 300_000uL, ::price, ::capAtLeast) { _, _ -> null })
        // Nothing missing there, nothing to protect.
        assertNull(cashOutFirst(least, largest, 0uL, ::price, ::capAtLeast, any))
        assertNull(cashOutFirst(least, least - 1uL, 300_000uL, ::price, ::capAtLeast, any))
    }

    @Test
    fun what_protection_asks_says_the_day_it_ends() {
        assertEquals("Open Licash now and then, and before it ends on May 21.", duty("May 21"))
    }

    @Test
    fun what_the_vault_is_for_sizes_it() {
        val fit = { least: ULong -> ContractFit(cap = maxOf(least, 131_071uL), funded = 100_000uL) }
        val most = 1_048_575uL
        // 100,000 put in: room for it, half again, or three times it.
        assertEquals(131_071uL, intentFit(100_000uL, 0uL, Intent.PAY, most, fit)?.cap)
        assertEquals(150_000uL, intentFit(100_000uL, 0uL, Intent.BOTH, most, fit)?.cap)
        assertEquals(300_000uL, intentFit(100_000uL, 0uL, Intent.RECEIVE, most, fit)?.cap)
        assertEquals(900_000uL, intentFit(500_000uL, 400_000uL, Intent.PAY, most, fit)?.cap)
        // At first her part only, whatever is not protected yet.
        assertEquals(0uL, intentLeast(100_000uL, 5_000_000uL, Intent.FITS))
        assertEquals(131_071uL, intentFit(100_000uL, 5_000_000uL, Intent.FITS, most, fit)?.cap)
        assertNull(intentFit(100_000uL, 0uL, Intent.FITS, most) { null })
    }

    @Test
    fun no_intent_saved_means_the_smallest_and_one_saved_is_kept() {
        assertEquals(Intent.FITS, intentOf(null))
        assertEquals(Intent.FITS, intentOf("something else"))
        assertEquals(Intent.RECEIVE, intentOf("RECEIVE"))
        assertEquals(Intent.BOTH, intentOf("BOTH"))
        assertEquals(Intent.PAY, intentOf("PAY"))
    }
}
