package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.ContractFit
import org.licash.core.DepositCoin

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

    // Caps of 2^n - 1 sat a coin of 1,000,000 sat may take whole, as a hub
    // allowing 4 times the coin fits them: the smallest at `least` and above.
    private val caps = listOf(1_048_575uL, 2_097_151uL)

    private fun fake(least: ULong): ContractFit? =
        caps.firstOrNull { it >= least }?.let { ContractFit(cap = it, funded = 970_000uL) }

    @Test
    fun every_cap_a_coin_takes_whole_is_offered_smallest_first() {
        assertEquals(caps, fitsFrom(131_071uL, ::fake).map { it.cap })
        assertEquals(listOf<ULong>(), fitsFrom(131_071uL) { null }.map { it.cap })
        // A fit below what was asked is not taken for another.
        assertEquals(listOf<ULong>(), fitsFrom(5uL) { ContractFit(cap = 4uL, funded = 1uL) }.map { it.cap })
    }

    @Test
    fun the_cap_offered_is_half_again_the_coin_else_the_largest_allowed() {
        val fits = fitsFrom(131_071uL, ::fake)
        // 1.5 times 1,000,000 is past 1,048,575: the next.
        assertEquals(2_097_151uL, suggestedFit(fits, 1_000_000uL)?.cap)
        // 600,000 half again is 900,000: the smallest covers it.
        assertEquals(1_048_575uL, suggestedFit(fits, 600_000uL)?.cap)
        // None as large allowed: the largest.
        assertEquals(2_097_151uL, suggestedFit(fits, 1_500_000uL)?.cap)
        assertNull(suggestedFit(emptyList(), 1_000_000uL))
    }

    @Test
    fun the_cover_is_chosen_first_and_decides_the_coins_paying_it() {
        val small = DepositCoin("a:0", 600_000uL)
        val large = DepositCoin("b:0", 1_000_000uL)
        val tiny = DepositCoin("c:0", 1_000uL)
        fun fit(cap: ULong) = ContractFit(cap = cap, funded = 1uL)
        val fits = listOf(
            large to listOf(fit(1_048_575uL), fit(2_097_151uL)),
            small to listOf(fit(1_048_575uL)),
            tiny to emptyList(),
        )
        // Every cover some coin opens, each with the coins that pay it, smallest first.
        assertEquals(
            listOf(1_048_575uL to listOf(small, large), 2_097_151uL to listOf(large)),
            coversOf(fits),
        )
        // At first the one suggested for the smallest coin a contract takes whole.
        assertEquals(1_048_575uL, suggestedCover(fits))
        assertEquals(2_097_151uL, suggestedCover(listOf(large to fits[0].second)))
        assertNull(suggestedCover(listOf(tiny to emptyList())))
        assertEquals(emptyList<Pair<ULong, List<DepositCoin>>>(), coversOf(emptyList()))
    }

    @Test
    fun what_she_holds_at_the_hub_counts_toward_the_cover_suggested() {
        val fits = fitsFrom(131_071uL, ::fake)
        // A small coin, 400,000 sat held there unprotected: half again both is past 1,048,575.
        assertEquals(2_097_151uL, suggestedFit(fits, 300_000uL, missing = 400_000uL)?.cap)
        assertEquals(1_048_575uL, suggestedFit(fits, 300_000uL)?.cap)
    }

    private val sizes = listOf(131_071uL, 262_143uL, 524_287uL, 1_048_575uL)

    // 3,000 sat and a sat of interest per 1,000 sat of the hub's part.
    private fun price(cap: ULong, funded: ULong) = 23_000uL + (cap - funded) / 1_000uL

    @Test
    fun with_no_coin_she_cashes_out_one_paying_for_what_she_holds() {
        // 300,000 sat held unprotected: half again is 450,000, the hub funding nearly all of 524,287.
        val any = { coin: ULong, least: ULong -> ContractFit(cap = least, funded = coin - price(least, FIXED_PART)) }
        assertEquals(
            CashOutFirst(524_287uL, price(524_287uL, FIXED_PART) + FIXED_PART),
            cashOutFirst(sizes, 300_000uL, ::price, any),
        )
        // More than the largest: the largest.
        assertEquals(1_048_575uL, cashOutFirst(sizes, 5_000_000uL, ::price, any)?.cap)
        // An older hub bounding the cap by 2 times the coin: the largest it takes, else none.
        val bounded = { coin: ULong, least: ULong -> sizes.firstOrNull { it >= least && it <= 2uL * coin || it == 131_071uL && it >= least }?.let { ContractFit(it, 1uL) } }
        assertEquals(131_071uL, cashOutFirst(sizes, 300_000uL, ::price, bounded)?.cap)
        assertNull(cashOutFirst(sizes, 300_000uL, ::price) { _, _ -> null })
        // Nothing missing there, nothing to protect.
        assertNull(cashOutFirst(sizes, 0uL, ::price, any))
        assertNull(cashOutFirst(emptyList(), 300_000uL, ::price, any))
    }

    @Test
    fun what_protection_asks_says_the_day_it_ends() {
        assertEquals("Open Licash now and then, and before it ends on May 21.", duty("May 21"))
    }

    @Test
    fun what_the_vault_is_for_sizes_it() {
        val caps = listOf(131_071uL, 262_143uL, 524_287uL, 1_048_575uL)
        val fits = caps.map { ContractFit(cap = it, funded = 100_000uL) }
        // 100,000 put in: room for it, half again, or three times it.
        assertEquals(131_071uL, intentFit(fits, 100_000uL, 0uL, Intent.PAY)?.cap)
        assertEquals(262_143uL, intentFit(fits, 100_000uL, 0uL, Intent.BOTH)?.cap)
        assertEquals(524_287uL, intentFit(fits, 100_000uL, 0uL, Intent.RECEIVE)?.cap)
        // Beyond the largest the coin pays: the largest.
        assertEquals(1_048_575uL, intentFit(fits, 1_000_000uL, 0uL, Intent.RECEIVE)?.cap)
        // Both is what was offered before there was a choice.
        for (coin in listOf(1uL, 99_999uL, 100_001uL, 700_000uL)) {
            assertEquals(suggestedFit(fits, coin), intentFit(fits, coin, 0uL, Intent.BOTH))
        }
    }

    @Test
    fun no_intent_saved_means_both() {
        assertEquals(Intent.BOTH, intentOf(null))
        assertEquals(Intent.BOTH, intentOf("something else"))
        assertEquals(Intent.RECEIVE, intentOf("RECEIVE"))
    }
}
