package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Balance
import org.licash.core.Kind
import org.licash.core.OpeningStep
import org.licash.core.Transfer

class WordsTest {
    private fun balance(notes: ULong = 0uL, onchain: ULong = 0uL, covered: ULong = 0uL, pending: ULong = 0uL) =
        Balance(
            notes = notes, notesPending = pending, onchain = onchain, moving = 0uL, kept = onchain, opening = 0uL,
            covered = covered,
        )

    @Test
    fun a_payment_with_too_little_is_sent_where_its_bitcoin_or_nothing_is() {
        // A contract offered comes first, as before: too little, or nothing held, whatever else failed.
        assertEquals(Lack.OFFER, lack(insufficient = true, noHub = false, notes = 5uL, bitcoin = 0uL, offered = true))
        assertEquals(Lack.OFFER, lack(insufficient = false, noHub = false, notes = 0uL, bitcoin = 9uL, offered = true))
        // No offer, nothing in notes, too little: bitcoin held or coming is where to look, else receive first.
        assertEquals(Lack.BITCOIN, lack(insufficient = false, noHub = true, notes = 0uL, bitcoin = 100uL, offered = false))
        assertEquals(Lack.NOTHING, lack(insufficient = false, noHub = true, notes = 0uL, bitcoin = 0uL, offered = false))
        assertEquals(Lack.NOTHING, lack(insufficient = true, noHub = false, notes = 0uL, bitcoin = 0uL, offered = false))
        // Notes held somewhere else, or a failure that is not about a balance: said as it is.
        assertEquals(Lack.OTHER, lack(insufficient = false, noHub = true, notes = 40uL, bitcoin = 100uL, offered = false))
        assertEquals(Lack.OTHER, lack(insufficient = true, noHub = false, notes = 40uL, bitcoin = 0uL, offered = false))
        assertEquals(Lack.OTHER, lack(insufficient = false, noHub = false, notes = 0uL, bitcoin = 100uL, offered = false))
        // Too little in notes, bitcoin held besides: adding it mends that, notes held or not.
        assertEquals(Lack.BITCOIN, lack(insufficient = true, noHub = false, notes = 21_000uL, bitcoin = 110_000uL, offered = false))
    }

    @Test
    fun a_coin_on_bitcoin_is_added_at_once_unless_it_is_still_on_its_way() {
        assertTrue(addable(balance(onchain = 10_000uL), opening = false))
        // Being added already, paying for protection, or not on Bitcoin yet: only waited for.
        assertFalse(addable(balance(onchain = 10_000uL).copy(moving = 5_000uL), opening = false))
        assertFalse(addable(balance(onchain = 10_000uL), opening = true))
        assertFalse(addable(balance(), opening = false))
        assertTrue(addFirst(addable = false, offered = true).contains("on its way"))
        assertTrue(addFirst(addable = true, offered = true).contains("protect it first"))
        assertFalse(addFirst(addable = true, offered = false).contains("protect it first"))
    }

    @Test
    fun a_payment_says_the_contact_it_went_to_or_came_from() {
        assertEquals("To Bob", counterpart(Kind.SENT, "Bob"))
        assertEquals("From Alice", counterpart(Kind.RECEIVED, "Alice"))
        assertNull(counterpart(Kind.SENT, null))
    }

    @Test
    fun home_never_says_protected_while_protection_is_being_set_up() {
        val held = balance(notes = 10_000uL, covered = 10_000uL)
        assertEquals(protection(held), homeProtection(held, opening = false))
        assertNull(homeProtection(held, opening = true))
    }

    @Test
    fun bitcoin_paid_to_the_wallet_with_nothing_done_about_it_is_said_waiting() {
        // Paid on Bitcoin, no offer for it, nothing under way: waiting, less what the wallet keeps on purpose.
        assertEquals(10_000uL, waiting(balance(onchain = 10_000uL).copy(kept = 0uL), offered = false, opening = false))
        assertEquals(6_000uL, waiting(balance(onchain = 10_000uL).copy(kept = 4_000uL), offered = false, opening = false))
        // Its own change and payouts only, an offer, a protection being set up or a move under way: nothing to say.
        assertNull(waiting(balance(onchain = 10_000uL), offered = false, opening = false))
        assertNull(waiting(balance(onchain = 10_000uL).copy(kept = 0uL), offered = true, opening = false))
        assertNull(waiting(balance(onchain = 10_000uL).copy(kept = 0uL), offered = false, opening = true))
        assertNull(waiting(balance(onchain = 10_000uL).copy(kept = 0uL, moving = 5_000uL), offered = false, opening = false))
        assertNull(waiting(balance(), offered = false, opening = false))
    }

    @Test
    fun nothing_held_says_nothing_of_protection() {
        val none = protection(balance())
        assertNull(none.shield)
        assertNull(none.label)
        assertEquals(0, none.percent)
    }

    @Test
    fun what_is_on_bitcoin_or_covered_is_protected_and_the_rest_is_not() {
        val p = protection(balance(notes = 100_000uL, onchain = 10_000uL, covered = 4_096uL, pending = 9_294uL))
        assertEquals(14_096uL, p.protected)
        assertEquals(105_198uL, p.open)
        assertEquals(119_294uL, p.total)
        assertEquals(Shield.SOME, p.shield)
        assertEquals("12% protected", p.label)
    }

    @Test
    fun all_or_none_is_said_in_a_word_not_a_number() {
        val all = protection(balance(notes = 4_000uL, onchain = 1_000uL, covered = 4_000uL))
        assertEquals(Shield.ALL, all.shield)
        assertEquals("Protected", all.label)
        val none = protection(balance(notes = 4_000uL))
        assertEquals(Shield.NONE, none.shield)
        assertEquals("Not protected", none.label)
    }

    @Test
    fun a_share_is_never_rounded_to_all_or_none() {
        assertEquals(1, protection(balance(notes = 1_000_000uL, onchain = 1uL)).percent)
        assertEquals(99, protection(balance(notes = 1uL, onchain = 1_000_000uL)).percent)
        assertEquals(50, protection(balance(notes = 500uL, onchain = 500uL)).percent)
    }

    @Test
    fun covering_more_than_is_held_protects_no_more_than_is_held() {
        val p = protection(balance(notes = 1_000uL, covered = 4_096uL))
        assertEquals(1_000uL, p.protected)
        assertEquals(0uL, p.open)
        assertEquals(Shield.ALL, p.shield)
    }

    @Test
    fun blocks_are_told_as_time_never_as_heights() {
        assertEquals("now", span(0))
        assertEquals("now", span(-3))
        assertEquals("10 min", span(1))
        assertEquals("50 min", span(5))
        assertEquals("1 hour", span(6))
        assertEquals("2 hours", span(12))
        assertEquals("24 hours", span(144))
        assertEquals("6 days", span(861))
        assertEquals("7 days", span(1_001))
    }

    @Test
    fun blocks_are_told_in_the_time_of_their_network() {
        // Mutinynet's take 30 seconds: the same blocks, a twentieth of the time.
        assertEquals("now", span(0, 30u))
        assertEquals("30 sec", span(1, 30u))
        assertEquals("5 min", span(10, 30u))
        assertEquals("1 hour", span(144, 30u))
        assertEquals("24 hours", span(2_880, 30u))
        assertEquals("3 days", span(8_640, 30u))
        assertEquals("10 min", span(1, 600u))
        assertEquals("33 hours", span(200, 600u))
        assertEquals(
            "If the provider declines or fails the payment, your sats come back by themselves, in about 2 hours.",
            refundWait(200u, 30u),
        )
    }

    @Test
    fun a_day_is_said_as_short_as_today_lets_it() {
        val zone = java.time.ZoneId.of("UTC")
        val us = java.util.Locale.US
        // 2026-11-15 12:00 UTC.
        val now = 1_794_744_000L
        // Narrow or plain, the space before PM is the JDK's to choose.
        assertEquals("11:00 AM", day(now - 3_600, now, zone, us).replace('\u202f', ' '))
        assertEquals("Yesterday", day(now - 86_400, now, zone, us))
        assertEquals("Nov 13", day(now - 2 * 86_400, now, zone, us))
        assertEquals("Dec 31, 2025", day(1_767_182_400L, now, zone, us))
    }

    @Test
    fun a_timelock_says_its_block_when_it_comes_and_how_long_until_then() {
        val zone = java.time.ZoneId.of("UTC")
        val us = java.util.Locale.US
        // 2026-11-15 12:00 UTC.
        val now = 1_794_744_000L
        fun said(height: UInt, tip: Int, secs: UInt = 600u) = atBlock(height, tip, secs, now, zone, us).replace('\u202f', ' ')
        // 144 blocks of 10 minutes: a day from now.
        assertEquals("Block 900,144 · about Nov 16, 12:00 PM · in 24 hours", said(900_144u, 900_000))
        // Mutinynet's 30 s blocks: the same blocks, a twentieth of the time.
        assertEquals("Block 900,144 · about Nov 15, 1:12 PM · in 1 hour", said(900_144u, 900_000, 30u))
        // Into another year: said with it.
        assertEquals("Block 908,000 · about Jan 10, 2027, 1:20 AM · in 56 days", said(908_000u, 900_000))
        // Reached, or the tip not known yet.
        assertEquals("Block 900,000 · passed", said(900_000u, 900_000))
        assertEquals("Block 899,000 · passed", said(899_000u, 900_000))
        assertEquals("Block 900,144", said(900_144u, 0))
    }

    @Test
    fun paying_through_a_provider_says_how_long_its_sats_may_wait() {
        assertEquals(
            "If the provider declines or fails the payment, your sats come back by themselves, in about 33 hours.",
            refundWait(200u),
        )
        assertEquals("Not paid. Your money comes back by itself in about 2 hours.", notPaid(12u))
    }

    @Test
    fun a_setup_preparing_says_how_long_so_far_between_its_first_steps() {
        assertEquals("45 s", ticking(45uL))
        assertEquals("2 min 05 s", ticking(125uL))
        val (done, says) = setup(OpeningStep.Preparing(125uL))
        assertEquals("Preparing it, a few minutes · 2 min 05 s", says)
        assertTrue(done > setup(OpeningStep.Terms).first && done < setup(OpeningStep.Choosing).first)
    }

    @Test
    fun a_setup_says_how_much_it_sent_how_fast_and_how_long_the_rest_takes() {
        assertEquals("0.0 MB of about 100 MB", transferred(Transfer(0uL, 0uL, 100_100_000uL)))
        assertEquals(
            "12 MB of about 100 MB · 1.5 MB/s · about 58 s left",
            transferred(Transfer(12_000_000uL, 8uL, 100_100_000uL)),
        )
        assertEquals(
            "1.0 MB of about 100 MB · 0.1 MB/s · about 17 min left",
            transferred(Transfer(1_000_000uL, 10uL, 100_100_000uL)),
        )
        assertEquals(
            "99 MB of about 99 MB · 9.9 MB/s · almost done",
            transferred(Transfer(99_000_000uL, 10uL, 99_100_000uL)),
        )
        assertEquals(
            "1.0 MB of about 541 MB · 0.1 MB/s · about 2 h left",
            transferred(Transfer(1_000_000uL, 10uL, 541_000_000uL)),
        )
        assertEquals(
            "0.1 MB of about 251 MB · 2 kB/s · about 33 h left",
            transferred(Transfer(100_000uL, 48uL, 251_000_000uL)),
        )
        // While the wallet prepares the contract itself, its slow start says nothing of the network.
        assertEquals("0.1 MB of about 251 MB", transferred(Transfer(100_000uL, 48uL, 251_000_000uL), busy = true))
        // Past what was expected: no time left to say.
        assertEquals("120 MB of about 100 MB · 12 MB/s", transferred(Transfer(120_000_000uL, 10uL, 100_100_000uL)))
    }

    @Test
    fun what_is_safe_is_told_apart_as_on_bitcoin_and_protected_by_contracts() {
        // 110,000 on Bitcoin, 9,800 in notes no contract covers: nothing by contracts.
        val share = Protection(protected = 110_000uL, open = 9_800uL)
        assertEquals(SafeSplit(bitcoin = 110_000uL, contracts = 0uL), safeSplit(share, 110_000uL))
        // A contract covering notes besides.
        assertEquals(SafeSplit(110_000uL, 50_000uL), safeSplit(Protection(160_000uL, 0uL), 110_000uL))
        // Never more on Bitcoin than what is protected.
        assertEquals(SafeSplit(5uL, 0uL), safeSplit(Protection(5uL, 1uL), 9uL))
    }
}
