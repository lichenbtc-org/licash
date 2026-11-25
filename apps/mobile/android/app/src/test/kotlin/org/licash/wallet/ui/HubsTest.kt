package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.ContractRange
import org.licash.core.ContractTerms
import org.licash.core.Fees
import org.licash.core.FeesRaised
import org.licash.core.Hub
import org.licash.core.HubRoom
import org.licash.core.HubsFound
import org.licash.core.LightningTerms
import org.licash.core.Range
import org.licash.core.Rate
import org.licash.core.State

class HubsTest {
    @Test
    fun optimization_shows_only_its_fee_and_never_a_zero_amount_payment() {
        assertEquals("Fee 1 sat", optimizationCost(1uL, State.DONE))
        assertEquals("Fee 1 sat", optimizationCost(1uL, State.PENDING))
        assertEquals("Free", optimizationCost(0uL, State.DONE))
        assertEquals("Not charged", optimizationCost(1uL, State.FAILED))
    }

    @Test
    fun protection_interest_is_said_short_and_on_hers_only_if_charged() {
        val range = ContractRange(131_071uL, 16_777_215uL, 432u, 52_560u, 2u, 20_000uL, 3_000uL, 10_000u, 0u, 52_560u)
        assertEquals("1% a year", interestOf(range))
        assertEquals("1% a year, 0.5% on yours", interestOf(range.copy(ppmYearFunded = 5_000u)))
    }

    @Test
    fun a_hub_saying_it_has_no_room_for_a_vault_is_not_started_at() {
        // Room, or nothing said of it, as hubs before any did: none to tell.
        assertNull(noRoom(opens = true, room = HubRoom.OPEN))
        assertEquals("No room for new vaults right now.", noRoom(opens = true, room = HubRoom.FULL))
        assertEquals("It can't fund new vaults right now.", noRoom(opens = true, room = HubRoom.UNFUNDED))
        assertEquals("It opens no vaults.", noRoom(opens = false, room = null))
        val (a, b, c) = listOf("a", "b", "c").map { Known("https://$it.example", it) }
        // The first not known to have none, unasked ones too; none if all are known to.
        assertEquals(a, pick(listOf(a, b, c), emptyMap()))
        assertEquals(b, pick(listOf(a, b, c), mapOf(a.url to "full")))
        assertEquals(c, pick(listOf(a, b, c), mapOf(a.url to "full", b.url to "full")))
        assertNull(pick(listOf(a), mapOf(a.url to "full")))
        assertNull(pick(emptyList(), emptyMap()))
    }

    private fun found(silent: UInt, onion: UInt) = HubsFound(hubs = emptyList(), silent = silent, silentOnion = onion)

    private fun hub(
        base: ULong = 0uL,
        ppm: ULong = 0uL,
        lightning: Boolean = false,
        contracts: Boolean = false,
        note: ULong = 0uL,
    ) = Hub(
        url = "https://hub.example", feeBase = base, feePpm = ppm, feeOutputMsat = note, deposits = null, silent = false,
        mailbox = true,
        lightningPay = null, lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        lightning = if (lightning) LightningTerms(Rate(2uL, 5_000uL), Rate(0uL, 0uL), Range(1uL, 1_000_000uL)) else null,
        contracts = if (contracts) ContractTerms(4_096uL, 23_000uL, 1_005u, true, null) else null,
    )

    @Test
    fun a_hub_is_told_by_its_fee_and_what_else_it_does() {
        assertEquals("No fee", about(hub()))
        assertEquals("Fee 0.5%", about(hub(ppm = 5_000uL)))
        assertEquals("Fee 1 sat + 0.5% · Lightning", about(hub(base = 1uL, ppm = 5_000uL, lightning = true)))
        assertEquals("No fee · Lightning · Protection", about(hub(lightning = true, contracts = true)))
    }

    @Test
    fun a_fee_on_the_notes_a_payment_makes_is_said_beside_its_rate() {
        assertEquals("None", paying(hub()))
        assertEquals("1 sat + 0.01%", paying(hub(base = 1uL, ppm = 100uL)))
        assertEquals("1 sat + 0.01% + 0.1 sat a note", paying(hub(base = 1uL, ppm = 100uL, note = 100uL)))
        assertEquals("2 sat a note", paying(hub(note = 2_000uL)))
        assertEquals("1.25 sat a note", paying(hub(note = 1_250uL)))
        assertEquals("Fee 0.1 sat a note", about(hub(note = 100uL)))
    }

    @Test
    fun a_hub_charging_more_than_agreed_is_told_by_the_fees_it_changed() {
        val agreed = Fees(spend = Rate(1uL, 100uL), lock = Rate(1uL, 0uL), refund = Rate(0uL, 0uL), outputMsat = 100uL)
        fun raised(charged: Fees) = raises(FeesRaised("https://hub.example", charged, agreed))
        assertEquals(
            listOf(Raise("Paying", "1 sat + 0.02% + 0.1 sat a note", "1 sat + 0.01% + 0.1 sat a note")),
            raised(agreed.copy(spend = Rate(1uL, 200uL))),
        )
        // The fee on each note made is a payment's too.
        assertEquals(
            listOf(Raise("Paying", "1 sat + 0.01% + 1 sat a note", "1 sat + 0.01% + 0.1 sat a note")),
            raised(agreed.copy(outputMsat = 1_000uL)),
        )
        assertEquals(
            listOf(Raise("Holding a payment", "2 sat", "1 sat"), Raise("Refunding one", "0.5%", "None")),
            raised(agreed.copy(lock = Rate(2uL, 0uL), refund = Rate(0uL, 5_000uL))),
        )
        assertEquals(emptyList<Raise>(), raised(agreed))
    }

    @Test
    fun the_most_a_payment_costs_counts_the_notes_it_may_make() {
        // 1 sat and 0.01% of 10,000, and 28 notes at a tenth of a sat each.
        assertEquals(2uL, payingUpTo(hub(base = 1uL, ppm = 100uL), 10_000uL))
        assertEquals(5uL, payingUpTo(hub(base = 1uL, ppm = 100uL, note = 100uL), 10_000uL))
        assertEquals(0uL, payingUpTo(hub(note = 100uL), 0uL))
        assertEquals(0uL, payingUpTo(hub(), 10_000uL))
    }

    @Test
    fun hubs_that_all_answered_leave_nothing_to_say() {
        assertNull(unanswered(found(0u, 0u), tor = false))
    }

    @Test
    fun those_that_did_not_answer_are_counted_and_tor_offered_when_it_would_reach_them() {
        assertEquals("1 more did not answer", unanswered(found(1u, 0u), tor = false))
        assertEquals("3 more did not answer", unanswered(found(3u, 0u), tor = false))
        assertEquals("3 more did not answer: try with Tor on", unanswered(found(3u, 2u), tor = false))
        assertEquals("3 more did not answer", unanswered(found(3u, 2u), tor = true))
    }

    @Test
    fun an_announced_name_is_shown_on_one_line_short_and_unturned() {
        assertEquals("a test hub", shownName("  a\n test\thub "))
        assertEquals("evil hub", shownName("evil\u202E hub"))
        assertEquals(40, shownName("x".repeat(100))!!.length)
        assertNull(shownName(" \u200B "))
    }
}
