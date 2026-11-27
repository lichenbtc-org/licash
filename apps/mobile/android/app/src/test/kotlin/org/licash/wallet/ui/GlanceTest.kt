package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.Activity
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.Details
import org.licash.core.Hub
import org.licash.core.Kind
import org.licash.core.Onchain
import org.licash.core.Rate
import org.licash.core.State
import org.licash.wallet.ChainStatus
import org.licash.wallet.STALE_SECS
import org.licash.wallet.Ui
import org.licash.wallet.key

class GlanceTest {
    private val now = 1_800_000_000L
    private val synced = ChainStatus(height = 900, peers = 1, synced = true)

    private fun line(kind: Kind, state: State = State.PENDING, id: String = "a", at: Long? = null) =
        Activity(id = id, kind = kind, state = state, amount = 10_000uL, fee = 0uL, detail = "", at = at)

    private fun hub() = Hub(
        url = "https://hub.example", feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false,
        mailbox = false,
        lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        contracts = null,
    )

    private fun deposit(paid: Boolean) = Details.Moved(
        hub = "https://hub.example", hash = "h", pays = null, address = "bc1q",
        payment = if (paid) Onchain(txid = "t", fee = null, height = null, confirmations = 0u) else null,
        depth = null, fundBy = null, timeout = null, refund = null,
    )

    @Test
    fun at_rest_home_says_nothing() {
        val done = listOf(line(Kind.SENT, State.DONE), line(Kind.RECEIVED, State.FAILED, "b"))
        assertNull(glance(Ui(history = done, chain = synced, hubs = listOf(hub())), now))
        // No hub yet: nothing to catch up for.
        assertNull(glance(Ui(), now))
    }

    @Test
    fun one_payment_under_way_is_told_with_its_amount_and_opens_itself() {
        val coming = line(Kind.ONCHAIN)
        val one = glance(Ui(incoming = listOf(coming), chain = synced), now) as Glance.One
        assertEquals("Receiving 10,000 sat", one.text)
        assertEquals(coming, one.activity)
        assertEquals(true, one.coming)

        val texts = mapOf(
            Kind.SENT to "Sending 10,000 sat",
            Kind.LIGHTNING to "Sending 10,000 sat",
            Kind.PAYOUT to "Sending 10,000 sat",
            Kind.RECEIVED to "Receiving 10,000 sat",
            Kind.INVOICE to "Receiving 10,000 sat",
            Kind.MOVED to "Receiving 10,000 sat",
            Kind.FUNDED to "Receiving 10,000 sat",
            Kind.ONCHAIN to "Receiving 10,000 sat",
            Kind.SWAP to "Moving 10,000 sat",
            Kind.CONTRACT to "Setting up protection",
            Kind.OPTIMIZED to "Optimizing notes",
            Kind.CLOSED to "Receiving 10,000 sat",
        )
        assertEquals(Kind.entries.toSet(), texts.keys)
        for ((kind, text) in texts) {
            val under = glance(Ui(history = listOf(line(kind)), chain = synced), now) as Glance.One
            assertEquals(kind.name, text, under.text)
            assertEquals(false, under.coming)
        }
    }

    @Test
    fun several_under_way_are_counted_and_open_the_history() {
        val ui = Ui(
            incoming = listOf(line(Kind.ONCHAIN, id = "c")),
            history = listOf(line(Kind.SENT), line(Kind.PAYOUT, id = "b"), line(Kind.SENT, State.DONE, "d")),
            chain = synced,
        )
        val many = glance(ui, now)
        assertEquals(Glance.Many(3), many)
        assertEquals("3 in progress", many?.text)
    }

    @Test
    fun what_is_stuck_or_never_paid_is_left_to_the_history() {
        val stuck = line(Kind.SENT, at = now - STALE_SECS - 1)
        assertNull(glance(Ui(history = listOf(stuck), chain = synced), now))
        val recent = line(Kind.SENT, at = now - 60)
        assertEquals("Sending 10,000 sat", glance(Ui(history = listOf(recent), chain = synced), now)?.text)

        val moved = line(Kind.MOVED)
        assertNull(glance(Ui(history = listOf(moved), under = mapOf(moved.key to deposit(false)), chain = synced), now))
        val paid = Ui(history = listOf(moved), under = mapOf(moved.key to deposit(true)), chain = synced)
        assertEquals("Receiving 10,000 sat", glance(paid, now)?.text)
    }

    @Test
    fun a_protection_being_opened_shows_its_steps_not_its_line() {
        val c = Contract(
            id = "c1", hub = "https://hub.example", state = ContractState.Opening, mock = false, cap = 4_096uL,
            covers = 0uL, price = 1_000uL, funded = 0uL, fundedReceived = false, paidFrom = 50_000uL,
            protectsUntil = 2_000u, closesAt = 2_100u, funding = null, createdAt = 0L, step = null, transfer = null,
        )
        val line = line(Kind.CONTRACT, id = "c1")
        val opening = Ui(history = listOf(line), contracts = listOf(c), opening = c.hub, chain = synced)
        assertEquals(Glance.Protecting("https://hub.example"), glance(opening, now))
        // Its opening interrupted, the app restarted: its line, under way.
        assertEquals("Setting up protection", (glance(opening.copy(opening = null), now) as Glance.One).text)
        // Another line under way still shows as itself.
        val sent = opening.copy(history = listOf(line, line(Kind.SENT, id = "s")))
        assertEquals("Sending 10,000 sat", glance(sent, now)?.text)
    }

    @Test
    fun a_payment_comes_before_protection_then_a_problem() {
        val all = Ui(
            history = listOf(line(Kind.SENT)), opening = "https://hub.example", problem = "No hub answered",
            hubs = listOf(hub()),
        )
        assertEquals("Sending 10,000 sat", glance(all, now)?.text)
        val opening = all.copy(history = emptyList())
        assertEquals(Glance.Protecting("https://hub.example"), glance(opening, now))
        assertEquals("Setting up protection", glance(opening, now)?.text)
        val behind = opening.copy(opening = null)
        assertEquals(Glance.Behind("No hub answered"), glance(behind, now))
        assertEquals("Not up to date", glance(behind, now)?.text)
        // Catching up is the connections' to say, not this line's.
        val syncing = behind.copy(problem = null)
        assertNull(glance(syncing, now))
        assertNull(glance(syncing.copy(chain = synced), now))
    }
}
