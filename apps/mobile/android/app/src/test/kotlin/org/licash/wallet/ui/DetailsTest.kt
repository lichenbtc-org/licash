package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Activity
import org.licash.core.Details
import org.licash.core.Kind
import org.licash.core.LockStep
import org.licash.core.Onchain
import org.licash.core.PayoutSteps
import org.licash.core.State

class DetailsTest {
    private fun line(kind: Kind, state: State = State.PENDING) =
        Activity(id = "a", kind = kind, state = state, amount = 1_000uL, fee = 0uL, detail = "The hub refused", at = null)

    private fun steps(
        lock: LockStep? = LockStep.LOCKED,
        coin: String? = "c0",
        claim: String? = null,
        claimBy: UInt? = 1_000u,
        tip: UInt = 900u,
    ) = PayoutSteps(
        lock = lock, lockExpiry = 1_100u, timeout = 1_010u, claimBy = claimBy, coin = coin, coinHeight = null,
        claim = claim, claimHeight = null, depth = 1u, tip = tip,
    )

    private fun payout(steps: PayoutSteps) = Details.Payout(
        hub = "https://hub.example", provider = "https://swaps.example", address = "bc1q", coin = steps.coin,
        claim = steps.claim, failure = null, progress = steps, providerFee = 0u, claimFee = 0u, lockFee = 0u,
    )

    private fun deposit(confirmations: UInt?, depth: UInt? = 2u) = Details.Moved(
        hub = "https://hub.example", hash = "h", provider = null, pays = null, address = "bc1q",
        payment = confirmations?.let { Onchain(txid = "t", fee = null, height = null, confirmations = it) },
        depth = depth, fundBy = null, timeout = null, refund = null,
    )

    private fun swap(lock: String?) = Details.Swap(
        from = "https://a.example", to = "https://b.example", provider = "https://swaps.example", lock = lock,
        theirs = null, failure = null, providerFee = 0u, lockFee = 0u, expiry = null,
    )

    @Test
    fun a_payout_is_on_its_way_then_sent_then_arrived() {
        val under = line(Kind.PAYOUT)
        assertEquals("On its way", status(under, false, payout(steps(coin = null))))
        assertEquals("On its way", status(under, false, payout(steps())))
        assertEquals("Sent. Confirming, about 10 min", status(under, false, payout(steps(claim = "t"))))
        assertEquals("Arrived", status(line(Kind.PAYOUT, State.DONE), false, payout(steps(claim = "t"))))
    }

    @Test
    fun one_that_failed_says_why_and_what_becomes_of_the_money() {
        val failed = line(Kind.PAYOUT, State.FAILED)
        assertEquals(
            "The hub refused. Your money comes back by itself.",
            status(failed, false, payout(steps())),
        )
        assertEquals("The hub refused. Nothing was taken.", status(failed, false, payout(steps(lock = null))))
        val moved = line(Kind.SWAP, State.FAILED)
        assertEquals("The hub refused. Nothing was taken.", status(moved, false, swap(null)))
        assertEquals("The hub refused. Your money comes back by itself.", status(moved, false, swap("l")))
        assertEquals("The hub refused", status(line(Kind.SENT, State.FAILED), false, null))
    }

    @Test
    fun bitcoin_coming_in_counts_its_blocks_down_as_time() {
        val moved = line(Kind.MOVED)
        assertEquals("Confirming, about 10 min", status(line(Kind.ONCHAIN), true, null))
        assertEquals("Waiting for its payment", status(moved, false, deposit(null)))
        assertEquals("Confirming, about 20 min", status(moved, false, deposit(0u)))
        assertEquals("Confirming, about 10 min", status(moved, false, deposit(1u)))
        assertEquals("Almost there", status(moved, false, deposit(2u)))
        assertEquals("In your balance", status(line(Kind.MOVED, State.DONE), false, deposit(2u)))
    }

    @Test
    fun no_status_names_a_block_a_note_or_a_provider() {
        val all = listOf(
            status(line(Kind.PAYOUT), false, payout(steps())),
            status(line(Kind.PAYOUT, State.FAILED), false, payout(steps())),
            status(line(Kind.SWAP), false, swap("l")),
            status(line(Kind.SWAP, State.DONE), false, swap("l")),
            status(line(Kind.MOVED), false, deposit(0u)),
            status(line(Kind.CONTRACT), false, Details.Contract("https://hub.example", "f")),
            status(line(Kind.CONTRACT, State.DONE), false, Details.Contract("https://hub.example", "f")),
            status(line(Kind.CONTRACT), false, Details.Contract("https://hub.example", null)),
            status(line(Kind.INVOICE), false, Details.Invoice("https://hub.example", null, null, null)),
            status(line(Kind.SENT), false, null),
        )
        for (said in all) {
            for (word in listOf("block", "note", "provider", "contract", "Licash")) {
                assertFalse("$said: $word", said.contains(word, ignoreCase = true))
            }
        }
    }

    @Test
    fun a_payout_to_finish_asks_for_the_app_in_time_not_blocks() {
        val under = line(Kind.PAYOUT)
        assertEquals("Open the app within 17 hours to finish it", needs(under, steps(), developer = false))
        assertEquals(
            "Open the app within 17 hours to finish it (block 1000)",
            needs(under, steps(), developer = true),
        )
        assertEquals("Keep the app open to finish it", needs(under, steps(tip = 0u), developer = false))
        assertEquals(
            "Too late to finish: your money comes back by itself",
            needs(under, steps(tip = 1_001u), developer = false),
        )
        // Nothing asked once sent, once over, or with no time to run out.
        assertNull(needs(under, steps(claim = "t"), developer = false))
        assertNull(needs(line(Kind.PAYOUT, State.DONE), steps(), developer = false))
        assertNull(needs(under, steps(claimBy = null), developer = false))
    }

    @Test
    fun the_history_names_a_line_in_a_word_or_two() {
        assertEquals("Arriving", title(line(Kind.ONCHAIN), coming = true))
        assertEquals("Protection", title(line(Kind.CONTRACT), coming = false))
        assertEquals("Sent on Bitcoin", title(line(Kind.PAYOUT), coming = false))
        assertEquals("From Bitcoin", title(line(Kind.MOVED), coming = false))
        // Her part of the coin a contract took, back as notes: not a payment from anyone.
        assertEquals("From Bitcoin, protected", title(line(Kind.FUNDED), coming = false))
        assertFalse(paid(line(Kind.FUNDED)))
    }

    @Test
    fun a_protection_being_set_up_says_so_then_confirming_or_why_it_failed() {
        val opening = Details.Contract("https://hub.example", funding = null)
        assertEquals("Being set up", status(line(Kind.CONTRACT), false, opening))
        val signed = Details.Contract("https://hub.example", funding = "f")
        assertEquals("Confirming, about 10 min", status(line(Kind.CONTRACT), false, signed))
        assertEquals("The hub refused. Nothing was taken.", status(line(Kind.CONTRACT, State.FAILED), false, opening))
        // Its funding signed, or never to confirm: why alone.
        assertEquals("The hub refused", status(line(Kind.CONTRACT, State.FAILED), false, signed))
    }

    @Test
    fun a_contract_says_what_it_cost_apart_from_the_reserve_it_gives_back_as_it_closes() {
        // Its money back is said as such, on its way too, and paid in, not out.
        assertEquals("Protection closed", title(line(Kind.CLOSED), coming = false))
        assertEquals("Protection closed", title(line(Kind.CLOSED), coming = true))
        assertFalse(paid(line(Kind.CLOSED)))
        assertTrue(paid(line(Kind.CONTRACT)))
        assertEquals(3_655uL, opened(23_655uL, 20_000uL))
        assertEquals(0uL, opened(5_000uL, 20_000uL))
    }

    private fun lightning(provider: String?, failure: String?, refundBlocks: UInt? = null) = Details.Lightning(
        hub = "https://hub.example", invoice = "lnbc", preimage = null, failure = failure, provider = provider,
        expiry = provider?.let { 1_200u }, refundBlocks = refundBlocks,
    )

    @Test
    fun a_payment_a_swap_provider_did_not_make_waits_for_its_lock_to_expire() {
        val under = line(Kind.LIGHTNING)
        assertEquals("Under way", status(under, false, lightning("https://swaps.example", null, 200u)))
        assertEquals(
            "Not paid. Your money comes back by itself in about 33 hours.",
            status(under, false, lightning("https://swaps.example", "declined", 200u)),
        )
        assertEquals(
            "Not paid. Your money comes back by itself.",
            status(under, false, lightning("https://swaps.example", "declined")),
        )
        // A hub's gateway refunds a failed payment at once: never this.
        assertEquals("Under way", status(under, false, lightning(null, "no route")))
    }
}
