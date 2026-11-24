package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Activity
import org.licash.core.Balance
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.Hub
import org.licash.core.Kind
import org.licash.core.Rate
import org.licash.core.State
import org.licash.wallet.Ui

class FundingTest {
    private fun hub() = Hub(
        url = "https://hub.example", feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false,
        mailbox = false,
        lightningPay = null, lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        lightning = null, contracts = null,
    )

    private fun line(kind: Kind) =
        Activity(id = "a", kind = kind, state = State.DONE, amount = 50_000uL, fee = 0uL, detail = "", at = null)

    private fun balance(notes: ULong = 0uL, onchain: ULong = 0uL, kept: ULong = 0uL) =
        Balance(notes, 0uL, onchain, 0uL, kept, 0uL, 0uL)

    private val fresh = Ui(wallet = true, hubs = listOf(hub()))

    @Test
    fun only_a_wallet_that_never_held_notes_is_guided() {
        assertTrue(guiding(fresh))
        // Its first coin, on its way or in a block, and the vault opening: still guided.
        assertTrue(guiding(fresh.copy(history = listOf(line(Kind.ONCHAIN), line(Kind.CONTRACT)))))
        // No hub yet: choosing one comes first.
        assertFalse(guiding(fresh.copy(hubs = emptyList())))
        // Notes held, or ever paid in or out: an existing wallet, not guided.
        assertFalse(guiding(fresh.copy(balance = balance(notes = 1uL))))
        for (kind in listOf(Kind.RECEIVED, Kind.SENT, Kind.PAYOUT, Kind.MOVED, Kind.INVOICE, Kind.LIGHTNING)) {
            assertFalse("$kind", guiding(fresh.copy(history = listOf(line(kind)))))
        }
    }

    @Test
    fun the_first_funding_goes_from_waiting_to_opening() {
        assertEquals(FundingStage.WAITING, stage(fresh))
        assertEquals(FundingStage.SEEN, stage(fresh.copy(incoming = listOf(line(Kind.ONCHAIN)))))
        assertEquals(FundingStage.IN_BLOCK, stage(fresh.copy(balance = balance(onchain = 50_000uL))))
        // Cashed out to itself, kept: not a first funding to protect.
        assertEquals(FundingStage.WAITING, stage(fresh.copy(balance = balance(onchain = 50_000uL, kept = 50_000uL))))
        assertEquals(FundingStage.OPENING, stage(fresh.copy(balance = balance(onchain = 50_000uL), opening = "https://hub.example")))
        assertEquals(listOf("Waiting", "Seen", "In a block", "Opening vault", "Ready"), FundingStage.entries.map { it.title })
        assertEquals("50,000 sat on its way. It needs a block, about 10 minutes.", stageSays(FundingStage.SEEN, 50_000uL))
    }

    @Test
    fun the_least_to_send_pays_the_price_and_a_small_part() {
        val price = { cap: ULong, funded: ULong -> 43_000uL + cap / 1_000uL + funded * 0uL }
        // A hub taking it: the price for the cap, and the fixed part.
        assertEquals(44_131uL, leastFor(131_071uL, price) { _, least -> least })
        // One refusing a contract of that cap for it: none.
        assertNull(leastFor(131_071uL, price) { _, _ -> null })
        assertEquals(524_287uL, receivingCap(listOf(131_071uL, 262_143uL, 524_287uL, 1_048_575uL)))
        assertEquals(262_143uL, receivingCap(listOf(131_071uL, 262_143uL)))
        assertNull(receivingCap(emptyList()))
    }

    @Test
    fun how_much_to_send_follows_what_the_vault_is_for() {
        assertEquals("Send at least 44,131 sat. Send what you plan to spend.", howMuch(Intent.BOTH, 44_131uL, null))
        assertEquals(
            "Send at least 50,000 sat for room to receive about 524,287 sat.",
            howMuch(Intent.RECEIVE, 44_131uL, 50_000uL to 524_287uL),
        )
        assertNull(howMuch(Intent.PAY, null, null))
    }

    private fun contract(createdAt: Long, state: ContractState) = Contract(
        id = "c$createdAt", hub = "https://hub.example", state = state, mock = false, cap = 131_071uL, price = 1_000uL,
        funded = 0uL, fundedReceived = false, paidFrom = 50_000uL, protectsUntil = 2_000u, closesAt = 2_100u,
        funding = null, createdAt = createdAt, covers = 0uL, step = null, transfer = null,
    )

    @Test
    fun the_guide_asked_for_again_lasts_until_a_new_vault_protects() {
        val held = fresh.copy(balance = balance(notes = 10_000uL), contracts = listOf(contract(100L, ContractState.Protecting)))
        // Never asked: a wallet holding notes is not guided.
        assertFalse(guiding(held))
        assertFalse(guideAsked(held, null))
        // Asked after its vault: guided, a vault being set up or failed since too.
        assertTrue(guideAsked(held, 200L))
        assertTrue(guideAsked(held.copy(contracts = held.contracts + contract(300L, ContractState.Opening)), 200L))
        assertTrue(guideAsked(held.copy(contracts = held.contracts + contract(300L, ContractState.Failed("no"))), 200L))
        // A vault asked for since then protects: done.
        assertFalse(guideAsked(held.copy(contracts = held.contracts + contract(300L, ContractState.Protecting)), 200L))
        // No hub: choosing one comes first.
        assertFalse(guideAsked(held.copy(hubs = emptyList()), 200L))
    }
}
