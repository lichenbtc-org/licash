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

    private fun contract(createdAt: Long, state: ContractState) = Contract(
        id = "c$createdAt", hub = "https://hub.example", state = state, mock = false, cap = 131_071uL, price = 1_000uL,
        funded = 0uL, fundedReceived = false, paidFrom = 50_000uL, protectsUntil = 2_000u, closesAt = 2_100u,
        funding = null, createdAt = createdAt, covers = 0uL, step = null, transfer = null,
    )

    @Test
    fun the_first_funding_goes_from_waiting_to_ready() {
        assertEquals(FundingStage.WAITING, stage(fresh))
        assertEquals(FundingStage.SEEN, stage(fresh.copy(incoming = listOf(line(Kind.ONCHAIN)))))
        assertEquals(FundingStage.IN_BLOCK, stage(fresh.copy(balance = balance(onchain = 50_000uL))))
        // Cashed out to itself, kept: not a first funding to protect.
        assertEquals(FundingStage.WAITING, stage(fresh.copy(balance = balance(onchain = 50_000uL, kept = 50_000uL))))
        assertEquals(FundingStage.OPENING, stage(fresh.copy(balance = balance(onchain = 50_000uL), opening = "https://hub.example")))
        assertEquals(listOf("Waiting", "Seen", "In a block", "Opening vault", "Ready"), FundingStage.entries.map { it.title })
        // One block is all a deposit is said to need: how deep it is, under its details.
        assertEquals("50,000 sat on its way. One block is enough, about 10 minutes.", stageSays(FundingStage.SEEN, 50_000uL))
        assertFalse(FundingStage.entries.any { stageSays(it, 1uL).contains("confirmation", ignoreCase = true) })
    }

    @Test
    fun a_vault_guided_to_keeps_its_steps_in_sight_until_it_protects() {
        val guided = fresh.copy(guideSince = 200L)
        // Signed, its coin spent, nothing on Bitcoin any more: still opening, not back to waiting.
        for (state in listOf(ContractState.Opening, ContractState.Confirming)) {
            val setUp = guided.copy(contracts = listOf(contract(300L, state)))
            assertEquals("$state", FundingStage.OPENING, stage(setUp))
            assertEquals(300L, guidedVault(setUp, 200L)?.createdAt)
        }
        // It protects: ready, whatever arrived on Bitcoin since.
        val ready = guided.copy(contracts = listOf(contract(300L, ContractState.Protecting)), balance = balance(onchain = 9_000uL))
        assertEquals(FundingStage.READY, stage(ready))
        // One from before the guide is not its vault, nor one that failed, nor any never guided.
        assertNull(guidedVault(guided.copy(contracts = listOf(contract(100L, ContractState.Protecting))), 200L))
        assertNull(guidedVault(guided.copy(contracts = listOf(contract(300L, ContractState.Failed("no")))), 200L))
        assertNull(guidedVault(ready, null))
        assertEquals(FundingStage.IN_BLOCK, stage(ready.copy(guideSince = null)))
        // The newest of those since.
        val two = guided.copy(contracts = listOf(contract(300L, ContractState.Protecting), contract(400L, ContractState.Opening)))
        assertEquals(400L, guidedVault(two, 200L)?.createdAt)
    }

    @Test
    fun a_step_is_done_once_passed_and_in_a_block_as_soon_as_reached() {
        val marks = { at: FundingStage -> FundingStage.entries.map { markOf(it, at) } }
        assertEquals(listOf(Mark.NOW, Mark.NEXT, Mark.NEXT, Mark.NEXT, Mark.NEXT), marks(FundingStage.WAITING))
        assertEquals(listOf(Mark.DONE, Mark.NOW, Mark.NEXT, Mark.NEXT, Mark.NEXT), marks(FundingStage.SEEN))
        // In a block: nothing more is waited for there, so it does not keep spinning.
        assertEquals(listOf(Mark.DONE, Mark.DONE, Mark.DONE, Mark.NEXT, Mark.NEXT), marks(FundingStage.IN_BLOCK))
        assertEquals(listOf(Mark.DONE, Mark.DONE, Mark.DONE, Mark.NOW, Mark.NEXT), marks(FundingStage.OPENING))
        assertEquals(List(5) { Mark.DONE }, marks(FundingStage.READY))
    }

    @Test
    fun a_first_deposit_is_asked_as_one_figure() {
        assertEquals(50_000uL, FIRST_DEPOSIT)
        assertEquals("Send at least 50,000 sat. It opens your vault and covers its reserve and fees.", HOW_MUCH)
    }

    @Test
    fun a_wallet_is_set_up_until_its_vault_was_said_ready_and_not_one_in_use() {
        // No hub, or one and nothing yet: set up.
        assertTrue(setupDue(fresh.copy(hubs = emptyList())))
        assertTrue(setupDue(fresh))
        // In use, never asked: as before this, no screen of it, with a vault or without.
        val held = fresh.copy(balance = balance(notes = 10_000uL))
        assertFalse(setupDue(held))
        assertFalse(setupDue(held.copy(contracts = listOf(contract(100L, ContractState.Protecting)))))
        // Asked: until its vault protects, then once more, to say so.
        val asked = held.copy(guideSince = 200L)
        assertTrue(setupDue(asked))
        assertTrue(setupDue(asked.copy(contracts = listOf(contract(300L, ContractState.Opening)))))
        val ready = asked.copy(contracts = listOf(contract(300L, ContractState.Protecting)))
        assertTrue(setupDue(ready))
        assertFalse(setupDue(ready.copy(guideSince = null)))
        // Its vault ended before that was said: over.
        assertFalse(setupDue(asked.copy(contracts = listOf(contract(300L, ContractState.Closed)))))
        assertEquals("Set up your vault", setupWords(FundingStage.WAITING).title)
        assertEquals(FundingStage.entries.size, FundingStage.entries.map { setupWords(it).line }.toSet().size)
    }

    @Test
    fun send_takes_a_balance_or_a_vault() {
        assertFalse(canSend(fresh))
        assertTrue(canSend(fresh.copy(balance = balance(notes = 1uL))))
        assertTrue(canSend(fresh.copy(balance = balance(onchain = 1uL))))
        for (state in listOf(ContractState.Opening, ContractState.Confirming, ContractState.Protecting)) {
            assertTrue("$state", canSend(fresh.copy(contracts = listOf(contract(1L, state)))))
        }
        // One that ended or failed is no vault.
        assertFalse(canSend(fresh.copy(contracts = listOf(contract(1L, ContractState.Closed), contract(2L, ContractState.Failed("no"))))))
        assertTrue(NOTHING_TO_SEND.contains("vault"))
    }

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
