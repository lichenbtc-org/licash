package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.Balance
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.Hub
import org.licash.core.Rate
import org.licash.wallet.ChainStatus
import org.licash.wallet.Ui

class NextStepTest {
    private val one = "https://one.example"
    private val two = "https://two.example"

    private fun contract(hub: String, until: UInt, state: ContractState = ContractState.Protecting) = Contract(
        id = "c$until", hub = hub, state = state, mock = false, cap = 131_071uL, price = 1_000uL, funded = 0uL,
        fundedReceived = false, paidFrom = 50_000uL, protectsUntil = until, closesAt = until + 100u, funding = null,
        createdAt = 0L, covers = 0uL, step = null, transfer = null,
    )

    private fun hub() = Hub(
        url = one, feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false, mailbox = false,
        lightningPay = null, lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null, lightning = null,
        contracts = null,
    )

    private val held = Ui(
        wallet = true,
        hubs = listOf(hub()),
        balance = Balance(10_000uL, 0uL, 0uL, 0uL, 0uL, 0uL, 0uL),
        chain = ChainStatus(height = 10_000),
    )

    @Test
    fun a_vault_ending_soon_is_renewed_unless_another_takes_over() {
        val soon = contract(one, 11_000u)
        assertEquals(Next.Renew(one, 1_000u), renewing(listOf(soon), 10_000u, null))
        // Past two weeks of blocks: not yet.
        assertNull(renewing(listOf(contract(one, 12_100u)), 10_000u, null))
        // Ended already, or the chain's height unknown: nothing to say.
        assertNull(renewing(listOf(contract(one, 9_000u)), 10_000u, null))
        assertNull(renewing(listOf(soon), 0u, null))
        // A new one opening, confirming or protecting longer at that hub.
        assertNull(renewing(listOf(soon), 10_000u, "$one/"))
        assertNull(renewing(listOf(soon, contract(one, 0u, ContractState.Confirming)), 10_000u, null))
        assertNull(renewing(listOf(soon, contract(one, 20_000u)), 10_000u, null))
        // At another hub: no help. The soonest first.
        assertEquals(
            Next.Renew(two, 500u),
            renewing(listOf(soon, contract(two, 10_500u), contract(one, 20_000u)), 10_000u, null),
        )
    }

    @Test
    fun one_step_at_a_time_the_most_pressing_first() {
        val protect = Next.Protect(one, 5_000uL)
        assertEquals(Next.Fund, nextStep(held, true, 1_000uL, true, protect))
        assertEquals(Next.OnBitcoin(1_000uL), nextStep(held, false, 1_000uL, true, protect))
        assertEquals(Next.Backup, nextStep(held, false, null, true, protect))
        // Nothing held: no backup to nag about yet.
        assertEquals(protect, nextStep(held.copy(balance = Balance(0uL, 0uL, 0uL, 0uL, 0uL, 0uL, 0uL)), false, null, true, protect))
        val ending = held.copy(contracts = listOf(contract(one, 10_100u)))
        assertEquals(Next.Renew(one, 100u), nextStep(ending, false, null, false, protect))
        assertEquals(protect, nextStep(held, false, null, false, protect))
        assertNull(nextStep(held, false, null, false, null))
    }

    @Test
    fun each_step_says_what_to_do_in_a_line() {
        assertNull(stepWords(Next.Fund))
        assertEquals(
            StepWords("Your vault at One ends in 7 days", "Open a new one to stay protected.", "Renew"),
            stepWords(Next.Renew(one, 1_008u), "One"),
        )
        assertEquals("Back up", stepWords(Next.Backup)?.action)
        assertEquals("5,000 sat at One not protected", stepWords(Next.Protect(one, 5_000uL), "One")?.title)
    }
}
