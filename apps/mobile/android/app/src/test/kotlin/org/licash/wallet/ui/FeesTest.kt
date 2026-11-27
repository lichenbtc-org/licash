package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.ContractFee
import org.licash.core.ContractRange
import org.licash.core.ViaProvider
import org.licash.core.InvoiceQuote
import org.licash.core.Rate

class FeesTest {
    @Test
    fun relative_fees_round_up_and_add_the_base_like_the_sdk() {
        assertEquals(0uL, relativeFee(0uL, 5_000uL))
        assertEquals(1uL, relativeFee(1uL, 1uL))
        assertEquals(50uL, relativeFee(10_000uL, 5_000uL))
        assertEquals(60uL, feeDue(10_000uL, Rate(10uL, 5_000uL)))
        assertEquals(11uL, feeDue(1uL, Rate(10uL, 1uL)))
        assertEquals(ULong.MAX_VALUE, feeDue(ULong.MAX_VALUE, Rate(ULong.MAX_VALUE, ULong.MAX_VALUE)))
    }

    @Test
    fun historical_fees_never_invent_a_rate_or_a_recipient_split() {
        val fee = recordedFee(1_000uL, 12uL)
        assertNull(fee.rate)
        assertTrue(fee.components.isEmpty())
        assertTrue(fee.explanation.contains("not saved"))
        assertEquals(0uL, recordedFee(1_000uL, 0uL).fee)
        assertTrue(recordedFee(1_000uL, 0uL).explanation.contains("may not be final"))
    }

    @Test
    fun a_payout_splits_its_fee_by_who_gets_it_leaving_out_parts_of_zero() {
        val quoted = payoutFee(10_000uL, 160uL, hub = 10uL, provider = 100uL, network = 50uL, quoted = true)
        assertEquals(listOf("Hub" to 10uL, "Payout provider" to 100uL, "Bitcoin network" to 50uL), quoted.components)
        assertTrue(quoted.explanation.contains("its own coin"))
        // Before its lock is made, the hub has charged nothing yet.
        val recorded = payoutFee(10_000uL, 150uL, hub = 0uL, provider = 100uL, network = 50uL, quoted = false)
        assertEquals(listOf("Payout provider" to 100uL, "Bitcoin network" to 50uL), recorded.components)
        assertTrue(recorded.explanation.contains("not saved"))
        assertNull(recorded.rate)
    }

    @Test
    fun parts_that_do_not_add_up_to_the_fee_are_not_shown() {
        assertTrue(payoutFee(10_000uL, 99uL, 10uL, 100uL, 50uL, quoted = false).components.isEmpty())
        assertTrue(payoutFee(10_000uL, 0uL, 0uL, 0uL, 0uL, quoted = true).components.isEmpty())
        assertTrue(feeParts(ULong.MAX_VALUE - 1uL, listOf("a" to ULong.MAX_VALUE, "b" to 1uL)).isEmpty())
        assertEquals(listOf("Hub" to 1uL, "Swap provider" to 4uL), swapFee(300uL, 5uL, hub = 1uL, provider = 4uL).components)
        assertEquals(recordedFee(300uL, 5uL), swapFee(300uL, 5uL, hub = 1uL, provider = 3uL))
    }

    @Test
    fun a_contract_costs_its_opening_fee_and_the_interest_on_each_part_and_not_its_reserve() {
        val range = ContractRange(131_071uL, 16_777_215uL, 432u, 52_560u, 2u, 20_000uL, 3_000uL, 10_000u, 5_000u, 52_560u)
        val fee = ContractFee(opening = 3_000uL, interest = 41_943uL, interestFunded = 20_971uL)
        val cost = contractCost(range, 16_777_215uL, fee, 8_388_607uL)
        assertEquals(65_914uL, cost.fee)
        assertEquals(
            listOf(
                "Hub's opening fee" to 3_000uL,
                "Interest on the hub's part" to 41_943uL,
                "Interest on your part" to 20_971uL,
            ),
            cost.components,
        )
        assertTrue(cost.explanation, cost.explanation.contains("1% a year on the 8,388,608 sat the hub funds"))
        assertTrue(cost.explanation, cost.explanation.contains("0.5% a year on the 8,388,607 sat you fund yourself"))
        assertTrue(cost.explanation, cost.explanation.contains("your reserve, which comes back to you"))
        assertEquals("Total cost", cost.totalLabel)
        // None of hers: no interest on her part, and her rate unsaid.
        val alone = contractCost(range, 131_071uL, ContractFee(3_000uL, 655uL, 0uL), 0uL)
        assertEquals(3_655uL, alone.fee)
        assertEquals(listOf("Hub's opening fee", "Interest on the hub's part"), alone.components.map { it.first })
        assertTrue(!alone.explanation.contains("you fund"))
    }

    @Test
    fun setup_cost_is_not_labeled_a_transaction_fee() {
        val cost = setupCost(4_096uL, 23_000uL)
        assertEquals("Total cost", cost.totalLabel)
        assertEquals("Setup cost", cost.title)
        assertNull(cost.rate)
    }

    @Test
    fun an_invoice_through_a_provider_splits_its_fee() {
        val provider = ViaProvider(url = "https://swaps.example", name = null, fee = 12uL, lockFee = 1uL, refundBlocks = 200u)
        val quote = InvoiceQuote(hub = "https://hub.example", amount = 1_000uL, fee = 13uL, description = null, provider = provider)
        val via = invoiceFee(quote)
        assertEquals(listOf("Hub" to 1uL, "Swap provider" to 12uL), via.components)
        assertTrue(via.explanation.contains("routing"))
    }
}
