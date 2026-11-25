package org.licash.wallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.LicashException

class FormatTest {
    @Test
    fun a_reason_is_a_sentence_with_its_amounts_grouped() {
        assertEquals(
            "Hub takes at most 5,000,000 sat, not 12,000,000 sat",
            plain("hub takes at most 5000000 sat, not 12000000 sat"),
        )
        // Short amounts and other numbers stay as they are.
        assertEquals("Lock expires at block 1200, 500 sat", plain("lock expires at block 1200, 500 sat"))
    }

    @Test
    fun a_hub_with_no_room_for_a_vault_is_said_as_that() {
        for (refusal in listOf(
            "The hub's wallet funds 0 sat of a contract at most now",
            "hub.example: the hub's wallet funds 100,000 sat of a contract at most now",
            "The hub has 64 contracts live, its most: later",
            "Too many openings under way: later",
            "too many openings signed and not funded: later",
        )) {
            assertEquals(refusal, HUB_NO_ROOM, openFailure(refusal))
        }
        assertTrue(HUB_NO_ROOM.contains("another hub"))
        // Anything else as it was said.
        assertEquals("The price is above the most you set", openFailure("The price is above the most you set"))
    }

    @Test
    fun a_hub_charging_more_than_agreed_is_named_and_where_to_approve_it() {
        val said = explain(org.licash.core.LicashException.FeesRaised("https://hub.example:8443"))
        assertEquals(
            "hub.example:8443 raised its fees since your protection there started. " +
                "Approve them in Settings, under Hubs, to pay there.",
            said,
        )
    }

    @Test
    fun a_fee_says_what_it_is_of_the_amount() {
        assertEquals(null, share(0uL, 100uL))
        assertEquals(null, share(5uL, 0uL))
        assertEquals("<0.01%", share(1uL, 1_000_000uL))
        assertEquals("0.24%", share(24uL, 10_000uL))
        assertEquals("1%", share(1uL, 100uL))
        assertEquals("1.2%", share(12uL, 1_000uL))
        assertEquals("5%", share(1uL, 20uL))
        assertEquals("10%", share(999uL, 10_000uL))
        assertEquals("13%", share(1uL, 8uL))
        assertEquals("3,000%", share(30uL, 1uL))
        assertEquals("12 sat · 0.24%", feeOf(12uL, 5_000uL))
        assertEquals("0 sat", feeOf(0uL, 5_000uL))
    }

    @Test
    fun a_balance_too_small_for_a_code_is_said_in_plain_words() {
        assertEquals(
            "Your balance can't pay 5,000 sat and its fee here.",
            plain("no hub it names is one trusted holding 5000 and the fee"),
        )
        assertEquals(
            "Your balance can't pay 20 sat and its fee here.",
            plain("no hub it names is one trusted holding 20 and the fee"),
        )
        // A code that once said where to pay on Bitcoin instead says no more of it.
        assertEquals(
            "Your balance can't pay 1,500 sat and its fee here.",
            plain("no hub it names is one trusted holding 1500 and the fee: pay tb1qexample on Bitcoin"),
        )
    }

    @Test
    fun no_provider_is_said_without_naming_providers() {
        assertEquals(
            "No one can send 20,000 sat on Bitcoin right now. Try less, or later.",
            plain("no swap provider found pays 20000 sat out on Bitcoin now"),
        )
        assertEquals(
            "No one can move 1,500 sat between your hubs right now. Try less, or later.",
            plain("no swap provider found moves 1500 sat from http://a:1 to http://b:2 now"),
        )
    }

    @Test
    fun the_most_providers_pay_out_is_offered_only_below_what_was_asked() {
        assertTrue(noPayout(LicashException.Invalid("no swap provider found pays 20000 sat out on Bitcoin now")))
        assertFalse(noPayout(LicashException.Invalid("not an address")))
        assertEquals(15_000uL, offeredInstead(20_000uL, 15_000uL))
        // Nothing asked (all of it), none found, or no less: nothing to offer.
        assertNull(offeredInstead(null, 15_000uL))
        assertNull(offeredInstead(20_000uL, null))
        assertNull(offeredInstead(20_000uL, 20_000uL))
        assertNull(offeredInstead(20_000uL, 0uL))
    }
}
