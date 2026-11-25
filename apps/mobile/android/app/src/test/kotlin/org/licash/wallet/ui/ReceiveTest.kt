package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.DonationAddress
import org.licash.core.Hub
import org.licash.core.LightningTerms
import org.licash.core.Range
import org.licash.core.Rate

class ReceiveTest {
    @Test
    fun the_ways_to_be_paid_are_those_the_hubs_make_possible() {
        assertEquals(listOf(Way.CODE, Way.BITCOIN), ways(lightning = false, silent = false))
        assertEquals(listOf(Way.LIGHTNING, Way.CODE, Way.BITCOIN), ways(lightning = true, silent = false))
        assertEquals(listOf(Way.CODE, Way.BITCOIN, Way.SILENT), ways(lightning = false, silent = true))
        assertEquals(
            listOf("Lightning invoice", "Licash address", "Bitcoin address", "Silent payment address"),
            ways(lightning = true, silent = true).map { it.label },
        )
    }

    @Test
    fun an_amount_is_asked_for_with_an_invoice_any_wallet_pays_where_a_hub_takes_lightning() {
        assertEquals(Way.LIGHTNING, picked(amount = 500, lightning = true))
        // Any amount, or no hub taking Lightning: the wallet's code.
        assertEquals(Way.CODE, picked(amount = null, lightning = true))
        assertEquals(Way.CODE, picked(amount = 500, lightning = false))
    }

    @Test
    fun an_invoice_asks_the_amount_entered_and_says_what_the_wallet_gets() {
        // No fee: nothing to say.
        assertNull(invoiceWords(4_000u, 4_000u, 4_000u))
        // The hub's fee in it.
        assertEquals("You get 3,997 sat, the hub's fee taken", invoiceWords(4_000u, 4_000u, 3_997u))
        // A sat short, where no amount and its fee come to it exactly.
        assertEquals(
            "The payer pays 100,001 sat\nYou get 100,000 sat, the hub's fee taken",
            invoiceWords(100_002u, 100_001u, 100_000u),
        )
        // Made by a provider where no hub takes Lightning.
        assertEquals("You get 495 sat, the provider's fee taken", invoiceWords(500u, 500u, 495u, "the provider"))
    }

    @Test
    fun lightning_waits_on_the_providers_asked_where_no_hub_takes_it() {
        assertEquals(
            listOf(Way.LIGHTNING to "Looking for a provider…"),
            closedWays(
                lightning = false,
                silent = true,
                donations = true,
                lookingForDonations = false,
                lookingForLightning = true,
            ),
        )
        // Found: open, through it.
        assertEquals(emptyList<Pair<Way, String>>(), closedWays(true, true, true, false, lookingForLightning = true))
    }

    @Test
    fun a_memo_is_its_words_one_space_apart_and_none_if_blank() {
        assertNull(memoOf(""))
        assertNull(memoOf("  \n\t "))
        assertEquals("Lunch on Friday", memoOf("  Lunch \n on\tFriday "))
        assertEquals(MAX_MEMO, memoOf("x".repeat(MAX_MEMO + 5))?.length)
    }

    @Test
    fun a_memo_is_offered_only_where_a_hub_says_one_in_its_invoices() {
        val terms = LightningTerms(Rate(0uL, 0uL), Rate(0uL, 0uL), Range(1uL, 1_000uL))
        fun hub(lightning: LightningTerms?) = Hub(
            url = "https://hub.example", feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null,
            silent = false, mailbox = false, lightningPay = null, lockFee = Rate(0uL, 0uL),
            refundFee = Rate(0uL, 0uL), depositFee = null, lightning = lightning, contracts = null,
        )
        assertFalse(memoTaken(emptyList()))
        assertFalse(memoTaken(listOf(hub(null), hub(terms))))
        assertTrue(memoTaken(listOf(hub(terms), hub(terms.copy(memo = true)))))
    }

    @Test
    fun a_way_not_open_says_why() {
        assertEquals(
            listOf(
                Way.LIGHTNING to "None of your hubs takes Lightning",
                Way.SILENT to "Your hubs don't index silent payments",
                Way.DONATIONS to "Looking for a provider…",
            ),
            closedWays(lightning = false, silent = false, donations = false, lookingForDonations = true),
        )
        assertEquals(
            listOf(Way.DONATIONS to "No provider takes donations now"),
            closedWays(lightning = true, silent = true, donations = false, lookingForDonations = false),
        )
        assertEquals(emptyList<Pair<Way, String>>(), closedWays(true, true, donations = true, lookingForDonations = false))
    }

    @Test
    fun a_donation_address_is_another_way_once_a_provider_takes_donations() {
        assertEquals(
            listOf(Way.CODE, Way.BITCOIN, Way.DONATIONS),
            ways(lightning = false, silent = false, donations = true),
        )
        assertEquals(Way.DONATIONS, ways(lightning = true, silent = true, donations = true).last())
        // Never picked for an amount: asked for.
        assertEquals(Way.LIGHTNING, picked(amount = 500, lightning = true))
    }

    @Test
    fun a_donation_address_says_who_pays_it_on_and_for_what() {
        val address = DonationAddress(
            lnurl = "LNURL1DP68GURN8GHJ7",
            provider = "https://swaps.example/",
            name = null,
            feeBase = 2u,
            feePpm = 5_000u,
            min = 100u,
            max = 1_000_000u,
            stocked = true,
            reachable = true,
        )
        assertEquals("Paid to you in notes by swaps.example, less its fee of 2 sat + 0.5%.", donationWords(address))
        assertEquals(
            "Paid to you in notes by Swaps, with no fee. " +
                "It can't take donations right now: payers are refused until it can.",
            donationWords(address.copy(name = "Swaps", feeBase = 0u, feePpm = 0u, stocked = false)),
        )
        // Unheard: shown as kept, the phone perhaps offline.
        assertEquals(
            "Paid to you in notes by swaps.example, less its fee of 2 sat + 0.5%. " +
                "It isn't answering right now: payers may be refused until it does.",
            donationWords(address.copy(stocked = false, reachable = false)),
        )
    }

    @Test
    fun receive_has_a_tab_for_licash_lightning_and_bitcoin_and_the_rest_under_more() {
        assertEquals(listOf("Licash", "Lightning", "Bitcoin"), TABS.map { it.second })
        assertEquals(listOf(Way.CODE, Way.LIGHTNING, Way.BITCOIN), TABS.map { it.first })
    }

    @Test
    fun the_bitcoin_tab_shows_the_bare_address() {
        assertEquals("BITCOIN:BCRT1QABC", bareQr("bcrt1qabc", null))
        assertEquals("BITCOIN:BCRT1QABC?amount=0.00050000", bareQr("bcrt1qabc", 50_000L))
    }

    private fun contract(state: ContractState) = Contract(
        id = "c", hub = "https://hub.example", state = state, mock = false, cap = 131_071uL, price = 1_000uL,
        funded = 0uL, fundedReceived = false, paidFrom = 50_000uL, protectsUntil = 2_000u, closesAt = 2_100u,
        funding = null, createdAt = 1L, covers = 0uL, step = null, transfer = null,
    )

    @Test
    fun what_a_hub_is_paid_with_no_vault_is_said_unprotected_each_time() {
        assertTrue(RECEIVED_UNPROTECTED.contains("not protected"))
        // Paid into a hub: its notes, on its word alone.
        for (way in listOf(Way.CODE, Way.LIGHTNING, Way.DONATIONS)) {
            assertTrue("$way", unprotectedWay(way, emptyList()))
            assertTrue("$way", unprotectedWay(way, listOf(contract(ContractState.Closed))))
            // A vault protecting, or being set up to: not said.
            for (state in listOf(ContractState.Opening, ContractState.Confirming, ContractState.Protecting)) {
                assertFalse("$way $state", unprotectedWay(way, listOf(contract(state))))
            }
        }
        // On Bitcoin it is hers; a bridge account says whose word it is held on.
        for (way in listOf(Way.BITCOIN, Way.SILENT, Way.ADDRESS)) assertFalse("$way", unprotectedWay(way, emptyList()))
    }
}
