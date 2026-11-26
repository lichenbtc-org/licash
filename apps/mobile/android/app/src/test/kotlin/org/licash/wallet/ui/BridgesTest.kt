package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.licash.core.Bridge
import org.licash.core.BridgeApp
import org.licash.core.BudgetPeriod
import org.licash.core.ImportedNotes
import org.licash.core.TopUpRules

class BridgesTest {
    private fun bridge(name: String?) =
        Bridge("https://bridge.example.org:8443", name, "https://hub.example", false, null, null, true, null, 0L)

    private fun app(pay: Boolean, receive: Boolean, budget: ULong? = null, period: BudgetPeriod? = null, revoked: Boolean = false) =
        BridgeApp("ab", "Zapper", pay, receive, null, budget, period, 20uL, null, revoked, 0L)

    @Test
    fun a_bridge_is_named_as_it_says_else_by_its_host() {
        assertEquals("Mine", bridgeName(bridge("Mine")))
        assertEquals("bridge.example.org:8443", bridgeName(bridge(null)))
        assertEquals("bridge.example.org:8443", bridgeName(bridge("  ")))
    }

    @Test
    fun rules_are_taken_only_when_they_top_up_to_more_than_they_start_below() {
        assertEquals(TopUpRules(1_000uL, 5_000uL, 10_000uL, null), rulesOf("1,000", " 5000", "10000", ""))
        assertEquals(TopUpRules(0uL, 5uL, 5uL, 2uL), rulesOf("0", "5", "5", "2"))
        assertNull(rulesOf("6000", "5000", "10000", ""))
        assertNull(rulesOf("0", "0", "10000", ""))
        assertNull(rulesOf("1", "5", "0", ""))
        assertNull(rulesOf("1", "5", "5", "x"))
        assertNull(rulesOf("", "5", "5", ""))
    }

    @Test
    fun rules_and_apps_are_said_in_words() {
        assertEquals("Topped up by hand", rulesWords(null))
        assertEquals(
            "Below 1,000 sat, up to 5,000 sat, 10,000 sat a day at most",
            rulesWords(TopUpRules(1_000uL, 5_000uL, 10_000uL, null)),
        )
        assertEquals("Pays and is paid", appWords(app(pay = true, receive = true)))
        assertEquals("Is paid", appWords(app(pay = false, receive = true)))
        assertEquals("Pays, 20 sat of 100 sat a week", appWords(app(true, false, 100uL, BudgetPeriod.WEEKLY)))
        assertEquals("Pays, 20 sat of 100 sat", appWords(app(true, false, 100uL, BudgetPeriod.NEVER)))
        assertEquals("Revoked", appWords(app(true, true, revoked = true)))
    }

    @Test
    fun an_import_says_what_it_added_and_left_out() {
        assertEquals("3 notes worth 100 sat imported", importedWords(ImportedNotes("ab", 3u, 100uL, 0u, 0u)))
        assertEquals(
            "0 notes worth 0 sat imported, 3 imported before, 1 of a hub you don't use left out",
            importedWords(ImportedNotes("ab", 0u, 0uL, 3u, 1u)),
        )
        assertEquals(
            "2 notes worth 50 sat imported, and 1 stuck payments worth 30 sat, claimable once expired",
            importedWords(ImportedNotes("ab", 2u, 50uL, 0u, 0u, 1u, 30uL)),
        )
    }

    @Test
    fun a_typed_amount_is_whole_sat_or_none() {
        assertEquals(1_500uL, satOf(" 1,500 "))
        assertNull(satOf(""))
        assertNull(satOf("-3"))
        assertNull(satOf("1.5"))
    }

    @Test
    fun a_lightning_address_is_a_way_only_once_named() {
        assertEquals(false, Way.ADDRESS in ways(lightning = true, silent = true, donations = true))
        assertEquals(Way.ADDRESS, ways(lightning = false, silent = false, address = true).last())
    }
}
