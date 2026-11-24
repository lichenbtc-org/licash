package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Network
import org.licash.wallet.Ui

class OnboardingTest {
    @Test
    fun the_networks_show_once_asked_for_and_never_hide_one_chosen() {
        assertFalse(networksShown(asked = false, Ui()))
        assertTrue(networksShown(asked = true, Ui()))
        // A test network chosen stays in sight, so it is never made unseen.
        assertTrue(networksShown(asked = false, Ui(network = Network.MUTINYNET)))
        assertTrue(networksShown(asked = false, Ui(developer = true)))
    }

    @Test
    fun a_wallet_that_cannot_be_opened_says_why_and_how_to_start_over() {
        val said = unopenedWords("A wallet of an earlier version, left as it is.")
        assertTrue(said.startsWith("A wallet of an earlier version, left as it is. To start over"))
        assertTrue(said.contains("clear this app's storage"))
        assertTrue(said.contains("lost"))
    }

    @Test
    fun networks_are_named_as_proper_nouns() {
        assertEquals(listOf("Bitcoin", "Signet", "Mutinynet", "Regtest"), Network.entries.map(::named))
    }

    @Test
    fun no_hub_found_for_a_first_one_says_where_to_get_one_on_any_network() {
        assertEquals(NONE_AVAILABLE, noneFound(none = true))
        // A wallet with a hub already: only "None found".
        assertNull(noneFound(none = false))
        // Nothing says a network has no hubs: that is for discovery to find.
        assertFalse(NONE_AVAILABLE.contains("test network"))
    }

    @Test
    fun a_hub_is_recommended_on_mutinynet_only() {
        assertEquals(listOf("https://hub.licash-mutinynet.sgn.space"), recommendedHubs(Network.MUTINYNET).map { it.url })
        for (network in listOf(Network.BITCOIN, Network.SIGNET, Network.REGTEST)) {
            assertTrue(recommendedHubs(network).isEmpty())
        }
    }
}
