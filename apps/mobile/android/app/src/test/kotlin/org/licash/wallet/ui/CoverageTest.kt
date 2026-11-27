package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Contract
import org.licash.core.ContractRange
import org.licash.core.ContractState
import org.licash.core.ContractTerms
import org.licash.core.Holding
import org.licash.core.Hub
import org.licash.core.Notes
import org.licash.core.Rate

class CoverageTest {
    private val one = "https://one.example"
    private val two = "https://two.example"

    private fun contract(hub: String, cap: ULong, covers: ULong, state: ContractState = ContractState.Protecting) =
        Contract(
            id = "c$cap", hub = hub, state = state, mock = false, cap = cap, price = 1_000uL, funded = 0uL, fundedReceived = false, paidFrom = 50_000uL,
            protectsUntil = 2_000u, closesAt = 2_100u, funding = null, createdAt = 0L, covers = covers, step = null,
            transfer = null,
        )

    private fun hub(terms: ContractTerms?) = Hub(
        url = one, feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false, mailbox = false,
        lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        contracts = terms,
    )

    @Test
    fun a_hub_counts_only_its_own_contracts_protecting_and_its_own_notes() {
        val contracts = listOf(
            contract("$one/", 4_096uL, 3_000uL),
            contract(one, 8_192uL, 0uL, ContractState.Confirming),
            contract(two, 4_096uL, 4_096uL),
        )
        val notes = listOf(Notes(one, 1_024uL, 2uL), Notes(one, 512uL, 3uL), Notes(two, 64uL, 9uL))
        val cover = hubCover(one, Holding(one, 4_000uL, 1_000uL), contracts, notes)
        assertEquals(HubCover(held = 5_000uL, covered = 3_000uL, caps = 4_096uL, notes = 5uL), cover)
        assertEquals(2_000uL, cover.missing)
        assertEquals(1_096uL, cover.room)
        assertEquals("3,000 of 5,000 sat protected, 2,000 sat not", cover.says)
        assertEquals("5 notes", cover.noteWords)
    }

    @Test
    fun it_says_what_is_missing_or_the_room_left() {
        assertNull(HubCover(0uL, 0uL, 0uL, 0uL).says)
        assertEquals("Not protected", HubCover(900uL, 0uL, 0uL, 2uL).says)
        assertEquals("900 sat not protected", HubCover(900uL, 0uL, 4_096uL, 2uL).says)
        assertEquals("All protected, room for 3,196 sat more", HubCover(900uL, 900uL, 4_096uL, 2uL).says)
        assertEquals("All protected, no room for more", HubCover(4_096uL, 4_096uL, 4_096uL, 2uL).says)
        assertEquals("1 note", HubCover(900uL, 0uL, 0uL, 1uL).noteWords)
        // Never more covered than held, whatever the contracts report.
        assertEquals(100uL, hubCover(one, Holding(one, 100uL, 0uL), listOf(contract(one, 4_096uL, 500uL)), emptyList()).covered)
    }

    @Test
    fun protecting_is_suggested_from_the_smallest_contract_until_dismissed() {
        val fixed = hub(ContractTerms(4_096uL, 23_000uL, 1_005u, false, null))
        val ranged = hub(ContractTerms(4_096uL, 23_000uL, 1_005u, false, ContractRange(10_000uL, 1_000_000uL, 432u, 52_560u, 2u, 20_000uL, 1_000uL, 5_000u, 0u, 52_560u)))
        val cover = { missing: ULong -> HubCover(missing + 1_000uL, 1_000uL, 4_096uL, 3uL) }
        assertEquals(4_096uL, smallestContract(fixed))
        assertEquals(10_000uL, smallestContract(ranged))
        assertNull(smallestContract(hub(null)))
        assertFalse(suggestProtecting(cover(4_095uL), fixed, null))
        assertTrue(suggestProtecting(cover(4_096uL), fixed, null))
        assertFalse(suggestProtecting(cover(9_999uL), ranged, null))
        assertTrue(suggestProtecting(cover(10_000uL), ranged, null))
        // No contracts there: nothing to suggest.
        assertFalse(suggestProtecting(cover(1_000_000uL), hub(null), null))
        // Dismissed at 5,000: not again until more is not protected.
        assertFalse(suggestProtecting(cover(5_000uL), fixed, 5_000uL))
        assertFalse(suggestProtecting(cover(4_500uL), fixed, 5_000uL))
        assertTrue(suggestProtecting(cover(5_001uL), fixed, 5_000uL))
    }

    @Test
    fun a_contract_opening_adds_its_cover_and_her_part() {
        // Nothing held: her part joins, all of it covered, the rest room.
        val none = HubCover(0uL, 0uL, 0uL, 0uL)
        assertEquals(HubCover(2_094_006uL, 2_094_006uL, 4_194_303uL, 0uL), coverAfter(none, 4_194_303uL, 2_094_006uL))
        assertEquals("All protected, room for 2,100,297 sat more", coverAfter(none, 4_194_303uL, 2_094_006uL).says)
        // More held than it covers: the rest still not.
        val held = HubCover(10_000_000uL, 1_000_000uL, 1_048_575uL, 9uL)
        assertEquals(HubCover(10_500_000uL, 3_097_151uL, 3_145_726uL, 9uL), coverAfter(held, 2_097_151uL, 500_000uL))
    }
}
