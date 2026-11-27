package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Balance
import org.licash.core.Contract
import org.licash.core.ContractQuote
import org.licash.core.ContractState
import org.licash.core.DepositCoin
import org.licash.core.Hub
import org.licash.core.OpeningStep
import org.licash.core.Rate
import org.licash.wallet.Ui

class SetupTest {
    private fun hub() = Hub(
        url = "https://hub.example", feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false,
        mailbox = false,
        lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        contracts = null,
    )

    private fun contract(createdAt: Long, state: ContractState) = Contract(
        id = "c$createdAt", hub = "https://hub.example", state = state, mock = false, cap = 131_071uL, price = 1_000uL,
        funded = 0uL, fundedReceived = false, paidFrom = 50_000uL, protectsUntil = 2_000u, closesAt = 2_100u,
        funding = null, createdAt = createdAt, covers = 0uL, step = null, transfer = null,
    )

    private val offer = ContractQuote(
        hub = "https://hub.example", price = 23_000uL, cap = 131_071uL, blocks = 1_000u, protectsFor = 820u, mock = false,
        coin = 50_000uL, download = 100_100_000uL, range = null, afterAssert = 180u,
        coins = listOf(DepositCoin("aa:0", 50_000uL)), suggestedCap = 131_071uL, suggestedBlocks = 26_280u, dust = 330uL,
        denominations = emptyList(), fundedNotes = 0u,
    )

    private val none = Ui(wallet = true)
    private val fresh = none.copy(hubs = listOf(hub()))
    private val arrived = fresh.copy(balance = Balance(0uL, 0uL, 50_000uL, 0uL, 0uL, 0uL, 0uL))

    private fun page(ui: Ui, backup: Boolean = false, another: Boolean = false, choosing: Boolean = false) =
        setupPage(ui, backup, another, choosing)

    @Test
    fun a_wallet_is_backed_up_then_given_a_hub_then_funded() {
        // Made here: its backup first, before anything is in it; put off or done, a hub.
        assertEquals(SetupPage.BACKUP, page(none, backup = true))
        assertEquals(SetupPage.HUB, page(none))
        // A hub is what the rest needs: no page of them before one.
        assertEquals(SetupPage.HUB, page(none, choosing = true))
        // With one, the funding: its backup is Home's to suggest from then on.
        assertEquals(SetupPage.FUND, page(fresh))
        assertEquals(SetupPage.FUND, page(fresh, backup = true))
        assertEquals(SetupPage.FUND, page(arrived))
    }

    @Test
    fun the_vault_is_a_page_only_once_asked_for_with_one_offered() {
        val offered = arrived.copy(offer = offer)
        // Nothing opens unasked.
        assertEquals(SetupPage.FUND, page(offered))
        assertEquals(SetupPage.VAULT, page(offered, choosing = true))
        // None offered, or its bitcoin not in a block yet: the funding.
        assertEquals(SetupPage.FUND, page(arrived, choosing = true))
        assertEquals(SetupPage.FUND, page(fresh.copy(offer = offer), choosing = true))
        // Accepted, it is being opened: back to its steps.
        assertEquals(SetupPage.FUND, page(offered.copy(opening = "https://hub.example", offer = null), choosing = true))
    }

    @Test
    fun another_hub_is_a_page_back_goes_from_and_ready_is_said_over_all() {
        assertEquals(SetupPage.HUB, page(arrived, another = true))
        val ready = fresh.copy(guideSince = 200L, contracts = listOf(contract(300L, ContractState.Protecting)))
        assertEquals(SetupPage.READY, page(ready))
        assertEquals(SetupPage.READY, page(ready, another = true, choosing = true))
    }

    @Test
    fun setting_up_shows_until_left_and_always_with_no_hub() {
        assertTrue(settingUp(fresh, left = false))
        assertFalse(settingUp(fresh, left = true))
        // Nothing works without a hub: Home has nothing to show.
        assertTrue(settingUp(none, left = true))
        // A wallet in use, never guided: Home, as before.
        val held = fresh.copy(balance = Balance(10_000uL, 0uL, 0uL, 0uL, 0uL, 0uL, 0uL))
        assertFalse(settingUp(held, left = false))
        // Guided since it was made, and in use since: the app starts at its Home, which leads back.
        assertTrue(startsAtHome(held.copy(guideSince = 200L)))
        assertFalse(settingUp(held.copy(guideSince = 200L), left = startsAtHome(held)))
        // With nothing yet, or no hub: at what it lacks.
        assertFalse(startsAtHome(fresh))
        assertFalse(startsAtHome(none))
        assertFalse(startsAtHome(Ui()))
    }

    @Test
    fun leaving_ends_the_guide_only_of_a_wallet_in_use() {
        val held = fresh.copy(balance = Balance(10_000uL, 0uL, 0uL, 0uL, 0uL, 0uL, 0uL), guideSince = 200L)
        // A new wallet is guided unasked: left for now, Home leading back.
        for (at in FundingStage.entries) {
            assertFalse("$at", leavingEnds(fresh, at, hide = true))
        }
        assertEquals("Not now", leaveWords(FundingStage.WAITING, hides = false))
        // In use and guided, since it was made or because it asked: going back keeps the guide, Home leading back.
        assertFalse(leavingEnds(held, FundingStage.WAITING, hide = false))
        // Guided only since sent here, by a Send with nothing to send: going back with nothing sent undoes it.
        assertTrue(leavingEnds(held, FundingStage.WAITING, hide = false, passing = true))
        // Something sent: only if asked to, so going back keeps its steps.
        assertFalse(leavingEnds(held, FundingStage.SEEN, hide = false, passing = true))
        assertFalse(leavingEnds(held, FundingStage.SEEN, hide = false))
        assertFalse(leavingEnds(held, FundingStage.IN_BLOCK, hide = false))
        assertTrue(leavingEnds(held, FundingStage.IN_BLOCK, hide = true))
        assertEquals("Hide guide", leaveWords(FundingStage.IN_BLOCK, hides = true))
        // Its vault being opened: never, it is said ready once it protects.
        assertFalse(leavingEnds(held, FundingStage.OPENING, hide = true))
        assertEquals("Go to my wallet", leaveWords(FundingStage.OPENING, hides = false))
    }

    @Test
    fun the_backup_says_what_the_words_do_not_bring_back() {
        assertTrue(BACKUP_WORDS.contains("bitcoin you hold on Bitcoin"))
        assertTrue(BACKUP_AUTO.contains("the words alone do not bring it back"))
        assertTrue(BACKUP_AUTO.contains("encrypted with your words"))
        assertTrue(BACKUP_AUTO.contains("sync"))
        assertEquals("Restoring needs both: the backup, and the words to open it.", BACKUP_BOTH)
    }

    @Test
    fun the_vault_is_said_ready_with_what_it_protects() {
        assertEquals(
            "Your tokens at hub.example are protected up to 131,071 sat. Pay and receive in a tap.",
            readySays(131_071uL, "hub.example"),
        )
        assertEquals("Protected. Pay and receive in a tap.", readySays(null, null))
        assertEquals("Asking the hub", openingSays(null))
        assertEquals(setup(OpeningStep.Signing).second, openingSays(OpeningStep.Signing))
        assertEquals("One block is enough.", ONE_BLOCK)
    }
}
