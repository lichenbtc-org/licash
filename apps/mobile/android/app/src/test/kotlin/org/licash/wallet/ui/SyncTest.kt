package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.Hub
import org.licash.core.Rate
import org.licash.core.Scan
import org.licash.core.TorStatus
import org.licash.wallet.ChainStatus
import org.licash.wallet.Ui
import org.licash.wallet.behind

class SyncTest {
    private fun hub() = Hub(
        url = "https://hub.example", feeBase = 0uL, feePpm = 0uL, feeOutputMsat = 0uL, deposits = null, silent = false,
        mailbox = false,
        lockFee = Rate(0uL, 0uL), refundFee = Rate(0uL, 0uL), depositFee = null,
        contracts = null,
    )

    private fun scan(from: UInt, next: UInt, height: UInt, tweaks: Boolean = true) =
        Scan(from = from, next = next, height = height, tweaks = tweaks, found = 0u, foundValue = 0uL)

    private val caughtUp = ChainStatus(height = 900, peers = 2, synced = true, headers = 900, peerHeight = 900)

    @Test
    fun a_fraction_only_on_a_known_way() {
        assertEquals(0.5f, fraction(0, 50, 100)!!, 0.0001f)
        assertEquals(0.25f, fraction(100, 125, 200)!!, 0.0001f)
        assertNull(fraction(0, 10, 0))
        assertNull(fraction(0, 150, 100))
        assertNull(fraction(100, 50, 200))
    }

    @Test
    fun a_new_wallet_waits_for_each_step_before_it() {
        val ui = Ui(chain = ChainStatus(peers = 1, headers = 400, peerHeight = 800), hubs = listOf(hub()))
        val stages = stages(ui)
        assertEquals(listOf("Bitcoin nodes", "Block headers", "Block filters", "Your payments"), stages.map { it.name })
        assertEquals(
            listOf(Progress.DONE, Progress.DOING, Progress.WAITING, Progress.WAITING),
            stages.map { it.state },
        )
        assertEquals("Block 400 of 800 (50%)", stages[1].detail)
        assertEquals(0.5f, stages[1].fraction!!, 0.0001f)
        // Waiting: no fraction shown, nor where it would be.
        assertNull(stages[2].fraction)
        assertEquals(listOf("Waiting", "Waiting"), stages.drop(2).map { it.detail })
        assertTrue(catchingUp(ui))
    }

    @Test
    fun settings_says_the_pinned_headers_download_and_set_up_not_connecting() {
        assertEquals("Downloading", status(Ui(chain = ChainStatus(importing = 42)), developer = false).first)
        assertEquals("Setting up", status(Ui(chain = ChainStatus(importing = 100)), developer = false).first)
        assertEquals("Connecting", status(Ui(chain = ChainStatus()), developer = false).first)
    }

    @Test
    fun the_pinned_headers_download_before_any_node_is_looked_for() {
        val ui = Ui(chain = ChainStatus(importing = 42), hubs = listOf(hub()))
        val stages = stages(ui)
        assertEquals(
            listOf("Block headers download", "Bitcoin nodes", "Block headers", "Block filters", "Your payments"),
            stages.map { it.name },
        )
        assertEquals(Progress.DOING, stages[0].state)
        assertEquals("Downloading (42%)", stages[0].detail)
        assertEquals(0.42f, stages[0].fraction!!, 0.0001f)
        assertTrue(stages.drop(1).all { it.state == Progress.WAITING })
        assertTrue(catchingUp(ui))
    }

    @Test
    fun downloaded_the_pinned_headers_are_prepared_for_a_time_untold() {
        val stage = stages(Ui(chain = ChainStatus(importing = 100), hubs = listOf(hub()))).first()
        assertEquals(PREPARING, stage.detail)
        // Downloaded: no longer named a download.
        assertEquals(HEADERS_SETUP, stage.name)
        assertEquals(PREPARING, said(stage, developer = false))
        assertNull(stage.fraction)
        assertTrue(stage.timed)
        assertFalse(stages(Ui(chain = ChainStatus(importing = 99))).first().timed)
    }

    @Test
    fun checked_the_pinned_headers_are_stored_as_far_as_told() {
        val stage = stages(Ui(chain = ChainStatus(importing = 100, storing = 35), hubs = listOf(hub()))).first()
        assertEquals("Storing (35%)", stage.detail)
        assertEquals(0.35f, stage.fraction!!, 0.0001f)
        assertTrue(stage.timed)
        assertEquals("Storing block headers (35%)", said(stage, developer = false))
        // Not told yet: still checked, for a time untold.
        assertEquals(PREPARING, stages(Ui(chain = ChainStatus(importing = 100, storing = -1))).first().detail)
    }

    @Test
    fun only_a_new_wallets_first_catching_up_is_shown_on_home() {
        val behind = Ui(chain = ChainStatus(peers = 1, headers = 400, peerHeight = 800), hubs = listOf(hub()))
        assertTrue(firstCatchingUp(behind))
        // Caught up once: the connections dot tells of it from then on.
        assertFalse(firstCatchingUp(behind.copy(caughtUp = true)))
        assertFalse(firstCatchingUp(Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(800u, 901u, 900u))))
    }

    @Test
    fun the_connections_say_how_long_they_took_to_answer() {
        assertEquals("85 ms", latency(85))
        assertEquals("1,240 ms", latency(1_240))
        val ui = Ui(
            chain = caughtUp.copy(pingMs = 120),
            hubs = listOf(hub().copy(mailbox = true)),
            scan = scan(800u, 901u, 900u),
            hubsReached = mapOf("https://hub.example" to true),
            hubsMs = mapOf("https://hub.example" to 640L),
            relaysReached = true,
            relaysMs = 900L,
        )
        assertEquals(listOf(120L, 640L, 900L), links(ui).map { it.ms })
        // None for a hub not answering, nor for Bitcoin with no node.
        val down = ui.copy(hubsReached = mapOf("https://hub.example" to false), chain = caughtUp.copy(pingMs = 120, peers = 0))
        assertEquals(listOf(null, null), links(down).take(2).map { it.ms })
    }

    @Test
    fun the_step_under_way_is_said_plainly_and_in_full_in_advanced_mode() {
        val ui = Ui(chain = ChainStatus(peers = 1, headers = 400, peerHeight = 800), hubs = listOf(hub()))
        val step = stages(ui)[1]
        assertEquals("Catching up with Bitcoin (50%)", said(step, developer = false))
        assertEquals("Block headers: Block 400 of 800 (50%)", said(step, developer = true))
        val importing = stages(Ui(chain = ChainStatus(importing = 42))).first()
        assertEquals("Downloading block headers (42%)", said(importing, developer = false))
        val nodes = stages(Ui(chain = ChainStatus())).first()
        assertEquals("Looking for Bitcoin nodes", said(nodes, developer = false))
        val hub = stages(Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(800u, 896u, 895u))).last()
        assertEquals("Checking the newest block", said(hub, developer = false))
    }

    @Test
    fun the_connections_are_tor_if_on_then_bitcoin() {
        // Tor and Bitcoin alone: the hubs and relays are said after them.
        fun chain(ui: Ui) = links(ui).filter { it.name == TOR || it.name == BITCOIN }
        val hubs = listOf(hub())
        val done = scan(800u, 901u, 900u)
        assertEquals(listOf(Link("Bitcoin", Reach.UP, "Up to date")), chain(Ui(chain = caughtUp, hubs = hubs, scan = done)))
        assertEquals(
            Link("Bitcoin", Reach.UP, "Up to date, block 900, 2 nodes"),
            chain(Ui(chain = caughtUp, hubs = hubs, scan = done, developer = true)).single(),
        )
        // No hub yet: payments are not looked for, and Bitcoin is not behind.
        assertEquals(Reach.UP, chain(Ui(chain = caughtUp)).single().reach)
        assertEquals(Link("Bitcoin", Reach.GOING, "Looking for Bitcoin nodes"), chain(Ui(hubs = hubs)).single())

        val ready = TorStatus(percent = 100u.toUByte(), ready = true, summary = "done", blocked = null)
        val stuck = TorStatus(percent = 10u.toUByte(), ready = false, summary = "connecting", blocked = "clock skew")
        val starting = TorStatus(percent = 30u.toUByte(), ready = false, summary = "connecting", blocked = null)
        val tor = Ui(tor = true, chain = caughtUp, hubs = hubs, scan = done)
        assertEquals(listOf(Reach.UP, Reach.UP), chain(tor.copy(torStatus = ready)).map { it.reach })
        assertEquals(Link("Tor", Reach.DOWN, "Stuck: clock skew"), chain(tor.copy(torStatus = stuck)).first())
        assertEquals(Link("Tor", Reach.GOING, "Connecting (30%)"), chain(tor.copy(torStatus = starting)).first())
        assertEquals("Waiting for Tor", chain(tor.copy(torStatus = starting)).last().detail)
        assertEquals(Reach.DOWN, chain(tor.copy(torStatus = stuck)).maxOf { it.reach })
    }

    @Test
    fun each_hub_and_the_mailbox_relays_say_whether_they_answered_when_last_asked() {
        val ui = Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(800u, 901u, 900u))
        fun hubLink(reached: Map<String, Boolean>) = links(ui.copy(hubsReached = reached)).last()
        assertEquals(Reach.GOING, hubLink(emptyMap()).reach)
        assertEquals(Reach.UP, hubLink(mapOf("https://hub.example" to true)).reach)
        val down = hubLink(mapOf("https://hub.example" to false))
        assertEquals(Reach.DOWN, down.reach)
        assertEquals("hub.example", down.name)
        // No mailbox: no relays looked in, none said.
        assertTrue(links(ui).none { it.name == RELAYS })
        val mail = ui.copy(hubs = listOf(hub().copy(mailbox = true)), hubsReached = mapOf("https://hub.example" to true))
        assertEquals(Reach.GOING, links(mail).last().reach)
        assertEquals(Link(RELAYS, Reach.UP, "Reached"), links(mail.copy(relaysReached = true)).last())
        // Full of mail, junk perhaps: a payment may be hidden there.
        val full = links(mail.copy(relaysReached = true, relaysFull = true)).last()
        assertEquals(Reach.DOWN, full.reach)
        assertTrue(full.detail, full.detail.contains("may hide a payment"))
        assertEquals(Reach.DOWN, links(mail.copy(relaysReached = false)).maxOf { it.reach })
    }

    @Test
    fun turning_tor_off_is_offered_once_it_keeps_the_app_from_bitcoin() {
        val ready = TorStatus(percent = 100u.toUByte(), ready = true, summary = "done", blocked = null)
        val stuck = TorStatus(percent = 10u.toUByte(), ready = false, summary = "connecting", blocked = "clock skew")
        val tor = Ui(tor = true, torStatus = ready, chain = caughtUp)
        assertFalse(torInTheWay(tor))
        assertFalse(offerTorOff(tor, null))
        // Connected to Tor, but no Bitcoin node through it: after a while.
        val noNodes = tor.copy(chain = ChainStatus())
        assertTrue(torInTheWay(noNodes))
        assertFalse(offerTorOff(noNodes, TOR_PATIENCE_MS - 1))
        assertTrue(offerTorOff(noNodes, TOR_PATIENCE_MS))
        // Stuck by its own word: at once.
        assertTrue(offerTorOff(tor.copy(torStatus = stuck), null))
        // Off, nothing to offer.
        assertFalse(offerTorOff(noNodes.copy(tor = false), TOR_PATIENCE_MS))
        // Importing the pinned headers, no node asked yet: Tor not in the way.
        for (importing in listOf(0, 42, 100)) {
            val importingNoNodes = noNodes.copy(chain = ChainStatus(importing = importing))
            assertFalse(torInTheWay(importingNoNodes))
            assertFalse(offerTorOff(importingNoNodes, TOR_PATIENCE_MS))
            // Unless Tor itself is not connected.
            assertTrue(torInTheWay(importingNoNodes.copy(torStatus = stuck.copy(blocked = null))))
        }
        // Said as it is: Tor connected, no node through it; or Tor not getting through.
        assertTrue(torOffMeans(noNodes).startsWith("No Bitcoin node answers through Tor."))
        assertTrue(torOffMeans(tor.copy(torStatus = stuck)).startsWith("Tor is not getting through."))
    }

    @Test
    fun no_peer_height_no_fraction() {
        val ui = Ui(chain = ChainStatus(peers = 1, headers = 400), hubs = listOf(hub()))
        val headers = stages(ui)[1]
        assertEquals("Block 400", headers.detail)
        assertNull(headers.fraction)
    }

    @Test
    fun tor_comes_first_over_tor_and_says_why_it_is_stuck() {
        val blocked = TorStatus(percent = 10u.toUByte(), ready = false, summary = "connecting", blocked = "clock skew")
        val ui = Ui(tor = true, torStatus = blocked, chain = caughtUp, hubs = listOf(hub()))
        val tor = stages(ui).first()
        assertEquals("Tor", tor.name)
        assertEquals(Progress.DOING, tor.state)
        assertEquals("Stuck: clock skew", tor.detail)
        assertEquals(0.1f, tor.fraction!!, 0.0001f)
        assertTrue(stages(ui).drop(1).all { it.state == Progress.WAITING })
        assertEquals("Starting", stages(ui.copy(torStatus = null)).first().detail)
    }

    @Test
    fun payments_are_looked_for_from_the_birthday() {
        val ui = Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(from = 800u, next = 850u, height = 900u))
        val payments = stages(ui).last()
        assertEquals(Progress.DOING, payments.state)
        assertEquals("Block 850 of 900, 51 to go (49%)", payments.detail)
        assertEquals(50f / 101f, payments.fraction!!, 0.0001f)
    }

    @Test
    fun caught_up_is_up_to_date_and_says_when_without_tweaks() {
        val ui = Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(from = 800u, next = 901u, height = 900u))
        assertEquals("Up to date", stages(ui).last().detail)
        assertFalse(catchingUp(ui))
        val fallback = ui.copy(scan = scan(from = 800u, next = 901u, height = 900u, tweaks = false))
        assertEquals("Up to date, fallback addresses only", stages(fallback).last().detail)
    }

    @Test
    fun a_hub_behind_the_light_client_is_waited_for() {
        val ui = Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(from = 800u, next = 896u, height = 895u))
        val payments = stages(ui).last()
        assertEquals(Progress.DOING, payments.state)
        assertEquals("Checked to block 895, checking block 896", payments.detail)
    }

    @Test
    fun caught_up_once_bitcoin_stays_up_while_keeping_up_with_new_blocks() {
        // A block come since the last look: looked in next round.
        val ui = Ui(chain = caughtUp, hubs = listOf(hub()), scan = scan(from = 800u, next = 900u, height = 899u))
        assertEquals(Progress.DOING, stages(ui).last().state)
        assertEquals("Checked to block 899, checking block 900", stages(ui).last().detail)
        assertEquals("Checking the newest block", said(stages(ui).last(), developer = false))
        assertTrue(bitcoinBehind(ui))
        fun bitcoin(ui: Ui, stale: Boolean) = links(ui, stale).first { it.name == BITCOIN }
        // Before the wallet first caught up: said at once.
        assertEquals(Reach.GOING, bitcoin(ui, stale = false).reach)
        // Since: up, as usual, until behind STALE_MS.
        val since = ui.copy(caughtUp = true)
        assertEquals(Link(BITCOIN, Reach.UP, "Up to date"), bitcoin(since, stale = false))
        assertEquals(Reach.GOING, bitcoin(since, stale = true).reach)
        // No node: the same, up for a while, then said.
        val noNodes = since.copy(chain = caughtUp.copy(peers = 0))
        assertEquals(Reach.UP, bitcoin(noNodes, stale = false).reach)
        assertEquals(Link(BITCOIN, Reach.GOING, "Looking for Bitcoin nodes"), bitcoin(noNodes, stale = true))
        // Up to date: not behind.
        assertFalse(bitcoinBehind(ui.copy(scan = scan(from = 800u, next = 901u, height = 900u))))
    }

    @Test
    fun without_a_hub_payments_wait_for_one() {
        assertEquals("Choose a hub first", stages(Ui(chain = caughtUp)).last().detail)
    }

    @Test
    fun behind_until_the_chain_and_the_payments_are_caught_up() {
        val hubs = listOf(hub())
        assertTrue(behind(Ui(chain = ChainStatus(importing = 0), hubs = hubs)))
        assertTrue(behind(Ui(chain = caughtUp.copy(synced = false), hubs = hubs)))
        assertTrue(behind(Ui(chain = caughtUp, hubs = hubs)))
        assertTrue(behind(Ui(chain = caughtUp, hubs = hubs, scan = scan(100u, 500u, 900u))))
        assertFalse(behind(Ui(chain = caughtUp, hubs = hubs, scan = scan(100u, 901u, 900u))))
        // Waiting for her to choose a hub is not catching up.
        assertFalse(behind(Ui(chain = caughtUp)))
        assertTrue(behind(Ui(chain = ChainStatus())))
    }
}
