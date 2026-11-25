package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CheerTest {
    @Test
    fun a_cheer_draws_its_ring_then_its_check_and_ends_whole() {
        assertEquals(Cheered(0f, 0f, 0f), cheered(0f))
        // Ends with ring and check whole, its sparks gone.
        assertEquals(Cheered(1f, 1f, 1f), cheered(1f))
        // The ring leads the check, which starts over its end.
        val mid = cheered(0.45f)
        assertTrue(mid.ring > mid.check && mid.check > 0f)
        assertEquals(0f, mid.sparks)
        // Never drawn backwards, nor beyond whole.
        var last = cheered(0f)
        for (i in 1..100) {
            val now = cheered(i / 100f)
            assertTrue("$i", now.ring >= last.ring && now.check >= last.check && now.sparks >= last.sparks)
            assertTrue("$i", now.ring <= 1f && now.check <= 1f && now.sparks <= 1f)
            last = now
        }
        assertEquals(cheered(1f), cheered(2f))
        assertTrue(CHEER_MS < 1_000)
    }
}
