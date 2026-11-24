package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TourTest {
    @Test
    fun the_tour_tells_the_vault_in_six_pages() {
        assertEquals(6, SLIDES.size)
        assertEquals("Bitcoin is gold in a vault", SLIDES.first().title)
        // Its last page says what the vault recovers, and that more is credit.
        assertTrue(SLIDES.last().line.contains("up to its balance"))
        assertTrue(SLIDES.last().line.contains("credit"))
        // Tokens, never claims.
        assertTrue(SLIDES.none { "${it.title} ${it.line}".contains("claim", ignoreCase = true) })
    }

    @Test
    fun the_tour_has_no_figures_dates_or_jargon() {
        for (slide in SLIDES) {
            val said = "${slide.title} ${slide.line}"
            // No ratio of tokens to gold, no amounts, no expiry.
            assertFalse(said, said.any(Char::isDigit))
            for (word in listOf("note", "contract", "expir", "block", "sat", "Lightning", "—", "--")) {
                assertFalse("$word in $said", said.contains(word, ignoreCase = true))
            }
        }
    }
}
