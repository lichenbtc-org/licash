package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TourTest {
    @Test
    fun the_tour_tells_the_vault_in_five_pages() {
        assertEquals(5, SLIDES.size)
        assertEquals("Bitcoin is gold in a vault", SLIDES.first().title)
        // Its last page says where the protection ends.
        assertTrue(SLIDES.last().line.contains("trust the hub"))
    }

    @Test
    fun the_tour_has_no_figures_dates_or_jargon() {
        for (slide in SLIDES) {
            val said = "${slide.title} ${slide.line}"
            // No claimed ratio of claims to gold, no amounts, no expiry.
            assertFalse(said, said.any(Char::isDigit))
            for (word in listOf("note", "contract", "expir", "block", "sat", "Lightning", "—", "--")) {
                assertFalse("$word in $said", said.contains(word, ignoreCase = true))
            }
        }
    }
}
