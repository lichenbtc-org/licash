package org.licash.wallet.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.licash.core.LnurlPay

class SendTest {
    @Test
    fun a_payment_on_bitcoin_arrives_a_block_after_those_awaited() {
        assertEquals("about 10 min", arrives(0u))
        assertEquals("about 20 min", arrives(1u))
        assertEquals("about 70 min", arrives(6u))
    }

    @Test
    fun a_code_is_shown_short_whatever_its_scheme_case_or_amount() {
        val body = "tlicash1qqqqsqpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsabcdefgh"
        val short = "tlicash1qq…abcdefgh"
        assertEquals(short, shortCode("licash:$body"))
        assertEquals(short, shortCode(" licash:$body?amount=5000 "))
        assertEquals(short, shortCode("LICASH:${body.uppercase()}"))
        assertEquals(short, shortCode(body))
    }

    @Test
    fun the_same_blocks_take_a_twentieth_of_the_time_on_mutinynet() {
        assertEquals("about 1 min", arrives(0u, 30u))
        assertEquals("about 1 min", arrives(1u, 30u))
        assertEquals("about 4 min", arrives(6u, 30u))
    }

    @Test
    fun a_lightning_address_takes_what_its_service_says() {
        val pay = LnurlPay(
            payee = "alice@pay.example", min = 10uL, max = 1_000_000uL, description = null,
            callback = "https://pay.example/cb", metadata = "[]",
        )
        assertEquals("From 10 sat to 1,000,000 sat", takesWords(pay))
        assertTrue(takes(pay, 10))
        assertTrue(takes(pay, 1_000_000))
        assertFalse(takes(pay, 9))
        assertFalse(takes(pay, 1_000_001))
        assertFalse(takes(pay, 0))
        assertFalse(takes(pay, null))
    }
}
