package org.licash.wallet.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** A page of the tour: what it says, big, and a line under it. */
internal data class Slide(val title: String, val line: String)

/**
 * How Licash works, told with gold: Bitcoin is gold in a vault; paying
 * with it is slow, costly and public; so people pay with ecash tokens a hub
 * issues, like a vault company, only its promise; Licash's come with the
 * payer's own vault of real bitcoin, redeemed for sure; the hub adds its
 * own to it, room for tokens she is paid; and up to the vault's balance
 * her tokens are recovered, beyond it credit. No figures and no dates: the
 * pictures carry it.
 */
internal val SLIDES = listOf(
    Slide("Bitcoin is gold in a vault", "Real and safe, but heavy to move."),
    Slide("A gold bar for a loaf of bread?", "Paying on Bitcoin is slow, costs a fee, and shows the baker your change."),
    Slide(
        "So people pay with ecash tokens",
        "Instant and private. A hub, like a vault company, issues them. Alone, a token is only its promise.",
    ),
    Slide(
        "Licash tokens come with your own vault",
        "Real bitcoin is locked in it for you, so your tokens can be redeemed for sure, even if the hub disappears.",
    ),
    Slide(
        "Room to be paid",
        "Spend your tokens and your gold goes with them. So the hub adds its own bitcoin: tokens you receive are backed too.",
    ),
    Slide(
        "Your vault is your safety net",
        "With enough tokens, you recover up to its balance. Fewer is fine: you redeem what you hold. More is credit from the hub.",
    ),
)

/**
 * The tour: a page at a time, swiped or with Next, Skip to its last. Its
 * last page ends with `last`, what to do next: make a wallet, or go back.
 */
@Composable
internal fun Tour(modifier: Modifier = Modifier, last: @Composable ColumnScope.() -> Unit) {
    val pager = rememberPagerState { SLIDES.size }
    val scope = rememberCoroutineScope()
    val end = pager.currentPage == SLIDES.lastIndex
    Column(modifier.fillMaxSize().padding(horizontal = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Wordmark(Modifier.align(Alignment.CenterStart))
            if (!end) {
                TextButton(
                    onClick = { scope.launch { pager.animateScrollToPage(SLIDES.lastIndex) } },
                    modifier = Modifier.align(Alignment.CenterEnd).testTag("tour-skip"),
                ) { Text("Skip") }
            }
        }
        HorizontalPager(pager, Modifier.fillMaxWidth().weight(1f)) { page ->
            Column(
                Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                TourDrawing(
                    page,
                    Modifier.weight(1f, fill = false).widthIn(max = 360.dp).fillMaxWidth().aspectRatio(1f),
                    // Comes in once come to, not while its neighbor is shown.
                    play = pager.settledPage == page,
                )
                Spacer(Modifier.height(24.dp))
                Text(
                    SLIDES[page].title,
                    modifier = Modifier.testTag("tour-title"),
                    style = MaterialTheme.typography.headlineSmall,
                    textAlign = TextAlign.Center,
                )
                Text(
                    SLIDES[page].line,
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
        Dots(pager.currentPage, SLIDES.size, Modifier.padding(vertical = 16.dp))
        if (end) {
            last()
        } else {
            BigButton("Next", Modifier.fillMaxWidth().testTag("tour-next")) {
                scope.launch { pager.animateScrollToPage(pager.currentPage + 1) }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** Which of the tour's pages is shown, of `count`. */
@Composable
private fun Dots(at: Int, count: Int, modifier: Modifier = Modifier) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        repeat(count) { i ->
            val color by animateColorAsState(
                if (i == at) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
                label = "dot",
            )
            val width by animateDpAsState(if (i == at) 20.dp else 8.dp, label = "dot")
            Box(Modifier.size(width, 8.dp).background(color, CircleShape))
        }
    }
}
