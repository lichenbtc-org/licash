package org.licash.wallet.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathMeasure
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import kotlin.math.cos
import kotlin.math.sin

/*
 * What progress looks like: a check drawn in a ring, once, where something
 * was reached. Small and short, and never alone: the words beside it say
 * what it was. The system's setting for animations scales it, or ends it.
 */

/** How long a cheer takes to draw, in ms. */
internal const val CHEER_MS = 700

/**
 * How much of the ring, of the check and of the sparks around them is
 * drawn `at` a part of the cheer, from 0 to 1: the ring first, the check
 * over its end, the sparks out and gone with it. Each from 0 to 1; the
 * sparks' is how far out they are, gone at 1.
 */
internal data class Cheered(val ring: Float, val check: Float, val sparks: Float)

internal fun cheered(at: Float): Cheered {
    fun part(from: Float, to: Float) = ((at - from) / (to - from)).coerceIn(0f, 1f)
    return Cheered(ring = part(0f, 0.55f), check = part(0.4f, 0.85f), sparks = part(0.5f, 1f))
}

/**
 * A check in a ring, drawn once shown (`play`), of `size`: the larger for
 * what a wallet was set up for, small beside a line. With `sparks`, a few
 * short rays around it, out and gone.
 */
@Composable
internal fun Cheer(
    modifier: Modifier = Modifier,
    size: Dp = 96.dp,
    play: Boolean = true,
    sparks: Boolean = true,
    color: Color = MaterialTheme.colorScheme.primary,
) {
    val drawn = remember { Animatable(0f) }
    val pop = remember { Animatable(1f) }
    LaunchedEffect(play) {
        if (!play) return@LaunchedEffect
        drawn.snapTo(0f)
        launch { drawn.animateTo(1f, tween(CHEER_MS, easing = FastOutSlowInEasing)) }
        pop.snapTo(0.8f)
        pop.animateTo(1f, spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow))
    }
    Canvas(modifier.size(size).testTag("cheer")) {
        val now = cheered(drawn.value)
        // Room around the ring for the sparks.
        val radius = this.size.minDimension * (if (sparks) 0.34f else 0.44f)
        val stroke = Stroke(this.size.minDimension * 0.06f, cap = StrokeCap.Round, join = StrokeJoin.Round)
        scale(pop.value) {
            drawArc(
                color,
                startAngle = -90f,
                sweepAngle = 360f * now.ring,
                useCenter = false,
                topLeft = Offset(center.x - radius, center.y - radius),
                size = androidx.compose.ui.geometry.Size(radius * 2, radius * 2),
                style = stroke,
            )
            if (now.check > 0f) {
                val whole = Path().apply {
                    moveTo(center.x - radius * 0.45f, center.y + radius * 0.02f)
                    lineTo(center.x - radius * 0.12f, center.y + radius * 0.36f)
                    lineTo(center.x + radius * 0.48f, center.y - radius * 0.32f)
                }
                val measure = PathMeasure().apply { setPath(whole, false) }
                val part = Path()
                measure.getSegment(0f, measure.length * now.check, part, true)
                drawPath(part, color, style = stroke)
            }
            if (sparks && now.sparks > 0f && now.sparks < 1f) {
                val from = radius * (1.22f + 0.12f * now.sparks)
                val to = radius * (1.32f + 0.3f * now.sparks)
                repeat(8) { i ->
                    val angle = Math.toRadians(i * 45.0 + 22.5)
                    val way = Offset(cos(angle).toFloat(), sin(angle).toFloat())
                    drawLine(
                        color.copy(alpha = 1f - now.sparks),
                        center + way * from,
                        center + way * to,
                        strokeWidth = stroke.width * 0.6f,
                        cap = StrokeCap.Round,
                    )
                }
            }
        }
    }
}

/**
 * Money that came in, said over the screen while `visible`: a check drawn
 * beside `text`, what arrived, from the top and gone again.
 */
@Composable
internal fun ReceivedBanner(visible: Boolean, text: String, modifier: Modifier = Modifier) {
    AnimatedVisibility(
        visible = visible,
        modifier = modifier,
        enter = slideInVertically { -it } + fadeIn(),
        exit = slideOutVertically { -it } + fadeOut(),
    ) {
        val colors = MaterialTheme.colorScheme
        Row(
            Modifier.padding(top = 8.dp).clip(RoundedCornerShape(24.dp)).background(colors.primaryContainer)
                .padding(start = 12.dp, end = 20.dp, top = 10.dp, bottom = 10.dp).testTag("received-banner"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Cheer(size = 28.dp, sparks = false, color = colors.onPrimaryContainer)
            Spacer(Modifier.width(10.dp))
            Text(text, style = MaterialTheme.typography.titleMedium, color = colors.onPrimaryContainer)
        }
    }
}
