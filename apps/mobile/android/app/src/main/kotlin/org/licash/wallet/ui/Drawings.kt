package org.licash.wallet.ui

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform

/**
 * The pictures of the tour, drawn rather than shipped as images: gold bars
 * are bitcoin, the user's plain, the hub's edged in teal; round tokens are
 * ecash, lichen green the user's, teal those paid to her, dashed those
 * beyond her vault (credit); a columned building is a hub, a vault company.
 * Flat on dark, outlined on light; the same shapes in both. Drawn in a
 * square of 720 units.
 */
@Composable
internal fun TourDrawing(slide: Int, modifier: Modifier = Modifier, play: Boolean = true) {
    val ink = if (isSystemInDarkTheme()) DarkInk else LightInk
    // Each picture comes in once shown (`play`): its parts in turn.
    val shown = remember(slide) { Animatable(0f) }
    LaunchedEffect(slide, play) { if (play) shown.animateTo(1f, tween(900, easing = FastOutSlowInEasing)) }
    Canvas(modifier) {
        val k = size.minDimension / UNITS
        val left = (size.width - UNITS * k) / 2
        val top = (size.height - UNITS * k) / 2
        withTransform({
            translate(left, top)
            scale(k, k, Offset.Zero)
        }) {
            Pictures(this, ink, shown.value).draw(slide)
        }
    }
}

/** The side of the square drawn in. */
private const val UNITS = 720f

/** The colors of a style, and how thick its lines are. */
private data class Palette(
    val gold: Color,
    val goldEdge: Color,
    val goldShine: Color,
    val hub: Color,
    val mine: Color,
    val body: Color,
    val bodyEdge: Color,
    val inside: Color,
    val insideEdge: Color,
    val door: Color,
    val dim: Color,
    val strong: Color,
    val shadow: Color,
    val ticket: Color,
    val feet: Color,
    val line: Float,
)

/** Flat, on the app's dark background. */
private val DarkInk = Palette(
    gold = Color(0xFFF2C14E),
    goldEdge = Color(0xFFC9972B),
    goldShine = Color(0xFFFFE7A3),
    hub = Color(0xFF6FB7A8),
    mine = Color(0xFFA8E06C),
    body = Color(0xFF181D20),
    bodyEdge = Color(0xFF39423F),
    inside = Color(0xFF0F1214),
    insideEdge = Color(0xFF2A3230),
    door = Color(0xFF20262A),
    dim = Color(0xFF8A9590),
    strong = Color(0xFFE7ECE9),
    shadow = Color(0xFF14181B),
    ticket = Color(0xFF181D20),
    feet = Color(0xFF20262A),
    line = 1f,
)

/** Outlined, on the app's cream background. */
private val LightInk = Palette(
    gold = Color(0xFFE0A93B),
    goldEdge = Color(0xFF1E3D0E),
    goldShine = Color(0xFFF6D88E),
    hub = Color(0xFF2F7F70),
    mine = Color(0xFF3F7D20),
    body = Color(0xFFFFFFFF),
    bodyEdge = Color(0xFF1E3D0E),
    inside = Color(0xFFF1EEE7),
    insideEdge = Color(0xFFC9C5BA),
    door = Color(0xFFFFFFFF),
    dim = Color(0xFF5E665F),
    strong = Color(0xFF1E3D0E),
    shadow = Color(0xFFEAE7DF),
    ticket = Color(0xFFFFFFFF),
    feet = Color(0xFF1E3D0E),
    line = 1.25f,
)

private val Loaf = Color(0xFFC98A4B)
private val Crust = Color(0xFF8A5A2B)

/** What is in a vault's place: the user's gold, or the hub's. */
private enum class Bar { GOLD, HUB }

/**
 * The five pictures, `t` from 0 to 1 as one comes in: what is drawn last
 * shows last.
 */
private class Pictures(val d: DrawScope, val p: Palette, val t: Float) {
    fun draw(slide: Int) = when (slide) {
        0 -> vault(List(6) { Bar.GOLD })
        1 -> paying()
        2 -> issued()
        3 -> own()
        else -> net()
    }

    /** How far part `i` of `n` has come in: one after the other. */
    private fun part(i: Int, n: Int): Float {
        val start = i.toFloat() / (n + 1)
        return ((t - start) * (n + 1) / 2f).coerceIn(0f, 1f)
    }

    private fun stroke(width: Float, dash: FloatArray? = null) = Stroke(
        width = width * p.line,
        cap = StrokeCap.Round,
        join = StrokeJoin.Round,
        pathEffect = dash?.let { PathEffect.dashPathEffect(it) },
    )

    private fun line(from: Offset, to: Offset, color: Color, width: Float, alpha: Float = 1f, dash: FloatArray? = null) =
        d.drawLine(
            color,
            from,
            to,
            strokeWidth = width * p.line,
            cap = StrokeCap.Round,
            pathEffect = dash?.let { PathEffect.dashPathEffect(it) },
            alpha = alpha,
        )

    private fun rect(x: Float, y: Float, w: Float, h: Float, r: Float, fill: Color, edge: Color? = null, width: Float = 4f) {
        d.drawRoundRect(fill, Offset(x, y), Size(w, h), CornerRadius(r))
        edge?.let { d.drawRoundRect(it, Offset(x, y), Size(w, h), CornerRadius(r), style = stroke(width)) }
    }

    private fun poly(vararg points: Pair<Float, Float>): Path = Path().apply {
        moveTo(points[0].first, points[0].second)
        for ((x, y) in points.drop(1)) lineTo(x, y)
        close()
    }

    /** A bar at (`x`, `y`), `s` times the size of a vault's. */
    private fun bar(x: Float, y: Float, kind: Bar, s: Float = 1f, alpha: Float = 1f) {
        if (alpha <= 0f) return
        // Coming in, it drops a little into its place.
        val dy = (1f - alpha) * -24f
        val shape = poly(x + 12 * s to y + dy, x + 80 * s to y + dy, x + 92 * s to y + 36 * s + dy, x to y + 36 * s + dy)
        when (kind) {
            Bar.GOLD -> {
                d.drawPath(shape, p.gold, alpha = alpha)
                d.drawPath(shape, p.goldEdge, alpha = alpha, style = stroke(4f))
                line(Offset(x + 22 * s, y + 10 * s + dy), Offset(x + 66 * s, y + 10 * s + dy), p.goldShine, 4f, alpha)
            }
            // Real gold too, the hub's: edged in its color.
            Bar.HUB -> {
                d.drawPath(shape, p.gold, alpha = alpha)
                d.drawPath(shape, p.hub, alpha = alpha, style = stroke(7f))
                line(Offset(x + 22 * s, y + 10 * s + dy), Offset(x + 66 * s, y + 10 * s + dy), p.hub, 4f, alpha)
            }
        }
    }

    /** An open vault, its six places filled from the bottom row up. */
    private fun vault(bars: List<Bar>) {
        d.drawOval(p.shadow, Offset(120f, 550f), Size(500f, 32f))
        rect(186f, 540f, 56f, 22f, 6f, p.feet)
        rect(478f, 540f, 56f, 22f, 6f, p.feet)
        rect(150f, 140f, 420f, 404f, 36f, p.body, p.bodyEdge, 6f)
        rect(192f, 182f, 336f, 320f, 20f, p.inside, p.insideEdge, 4f)
        val spots = listOf(214f to 446f, 314f to 446f, 414f to 446f, 264f to 398f, 364f to 398f, 314f to 350f)
        spots.zip(bars).forEachIndexed { i, (spot, kind) ->
            bar(spot.first, spot.second, kind, alpha = part(i, spots.size))
        }
        val door = poly(570f to 152f, 644f to 122f, 644f to 578f, 570f to 548f)
        d.drawPath(door, p.door)
        d.drawPath(door, p.bodyEdge, style = stroke(6f))
        d.drawOval(p.dim, Offset(590f, 304f), Size(40f, 92f), style = stroke(6f))
        line(Offset(610f, 304f), Offset(610f, 396f), p.dim, 6f)
        line(Offset(592f, 350f), Offset(628f, 350f), p.dim, 6f)
        rect(562f, 210f, 14f, 40f, 5f, p.bodyEdge)
        rect(562f, 440f, 14f, 40f, 5f, p.bodyEdge)
    }

    /** An ecash token: a coin with a ring and a dot; only outlined and dashed, beyond the vault. */
    private fun token(cx: Float, cy: Float, color: Color, dashed: Boolean = false, alpha: Float = 1f, r: Float = 30f) {
        if (alpha <= 0f) return
        // Coming in, it drops a little into its place.
        val c = Offset(cx, cy + (1f - alpha) * -16f)
        if (!dashed) d.drawCircle(p.ticket, r, c, alpha = alpha)
        d.drawCircle(color, r, c, alpha = alpha, style = stroke(5f, if (dashed) floatArrayOf(8f, 7f) else null))
        d.drawCircle(color, r * 0.6f, c, alpha = alpha * if (dashed) 0.5f else 1f, style = stroke(3f))
        if (!dashed) d.drawCircle(color, r * 0.2f, c, alpha = alpha)
    }

    /** The user's key, under the vault. */
    private fun key(cx: Float = 268f, cy: Float = 634f, alpha: Float = 1f) {
        if (alpha <= 0f) return
        d.drawCircle(p.mine, 26f, Offset(cx, cy), alpha = alpha, style = stroke(12f))
        line(Offset(cx + 26, cy), Offset(cx + 176, cy), p.mine, 12f, alpha)
        line(Offset(cx + 136, cy), Offset(cx + 136, cy + 24), p.mine, 12f, alpha)
        line(Offset(cx + 168, cy), Offset(cx + 168, cy + 30), p.mine, 12f, alpha)
    }

    /**
     * A gold bar to pay for a loaf: an hourglass between them, its sand
     * running (slow), a sliver of the bar falling away (the fee), an eye
     * over it all (public).
     */
    private fun paying() {
        bar(24f, 334f, Bar.GOLD, 2.4f)
        hourglass(340f, 290f, part(0, 3))
        loaf(436f, 300f)
        val fee = part(1, 3)
        line(Offset(140f, 432f), Offset(140f, 432f + 64f * fee), p.dim, 4f, fee, floatArrayOf(4f, 8f))
        bar(116f, 500f + 30f * fee, Bar.GOLD, 0.5f, fee)
        val seen = part(2, 3)
        val eye = Path().apply {
            moveTo(270f, 160f)
            quadraticTo(340f, 96f, 410f, 160f)
            quadraticTo(340f, 224f, 270f, 160f)
            close()
        }
        d.drawPath(eye, p.strong, alpha = seen, style = stroke(6f))
        d.drawCircle(p.strong, 17f, Offset(340f, 160f), alpha = seen)
    }

    /** An hourglass `sand` of the way run, its neck at (`cx`, `top` + 70). */
    private fun hourglass(cx: Float, top: Float, sand: Float) {
        val w = 46f
        val h = 70f
        val upper = 0.85f * (1f - 0.8f * sand)
        d.drawPath(poly(cx - w * upper to top + h - h * upper, cx + w * upper to top + h - h * upper, cx to top + h - 4f), p.gold)
        val lower = 0.85f * (0.15f + 0.85f * sand)
        d.drawPath(poly(cx - w * lower to top + 2 * h - 4f, cx + w * lower to top + 2 * h - 4f, cx to top + 2 * h - 4f - h * lower), p.gold)
        if (sand < 1f) line(Offset(cx, top + h), Offset(cx, top + 2 * h - 6f), p.gold, 3f)
        val glass = Path().apply {
            moveTo(cx - w, top)
            lineTo(cx + w, top)
            lineTo(cx + 4f, top + h)
            lineTo(cx + w, top + 2 * h)
            lineTo(cx - w, top + 2 * h)
            lineTo(cx - 4f, top + h)
            close()
        }
        d.drawPath(glass, p.strong, style = stroke(6f))
        line(Offset(cx - w - 14f, top), Offset(cx + w + 14f, top), p.strong, 10f)
        line(Offset(cx - w - 14f, top + 2 * h), Offset(cx + w + 14f, top + 2 * h), p.strong, 10f)
    }

    /** A loaf of bread, its left at `x` and its top at `y`, on a board. */
    private fun loaf(x: Float, y: Float) {
        rect(x - 16f, y + 124f, 212f, 18f, 8f, Crust)
        val loaf = Path().apply {
            moveTo(x, y + 114f)
            lineTo(x, y + 62f)
            arcTo(Rect(x, y, x + 180f, y + 124f), 180f, 180f, false)
            lineTo(x + 180f, y + 114f)
            quadraticTo(x + 180f, y + 124f, x + 170f, y + 124f)
            lineTo(x + 10f, y + 124f)
            quadraticTo(x, y + 124f, x, y + 114f)
            close()
        }
        d.drawPath(loaf, Loaf)
        d.drawPath(loaf, Crust, style = stroke(6f))
        for (cut in listOf(50f, 86f, 122f)) {
            val dy = if (cut == 86f) 22f else 34f
            line(Offset(x + cut, y + dy), Offset(x + cut + 16f, y + dy + 36f), Crust, 6f)
        }
    }

    /** A hub: a vault company's columned building, tokens fanning out of it. */
    private fun issued() {
        d.drawOval(p.shadow, Offset(160f, 606f), Size(400f, 28f))
        rect(186f, 584f, 348f, 24f, 6f, p.body, p.bodyEdge, 4f)
        rect(206f, 560f, 308f, 26f, 6f, p.body, p.bodyEdge, 4f)
        for (i in 0 until 4) rect(232f + i * 76f, 430f, 32f, 130f, 6f, p.body, p.bodyEdge, 4f)
        rect(206f, 404f, 308f, 28f, 6f, p.body, p.bodyEdge, 4f)
        val roof = poly(190f to 404f, 360f to 318f, 530f to 404f)
        d.drawPath(roof, p.body)
        d.drawPath(roof, p.bodyEdge, style = stroke(6f))
        d.drawCircle(p.gold, 18f, Offset(360f, 372f))
        // Fanned out from its roof.
        val fan = listOf(
            150f to 260f, 236f to 196f, 322f to 156f, 410f to 156f, 496f to 196f, 580f to 260f,
            270f to 268f, 360f to 236f, 450f to 268f,
        )
        val open = part(0, 1)
        for ((x, y) in fan) {
            val cx = 360f + (x - 360f) * open
            val cy = 330f + (y - 330f) * open
            token(cx, cy, p.strong, alpha = (open * 3).coerceAtMost(1f))
        }
    }

    /** The user's own vault: her gold in it, a token for each bar, and her key. */
    private fun own() {
        vault(List(3) { Bar.GOLD })
        val held = part(3, 5)
        for ((i, y) in listOf(570f, 498f, 426f).withIndex()) token(74f, y, p.mine, alpha = part(3 + i, 6))
        key(alpha = held)
    }

    /** What the vault protects, her gold and the hub's in it: tokens up to its balance; those beyond, not. */
    private fun net() {
        vault(List(3) { Bar.GOLD } + List(3) { Bar.HUB })
        val covered = part(5, 7)
        for (i in 0 until 6) token(76f + i * 82f, 640f, p.mine, alpha = (covered * 6 - i).coerceIn(0f, 1f))
        val beyond = part(6, 7)
        line(Offset(560f, 592f), Offset(560f, 688f), p.dim, 4f, beyond, floatArrayOf(4f, 8f))
        for (i in 6 until 8) token(76f + i * 82f + 12f, 640f, p.dim, dashed = true, alpha = beyond)
    }
}
