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
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.drawscope.withTransform

/**
 * The pictures of the tour, drawn rather than shipped as images: gold bars
 * are the user's bitcoin, dashed teal bars the room a hub adds, lichen
 * green what the user holds (the key, claims), a calendar tag the date the
 * vault opens to the user alone. Flat on dark, outlined on light; the same
 * shapes in both. Drawn in a square of 720 units.
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
    val tag: Color,
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
    tag = Color(0xFF2C3A22),
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
    tag = Color(0xFFD9EDC4),
    ticket = Color(0xFFFFFFFF),
    feet = Color(0xFF1E3D0E),
    line = 1.25f,
)

private val Loaf = Color(0xFFC98A4B)
private val Crust = Color(0xFF8A5A2B)

/** What is in a vault's place: nothing, a gold bar or a hub's. */
private enum class Bar { GOLD, HUB }

/**
 * The five pictures, `t` from 0 to 1 as one comes in: what is drawn last
 * shows last.
 */
private class Pictures(val d: DrawScope, val p: Palette, val t: Float) {
    fun draw(slide: Int) = when (slide) {
        0 -> vault(List(6) { Bar.GOLD })
        1 -> paying()
        2 -> claims()
        3 -> own()
        else -> sized()
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
            Bar.HUB -> {
                d.drawPath(shape, p.hub, alpha = 0.16f * alpha)
                d.drawPath(shape, p.hub, alpha = alpha, style = stroke(4f, floatArrayOf(10f, 8f)))
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

    /** A claim: a ticket, a dot on it unless only outlined. */
    private fun ticket(cx: Float, cy: Float, rot: Float, color: Color, dashed: Boolean = false, alpha: Float = 1f) {
        if (alpha <= 0f) return
        d.rotate(rot, Offset(cx, cy)) {
            if (!dashed) {
                drawRoundRect(p.ticket, Offset(cx - 44, cy - 25), Size(88f, 50f), CornerRadius(10f), alpha = alpha)
            }
            drawRoundRect(
                color,
                Offset(cx - 44, cy - 25),
                Size(88f, 50f),
                CornerRadius(10f),
                alpha = alpha,
                style = stroke(4f, if (dashed) floatArrayOf(8f, 7f) else null),
            )
            if (!dashed) drawCircle(color, 10f, Offset(cx, cy), alpha = alpha)
        }
    }

    /** The user's key, under the vault. */
    private fun key(cx: Float = 268f, cy: Float = 634f, alpha: Float = 1f) {
        if (alpha <= 0f) return
        d.drawCircle(p.mine, 26f, Offset(cx, cy), alpha = alpha, style = stroke(12f))
        line(Offset(cx + 26, cy), Offset(cx + 176, cy), p.mine, 12f, alpha)
        line(Offset(cx + 136, cy), Offset(cx + 136, cy + 24), p.mine, 12f, alpha)
        line(Offset(cx + 168, cy), Offset(cx + 168, cy + 30), p.mine, 12f, alpha)
    }

    /** The calendar tag hung on the vault: the date it opens to its user alone. */
    private fun tag(alpha: Float) {
        if (alpha <= 0f) return
        val string = Path().apply {
            moveTo(206f, 142f)
            cubicTo(190f, 110f, 170f, 104f, 150f, 96f)
        }
        d.drawPath(string, p.dim, alpha = alpha, style = stroke(4f))
        d.rotate(-14f, Offset(104f, 84f)) {
            drawRoundRect(p.tag, Offset(52f, 48f), Size(104f, 76f), CornerRadius(14f), alpha = alpha)
            drawRoundRect(p.mine, Offset(52f, 48f), Size(104f, 76f), CornerRadius(14f), alpha = alpha, style = stroke(4f))
            line(Offset(52f, 72f), Offset(156f, 72f), p.mine, 4f, alpha)
            line(Offset(80f, 40f), Offset(80f, 58f), p.mine, 6f, alpha)
            line(Offset(128f, 40f), Offset(128f, 58f), p.mine, 6f, alpha)
            for ((x, y) in listOf(78f to 90f, 104f to 90f, 130f to 90f, 78f to 108f, 104f to 108f)) {
                drawCircle(p.mine, 5f, Offset(x, y), alpha = alpha)
            }
            drawCircle(p.mine, 9f, Offset(130f, 108f), alpha = alpha, style = stroke(4f))
        }
    }

    /** Gold carried to a shop, change carried back, someone watching. */
    private fun paying() {
        bar(70f, 290f, Bar.GOLD, 2.4f)
        val there = part(0, 3)
        line(Offset(318f, 340f), Offset(318f + 110 * there, 340f), p.strong, 8f, there)
        d.drawPath(
            Path().apply { moveTo(406f, 320f); lineTo(428f, 340f); lineTo(406f, 360f) },
            p.strong,
            alpha = there,
            style = stroke(8f),
        )
        val loaf = Path().apply {
            moveTo(470f, 410f)
            lineTo(470f, 358f)
            arcTo(Rect(470f, 296f, 650f, 420f), 180f, 180f, false)
            lineTo(650f, 410f)
            quadraticTo(650f, 420f, 640f, 420f)
            lineTo(480f, 420f)
            quadraticTo(470f, 420f, 470f, 410f)
            close()
        }
        d.drawPath(loaf, Loaf)
        d.drawPath(loaf, Crust, style = stroke(6f))
        for (x in listOf(520f, 556f, 592f)) {
            val y = if (x == 556f) 318f else 330f
            line(Offset(x, y), Offset(x + 16, y + if (x == 556f) 38f else 34f), Crust, 6f)
        }
        val back = part(1, 3)
        line(Offset(428f, 500f), Offset(428f - 110 * back, 500f), p.dim, 8f, back)
        d.drawPath(
            Path().apply { moveTo(340f, 480f); lineTo(318f, 500f); lineTo(340f, 520f) },
            p.dim,
            alpha = back,
            style = stroke(8f),
        )
        bar(120f, 470f, Bar.GOLD, 1.5f, back)
        bar(500f, 474f, Bar.GOLD, 0.45f, back)
        // Someone sees it all.
        val seen = part(2, 3)
        val eye = Path().apply {
            moveTo(500f, 196f)
            quadraticTo(560f, 140f, 620f, 196f)
            quadraticTo(560f, 252f, 500f, 196f)
            close()
        }
        d.drawPath(eye, p.strong, alpha = seen, style = stroke(6f))
        d.drawCircle(p.strong, 16f, Offset(560f, 196f), alpha = seen)
        line(Offset(560f, 250f), Offset(560f, 284f), p.strong, 4f, seen, floatArrayOf(4f, 8f))
    }

    /** Many claims fanned out over one bar of gold. */
    private fun claims() {
        bar(250f, 470f, Bar.GOLD, 2.4f)
        val fan = listOf(
            Triple(150f, 300f, -24f), Triple(232f, 250f, -14f), Triple(320f, 222f, -5f), Triple(410f, 222f, 5f),
            Triple(498f, 250f, 14f), Triple(580f, 300f, 24f), Triple(196f, 372f, -16f), Triple(290f, 340f, -6f),
            Triple(384f, 330f, 2f), Triple(478f, 344f, 8f), Triple(560f, 380f, 18f),
        )
        // Fanned out from the middle, over the bar.
        val open = part(0, 1)
        for ((x, y, r) in fan) {
            val cx = 365f + (x - 365f) * open
            val cy = 420f + (y - 420f) * open
            ticket(cx, cy, r * open, p.strong, alpha = (open * 3).coerceAtMost(1f))
        }
    }

    /** The user's own vault: gold and room in it, its date, the claims and the key held. */
    private fun own() {
        vault(List(3) { Bar.GOLD } + List(3) { Bar.HUB })
        val held = part(5, 7)
        tag(part(6, 7))
        ticket(78f, 268f, -10f, p.mine, alpha = held)
        ticket(84f, 350f, 8f, p.mine, alpha = held)
        ticket(74f, 432f, -6f, p.mine, alpha = held)
        key(alpha = held)
    }

    /** The vault's size: claims up to it are covered, beyond it only promised. */
    private fun sized() {
        vault(List(3) { Bar.GOLD } + List(3) { Bar.HUB })
        val covered = part(5, 7)
        for (i in 0 until 4) ticket(98f + i * 104, 640f, 0f, p.mine, alpha = covered)
        val beyond = part(6, 7)
        line(Offset(462f, 596f), Offset(462f, 684f), p.dim, 4f, beyond, floatArrayOf(4f, 8f))
        for (i in 4 until 6) ticket(98f + i * 104, 640f, 0f, p.dim, dashed = true, alpha = beyond)
    }
}
