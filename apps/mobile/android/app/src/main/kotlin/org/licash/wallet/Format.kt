package org.licash.wallet

import java.text.DateFormat
import java.util.Date
import java.util.Locale
import org.licash.core.Balance
import org.licash.core.ChainException
import org.licash.core.LicashException

/** `12,345 sat`, commas between thousands. */
fun sat(amount: ULong): String = "${digits(amount)} sat"

/** `12,345`. */
fun digits(amount: ULong): String = String.format(Locale.US, "%,d", amount.toLong())

/** All the wallet holds: in notes, and on Bitcoin. */
val Balance.total: ULong get() = notes + notesPending + onchain + moving + opening

/**
 * Of [total], what hubs owe on trust alone: the notes no contract covers.
 * The rest, on Bitcoin or covered by a contract, is the wallet's own.
 */
val Balance.credit: ULong
    get() {
        val held = notes + notesPending
        return if (held > covered) held - covered else 0uL
    }

/**
 * [credit] as a share of [total], in whole percent: 0 if nothing is held.
 * Never 0 with some on credit, nor 100 with some protected.
 */
val Balance.creditPercent: Int
    get() {
        if (total == 0uL) return 0
        val rounded = ((credit.toDouble() * 100 / total.toDouble()) + 0.5).toInt()
        return when {
            credit > 0uL && rounded == 0 -> 1
            credit < total && rounded == 100 -> 99
            else -> rounded
        }
    }

/**
 * What [fee] is of [of], to two significant digits: `0.24%`, `1.2%`, `5%`,
 * `12%`, `<0.01%` below. Null for no fee, or a fee of nothing.
 */
fun share(fee: ULong, of: ULong): String? {
    if (fee == 0uL || of == 0uL) return null
    val at = { scale: Long -> Math.round(fee.toDouble() * scale / of.toDouble()) }
    val hundredths = at(10_000)
    if (hundredths == 0L) return "<0.01%"
    if (hundredths < 100) return String.format(Locale.US, "0.%02d%%", hundredths)
    val tenths = at(1_000)
    return when {
        tenths < 100 && tenths % 10 != 0L -> "${tenths / 10}.${tenths % 10}%"
        tenths < 100 -> "${tenths / 10}%"
        else -> "${digits(at(100).toULong())}%"
    }
}

/** A fee and what it is of [of]: `12 sat · 0.24%`. */
fun feeOf(fee: ULong, of: ULong): String = sat(fee) + (share(fee, of)?.let { " · $it" } ?: "")

/** `ppm` millionths as a percentage: `0.5%`. */
fun percent(ppm: ULong): String =
    java.text.DecimalFormat("0.####", java.text.DecimalFormatSymbols(Locale.US))
        .format(ppm.toDouble() / 10_000) + "%"

/** What went wrong, for the user. */
fun explain(e: Throwable): String = when (e) {
    is LicashException.Invalid -> plain(e.reason)
    is LicashException.Unavailable -> plain(e.reason)
    is LicashException.Pending -> "Still under way: it finishes by itself."
    is LicashException.Insufficient ->
        "Not enough: ${sat(e.needed)} needed, ${sat(e.available)} available."
    is LicashException.NeedsTor -> "This hub is on Tor: turn Tor on in Settings."
    is LicashException.UnknownHub -> "This payment is at a hub you don't use yet: ${e.url}"
    is LicashException.FeesRaised ->
        "${host(e.hub)} raised its fees since your protection there started. Approve them in Settings, under Hubs, to pay there."
    is LicashException.Failed -> plain(e.reason)
    is LicashException.NoteUnkept -> "${host(e.hub)} can't carry a note with a payment."
    is ChainException.Failed -> plain(e.reason)
    else -> plain(e.message ?: e.toString())
}

/**
 * Why a protection was not set up, `reason` as [explain] says it: a hub
 * with no room for one, at its limit or its own bitcoin short, said as
 * that, and what to do about it.
 */
internal fun openFailure(reason: String): String =
    if (NO_ROOM.any { it.containsMatchIn(reason) }) HUB_NO_ROOM else reason

/** Said of a hub that opens no vault now. */
internal const val HUB_NO_ROOM = "This hub can't open new vaults right now. Try later, or use another hub."

/** The hub's refusals for want of room: its wallet short, its contracts as many as it takes, its openings too many. */
private val NO_ROOM = listOf(
    Regex("the hub's wallet funds [\\d,]+ sat of a contract at most now", RegexOption.IGNORE_CASE),
    Regex("the hub has [\\d,]+ contracts live, its most", RegexOption.IGNORE_CASE),
    Regex("too many openings (under way|signed and not funded)", RegexOption.IGNORE_CASE),
)

/**
 * A reason the core gives, in the app's words: a sentence, its amounts
 * grouped, and no one to pay out or move said without naming providers.
 */
internal fun plain(reason: String): String {
    fun amount(m: MatchResult) = m.groupValues[1].toULongOrNull()?.let(::sat) ?: "${m.groupValues[1]} sat"
    NO_PAYOUT.matchEntire(reason)?.let { return "No one can send ${amount(it)} on Bitcoin right now. Try less, or later." }
    NO_MOVE.matchEntire(reason)?.let { return "No one can move ${amount(it)} between your hubs right now. Try less, or later." }
    NO_HUB.matchEntire(reason)?.let { return "Your balance can't pay ${amount(it)} and its fee here." }
    return AMOUNT.replace(reason, ::amount).replaceFirstChar { it.uppercase() }
}

private val NO_PAYOUT = Regex("no swap provider found pays (\\d+) sat out on Bitcoin now")
private val NO_MOVE = Regex("no swap provider found moves (\\d+) sat from \\S+ to \\S+ now")

/** The core's reason when no hub a code names holds the amount and its fee, with where to pay on Bitcoin instead, if the code says. */
private val NO_HUB = Regex("no hub it names is one trusted holding (\\d+) and the fee(?:: pay \\S+ on Bitcoin)?")
private val AMOUNT = Regex("\\b(\\d{4,}) sat\\b")

/**
 * The host of a hub's `url`, to name it short: with its port if it names
 * one, as hubs sharing a host do.
 */
fun host(url: String): String = runCatching {
    val uri = java.net.URI(url)
    val host = uri.host ?: return@runCatching null
    if (uri.port == -1) host else "$host:${uri.port}"
}.getOrNull() ?: url

/** About how long `blocks` take, `blockSecs` each (ten minutes on Bitcoin's networks): `about 6 days`. */
fun duration(blocks: Long, blockSecs: Long = 600): String {
    val minutes = blocks * blockSecs / 60
    return when {
        blocks <= 0 -> "now"
        minutes < 90 -> "about $minutes minutes"
        minutes < 48 * 60 -> "about ${(minutes + 30) / 60} hours"
        else -> "about ${(minutes + 720) / 1440} days"
    }
}

/** When, from seconds since 1970. */
fun at(seconds: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))

/** Whether `e` says no swap provider pays the amount out on Bitcoin now. */
fun noPayout(e: Throwable): Boolean = e is LicashException.Invalid && NO_PAYOUT.matches(e.reason)

/** The most to offer instead of `asked`, none paying it out: `most`, if some and less. */
fun offeredInstead(asked: ULong?, most: ULong?): ULong? = most?.takeIf { asked != null && it in 1uL until asked }

/** Whether `e` says no hub the code names holds the amount and its fee: the payer holds too little there. */
fun noHub(e: Throwable): Boolean = e is LicashException.Invalid && NO_HUB.matches(e.reason)
