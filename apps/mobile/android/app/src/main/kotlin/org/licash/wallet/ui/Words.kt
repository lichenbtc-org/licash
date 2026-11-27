package org.licash.wallet.ui

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import org.licash.core.Balance
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.Fees
import org.licash.core.FeesRaised
import org.licash.core.Hub
import org.licash.core.Kind
import org.licash.core.OpeningStep
import org.licash.core.Rate
import org.licash.core.Recovery
import org.licash.core.RecoveryStage
import org.licash.core.State
import org.licash.core.Transfer
import org.licash.wallet.credit
import org.licash.wallet.digits
import org.licash.wallet.host
import org.licash.wallet.percent
import org.licash.wallet.sat
import org.licash.wallet.total
import kotlin.math.roundToLong

/*
 * The app's words, where a screen does not own them: what is said the same
 * way wherever it shows. Protected, of what the wallet holds, is what is
 * its own whatever a hub does: on Bitcoin, or covered by a hub's
 * collateral. The rest is not protected: owed by a hub, on its word alone.
 * Pure, to be tested without a screen.
 */

/** How much of what the wallet holds is protected: all, some or none of it. */
enum class Shield { ALL, SOME, NONE }

/** Of what is protected, what is `bitcoin` held and what `contracts` cover: in sat. */
data class SafeSplit(val bitcoin: ULong, val contracts: ULong)

/** `share`'s protected part split into what is on Bitcoin, `onBitcoin` at most, and what contracts cover. */
fun safeSplit(share: Protection, onBitcoin: ULong): SafeSplit {
    val bitcoin = minOf(share.protected, onBitcoin)
    return SafeSplit(bitcoin, share.protected - bitcoin)
}

/** What the wallet holds, as `protected` and `open`, the rest: in sat. */
data class Protection(val protected: ULong, val open: ULong) {
    val total: ULong get() = protected + open

    /** None while nothing is held: nothing to say of it. */
    val shield: Shield?
        get() = when {
            total == 0uL -> null
            open == 0uL -> Shield.ALL
            protected == 0uL -> Shield.NONE
            else -> Shield.SOME
        }

    /**
     * [protected] as a share of [total], in whole percent: never 0 with
     * some protected, nor 100 with some not.
     */
    val percent: Int
        get() {
            if (total == 0uL) return 0
            val rounded = ((protected.toDouble() * 100 / total.toDouble()) + 0.5).toInt()
            return when {
                protected > 0uL && rounded == 0 -> 1
                open > 0uL && rounded == 100 -> 99
                else -> rounded
            }
        }

    /** In a word or two, as Home says it. */
    val label: String?
        get() = when (shield) {
            null -> null
            Shield.ALL -> PROTECTED
            Shield.NONE -> NOT_PROTECTED
            Shield.SOME -> "$percent% protected"
        }
}

/** Whom a line of the history was paid to (one made) or by: its contact, if known. */
fun counterpart(kind: Kind, contact: String?): String? = contact?.let { if (kind == Kind.SENT) "To $it" else "From $it" }

/** How much of `balance` is protected. */
fun protection(balance: Balance): Protection = Protection(balance.total - balance.credit, balance.credit)

/**
 * The protection Home says beside the balance: none while one is being set
 * up (`opening`), which Home says instead, so it never says both.
 */
fun homeProtection(balance: Balance, opening: Boolean): Protection? = if (opening) null else protection(balance)

const val PROTECTED = "Protected"
const val PROTECTED_BY_CONTRACTS = "Protected by contracts"
const val NOT_PROTECTED = "Not protected"

/** What each means, where asked. */
const val PROTECTED_MEANS =
    "Notes claimable from a live recovery contract, should their hub fail you. Coverage counts whole eligible notes within each contract's payout and note limits. Recovering costs Bitcoin fees and needs the app opened before the contract's deadline."
const val NOT_PROTECTED_MEANS =
    "Held on credit: a hub owes it to you, on its word alone. Protect it with a contract, paid with a coin " +
        "you hold on Bitcoin, or cash it out to Bitcoin."

/** What bitcoin held is, beside what is protected: safe already, needing no contract. */
const val SAFE_ONCHAIN_MEANS =
    "Bitcoin you hold yourself: safe whatever a hub does. Paying for a contract with a coin of it protects " +
        "your notes at that hub, and adds the rest of the coin to your balance."

/**
 * What paying through a swap provider risks, said before paying: should it
 * decline or fail the payment, the sats wait `blocks` for their lock to
 * expire.
 */
fun refundWait(blocks: UInt, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): String =
    "If the provider declines or fails the payment, your sats come back by themselves, in about ${span(blocks.toLong(), blockSecs)}."

/**
 * Where a payment through a swap provider that it declined or failed
 * stands: its sats back once its lock expires, `blocks` from now if known.
 */
fun notPaid(blocks: UInt?, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): String = when {
    blocks == null || blocks == 0u -> "Not paid. Your money comes back by itself."
    else -> "Not paid. Your money comes back by itself in about ${span(blocks.toLong(), blockSecs)}."
}

/** Seconds a block takes on Bitcoin's networks, 10 minutes: Mutinynet's take 30. */
const val BITCOIN_BLOCK_SECONDS = 600u

/**
 * How long `blocks` take, `blockSecs` each (those of the wallet's network),
 * as a clock would say it: `6 days`. Never a block height: what a block is,
 * nobody needs to know.
 */
fun span(blocks: Long, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): String {
    val seconds = blocks * blockSecs.toLong()
    val minutes = (seconds + 30) / 60
    val hours = (seconds + 1800) / 3600
    val days = (seconds + 43200) / 86400
    return when {
        blocks <= 0 -> "now"
        seconds < 60 -> "$seconds sec"
        seconds < 3600 -> "$minutes min"
        hours < 48 -> if (hours == 1L) "1 hour" else "$hours hours"
        else -> "$days days"
    }
}

/** The minutes `blocks` take, `blockSecs` each, rounded and at least one. */
fun minutes(blocks: Long, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): Long =
    maxOf(1L, (blocks * blockSecs.toLong() + 30) / 60)

/**
 * A timelock's block `height`, for advanced mode: the block, then, from
 * the `tip` the light client reached (0 if not yet known: the block alone),
 * `blockSecs` a block, about when it comes and how long until then:
 * `Block 912,345 · about Dec 3, 14:20 · in 6 days`. Once reached,
 * `Block 912,345 · passed`. Blocks come when they come: about.
 */
fun atBlock(
    height: UInt,
    tip: Int,
    blockSecs: UInt,
    now: Long,
    zone: ZoneId = ZoneId.systemDefault(),
    locale: Locale = Locale.getDefault(),
): String {
    val block = "Block ${digits(height.toULong())}"
    if (tip <= 0) return block
    val left = height.toLong() - tip
    if (left <= 0) return "$block · passed"
    val at = Instant.ofEpochSecond(now + left * blockSecs.toLong()).atZone(zone)
    val sameYear = at.year == Instant.ofEpochSecond(now).atZone(zone).year
    val date = at.format(DateTimeFormatter.ofPattern(if (sameYear) "MMM d" else "MMM d, yyyy", locale))
    val time = at.format(DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(locale))
    return "$block · about $date, $time · in ${span(left, blockSecs)}"
}

/**
 * When `seconds` since 1970 was, as short as `now` lets it be said: the
 * time today, `Yesterday`, `Nov 13`, and with its year once it is another.
 */
fun day(
    seconds: Long,
    now: Long,
    zone: ZoneId = ZoneId.systemDefault(),
    locale: Locale = Locale.getDefault(),
): String {
    val at = Instant.ofEpochSecond(seconds).atZone(zone)
    val date = at.toLocalDate()
    val today = Instant.ofEpochSecond(now).atZone(zone).toLocalDate()
    val format = { pattern: String -> at.format(DateTimeFormatter.ofPattern(pattern, locale)) }
    return when {
        date == today -> at.format(
            DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withLocale(locale),
        )
        date == today.minusDays(1) -> "Yesterday"
        date.year == today.year -> format("MMM d")
        else -> format("MMM d, yyyy")
    }
}

/**
 * A hub's name, short, from its `url`: its host, with its port if it names
 * one; an onion service's by its first letters, the rest telling nobody
 * anything.
 */
fun name(url: String): String {
    val host = host(url)
    val onion = host.substringBefore(':').removeSuffix(".onion")
    return if (onion.length > 12 && host.substringBefore(':').endsWith(".onion")) {
        onion.take(8) + "….onion" + host.substring(host.substringBefore(':').length)
    } else {
        host
    }
}

/** A fee, as short as it can be said: `None`, `10 sat`, `0.5%`, `10 sat + 0.5%`. */
fun charge(rate: Rate): String = when {
    rate.base == 0uL && rate.ppm == 0uL -> "None"
    rate.ppm == 0uL -> sat(rate.base)
    rate.base == 0uL -> percent(rate.ppm)
    else -> "${sat(rate.base)} + ${percent(rate.ppm)}"
}

/**
 * What a hub charges a payment in Licash: its rate and, if it charges for
 * the notes a payment makes, that for each: `1 sat + 0.01% + 0.1 sat a note`.
 */
fun paying(hub: Hub): String = paying(Rate(hub.feeBase, hub.feePpm), hub.feeOutputMsat)

/** [paying], of a `rate` and a fee of `outputMsat` thousandths of a sat for each note made. */
fun paying(rate: Rate, outputMsat: ULong): String {
    if (outputMsat == 0uL) return charge(rate)
    val (whole, rest) = outputMsat / 1_000uL to outputMsat % 1_000uL
    val each = if (rest == 0uL) sat(whole) else "$whole.${rest.toString().padStart(3, '0').trimEnd('0')} sat"
    return if (rate.base == 0uL && rate.ppm == 0uL) "$each a note" else "${charge(rate)} + $each a note"
}

/** A fee a hub changed since it was agreed to: what it is on, what it is `now`, and what was `agreed`. */
data class Raise(val what: String, val now: String, val agreed: String)

/**
 * What a hub charging more than agreed changed, to approve: each of its
 * fees that differs, the others left unsaid. Approving takes none lower
 * than agreed.
 */
fun raises(raised: FeesRaised): List<Raise> {
    val (now, agreed) = raised.charged to raised.agreed
    fun said(fees: Fees) = paying(fees.spend, fees.outputMsat)
    return listOfNotNull(
        Raise("Paying", said(now), said(agreed)).takeIf { it.now != it.agreed },
        Raise("Holding a payment", charge(now.lock), charge(agreed.lock)).takeIf { now.lock != agreed.lock },
        Raise("Refunding one", charge(now.refund), charge(agreed.refund)).takeIf { now.refund != agreed.refund },
    )
}

/** Why a hub's fees are the owner's to approve, said wherever they are. */
const val RAISED_MEANS = "This hub raised its fees since your protection there started. Nothing is paid there until you approve them."

/** An optimization moves no amount away: show only its fee, not `0 sat`. */
internal fun optimizationCost(fee: ULong, state: State): String = when {
    state == State.FAILED -> "Not charged"
    fee == 0uL -> "Free"
    else -> "Fee ${sat(fee)}"
}

/**
 * The most a hub charges on paying `amount`, said before the notes it
 * takes are known: its rate on the amount, and its fee on as many notes
 * as the amount and what is left of it can be made in.
 */
fun payingUpTo(hub: Hub, amount: ULong): ULong {
    val notes = 2uL * (ULong.SIZE_BITS - amount.countLeadingZeroBits()).toULong()
    val made = (hub.feeOutputMsat * notes + 500uL) / 1_000uL
    val due = feeDue(amount, org.licash.core.Rate(hub.feeBase, hub.feePpm))
    return if (ULong.MAX_VALUE - due < made) ULong.MAX_VALUE else due + made
}

/** What protection under the mock authority is worth, said wherever one shows. */
const val MOCK = "Test only: protects nothing"

/**
 * A protection as a row says it: where it `stands`, in a word; whether it
 * is `on`, protecting now, `runs`, protecting or about to, or `failed`;
 * whether the hub's bitcoin is `held` behind it; how long it has `left` to
 * protect, and in how long it `ends`, the hub's bitcoin back to it, while
 * the chain's height is known.
 */
data class Cover(
    val stands: String,
    val on: Boolean,
    val runs: Boolean,
    val failed: Boolean,
    val held: Boolean,
    val left: String?,
    val ends: String?,
)

/** `contract`, in words, at the chain's `height`: 0 while unknown. */
fun cover(contract: Contract, height: Int, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): Cover {
    val state = contract.state
    val on = state == ContractState.Protecting
    val runs = on || state == ContractState.Opening || state == ContractState.Confirming
    val held = on || state == ContractState.Confirming || state == ContractState.Ending
    val known = height > 0
    return Cover(
        stands = when (state) {
            ContractState.Opening -> "Setting up"
            ContractState.Confirming -> "Confirming"
            // Keep the live status distinct from regtest's mock protection.
            ContractState.Protecting -> if (contract.mock) "Protecting" else "Live"
            ContractState.Ending -> "Ending"
            ContractState.Closed -> "Ended"
            is ContractState.Failed -> "Failed"
        },
        on = on,
        runs = runs,
        failed = state is ContractState.Failed,
        held = held,
        left = if (runs && known) "${span(contract.protectsUntil.toLong() - height, blockSecs)} left" else null,
        ends = if ((runs || held) && known) span(contract.closesAt.toLong() - height, blockSecs) else null,
    )
}

/**
 * A protection forced closed, or closed with its hub and awaiting the
 * fold that pays it, as its row says it: where it `stands`, in a
 * word, and what it waits for (`says`), at the chain's `height`, 0 while
 * unknown; whether it may still be given up, and whether it failed.
 */
data class Forcing(val stands: String, val says: String?, val revocable: Boolean, val failed: Boolean)

/** `recovery`, in words, at the chain's `height`. */
fun forcing(recovery: Recovery, height: Int, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): Forcing {
    val wait = recovery.nextAt?.takeIf { height > 0 }?.let { span(it.toLong() - height, blockSecs) }
    val revocable = recovery.stage == RecoveryStage.CLAIMED && !recovery.irrevocable
    val (stands, says) = when (recovery.stage) {
        RecoveryStage.FOLDING -> "Closing" to "Waiting for the hub's transaction: your notes and reserve come back on Bitcoin together"
        RecoveryStage.CLAIMED -> "Forcing closed" to wait?.let { "Final in $it: it can be given up until then" }
        RecoveryStage.REQUESTING -> "Requesting" to "Asking on Bitcoin for what the hub holds"
        RecoveryStage.REQUESTED -> "Requested" to (wait?.let { "The hub has $it to answer" } ?: "The hub may answer")
        RecoveryStage.TIMING_OUT -> "Paying back" to (wait?.let { "Back on Bitcoin in $it" } ?: "The hub did not answer")
        RecoveryStage.SWEEPING -> "Sweeping" to "To your Bitcoin, once in a block"
        RecoveryStage.DONE -> "Recovered" to "${sat(recovery.received ?: recovery.claimed)} back on Bitcoin"
        RecoveryStage.ANSWERED -> "Answered" to answered(recovery, height, blockSecs)
        RecoveryStage.LOST -> "Lost" to "Its bitcoin went elsewhere"
        RecoveryStage.ASSERTED -> "Hub proved" to (wait?.let { "${owed(recovery)}: paid in $it" } ?: "Being paid")
        RecoveryStage.CHALLENGING -> "Challenging" to "The hub's proof does not check: challenging it on Bitcoin"
        RecoveryStage.CHALLENGED -> "Challenged" to (wait?.let { "The hub has $it to answer the challenge" } ?: "Being paid")
        RecoveryStage.PAID -> "Paying back" to (wait?.let { "Back on Bitcoin in $it" } ?: "Paid on Bitcoin")
    }
    val failed = recovery.stage == RecoveryStage.LOST
    return Forcing(stands, says, revocable, failed)
}

/** What the hub says the claim is owed, in words. */
private fun owed(recovery: Recovery): String =
    recovery.corrected?.let { "The hub says ${sat(it)} is owed" } ?: "The hub answered"

/** A forced close the hub answered: its proof awaited, by its deadline. */
private fun answered(recovery: Recovery, height: Int, blockSecs: UInt): String {
    val deadline = recovery.deadline ?: return owed(recovery)
    val left = span(deadline.toLong() - height, blockSecs).takeIf { height > 0 }
    return left?.let { "${owed(recovery)}: it must prove so within $it, or you are paid your claim" }
        ?: "${owed(recovery)}: it must prove so, or you are paid your claim"
}

/** The steps of setting a protection up, the last its payment confirming. */
const val SETUP_STEPS = 7f

/**
 * How far setting a protection up is, in steps done of [SETUP_STEPS], and
 * what it waits on, in a word or two.
 */
fun setup(step: OpeningStep): Pair<Float, String> = when (step) {
    OpeningStep.Terms -> 0f to "Asking the hub"
    is OpeningStep.Preparing -> 0.75f to "Preparing it, a few minutes · ${ticking(step.seconds)}"
    OpeningStep.Choosing -> 1.5f to "The hub is choosing"
    OpeningStep.Uploading -> 3f to "Sending to the hub"
    OpeningStep.Signatures -> 4f to "Waiting for the hub"
    OpeningStep.Signing -> 5f to "Signing"
    is OpeningStep.Confirming -> 6f to if (step.confirmations == 0u) "Waiting for Bitcoin" else "Confirming"
}

/** `seconds` as a clock ticks them: `45 s`, `2 min 05 s`. */
fun ticking(seconds: ULong): String {
    val (m, s) = seconds.toLong() / 60 to seconds.toLong() % 60
    return if (m == 0L) "$s s" else "$m min ${s.toString().padStart(2, '0')} s"
}

/**
 * What setting a protection up sent and got so far, its speed and about
 * how long the rest takes at it: `12 MB of about 100 MB · 1.5 MB/s · about
 * 1 min left`. Its speed once a second has passed, the rest once some is;
 * neither while the wallet works out a step itself (`busy`), which its
 * seconds count too: what little went then said nothing of the network.
 */
fun transferred(t: Transfer, busy: Boolean = false): String {
    val parts = mutableListOf("${megabytes(t.bytes)} of about ${megabytes(t.expected)}")
    if (!busy && t.seconds > 0uL && t.bytes > 0uL) {
        val rate = t.bytes / t.seconds
        // Under 0.1 MB/s, as over Tor at times, in kB/s: not 0.0 MB/s.
        parts += if (rate < 100_000uL) "${rate / 1000uL} kB/s" else "${megabytes(rate)}/s"
        if (t.expected > t.bytes && rate > 0uL) {
            val left = ((t.expected - t.bytes) / rate).toLong()
            parts += when {
                left == 0L -> "almost done"
                left < 60 -> "about $left s left"
                left < 90 * 60 -> "about ${(left + 59) / 60} min left"
                else -> "about ${(left + 1800) / 3600} h left"
            }
        }
    }
    return parts.joinToString(" · ")
}

/** `bytes` in megabytes, to a tenth below 10: `0.4 MB`, `12 MB`. */
private fun megabytes(bytes: ULong): String {
    val mb = bytes.toDouble() / 1_000_000
    return if (mb < 10) String.format(Locale.US, "%.1f MB", mb) else "${mb.roundToLong()} MB"
}

/**
 * Whether `contract` shows outside advanced mode at `now`, in seconds
 * since 1970: not once ended, nor failed over a day ago.
 */
fun shown(contract: Contract, now: Long): Boolean = when (contract.state) {
    ContractState.Closed -> false
    is ContractState.Failed -> now - contract.createdAt < 86_400
    else -> true
}

/**
 * What a swap provider's or a gateway's fee rising since its quote means:
 * nothing was paid, and it is the owner's to accept at the new price.
 */
fun feeRose(agreed: ULong, asked: ULong): String =
    "The fee went up from ${sat(agreed)} to ${sat(asked)} since it was quoted. Nothing was paid: " +
        "see the new price to accept it."

/** `amount` sat in bitcoin, as a payment link says it: `0.00033000`. */
fun btc(amount: ULong): String =
    "%d.%08d".format(Locale.US, (amount / 100_000_000uL).toLong(), (amount % 100_000_000uL).toLong())

/** What a payment that finds too little to pay with is told to do about it. */
enum class Lack {
    /** Protect what is on Bitcoin: a contract is offered for it. */
    OFFER,

    /** Open what is on Bitcoin, held or on its way: it is not in the balance yet. */
    BITCOIN,

    /** Nothing is held at all: receive first. */
    NOTHING,

    /** Not to be told apart: the reason says it. */
    OTHER,
}

/**
 * Where a payment that failed sends its payer. A contract offered comes
 * first, as it always has, for `insufficient` or an empty balance, whatever
 * else went wrong. Then a balance too small (`insufficient`) with `bitcoin`
 * held or coming, notes held or not: adding it mends that. Otherwise only
 * `noHub` (no hub the code names holds the amount) with no notes at all is
 * told to look at bitcoin, or to receive: any other failure is said as it
 * is, and so is `noHub` with notes held elsewhere, which more bitcoin does
 * not mend.
 */
fun lack(insufficient: Boolean, noHub: Boolean, notes: ULong, bitcoin: ULong, offered: Boolean): Lack = when {
    offered && (insufficient || notes == 0uL) -> Lack.OFFER
    insufficient && bitcoin > 0uL -> Lack.BITCOIN
    notes != 0uL || !(insufficient || noHub) -> Lack.OTHER
    bitcoin > 0uL -> Lack.BITCOIN
    else -> Lack.NOTHING
}

/**
 * Whether bitcoin held can be added to the balance now: a coin on Bitcoin,
 * none being added already, and none paying for a protection being set up
 * (`opening`). Otherwise it is on its way, and only waited for.
 */
fun addable(balance: Balance, opening: Boolean): Boolean =
    balance.onchain > 0uL && balance.moving == 0uL && !opening

/**
 * What is on Bitcoin, paid to the wallet and not its own to keep, that is
 * not in the balance and that nothing is being done about: none offered
 * to protect it, no protection being set up, none of it being added. The
 * wallet's own change and payouts (`kept`) wait on purpose and are not
 * counted. Null if there is none.
 */
fun waiting(balance: Balance, offered: Boolean, opening: Boolean): ULong? {
    if (offered || opening || balance.moving > 0uL || balance.onchain <= balance.kept) return null
    return balance.onchain - balance.kept
}
