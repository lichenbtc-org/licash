package org.licash.wallet

import org.licash.core.Activity
import org.licash.core.Contract
import org.licash.core.ContractExit
import org.licash.core.ContractState
import org.licash.core.ExitStep
import org.licash.core.Details
import org.licash.core.Kind
import org.licash.core.Recovery
import org.licash.core.RecoveryStage
import org.licash.core.State

/*
 * What keeps the app at work out of sight, and what it tells of then. A
 * payment under way finishes only while the app runs: a payout's coin is
 * claimed before its deadline, notes locked to the wallet are claimed, a
 * deposit is swapped in. Pure, apart from Android: the engine acts on it.
 */

/** How closely to watch what is under way. */
enum class Watch {
    /** Nothing under way. */
    NONE,

    /** Nothing urgent: a look now and then. */
    LATER,

    /** A payment the app finishes: kept at work, in a foreground service. */
    NOW,
}

/**
 * Lines under way for longer are stuck, their hub or provider gone: nothing
 * left to finish in time, and not to keep the app at work for ever.
 */
internal const val STALE_SECS = 7 * 24 * 3600L

/** A Lightning invoice asked is looked for so long after: perhaps paid out of sight. */
internal const val ASKED_SECS = 24 * 3600L

/** How closely to watch what `ui` shows under way, at `now` in seconds since the epoch. */
internal fun watchOf(ui: Ui, now: Long): Watch {
    val contracting = ui.opening != null || ui.balance.moving > 0uL || ui.paid.isNotEmpty() ||
        ui.contracts.any { it.state == ContractState.Opening || it.state == ContractState.Confirming }
    // Of unknown age: perhaps not stuck.
    val under = ui.history.filter { it.state == State.PENDING && (it.at ?: now) > now - STALE_SECS }
    val asked = ui.asked?.let { it > now - ASKED_SECS } ?: false
    // A forced close moves on with blocks, an hour or a day apart: a look now and then.
    val forcing = ui.recoveries.any { carriedOn(it) }
    // A proof posted: a challenge of it is answered within hours, not when a periodic job comes.
    val disputed = ui.recoveries.any { it.stage in DISPUTED }
    // Mailed to its payee within the hour unless collected at its hub: a look now and then does.
    val delivering = ui.onTheirWay > 0u
    // A contract protecting nears its end by blocks: its exit is looked at now and then.
    val protecting = ui.contracts.any { it.state == ContractState.Protecting }
    return when {
        contracting || disputed || under.any { it.kind != Kind.OPTIMIZED && !unpaid(it, ui.under[it.key]) } -> Watch.NOW
        under.isNotEmpty() || asked || forcing || delivering || protecting || ui.noteMaintenance -> Watch.LATER
        else -> Watch.NONE
    }
}

/**
 * Whether the app is behind Bitcoin: its light client downloading or
 * catching up, or the wallet's payments not looked for up to the blocks
 * its hubs index. Waiting for a hub to be chosen is not behind.
 */
internal fun behind(ui: Ui): Boolean {
    if (ui.chain.importing >= 0 || !ui.chain.synced) return true
    if (ui.hubs.isEmpty()) return false
    val scan = ui.scan ?: return true
    return scan.next <= scan.height
}

/** A forced close's stages from the hub's answer until paid: kept at work, the hub's proof to check and challenge in time. */
internal val DISPUTED = setOf(
    RecoveryStage.ANSWERED,
    RecoveryStage.ASSERTED,
    RecoveryStage.CHALLENGING,
    RecoveryStage.CHALLENGED,
)

/** A notification of a contract's exit or forced close: `key` told once, `urgent` asking her to act or stay online. */
internal data class ExitNotice(val key: String, val urgent: Boolean, val text: String)

/**
 * What to tell of the contracts' `exits` this round and of the forced
 * closes `recoveries` disputed or held back by their claim's fee: what the
 * exit did, what she must do, and when to keep the app online. Amounts
 * only, never a hub's name.
 */
internal fun exitNotices(exits: List<ContractExit>, recoveries: List<Recovery>): List<ExitNotice> {
    val told = exits.mapNotNull { e ->
        val key = "exit ${e.id} ${e.step}"
        val done = e.error == null
        when (e.step) {
            ExitStep.NEEDS_CONSENT -> ExitNotice(
                key,
                true,
                if (e.owed == 0uL) {
                    "Protection of ${sat(e.uncovered)} ends soon. Allow exits in Settings, Recovery safety, " +
                        "or pay those notes out yourself."
                } else {
                    "Protection of ${sat(e.uncovered)}, and ${sat(e.owed)} of payments owed to you that only " +
                        "forcing it closed recovers, ends soon. Allow exits in Settings, Recovery safety."
                },
            )
            ExitStep.NEVER_FITTED -> ExitNotice(
                key,
                true,
                "A contract ends sooner than your exit margin allows. Pay its notes out or force close it yourself.",
            )
            ExitStep.CASHING_OUT -> if (done) ExitNotice(key, false, "Paying out ${sat(e.uncovered)} to your address as protection ends") else null
            ExitStep.FOLDING -> if (done) ExitNotice(key, false, "Paid out, a contract closed with its hub: what was left of your notes and its reserve are on their way back") else null
            ExitStep.FORCE_CLOSING -> if (done) {
                ExitNotice(key, true, "Not paid out in time: a contract forced closed. Keep Licash online until it is done.")
            } else {
                ExitNotice("$key failed", true, "A contract ending could not be forced closed. Open Licash to try again.")
            }
            ExitStep.WAITING, ExitStep.COVERED, ExitStep.PAYING -> null
        }
    }
    val disputed = recoveries.filter { it.stage in DISPUTED }.map {
        ExitNotice(
            "dispute ${it.id}",
            true,
            "A hub answered a forced close. Keep Licash online with a connection until it is done, " +
                "so a false proof is challenged in time.",
        )
    }
    // Its claim's window short: told at once.
    val capped = recoveries.filter { it.feeCapped && carriedOn(it) }.map {
        ExitNotice(
            "fee ${it.id}",
            true,
            "A forced close needs a higher fee than its reserve pays to get its claim on Bitcoin. " +
                "Open Licash and allow it within the hour.",
        )
    }
    return told + disputed + capped
}

/**
 * Whether `contract` still has steps to carry on: being opened or
 * confirmed, or protecting while the notes she funded it with are not in
 * her balance yet, issued only once its funding is buried.
 */
internal fun carriedOn(contract: Contract): Boolean = when (contract.state) {
    ContractState.Opening, ContractState.Confirming -> true
    ContractState.Protecting -> contract.funded > 0uL && !contract.fundedReceived
    else -> false
}

/** Whether `recovery` still has steps to carry on. */
internal fun carriedOn(recovery: Recovery): Boolean =
    recovery.stage !in setOf(RecoveryStage.DONE, RecoveryStage.LOST)

/**
 * A deposit whose own payment on Bitcoin was never sent: it ends only once
 * its hub cancels it. Where it stands unread, perhaps sent.
 */
internal fun unpaid(activity: Activity, details: Details?): Boolean =
    activity.kind == Kind.MOVED && details is Details.Moved && details.payment == null

/** The lines finished since last looked, and those under way now, by [key]. */
internal data class Look(val finished: List<Activity>, val under: Set<String>)

/**
 * Compare `history` with the lines under way `before`, and with every line
 * `seen` last time if known. Never looked before (`before` null, as on the
 * first start of an app that did not keep them): none finished, so nothing
 * done long ago is told of as new. A Lightning invoice paid and its notes
 * taken at once, never seen under way, finished too if not `seen` before.
 */
internal fun look(history: List<Activity>, before: Set<String>?, seen: Set<String>? = null): Look {
    val under = history.filter { it.state == State.PENDING }.map { it.key }.toSet()
    val finished = before?.let { b ->
        history.filter {
            it.state != State.PENDING &&
                (it.key in b || (seen != null && it.kind == Kind.INVOICE && it.key !in seen))
        }
    }
    return Look(finished.orEmpty(), under)
}

/**
 * What to tell of a line finished, if anything, in a notification: amounts
 * only, never why one failed (it may name a hub or a transaction); a coin
 * moving in shows as its deposit.
 */
internal fun news(activity: Activity): String? =
    finishedWords(activity)?.let { if (activity.state == State.FAILED) "$it: open Licash for why" else it }

/**
 * What to tell, in sight, of a line that finished while the app was open
 * ([look]): said over the screen and felt, done or failed. Money in is
 * `received`, as money in from the mailbox is.
 */
internal fun settled(activity: Activity): Event? {
    val words = finishedWords(activity) ?: return null
    return when (activity.state) {
        State.PENDING -> null
        State.DONE -> Event(
            words,
            received = activity.amount.takeIf { activity.kind == Kind.INVOICE || activity.kind == Kind.MOVED },
            settled = true,
        )
        State.FAILED -> Event("$words: see History for why", settled = false)
    }
}

/** A line finished, in words, `failed` said of one that did: none for those not told of. */
private fun finishedWords(activity: Activity): String? {
    val amount = sat(activity.amount)
    return when (activity.state) {
        State.PENDING -> null
        State.DONE -> when (activity.kind) {
            Kind.SENT -> "Sent $amount"
            Kind.LIGHTNING -> "Paid $amount over Lightning"
            Kind.PAYOUT -> "Sent $amount on Bitcoin"
            Kind.SWAP -> "Moved $amount between hubs"
            Kind.MOVED -> "$amount added to your balance"
            Kind.INVOICE -> "Received $amount over Lightning"
            Kind.CONTRACT -> "Protection on"
            Kind.RECEIVED, Kind.FUNDED, Kind.ONCHAIN, Kind.OPTIMIZED, Kind.CLOSED -> null
        }
        State.FAILED -> when (activity.kind) {
            Kind.SENT -> "Sending $amount"
            Kind.LIGHTNING -> "Paying $amount over Lightning"
            Kind.PAYOUT -> "Sending $amount on Bitcoin"
            Kind.SWAP -> "Moving $amount between hubs"
            Kind.MOVED -> "Adding $amount to your balance"
            Kind.INVOICE -> "Receiving $amount over Lightning"
            Kind.CONTRACT -> "Setting up protection"
            Kind.RECEIVED, Kind.FUNDED, Kind.ONCHAIN, Kind.OPTIMIZED, Kind.CLOSED -> null
        }?.let { "$it failed" }
    }
}

/** Blocks before a payout's deadline to warn at: about two hours. */
internal const val WARN_BLOCKS = 12u

/**
 * The payouts whose provider sent its coin, not claimed yet within
 * [WARN_BLOCKS] of the block to claim it by: that block, by [key]. Past it,
 * the provider may take its coin back and the payout fails.
 */
internal fun nearing(ui: Ui): Map<String, UInt> = buildMap {
    for (activity in ui.history) {
        if (activity.kind != Kind.PAYOUT || activity.state != State.PENDING) continue
        val steps = (ui.under[activity.key] as? Details.Payout)?.progress ?: continue
        val by = steps.claimBy ?: continue
        val tip = maxOf(steps.tip, ui.chain.height.coerceAtLeast(0).toUInt())
        if (steps.coin != null && steps.claim == null && tip + WARN_BLOCKS >= by) put(activity.key, by)
    }
}
