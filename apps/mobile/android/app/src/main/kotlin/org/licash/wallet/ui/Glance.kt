package org.licash.wallet.ui

import org.licash.core.Activity
import org.licash.core.ContractState
import org.licash.core.Kind
import org.licash.core.State
import org.licash.wallet.STALE_SECS
import org.licash.wallet.Ui
import org.licash.wallet.key
import org.licash.wallet.sat
import org.licash.wallet.unpaid

/**
 * What Home says is going on, in one line at most, and what a tap on it
 * opens: a payment under way before anything else, then protection being
 * set up, then what kept the last sync short. Nothing going on, nothing
 * said; catching up with Bitcoin is said by the connections ([links]).
 */
sealed interface Glance {
    val text: String

    /** One payment under way: itself, on a tap. `coming`, on Bitcoin, in no block yet. */
    data class One(override val text: String, val activity: Activity, val coming: Boolean) : Glance

    /** Several under way: the history, on a tap. */
    data class Many(val count: Int) : Glance {
        override val text: String get() = "$count in progress"
    }

    /** Protection being set up at `hub`: where the money is, on a tap. */
    data class Protecting(val hub: String) : Glance {
        override val text: String get() = "Setting up protection"
    }

    /** The last look for payments fell short: `reason`, on a tap. */
    data class Behind(val reason: String) : Glance {
        override val text: String get() = "Not up to date"
    }
}

/**
 * The line for `ui` at `now`, in seconds since 1970. Left out: a line under
 * way for longer than a week, stuck with nothing to wait for, and a deposit
 * whose payment on Bitcoin was never sent; the history keeps both.
 */
fun glance(ui: Ui, now: Long): Glance? {
    val coming = ui.incoming.map { Glance.One(doing(it, coming = true), it, coming = true) }
    val opened = ui.contracts.filter { it.state == ContractState.Opening }.map { it.id }.toSet()
    val under = ui.history
        .filter { it.state == State.PENDING && (it.at ?: now) > now - STALE_SECS && !unpaid(it, ui.under[it.key]) }
        // While the app opens a contract, those being opened show as Protecting, its steps on a tap.
        .filter { !(ui.opening != null && it.kind == Kind.CONTRACT && it.id in opened) }
        .map { Glance.One(doing(it, coming = false), it, coming = false) }
    val lines = coming + under
    val opening = ui.opening
    return when {
        lines.size == 1 -> lines.single()
        lines.size > 1 -> Glance.Many(lines.size)
        opening != null -> Glance.Protecting(opening)
        ui.problem != null -> Glance.Behind(ui.problem)
        else -> null
    }
}

/** What a payment under way is doing, with its amount: `Receiving 10,000 sat`. */
internal fun doing(activity: Activity, coming: Boolean): String = when {
    coming -> "Receiving ${sat(activity.amount)}"
    else -> when (activity.kind) {
        Kind.SENT, Kind.LIGHTNING, Kind.PAYOUT -> "Sending ${sat(activity.amount)}"
        Kind.RECEIVED, Kind.INVOICE, Kind.MOVED, Kind.FUNDED, Kind.ONCHAIN, Kind.CLOSED -> "Receiving ${sat(activity.amount)}"
        Kind.SWAP -> "Moving ${sat(activity.amount)}"
        Kind.CONTRACT -> "Setting up protection"
        Kind.OPTIMIZED -> "Optimizing notes"
    }
}
