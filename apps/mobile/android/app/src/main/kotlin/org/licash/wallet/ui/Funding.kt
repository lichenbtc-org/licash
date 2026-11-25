package org.licash.wallet.ui

import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.core.Kind
import org.licash.wallet.Ui
import org.licash.wallet.sat
import org.licash.wallet.total

/** Where a first funding stands, in the order it goes. */
internal enum class FundingStage(val title: String) {
    WAITING("Waiting"),
    SEEN("Seen"),
    IN_BLOCK("In a block"),
    OPENING("Opening vault"),
    READY("Ready"),
}

/**
 * Whether the first funding is guided unasked: a hub chosen, and nothing
 * protected, held in notes or paid in or out with them yet. A wallet that
 * ever did more is never guided again.
 */
internal fun guiding(ui: Ui): Boolean =
    ui.hubs.isNotEmpty() && ui.contracts.isEmpty() && ui.paid.isEmpty() &&
        ui.balance.notes == 0uL && ui.balance.notesPending == 0uL && ui.balance.moving == 0uL &&
        ui.history.all { it.kind == Kind.ONCHAIN || it.kind == Kind.CONTRACT }

/**
 * Whether the guide asked for again at `since` (seconds since 1970) still
 * shows: with a hub, until a vault asked for since then protects (or did,
 * and ended). Never asked: no.
 */
internal fun guideAsked(ui: Ui, since: Long?): Boolean =
    since != null && ui.hubs.isNotEmpty() && ui.contracts.none {
        it.createdAt >= since &&
            (it.state == ContractState.Protecting || it.state == ContractState.Ending || it.state == ContractState.Closed)
    }

/**
 * The vault the guide asked for at `since` led to, if any yet: the newest
 * of those made since that is being set up or protects. None never asked.
 */
internal fun guidedVault(ui: Ui, since: Long?): Contract? = since?.let { from ->
    ui.contracts.filter { it.createdAt >= from }.sortedByDescending { it.createdAt }.firstOrNull {
        it.state == ContractState.Opening || it.state == ContractState.Confirming || it.state == ContractState.Protecting
    }
}

/**
 * Where the first funding of `ui` stands, guided since `since` if ever:
 * its vault being set up or protecting, once there is one, whatever is on
 * Bitcoin then; before, what was paid there.
 */
internal fun stage(ui: Ui, since: Long? = ui.guideSince): FundingStage {
    val vault = guidedVault(ui, since)
    return when {
        vault?.state == ContractState.Protecting -> FundingStage.READY
        ui.opening != null || vault != null -> FundingStage.OPENING
        ui.balance.onchain > ui.balance.kept -> FundingStage.IN_BLOCK
        ui.incoming.isNotEmpty() -> FundingStage.SEEN
        else -> FundingStage.WAITING
    }
}

/**
 * The mark of `step` once the funding is at `at`: done before it, to come
 * after it, and under way at it, but where nothing more is waited for: in
 * a block is enough, and ready is the end.
 */
internal fun markOf(step: FundingStage, at: FundingStage): Mark = when {
    step.ordinal < at.ordinal -> Mark.DONE
    step != at -> Mark.NEXT
    step == FundingStage.IN_BLOCK || step == FundingStage.READY -> Mark.DONE
    else -> Mark.NOW
}

/** What `stage` says under its title, once at it: `coming`, the sat on their way. */
internal fun stageSays(stage: FundingStage, coming: ULong): String = when (stage) {
    FundingStage.WAITING -> "Send bitcoin to this address, from any wallet or exchange."
    FundingStage.SEEN -> "${sat(coming)} on its way. One block is enough, about 10 minutes."
    FundingStage.IN_BLOCK -> "Your bitcoin is here. Open your vault to pay with it."
    FundingStage.OPENING -> "This takes a few minutes. You can leave the app."
    FundingStage.READY -> "Protected. Pay and receive in a tap."
}

/**
 * What a first deposit is asked to be, at least, in sat: one figure, the
 * same at every hub, above what the smallest vault costs with its reserve
 * at any of them but one nearly full. Not a quote: the vault's own page
 * says what it costs, before it is paid.
 */
internal const val FIRST_DEPOSIT = 50_000uL

/** How much to send, said over the address. */
internal val HOW_MUCH = "Send at least ${sat(FIRST_DEPOSIT)}. It opens your vault and covers its reserve and fees."

/**
 * How much more to send, folded under the address: her deposit sizes her
 * vault, the hub adding the rest of it, so more than she means to spend
 * leaves room to swap some out later, for more room to receive protected.
 */
internal const val DEPOSIT_MORE =
    "Send a bit more than you expect to spend. Your vault is sized to your deposit, so the extra leaves " +
        "room to swap some out later if you need more room to receive."

/** Said of bitcoin in a block that no vault is offered for. */
internal const val NO_VAULT_YET = "No vault fits it yet. Send more, or see it under your balance."

/** Home's card back to the guide, the funding at `at`. */
internal fun setupWords(at: FundingStage): StepWords = StepWords(
    "Set up your vault",
    when (at) {
        FundingStage.WAITING -> "Send bitcoin to open it. It protects what you hold."
        FundingStage.SEEN -> "Your bitcoin is on its way."
        FundingStage.IN_BLOCK -> "Your bitcoin arrived. Open your vault."
        FundingStage.OPENING -> "Opening. This takes a few minutes."
        FundingStage.READY -> "Your vault is ready."
    },
    "Continue",
)

/**
 * Whether the wallet is set up step by step, on screens of their own
 * ([Setup]): with no hub yet; with one and nothing held or done yet
 * ([guiding]); or guided since `since`, until its vault protects and that
 * was said once. A wallet in use that never asked is not.
 */
internal fun setupDue(ui: Ui, since: Long? = ui.guideSince): Boolean =
    ui.hubs.isEmpty() || guiding(ui) || guideAsked(ui, since) || (since != null && stage(ui, since) == FundingStage.READY)

/**
 * Whether there is anything to send with: a balance, or a vault open or
 * being opened, which one is on its way to. Else Send only says what is
 * missing.
 */
internal fun canSend(ui: Ui): Boolean = ui.balance.total > 0uL || hasVault(ui.contracts)

/** Whether a vault of `contracts` protects, or is being set up to. */
internal fun hasVault(contracts: List<Contract>): Boolean = contracts.any {
    it.state == ContractState.Opening || it.state == ContractState.Confirming || it.state == ContractState.Protecting
}

/** Said under what is paid into a hub with no vault there ([hasVault]): each time, as it is true each time. */
internal const val RECEIVED_UNPROTECTED = "No vault yet: what you receive is held by your hub, not protected."

/** Said where Send was asked for with nothing to send. */
internal const val NOTHING_TO_SEND = "Nothing to send yet. Fund your vault first."
