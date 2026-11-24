package org.licash.wallet.ui

import android.net.Uri
import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.licash.core.Contract
import org.licash.core.ContractQuote
import org.licash.core.PaidContractQuote
import org.licash.core.ContractSafety
import org.licash.core.ContractInspection
import org.licash.core.ContractState
import org.licash.core.Network
import org.licash.core.OpeningStep
import org.licash.core.Recovery
import org.licash.core.RecoveryStage
import org.licash.core.blockSeconds
import org.licash.wallet.digits
import org.licash.wallet.sat
import org.licash.wallet.share
import org.licash.wallet.safetyStatus
import org.licash.wallet.checkInHours

/**
 * A protection at a hub, in a row: how much it covers, how long it has
 * left and where it stands, and what it is worth, never folded away. A
 * tap unfolds the rest. Once forced closed (`recovery`), where that
 * stands instead; in advanced mode, forcing it closed.
 */
@Composable
internal fun CoverRow(
    c: Contract,
    height: Int,
    network: Network,
    developer: Boolean,
    recovery: Recovery?,
    end: () -> Unit,
    forceClose: () -> Unit,
    giveUp: () -> Unit,
    allowFee: () -> Unit = {},
    safety: suspend () -> ContractSafety? = { null },
    inspection: suspend () -> ContractInspection? = { null },
    explorer: (String) -> String? = { null },
) {
    val colors = MaterialTheme.colorScheme
    val blockSecs = LocalBlockSeconds.current
    val cover = cover(c, height, blockSecs)
    val forcing = recovery?.let { forcing(it, height, blockSecs) }
    var open by rememberSaveable(c.id) { mutableStateOf(false) }
    var plan by remember(c.id) { mutableStateOf<ContractSafety?>(null) }
    var details by remember(c.id) { mutableStateOf<ContractInspection?>(null) }
    LaunchedEffect(open, c.id, c.state) {
        if (open) {
            if (recovery == null) plan = safety()
            details = inspection()
        }
    }
    // While it is set up: the step it is at.
    val step = c.step?.let { setup(it) }
    val tint = when {
        forcing != null -> if (forcing.failed) colors.error else colors.tertiary
        cover.failed -> colors.error
        cover.on -> colors.primary
        else -> colors.onSurfaceVariant
    }
    Column(Modifier.fillMaxWidth().testTag("contract")) {
        Row(
            Modifier.fillMaxWidth().clickable { open = !open }.heightIn(min = 56.dp).padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                if (cover.on) Glyphs.shield else Glyphs.shieldOff,
                contentDescription = null,
                Modifier.size(20.dp),
                tint = tint,
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text("Up to ${sat(c.cap)}", style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                (forcing?.says ?: step?.second ?: cover.left)?.let {
                    Text(
                        it,
                        modifier = if (step != null) Modifier.testTag("contract-step") else Modifier,
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.onSurfaceVariant,
                    )
                }
                // How fast what it sends and gets goes, while it does.
                c.transfer?.takeIf { forcing == null && step != null }?.let {
                    Text(
                        transferred(it, busy = c.step is OpeningStep.Preparing),
                        modifier = Modifier.testTag("contract-transfer"),
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.onSurfaceVariant,
                    )
                }
            }
            Text(
                forcing?.stands ?: cover.stands,
                Modifier.testTag("contract-state"),
                style = MaterialTheme.typography.labelLarge,
                color = tint,
            )
            Icon(
                if (open) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                contentDescription = if (open) "Hide" else "Show",
                tint = colors.onSurfaceVariant,
            )
        }
        // What it is worth, in sight while it runs: nobody is to count on what protects nothing.
        step?.let { (done, _) ->
            LinearProgressIndicator(
                progress = { done / SETUP_STEPS },
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            )
        }
        if (cover.runs && recovery == null) Worth(c.mock)
        AnimatedVisibility(open) {
            Column {
                if (recovery != null) {
                    Forced(recovery, developer, giveUp, allowFee, height)
                } else {
                    Unfolded(c, cover, developer, end, forceClose, plan, height, network, details?.holderReserve)
                }
                details?.let { ContractLayout(it, explorer) }
            }
        }
    }
}

/** One lock, split into its payout pool and reserves. The claim cap is a
 * limit inside the pool, never another slice of the same bitcoin. */
@Composable
private fun ContractLayout(info: ContractInspection, explorer: (String) -> String?) {
    val colors = MaterialTheme.colorScheme
    val context = LocalContext.current
    var technical by remember(info.address) { mutableStateOf(false) }
    Line("Locked on Bitcoin", sat(info.locked), tag = "contract-locked")
    Row(Modifier.fillMaxWidth().height(12.dp).testTag("contract-split")) {
        listOf(info.payoutPool to colors.primary, info.holderReserve to colors.tertiary, info.hubReserve to colors.secondary).forEach { (amount, color) ->
            if (amount > 0uL) Box(Modifier.weight(amount.toFloat()).fillMaxHeight().background(color))
        }
    }
    Line("Payout pool", sat(info.payoutPool))
    Line("Your reserve", sat(info.holderReserve))
    Line("Hub reserve", sat(info.hubReserve))
    // What the limit means, once asked.
    Row(verticalAlignment = Alignment.CenterVertically) {
        Line("Maximum claim", sat(info.claimLimit.toULong()), Modifier.weight(1f))
        Info(
            "Maximum claim",
            "The claim limit is inside the pool, not extra bitcoin. The recovery outcome decides how the pool and reserves are paid.",
            Modifier.testTag("claim-info"),
        )
    }
    explorer(info.address)?.let { link ->
        Entry("View contract on Bitcoin", tag = "contract-explorer", onClick = {
            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link))) }
        })
    }
    TextButton(onClick = { technical = !technical }, modifier = Modifier.testTag("contract-technical")) {
        Text(if (technical) "Hide technical details" else "Technical details")
    }
    if (technical) {
        Line("Type", "Native corrected")
        Line("Graph version", digits(info.graphVersion.toULong()))
        Line("Claim note limit", digits(info.noteLimit.toULong()))
        Line("Denominations (sat)", info.denominations.joinToString { digits(it) })
        Line("Keyset", info.keyset)
        Line("Hub program", info.program)
        Text(info.address, style = MaterialTheme.typography.bodySmall)
    }
}

/** A protection's row unfolded: what it covers and costs; closing it with its hub, forcing it closed in advanced mode. */
@Composable
private fun Unfolded(
    c: Contract,
    cover: Cover,
    developer: Boolean,
    end: () -> Unit,
    forceClose: () -> Unit,
    safety: ContractSafety?,
    height: Int,
    network: Network,
    // Her reserve, of its price, once its layout is read: apart, as it comes back.
    reserve: ULong? = null,
) {
    val state = c.state
    if (state is ContractState.Failed) Line("Why", state.reason)
    // Of what its hub holds, those ending first covering first.
    if (cover.on) Line("Covers now", sat(c.covers), tag = "covers")
    if (cover.ends != null) Line("Ends by itself in", cover.ends)
    if (!cover.failed) {
        // Until its layout is read, which takes a while, what was paid, the reserve in it.
        val known = reserve?.takeIf { it <= c.price }
        if (known == null) {
            Line("Paid", sat(c.price), tag = "contract-paid")
        } else {
            val cost = c.price - known
            FeeLine("Cost", cost, c.cap, value = sat(cost), breakdown = setupCost(c.cap, cost))
            if (known > 0uL) Line("Reserve, refundable", sat(known), tag = "contract-reserve")
        }
    }
    // What she funded of it herself: hers once issued, else its recovery claims it.
    if (c.funded > 0uL && !cover.failed) {
        Line("You funded", "${sat(c.funded)} · ${if (c.fundedReceived) "in your balance" else "on its way"}", tag = "contract-funded")
    }
    if (cover.held) {
        // Its status at a glance; the margin and what it means, when tapped.
        safety?.let {
            var planning by remember { mutableStateOf(false) }
            Line("Recovery planning", safetyStatus(it, height), tag = "planning", onClick = { planning = true })
            if (planning) {
                Sheet("Recovery planning", dismiss = { planning = false }) {
                    Line("Your exit margin", "${it.exitMargin} blocks")
                    Line("During a forced close", "Come online at least every ${checkInHours(it.challengeWindow, blockSeconds(network))} hours")
                    Say("Planning only. Start earlier for confirmation time. Stay online: the wallet checks the hub's proof and must challenge a bad one within ${it.challengeWindow} blocks.")
                }
            }
        }
    }
    if (developer) {
        Line("Paid from", "A coin of ${sat(c.paidFrom)}")
        Line("Protects until", "block ${c.protectsUntil}")
        Line("Closes at", "block ${c.closesAt}")
        c.funding?.let { Line("Funding", it.take(16) + "…") }
        Line("Id", c.id.take(16) + "…")
    }
    if (cover.held) {
        Row {
            TextButton(onClick = end, modifier = Modifier.testTag("close-contract")) { Text("Close") }
            // Its hub silent: what it holds claimed on Bitcoin, unilaterally.
            if (developer && cover.on) {
                TextButton(onClick = forceClose, modifier = Modifier.testTag("force-close")) {
                    Text("Force close", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

/**
 * A protection forced closed, unfolded: what it claimed, what stopped it,
 * giving it up while it may be, and allowing its claim a higher fee once
 * the reserve's falls short.
 */
@Composable
private fun Forced(r: Recovery, developer: Boolean, giveUp: () -> Unit, allowFee: () -> Unit, height: Int) {
    Line("Claimed", sat(r.claimed), tag = "recovery-claimed")
    r.corrected?.let {
        Line("Owed, the hub says", sat(it), tag = "recovery-corrected")
        Say("Before reserves and Bitcoin fees.")
    }
    r.received?.let { Line("Back on Bitcoin", sat(it), tag = "recovery-received") }
    if (r.stage == RecoveryStage.ANSWERED && height > 0) r.deadline?.let {
        Line("Hub's time left to prove", "${it.toLong().minus(height).coerceAtLeast(0)} blocks")
    }
    if (r.feeCapped) {
        Line("Stopped by", "The fee its reserve pays", tag = "recovery-fee-capped")
        if (developer) r.error?.let { Say(it) }
    } else {
        r.error?.let { Line("Stopped by", it) }
    }
    if (developer) {
        r.nextAt?.let { Line("Next step at", "block $it") }
        r.request?.let { Line("Request", it.take(16) + "…") }
        r.publication?.let { Line("Claim", it.take(16) + "…") }
        r.timeout?.let { Line("Payback", it.take(16) + "…") }
        r.response?.let { Line("Hub's answer", it.take(16) + "…") }
        r.deadline?.let { Line("Hub proves by", "block $it") }
        r.assertion?.let { Line("Hub's proof", it.take(16) + "…") }
        r.payout?.let { Line("Payout", it.take(16) + "…") }
        r.sweep?.let { Line("Sweep", it.take(16) + "…") }
        r.fold?.let { Line("Fold", it.take(16) + "…") }
    }
    if (r.feeCapped) {
        TextButton(onClick = allowFee, modifier = Modifier.testTag("allow-publication-fee")) { Text("Allow a higher fee") }
    }
    if (forcing(r, height).revocable) {
        TextButton(onClick = giveUp, modifier = Modifier.testTag("give-up-recovery")) { Text("Cancel closing") }
    }
}

/**
 * Let a forced close's claim pay up to a total fee she types, past what
 * its reserve pays, the rest from her coins on Bitcoin. Her claim must be
 * in a block within its window, about an hour, or what it claimed is lost.
 */
@Composable
internal fun AllowFeeSheet(recovery: Recovery?, busy: Boolean, allow: (ULong) -> Unit, dismiss: () -> Unit) {
    var amount by remember { mutableStateOf<Long?>(null) }
    Sheet("Allow a higher fee", dismiss) {
        if (recovery?.feeCapped == true) {
            Say(
                "Fees on Bitcoin are higher than this contract's reserve pays for publishing its claim. " +
                    "Allow a total fee for it: what the reserve does not cover comes from your coins on Bitcoin.",
            )
            Say("It must be in a block soon, within about an hour, or the close fails and the notes it claimed are lost.")
            AmountField(amount, { amount = it })
            if (busy) Say("Waiting for the contract sync under way to finish first.")
            BigButton(
                if (busy) "Allowing…" else "Allow",
                Modifier.fillMaxWidth().testTag("allow-publication-fee-confirm"),
                enabled = !busy && amount != null,
                onClick = { amount?.let { allow(it.toULong()) } },
            )
            TextButton(onClick = dismiss, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
        } else {
            Say("Its claim no longer waits for a higher fee.")
            BigButton("Done", Modifier.fillMaxWidth(), onClick = dismiss)
        }
    }
}

/** Cancel only this unsigned attempt, not the contract or the right to try again. */
@Composable
internal fun GiveUpSheet(recovery: Recovery?, busy: Boolean, confirm: () -> Unit, dismiss: () -> Unit) {
    val allowed = recovery?.let { forcing(it, 0).revocable } == true
    Sheet(if (allowed) "Cancel closing?" else "Closing changed", dismiss) {
        if (allowed && recovery != null) {
            Line("Back to wallet", sat(recovery.claimed))
            Line("Notes", digits(recovery.notes.toULong()))
            Say("Stops this attempt and releases its reserved notes. It does not close the contract or recover Bitcoin.")
            Say("You can force close again while the contract allows it. An offline hub still cannot pay you.")
            if (busy) Say("Waiting for the contract sync under way to finish first: over Tor, this can take a few minutes.")
            BigButton(
                if (busy) "Canceling…" else "Stop this attempt",
                Modifier.fillMaxWidth().testTag("give-up-recovery-confirm"),
                enabled = !busy,
                danger = true,
                onClick = confirm,
            )
            TextButton(onClick = dismiss, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Keep closing") }
        } else {
            Say("This attempt has moved on. It can no longer be canceled here.")
            BigButton("Done", Modifier.fillMaxWidth(), onClick = dismiss)
        }
    }
}

/**
 * What forcing a protection closed does, before it is done: for a hub that
 * stopped answering only, and final once its request is signed. With the
 * `shortfall` of her coins for a challenge's fee, if she holds none.
 */
@Composable
internal fun ForceSheet(
    c: Contract,
    held: ULong,
    shortfall: ULong?,
    busy: Boolean,
    error: String?,
    wait: Wait,
    force: () -> Unit,
    dismiss: () -> Unit,
) {
    val claimed = if (held < c.cap) held else c.cap
    Sheet("Force close", dismiss) {
        Say(
            "Only if ${name(c.hub)} stopped answering: while it answers, close with it instead, which pays the same. " +
                "Your ${sat(claimed)} there leave your balance and are claimed on Bitcoin, " +
                "back on Bitcoin in a few days if the hub stays silent. Its fees come from your reserve in the contract.",
        )
        if (shortfall != null) {
            Say(
                "Keep a coin of at least ${sat(shortfall)} on Bitcoin besides your others first: should the hub " +
                    "prove falsely, your challenge's fee comes from it, set aside until the close is over. " +
                    "Without it, notes of yours are cashed out for it while you are online, " +
                    "else a challenge pays what your coins hold, and may come too late.",
            )
        }
        Say("Once its request is signed, it cannot be canceled, even before it is on Bitcoin.")
        BigButton(
            if (busy) "Forcing closed…" else "Force close",
            Modifier.fillMaxWidth().testTag("force-close-confirm"),
            danger = true,
            busy = busy,
        ) { force() }
        Waited(wait)
        error?.let { Problem(it) }
    }
}

/**
 * That a protection is worth nothing, under the mock authority, said where
 * one shows and before one is paid for. A genuine one this app recovers
 * from by itself: the hub proves, the holder only checks.
 */
@Composable
internal fun Worth(mock: Boolean) {
    if (!mock) return
    Text(
        MOCK,
        modifier = Modifier.padding(bottom = 8.dp).testTag("worth"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error,
    )
}

/**
 * What a hub of one contract asks of the coin that pays for it besides its
 * price, when the coin is cashed out to pay it: her part of the contract,
 * which the hub issues back to her as notes.
 */
internal const val FIXED_PART = 1_000uL

/** How long opening a contract takes: a tester's took under four minutes, then its funding confirms. */
internal const val SETUP_TAKES = "A few minutes, then a confirmation on Bitcoin"

/**
 * What protecting at a hub covers, lasts and costs, before it is paid:
 * to pay it, or to get a coin on Bitcoin that pays it first. A coin is spent
 * whole: it pays the price, and the rest of it is her part of the contract.
 */
@Composable
internal fun ProtectSheet(
    q: ContractQuote,
    hub: String,
    open: () -> Unit,
    payWithNotes: () -> Unit,
    cashOutFirst: () -> Unit,
    dismiss: () -> Unit,
) {
    val download = android.text.format.Formatter.formatShortFileSize(LocalContext.current, q.download.toLong())
    Sheet("Protect at $hub", dismiss) {
        Line("Covers up to", sat(q.cap), tag = "quote-cap")
        Line("For", span(q.protectsFor.toLong(), LocalBlockSeconds.current), tag = "quote-for")
        FeeLine("Cost", q.price, q.cap, tag = "quote-price", value = sat(q.price), breakdown = setupCost(q.cap, q.price))
        Line("Takes", "$SETUP_TAKES · $download")
        Worth(q.mock)
        Spacer(Modifier.height(8.dp))
        val coin = q.coin
        if (coin != null) {
            // The coin is spent whole: the price, and the rest is hers, issued back as notes.
            val part = if (coin > q.price) coin - q.price else 0uL
            Line("Paid with", "${sat(coin)} on Bitcoin", tag = "contract-paid-with")
            Line("Into your balance", sat(part), tag = "contract-funded")
            BigButton(
                "Protect for ${sat(q.price)}",
                Modifier.fillMaxWidth().testTag("protect"),
            ) { open() }
        } else {
            Say("Paid from one coin on Bitcoin you hold, spent whole, and none you hold pays for it.")
            Say(PAY_WITH_NOTES)
            BigButton("Pay ${sat(q.price + FIXED_PART)} from notes", Modifier.fillMaxWidth().testTag("pay-with-notes")) {
                payWithNotes()
            }
            Spacer(Modifier.height(8.dp))
            Say("Or cash out to yourself first, then protect.")
            BigButton("Cash out ${sat(q.price + FIXED_PART)}", Modifier.fillMaxWidth().testTag("cash-out-first"), quiet = true) {
                cashOutFirst()
            }
        }
    }
}

/** What a protection paid for with notes waits for: its coin of `value` sat on Bitcoin. */
internal fun paidWaits(value: ULong): String = "Paid with notes: set up once its coin of ${sat(value)} is on Bitcoin"

/**
 * A protection paid for with notes, before it is paid: a swap provider sends
 * this wallet a coin of its price and her small part for notes at the hub,
 * and protection is set up on that coin once it confirms, as on any. Should
 * it not be, the coin stays hers. What the coin costs on top, and through
 * whom.
 */
@Composable
internal fun PaidSheet(q: PaidContractQuote, hub: String, busy: Boolean, pay: () -> Unit, dismiss: () -> Unit) {
    val total = q.value + q.payout.fee
    Sheet("Protect at $hub", dismiss) {
        Line("Covers up to", sat(q.cap), tag = "paid-cap")
        Line("Coin to this wallet", sat(q.value), tag = "paid-coin")
        Line("Of it into your balance", sat(q.funded), tag = "paid-funded")
        Line("Its fees", sat(q.payout.fee), tag = "paid-fees")
        Line("Through", q.payout.providerName ?: q.payout.provider, tag = "paid-provider")
        Say(
            "Paid from your notes here. Protection is set up on the coin once it confirms, " +
                "${SETUP_TAKES.replaceFirstChar { it.lowercase() }}. Should it not be, the coin stays yours.",
        )
        BigButton(
            if (busy) "Paying…" else "Pay ${sat(total)}",
            Modifier.fillMaxWidth().testTag("pay-paid"),
            busy = busy,
        ) { pay() }
    }
}

/**
 * Closing a protection early with its hub: the hub folds it with you, and
 * what you hold there comes to you on Bitcoin, up to what it covers, with
 * your reserve. Never without what it covers: a protection that ends
 * leaves nothing unclaimed that it could have paid. What is held beyond
 * its cap stays at the hub, unprotected, and cashing it out first is what
 * takes it too.
 */
@Composable
internal fun EndSheet(
    c: Contract,
    height: Int,
    held: ULong,
    busy: Boolean,
    error: String?,
    wait: Wait,
    cashOut: () -> Unit,
    close: () -> Unit,
    dismiss: () -> Unit,
) {
    val ends = cover(c, height, LocalBlockSeconds.current).ends
    val claimed = if (held < c.cap) held else c.cap
    Sheet("Close with ${name(c.hub)}", dismiss) {
        if (claimed > 0uL) {
            Say(
                "${name(c.hub)} pays you what you hold there, up to ${sat(c.cap)}, and your part of the protection's cost " +
                    "comes back with it: about ${sat(claimed)} on Bitcoin, in one transaction. It protects nothing from then on.",
            )
        } else {
            Say(
                "You hold nothing at ${name(c.hub)}: closing brings your part of the protection's cost back on Bitcoin, " +
                    "and it protects nothing from then on.",
            )
        }
        if (held > claimed) {
            Say(
                "${sat(held - claimed)} of what you hold there is beyond what it covers: it stays at ${name(c.hub)}, " +
                    "unprotected. Cash out first to take it too.",
            )
        }
        if (ends != null) Say("Otherwise it ends by itself in $ends.")
        BigButton(
            if (busy) "Closing…" else "Close and receive",
            Modifier.fillMaxWidth().testTag("end-close"),
            busy = busy,
        ) { close() }
        if (held > 0uL) {
            Spacer(Modifier.height(12.dp))
            BigButton(
                "Cash out ${sat(held)} first",
                Modifier.fillMaxWidth().testTag("end-cash-out"),
                enabled = !busy,
                quiet = true,
            ) { cashOut() }
        }
        Waited(wait)
        error?.let { Problem(it) }
    }
}
