package org.licash.wallet.ui

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.licash.core.Activity
import org.licash.core.Details
import org.licash.core.Kind
import org.licash.core.Linking
import org.licash.core.LockStep
import org.licash.core.NoteLine
import org.licash.core.NotesOf
import org.licash.core.NotesPaid
import org.licash.core.Onchain
import org.licash.core.PayoutSteps
import org.licash.core.State
import org.licash.wallet.AppLog
import org.licash.wallet.Engine
import org.licash.wallet.Ui
import org.licash.wallet.at
import org.licash.wallet.digits
import org.licash.wallet.explain
import org.licash.wallet.host
import org.licash.wallet.key
import org.licash.wallet.sat
import org.licash.wallet.share

/** A line of the history on its own: what it cost and where it stands. */
@Composable
fun ActivityDetails(engine: Engine, ui: Ui, shown: Activity, back: () -> Unit) {
    val context = LocalContext.current
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    // As it stands now: the history changes while shown.
    val coming = ui.incoming.find { it.id == shown.id }
    val activity = coming ?: ui.history.find { it.id == shown.id && it.kind == shown.kind } ?: shown
    var details by remember { mutableStateOf<Details?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var unopened by remember { mutableStateOf(false) }
    var notes by remember { mutableStateOf<NotesOf?>(null) }
    // A contract's reserve: what of its price comes back.
    var reserve by remember { mutableStateOf<ULong?>(null) }
    LaunchedEffect(activity, ui.scan?.next) {
        engine.details(activity)
            .onSuccess { details = it; error = null }
            .onFailure { error = explain(it) }
        if (activity.kind == Kind.CONTRACT) reserve = engine.contractInspection(activity.id).getOrNull()?.holderReserve
        engine.notesOf(activity).onSuccess { notes = it }.onFailure { AppLog.warn("its notes", it) }
    }
    val copy: (String, String) -> Unit = { label, text ->
        scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText(label, text))) }
    }
    val tx = when (val d = details) {
        is Details.Moved -> d.payment
        is Details.Coin -> d.tx
        else -> null
    }
    // A payout's claim pays the address: else the provider's coin, as soon
    // as the provider tells of it.
    val txid = tx?.txid ?: (details as? Details.Payout)?.progress?.let { it.claim ?: it.coin }
        ?: (details as? Details.Contract)?.funding
    val view: (String) -> Unit = { link ->
        unopened = false
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link))) }
            .onFailure {
                AppLog.warn("opening $link", it)
                unopened = true
            }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        TopBar(title(activity, coming != null), back)
        val sign = when {
            activity.kind == Kind.SWAP -> ""
            paid(activity) -> "−"
            else -> "+"
        }
        Text(
            if (activity.kind == Kind.OPTIMIZED) optimizationCost(activity.fee, activity.state)
            else "$sign${digits(activity.amount)} sat",
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp).testTag("amount"),
            style = Heading,
        )
        Text(
            status(activity, coming != null, details, LocalBlockSeconds.current),
            modifier = Modifier.padding(horizontal = 4.dp).testTag("state"),
            style = MaterialTheme.typography.bodyLarge,
            color = if (activity.state == State.FAILED) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
        // What it needs of its owner, never folded away.
        (details as? Details.Payout)?.let { needs(activity, it.progress, ui.developer, LocalBlockSeconds.current) }?.let {
            Text(
                it,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp).testTag("needs"),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Summary(activity, details, tx, ui.developer, txid?.let { engine.explorerLink(it) }?.let { { view(it) } }, ui.contacts[activity.key], reserve)
        // Who paid, as they proved to this wallet alone: a contact, or one to keep.
        activity.from?.takeIf { activity.kind == Kind.RECEIVED }?.let { SaveContact(engine, it, payer = true) }
        if (unopened) {
            Text(
                "No app here opens web links.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        val payout = details as? Details.Payout
        // How its notes moved: for those who asked to see notes.
        val flow = notes?.takeIf { ui.developer }?.let(::flowOf)
        if (payout != null || flow != null || ui.developer) {
            Spacer(Modifier.height(8.dp))
            More(modifier = Modifier.testTag("more")) {
                payout?.let { PayoutTimeline(activity, it, ui.developer, engine::explorerLink, view) }
                flow?.let { Group("") { NotesFlow(activity, it) } }
                if (ui.developer) {
                    Technical(activity, details, copy)
                    notes?.takeIf { it.spent.isNotEmpty() || it.made.isNotEmpty() }?.let {
                        NotesGroup(activity, it, copy)
                    }
                }
            }
        }
        Spacer(Modifier.height(48.dp))
    }
}

internal fun title(activity: Activity, coming: Boolean): String = when {
    coming && activity.kind != Kind.CLOSED -> "Arriving"
    else -> when (activity.kind) {
        Kind.SENT -> "Sent"
        Kind.RECEIVED -> "Received"
        Kind.MOVED -> "From Bitcoin"
        Kind.FUNDED -> "From Bitcoin, protected"
        Kind.ONCHAIN -> "On Bitcoin"
        Kind.LIGHTNING -> "Paid over Lightning"
        Kind.INVOICE -> "Received over Lightning"
        Kind.PAYOUT -> "Sent on Bitcoin"
        Kind.CONTRACT -> "Protection"
        Kind.SWAP -> "Moved"
        Kind.OPTIMIZED -> "Optimized notes"
        Kind.CLOSED -> "Protection closed"
    }
}

/** What her part of a coin a contract took is, said on its line. */
internal const val FUNDED_MEANS = "The rest of your coin on Bitcoin, after the cost and reserve of its " +
    "protection: added to your balance once it confirmed. The reserve comes back when it ends."

/** Of a contract's `price`, what it cost: the rest, its `reserve`, comes back. */
internal fun opened(price: ULong, reserve: ULong): ULong = price - minOf(price, reserve)

/** Whether it paid out, rather than in. */
internal fun paid(activity: Activity): Boolean =
    activity.kind == Kind.SENT || activity.kind == Kind.LIGHTNING || activity.kind == Kind.PAYOUT ||
        activity.kind == Kind.CONTRACT || activity.kind == Kind.OPTIMIZED

/** What a wait for a block is, said the same way wherever one shows. */
private const val CONFIRMING = "Confirming, about 10 min"

/**
 * Where it stands, in a few words: what a newcomer asks of a payment, not
 * how it is made. Never a block's height, nor who makes it happen.
 */
internal fun status(
    activity: Activity,
    coming: Boolean,
    details: Details?,
    blockSecs: UInt = BITCOIN_BLOCK_SECONDS,
): String = when {
    coming -> CONFIRMING
    activity.state == State.FAILED && details is Details.Payout -> when (details.progress.lock) {
        LockStep.LOCKED -> "${activity.detail}. Your money comes back by itself."
        else -> "${activity.detail}. Nothing was taken."
    }
    activity.state == State.FAILED && details is Details.Swap -> when (details.lock) {
        null -> "${activity.detail}. Nothing was taken."
        else -> "${activity.detail}. Your money comes back by itself."
    }
    // Given up short of signing its funding: nothing paid.
    activity.state == State.FAILED && details is Details.Contract && details.funding == null ->
        "${activity.detail}. Nothing was taken."
    activity.state == State.FAILED -> activity.detail
    // A swap provider declined or failed it: its lock returns the sats once expired.
    activity.state == State.PENDING && details is Details.Lightning && details.provider != null &&
        details.failure != null -> notPaid(details.refundBlocks, blockSecs)
    else -> when (details) {
        is Details.Payout -> when {
            activity.state == State.DONE -> "Arrived"
            details.progress.claim != null -> "Sent. $CONFIRMING"
            else -> "On its way"
        }
        is Details.Swap -> if (activity.state == State.DONE) "Done" else "Moving"
        is Details.Moved -> moving(activity, details, blockSecs)
        is Details.Coin -> if (details.moving != null) "Being added to your balance" else "Yours, on Bitcoin"
        is Details.Invoice -> if (activity.state == State.DONE) "In your balance" else "Paid, arriving"
        is Details.Contract -> when {
            activity.state == State.DONE -> "Set up"
            details.funding == null -> "Being set up"
            else -> CONFIRMING
        }
        else -> when {
            activity.state == State.PENDING -> "Under way"
            paid(activity) -> "Paid"
            else -> "Received"
        }
    }
}

/** Where bitcoin coming into the balance stands: the blocks its hub waits for, as time. */
private fun moving(activity: Activity, move: Details.Moved, blockSecs: UInt): String {
    if (activity.state == State.DONE) return "In your balance"
    val paid = move.payment ?: return "Waiting for its payment"
    val depth = (move.depth ?: 1u).toInt()
    val left = depth - paid.confirmations.toInt()
    return if (left > 0) "Confirming, about ${minutes(left.toLong(), blockSecs)} min" else "Almost there"
}

/**
 * What a payout under way needs of its owner, if anything: the app open
 * before its time runs out, this phone finishing it. In advanced mode,
 * the block it runs out at too.
 */
internal fun needs(
    activity: Activity,
    p: PayoutSteps,
    developer: Boolean,
    blockSecs: UInt = BITCOIN_BLOCK_SECONDS,
): String? {
    val by = p.claimBy ?: return null
    if (activity.state != State.PENDING || p.claim != null) return null
    val block = if (developer) " (block $by)" else ""
    return when {
        p.tip == 0u -> "Keep the app open to finish it$block"
        p.tip > by -> "Too late to finish$block: your money comes back by itself"
        else -> "Open the app within ${span((by - p.tip).toLong(), blockSecs)} to finish it$block"
    }
}

/** The confirmations of a transaction in block `height`, at `tip`. */
private fun depthOf(height: UInt?, tip: UInt): Int =
    height?.let { if (tip >= it) (tip - it + 1u).toInt() else 0 } ?: 0

/**
 * Each step of a payout: its notes locked for the provider, the provider's
 * coin sent and confirmed, the coin claimed paying the address, and that
 * confirmed. Named plainly, how each is made told in advanced mode only.
 * A transaction known links to the block explorer.
 */
@Composable
private fun PayoutTimeline(
    activity: Activity,
    payout: Details.Payout,
    developer: Boolean,
    link: (String) -> String?,
    open: (String) -> Unit,
) {
    val p = payout.progress
    // Read once: a record's fields are mutable, so not smart cast.
    val coin = p.coin
    val coinHeight = p.coinHeight
    val claim = p.claim
    val claimHeight = p.claimHeight
    val failed = activity.state == State.FAILED
    val done = activity.state == State.DONE
    val view = { txid: String? ->
        txid?.let(link)?.let { url -> "View" to { open(url) } }
    }
    val coinDepth = depthOf(coinHeight, p.tip)
    val coinConfirmed = claim != null || (coinHeight != null && coinDepth >= p.depth.toInt())
    val hub = host(payout.hub)
    // How it is made, step by step, is for advanced mode: else, that it is.
    fun said(detail: String?): String? = detail.takeIf { developer }
    Group("") {
        val (lockMark, lockDetail) = when (p.lock) {
            null -> (if (failed) Mark.FAILED else Mark.NOW) to "Locking them at $hub"
            LockStep.REQUESTED -> (if (failed) Mark.FAILED else Mark.NOW) to "Waiting for $hub to certify the lock"
            LockStep.LOCKED -> Mark.DONE to "At $hub. The provider gets them only once you claim its coin; " +
                "else they come back to you after block ${p.lockExpiry}."
            LockStep.PAID -> Mark.DONE to "Paid to the provider at $hub"
            LockStep.REFUNDED -> Mark.FAILED to "Given back to you at $hub"
            LockStep.ABANDONED -> Mark.FAILED to "Never made: your notes stayed yours"
        }
        Step(lockMark, "Set aside", said(lockDetail), tag = "step locked")
        Step(
            mark = when {
                coin != null -> Mark.DONE
                !failed && p.lock == LockStep.LOCKED -> Mark.NOW
                else -> Mark.NEXT
            },
            title = "Bitcoin ready",
            detail = said(
                coin?.let { id ->
                    "Transaction ${short(id)}" + (p.timeout?.let { ", yours to claim before block $it" } ?: "")
                },
            ),
            action = view(coin),
            tag = "step coin",
        )
        Step(
            mark = when {
                coinConfirmed -> Mark.DONE
                failed || coin == null -> Mark.NEXT
                else -> Mark.NOW
            },
            title = "Confirmed",
            detail = when {
                coinConfirmed -> said(coinHeight?.let { "In block $it" })
                coinHeight != null -> said("$coinDepth of ${p.depth} confirmations")
                coin != null && !failed -> "About 10 min"
                else -> null
            },
            tag = "step coin-confirmed",
        )
        Step(
            mark = when {
                claim != null -> Mark.DONE
                failed || !coinConfirmed -> Mark.NEXT
                else -> Mark.NOW
            },
            title = "Sent to the address",
            detail = said(
                when {
                    claim != null -> "Transaction ${short(claim)}, broadcast by this phone"
                    coinConfirmed && !failed -> "Claiming it"
                    else -> null
                },
            ),
            action = view(claim),
            tag = "step claimed",
        )
        Step(
            mark = when {
                done -> Mark.DONE
                failed || claim == null -> Mark.NEXT
                else -> Mark.NOW
            },
            title = "Arrived",
            detail = when {
                done -> said(claimHeight?.let { "In block $it" })
                claimHeight != null -> said("${depthOf(claimHeight, p.tip)} of ${p.depth} confirmations")
                claim != null && !failed -> "About 10 min"
                else -> null
            },
            last = true,
            tag = "step arrived",
        )
    }
}

/**
 * What it cost, where it went or came from, and when: its amount is above.
 * Who made it happen is for advanced mode; `view` shows it on Bitcoin,
 * if it is there.
 */
@Composable
private fun Summary(
    activity: Activity,
    details: Details?,
    tx: Onchain?,
    developer: Boolean,
    view: (() -> Unit)?,
    contact: String? = null,
    reserve: ULong? = null,
) {
    val failed = activity.state == State.FAILED
    Group("") {
        // What it cost on top, and what it came to: nothing of one that failed.
        val costs = @Composable { breakdown: FeeBreakdown ->
            if (!failed) {
                FeeLine("Fee", activity.fee, activity.amount, breakdown = breakdown)
                if (activity.fee > 0uL) Line("Total", sat(activity.amount + activity.fee), tag = "total")
            }
        }
        // A contract's money back, a coin on Bitcoin: from where, not from whom.
        if (activity.kind == Kind.CLOSED) {
            Line("From", "Protection at ${name(activity.detail)}", tag = "closed-from")
            Line("To", "Your Bitcoin", tag = "closed-to")
        } else when (details) {
            is Details.Moved -> {
                // Taken by a swap provider, or by the hub itself before hubs left that to providers.
                val (who, tag) = if (details.provider != null) "Provider" to "fee-provider" else "Hub" to "fee-hub"
                FeeLine("$who fee", activity.fee, activity.amount, tag = tag, value = sat(activity.fee), breakdown = recordedFee(activity.amount, activity.fee, listOf(who to activity.fee)))
                details.payment?.fee?.let {
                    FeeLine("Network fee", it, activity.amount, tag = "fee-network", value = sat(it), breakdown = FeeBreakdown(activity.amount, it, listOf("Bitcoin network" to it), explanation = "Fee of the full funding transaction. It is not a per-deposit allocation or a hub fee."))
                }
                Line("At", name(details.hub))
                details.provider?.let { Line("Through", host(it), tag = "through") }
            }
            is Details.Coin -> Line("From", if (details.change) "Your own change" else "Bitcoin")
            is Details.Lightning -> {
                if (failed) {
                    FeeLine("Refund fee", activity.fee, activity.amount, value = sat(activity.fee), breakdown = recordedFee(activity.amount, activity.fee))
                } else {
                    costs(recordedFee(activity.amount, activity.fee))
                }
                Line("From", name(details.hub))
                details.provider?.let { Line("Through", host(it), tag = "through") }
            }
            is Details.Payout -> {
                costs(payoutFee(activity.amount, activity.fee, details.lockFee, details.providerFee, details.claimFee, quoted = false))
                Line("To", short(details.address), tag = "to")
                Line("From", name(details.hub))
                if (developer) Line("Through", host(details.provider))
            }
            is Details.Invoice -> {
                details.asks?.takeIf { it > activity.amount }?.let {
                    FeeLine("Payer's fee", it - activity.amount, activity.amount, value = sat(it - activity.amount), breakdown = recordedFee(activity.amount, it - activity.amount))
                }
                Line("At", name(details.hub))
            }
            is Details.Contract -> {
                reserve?.let {
                    Line("Cost", sat(opened(activity.amount, it)), tag = "contract-cost")
                    Line("Reserve, refundable", sat(it), tag = "contract-reserve")
                }
                Line("Paid from", "Your Bitcoin", tag = "paid-from")
                Line("At", name(details.hub), tag = "at")
            }
            is Details.Swap -> {
                costs(swapFee(activity.amount, activity.fee, details.lockFee, details.providerFee))
                Line("From", name(details.from))
                Line("To", name(details.to))
                if (developer) Line("Through", host(details.provider))
            }
            else -> if (activity.kind == Kind.SENT) {
                costs(recordedFee(activity.amount, activity.fee))
                (details as? Details.Notes)?.let { Line("From", name(it.hub)) }
            } else {
                (details as? Details.Notes)?.let { Line("At", name(it.hub)) }
                if (activity.kind == Kind.FUNDED) Say(FUNDED_MEANS)
                if (activity.kind == Kind.OPTIMIZED) Say("Smaller notes leave room for receiving and help recovery fit its note limit.")
            }
        }
        // Whom it was paid to: a contact. Who paid is said below, as proved.
        contact?.takeIf { activity.kind == Kind.SENT }?.let { Line("To", it, tag = "contact") }
        val noted = activity.kind == Kind.SENT || activity.kind == Kind.RECEIVED
        activity.memo?.let { Line(if (noted) "Note" else "Memo", it, tag = "memo") }
        activity.code?.let {
            Line("To", it, tag = "code")
            if (activity.fee > 0uL) FeeLine("Fee to move it to your balance", activity.fee, activity.amount)
        }
        if (developer) tx?.let { Line("Confirmations", confirmations(it, details)) }
        activity.at?.let { Line("Date", at(it), tag = "date") }
        view?.let {
            Divider()
            Entry("View on Bitcoin", modifier = Modifier.testTag("explorer"), onClick = it)
        }
    }
}

/** A long address, its ends shown. */
private fun short(address: String): String =
    if (address.length <= 20) address else address.take(10) + "…" + address.takeLast(8)

private fun confirmations(tx: Onchain, details: Details?): String {
    val depth = (details as? Details.Moved)?.depth
    return when {
        depth != null && tx.confirmations < depth -> "${tx.confirmations} of $depth"
        else -> "${tx.confirmations}"
    }
}

/** Everything known of it, in advanced mode: a tap copies a value. */
@Composable
private fun Technical(activity: Activity, details: Details?, copy: (String, String) -> Unit) {
    Group("Advanced") {
        when (details) {
            is Details.Notes -> {
                Fact("Payment", activity.id, copy)
                Fact("Hub", details.hub, copy)
            }
            is Details.Moved -> {
                Fact("Deposit hash", details.hash, copy)
                Fact("Hub", details.hub, copy)
                details.address?.let { Fact("Address", it, copy) }
                details.pays?.let { Fact("Pays", sat(it), copy, "$it") }
                details.payment?.let { Transaction(it, copy) }
                details.depth?.let { Fact("Confirmations needed", "$it", copy) }
                details.fundBy?.let { Fact("Confirmed by block", "$it", copy) }
                details.timeout?.let { Fact("Refundable after block", "$it", copy) }
                details.refund?.let { Fact("Refund", it, copy) }
            }
            is Details.Coin -> {
                Transaction(details.tx, copy)
                Fact("Output", "${details.vout}", copy)
                if (details.change) Fact("Change", "of a payment of this wallet's", copy)
                details.moving?.let { Fact("Spent by", it, copy) }
            }
            is Details.Lightning -> {
                Fact("Lock", activity.id, copy)
                Fact("Hub", details.hub, copy)
                Fact("Invoice", details.invoice, copy)
                details.preimage?.let { Fact("Preimage", it, copy) }
                details.failure?.let { Fact("Failure", it, copy) }
                details.provider?.let { Fact("Provider", it, copy) }
                details.expiry?.let { Fact("Expiry", "$it", copy) }
            }
            is Details.Payout -> {
                Fact("Payout hash", activity.id, copy)
                Fact("Address", details.address, copy)
                Fact("Hub", details.hub, copy)
                Fact("Provider", details.provider, copy)
                val p = details.progress
                p.coin?.let { Fact("Provider's coin", it, copy) }
                p.coinHeight?.let { Fact("Its block", "$it", copy) }
                p.claim?.let { Fact("Claim", it, copy) }
                p.claimHeight?.let { Fact("The claim's block", "$it", copy) }
                p.lock?.let { Fact("Lock", it.name.lowercase(), copy) }
                p.lockExpiry?.let { Fact("Lock refunded from block", "$it", copy) }
                p.timeout?.let { Fact("Provider takes its coin back from block", "$it", copy) }
                p.claimBy?.let { Fact("Claimed by block", "$it", copy) }
                Fact("Confirmations needed", "${p.depth}", copy)
                details.failure?.let { Fact("Failure", it, copy) }
            }
            is Details.Invoice -> {
                Fact("Payment hash", activity.id, copy)
                Fact("Hub", details.hub, copy)
                details.invoice?.let { Fact("Invoice", it, copy) }
                details.failure?.let { Fact("Failure", it, copy) }
            }
            is Details.Contract -> {
                Fact("Contract", activity.id, copy)
                Fact("Hub", details.hub, copy)
                details.funding?.let { Fact("Funding", it, copy) }
            }
            is Details.Swap -> {
                Fact("Swap hash", activity.id, copy)
                Fact("From", details.from, copy)
                Fact("To", details.to, copy)
                Fact("Provider", details.provider, copy)
                details.lock?.let { Fact("Your lock", it, copy) }
                details.theirs?.let { Fact("The provider's lock", it, copy) }
                details.failure?.let { Fact("Failure", it, copy) }
            }
            null -> Fact("Id", activity.id, copy)
        }
    }
}

/**
 * The notes in and out, in advanced mode: those it spent, whom they paid
 * and what it kept, and those it made the wallet's, each with its hub and
 * whether its hub can still tell which payment it came from. A tap copies
 * a note's identifier.
 */
@Composable
private fun NotesGroup(activity: Activity, notes: NotesOf, copy: (String, String) -> Unit) {
    Group("Each note") {
        val made = notes.made
        val unlinked = made.count { it.linking == Linking.UNLINKED }
        Text(
            listOfNotNull(
                notes.spent.takeIf { it.isNotEmpty() }?.let { "Spent ${count(it)}." },
                made.takeIf { it.isNotEmpty() }?.let {
                    "Made ${count(it)}" + if (unlinked > 0) ", $unlinked unlinked since." else "."
                },
            ).joinToString(" ") + " An unlinked note was signed again blindly by its hub: " +
                "the hub can't tell which payment it came from when it is spent.",
            modifier = Modifier.padding(vertical = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (notes.spent.isNotEmpty()) {
            Text("In: spent", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleSmall)
            notes.spent.forEach { NoteRow(it, spentHere = true, copy = copy) }
        }
        if (notes.paid.isNotEmpty()) {
            Text("Out: paid and kept", Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleSmall)
            if (activity.state == State.PENDING) {
                Text(
                    if (activity.kind == Kind.SENT) "Once its hub releases it."
                    else "Once paid. Refunded instead, the notes come back less the hub's refund fee.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            notes.paid.forEach { PaidRow(activity.kind, it) }
        }
        if (made.isNotEmpty()) {
            Text(
                if (notes.paid.isEmpty()) "In: made the wallet's" else "Made the wallet's",
                Modifier.padding(top = 8.dp),
                style = MaterialTheme.typography.titleSmall,
            )
            made.forEach { NoteRow(it, spentHere = false, copy = copy) }
        }
    }
}

/** Part of what the notes spent paid: to whom, how much, in which notes. */
@Composable
private fun PaidRow(kind: Kind, part: NotesPaid) {
    val to = paidTo(kind, part.to)
    Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(to, style = MaterialTheme.typography.bodyLarge)
            val each = part.notes.joinToString(" + ") { digits(it) }
            val what = if (part.notes.size == 1) "1 note" else "${part.notes.size} notes"
            Text(
                listOfNotNull(host(part.hub), each.takeIf { it.isNotEmpty() }?.let { "$what: $it" })
                    .joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.width(12.dp))
        Text(sat(part.amount), style = MaterialTheme.typography.bodyLarge)
    }
}

/** `3 notes, 4,096 sat`. */
private fun count(notes: List<NoteLine>): String {
    val total = notes.fold(0uL) { sum, n -> sum + n.amount }
    val what = if (notes.size == 1) "1 note" else "${notes.size} notes"
    return "$what, ${sat(total)}"
}

/** A note: its amount, hub and linking, and where it went or came from. */
@Composable
private fun NoteRow(note: NoteLine, spentHere: Boolean, copy: (String, String) -> Unit) {
    var done by remember { mutableStateOf(false) }
    LaunchedEffect(done) {
        if (done) {
            delay(COPIED_MS)
            done = false
        }
    }
    val linking = when (note.linking) {
        Linking.UNLINKED -> "unlinked"
        Linking.STAYS_LINKED -> "stays linked: its hub refused to unlink it"
        Linking.LINKED -> "linked, to be unlinked"
    }
    val where = when {
        note.gone -> "spent by a copy of this wallet"
        spentHere && note.madeByItself -> "made for this payment's amounts"
        !spentHere && note.spentBy != null -> "spent since"
        else -> null
    }
    Row(
        Modifier.fillMaxWidth().clickable {
            copy("Note", note.id)
            done = true
        }.padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(sat(note.amount), style = MaterialTheme.typography.bodyLarge)
            Text(
                listOfNotNull(host(note.hub), linking, where).joinToString(" · "),
                style = MaterialTheme.typography.bodySmall,
                color = if (note.linking == Linking.UNLINKED) {
                    MaterialTheme.colorScheme.onSurfaceVariant
                } else {
                    MaterialTheme.colorScheme.tertiary
                },
            )
        }
        Spacer(Modifier.width(12.dp))
        Text(
            if (done) "Copied" else short(note.id),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun Transaction(tx: Onchain, copy: (String, String) -> Unit) {
    Fact("Transaction", tx.txid, copy)
    tx.height?.let { Fact("Block", "$it", copy) }
    tx.fee?.let { Fact("Network fee", sat(it), copy, "$it") }
}

@Composable
private fun Fact(label: String, value: String, copy: (String, String) -> Unit, copied: String = value) {
    var done by remember { mutableStateOf(false) }
    LaunchedEffect(done) {
        if (done) {
            delay(COPIED_MS)
            done = false
        }
    }
    Column(
        Modifier.fillMaxWidth().clickable {
            copy(label, copied)
            done = true
        }.padding(vertical = 10.dp),
    ) {
        Text(
            if (done) "$label · Copied" else label,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
    }
}
