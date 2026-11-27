package org.licash.wallet.ui

import android.content.Intent
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.Icon
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.licash.core.ExtraCode
import org.licash.core.FeesRaised
import org.licash.core.InvoiceQuote
import org.licash.core.LicashException
import org.licash.core.PayQuote
import org.licash.core.PayoutQuote
import org.licash.core.Scanned
import org.licash.core.State
import org.licash.wallet.Engine
import org.licash.wallet.behind
import org.licash.wallet.Ui
import org.licash.wallet.explain
import org.licash.wallet.feeOf
import org.licash.wallet.host
import org.licash.wallet.noHub
import org.licash.wallet.noPayout
import org.licash.wallet.offeredInstead
import org.licash.wallet.sat
import org.licash.wallet.share

private sealed interface Step {
    data object Looking : Step
    /** A code to pay in notes. */
    data class Paying(
        val code: String,
        val asked: ULong?,
        val visit: Boolean = false,
    ) : Step
    data object Planning : Step
    /** Swapping through `provider`, named `through`, if chosen. */
    data class Review(
        val code: String,
        val amount: ULong?,
        val quote: PayQuote,
        val provider: String? = null,
        val through: String? = null,
    ) : Step
    data class Visit(val code: String, val asked: ULong?) : Step
    data class Invoice(val text: String, val quote: InvoiceQuote) : Step
    data class Address(val address: String) : Step
    data class Payout(val quote: PayoutQuote, val asked: ULong? = null) : Step
    data object Busy : Step
    data object Quoting : Step
    data class PayingOut(val amount: ULong, val depth: UInt) : Step
    /** To the code `code`, if one; `kept` at its hub for the payee to collect. */
    data class Sent(val amount: ULong, val handover: String?, val code: String? = null, val kept: Boolean = false) : Step
    data class Paid(val amount: ULong, val fee: ULong) : Step
    data object Later : Step
    data class Received(val amount: ULong) : Step
    data class Trust(val payment: String, val hub: String) : Step
    /** A provider's or gateway's fee risen since its quote: `requote` to see the new price. */
    class FeeRose(val agreed: ULong, val asked: ULong, val requote: () -> Unit) : Step
    /** A hub charging more than agreed, in the way of a payment: made `again` once approved. */
    class Approve(val raised: FeesRaised, val again: () -> Unit) : Step
    data class Failed(val why: String, val title: String = "Couldn't pay") : Step

    /** No provider pays out as much as asked: about `most` is offered instead. */
    data class TooMuch(val why: String, val address: String, val most: ULong) : Step
    /** A note the hub of a payment would not carry: paid without it if the user says. */
    data class NoNote(val code: String, val amount: ULong?, val hub: String) : Step

    /**
     * Too little to pay with, but bitcoin held or on its way, not in the
     * balance yet: added now if `addable`, or protected first if `offered`.
     */
    data class AddFirst(val why: String, val addable: Boolean, val offered: Boolean) : Step

    /** Too little to pay with, and nothing held at all. */
    data class NothingYet(val why: String) : Step

    /** A coin on Bitcoin of `amount` being added to the balance. */
    data class Adding(val amount: ULong) : Step
}

/**
 * Scan or paste: a code to pay, or a payment handed over to take; with
 * `cashOut`, a hub, a Bitcoin address to pay notes there out to, as much
 * as chosen: all of them, or `cashOutAmount` as suggested.
 * `ownAddress`, if `link` pays this wallet's own address, is shown so.
 */
@Composable
fun Send(
    engine: Engine,
    ui: Ui,
    link: String?,
    cashOut: String? = null,
    ownAddress: String? = null,
    cashOutAmount: ULong? = null,
    toReceive: (() -> Unit)? = null,
    back: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboard.current
    // Opened with a link: no camera to start.
    var step by remember { mutableStateOf<Step>(if (link == null) Step.Looking else Step.Busy) }
    var empty by remember { mutableStateOf(false) }
    // Protection offered, the balance being too little to pay.
    var protecting by remember { mutableStateOf(false) }
    val offer = ui.offer?.takeIf { ui.opening == null }
    if (protecting && offer != null) {
        OfferSheet(engine, offer, !behind(ui)) {
            protecting = false
            back()
        }
    }
    // This wallet's own address, once cashing out to it.
    var own by remember { mutableStateOf(ownAddress) }
    // A note for the payee of a code, and whether to tell them who paid.
    var note by remember { mutableStateOf("") }
    var shareCode by remember { mutableStateOf(false) }
    // Which: 0 the wallet's own, else an extra code's number.
    var shareAs by remember { mutableStateOf(0u) }
    var codes by remember { mutableStateOf<List<ExtraCode>>(emptyList()) }
    LaunchedEffect(Unit) { codes = engine.codes().getOrDefault(emptyList()) }

    // Too little to pay with: protection offered first, if a coin pays for
    // one, its rest joining the balance; else bitcoin held or coming, to
    // open, or nothing held, to receive; else why.
    fun tooLittle(e: Throwable, title: String = "Couldn't pay"): Step {
        val why = explain(e)
        val b = ui.balance
        val bitcoin = b.onchain + b.moving + b.opening + ui.incoming.sumOf { it.amount }
        val addable = addable(b, ui.opening != null)
        return when (lack(e is LicashException.Insufficient, noHub(e), b.notes, bitcoin, ui.offer != null)) {
            Lack.OFFER -> Step.AddFirst(why, addable, offered = true)
            Lack.BITCOIN -> Step.AddFirst(why, addable, offered = false)
            Lack.NOTHING -> Step.NothingYet(why)
            Lack.OTHER -> Step.Failed(why, title)
        }
    }

    suspend fun taking(payment: String, trust: Boolean): Step =
        engine.receive(payment, trust).fold(
            { Step.Received(it.amount) },
            { e ->
                when (e) {
                    is LicashException.UnknownHub -> Step.Trust(payment, e.url)
                    else -> Step.Failed(explain(e), "Couldn't receive")
                }
            },
        )

    fun take(payment: String, trust: Boolean) {
        step = Step.Busy
        scope.launch { step = taking(payment, trust) }
    }

    suspend fun quoting(address: String, amount: ULong?): Step {
        step = Step.Quoting
        return engine.payoutQuote(address, amount, cashOut).fold(
            { Step.Payout(it, amount) },
            { e ->
                // Too much for any provider: the most they pay out, if less, to send instead.
                val most = if (noPayout(e)) offeredInstead(amount, engine.payoutMost(address, cashOut).getOrNull()) else null
                most?.let { Step.TooMuch(explain(e), address, it) } ?: tooLittle(e, "Can't send on Bitcoin")
            },
        )
    }

    fun quote(address: String, amount: ULong?) {
        scope.launch { step = quoting(address, amount) }
    }

    fun read(text: String) {
        step = Step.Busy
        scope.launch {
            step = engine.scanned(text).fold(
                { scanned ->
                    when {
                        // Cashing out: to an address, nothing else, as much as chosen.
                        cashOut != null -> when (scanned) {
                            is Scanned.Bitcoin -> when (val asked = scanned.amount) {
                                null -> Step.Address(scanned.address)
                                else -> quoting(scanned.address, asked)
                            }
                            else -> Step.Failed("To cash out, scan or paste a Bitcoin address.", "Not a Bitcoin address")
                        }
                        scanned is Scanned.Code -> when {
                            scanned.notes -> Step.Paying(text, scanned.amount)
                            else -> Step.Failed("This address names no hub you use, and no Bitcoin address to pay.", "Can't pay this")
                        }
                        scanned is Scanned.Visit -> Step.Visit(text, scanned.amount)
                        scanned is Scanned.Bitcoin -> when (val asked = scanned.amount) {
                            null -> Step.Address(scanned.address)
                            else -> quoting(scanned.address, asked)
                        }
                        scanned is Scanned.Payment -> taking(text, false)
                        scanned is Scanned.Invoice -> engine.invoiceQuote(text).fold(
                            { Step.Invoice(text, it) },
                            { Step.Failed(explain(it)) },
                        )
                        else -> Step.Failed("Nothing to pay there.", "Nothing to pay")
                    }
                },
                { Step.Failed(explain(it), "Can't read this") },
            )
        }
    }

    // Why a payment failed: its hub's fees to approve first, if it charges
    // more than agreed, and the payment made `again` then; a fee risen since
    // quoted, to `requote` and confirm at the new price.
    suspend fun unpaid(e: Throwable, requote: (() -> Unit)? = null, again: () -> Unit): Step {
        if (e is LicashException.FeeRose && requote != null) return Step.FeeRose(e.agreed, e.asked, requote)
        val hub = (e as? LicashException.FeesRaised)?.hub
        val raised = hub?.let { engine.feesRaised(it).getOrNull() }
        return if (raised == null) Step.Failed(explain(e)) else Step.Approve(raised, again)
    }

    suspend fun paying(code: String, amount: ULong?): Step =
        engine.pay(code, amount, noteOf(note), shareAs.takeIf { shareCode }).fold(
            { Step.Sent(it.amount, it.handover, code, it.kept) },
            { e ->
                when (e) {
                    is LicashException.Pending -> Step.Later
                    is LicashException.NoteUnkept -> Step.NoNote(code, amount, e.hub)
                    else -> unpaid(e, { step = Step.Paying(code, amount) }) {
                        step = Step.Busy
                        scope.launch { step = paying(code, amount) }
                    }
                }
            },
        )

    fun pay(code: String, amount: ULong?) {
        step = Step.Busy
        scope.launch { step = paying(code, amount) }
    }

    // Quoted first: paid at once at a hub trusted holding enough for no
    // more than the fee `shown`, else reviewed, a swap, a hub not added or
    // a fee risen in the way.
    fun plan(s: Step.Paying, amount: ULong?, shown: ULong?) {
        step = Step.Planning
        scope.launch {
            step = engine.payQuote(s.code, amount).fold(
                { quote ->
                    if (quote.trusted && quote.swapFrom == null && shown != null && quote.fee <= shown) {
                        step = Step.Busy
                        paying(s.code, amount)
                    } else {
                        Step.Review(s.code, amount, quote)
                    }
                },
                { e -> tooLittle(e) },
            )
        }
    }

    fun requoteInvoice(text: String) {
        step = Step.Busy
        scope.launch {
            step = engine.invoiceQuote(text).fold({ Step.Invoice(text, it) }, { Step.Failed(explain(it)) })
        }
    }

    fun payInvoice(text: String, quote: InvoiceQuote) {
        step = Step.Busy
        scope.launch {
            step = engine.payInvoice(text, quote).fold(
                { if (it.state == State.DONE) Step.Paid(it.amount, it.fee) else Step.Later },
                { e -> unpaid(e, { requoteInvoice(text) }) { payInvoice(text, quote) } },
            )
        }
    }

    fun payOut(quote: PayoutQuote, asked: ULong?) {
        step = Step.Busy
        scope.launch {
            step = engine.payOut(quote, asked).fold(
                { Step.PayingOut(it.amount, quote.depth) },
                { e -> unpaid(e, { quote(quote.address, asked) }) { payOut(quote, asked) } },
            )
        }
    }


    LaunchedEffect(link) { link?.let { read(it) } }
    // Each step after a wait tells how long it took.
    val wait = rememberWait(step == Step.Busy || step == Step.Planning || step == Step.Quoting)
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp)) {
        TopBar(if (cashOut == null && ownAddress == null) "Send" else "Cash out", back)
        Column(Modifier.fillMaxWidth().weight(1f).verticalScroll(rememberScrollState())) {
            CompositionLocalProvider(LocalWait provides wait) {
                // Each step fades into the next; one that only changes what it shows does not.
                AnimatedContent(
                    targetState = step,
                    modifier = Modifier.fillMaxWidth(),
                    transitionSpec = { fadeIn(tween(150, delayMillis = 50)) togetherWith fadeOut(tween(50)) },
                    contentKey = { it::class },
                    label = "step",
                ) { s ->
                    // One column, as the step was before it faded: its parts stacked, not laid over each other.
                    Column(Modifier.fillMaxWidth()) {
                        when (s) {
                            Step.Looking -> {
                                if (cashOut != null) {
                                    Spacer(Modifier.height(8.dp))
                                    BigButton("To this wallet", Modifier.fillMaxWidth().testTag("to-own")) {
                                        scope.launch {
                                            engine.bitcoinAddress().fold(
                                                { own = it; step = Step.Address(it) },
                                                { step = Step.Failed(explain(it)) },
                                            )
                                        }
                                    }
                                    Text(
                                        "Or scan an address",
                                        modifier = Modifier.fillMaxWidth().padding(top = 20.dp, bottom = 8.dp),
                                        style = MaterialTheme.typography.labelLarge,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        textAlign = TextAlign.Center,
                                    )
                                }
                                Scanner(Modifier.fillMaxWidth().aspectRatio(1f).clip(RoundedCornerShape(24.dp))) { read(it) }
                                Spacer(Modifier.height(16.dp))
                                BigButton("Paste", Modifier.fillMaxWidth().testTag("paste"), quiet = true) {
                                    scope.launch {
                                        val clip = clipboard.getClipEntry()?.clipData
                                        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()?.trim()
                                        empty = text.isNullOrEmpty()
                                        if (!text.isNullOrEmpty()) read(text)
                                    }
                                }
                                if (empty) {
                                    Spacer(Modifier.height(8.dp))
                                    Text(
                                        "Nothing copied yet",
                                        modifier = Modifier.fillMaxWidth(),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        textAlign = TextAlign.Center,
                                    )
                                }
                                // Or someone paid before, by name.
                                if (cashOut == null) Contacts(engine) { read(it.code) }
                            }
                            is Step.Paying -> Paying(engine, ui, s, {
                                NoteFields(note, { note = it }, shareCode, { shareCode = it }, codes, shareAs, { shareAs = it })
                            }) { amount, shown -> plan(s, amount, shown) }
                            Step.Busy -> Middle("One moment…")
                            Step.Planning -> Middle("One moment…")
                            is Step.Review -> Review(s.quote, payee(engine, s.code), s.through.takeIf { ui.developer }, { pay(s.code, s.amount) }) {
                                // A swap first: any provider that could, to choose.
                                if (ui.developer && s.quote.swapFrom != null) {
                                    Providers {
                                        engine.payOffers(s.code, s.amount).map { offers ->
                                            val swaps = offers.filter { it.provider != null }
                                            val current = s.provider ?: swaps.firstOrNull()?.provider
                                            swaps.map { o ->
                                                val provider = o.provider!!
                                                val name = o.providerName ?: host(provider)
                                                Offer(
                                                    name,
                                                    "Fees ${feeOf(o.quote.fee, o.quote.amount)}" + if (o.known) ", used before" else "",
                                                    provider == current,
                                                ) {
                                                    step = Step.Planning
                                                    scope.launch {
                                                        step = engine.choosePayOffer(s.code, s.amount, provider).fold(
                                                            { Step.Review(s.code, s.amount, it, provider, name) },
                                                            { Step.Failed(explain(it)) },
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            is Step.Visit -> Ask(
                                "Pay at their hub?",
                                "Their hub is not one of yours.",
                                "Pay there",
                                {
                                    val paying = Step.Paying(s.code, s.asked, visit = true)
                                    if (s.asked != null) plan(paying, null, null) else step = paying
                                },
                                back,
                            )
                            Step.Quoting -> Middle("Getting a price…")
                            is Step.Invoice -> Invoice(s.quote, { payInvoice(s.text, s.quote) }) {
                                if (ui.developer) {
                                    Providers {
                                        engine.invoiceOffers(s.text).map { offers ->
                                            offers.map { o ->
                                                val through = o.provider.name ?: host(o.provider.url)
                                                Offer(
                                                    through,
                                                    "Fees ${feeOf(o.fee, o.amount)}, from ${name(o.hub)}",
                                                    o == s.quote,
                                                ) { step = Step.Invoice(s.text, o) }
                                            }
                                        }
                                    }
                                }
                            }
                            is Step.Address -> ToAddress(
                                s.address,
                                own = s.address == own,
                                prefill = cashOutAmount.takeIf { cashOut != null },
                                all = if (cashOut != null) "Cash out all" else "Send all",
                            ) { amount -> quote(s.address, amount) }
                            is Step.Payout -> Payout(s.quote, s.quote.address == own, ui.hubs.size > 1, { payOut(s.quote, s.asked) }) {
                                if (ui.developer) {
                                    Providers {
                                        engine.payoutOffers(s.quote.address, s.asked, s.quote.hub).map { offers ->
                                            offers.map { o ->
                                                Offer(
                                                    o.providerName ?: host(o.provider),
                                                    "Fees ${feeOf(o.fee, o.amount)}, pays ${sat(o.amount)}",
                                                    o.provider == s.quote.provider,
                                                ) { step = Step.Payout(o, s.asked) }
                                            }
                                        }
                                    }
                                }
                            }
                            is Step.PayingOut -> Told("Sending ${sat(s.amount)}", "Arrives in ${arrives(s.depth, LocalBlockSeconds.current)}", back)
                            is Step.Paid -> Done("Paid ${sat(s.amount)}", back, if (s.fee > 0uL) "Fee ${feeOf(s.fee, s.amount)}" else null)
                            is Step.Sent -> {
                                Sent(s, back)
                                s.code?.let { SaveContact(engine, it) }
                            }
                            // Not to pay again: it finishes by itself.
                            Step.Later -> Told("Under way", "It finishes by itself", back)
                            is Step.Received -> Done("Received ${sat(s.amount)}", back)
                            is Step.NoNote -> Ask(
                                "Send without the note?",
                                "${name(s.hub)} can't carry a note with a payment. They would get the payment, but not your note" +
                                    (if (shareCode) " or your address." else "."),
                                "Send without the note",
                                {
                                    note = ""
                                    shareCode = false
                                    pay(s.code, s.amount)
                                },
                                back,
                            )
                            is Step.Trust -> Ask(
                                "Take it?",
                                "It is at ${name(s.hub)}, a hub you don't use yet. Taking it adds that hub.",
                                "Take it",
                                { take(s.payment, true) },
                                back,
                            )
                            is Step.Approve -> Ask(
                                "Approve higher fees?",
                                "${name(s.raised.hub)} raised its fees since your protection there started.\n\n" +
                                    raises(s.raised).joinToString("\n") { "${it.what}: ${it.now}, was ${it.agreed}" },
                                "Approve and pay",
                                {
                                    step = Step.Busy
                                    scope.launch {
                                        engine.approveFees(s.raised).fold({ s.again() }, { step = Step.Failed(explain(it)) })
                                    }
                                },
                                back,
                            )
                            is Step.FeeRose -> Ask("The fee went up", feeRose(s.agreed, s.asked), "See new price", s.requote, back)
                            is Step.Failed -> Ask(s.title, s.why, "Try again", { step = Step.Looking }, back, failed = true)
                            is Step.AddFirst -> Outcome(
                                Tone.ASK,
                                if (ui.balance.notes > 0uL) "Not enough in your balance" else "Your bitcoin isn't in your balance yet",
                                "${s.why}\n\n" + addFirst(s.addable, s.offered && offer != null),
                                detailTag = "ask",
                            ) {
                                // On its way only: nothing to do but wait.
                                // Protected first where offered, as on the page for what is on Bitcoin.
                                val protectable = s.offered && offer != null
                                if (protectable) {
                                    BigButton("Add to balance, protected", Modifier.fillMaxWidth().testTag("protect-it")) {
                                        protecting = true
                                    }
                                    Spacer(Modifier.height(12.dp))
                                }
                                if (s.addable) {
                                    BigButton(
                                        if (protectable) "Add without protection" else "Add to balance",
                                        Modifier.fillMaxWidth().testTag("add-to-balance"),
                                        quiet = protectable,
                                    ) {
                                        step = Step.Busy
                                        scope.launch {
                                            step = engine.moveLargest().fold(
                                                { Step.Adding(it.amount) },
                                                { Step.Failed(explain(it), "Couldn't add it") },
                                            )
                                        }
                                    }
                                    Spacer(Modifier.height(12.dp))
                                }
                                BigButton("Cancel", Modifier.fillMaxWidth().testTag("cancel"), quiet = true, onClick = back)
                            }
                            is Step.Adding -> Told("Adding ${sat(s.amount)}", ADDING, back)
                            is Step.TooMuch -> Outcome(
                                Tone.ASK,
                                "Can't send that much on Bitcoin",
                                "${s.why}\n\nThe providers pay out about ${sat(s.most)} now.",
                                detailTag = "too-much",
                            ) {
                                BigButton("Use ${sat(s.most)}", Modifier.fillMaxWidth().testTag("use-most")) {
                                    quote(s.address, s.most)
                                }
                                Spacer(Modifier.height(12.dp))
                                BigButton("Cancel", Modifier.fillMaxWidth().testTag("cancel"), quiet = true, onClick = back)
                            }
                            is Step.NothingYet -> Ask(
                                "Nothing to pay with yet",
                                "${s.why}\n\n$RECEIVE_FIRST",
                                "Receive",
                                toReceive ?: back,
                                back,
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Why bitcoin held is not paid with yet, and what can be done: added now
 * if `addable`, else only waited for; protected first if `offered`.
 */
internal fun addFirst(addable: Boolean, offered: Boolean): String = when {
    !addable -> "You pay from your balance, and your bitcoin is still on its way to it. Try again once it has arrived."
    offered -> "You pay from your balance. Add your bitcoin to it: protect it first, covered by a contract " +
        "at your hub, for a fee, or add your largest coin now without protection."
    else -> "You pay from your balance. Add your largest coin to it now, held at your hub without protection."
}

/** A coin being added to the balance, before it can be paid with. */
internal const val ADDING = "It joins your balance once confirmed on Bitcoin, in about an hour. Pay then."

/** What to do when nothing is held at all. */
internal const val RECEIVE_FIRST = "You pay from your balance, and it is empty. Receive some first."

/** One fact of a payment to confirm: `tag` names its value, for the tests; a fee's `share` of the amount. */
private class Fact(val label: String, val value: String, val tag: String, val share: String? = null, val fee: FeeBreakdown? = null)

/** What a payment costs and when it arrives, to confirm it by: with what it comes to, if it costs. */
private fun costs(
    amount: ULong,
    fee: ULong,
    arrives: String,
    breakdown: FeeBreakdown = FeeBreakdown(amount, fee),
): List<Fact> = listOfNotNull(
    Fact("Fee", if (fee == 0uL) "None" else sat(fee), "fee", share(fee, amount), breakdown),
    if (fee > 0uL) Fact("Total", sat(amount + fee), "total") else null,
    Fact("Arrives", arrives, "arrives"),
)

/** How long a payment on Bitcoin takes to count, `depth` blocks deep, of `blockSecs` each. */
internal fun arrives(depth: UInt, blockSecs: UInt = BITCOIN_BLOCK_SECONDS): String =
    "about ${minutes(depth.toLong() + 1, blockSecs)} min"

/**
 * A payment to confirm: how much, then what there is to know before
 * agreeing, a fact a line, and one button. `head` goes under the amount,
 * `more` under the button.
 */
@Composable
private fun Confirm(
    amount: ULong,
    facts: List<Fact>,
    action: String,
    act: () -> Unit,
    head: @Composable () -> Unit = {},
    more: @Composable () -> Unit = {},
) {
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(32.dp))
        Text(sat(amount), modifier = Modifier.testTag("paying"), style = Heading)
        head()
        Facts(facts)
        Waited(modifier = Modifier.fillMaxWidth().padding(top = 8.dp))
        Spacer(Modifier.height(24.dp))
        BigButton(action, Modifier.fillMaxWidth().testTag("confirm"), onClick = act)
        more()
    }
}

@Composable
private fun Facts(facts: List<Fact>) {
    Group("") {
        facts.forEachIndexed { i, fact ->
            if (i > 0) Divider()
            val fee = fact.fee
            if (fee != null) FeeLine(fact.label, fee.fee, fee.amount, fact.tag, fact.value, fee)
            else Line(fact.label, fact.value, tag = fact.tag, share = fact.share)
        }
    }
}

/**
 * A code to pay in notes: the amount it asks, or one typed straight in.
 * The keyboard's action only hides it: the button pays. At a hub not
 * added, what it costs is told next, once known.
 */
@Composable
private fun Paying(
    engine: Engine,
    ui: Ui,
    s: Step.Paying,
    noting: @Composable () -> Unit,
    pay: (amount: ULong?, shown: ULong?) -> Unit,
) {
    var amount by remember { mutableStateOf(s.asked?.toLong()) }
    // What the wallet pays as things stand, at a hub trusted holding
    // enough: none known, a swap or a visit in the way, told next.
    var exact by remember { mutableStateOf<ULong?>(null) }
    LaunchedEffect(amount, ui.balance) {
        exact = null
        val a = amount?.takeIf { !s.visit && it > 0 } ?: return@LaunchedEffect
        delay(250)
        exact = engine.payFee(s.code, if (s.asked == null) a.toULong() else null).getOrNull()
    }
    // Else the most a hub would charge: the code may name several.
    val estimatedHub = amount?.takeIf { !s.visit }
        ?.let { a -> ui.hubs.maxByOrNull { payingUpTo(it, a.toULong()) } }
    val fee = exact ?: amount?.let { a -> estimatedHub?.let { payingUpTo(it, a.toULong()) } }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(32.dp))
        if (s.asked == null) {
            AmountField(amount, { amount = it })
        } else {
            Text(sat(s.asked), modifier = Modifier.testTag("paying"), style = Heading)
        }
        if (!s.visit) {
            Facts(
                listOf(
                    Fact("To", payee(engine, s.code), "to"),
                    Fact(
                        "Fee",
                        fee?.let { if (it == 0uL) "None" else if (exact != null) sat(it) else "Up to ${sat(it)}" } ?: "",
                        "fee",
                        fee?.let { f -> amount?.let { share(f, it.toULong()) } },
                        fee?.let { f -> amount?.let { a -> estimatedHub?.let { hub -> FeeBreakdown(
                            a.toULong(), f,
                            components = listOf((if (exact != null) "Hub" else "Hub (estimate)") to f),
                            rate = org.licash.core.Rate(hub.feeBase, hub.feePpm),
                            explanation = if (exact != null) {
                                "What paying costs now, the notes it spends and makes counted."
                            } else {
                                "Upper estimate using current terms at ${name(hub.url)}, with its fee for each note made. The hub used to pay may charge less."
                            },
                        ) } } },
                    ),
                    Fact("Arrives", "Instantly", "arrives"),
                ),
            )
        }
        Spacer(Modifier.height(16.dp))
        noting()
        Spacer(Modifier.height(24.dp))
        BigButton(if (s.visit) "Continue" else "Pay", Modifier.fillMaxWidth().testTag("confirm"), enabled = amount != null) {
            pay(if (s.asked == null) amount?.toULong() else null, exact)
        }
    }
}

/**
 * A payment in notes to review: what it pays and costs, the swap bringing
 * notes to its hub first, and whether that hub is one not added.
 */
@Composable
private fun Review(quote: PayQuote, to: String, through: String?, pay: () -> Unit, more: @Composable () -> Unit) {
    val swap = quote.swapFrom
    Confirm(
        quote.amount,
        listOf(Fact("To", to, "to")) +
            costs(quote.amount, quote.fee, if (swap == null) "Instantly" else "Shortly") + listOfNotNull(
            swap?.let { Fact("Moved first", "${sat(quote.swapped)} from ${name(it)}", "moves") },
            through?.let { Fact("Through", it, "through") },
        ),
        "Pay",
        pay,
        head = {
            if (!quote.trusted) {
                Text(
                    "At ${name(quote.hub)}, a hub you have not added",
                    modifier = Modifier.padding(top = 8.dp).testTag("not-added"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        },
        more = more,
    )
}

/** A provider's offer, in a list to choose from: `choose` takes it. */
private class Offer(val name: String, val detail: String, val current: Boolean, val choose: () -> Unit)

/**
 * Every provider's offer, once asked, `load`ing them: to choose another
 * than the one picked, in advanced mode.
 */
@Composable
private fun Providers(load: suspend () -> Result<List<Offer>>) {
    val scope = rememberCoroutineScope()
    var offers by remember { mutableStateOf<List<Offer>?>(null) }
    var asking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val wait = rememberWait(asking)
    Spacer(Modifier.height(16.dp))
    val list = offers
    if (list == null) {
        TextButton(
            enabled = !asking,
            onClick = {
                asking = true
                error = null
                scope.launch {
                    load().fold({ offers = it }, { error = explain(it) })
                    asking = false
                }
            },
            modifier = Modifier.testTag("providers"),
        ) { Text(if (asking) "Asking the providers…" else "All providers") }
        Waited(wait, Modifier.padding(start = 12.dp))
    } else {
        Text(
            if (list.size == 1) "The only provider" else "${list.size} providers",
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            style = MaterialTheme.typography.titleSmall,
        )
        Waited(wait)
        list.forEach { o ->
            Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(o.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        o.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (o.current) {
                    Text("Chosen", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                } else {
                    TextButton(onClick = o.choose, modifier = Modifier.testTag("use ${o.name}")) { Text("Use") }
                }
            }
        }
    }
    error?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
    }
}

/**
 * A Lightning invoice to pay: what it asks, and all it costs on top; from
 * which hub, through which swap provider, and how long its sats wait should
 * it not pay. `more` under the button.
 */
@Composable
private fun Invoice(quote: InvoiceQuote, pay: () -> Unit, more: @Composable () -> Unit) {
    val provider = quote.provider
    Confirm(
        quote.amount,
        costs(quote.amount, quote.fee, "In seconds", invoiceFee(quote)) + listOfNotNull(
            Fact("From", name(quote.hub), "from"),
            Fact("Through", provider.name ?: host(provider.url), "through"),
        ),
        "Pay",
        pay,
        more = {
            provider.let {
                Text(
                    refundWait(it.refundBlocks, LocalBlockSeconds.current),
                    modifier = Modifier.fillMaxWidth().padding(top = 12.dp).testTag("refund-wait"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
            more()
        },
        head = {
            quote.description?.let {
                Text(
                    it,
                    modifier = Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodyLarge,
                    textAlign = TextAlign.Center,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
    )
}

/**
 * A Bitcoin address to pay: how much, typed straight in, or all. The
 * keyboard's action continues to what it costs, to confirm.
 */
@Composable
private fun ToAddress(address: String, own: Boolean, prefill: ULong?, all: String, quote: (ULong?) -> Unit) {
    var amount by remember { mutableStateOf(prefill?.toLong()) }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(32.dp))
        AmountField(amount, { amount = it }, action = ImeAction.Go) { amount?.let { quote(it.toULong()) } }
        Text(
            if (own) "To this wallet" else "To ${shortAddress(address)}",
            modifier = Modifier.testTag("to"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))
        BigButton("Continue", Modifier.fillMaxWidth().testTag("continue"), enabled = amount != null) {
            amount?.let { quote(it.toULong()) }
        }
        Spacer(Modifier.height(12.dp))
        BigButton(all, Modifier.fillMaxWidth().testTag("all"), quiet = true) { quote(null) }
    }
}

/**
 * A payout on Bitcoin to confirm: what the address gets, all it costs on
 * top and when it arrives; from which hub, with `several`.
 */
@Composable
private fun Payout(quote: PayoutQuote, own: Boolean, several: Boolean, pay: () -> Unit, more: @Composable () -> Unit) {
    Confirm(
        quote.amount,
        listOf(Fact("To", if (own) "This wallet" else shortAddress(quote.address), "to")) +
            costs(
                quote.amount,
                quote.fee,
                arrives(quote.depth, LocalBlockSeconds.current).replaceFirstChar { it.uppercase() },
                payoutFee(quote.amount, quote.fee, quote.lockFee, quote.providerFee, quote.claimFee, quoted = true),
            ) +
            listOfNotNull(if (several) Fact("From", name(quote.hub), "from") else null),
        "Send",
        pay,
        more = more,
    )
}

/** A long address, its ends shown. */
private fun shortAddress(address: String): String =
    if (address.length <= 20) address else address.take(10) + "…" + address.takeLast(8)

/**
 * The wallet the code `code` pays, to check before paying: its contact's
 * name if one, else the code shortened. A contact's is never shown of
 * another wallet's code.
 */
@Composable
private fun payee(engine: Engine, code: String): String {
    var name by remember(code) { mutableStateOf<String?>(null) }
    LaunchedEffect(code) { name = engine.contactOf(code).getOrNull()?.name }
    return name ?: shortCode(code)
}

/** A payment code shortened: its text without scheme or amount, as a QR code's in upper case too. */
internal fun shortCode(code: String): String =
    shortAddress(code.trim().substringAfter(':').substringBefore('?').lowercase())

/** Paid; if not to the payee's mailbox, what to hand them. */
@Composable
private fun Sent(s: Step.Sent, back: () -> Unit) {
    val context = LocalContext.current
    if (s.handover == null) {
        Done("Sent ${sat(s.amount)}", back)
        return
    }
    // Its own layout, not an outcome's: felt the same, once.
    val feel = rememberFeel()
    LaunchedEffect(Unit) { feel.confirm() }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(32.dp))
        Text("Sent ${sat(s.amount)}", style = MaterialTheme.typography.headlineSmall)
        Text(
            if (s.kept) "They collect it from the hub. If they can't, hand them this" else "Hand them this to finish",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Waited(modifier = Modifier.padding(top = 8.dp), center = true)
        Spacer(Modifier.height(16.dp))
        if (s.handover.length <= 1500) QrCode(s.handover)
        Spacer(Modifier.height(16.dp))
        BigButton("Share", Modifier.fillMaxWidth()) {
            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, s.handover)
            context.startActivity(Intent.createChooser(send, null))
        }
        Spacer(Modifier.height(12.dp))
        BigButton("Done", Modifier.fillMaxWidth().testTag("done"), quiet = true, onClick = back)
    }
}

/** What [Outcome] says in its glyph: done, under way, a question, or failed. */
private enum class Tone { DONE, BUSY, ASK, FAILED }

/**
 * Where paying ends, or stops to ask, all alike: a glyph in a disc, a
 * title, a line under it, and its buttons. `titleTag` and `detailTag`
 * name them, for the tests.
 */
@Composable
private fun Outcome(
    tone: Tone,
    title: String,
    detail: String? = null,
    titleTag: String? = null,
    detailTag: String? = null,
    buttons: @Composable ColumnScope.() -> Unit = {},
) {
    val colors = MaterialTheme.colorScheme
    val tint = when (tone) {
        Tone.FAILED -> colors.error
        Tone.ASK -> colors.onSurfaceVariant
        else -> colors.primary
    }
    // Felt once, as it shows: done, or failed. A wait or a question is not.
    val feel = rememberFeel()
    LaunchedEffect(tone) {
        when (tone) {
            Tone.DONE -> feel.confirm()
            Tone.FAILED -> feel.reject()
            else -> {}
        }
    }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(72.dp))
        Box(
            Modifier.size(88.dp).clip(CircleShape).background(tint.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) {
            when (tone) {
                Tone.BUSY -> CircularProgressIndicator(Modifier.size(40.dp), color = tint, strokeWidth = 3.dp)
                Tone.DONE -> Icon(Icons.Filled.Check, contentDescription = null, Modifier.size(44.dp), tint = tint)
                Tone.ASK -> Icon(Icons.Outlined.Info, contentDescription = null, Modifier.size(44.dp), tint = tint)
                Tone.FAILED -> Icon(Icons.Filled.Warning, contentDescription = null, Modifier.size(40.dp), tint = tint)
            }
        }
        Spacer(Modifier.height(24.dp))
        Text(
            title,
            // Said by a screen reader as it shows.
            modifier = (titleTag?.let { Modifier.testTag(it) } ?: Modifier)
                .semantics { liveRegion = LiveRegionMode.Polite },
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        detail?.let {
            Spacer(Modifier.height(8.dp))
            Text(
                it,
                modifier = detailTag?.let { tag -> Modifier.testTag(tag) } ?: Modifier,
                style = MaterialTheme.typography.bodyLarge,
                color = colors.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        Waited(modifier = Modifier.padding(top = 8.dp), center = true)
        Spacer(Modifier.height(40.dp))
        buttons()
    }
}

/** Waiting on something quick: what, under a spinner. */
@Composable
private fun Middle(text: String) = Outcome(Tone.BUSY, text)

/** It went through: said in a few words, `sub` under them if any. */
@Composable
private fun Done(text: String, back: () -> Unit, sub: String? = null) = Outcome(Tone.DONE, text, sub, titleTag = "result") {
    BigButton("Done", Modifier.fillMaxWidth().testTag("done"), onClick = back)
}

/** It is under way: what, and what to expect of it. */
@Composable
private fun Told(text: String, sub: String, back: () -> Unit) = Outcome(Tone.BUSY, text, sub, titleTag = "result") {
    BigButton("Done", Modifier.fillMaxWidth().testTag("done"), onClick = back)
}

/**
 * A question, or what went wrong `failed`: its `title`, why under it
 * (tagged `ask`), and what to do about it or leave.
 */
@Composable
private fun Ask(
    title: String,
    why: String,
    action: String,
    act: () -> Unit,
    back: () -> Unit,
    failed: Boolean = false,
) = Outcome(if (failed) Tone.FAILED else Tone.ASK, title, why, detailTag = "ask") {
    BigButton(action, Modifier.fillMaxWidth().testTag("confirm"), onClick = act)
    Spacer(Modifier.height(12.dp))
    BigButton("Cancel", Modifier.fillMaxWidth().testTag("cancel"), quiet = true, onClick = back)
}
