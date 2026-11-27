package org.licash.wallet.ui

import android.content.ClipData
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.licash.core.Code
import org.licash.core.Contract
import org.licash.core.DonationAddress
import org.licash.core.ExtraCode
import org.licash.core.LightningInvoice
import org.licash.core.State
import org.licash.wallet.Engine
import org.licash.wallet.explain
import org.licash.wallet.percent
import org.licash.wallet.sat

/** How often an invoice shown is followed, in ms. */
private const val FOLLOW_MS = 3_000L

/** How long copying says it copied, in ms. */
internal const val COPIED_MS = 2_000L

/**
 * What Receive shows: the way it picks for the amount, or one of the
 * others asked for, `label` naming it and `says` who pays it.
 */
internal enum class Way(val label: String, val says: String, val tag: String) {
    /** A Lightning invoice a hub makes, or a provider where none does, for an amount: any wallet pays it. */
    LIGHTNING("Lightning invoice", "Any Lightning wallet, for an amount", "way-lightning"),

    /** The wallet's code, called its address, as what one is paid at is: paid in notes. */
    CODE("Licash address", "Licash wallets, cheaper and more private", "way-code"),

    /** The code on Bitcoin: an address any wallet pays, handed out once asked for, and the silent payment address. */
    BITCOIN("Bitcoin address", "Any Bitcoin wallet, on Bitcoin", "way-bitcoin"),

    /** The silent payment address alone, for wallets paying those only. */
    SILENT("Silent payment address", "Wallets paying silent payments, on Bitcoin", "way-silent"),

    /** A static LNURL of a swap provider's: any wallet pays it, again, while the phone is off. */
    DONATIONS("Donation address", "Any Lightning wallet, again and again, even while you're offline", "way-donations"),

    /** The Lightning Address of an account at a bridge: any wallet pays it, again, into that account. */
    ADDRESS("Lightning Address", "Any Lightning wallet, again and again, into your bridge account", "way-address"),
}

/**
 * Whether what is received `way` is held on a hub's word alone: paid into
 * a hub, as its notes, with no vault protecting or being set up
 * ([hasVault]). Not what is paid on Bitcoin, hers, nor into a bridge
 * account, which says of itself whose word it is held on.
 */
internal fun unprotectedWay(way: Way, contracts: List<Contract>): Boolean =
    (way == Way.CODE || way == Way.LIGHTNING || way == Way.DONATIONS) && !hasVault(contracts)

/** The ways Receive shows a tab of, in its order: the rest are under More. */
internal val TABS = listOf(Way.CODE to "Licash", Way.LIGHTNING to "Lightning", Way.BITCOIN to "Bitcoin")

/** The bare address Receive shows on Bitcoin, for `amount` if any, as a QR code holds it best. */
internal fun bareQr(address: String, amount: Long?): String =
    "BITCOIN:${address.uppercase()}" + (amount?.let { "?amount=${btc(it.toULong())}" } ?: "")

/**
 * The way Receive picks for `amount`: an invoice any wallet pays, if a
 * hub trusted takes `lightning` payments; else the wallet's code.
 */
internal fun picked(amount: Long?, lightning: Boolean): Way =
    if (amount != null && lightning) Way.LIGHTNING else Way.CODE

/**
 * The ways to be paid while a hub trusted takes `lightning` payments, and
 * `silent` ones, and while a provider takes `donations` to the wallet.
 */
internal fun ways(lightning: Boolean, silent: Boolean, donations: Boolean = false, address: Boolean = false): List<Way> =
    listOfNotNull(
        Way.LIGHTNING.takeIf { lightning },
        Way.CODE,
        Way.BITCOIN,
        Way.SILENT.takeIf { silent },
        Way.DONATIONS.takeIf { donations },
        Way.ADDRESS.takeIf { address },
    )

/**
 * The ways not open to the wallet now, each with why: said grayed out
 * under the others, so none is a mystery. `lookingForDonations` and
 * `lookingForLightning` while providers are still asked.
 */
internal fun closedWays(
    lightning: Boolean,
    silent: Boolean,
    donations: Boolean,
    lookingForDonations: Boolean,
    lookingForLightning: Boolean = false,
): List<Pair<Way, String>> = listOfNotNull(
    when {
        lightning -> null
        lookingForLightning -> Way.LIGHTNING to "Looking for a provider…"
        else -> Way.LIGHTNING to "No provider takes Lightning now"
    },
    (Way.SILENT to "Your hubs don't index silent payments").takeIf { !silent },
    when {
        donations -> null
        lookingForDonations -> Way.DONATIONS to "Looking for a provider…"
        else -> Way.DONATIONS to "No provider takes donations now"
    },
)

/** What a donation address takes and costs, and who pays it on, in words. */
internal fun donationWords(address: DonationAddress): String {
    val by = address.name ?: address.provider.substringAfter("://").trimEnd('/')
    val fee = listOfNotNull(
        sat(address.feeBase).takeIf { address.feeBase > 0u },
        percent(address.feePpm).takeIf { address.feePpm > 0u },
    ).joinToString(" + ")
    val paid = when {
        fee.isEmpty() -> "Paid to you in notes by $by, with no fee."
        else -> "Paid to you in notes by $by, less its fee of $fee."
    }
    return when {
        !address.reachable -> "$paid It isn't answering right now: payers may be refused until it does."
        address.stocked -> paid
        else -> "$paid It can't take donations right now: payers are refused until it can."
    }
}

/** The most characters of an invoice's memo, as the hub takes it. */
internal const val MAX_MEMO = 100

/** What is typed as a memo: its words, one space apart, none if blank. */
internal fun memoOf(typed: String): String? =
    typed.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ").take(MAX_MEMO).ifEmpty { null }

/**
 * What the payer of an invoice asked for an amount pays, and what the
 * wallet gets of it: in words, those differing from the amount only.
 * `by` made it: the hub, or a provider.
 */
internal fun invoiceWords(amount: ULong, asks: ULong, gets: ULong, by: String = "the provider"): String? = listOfNotNull(
    "The payer pays ${sat(asks)}".takeIf { asks != amount },
    "You get ${sat(gets)}, $by's fee taken".takeIf { gets != asks },
).joinToString("\n").ifEmpty { null }

/**
 * What to be paid at, as a QR code and one Copy, picked for the payer: for
 * an amount, a Lightning invoice any wallet pays, from a hub taking
 * payments over Lightning; for any amount, the wallet's code, paid in
 * notes. The other ways, an address on Bitcoin any wallet pays among them,
 * one tap away in a sheet. Under it,
 * what it is and the amount asked, and nothing else.
 */
@Composable
fun Receive(engine: Engine, back: () -> Unit) {
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    var amount by rememberSaveable { mutableStateOf<Long?>(null) }
    var code by remember { mutableStateOf<Code?>(null) }
    var bitcoin by remember { mutableStateOf<Code?>(null) }
    // Looked for once, out of sight: a way to be paid only if found.
    var donations by remember { mutableStateOf<DonationAddress?>(null) }
    var lookingForDonations by remember { mutableStateOf(true) }
    // The Lightning Address of a bridge account, if one is named.
    var address by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    // The amount typed in, in place of the QR code: asked for once done.
    var editing by remember { mutableStateOf(false) }
    var typed by remember { mutableStateOf<Long?>(null) }
    // Said to the payer of an invoice, at a hub that says one: typed with the amount.
    var memo by rememberSaveable { mutableStateOf<String?>(null) }
    var typedMemo by remember { mutableStateOf("") }
    val edit = {
        typed = amount
        typedMemo = memo.orEmpty()
        editing = true
    }
    val done = {
        amount = typed
        memo = memoOf(typedMemo)
        editing = false
    }
    var received by remember { mutableStateOf<String?>(null) }
    // Which code to be paid at: 0 the wallet's own, else an extra code's
    // number, separate from it, no one able to tell.
    var codeIndex by rememberSaveable { mutableStateOf(0) }
    var codes by remember { mutableStateOf<List<ExtraCode>>(emptyList()) }
    var pickingCode by rememberSaveable { mutableStateOf(false) }
    var naming by rememberSaveable { mutableStateOf(false) }
    var typedLabel by rememberSaveable { mutableStateOf("") }
    // A new identity being made: seconds, its hubs asked over Tor.
    var creating by remember { mutableStateOf(false) }
    var createError by remember { mutableStateOf<String?>(null) }
    var copied by remember { mutableStateOf(false) }
    var choosing by rememberSaveable { mutableStateOf(false) }
    val ui by engine.ui.collectAsState()
    // A provider's node makes the invoice, hubs making none: looked for
    // once, out of sight.
    var providerLightning by remember { mutableStateOf(false) }
    var lookingForLightning by remember { mutableStateOf(false) }
    LaunchedEffect(ui.hubs) {
        lookingForLightning = true
        providerLightning = engine.providerTakesLightning().getOrDefault(false)
        lookingForLightning = false
    }
    val takesLightning = providerLightning
    val invoicedBy = "the provider"
    val ways = ways(takesLightning, ui.hubs.any { it.silent }, donations != null, address != null)
    // Picked for the amount, unless another way was asked for.
    var chosen by rememberSaveable { mutableStateOf<Way?>(null) }
    val way = chosen?.takeIf { it in ways } ?: picked(amount, takesLightning)
    val lightning = way == Way.LIGHTNING
    // An invoice, made by a hub: for an amount, paid once.
    var invoice by remember { mutableStateOf<LightningInvoice?>(null) }
    val request = invoice?.request?.takeIf { lightning }
    var silentAddress by remember { mutableStateOf<String?>(null) }
    val silent = silentAddress?.takeIf { way == Way.SILENT }
    LaunchedEffect(way == Way.SILENT) {
        if (way == Way.SILENT && silentAddress == null) {
            engine.silentAddress().onSuccess { silentAddress = it }.onFailure { error = explain(it) }
        }
    }
    // No amount, as a silent payment address.
    val anyAmount = way == Way.SILENT || way == Way.DONATIONS || way == Way.ADDRESS
    val shown = when (way) {
        Way.LIGHTNING -> request?.let { way.label to it }
        Way.SILENT -> silent?.let { way.label to it }
        Way.DONATIONS -> donations?.let { way.label to it.lnurl }
        Way.ADDRESS -> address?.let { way.label to it }
        Way.CODE -> code?.let { way.label to it.text }
        Way.BITCOIN -> bitcoin?.address?.let { way.label to it }
    }
    LaunchedEffect(received) {
        codes = engine.codes().getOrDefault(emptyList())
    }
    LaunchedEffect(amount, received, codeIndex) {
        code = null
        error = null
        val asked = amount?.toULong()
        val made = if (codeIndex == 0) engine.code(asked) else engine.extraCode(codeIndex.toUInt(), asked)
        made.onSuccess { code = it }.onFailure { error = explain(it) }
    }
    // Only once asked for: an address handed out is watched from then on,
    // and made again once paid.
    LaunchedEffect(way == Way.BITCOIN, amount, received) {
        bitcoin = null
        if (way != Way.BITCOIN) return@LaunchedEffect
        error = null
        engine.bitcoinCode(amount?.toULong())
            .onSuccess { bitcoin = it }
            .onFailure { error = explain(it) }
    }
    LaunchedEffect(ui.hubs) {
        lookingForDonations = true
        donations = engine.donationAddress().getOrNull()
        lookingForDonations = false
    }
    LaunchedEffect(Unit) { address = engine.bridgeAddress().getOrNull() }
    // Shown, its provider is kept: the same address shows from then on.
    val shownDonations = donations?.lnurl?.takeIf { way == Way.DONATIONS }
    LaunchedEffect(shownDonations) {
        shownDonations?.let { engine.keepDonationAddress(it) }
    }
    // An invoice is what an amount asks for, unless another way was.
    val invoicing = (chosen?.takeIf { it in ways } ?: picked(1, takesLightning)) == Way.LIGHTNING
    val memoed = memo?.takeIf { lightning }
    LaunchedEffect(lightning, amount, memoed) {
        invoice = null
        val asked = amount?.takeIf { lightning } ?: return@LaunchedEffect
        error = null
        engine.askInvoiceFor(asked.toULong(), memoed)
            .onSuccess { invoice = it }
            .onFailure { error = explain(it) }
    }
    // Followed while shown: its notes taken once it is paid.
    LaunchedEffect(invoice?.hash) {
        val hash = invoice?.hash ?: return@LaunchedEffect
        while (true) {
            delay(FOLLOW_MS)
            val followed = engine.followInvoice(hash).getOrNull() ?: continue
            invoice = followed
            when (followed.state) {
                State.DONE -> {
                    received = "Received ${sat(followed.amount)}"
                    amount = null
                    memo = null
                    return@LaunchedEffect
                }
                State.FAILED -> {
                    error = "Not paid: ${followed.reason ?: "canceled"}"
                    return@LaunchedEffect
                }
                State.PENDING -> {}
            }
        }
    }
    LaunchedEffect(copied) {
        if (copied) {
            delay(COPIED_MS)
            copied = false
        }
    }
    DisposableEffect(Unit) {
        engine.eager = true
        engine.poke()
        onDispose { engine.eager = false }
    }
    LaunchedEffect(Unit) {
        engine.events.collect { event -> if (event.received != null) received = event.text }
    }
    if (pickingCode) {
        Sheet("Which identity", dismiss = { pickingCode = false }) {
            Entry(MAIN_IDENTITY, sub = "The one your contacts know", tag = "code-0") {
                pickingCode = false
                codeIndex = 0
            }
            codes.forEach { extra ->
                Entry(extra.label, sub = codeWords(extra), tag = "code-${extra.index}") {
                    pickingCode = false
                    codeIndex = extra.index.toInt()
                }
            }
            Entry("New anonymous identity", sub = "No one can tell it's yours", tag = "new-code") {
                pickingCode = false
                typedLabel = ""
                createError = null
                naming = true
            }
        }
    }
    if (naming) {
        // Open while it is made, which asks its hubs: closed once made, or why not said under the button.
        Sheet("New anonymous identity", dismiss = { naming = false }, dismissable = !creating) {
            val create = {
                labelOf(typedLabel)?.takeIf { !creating }?.let { label ->
                    creating = true
                    createError = null
                    scope.launch {
                        engine.addCode(label)
                            .onSuccess { made ->
                                codes = codes + made
                                codeIndex = made.index.toInt()
                                naming = false
                            }
                            .onFailure { createError = explain(it) }
                        creating = false
                    }
                }
                Unit
            }
            OutlinedTextField(
                value = typedLabel,
                onValueChange = { typedLabel = it.take(MAX_CODE_LABEL) },
                modifier = Modifier.fillMaxWidth().testTag("code-label"),
                singleLine = true,
                label = { Text("Name, only you see it") },
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Sentences,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(onDone = { create() }),
                shape = RoundedCornerShape(14.dp),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                SEPARATE_WORDS,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            BigButton(
                if (creating) "Creating…" else "Create",
                Modifier.fillMaxWidth().testTag("create-code"),
                enabled = labelOf(typedLabel) != null,
                busy = creating,
            ) { create() }
            Waited(rememberWait(creating), Modifier.fillMaxWidth().padding(top = 8.dp), center = true)
            createError?.let { Problem(it) }
            Spacer(Modifier.height(16.dp))
        }
    }
    if (choosing) {
        Sheet("More ways", dismiss = { choosing = false }) {
            // Which identity the Licash code is of.
            if (way == Way.CODE) {
                Entry("Identity", value = codeName(codeIndex.toUInt(), codes), tag = "which-code") {
                    choosing = false
                    pickingCode = true
                }
            }
            ways.filter { it != way && TABS.none { (tab, _) -> tab == it } }.forEach { other ->
                Entry(other.label, sub = other.says, tag = other.tag) {
                    choosing = false
                    chosen = other
                    error = null
                    // An invoice asks for an amount.
                    if (other == Way.LIGHTNING && amount == null) edit() else editing = false
                }
            }
            val closed = closedWays(
                takesLightning,
                ui.hubs.any { it.silent },
                donations != null,
                lookingForDonations,
                lookingForLightning,
            )
            closed.filter { (other, _) -> TABS.none { (tab, _) -> tab == other } }.forEach { (other, why) ->
                Entry(
                    other.label,
                    sub = why,
                    tag = other.tag + "-closed",
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                )
            }
        }
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp)) {
        TopBar("Receive", back)
        Segmented(TABS.map { it.second }, TABS.indexOfFirst { it.first == way }, Modifier.fillMaxWidth()) { i ->
            val tab = TABS[i].first
            if (tab !in ways) {
                // Not open now: why, in place of it.
                error = closedWays(takesLightning, true, true, false, lookingForLightning).find { it.first == tab }?.second
                return@Segmented
            }
            chosen = tab
            error = null
            // An invoice asks for an amount.
            if (tab == Way.LIGHTNING && amount == null) edit() else editing = false
        }
        Column(
            Modifier.fillMaxWidth().weight(1f).verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(16.dp))
            received?.let {
                Cheer(size = 72.dp)
                Spacer(Modifier.height(8.dp))
                Text(
                    it,
                    modifier = Modifier.testTag("received"),
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(16.dp))
            }
            val pending = !editing && error == null && when {
                lightning -> amount != null && request == null
                way == Way.DONATIONS -> donations == null
                way == Way.ADDRESS -> address == null
                way == Way.SILENT -> silent == null
                else -> (if (way == Way.BITCOIN) bitcoin else code) == null
            }
            val wait = rememberWait(pending)
            // In upper case, which a QR code holds in fewer modules.
            when {
                editing -> {
                    Spacer(Modifier.height(32.dp))
                    AmountField(typed, { typed = it }) { done() }
                    Spacer(Modifier.height(16.dp))
                    if (invoicing) {
                        MemoField(typedMemo, invoicedBy, { typedMemo = it }) { done() }
                    }
                }
                lightning && request != null -> QrCode(request.uppercase())
                lightning -> if (amount != null && error == null) Waiting()
                way == Way.DONATIONS -> donations?.let { QrCode(it.lnurl) }
                way == Way.ADDRESS -> address?.let {
                    QrCode("lightning:$it")
                    Spacer(Modifier.height(8.dp))
                    Text(it, modifier = Modifier.testTag("lightning-address"), style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                }
                way == Way.SILENT -> when (silent) {
                    null -> if (error == null) Waiting()
                    else -> {
                        QrCode(silent.uppercase())
                        Spacer(Modifier.height(8.dp))
                        Text(
                            silent,
                            modifier = Modifier.testTag("silent"),
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
                way == Way.BITCOIN -> when (val address = bitcoin?.address) {
                    null -> if (error == null) Waiting()
                    else -> {
                        QrCode(bareQr(address, amount))
                        Spacer(Modifier.height(8.dp))
                        Text(
                            address,
                            modifier = Modifier.testTag("bitcoin-address"),
                            style = MaterialTheme.typography.bodySmall,
                            textAlign = TextAlign.Center,
                        )
                    }
                }
                else -> when (val made = code) {
                    null -> if (error == null) Waiting()
                    else -> QrCode(made.qr)
                }
            }
            if (!editing) Waited(wait, Modifier.fillMaxWidth().padding(top = 8.dp), center = true)
            error?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
            }
            Spacer(Modifier.height(16.dp))
            if (!editing) {
                Text(
                    way.label,
                    modifier = Modifier.testTag("way"),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    when {
                        way == Way.SILENT -> "Any amount, on Bitcoin"
                        way == Way.ADDRESS -> "Any amount"
                        way == Way.DONATIONS -> donations?.let { "${sat(it.min)} to ${sat(it.max)}" } ?: "Any amount"
                        else -> amount?.let { sat(it.toULong()) } ?: if (lightning) "Choose an amount" else "Any amount"
                    },
                    modifier = Modifier.testTag("asking"),
                    style = MaterialTheme.typography.titleMedium,
                )
                memoed?.let {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "\u201c$it\u201d",
                        modifier = Modifier.testTag("memo"),
                        style = MaterialTheme.typography.bodyMedium,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            // What the payer pays and the wallet gets, and what the hub is waiting for: nothing else.
            val made = invoice?.takeIf { request != null }
            val paying = made?.asks?.let { asks -> amount?.let { invoiceWords(it.toULong(), asks, made.amount, invoicedBy) } }
            val waits = invoice?.reason?.takeIf { lightning && amount != null && request == null }
            val says = when (way) {
                Way.SILENT -> "Found once in a block. Each payment lands at an address of its own."
                Way.BITCOIN -> "Any Bitcoin wallet or exchange. Arrives once in a block, about 10 minutes."
                Way.DONATIONS -> donations?.let { donationWords(it) }
                Way.ADDRESS -> "Paid into your bridge account, held on its operator's word."
                else -> paying ?: waits
            }
            says?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
            // Paid into a hub, with no vault: said each time, not on what is paid on Bitcoin or into a bridge.
            if (!editing && unprotectedWay(way, ui.contracts)) {
                Text(
                    RECEIVED_UNPROTECTED,
                    modifier = Modifier.padding(top = 8.dp).testTag("receive-unprotected"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                )
            }
            if (!editing) {
                TextButton(onClick = { choosing = true }, modifier = Modifier.testTag("other-ways")) {
                    Text("More")
                }
            }
        }
        Row(Modifier.padding(vertical = 24.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            if (editing) {
                BigButton("Cancel", Modifier.weight(1f), quiet = true) { editing = false }
                BigButton("Done", Modifier.weight(1f).testTag("done")) { done() }
            } else {
                // A silent payment address or a donation one asks for no amount.
                if (!anyAmount) {
                    BigButton("Amount", Modifier.weight(1f).testTag("set-amount"), quiet = true, onClick = edit)
                }
                BigButton(if (copied) "Copied" else "Copy", Modifier.weight(1f).testTag("copy"), enabled = shown != null) {
                    shown?.let { (label, text) ->
                        val clip = ClipData.newPlainText(label, text)
                        scope.launch { clipboard.setClipEntry(ClipEntry(clip)) }
                        copied = true
                    }
                }
            }
        }
    }
}

/**
 * A memo for the invoice, typed under its amount: its payer reads it, and so
 * do `by`, the hub or provider making it, and its Lightning node, which the
 * words under it say.
 */
@Composable
private fun MemoField(memo: String, by: String, onMemo: (String) -> Unit, done: () -> Unit) {
    OutlinedTextField(
        value = memo,
        onValueChange = { onMemo(it.take(MAX_MEMO)) },
        modifier = Modifier.fillMaxWidth().testTag("memo-field"),
        singleLine = true,
        label = { Text("Memo (optional)") },
        keyboardOptions = KeyboardOptions(
            capitalization = KeyboardCapitalization.Sentences,
            imeAction = ImeAction.Done,
        ),
        keyboardActions = KeyboardActions(onDone = { done() }),
        shape = RoundedCornerShape(14.dp),
    )
    Spacer(Modifier.height(4.dp))
    Text(
        "The payer sees it, and so do $by and its Lightning node.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
}

/** What a separate code is, said where one is made. */
internal const val SEPARATE_WORDS =
    "An address of its own to be paid at: no one can tell it's yours, or link it to your other identities. " +
        "Payments to it move to your balance, less a hub fee."

/** The wallet's own code, as an identity: the one its contacts know. */
internal const val MAIN_IDENTITY = "Main identity"

/** What an extra code took, in words. */
internal fun codeWords(code: ExtraCode): String = when (code.payments) {
    0u -> "Anonymous, nothing received yet"
    1u -> "Anonymous, 1 payment received"
    else -> "Anonymous, ${code.payments} payments received"
}

/** Where a QR code shows once made. */
@Composable
private fun Waiting() {
    Box(
        Modifier.widthIn(max = 316.dp).fillMaxWidth().aspectRatio(1f),
        contentAlignment = Alignment.Center,
    ) { CircularProgressIndicator() }
}
