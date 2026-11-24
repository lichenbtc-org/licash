package org.licash.wallet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.ContractRange
import org.licash.core.FeesRaised
import org.licash.core.FoundHub
import org.licash.core.Hub
import org.licash.core.HubsFound
import org.licash.core.Network
import org.licash.core.NoteOptimization
import org.licash.wallet.Engine
import org.licash.wallet.Ui
import org.licash.wallet.explain
import org.licash.wallet.digits
import org.licash.wallet.feeOf
import org.licash.wallet.percent
import org.licash.wallet.sat

/*
 * Hubs, wherever one is chosen or looked at: those announced to pick
 * from, one added by its address, and what one charges. Shared by the
 * first run, which has none yet, and by Settings.
 */

/** What a hub is, said where one is chosen. */
const val HUB_MEANS = "A hub holds your balance and moves it for you. Up to what you protect, you can take it back " +
    "on Bitcoin without the hub. You can add more hubs later."

/** A hub in a line under its name: its fee on a payment, and what else it does. */
/**
 * A name a hub announced, as shown: its words one space apart, at most 40
 * characters, without control or formatting ones, none if blank. Its own
 * word only: its address goes with it.
 */
internal fun shownName(announced: String): String? =
    // No control or formatting characters, which could turn what follows around.
    announced.filterNot { it.isISOControl() && !it.isWhitespace() || Character.getType(it) == Character.FORMAT.toInt() }
        .split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ").take(40).trim().ifEmpty { null }

internal fun about(hub: Hub): String = listOfNotNull(
    paying(hub).let { if (it == "None") "No fee" else "Fee $it" },
    hub.lightning?.let { "Lightning" },
    hub.contracts?.let { "Protection" },
).joinToString(" · ")

/** How many announced hubs did not answer, and whether Tor would reach them: nothing if all did. */
internal fun unanswered(found: HubsFound, tor: Boolean): String? {
    if (found.silent == 0u) return null
    val more = if (found.silent == 1u) "1 more did not answer" else "${found.silent} more did not answer"
    return if (!tor && found.silentOnion > 0u) "$more: try with Tor on" else more
}

/**
 * What a hub charges and takes, in a sheet: only what it does. Its address,
 * to copy, `full`. What it `raised` since agreed, if anything, first, to
 * `approve`.
 */
@Composable
internal fun HubFees(
    hub: Hub,
    full: Boolean = false,
    raised: FeesRaised? = null,
    approve: (FeesRaised) -> Unit = {},
    optimize: (() -> Unit)? = null,
    approving: Boolean = false,
    approveError: String? = null,
    approveWait: Wait? = null,
    dismiss: () -> Unit,
) {
    val blockSecs = LocalBlockSeconds.current
    Sheet(if (full) name(hub.url) else "Fees and limits", dismiss, dismissable = !approving) {
        if (full) {
            SelectionContainer {
                Text(
                    hub.url,
                    modifier = Modifier.padding(bottom = 8.dp).testTag("hub-url"),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        raised?.let { r ->
            Group("Raised fees") {
                raises(r).forEachIndexed { i, raise ->
                    if (i > 0) Divider()
                    Entry(raise.what, value = raise.now, sub = "Was ${raise.agreed}", tag = "raised")
                }
            }
            Problem(RAISED_MEANS, error = false)
            BigButton(
                if (approving) "Approving…" else "Approve fees",
                Modifier.fillMaxWidth().testTag("approve-fees"),
                busy = approving,
            ) { approve(r) }
            Waited(approveWait)
            approveError?.let { Problem(it) }
        }
        // What a payment costs, a section a direction: limits under each.
        Group("Paying") {
            Entry("In Licash", value = paying(hub), tag = "fee-pay")
            val most = hub.lightningPay
            if (hub.lightning != null || most != null) {
                Divider()
                Entry(
                    "Over Lightning",
                    value = hub.lightning?.let { charge(it.pay) } ?: "Yes",
                    sub = most?.let { "Up to ${sat(it)}" },
                )
            }
        }
        if (hub.lightning != null || hub.deposits != null) {
            Group("Receiving") {
                hub.lightning?.let {
                    Entry("Over Lightning", value = charge(it.receive), sub = between(it.receiveRange.min, it.receiveRange.max))
                }
                hub.deposits?.let { range ->
                    if (hub.lightning != null) Divider()
                    Entry(
                        "On Bitcoin",
                        value = hub.depositFee?.let { charge(it) } ?: "Yes",
                        sub = between(range.min, range.max),
                    )
                }
            }
        }
        hub.contracts?.let {
            Group("Protection") {
                // Terms chosen within its range, priced by cap and length;
                // else its one fixed contract.
                val range = it.range
                if (range != null) {
                    // A row each, short enough not to be cut: the (i) on the
                    // protect sheet says what interest and the reserve are.
                    Entry("Opening fee", value = sat(range.fee), tag = "protection-price")
                    Divider()
                    Entry("Interest", value = interestOf(range), tag = "protection-interest")
                    Divider()
                    Entry("Reserve, refundable", value = sat(range.reserve), tag = "protection-reserve")
                    Divider()
                    Entry("Covers", value = between(range.minCap, range.maxCap), tag = "protection-cap")
                    Divider()
                    Entry(
                        "For",
                        value = "${span(range.minBlocks.toLong(), blockSecs)} to ${span(range.maxBlocks.toLong(), blockSecs)}",
                        tag = "protection-for",
                    )
                } else {
                    Entry("Price", value = feeOf(it.price, it.cap))
                    Divider()
                    Entry("Covers up to", value = sat(it.cap), tag = "protection-cap")
                    Divider()
                    Entry("For", value = span(it.blocks.toLong(), blockSecs))
                }
            }
        }
        if (full) {
            Group("Held payments") {
                Entry("Holding one", value = charge(hub.lockFee))
                Divider()
                Entry("Refunding one", value = charge(hub.refundFee))
            }
        }
        optimize?.let { action ->
            TextButton(onClick = action, modifier = Modifier.testTag("optimize-notes")) { Text("Optimize notes") }
        }
    }
}

/** Explicit optimization, with the shown fee as a hard execution cap. */
@Composable
internal fun OptimizeNotes(engine: Engine, hub: Hub, dismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var quote by remember(hub.url) { mutableStateOf<NoteOptimization?>(null) }
    var loading by remember(hub.url) { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(hub.url) {
        engine.optimizationQuote(hub.url).onSuccess { quote = it }.onFailure { error = explain(it) }
        loading = false
    }
    val wait = rememberWait(loading || busy)
    Sheet("Optimize notes", dismiss, dismissable = !busy) {
        Say("Smaller notes leave receiving room and help recovery fit its note limit. Automatic shaping normally handles this.")
        Say("Doing it manually bypasses privacy rest and the daily fee budget, but not the fees you agreed to.")
        when {
            loading -> Say("Checking the notes…")
            quote == null && error == null -> Say("No optimization is available, or one is still pending.")
            else -> quote?.let { q ->
                Line("Notes", "${q.notesBefore} to ${q.notesAfter}")
                Line("Reminting", sat(q.value))
                Line("Fee", feeOf(q.fee, q.value))
                if (q.id != null) {
                    Say("Optimized. Its fee is recorded in History.")
                } else {
                    BigButton("Optimize for ${sat(q.fee)}", Modifier.fillMaxWidth().testTag("confirm-optimize"), enabled = !busy) {
                        busy = true
                        error = null
                        scope.launch {
                            engine.optimizeNotes(q).onSuccess { quote = it }.onFailure { error = explain(it) }
                            busy = false
                        }
                    }
                }
            }
        }
        Waited(wait)
        error?.let { Problem(it) }
        TextButton(onClick = dismiss, enabled = !busy) { Text("Done") }
    }
}

/** A hub's interest by the year, on its own part of the cover, then on hers if it charges any. */
internal fun interestOf(range: ContractRange): String =
    "${percent(range.ppmYear.toULong())} a year" +
        if (range.ppmYearFunded == 0u) "" else ", ${percent(range.ppmYearFunded.toULong())} on yours"

/** From `min` to `max`, in sat: a range a hub takes. */
private fun between(min: ULong, max: ULong): String = "${digits(min)} to ${sat(max)}"

/** A hub added by its address, typed or pasted: `action` names the button. */
@Composable
internal fun AddHub(engine: Engine, action: String = "Add") {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var adding by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    Row(
        Modifier.fillMaxWidth().padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = url,
            onValueChange = { url = it },
            modifier = Modifier.weight(1f).testTag("hub-address"),
            singleLine = true,
            label = { Text("Hub address") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
            shape = RoundedCornerShape(14.dp),
        )
        FilledTonalButton(
            enabled = url.isNotBlank() && !adding,
            onClick = {
                adding = true
                scope.launch {
                    engine.addHub(url.trim())
                        .onSuccess { url = ""; error = null; feel.confirm() }
                        .onFailure { error = explain(it); feel.reject() }
                    adding = false
                }
            },
            modifier = Modifier.testTag("add-address"),
        ) { Text(if (adding) "…" else action) }
    }
    Waited(rememberWait(adding))
    error?.let { Problem(it) }
}

/**
 * The hubs announced on Nostr, on the relays the hubs used name and on the
 * default ones, to pick from: a tap shows one, and adds it once the owner
 * says so. Looked for at once if `auto`, else once asked. Those announced
 * but not answering are only counted.
 */
@Composable
internal fun FoundHubs(engine: Engine, ui: Ui, auto: Boolean) {
    val scope = rememberCoroutineScope()
    var found by remember { mutableStateOf<HubsFound?>(null) }
    var looking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    // The one picked, in its sheet, until it is added; `joining` while it is.
    var adding by remember { mutableStateOf<FoundHub?>(null) }
    var joining by remember { mutableStateOf(false) }
    var joinError by remember { mutableStateOf<String?>(null) }
    // The last added, said under the list.
    var joined by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    val lookWait = rememberWait(looking)
    val joinWait = rememberWait(joining)
    fun look() {
        looking = true
        error = null
        scope.launch {
            engine.findHubs().onSuccess { found = it }.onFailure { error = explain(it) }
            looking = false
        }
    }
    if (auto) LaunchedEffect(Unit) { look() }
    // Those added since looking drop out.
    val shown = found?.hubs?.filter { f -> ui.hubs.none { sameHub(it.url, f.hub.url) } }
    shown?.forEach { f ->
        Entry(
            f.name ?: name(f.hub.url),
            modifier = Modifier.testTag("add-found"),
            sub = about(f.hub),
            onClick = { adding = f },
        )
        Divider()
    }
    if (shown?.isEmpty() == true) {
        // For a first hub, none to start with: said plainly, and the way left.
        Entry(if (ui.hubs.isEmpty()) "No hubs available" else "None found", tag = "none-found")
        noneFound(ui.hubs.isEmpty())?.let { Problem(it, error = false) }
    }
    found?.let { unanswered(it, ui.tor) }?.let { Problem(it, error = false) }
    error?.let { Problem(it) }
    TextButton(enabled = !looking, onClick = ::look, modifier = Modifier.testTag("find-hubs")) {
        Text(if (looking) "Looking…" else if (found == null) "Find hubs" else "Look again")
    }
    Waited(lookWait, Modifier.padding(start = 12.dp))
    joined?.let {
        Text("Added $it", Modifier.padding(start = 12.dp, top = 8.dp).testTag("joined"), style = MaterialTheme.typography.bodyMedium)
    }
    adding?.let { f ->
        val named = f.name ?: name(f.hub.url)
        Sheet(named, dismiss = { adding = null; joinError = null }, dismissable = !joining) {
            Text(
                f.hub.url,
                modifier = Modifier.padding(bottom = 8.dp).testTag("found-url"),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Line("Paying", paying(f.hub))
            Say("Up to what you protect, your balance here can be taken back on Bitcoin without the hub. Above it, it rests on the hub's word.")
            // Stays here while it is added, which asks the hub a few times:
            // closed once it is, or why not said under the button.
            BigButton(
                if (joining) "Adding…" else "Add hub",
                Modifier.fillMaxWidth().testTag("add-hub"),
                busy = joining,
            ) {
                joining = true
                joinError = null
                scope.launch {
                    engine.addHub(f.hub.url, f.name)
                        .onSuccess {
                            joined = named
                            adding = null
                            feel.confirm()
                        }
                        .onFailure {
                            joinError = explain(it)
                            feel.reject()
                        }
                    joining = false
                }
            }
            Waited(joinWait)
            joinError?.let { Problem(it) }
        }
    }
}

/**
 * Why no hub was found, for a wallet with `none` yet: where to get one.
 * Null where nothing more is to be said.
 */
internal fun noneFound(none: Boolean): String? = if (none) NONE_AVAILABLE else null

/** No hub found for a wallet without one: what to do instead. */
internal const val NONE_AVAILABLE = "Ask a hub's operator for its address and enter it below."

/** A hub shipped with the app, to start with: its address and the name shown. */
internal data class Known(val url: String, val name: String)

/**
 * The hubs recommended on `network`, to start with in a tap: the first
 * that answers is used. None where none is known; then hubs are looked
 * for on Nostr instead.
 */
internal fun recommendedHubs(network: Network): List<Known> = when (network) {
    Network.MUTINYNET -> listOf(Known("https://hub.licash-mutinynet.sgn.space", "sgn.space"))
    else -> emptyList()
}

/**
 * No hub yet: the one recommended for the wallet's network, in a tap; else,
 * or once asked for another, those announced on Nostr; else one by the
 * address its operator gave. What a hub is, once asked.
 */
@Composable
internal fun FirstHub(engine: Engine, ui: Ui) {
    val recommended = recommendedHubs(ui.network)
    val scope = rememberCoroutineScope()
    val feel = rememberFeel()
    var others by rememberSaveable { mutableStateOf(false) }
    var adding by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.align(Alignment.CenterHorizontally), verticalAlignment = Alignment.CenterVertically) {
            Text("Choose a hub", modifier = Modifier.testTag("choose-hub"), style = MaterialTheme.typography.headlineSmall)
            Info("Hubs", HUB_MEANS)
        }
        if (recommended.isNotEmpty() && !others) {
            val first = recommended.first()
            Column(
                Modifier.fillMaxWidth().padding(top = 16.dp).clip(RoundedCornerShape(16.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainer).padding(16.dp),
            ) {
                Text("Recommended", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text(first.name, modifier = Modifier.testTag("recommended-hub"), style = MaterialTheme.typography.titleLarge)
                Text(
                    "Holds your balance and moves it for you.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(16.dp))
                BigButton(
                    if (adding) "Connecting…" else "Use this hub",
                    Modifier.fillMaxWidth().testTag("use-recommended"),
                    busy = adding,
                    enabled = !adding,
                ) {
                    adding = true
                    error = null
                    scope.launch {
                        // The first that answers.
                        var last: Throwable? = null
                        for (known in recommended) {
                            val added = engine.addHub(known.url, known.name)
                            if (added.isSuccess) {
                                feel.confirm()
                                adding = false
                                return@launch
                            }
                            last = added.exceptionOrNull()
                        }
                        feel.reject()
                        error = last?.let(::explain)
                        // Not reached: the others to choose from instead.
                        others = true
                        adding = false
                    }
                }
                Waited(rememberWait(adding))
            }
            TextButton(
                onClick = { others = true },
                modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 8.dp).testTag("choose-another"),
                enabled = !adding,
            ) { Text("Choose another") }
        } else {
            error?.let { Problem("${name(recommended.first().url)} did not answer: $it") }
            Group("") { FoundHubs(engine, ui, auto = true) }
            Group("Or its address") { AddHub(engine, "Connect") }
        }
    }
}

/** Something that went wrong, or to know, in a line under what it is about. */
@Composable
internal fun Problem(text: String, error: Boolean = true) {
    Text(
        text,
        modifier = Modifier.padding(top = 8.dp, bottom = 12.dp),
        style = MaterialTheme.typography.bodySmall,
        color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}
