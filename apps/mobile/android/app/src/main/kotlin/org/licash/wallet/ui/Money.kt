package org.licash.wallet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Holding
import org.licash.core.Notes
import org.licash.wallet.Engine
import org.licash.wallet.behind
import org.licash.wallet.Ui
import org.licash.wallet.explain
import org.licash.wallet.digits
import org.licash.wallet.sat

/** Where [Money] is `at`, for what is on Bitcoin: a hub's page is at its URL. */
const val ON_BITCOIN = "bitcoin"

/**
 * Where the money is: how much is protected and how much is not, and what
 * is held at each hub and on Bitcoin. A row opens its page, `at` a hub's
 * URL or [ON_BITCOIN], through `go`: what is held there, and what to do
 * with it. `cashOut` pays out on Bitcoin what is held at a hub, as much as
 * the owner chooses, the amount suggested if any; `payOwn` pays
 * a link to an address of this wallet's, the address given.
 */
@Composable
fun Money(
    engine: Engine,
    ui: Ui,
    at: String?,
    go: (String?) -> Unit,
    cashOut: (hub: String, amount: ULong?) -> Unit,
    payOwn: (link: String, address: String) -> Unit,
    back: () -> Unit,
) {
    var holdings by remember { mutableStateOf<List<Holding>?>(null) }
    var notes by remember { mutableStateOf<List<Notes>>(emptyList()) }
    var visited by remember { mutableStateOf<List<Holding>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var changed by remember { mutableStateOf(0) }
    LaunchedEffect(ui.balance, ui.history, ui.hubs, changed) {
        engine.holdings().onSuccess { holdings = it }.onFailure { holdings = emptyList(); error = explain(it) }
        engine.notes().onSuccess { notes = it }.onFailure { error = explain(it) }
        engine.visited().onSuccess { visited = it }.onFailure { error = explain(it) }
    }
    // A hub the wallet uses holds nothing until it is known to hold something.
    val held = ui.hubs.map { hub ->
        holdings.orEmpty().find { sameHub(it.hub, hub.url) } ?: Holding(hub.url, 0uL, 0uL)
    } + holdings.orEmpty().filter { h -> ui.hubs.none { sameHub(it.url, h.hub) } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp)) {
        when (at) {
            null -> TopBar("Balance", back)
            ON_BITCOIN -> TopBar("On Bitcoin", back = { go(null) }) {
                Info("On Bitcoin", ON_BITCOIN_MEANS)
            }
            else -> TopBar(engine.called(at), back = { go(null) })
        }
        error?.let {
            Text(
                it,
                modifier = Modifier.padding(horizontal = 4.dp).testTag("error"),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        val fail = { why: String -> error = why }
        when (at) {
            null -> Summary(engine, ui, held, notes, visited, go) { changed++ }
            ON_BITCOIN -> OnBitcoin(engine, ui, go)
            else -> HubPage(
                engine,
                ui,
                holding = held.find { sameHub(it.hub, at) } ?: Holding(at, 0uL, 0uL),
                others = held,
                notes = notes.filter { sameHub(it.hub, at) },
                cashOut = cashOut,
                payOwn = payOwn,
                fail = fail,
                changed = { changed++ },
            )
        }
        Spacer(Modifier.height(48.dp))
    }
}

/** Whether two URLs name one hub: contracts keep it without a last slash. */
internal fun sameHub(a: String, b: String): Boolean = a.trimEnd('/') == b.trimEnd('/')

/** All of it, how much is protected, and where it is held. */
@Composable
private fun Summary(
    engine: Engine,
    ui: Ui,
    held: List<Holding>,
    notes: List<Notes>,
    visited: List<Holding>,
    go: (String?) -> Unit,
    changed: () -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    val b = ui.balance
    val share = protection(b)
    val scope = rememberCoroutineScope()
    // A hub only visited the owner asks about, by its URL.
    var adding by remember { mutableStateOf<String?>(null) }
    var joining by remember { mutableStateOf(false) }
    var joinError by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    val joinWait = rememberWait(joining)
    Text(sat(share.total), modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp), style = Heading)
    if (share.total > 0uL) {
        Row(
            Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 4.dp).height(10.dp).clip(RoundedCornerShape(5.dp))
                .background(colors.surfaceContainerHighest),
        ) {
            val safe = share.percent
            if (safe > 0) Box(Modifier.weight(safe.toFloat()).fillMaxHeight().background(colors.primary))
            if (safe < 100) Box(Modifier.weight((100 - safe).toFloat()).fillMaxHeight().background(colors.outline))
        }
        // Safe on Bitcoin apart from protected by contracts: bitcoin held
        // protects notes once it pays for a contract.
        val split = safeSplit(share, b.onchain + b.moving + b.opening)
        if (split.bitcoin > 0uL) {
            Share(Glyphs.bitcoin, colors.primary, "On Bitcoin", split.bitcoin, "safe-onchain", SAFE_ONCHAIN_MEANS)
        }
        Share(Glyphs.shield, colors.primary, PROTECTED_BY_CONTRACTS, split.contracts, "protected", PROTECTED_MEANS)
        Share(Glyphs.shieldOff, colors.onSurfaceVariant, NOT_PROTECTED, share.open, "credit", NOT_PROTECTED_MEANS)
        // Not while a contract is set up: it is that coin's being protected, as On Bitcoin says.
        if (share.open > 0uL && b.onchain > 0uL && ui.opening == null) {
            Entry(
                "Protect it with your bitcoin",
                sub = "A contract paid with a coin on Bitcoin covers notes here",
                tag = "protect-with-bitcoin",
                onClick = { go(ON_BITCOIN) },
            )
        }
    }
    // Notes are how it is held, not what: counted in advanced mode only.
    // In line with the total above it, not the groups' insides.
    if (ui.developer) Line("Notes", digits(noteCount(notes)), Modifier.padding(horizontal = 4.dp), tag = "note-count")
    Group("") {
        held.forEach { holding ->
            // How much of it its contracts cover, and the notes it is in.
            val cover = hubCover(holding.hub, holding, ui.contracts, notes)
            Entry(
                engine.called(holding.hub),
                value = sat(holding.available + holding.pending),
                sub = listOfNotNull(cover.says, cover.noteWords.takeIf { ui.developer && cover.notes > 0uL })
                    .joinToString(" · ").ifEmpty { null },
                tag = "holding",
                onClick = { go(holding.hub) },
            )
            CoverBar(cover, Modifier.padding(bottom = 12.dp))
            Divider()
        }
        // Where bitcoin held is added to the balance: said, since nothing else leads here.
        Entry(
            "On Bitcoin",
            value = sat(b.onchain + b.moving + b.opening),
            sub = ADD_ONCHAIN.takeIf { b.onchain > 0uL && b.moving == 0uL && ui.opening == null },
            tag = "onchain",
            onClick = { go(ON_BITCOIN) },
        )
    }
    if (visited.isNotEmpty()) {
        Group("Not in your balance") {
            visited.forEachIndexed { i, holding ->
                if (i > 0) Divider()
                Entry(
                    name(holding.hub),
                    value = sat(holding.available + holding.pending),
                    tag = "visited",
                    onClick = { adding = holding.hub },
                )
            }
        }
    }
    adding?.let { url ->
        Sheet(name(url), dismiss = { adding = null; joinError = null }, dismissable = !joining) {
            Say("Left over from paying someone at this hub. Add the hub to use it.")
            // Stays while the hub is added; closed once it is, else why not under it.
            BigButton(
                if (joining) "Adding…" else "Add hub",
                Modifier.fillMaxWidth().testTag("add-visited"),
                busy = joining,
            ) {
                joining = true
                joinError = null
                scope.launch {
                    engine.addHub(url)
                        .onSuccess {
                            adding = null
                            feel.confirm()
                        }
                        .onFailure {
                            joinError = explain(it)
                            feel.reject()
                        }
                    changed()
                    joining = false
                }
            }
            Waited(joinWait)
            joinError?.let { Problem(it) }
        }
    }
}

/** How bitcoin comes to be held, said while none is. */
internal const val NOTHING_ONCHAIN = "Receive at a Bitcoin address, then add it here"

/** What the On Bitcoin page does with bitcoin held, said under its row. */
internal const val ADD_ONCHAIN = "Add it to your balance, protected or not"

internal fun noteCount(notes: List<Notes>): ULong = notes.sumOf { it.count.toULong() }

/** A share of the balance: its glyph and name, how much, and what it means on a tap. */
@Composable
private fun Share(icon: ImageVector, tint: Color, label: String, amount: ULong, tag: String, means: String) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(start = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, Modifier.size(20.dp), tint = tint)
        Spacer(Modifier.width(12.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Info(label, means)
        Spacer(Modifier.weight(1f))
        Text(sat(amount), modifier = Modifier.testTag(tag), style = Amounts)
    }
}

/**
 * What is held on Bitcoin, by where it stands, and what is on its way: to
 * protect, as offered ([Ui.offer]), or to add to the balance unprotected,
 * once warned.
 */
@Composable
private fun OnBitcoin(engine: Engine, ui: Ui, go: (String?) -> Unit) {
    val b = ui.balance
    val scope = rememberCoroutineScope()
    val coming = ui.incoming.sumOf { it.amount }
    var choosing by remember { mutableStateOf(false) }
    var warned by remember { mutableStateOf(false) }
    // Adding without protection, once confirmed: the sheet stays while it is done.
    var adding by remember { mutableStateOf(false) }
    var addError by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    val addWait = rememberWait(adding)
    Text(
        sat(b.onchain + b.moving + b.opening),
        modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp),
        style = Heading,
    )
    // What each is called, how much, and its tag for the tests.
    val rows = listOf(
        Triple("In your wallet", b.onchain, "kept"),
        Triple("Being added", b.moving, "moving"),
        Triple("Change coming back", b.opening, "change"),
        Triple("Arriving", coming, "coming"),
    ).filter { it.second > 0uL }
    Group("") {
        if (rows.isEmpty()) Entry("Nothing here", sub = NOTHING_ONCHAIN)
        rows.forEachIndexed { i, (label, amount, tag) ->
            if (i > 0) Divider()
            Line(label, sat(amount), tag = tag)
        }
    }
    val offer = ui.offer?.takeIf { ui.opening == null }
    if (offer != null) {
        Spacer(Modifier.height(20.dp))
        BigButton("Add to balance, protected", Modifier.fillMaxWidth().testTag("offer-protect")) { choosing = true }
    } else if (b.onchain > 0uL && ui.opening == null) {
        // None offered, perhaps because it is too little for the price: the hub's own page
        // says what protecting costs and what it takes, hub by hub.
        val hubs = ui.hubs.filter { it.contracts != null }
        if (hubs.isNotEmpty()) {
            Group("Protect at") {
                hubs.forEachIndexed { i, hub ->
                    if (i > 0) Divider()
                    Entry(engine.called(hub.url), tag = "protect-at", onClick = { go(hub.url) })
                }
            }
        }
    }
    if (b.onchain > 0uL && b.moving == 0uL) {
        Spacer(Modifier.height(if (offer != null) 8.dp else 20.dp))
        BigButton("Add without protection", Modifier.fillMaxWidth().testTag("move-in"), quiet = true) { warned = true }
    }
    if (choosing && offer != null) OfferSheet(engine, offer, !behind(ui)) { choosing = false }
    if (warned) {
        Sheet("Not protected", dismiss = { warned = false; addError = null }, dismissable = !adding) {
            Say(UNPROTECTED_MOVE)
            BigButton(
                if (adding) "Adding…" else "Add anyway",
                Modifier.fillMaxWidth().testTag("move-in-anyway"),
                danger = true,
                busy = adding,
            ) {
                adding = true
                addError = null
                scope.launch {
                    engine.moveLargest()
                        .onSuccess {
                            warned = false
                            feel.confirm()
                        }
                        .onFailure {
                            addError = explain(it)
                            feel.reject()
                        }
                    adding = false
                }
            }
            Waited(addWait)
            addError?.let { Problem(it) }
        }
    }
}

/** What adding Bitcoin to the balance with no protection risks. */
internal const val UNPROTECTED_MOVE = "In your balance, it is held at your hub: if the hub fails or " +
    "refuses to pay, it is lost. Protection recovers it on Bitcoin instead. Keep it here, or protect it first. " +
    "Your largest coin moves in whole, never joined with another."

/** What money on Bitcoin is, said on its page: safe already, but not spendable in Licash until added. */
internal const val ON_BITCOIN_MEANS = "Bitcoin you hold yourself: already safe, but paid only on Bitcoin, " +
    "slowly. Add it to your balance to pay in Licash: protected, through a contract at a hub that " +
    "covers it, or without protection, on the hub's word."

/** A hub of the wallet's, by the name it announced when added, else by its address. */
internal fun Engine.called(url: String): String = hubName(url) ?: name(url)
