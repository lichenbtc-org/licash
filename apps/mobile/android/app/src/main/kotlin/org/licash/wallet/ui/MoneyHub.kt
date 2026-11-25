package org.licash.wallet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Activity
import org.licash.core.Contract
import org.licash.core.ContractQuote
import org.licash.core.ContractState
import org.licash.core.Holding
import org.licash.core.Notes
import org.licash.core.PaidContractQuote
import org.licash.wallet.Engine
import org.licash.wallet.behind
import org.licash.wallet.Ui
import org.licash.wallet.carriedOn
import org.licash.wallet.digits
import org.licash.wallet.explain
import org.licash.wallet.sat

/**
 * What is held at one hub, and what to do with it: cash it out, protect
 * it. Its protections, each opening on a tap; what the hub charges, once
 * asked. In advanced mode, the notes held there and moving them to
 * another hub too.
 */
@Composable
internal fun HubPage(
    engine: Engine,
    ui: Ui,
    holding: Holding,
    others: List<Holding>,
    notes: List<Notes>,
    cashOut: (hub: String, amount: ULong?) -> Unit,
    payOwn: (link: String, address: String) -> Unit,
    fail: (String) -> Unit,
    changed: () -> Unit,
    open: (Activity) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val hub = ui.hubs.find { sameHub(it.url, holding.hub) }
    val now = System.currentTimeMillis() / 1000
    // One closed with its hub still shows while its fold is awaited: her notes are out of her balance.
    val covers = ui.contracts.filter {
        sameHub(it.hub, holding.hub) &&
            (ui.developer || shown(it, now) || ui.recoveries.any { r -> r.id == it.id && carriedOn(r) })
    }
    val opening = ui.opening?.let { sameHub(it, holding.hub) } == true
    // Paid for with notes, waiting for its coin on Bitcoin to be set up on.
    val paidHere = ui.paid.filter { sameHub(it.hub, holding.hub) }
    // One being set up shows the step it is at in its own row, once it has one.
    val stepping = covers.any { it.state == ContractState.Opening && it.step != null }
    val held = holding.available + holding.pending
    // Protecting: the hub asked what it costs, then what it quotes.
    var quoting by remember { mutableStateOf(false) }
    val quoteWait = rememberWait(quoting)
    var quote by remember { mutableStateOf<ContractQuote?>(null) }
    var paidQuote by remember { mutableStateOf<PaidContractQuote?>(null) }
    var paying by remember { mutableStateOf(false) }
    var ending by remember { mutableStateOf<Contract?>(null) }
    var forcing by remember { mutableStateOf<Contract?>(null) }
    var shortfall by remember { mutableStateOf<ULong?>(null) }
    // A close of `ending` or `forcing`, asked and not done: the sheet may be left, it goes on.
    var closing by remember { mutableStateOf(false) }
    var closeError by remember { mutableStateOf<String?>(null) }
    val closeWait = rememberWait(closing)
    val feel = rememberFeel()
    var canceling by remember { mutableStateOf<String?>(null) }
    var cancelingBusy by remember { mutableStateOf(false) }
    var allowing by remember { mutableStateOf<String?>(null) }
    var allowingBusy by remember { mutableStateOf(false) }
    var fees by remember { mutableStateOf(false) }
    var moving by remember { mutableStateOf(false) }
    val cover = hubCover(holding.hub, holding, ui.contracts, notes)
    // Not protected and worth a contract: protect it or cash part out, until dismissed.
    var dismissed by remember(holding.hub) { mutableStateOf(engine.prefs.unprotectedDismissed(holding.hub)) }
    val suggest = suggestProtecting(cover, hub, dismissed)

    fun protect() {
        quoting = true
        scope.launch {
            engine.contractQuote(holding.hub).fold({ quote = it }, { fail(explain(it)) })
            quoting = false
        }
    }

    // With no coin on Bitcoin: one paid for with the notes here, of `cap` over `blocks` if chosen, a coin of `coin` sat at least.
    fun payWithNotes(cap: ULong?, blocks: UInt?, coin: ULong? = null) {
        quote = null
        quoting = true
        scope.launch {
            engine.paidContractQuote(holding.hub, cap, blocks, coin).fold({ paidQuote = it }, { fail(explain(it)) })
            quoting = false
        }
    }

    Text(sat(holding.available), modifier = Modifier.padding(horizontal = 4.dp, vertical = 8.dp), style = Heading)
    if (holding.pending > 0uL) Line("Settling", sat(holding.pending), Modifier.padding(horizontal = 4.dp))
    // How much of it its contracts cover, what they leave out, the room they have left.
    cover.says?.let {
        CoverBar(cover, Modifier.padding(horizontal = 4.dp, vertical = 4.dp))
        Text(
            // Its notes counted in advanced mode only.
            if (ui.developer) "$it · ${cover.noteWords}" else it,
            modifier = Modifier.padding(horizontal = 4.dp).testTag("hub-cover"),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    Spacer(Modifier.height(12.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        BigButton(
            "Cash out",
            Modifier.weight(1f).testTag("cash-out"),
            enabled = holding.available > 0uL,
            quiet = true,
        ) { cashOut(holding.hub, null) }
        if (hub?.contracts != null && ui.opening == null && paidHere.isEmpty()) {
            BigButton(
                if (quoting) "Asking…" else "Protect",
                Modifier.weight(1f).testTag("open-contract"),
                busy = quoting,
            ) { protect() }
        }
    }
    Waited(quoteWait, Modifier.padding(horizontal = 4.dp, vertical = 4.dp))
    if (suggest && ui.opening == null) {
        Group("Not protected") {
            Text(
                unprotectedWords(cover.missing, holding.hub),
                modifier = Modifier.padding(vertical = 12.dp).testTag("unprotected"),
                style = MaterialTheme.typography.bodyMedium,
            )
            Row(Modifier.padding(bottom = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                BigButton(
                    if (quoting) "Asking…" else "Protect",
                    Modifier.weight(1f).testTag("suggest-protect"),
                    busy = quoting,
                ) { protect() }
                BigButton("Cash out part", Modifier.weight(1f).testTag("suggest-cash-out"), quiet = true) {
                    cashOut(holding.hub, cover.missing)
                }
            }
            TextButton(onClick = {
                engine.prefs.dismissUnprotected(holding.hub, cover.missing)
                dismissed = cover.missing
            }, Modifier.testTag("suggest-dismiss")) { Text("Not now") }
        }
    }
    if (covers.isNotEmpty() || opening || paidHere.isNotEmpty()) {
        Group("Protection") {
            // Of what is held here, how much those running protect.
            if (covers.any { it.state == ContractState.Protecting }) {
                Line("Protected now", "${digits(covers.sumOf { it.covers })} of ${sat(held)}", tag = "hub-covered")
                Divider()
            }
            covers.forEachIndexed { i, c ->
                if (i > 0) Divider()
                CoverRow(
                    c,
                    ui.chain.height,
                    ui.network,
                    ui.developer,
                    recovery = ui.recoveries.find { it.id == c.id },
                    safety = { engine.contractSafety(c.id).getOrNull() },
                    inspection = { engine.contractInspection(c.id).getOrNull() },
                    explorer = engine::explorerAddress,
                    end = { ending = c },
                    forceClose = { forcing = c },
                    giveUp = { canceling = c.id },
                    allowFee = { allowing = c.id },
                )
            }
            if (opening && !stepping) {
                if (covers.isNotEmpty()) Divider()
                Entry("Setting up", sub = SETUP_TAKES, tag = "opening")
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(bottom = 12.dp))
            }
            paidHere.forEachIndexed { i, p ->
                if (i > 0 || covers.isNotEmpty() || (opening && !stepping)) Divider()
                Entry("Setting up", sub = paidWaits(p.value), tag = "opening-paid")
            }
        }
    }
    Group("") {
        Entry("Fees and limits", onClick = { fees = true })
        if (ui.developer && others.size >= 2 && holding.available > 0uL) {
            Divider()
            Entry("Move to another hub", modifier = Modifier.testTag("move"), onClick = { moving = true })
        }
    }
    if (ui.developer) {
        Group("Notes") {
            if (notes.isEmpty()) Entry("None")
            notes.forEachIndexed { i, n ->
                if (i > 0) Divider()
                Line("${digits(n.denomination)} sat × ${n.count}", sat(n.denomination * n.count), tag = "denomination")
            }
        }
    }

    if (fees && hub != null) HubFees(hub) { fees = false }
    quote?.let { q ->
        // Of terms chosen, if the hub lets them be: paid, whole, from a coin
        // held that a contract takes.
        val range = q.range
        if (range != null) {
            ChooseSheet(
                q,
                range,
                q.coins,
                !behind(ui),
                cover,
                open = { chosen, price ->
                    quote = null
                    engine.openContract(q.hub, price, chosen)
                },
                dismiss = { quote = null },
                hub = engine.called(q.hub),
                payWithNotes = { cap, blocks, coin -> payWithNotes(cap, blocks, coin) },
                intent = intentOf(engine.prefs.intent),
                chooseIntent = { engine.prefs.intent = it.name },
                cashOut = { coin ->
                    quote = null
                    scope.launch {
                        engine.bitcoinAddress().fold(
                            { payOwn("bitcoin:$it?amount=${btc(coin)}", it) },
                            { fail(explain(it)) },
                        )
                    }
                },
            )
        } else {
            ProtectSheet(
                q,
                engine.called(q.hub),
                open = {
                    quote = null
                    engine.openContract(q.hub, q.price)
                },
                payWithNotes = { payWithNotes(null, null) },
                cashOutFirst = {
                    quote = null
                    scope.launch {
                        engine.bitcoinAddress().fold(
                            { payOwn("bitcoin:$it?amount=${btc(q.price + FIXED_PART)}", it) },
                            { fail(explain(it)) },
                        )
                    }
                },
                dismiss = { quote = null },
            )
        }
    }
    paidQuote?.let { q ->
        PaidSheet(
            q,
            engine.called(q.hub),
            busy = paying,
            pay = {
                paying = true
                scope.launch {
                    val paid = engine.openPaidContract(q)
                    paidQuote = null
                    paying = false
                    paid.onFailure { fail(explain(it)) }
                }
            },
            dismiss = { if (!paying) paidQuote = null },
        )
    }
    ending?.let { c ->
        EndSheet(
            c,
            ui.chain.height,
            holding.available,
            busy = closing,
            error = closeError,
            wait = closeWait,
            cashOut = {
                ending = null
                cashOut(c.hub, null)
            },
            close = {
                closing = true
                closeError = null
                scope.launch {
                    engine.closeContract(c.id).await()
                        .onSuccess {
                            ending = null
                            feel.confirm()
                        }
                        .onFailure {
                            closeError = explain(it)
                            feel.reject()
                        }
                    closing = false
                }
            },
            dismiss = {
                ending = null
                closeError = null
            },
        )
    }
    forcing?.let { c ->
        LaunchedEffect(c.id) { shortfall = engine.challengeShortfall().getOrNull() }
        ForceSheet(
            c,
            held,
            shortfall,
            busy = closing,
            error = closeError,
            wait = closeWait,
            force = {
                closing = true
                closeError = null
                scope.launch {
                    engine.forceClose(c.id).await()
                        .onSuccess {
                            forcing = null
                            shortfall = null
                            feel.confirm()
                        }
                        .onFailure {
                            closeError = explain(it)
                            feel.reject()
                        }
                    closing = false
                }
            },
            dismiss = {
                forcing = null
                shortfall = null
                closeError = null
            },
        )
    }
    canceling?.let { id ->
        GiveUpSheet(
            recovery = ui.recoveries.find { it.id == id },
            busy = cancelingBusy,
            confirm = {
                cancelingBusy = true
                scope.launch {
                    engine.giveUpRecovery(id).fold(
                        { canceling = null },
                        { canceling = null; fail("Couldn't cancel closing: ${explain(it)}") },
                    )
                    cancelingBusy = false
                }
            },
            dismiss = { if (!cancelingBusy) canceling = null },
        )
    }
    allowing?.let { id ->
        AllowFeeSheet(
            recovery = ui.recoveries.find { it.id == id },
            busy = allowingBusy,
            allow = { sats ->
                allowingBusy = true
                scope.launch {
                    engine.allowPublicationFee(id, sats).fold(
                        { allowing = null },
                        { allowing = null; fail("Couldn't allow the fee: ${explain(it)}") },
                    )
                    allowingBusy = false
                }
            },
            dismiss = { if (!allowingBusy) allowing = null },
        )
    }
    if (moving) {
        MoveSheet(
            engine,
            holding,
            others,
            // Under way: its line of the history shows how it goes, to the end.
            moved = { line ->
                moving = false
                changed()
                open(line)
            },
            dismiss = { moving = false },
        )
    }
}
