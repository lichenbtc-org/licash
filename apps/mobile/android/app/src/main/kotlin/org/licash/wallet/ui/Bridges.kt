package org.licash.wallet.ui

import android.content.ClipData
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.AppTerms
import org.licash.core.Bridge
import org.licash.core.BridgeAccount
import org.licash.core.BridgeApp
import org.licash.core.BudgetPeriod
import org.licash.core.ConnectedApp
import org.licash.core.ImportSource
import org.licash.core.ImportedNotes
import org.licash.core.State
import org.licash.core.TopUpRules
import org.licash.wallet.Engine
import org.licash.wallet.explain
import org.licash.wallet.sat

internal const val BRIDGES_MEANS =
    "A bridge keeps an account apps pay and are paid through over Nostr Wallet Connect, " +
        "topped up out of your notes. What it holds rests on its operator's word: keep little there."

private const val EXPORT_MEANS =
    "Freezes the bridge for good: it pays nothing out from then on, until its operator unfreezes it. " +
        "Its notes come to this phone, for a recovery of your contract with its hub to claim " +
        "should the hub stop cooperating, within what your own notes leave of the contract's cap."

/** The budget periods an app's budget starts again after, as chosen. */
internal val PERIODS = listOf(
    BudgetPeriod.DAILY to "Day",
    BudgetPeriod.WEEKLY to "Week",
    BudgetPeriod.MONTHLY to "Month",
    BudgetPeriod.NEVER to "Ever",
)

/** A bridge's name: as it says, else its host. */
internal fun bridgeName(bridge: Bridge): String = bridge.name?.takeIf { it.isNotBlank() } ?: name(bridge.url)

/** An amount of whole sat typed, if one: blank or anything else, none. */
internal fun satOf(typed: String): ULong? = typed.trim().replace(",", "").toULongOrNull()

/**
 * The top-up rules typed: below `below`, up to `upTo`, `daily` at most a
 * day, each fee at most `maxFee` if typed. None if they make no sense.
 */
internal fun rulesOf(below: String, upTo: String, daily: String, maxFee: String): TopUpRules? {
    val b = satOf(below) ?: return null
    val u = satOf(upTo) ?: return null
    val d = satOf(daily) ?: return null
    val fee = if (maxFee.isBlank()) null else satOf(maxFee) ?: return null
    if (u == 0uL || b > u || d == 0uL) return null
    return TopUpRules(b, u, d, fee)
}

/** What top-up rules do, in words. */
internal fun rulesWords(rules: TopUpRules?): String = when (rules) {
    null -> "Topped up by hand"
    else -> "Below ${sat(rules.below)}, up to ${sat(rules.upTo)}, ${sat(rules.daily)} a day at most"
}

/** What an app may do and has spent, in words. */
internal fun appWords(app: BridgeApp): String {
    if (app.revoked) return "Revoked"
    val may = when {
        app.pay && app.receive -> "Pays and is paid"
        app.pay -> "Pays"
        else -> "Is paid"
    }
    val budget = app.budget?.let { b ->
        val per = when (app.period) {
            BudgetPeriod.DAILY -> " a day"
            BudgetPeriod.WEEKLY -> " a week"
            BudgetPeriod.MONTHLY -> " a month"
            BudgetPeriod.YEARLY -> " a year"
            else -> ""
        }
        "${sat(app.spent)} of ${sat(b)}$per"
    }
    return listOfNotNull(may, budget).joinToString(", ")
}

/** Notes imported, in words. */
internal fun importedWords(imported: ImportedNotes): String {
    val said = "${imported.added} notes worth ${sat(imported.amount)} imported"
    val known = if (imported.known > 0u) ", ${imported.known} imported before" else ""
    val unknown = if (imported.unknown > 0u) ", ${imported.unknown} of a hub you don't use left out" else ""
    return said + known + unknown
}

/**
 * Connected apps: the bridges added, each opening its account; one added
 * by its address and pairing code; and the notes imported of frozen ones.
 */
@Composable
internal fun BridgesPage(engine: Engine) {
    val scope = rememberCoroutineScope()
    var bridges by remember { mutableStateOf<List<Bridge>?>(null) }
    var open by remember { mutableStateOf<Bridge?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    fun load() {
        scope.launch {
            engine.bridges().onSuccess { bridges = it; error = null }.onFailure { error = explain(it) }
        }
    }
    LaunchedEffect(Unit) { load() }
    open?.let { bridge ->
        BackHandler { open = null; load() }
        BridgePage(engine, bridge) { open = null; load() }
        return
    }
    Say(BRIDGES_MEANS)
    bridges?.takeIf { it.isNotEmpty() }?.let { list ->
        Group("") {
            list.forEachIndexed { i, bridge ->
                if (i > 0) Divider()
                Entry(bridgeName(bridge), Modifier.testTag("bridge"), sub = rulesWords(bridge.rules), onClick = { open = bridge })
            }
        }
    }
    error?.let { Problem(it) }
    Group("Add a bridge") { AddBridge(engine) { open = it; load() } }
    Group("Notes imported") { ImportedPage(engine) }
}

/** A bridge added by its address, and its operator's pairing code if it keeps only its owner's. */
@Composable
private fun AddBridge(engine: Engine, added: (Bridge) -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }
    var pairing by remember { mutableStateOf("") }
    var adding by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    Field(url, "Bridge address", "bridge-url", KeyboardType.Uri) { url = it }
    Field(pairing, "Pairing code, if it asks one", "bridge-pairing") { pairing = it }
    FilledTonalButton(
        enabled = url.isNotBlank() && !adding,
        onClick = {
            adding = true
            scope.launch {
                engine.addBridge(url.trim(), pairing.trim().ifEmpty { null })
                    .onSuccess { url = ""; pairing = ""; error = null; feel.confirm(); added(it) }
                    .onFailure { error = explain(it); feel.reject() }
                adding = false
            }
        },
        modifier = Modifier.padding(vertical = 8.dp).testTag("add-bridge"),
    ) { Text(if (adding) "…" else "Add") }
    Waited(rememberWait(adding))
    error?.let { Problem(it) }
}

/** A bridge: its account, topping it up, its rules, apps and address; exporting its notes, or forgetting it. */
@Composable
private fun BridgePage(engine: Engine, start: Bridge, gone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var bridge by remember { mutableStateOf(start) }
    var account by remember { mutableStateOf<BridgeAccount?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var naming by remember { mutableStateOf(false) }
    var connecting by remember { mutableStateOf(false) }
    var revoking by remember { mutableStateOf<BridgeApp?>(null) }
    var exporting by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf(false) }
    val url = bridge.url
    fun reload() {
        scope.launch {
            engine.bridgeAccount(url).onSuccess { account = it; error = null }.onFailure { error = explain(it) }
        }
    }
    LaunchedEffect(url) { reload() }
    Text(bridgeName(bridge), Modifier.padding(top = 8.dp), style = MaterialTheme.typography.titleMedium)
    Text(
        url,
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Group("Account") {
        Line("Balance", account?.let { sat(it.balance) } ?: "…", tag = "bridge-balance")
        account?.takeIf { it.reserved > 0uL }?.let { Line("Held for payments", sat(it.reserved)) }
        if (bridge.addresses) {
            Line(
                "Lightning Address",
                account?.lightningAddress ?: "None",
                tag = "bridge-address",
                onClick = { naming = true },
            )
        }
    }
    error?.let { Problem(it) }
    Group("Move") {
        AmountAction("Top up", "bridge-top-up") { amount ->
            engine.topUpBridge(url, amount, null).map { "Topping up: ${sat(it.credits)} credited once paid" }
                .also { reload() }
        }
        AmountAction("Withdraw", "bridge-withdraw") { amount ->
            engine.withdrawBridge(url, amount).map {
                when (it) {
                    State.DONE -> "Withdrawn"
                    State.PENDING -> "Withdrawing"
                    State.FAILED -> "The bridge could not pay it"
                }
            }.also { reload() }
        }
    }
    Group("Automatic top-ups") {
        RulesEditor(bridge.rules) { rules ->
            engine.setBridgeRules(url, rules).onSuccess { bridge = bridge.copy(rules = rules) }
        }
    }
    Group("Apps") {
        account?.apps?.filter { !it.revoked }?.forEach { app ->
            Entry(app.name, Modifier.testTag("bridge-app"), sub = appWords(app), onClick = { revoking = app })
            Divider()
        }
        TextButton(onClick = { connecting = true }, modifier = Modifier.testTag("connect-app")) { Text("Connect an app") }
    }
    // An open bridge's notes are every account's: only its operator exports them.
    if (!bridge.open) {
        Group("") {
            Entry("Freeze and export its notes", tag = "export-bridge", color = MaterialTheme.colorScheme.error) {
                exporting = true
            }
        }
    }
    Group("") {
        Entry("Remove bridge", tag = "remove-bridge", color = MaterialTheme.colorScheme.error) { removing = true }
    }
    if (naming) NameAddress(engine, url, account?.lightningAddress) { named ->
        naming = false
        named?.let { account = it }
    }
    if (connecting) ConnectApp(engine, url) { connecting = false; reload() }
    revoking?.let { app ->
        Confirm(app.name, appWords(app), "Revoke", dismiss = { revoking = null }) {
            engine.revokeApp(url, app.key).map { "Revoked" }.also { reload() }
        }
    }
    if (exporting) {
        Confirm("Freeze and export", EXPORT_MEANS, "Freeze and export", dismiss = { exporting = false; reload() }) {
            engine.exportBridge(url).map { importedWords(it.imported) }
        }
    }
    if (removing) {
        Confirm(
            "Remove bridge",
            "Forgets the bridge here. Its account stays there, found again by adding it.",
            "Remove",
            dismiss = { removing = false },
        ) {
            engine.removeBridge(url).map { "Removed" }.also { r -> if (r.isSuccess) gone() }
        }
    }
}

/** An amount typed, and `action` done with it: what it came to said under it. */
@Composable
private fun AmountAction(action: String, tag: String, run: suspend (ULong) -> Result<String>) {
    val scope = rememberCoroutineScope()
    var typed by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var said by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val feel = rememberFeel()
    Row(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it },
            modifier = Modifier.weight(1f).testTag("$tag-amount"),
            singleLine = true,
            label = { Text("Amount, sat") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done),
            shape = RoundedCornerShape(14.dp),
        )
        FilledTonalButton(
            enabled = satOf(typed)?.let { it > 0uL } == true && !busy,
            onClick = {
                val amount = satOf(typed) ?: return@FilledTonalButton
                busy = true
                scope.launch {
                    run(amount)
                        .onSuccess { said = it; error = null; typed = ""; feel.confirm() }
                        .onFailure { error = explain(it); said = null; feel.reject() }
                    busy = false
                }
            },
            modifier = Modifier.testTag(tag),
        ) { Text(if (busy) "…" else action) }
    }
    Waited(rememberWait(busy))
    said?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
    error?.let { Problem(it) }
}

/** The rules topping a bridge up each round, typed; saved, or turned off. */
@Composable
private fun RulesEditor(rules: TopUpRules?, save: suspend (TopUpRules?) -> Result<Unit>) {
    val scope = rememberCoroutineScope()
    var below by remember(rules) { mutableStateOf(rules?.below?.toString().orEmpty()) }
    var upTo by remember(rules) { mutableStateOf(rules?.upTo?.toString().orEmpty()) }
    var daily by remember(rules) { mutableStateOf(rules?.daily?.toString().orEmpty()) }
    var maxFee by remember(rules) { mutableStateOf(rules?.maxFee?.toString().orEmpty()) }
    var error by remember { mutableStateOf<String?>(null) }
    val typed = rulesOf(below, upTo, daily, maxFee)
    Text(rulesWords(rules), Modifier.padding(vertical = 8.dp).testTag("bridge-rules"), style = MaterialTheme.typography.bodyMedium)
    Field(below, "Below, sat", "rules-below", KeyboardType.Number) { below = it }
    Field(upTo, "Up to, sat", "rules-up-to", KeyboardType.Number) { upTo = it }
    Field(daily, "A day at most, sat", "rules-daily", KeyboardType.Number) { daily = it }
    Field(maxFee, "Fee at most, sat (optional)", "rules-max-fee", KeyboardType.Number) { maxFee = it }
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        FilledTonalButton(
            enabled = typed != null && typed != rules,
            onClick = { scope.launch { save(typed).onSuccess { error = null }.onFailure { error = explain(it) } } },
            modifier = Modifier.testTag("save-rules"),
        ) { Text("Save") }
        if (rules != null) {
            TextButton(
                onClick = { scope.launch { save(null).onSuccess { error = null }.onFailure { error = explain(it) } } },
                modifier = Modifier.testTag("rules-off"),
            ) { Text("Turn off") }
        }
    }
    error?.let { Problem(it) }
}

/** The account's Lightning Address named, or cleared: the account as it then is, or none if left. */
@Composable
private fun NameAddress(engine: Engine, url: String, address: String?, done: (BridgeAccount?) -> Unit) {
    val scope = rememberCoroutineScope()
    var typed by remember { mutableStateOf(address?.substringBefore('@').orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    fun name(to: String?) {
        busy = true
        scope.launch {
            engine.nameBridgeAddress(url, to).onSuccess { done(it) }.onFailure { error = explain(it) }
            busy = false
        }
    }
    Sheet("Lightning Address", dismiss = { done(null) }, dismissable = !busy) {
        Say("Any Lightning wallet pays it, again and again, into this account, and zaps are receipted on Nostr.")
        Field(typed, "Name", "address-name") { typed = it }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FilledTonalButton(enabled = typed.isNotBlank() && !busy, onClick = { name(typed.trim()) }, modifier = Modifier.testTag("save-address")) {
                Text("Save")
            }
            if (address != null) {
                TextButton(enabled = !busy, onClick = { name(null) }) { Text("Clear") }
            }
        }
        Waited(rememberWait(busy))
        error?.let { Problem(it) }
    }
}

/** An app connected on the terms chosen: its URI shown once, to copy or scan into it. */
@Composable
private fun ConnectApp(engine: Engine, url: String, done: () -> Unit) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboard.current
    var name by remember { mutableStateOf("") }
    var pay by remember { mutableStateOf(true) }
    var receive by remember { mutableStateOf(true) }
    var budget by remember { mutableStateOf("") }
    var period by remember { mutableStateOf(1) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var connected by remember { mutableStateOf<ConnectedApp?>(null) }
    var copied by remember { mutableStateOf(false) }
    // Its URI holds the key it pays with: kept out of screenshots.
    Sheet("Connect an app", dismiss = done, dismissable = !busy, secure = true) {
        when (val made = connected) {
            null -> {
                Field(name, "App name", "app-name") { name = it }
                Toggle("Pays", pay) { pay = it }
                Toggle("Is paid", receive) { receive = it }
                Field(budget, "Budget, sat (optional)", "app-budget", KeyboardType.Number) { budget = it }
                if (budget.isNotBlank()) {
                    Segmented(PERIODS.map { it.second }, period, Modifier.fillMaxWidth().padding(vertical = 8.dp)) { period = it }
                }
                val typedBudget = if (budget.isBlank()) null else satOf(budget)
                val ready = name.isNotBlank() && (pay || receive) && (budget.isBlank() || typedBudget != null)
                BigButton("Connect", Modifier.fillMaxWidth().padding(top = 8.dp).testTag("connect"), enabled = ready && !busy, busy = busy) {
                    busy = true
                    val terms = AppTerms(name.trim(), pay, receive, null, typedBudget, PERIODS[period].first, null)
                    scope.launch {
                        engine.connectApp(url, terms).onSuccess { connected = it; error = null }.onFailure { error = explain(it) }
                        busy = false
                    }
                }
            }
            else -> {
                Say("Scan or paste this into ${made.app.name}. It is shown only now: whoever has it pays from this account.")
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    QrCode(made.uri, description = "Connection for ${made.app.name}")
                }
                Spacer(Modifier.height(12.dp))
                BigButton(if (copied) "Copied" else "Copy", Modifier.fillMaxWidth().testTag("copy-uri")) {
                    scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("NWC", made.uri))) }
                    copied = true
                }
                TextButton(onClick = done, modifier = Modifier.testTag("connected-done")) { Text("Done") }
            }
        }
        Waited(rememberWait(busy))
        error?.let { Problem(it) }
    }
}

/** The notes imported of frozen bridges, each discarded once; more imported from an export pasted. */
@Composable
private fun ImportedPage(engine: Engine) {
    val scope = rememberCoroutineScope()
    var sources by remember { mutableStateOf<List<ImportSource>>(emptyList()) }
    var discarding by remember { mutableStateOf<ImportSource?>(null) }
    var typed by remember { mutableStateOf("") }
    var said by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    fun load() {
        scope.launch { engine.importedNotes().onSuccess { sources = it } }
    }
    LaunchedEffect(Unit) { load() }
    sources.forEach { s ->
        val sub = "${s.notes} notes, ${sat(s.amount)}" + if (s.claimed > 0u) ", ${s.claimed} claimed" else ""
        Entry(s.source.take(16) + "…", Modifier.testTag("imported"), sub = sub, onClick = { discarding = s })
        Divider()
    }
    Field(typed, "Export from a bridge's operator", "import-text") { typed = it }
    FilledTonalButton(
        enabled = typed.isNotBlank(),
        onClick = {
            scope.launch {
                engine.importNotes(typed.trim())
                    .onSuccess { said = importedWords(it); error = null; typed = ""; load() }
                    .onFailure { error = explain(it); said = null }
            }
        },
        modifier = Modifier.padding(vertical = 8.dp).testTag("import-notes"),
    ) { Text("Import") }
    said?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
    error?.let { Problem(it) }
    discarding?.let { s ->
        Confirm(
            "Discard notes imported",
            "Forgets them here, for the bridge to be unfrozen: a note claimed in two contracts is void in both.",
            "Discard",
            dismiss = { discarding = null; load() },
        ) {
            engine.discardImported(s.source).map { "$it notes forgotten" }
        }
    }
}

/** A question in a sheet: `action` done once confirmed, what it came to said, the sheet left to close. */
@Composable
private fun Confirm(title: String, text: String, action: String, dismiss: () -> Unit, run: suspend () -> Result<String>) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var said by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    Sheet(title, dismiss = dismiss, dismissable = !busy) {
        Say(text)
        when (val done = said) {
            null -> BigButton(action, Modifier.fillMaxWidth().testTag("confirm"), danger = true, enabled = !busy, busy = busy) {
                busy = true
                scope.launch {
                    run().onSuccess { said = it; error = null }.onFailure { error = explain(it) }
                    busy = false
                }
            }
            else -> {
                Text(done, Modifier.testTag("confirmed"), style = MaterialTheme.typography.bodyLarge)
                TextButton(onClick = dismiss) { Text("Done") }
            }
        }
        error?.let { Problem(it) }
    }
}

/** A field of one line, labeled. */
@Composable
private fun Field(value: String, label: String, tag: String, type: KeyboardType = KeyboardType.Text, set: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = set,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).testTag(tag),
        singleLine = true,
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = type, imeAction = ImeAction.Next),
        shape = RoundedCornerShape(14.dp),
    )
}
