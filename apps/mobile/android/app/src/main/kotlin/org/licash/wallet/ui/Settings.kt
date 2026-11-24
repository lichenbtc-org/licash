package org.licash.wallet.ui

import android.content.Context
import android.text.format.Formatter
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.licash.core.ExitConsent
import org.licash.core.Hub
import org.licash.wallet.AppLog
import org.licash.wallet.BuildConfig
import org.licash.wallet.Engine
import org.licash.wallet.Storage
import org.licash.wallet.Ui
import org.licash.wallet.digits
import org.licash.wallet.explain
import org.licash.wallet.exportLogs
import org.licash.wallet.percent
import org.licash.wallet.storage

/** A page of Settings, behind a row of its first. */
private enum class Page(val title: String) {
    Hubs("Hubs"),
    Backup("Backup"),
    Cold("Cold storage"),
    Bitcoin("Bitcoin"),
    Tor("Tor"),
    About("About"),
    Advanced("Advanced"),
}

private const val TOR_MEANS =
    "Reaches hubs, relays and Bitcoin through Tor, each apart: slower, and hides where you are from them."

private const val ADVANCED_MEANS =
    "Shows how payments are made, the notes held, providers to choose from, " +
        "the Bitcoin light client's settings and the log."

/**
 * Settings: on its first page, a row for each kind of thing, each with a
 * glyph on a tile. What is on or off switches there; what holds more
 * opens a page of its own.
 */
@Composable
fun Settings(engine: Engine, ui: Ui, balance: () -> Unit, back: () -> Unit) {
    var page by rememberSaveable { mutableStateOf<Page?>(null) }
    // The tour again, as shown before the wallet was made.
    var touring by rememberSaveable { mutableStateOf(false) }
    BackHandler(enabled = page != null || touring) { if (touring) touring = false else page = null }
    if (touring) {
        Tour {
            // The rest of the onboarding again: Home guides to a vault, for a wallet holding already too.
            if (ui.wallet && ui.hubs.isNotEmpty()) {
                BigButton("Guide me to a vault", Modifier.fillMaxWidth().testTag("guide-start")) {
                    engine.prefs.guideSince = System.currentTimeMillis() / 1000
                    touring = false
                    back()
                }
                Spacer(Modifier.height(8.dp))
            }
            BigButton("Done", Modifier.fillMaxWidth().testTag("tour-done"), quiet = ui.wallet && ui.hubs.isNotEmpty()) {
                touring = false
            }
            Spacer(Modifier.height(24.dp))
        }
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
    ) {
        when (val p = page) {
            null -> {
                TopBar("Settings", back)
                Overview(engine, ui, tour = { touring = true }) { page = it }
            }
            else -> {
                TopBar(p.title, back = { page = null })
                when (p) {
                    Page.Hubs -> HubsPage(engine, ui)
                    Page.Backup -> BackupPage(engine, ui)
                    Page.Cold -> ColdPage(engine, ui)
                    Page.Bitcoin -> BitcoinPage(engine, ui)
                    Page.Tor -> TorPage(engine, ui)
                    Page.About -> About(ui)
                    Page.Advanced -> Advanced(engine, ui, balance)
                }
            }
        }
        Spacer(Modifier.height(48.dp))
    }
}

/**
 * The first page: the backup and hubs; how Licash works and about it;
 * Bitcoin and Tor folded under Network, what is wrong with them in sight;
 * advanced mode.
 */
@Composable
private fun Overview(engine: Engine, ui: Ui, tour: () -> Unit, open: (Page) -> Unit) {
    val scope = rememberCoroutineScope()
    var torFailed by remember { mutableStateOf<String?>(null) }
    Group("") {
        if (ui.wallet) {
            Entry("Backup", icon = Glyphs.key, tag = "backup") { open(Page.Backup) }
            Divider()
        }
        Entry("Hubs", value = "${ui.hubs.size}", icon = Glyphs.bank, tag = "hubs") { open(Page.Hubs) }
        // An advanced feature: shown in advanced mode, or once set up.
        val cold = ui.cold
        if (ui.wallet && (ui.developer || cold != null)) {
            Divider()
            Entry(
                "Cold storage",
                value = cold?.let { org.licash.wallet.sat(it.balance) } ?: "Off",
                sub = cold?.let { "Withdraws past ${org.licash.wallet.sat(it.threshold)}" },
                icon = Icons.Filled.Lock,
                tag = "cold",
            ) { open(Page.Cold) }
        }
    }
    Group("") {
        Entry("How Licash works", sub = "The tour, and a guide to a vault", icon = Glyphs.vault, tag = "how-it-works", onClick = tour)
        Divider()
        Entry("About", icon = Icons.Outlined.Info, tag = "about") { open(Page.About) }
    }
    // What is wrong stays in sight; the rest only once asked.
    ui.problem?.let { Problem(it) }
    torFailed?.let { Problem(it) }
    More("Network", Modifier.padding(top = 8.dp).testTag("network")) {
        Group("") {
            val (state, detail) = status(ui, ui.developer)
            Entry("Bitcoin", value = state, sub = detail, icon = Glyphs.bitcoin, tag = "chain") { open(Page.Bitcoin) }
            Divider()
            Toggle("Tor", ui.tor, sub = "Hides where you are, slower", icon = Icons.Filled.Lock, means = TOR_MEANS) { on ->
                torFailed = null
                scope.launch { engine.setTor(on).onFailure { torFailed = explain(it) } }
            }
            if (ui.tor) {
                Divider()
                val tor = ui.torStatus
                val value = when {
                    tor == null -> "Starting"
                    tor.ready -> "Connected"
                    tor.blocked != null -> "Stuck"
                    else -> "${tor.percent}%"
                }
                Entry("Tor status", value = value, tag = "tor-status") { open(Page.Tor) }
            }
        }
    }
    Group("") {
        Toggle("Advanced mode", ui.developer, icon = Glyphs.code, means = ADVANCED_MEANS) { engine.setDeveloper(it) }
        if (ui.developer) {
            Divider()
            Entry("Advanced", icon = Icons.Filled.Build, tag = "advanced") { open(Page.Advanced) }
        }
    }
}

/** The hubs used, each opening what it charges; one added by its address, or found. */
@Composable
private fun HubsPage(engine: Engine, ui: Ui) {
    val scope = rememberCoroutineScope()
    var shown by remember { mutableStateOf<Hub?>(null) }
    var optimizing by remember { mutableStateOf<Hub?>(null) }
    // Approving a hub's fees: its sheet stays while it is done.
    var approving by remember { mutableStateOf(false) }
    var approveError by remember { mutableStateOf<String?>(null) }
    val approveWait = rememberWait(approving)
    val feel = rememberFeel()
    fun raised(hub: Hub) = ui.raised.find { it.hub == hub.url }
    if (ui.hubs.isNotEmpty()) {
        Group("") {
            ui.hubs.forEachIndexed { i, hub ->
                if (i > 0) Divider()
                // Named as it announced itself, its address under it, else by its address.
                val announced = engine.hubName(hub.url)
                val sub = when {
                    raised(hub) != null -> "Raised its fees: approve to pay there"
                    announced != null -> name(hub.url)
                    else -> about(hub)
                }
                Entry(announced ?: name(hub.url), Modifier.testTag("hub"), sub = sub, onClick = { shown = hub })
            }
        }
    }
    Group("Add a hub") { AddHub(engine) }
    Group("More hubs") { FoundHubs(engine, ui, auto = false) }
    shown?.let { hub ->
        HubFees(
            hub,
            full = true,
            raised = raised(hub),
            approve = { r ->
                approving = true
                approveError = null
                scope.launch {
                    engine.approveFees(r)
                        .onSuccess {
                            shown = null
                            feel.confirm()
                        }
                        .onFailure {
                            approveError = explain(it)
                            feel.reject()
                        }
                    approving = false
                }
            },
            optimize = if (ui.developer) ({ shown = null; optimizing = hub }) else null,
            approving = approving,
            approveError = approveError,
            approveWait = approveWait,
        ) {
            shown = null
            approveError = null
        }
    }
    optimizing?.let { hub -> OptimizeNotes(engine, hub) { optimizing = null } }
}

/** The app's version, what it keeps on the phone, and its logs to share. */
@Composable
private fun About(ui: Ui) {
    val context = LocalContext.current
    var kept by remember { mutableStateOf<Storage?>(null) }
    var sizes by remember { mutableStateOf(false) }
    var exporting by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { kept = withContext(Dispatchers.IO) { storage(context) } }
    Group("") {
        Line("Version", "${BuildConfig.VERSION_NAME} (${BuildConfig.COMMIT})", tag = "version")
        Divider()
        Entry("Storage", value = kept?.let { bytes(context, it.total) } ?: "…", tag = "storage") {
            // Opened once measured, if tapped before.
            sizes = true
        }
        Divider()
        Entry("Export logs", tag = "export-logs") {
            exporting = null
            runCatching { context.startActivity(exportLogs(context, ui)) }
                .onFailure {
                    AppLog.warn("exporting the logs", it)
                    exporting = "Could not export the logs: ${it.message ?: it.javaClass.simpleName}"
                }
        }
        exporting?.let { Problem(it) }
    }
    val k = kept
    if (sizes && k != null) Sheet("Storage", dismiss = { sizes = false }) { StorageUsed(k, ui.developer) }
}

/** What the app keeps on the phone, by what keeps it; in advanced mode, each network's light client. */
@Composable
private fun StorageUsed(k: Storage, advanced: Boolean) {
    val context = LocalContext.current
    val size = { b: Long -> bytes(context, b) }
    Line("Total", size(k.total), tag = "storage-total")
    Divider()
    Line("Wallet", size(k.wallet))
    Line("Bitcoin light client", size(k.chain), tag = "storage-chain")
    if (advanced) k.chains.forEach { (name, b) -> Line("  $name", size(b)) }
    if (k.tor > 0) Line("Tor", size(k.tor))
    Line("Logs", size(k.logs))
    Line("Cache", size(k.cache))
    if (k.other > 0) Line("Other", size(k.other))
    k.app?.let { Line("The app itself", size(it), tag = "storage-app") }
}

private fun bytes(context: Context, bytes: Long): String = Formatter.formatShortFileSize(context, bytes)

/**
 * How the app catches up with Bitcoin, step by step, and the block the
 * wallet's payments are looked for from.
 */
@Composable
private fun BitcoinPage(engine: Engine, ui: Ui) {
    var birthday by remember { mutableStateOf<UInt?>(null) }
    LaunchedEffect(ui.scan?.from) { birthday = engine.birthday().getOrNull() }
    Group("") { SyncStages(engine, ui) }
    ui.problem?.let { Problem(it) }
    Group("") {
        Line("Network", named(ui.network))
        Divider()
        Line("Wallet birthday", birthday?.let { "Block ${digits(it.toULong())}" } ?: "Not known yet", tag = "birthday")
        ui.scan?.let {
            Divider()
            Line("Payments looked for up to", "Block ${digits((it.next.toLong() - 1).coerceAtLeast(0).toULong())}")
        }
    }
}

/**
 * How the app's Tor client stands: how far it is in connecting, what
 * it is doing, and why it seems stuck; and starting it afresh, after a yes.
 */
@Composable
private fun TorPage(engine: Engine, ui: Ui) {
    val scope = rememberCoroutineScope()
    var asking by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        while (true) {
            engine.live()
            delay(2_000)
        }
    }
    val tor = ui.torStatus
    Group("") {
        if (!ui.tor) {
            Line("Status", "Off")
        } else {
            Line("Status", if (tor?.ready == true) "Connected" else "Connecting", tag = "tor-state")
            Divider()
            Line("Progress", tor?.let { "${it.percent}%" } ?: "…", tag = "tor-percent")
            tor?.let {
                if (!it.ready) LinearProgressIndicator(progress = { it.percent.toFloat() / 100f }, modifier = Modifier.fillMaxWidth())
                Divider()
                Text(
                    it.summary,
                    modifier = Modifier.padding(vertical = 12.dp).testTag("tor-summary"),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                it.blocked?.let { why -> Problem("Stuck: $why") }
            }
        }
    }
    if (ui.tor) {
        Group("") {
            Entry("Reset Tor", sub = "Forget what Tor learned and connect afresh", tag = "reset-tor") {
                error = null
                asking = true
            }
            error?.let { Problem(it) }
        }
    }
    if (asking) {
        Sheet("Reset Tor?", dismiss = { asking = false }, dismissable = !busy) {
            Say("Forgets what Tor learned of its network and connects from the start. Use it when Tor does not connect. Nothing you hold is touched.")
            BigButton(if (busy) "Resetting…" else "Reset", Modifier.fillMaxWidth().testTag("reset-tor-confirm"), enabled = !busy) {
                busy = true
                scope.launch {
                    engine.resetTor().onFailure { error = explain(it) }
                    busy = false
                    asking = false
                }
            }
            Spacer(Modifier.height(12.dp))
            BigButton("Cancel", Modifier.fillMaxWidth(), quiet = true, enabled = !busy) { asking = false }
        }
    }
}

/**
 * How far the app follows Bitcoin, in a word, and what there is to add:
 * in advanced mode, the block it is at and the nodes it hears from.
 */
internal fun status(ui: Ui, developer: Boolean): Pair<String, String?> {
    val chain = ui.chain
    val nodes = "${chain.peers} " + if (chain.peers == 1L) "node" else "nodes"
    return when {
        // The pinned headers come first, from no node: said as on Home.
        chain.importing in 0..99 -> "Downloading" to null
        chain.importing >= 100 -> "Setting up" to null
        chain.peers == 0L -> "Connecting" to null
        !chain.synced -> "Catching up" to "Block ${chain.height}, $nodes".takeIf { developer }
        ui.scan != null && ui.scan.next.toInt() <= chain.height ->
            "Checking" to "Block ${ui.scan.next} of ${chain.height}".takeIf { developer }
        else -> "Up to date" to "Block ${chain.height}, $nodes".takeIf { developer }
    }
}

/**
 * For those testing the app: the balance's notes, the log, what renewing
 * notes may cost, the light client's settings, and deleting the wallet.
 */
@Composable
private fun Advanced(engine: Engine, ui: Ui, balance: () -> Unit) {
    val scope = rememberCoroutineScope()
    var logs by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf(false) }
    var erasing by remember { mutableStateOf(false) }
    var eraseError by remember { mutableStateOf<String?>(null) }
    val eraseWait = rememberWait(erasing)
    val feel = rememberFeel()
    Group("") {
        Entry("Balance and notes", onClick = balance)
        Divider()
        Toggle("Show the log", logs) { logs = it }
        if (logs) {
            Text(
                AppLog.recent().takeLast(80).joinToString("\n"),
                modifier = Modifier.padding(bottom = 12.dp),
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                lineHeight = 12.sp,
            )
        }
    }
    if (ui.wallet) Group("Renewing notes") { RenewLimit(engine) }
    if (ui.wallet) {
        Group("Recovery safety") {
            ExitMargin(engine)
            Divider()
            ExitConsentEntry(engine, ui.contracts.isNotEmpty())
        }
    }
    Group("Bitcoin light client") {
        LightClient(engine)
        Divider()
        ResetChain(engine)
    }
    Group("") {
        Entry("Delete wallet", tag = "delete-wallet", color = MaterialTheme.colorScheme.error) { deleting = true }
    }
    if (deleting) {
        Sheet("Delete this wallet?", dismiss = { deleting = false; eraseError = null }, dismissable = !erasing) {
            Say("What it holds is lost for good, unless you saved a backup file.")
            // Stays while it is done: then the first screen shows in its place.
            BigButton(
                if (erasing) "Deleting…" else "Delete",
                Modifier.fillMaxWidth().testTag("delete"),
                danger = true,
                busy = erasing,
            ) {
                erasing = true
                eraseError = null
                scope.launch {
                    engine.delete()
                        .onSuccess { deleting = false }
                        .onFailure {
                            eraseError = explain(it)
                            feel.reject()
                        }
                    erasing = false
                }
            }
            Waited(eraseWait)
            eraseError?.let { Problem(it) }
            Spacer(Modifier.height(12.dp))
            BigButton("Cancel", Modifier.fillMaxWidth(), enabled = !erasing, quiet = true) { deleting = false; eraseError = null }
        }
    }
}

/**
 * The most the wallet pays, on its own, to renew notes a hub that
 * restarted can no longer unlink: in parts per million of them.
 */
@Composable
private fun RenewLimit(engine: Engine) {
    val scope = rememberCoroutineScope()
    var ppm by remember { mutableStateOf(engine.renewLimit()?.toString() ?: "") }
    var error by remember { mutableStateOf<String?>(null) }
    var saved by remember { mutableStateOf(false) }
    val asked = ppm.trim().toUIntOrNull()
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Most to pay", style = MaterialTheme.typography.bodyLarge)
        Info(
            "Renewing notes",
            "A hub that restarted can no longer unlink the notes it issued before. " +
                "The wallet swaps them for new ones there within this share, or if its fees are at most " +
                "1 sat base, this rate and 0.1 sat per output. Protection's agreed fees take precedence. 0 means free only.",
        )
    }
    Row(
        Modifier.fillMaxWidth().padding(bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Field(
            ppm,
            { ppm = it; error = null; saved = false },
            "Parts per million",
            error ?: asked?.let { "${percent(it.toULong())} of the notes renewed" } ?: "0 for free renewals only",
            Modifier.weight(1f),
            failed = error != null || (ppm.isNotBlank() && asked == null),
            number = true,
        )
        FilledTonalButton(
            enabled = asked != null && !saved,
            onClick = {
                if (asked != null) {
                    scope.launch {
                        engine.setRenewLimit(asked).onSuccess { saved = true }.onFailure { error = explain(it) }
                    }
                }
            },
        ) { Text(if (saved) "Saved" else "Save") }
    }
}

/** A holder-owned planning margin: what exits plan with once she consents, never consent itself. */
@Composable
private fun ExitMargin(engine: Engine) {
    val scope = rememberCoroutineScope()
    var days by remember { mutableStateOf(engine.prefs.exitMarginDays.toString()) }
    var saved by remember { mutableStateOf(false) }
    val value = days.toIntOrNull()?.takeIf { it in 1..30 }
    Say("Time reserved for a forced close to play out (your exit margin), about 14 days by default. Nothing closes on its own unless you allow exits below. Your wallet must stay online and confirm its timeout promptly; a hub may answer late until that timeout wins.")
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Field(days, { days = it; saved = false }, "Days", "1 to 30, estimated from block times", Modifier.weight(1f), failed = value == null, number = true)
        FilledTonalButton(enabled = value != null && !saved, onClick = {
            value?.let { scope.launch { engine.setExitMargin(it).onSuccess { saved = true } } }
        }) { Text(if (saved) "Saved" else "Save") }
    }
}

/**
 * Her consent to exit contracts ending, with the address their notes are
 * paid out to: given, shown and revoked here only, never assumed.
 */
@Composable
private fun ExitConsentEntry(engine: Engine, contracts: Boolean) {
    val scope = rememberCoroutineScope()
    var consent by remember { mutableStateOf<ExitConsent?>(null) }
    var address by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(contracts) { consent = engine.exitConsent().getOrNull() }
    Column(Modifier.padding(vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Exits", style = MaterialTheme.typography.bodyLarge)
        Say(
            "Allowed, as a contract nears its end and no other at its hub protects your notes there, Licash pays " +
                "those notes out to your address for at most 1% and 1,000 sat, then closes the contract early. " +
                "If they are not paid out a day before its last safe block, it forces the contract closed. " +
                "Not allowed, it only tells you. Revoking stops new steps; steps under way are finished.",
        )
        val given = consent
        if (given != null) {
            Say("Allowed, paying out to ${given.address}.")
            FilledTonalButton(onClick = {
                scope.launch { engine.revokeExitConsent().onSuccess { consent = null }.onFailure { error = explain(it) } }
            }, modifier = Modifier.testTag("revoke-exits")) { Text("Revoke") }
        } else if (!contracts) {
            Say("Asked once a contract protects your notes.")
        } else {
            Field(address, { address = it; error = null }, "Bitcoin address", error ?: "Where your notes are paid out to", failed = error != null)
            FilledTonalButton(enabled = address.isNotBlank(), onClick = {
                scope.launch {
                    engine.consentToExit(address.trim()).onSuccess { consent = it }.onFailure { error = explain(it) }
                }
            }, modifier = Modifier.testTag("allow-exits")) { Text("Allow exits") }
        }
    }
}

/** The light client's nodes and block server, and the block explorer that payments link to. */
@Composable
private fun LightClient(engine: Engine) {
    val scope = rememberCoroutineScope()
    var peers by remember { mutableStateOf(engine.prefs.peers) }
    var cdn by remember { mutableStateOf(engine.prefs.cdn) }
    var explorer by remember { mutableStateOf(engine.prefs.explorer) }
    // Applying restarts the light client: said while it is, then that it was.
    var applying by remember { mutableStateOf(false) }
    var applied by remember { mutableStateOf(false) }
    var applyError by remember { mutableStateOf<String?>(null) }
    val applyWait = rememberWait(applying)
    val feel = rememberFeel()
    Column(Modifier.padding(vertical = 12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Field(peers, { peers = it; applied = false }, "Nodes", "host:port, separated by commas")
        Field(cdn, { cdn = it; applied = false }, "Block server", "default, a URL, or empty for none")
        FilledTonalButton(
            enabled = !applying,
            onClick = {
                applying = true
                applied = false
                applyError = null
                scope.launch {
                    engine.setChain(peers, cdn)
                        .onSuccess {
                            applied = true
                            feel.confirm()
                        }
                        .onFailure {
                            applyError = explain(it)
                            feel.reject()
                        }
                    applying = false
                }
            },
            modifier = Modifier.testTag("apply-chain"),
        ) {
            if (applying) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(if (applying) "Applying…" else "Apply")
        }
        Waited(applyWait)
        if (applied) Text("Applied", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        applyError?.let { Problem(it) }
    }
    Divider()
    Row(
        Modifier.fillMaxWidth().padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Field(explorer, { explorer = it }, "Block explorer", "default, a URL, or empty for none", Modifier.weight(1f))
        FilledTonalButton(onClick = { engine.prefs.explorer = explorer }) { Text("Save") }
    }
}

/** A setting typed in: its name in the field, and a hint under it, red if `failed`. */
@Composable
private fun Field(
    value: String,
    change: (String) -> Unit,
    label: String,
    hint: String,
    modifier: Modifier = Modifier.fillMaxWidth(),
    failed: Boolean = false,
    number: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = change,
        modifier = modifier,
        singleLine = true,
        label = { Text(label) },
        supportingText = { Text(hint) },
        isError = failed,
        keyboardOptions = KeyboardOptions(
            keyboardType = if (number) KeyboardType.Number else KeyboardType.Uri,
            imeAction = ImeAction.Done,
        ),
        shape = RoundedCornerShape(14.dp),
    )
}
