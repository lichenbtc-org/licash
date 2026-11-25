package org.licash.wallet.ui

import android.content.ClipData
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Activity
import org.licash.core.Contract
import org.licash.core.Kind
import org.licash.core.OpeningStep
import org.licash.wallet.Engine
import org.licash.wallet.HUB_NO_ROOM
import org.licash.wallet.Ui
import org.licash.wallet.behind
import org.licash.wallet.sat

/** A page of setting a wallet up, in the order they come. */
internal enum class SetupPage { BACKUP, HUB, FUND, VAULT, READY }

/**
 * The page setting `ui` up is at ([setupDue]). Before a hub: backing up a
 * wallet made here, while that is due and not put off (`backup`), then
 * choosing one. With one: the funding, step by step, until its vault
 * protects, said once; aside from it, `another` hub asked for, and the
 * vault offered once asked for (`choosing`), while it is.
 */
internal fun setupPage(ui: Ui, backup: Boolean, another: Boolean, choosing: Boolean): SetupPage {
    if (ui.hubs.isEmpty()) return if (backup) SetupPage.BACKUP else SetupPage.HUB
    val at = stage(ui)
    return when {
        at == FundingStage.READY -> SetupPage.READY
        another -> SetupPage.HUB
        choosing && at == FundingStage.IN_BLOCK && ui.offer != null -> SetupPage.VAULT
        else -> SetupPage.FUND
    }
}

/** What the words bring back, said where a new wallet is backed up. */
internal const val BACKUP_WORDS = "Your 24 recovery words bring back your keys and bitcoin you hold on Bitcoin. " +
    "Write them on paper and never share them."

/** What they do not, and what does. */
internal const val BACKUP_AUTO = "Your balance is held in hubs: the words alone do not bring it back. " +
    "The automatic backup does. It saves your balance each time it changes, encrypted with your words, " +
    "to a folder you choose. Pick one a sync app copies off this phone."

/** That restoring takes both. */
internal const val BACKUP_BOTH = "Restoring needs both: the backup, and the words to open it."

/** Said of a deposit before it is in a block. */
internal const val ONE_BLOCK = "One block is enough."

/** What setting a vault up waits on at `step`: asking its hub, before it says. */
internal fun openingSays(step: OpeningStep?): String = step?.let { setup(it).second } ?: "Asking the hub"

/**
 * Where setting up is, kept while the screens it opens are shown: `left`
 * for Home, which leads back; its `backup` due when first shown, and
 * passed, done or put off (`later`); `another` hub asked for; its vault
 * being chosen (`choosing`); why it was come to, if sent here (`hint`);
 * and whether it is guided only since it was (`passing`), which going
 * back with nothing sent undoes ([leavingEnds]).
 */
@Stable
class SetupNav(left: Boolean = false) {
    var left by mutableStateOf(left)
    var backup by mutableStateOf(false)
    var later by mutableStateOf(false)
    var another by mutableStateOf(false)
    var choosing by mutableStateOf(false)
    var hint by mutableStateOf<String?>(null)
    var passing by mutableStateOf(false)

    /** Come back to, `why` if sent, `passing` if guided only since. */
    fun enter(why: String? = null, passing: Boolean = false) {
        hint = why
        this.passing = passing
        left = false
    }

    /** As for a wallet not set up at all. */
    fun reset() {
        left = false
        backup = false
        later = false
        another = false
        choosing = false
        hint = null
        passing = false
    }

    companion object {
        /** Kept while the screen turns, so that what was left or put off stays so. */
        val Saver = listSaver<SetupNav, Any?>(
            save = { listOf(it.left, it.backup, it.later, it.another, it.choosing, it.hint, it.passing) },
            restore = {
                SetupNav(it[0] as Boolean).apply {
                    backup = it[1] as Boolean
                    later = it[2] as Boolean
                    another = it[3] as Boolean
                    choosing = it[4] as Boolean
                    hint = it[5] as String?
                    passing = it[6] as Boolean
                }
            },
        )
    }
}

/**
 * Whether the app starts at Home though setting up is due: a wallet in
 * use, holding or having paid ([guiding] not), whose Home leads there.
 * Only one with nothing yet starts at what it lacks.
 */
internal fun startsAtHome(ui: Ui): Boolean = ui.wallet && ui.hubs.isNotEmpty() && !guiding(ui)

/** Whether setting up shows in Home's place: while due ([setupDue]) and not left, which with no hub it cannot be. */
internal fun settingUp(ui: Ui, left: Boolean): Boolean = setupDue(ui) && (!left || ui.hubs.isEmpty())

/**
 * Whether leaving the funding at `at` ends the guide too, of a wallet in
 * use, which is not guided unasked ([guiding]): asked to (`hide`), or,
 * with nothing sent yet, guided only since it was sent here (`passing`),
 * which going back undoes. A guide it asked for, or has since it was
 * made, is kept however left: Home leads back to it.
 */
internal fun leavingEnds(ui: Ui, at: FundingStage, hide: Boolean, passing: Boolean = false): Boolean =
    !guiding(ui) && at < FundingStage.OPENING && (hide || (passing && at == FundingStage.WAITING))

/**
 * A new wallet set up, a screen at a time with nothing else on it: its
 * backup, a hub, then its first vault, funded and opened step by step,
 * and that it is ready, once. In Home's place while due and not left
 * ([settingUp]): left, Home leads back here.
 */
@Composable
fun Setup(
    engine: Engine,
    ui: Ui,
    nav: SetupNav,
    settings: () -> Unit,
    money: (at: String?) -> Unit,
    open: (Activity) -> Unit,
) {
    var wordsDue by remember { mutableStateOf(engine.prefs.wordsDue) }
    // Its backup's page stays once the words were shown, for the automatic backup beside them: until passed.
    val due = remember { engine.prefs.wordsDue }
    SideEffect { if (due) nav.backup = true }
    val page = setupPage(ui, backup = (due || nav.backup) && !nav.later, another = nav.another, choosing = nav.choosing)
    val at = stage(ui)
    val feel = rememberFeel()
    // A step of the funding reached in sight is felt: not those reached before, nor those told of
    // apart, bitcoin arrived and the vault ready.
    var was by remember { mutableStateOf(at) }
    LaunchedEffect(at) {
        if (ui.hubs.isNotEmpty() && at > was && (at == FundingStage.SEEN || at == FundingStage.OPENING)) feel.confirm()
        was = at
    }
    // Another hub added: back to the funding.
    var hubs by remember { mutableStateOf(ui.hubs.size) }
    LaunchedEffect(ui.hubs.size) {
        if (ui.hubs.size != hubs) nav.another = false
        hubs = ui.hubs.size
    }
    val leaving = { hide: Boolean ->
        if (leavingEnds(ui, at, hide, nav.passing)) engine.guide(null)
        nav.hint = null
        nav.passing = false
        nav.left = true
    }
    BackHandler(enabled = page == SetupPage.FUND) { leaving(false) }
    BackHandler(enabled = page == SetupPage.VAULT) { nav.choosing = false }
    BackHandler(enabled = page == SetupPage.HUB && nav.another) { nav.another = false }
    BackHandler(enabled = page == SetupPage.READY) { engine.guide(null) }
    Column(Modifier.fillMaxSize().padding(horizontal = 24.dp).testTag("setup")) {
        when {
            page == SetupPage.VAULT -> TopBar("Open your vault", back = { nav.choosing = false })
            page == SetupPage.HUB && nav.another -> TopBar("Another hub", back = { nav.another = false })
            else -> Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Wordmark()
                Spacer(Modifier.width(10.dp))
                NetworkChip(ui.network)
                Connections(engine, ui)
                Spacer(Modifier.weight(1f))
                IconButton(onClick = settings) { Icon(Icons.Default.Settings, contentDescription = "Settings") }
            }
        }
        AnimatedContent(
            targetState = page,
            modifier = Modifier.fillMaxWidth().weight(1f),
            transitionSpec = {
                val way = if (targetState.ordinal >= initialState.ordinal) 1 else -1
                (fadeIn(tween(210, delayMillis = 70)) + slideInHorizontally(tween(280)) { it / 14 * way }) togetherWith
                    (fadeOut(tween(70)) + slideOutHorizontally(tween(280)) { -it / 14 * way })
            },
            label = "setup",
        ) { shown ->
            Column(Modifier.fillMaxSize()) {
                when (shown) {
                    SetupPage.BACKUP -> BackupFirst(
                        engine,
                        ui,
                        saved = !wordsDue,
                        seen = {
                            if (wordsDue && !engine.prefs.wordsDue) feel.confirm()
                            wordsDue = engine.prefs.wordsDue
                        },
                    ) { nav.later = true }
                    SetupPage.HUB -> Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.Center,
                    ) { FirstHub(engine, ui) }
                    SetupPage.FUND -> Fund(
                        engine,
                        ui,
                        at,
                        nav.hint,
                        choose = {
                            // Guided from here on: its steps stay while its vault is set up.
                            if (ui.guideSince == null) engine.guide(System.currentTimeMillis() / 1000)
                            nav.choosing = true
                        },
                        another = { nav.another = true },
                        money = money,
                        open = open,
                        leave = leaving,
                    )
                    SetupPage.VAULT -> Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).testTag("offer-page")) {
                        Say(VAULT_MEANS)
                        ui.offer?.let { q ->
                            Offered(engine, q, ready = !behind(ui), verb = "Open") { nav.choosing = false }
                        }
                        Spacer(Modifier.height(24.dp))
                    }
                    SetupPage.READY -> Ready(engine, guidedVault(ui, ui.guideSince)) { engine.guide(null) }
                }
            }
        }
    }
}

/** What a vault is, said over the one offered: the tour's last page, in a line. */
internal const val VAULT_MEANS = "Your vault is your insurance: you choose how much it protects."

/**
 * A wallet made here backed up before anything is in it: its words, and
 * the automatic backup, which what hubs hold needs. Put off with `next`,
 * which goes on once done too.
 */
@Composable
private fun ColumnScope.BackupFirst(engine: Engine, ui: Ui, saved: Boolean, seen: () -> Unit, next: () -> Unit) {
    var words by remember { mutableStateOf(false) }
    var auto by remember { mutableStateOf(false) }
    Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.Center) {
        // A wallet just made: said, before what it needs.
        Row(Modifier.padding(bottom = 16.dp), verticalAlignment = Alignment.CenterVertically) {
            Cheer(size = 28.dp, sparks = false)
            Spacer(Modifier.width(10.dp))
            Text("Wallet created", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        }
        Text(
            "Back up your wallet",
            modifier = Modifier.padding(bottom = 12.dp).testTag("setup-backup"),
            style = MaterialTheme.typography.headlineSmall,
        )
        Say(BACKUP_WORDS)
        Say(BACKUP_AUTO)
        Group("") {
            Entry("Recovery words", sub = if (saved) "Shown" else "24 words, on paper", icon = Glyphs.key, tag = "setup-words") {
                words = true
            }
            Divider()
            Entry("Automatic backup", sub = autoBackupState(ui.backup), icon = Glyphs.shield, tag = "setup-auto") { auto = true }
        }
        Text(
            BACKUP_BOTH,
            modifier = Modifier.padding(top = 12.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    val done = saved && ui.backup != null
    BigButton(
        if (saved || ui.backup != null) "Continue" else "Later",
        Modifier.fillMaxWidth().testTag("backup-later"),
        quiet = !done,
        onClick = next,
    )
    Spacer(Modifier.height(24.dp))
    if (words) {
        Phrase(engine) {
            words = false
            seen()
        }
    }
    if (auto) AutoBackupSheet(engine, ui) { auto = false }
}

/**
 * The first vault funded and opened, step by step: the address to send
 * bitcoin to and how much, then where it stands, and once it is in a block
 * the vault to open, on a tap: nothing opens unasked. While it is set up,
 * what it is and how far. Left for Home with `leave`.
 */
@Composable
private fun ColumnScope.Fund(
    engine: Engine,
    ui: Ui,
    at: FundingStage,
    hint: String?,
    choose: () -> Unit,
    another: () -> Unit,
    money: (String?) -> Unit,
    open: (Activity) -> Unit,
    leave: (hide: Boolean) -> Unit,
) {
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val colors = MaterialTheme.colorScheme
    var address by remember { mutableStateOf<String?>(null) }
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(at == FundingStage.WAITING) { engine.bitcoinAddress().onSuccess { address = it } }
    LaunchedEffect(copied) {
        if (copied) {
            kotlinx.coroutines.delay(COPIED_MS)
            copied = false
        }
    }
    val vault = guidedVault(ui, ui.guideSince)
    val coming = ui.incoming.sumOf { it.amount }
    // The one a vault takes whole: else there is none to open yet.
    val offer = ui.offer?.takeIf { fitting(it).isNotEmpty() }
    Column(
        Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).testTag("funding"),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(16.dp))
        Text(
            if (at == FundingStage.WAITING) "Fill your vault" else at.title,
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.testTag("funding-title"),
        )
        Text(
            stageSays(at, coming),
            modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = colors.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        hint?.let {
            Text(
                it,
                modifier = Modifier.padding(bottom = 12.dp).testTag("setup-hint"),
                style = MaterialTheme.typography.bodyMedium,
                color = colors.primary,
                textAlign = TextAlign.Center,
            )
        }
        if (at == FundingStage.WAITING) {
            Text(
                HOW_MUCH,
                modifier = Modifier.padding(bottom = 12.dp).testTag("funding-how-much"),
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
            )
            More("How much to send", Modifier.testTag("funding-more")) {
                Say(DEPOSIT_MORE)
            }
            address?.let { shown ->
                QrCode("bitcoin:$shown".uppercase(), size = 220.dp, description = "Bitcoin address as a QR code")
                SelectionContainer {
                    Text(
                        shown,
                        modifier = Modifier.padding(vertical = 12.dp).testTag("funding-address"),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        textAlign = TextAlign.Center,
                    )
                }
                BigButton(if (copied) "Copied" else "Copy address", Modifier.fillMaxWidth().testTag("copy-address"), quiet = true) {
                    scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("Bitcoin address", shown))) }
                    copied = true
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Column(Modifier.fillMaxWidth()) {
            for (step in FundingStage.entries) {
                val here = step == at
                Step(
                    mark = markOf(step, at),
                    title = step.title,
                    detail = when (step) {
                        FundingStage.SEEN -> "${sat(coming)} on its way".takeIf { here }
                        FundingStage.IN_BLOCK -> when {
                            at < step -> ONE_BLOCK
                            here && offer == null -> NO_VAULT_YET
                            else -> null
                        }
                        FundingStage.OPENING -> openingSays(vault?.step).takeIf { here }
                        else -> null
                    },
                    last = step == FundingStage.READY,
                    // How deep, and the rest of it, for who cares to see.
                    action = when (step) {
                        FundingStage.SEEN -> ui.incoming.firstOrNull()?.takeIf { here }?.let { "Details" to { open(it) } }
                        FundingStage.IN_BLOCK ->
                            ui.history.firstOrNull { it.kind == Kind.ONCHAIN }?.takeIf { here }?.let { "Details" to { open(it) } }
                        else -> null
                    },
                    tag = "funding-step",
                    content = when {
                        // Under what it waits for, and not before it: a block is enough.
                        step == FundingStage.IN_BLOCK && at <= step -> {
                            {
                                BigButton(
                                    "Open your vault",
                                    Modifier.fillMaxWidth().testTag("open-vault"),
                                    enabled = here && offer != null,
                                    onClick = choose,
                                )
                                if (here) {
                                    ui.openFailed?.let { why ->
                                        Problem(why)
                                        if (why == HUB_NO_ROOM) {
                                            TextButton(onClick = another, modifier = Modifier.testTag("another-hub")) {
                                                Text("Use another hub")
                                            }
                                        }
                                    }
                                    if (offer == null) {
                                        TextButton(onClick = { money(ON_BITCOIN) }, modifier = Modifier.testTag("see-bitcoin")) {
                                            Text("See it")
                                        }
                                    }
                                }
                            }
                        }
                        step == FundingStage.OPENING && here -> {
                            { Opening(engine, vault, money) }
                        }
                        else -> null
                    },
                )
            }
        }
        // What a deposit is seen by, and a vault opened after.
        FirstCatchUp(engine, ui)
        Spacer(Modifier.height(8.dp))
    }
    // A wallet in use, guided because it asked: the guide hidden for good. Else left for now, Home leading back.
    val hides = leavingEnds(ui, at, hide = true)
    TextButton(onClick = { leave(hides) }, modifier = Modifier.align(Alignment.CenterHorizontally).testTag("funding-hide")) {
        Text(leaveWords(at, hides))
    }
    Spacer(Modifier.height(8.dp))
}

/** What leaving the funding at `at` is called: `hides`, if it ends the guide ([leavingEnds]). */
internal fun leaveWords(at: FundingStage, hides: Boolean): String = when {
    hides -> "Hide guide"
    at == FundingStage.OPENING -> "Go to my wallet"
    else -> "Not now"
}

/** The vault being set up: how far, how fast, and what it is, kept in sight until it protects. */
@Composable
private fun Opening(engine: Engine, vault: Contract?, money: (String?) -> Unit) {
    val colors = MaterialTheme.colorScheme
    val step = vault?.step
    Column(Modifier.fillMaxWidth()) {
        if (step != null) {
            LinearProgressIndicator(
                progress = { setup(step).first / SETUP_STEPS },
                modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp),
            )
        } else {
            LinearProgressIndicator(Modifier.fillMaxWidth().padding(bottom = 4.dp))
        }
        vault?.transfer?.takeIf { step != null }?.let {
            Text(
                transferred(it, busy = step is OpeningStep.Preparing),
                modifier = Modifier.testTag("setup-transfer"),
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant,
            )
        }
        if (vault != null) {
            Line(PROTECTED_AMOUNT, sat(vault.cap), tag = "setup-cap")
            Line("Into your balance", sat(vault.funded), tag = "setup-funded")
            Line("Hub", engine.called(vault.hub), tag = "setup-hub")
            TextButton(onClick = { money(vault.hub) }, modifier = Modifier.testTag("setup-vault")) { Text("See your vault") }
        }
    }
}

/** The vault protects: said once, with a cheer, then Home. */
@Composable
private fun ColumnScope.Ready(engine: Engine, vault: Contract?, done: () -> Unit) {
    val feel = rememberFeel()
    LaunchedEffect(Unit) { feel.confirm() }
    Column(
        Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Cheer(size = 144.dp)
        Spacer(Modifier.height(24.dp))
        Text(
            "Your vault is ready",
            modifier = Modifier.testTag("setup-ready"),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Text(
            readySays(vault?.cap, vault?.let { engine.called(it.hub) }),
            modifier = Modifier.padding(top = 8.dp),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
    BigButton("Done", Modifier.fillMaxWidth().testTag("setup-done"), onClick = done)
    Spacer(Modifier.height(24.dp))
}

/** What a vault ready says: how much it protects, `cap` sat at `hub`, if known. */
internal fun readySays(cap: ULong?, hub: String?): String =
    if (cap != null && hub != null) {
        "Your tokens at $hub are protected up to ${sat(cap)}. Pay and receive in a tap."
    } else {
        "Protected. Pay and receive in a tap."
    }
