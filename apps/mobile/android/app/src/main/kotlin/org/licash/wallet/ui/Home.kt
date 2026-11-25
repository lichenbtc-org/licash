package org.licash.wallet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectVerticalDragGestures
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.licash.core.Activity
import org.licash.core.Holding
import org.licash.wallet.Engine
import org.licash.wallet.behind
import org.licash.wallet.Ui
import org.licash.wallet.digits
import org.licash.wallet.sat
import org.licash.wallet.total

/**
 * Home, at a glance: what the wallet holds, how much of it is protected,
 * and what is going on, if anything; to receive and to send. The rest is a
 * tap away: where the money is behind the balance, the history behind
 * Activity, or a swipe up. Of a wallet with a hub: before, it is set up
 * ([Setup]), which `setup` goes back to, with why if sent. Send, with
 * nothing to send ([canSend]), is grayed and says so there.
 */
@Composable
fun Home(
    engine: Engine,
    ui: Ui,
    receive: () -> Unit,
    send: () -> Unit,
    settings: () -> Unit,
    money: (at: String?) -> Unit,
    history: () -> Unit,
    open: (Activity) -> Unit,
    setup: (why: String?) -> Unit,
) {
    // A swipe up opens the history, wherever it starts: what the middle,
    // which scrolls, leaves of one, and one over the rest.
    val up by rememberUpdatedState(history)
    val far = with(LocalDensity.current) { 64.dp.toPx() }
    val pull = remember(far) {
        object : NestedScrollConnection {
            var dragged = 0f

            override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                if (source == NestedScrollSource.UserInput) dragged += available.y
                return Offset.Zero
            }

            override suspend fun onPreFling(available: Velocity): Velocity {
                if (dragged < -far) up()
                dragged = 0f
                return Velocity.Zero
            }
        }
    }
    Column(
        Modifier.fillMaxSize().padding(horizontal = 24.dp).nestedScroll(pull).pointerInput(far) {
            var dragged = 0f
            detectVerticalDragGestures(
                onDragStart = { dragged = 0f },
                onDragEnd = { if (dragged < -far) up() },
            ) { _, by -> dragged += by }
        },
    ) {
        Row(Modifier.fillMaxWidth().padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Wordmark()
            Spacer(Modifier.width(10.dp))
            NetworkChip(ui.network)
            Connections(engine, ui)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = settings) { Icon(Icons.Default.Settings, contentDescription = "Settings") }
        }
        // In the middle of what is left, scrolling on short screens and with
        // large fonts; pulled down, it looks for payments now.
        PullToLook(engine, Modifier.fillMaxWidth().weight(1f)) {
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Total(ui) { money(null) }
                Going(ui, money, history, open)
                // One thing to do next, if any: a first vault guided.
                Suggested(engine, ui, money) { setup(null) }
                FirstCatchUp(engine, ui)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            BigButton("Receive", Modifier.weight(1f).testTag("receive"), onClick = receive)
            // Grayed with nothing to send, but still taking a tap: it says what is missing, where it is got.
            val able = canSend(ui)
            BigButton(
                "Send",
                Modifier.weight(1f).alpha(if (able) 1f else GRAYED).testTag("send")
                    .semantics { if (!able) stateDescription = NOTHING_TO_SEND },
            ) { if (able) send() else setup(NOTHING_TO_SEND) }
        }
        Column(
            Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 8.dp).clip(RoundedCornerShape(16.dp))
                .clickable(onClick = history).padding(vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Default.KeyboardArrowUp,
                contentDescription = null,
                Modifier.size(20.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                "Activity",
                modifier = Modifier.testTag("activity"),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** A new wallet's first catching up, while it is ([firstCatchingUp]): each step, as it goes. */
@Composable
internal fun FirstCatchUp(engine: Engine, ui: Ui) {
    if (!firstCatchingUp(ui)) return
    Spacer(Modifier.height(16.dp))
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer).padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        CatchingUp(engine, ui)
        Text(
            "You can leave the app: it keeps catching up, its progress in a notification.",
            modifier = Modifier.padding(bottom = 8.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** How faint what is grayed but still taps is drawn: as what is disabled. */
private const val GRAYED = 0.38f

/** What the wallet holds, and how much of it is protected: both open where it is. */
@Composable
private fun Total(ui: Ui, open: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val figure = digits(ui.balance.total)
    Row(
        Modifier.clip(RoundedCornerShape(16.dp)).clickable(onClick = open).padding(horizontal = 8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        // Smaller once long, to stay on one line.
        val size = when {
            figure.length <= 9 -> 56
            figure.length <= 11 -> 46
            else -> 36
        }
        Text(
            figure,
            modifier = Modifier.testTag("balance"),
            style = Figures.copy(fontSize = size.sp),
            maxLines = 1,
        )
        Text(
            " sat",
            modifier = Modifier.padding(bottom = 8.dp),
            style = MaterialTheme.typography.titleMedium,
            color = colors.onSurfaceVariant,
        )
    }
    homeProtection(ui.balance, ui.opening != null)?.let { VaultGauge(it, open) }
}

/** What is going on, in a line: see [glance]. */
@Composable
private fun Going(ui: Ui, money: (String?) -> Unit, history: () -> Unit, open: (Activity) -> Unit) {
    val going = glance(ui, System.currentTimeMillis() / 1000) ?: return
    var why by remember { mutableStateOf<String?>(null) }
    Spacer(Modifier.height(8.dp))
    Pill(
        icon = Icons.Default.Warning,
        text = going.text,
        busy = going !is Glance.Behind,
        tag = "status",
        onClick = when (going) {
            is Glance.One -> ({ open(going.activity) })
            is Glance.Many -> history
            is Glance.Protecting -> ({ money(going.hub) })
            is Glance.Behind -> ({ why = going.reason })
        },
    )
    why?.let { Sheet("Not up to date", dismiss = { why = null }) { Say(it) } }
}

/**
 * The one step Home suggests ([nextStep]), as a card opening it: back to
 * setting up a first vault (`setup`), where it stands; its offer for
 * bitcoin arrived; that bitcoin to move in when too little for one; the
 * recovery words of a wallet made here; a vault to renew; what a hub holds
 * beyond its vaults.
 */
@Composable
private fun Suggested(engine: Engine, ui: Ui, money: (String?) -> Unit, setup: () -> Unit) {
    var holdings by remember { mutableStateOf<List<Holding>>(emptyList()) }
    LaunchedEffect(ui.balance, ui.contracts, ui.hubs) { engine.holdings().onSuccess { holdings = it } }
    var sheet by remember { mutableStateOf<Next?>(null) }
    val unprotected = holdings.firstNotNullOfOrNull { h ->
        val cover = hubCover(h.hub, h, ui.contracts, emptyList())
        val terms = ui.hubs.find { sameHub(it.url, h.hub) }
        Next.Protect(h.hub, cover.missing).takeIf { suggestProtecting(cover, terms, engine.prefs.unprotectedDismissed(h.hub)) }
    }
    // The guide asked for, over once its vault ended before it was said ready: then forgotten.
    val due = setupDue(ui)
    LaunchedEffect(ui.guideSince, due) { if (ui.guideSince != null && !due) engine.guide(null) }
    val next = nextStep(
        ui,
        guided = due,
        onBitcoin = waiting(ui.balance, offered = ui.offer != null, opening = ui.opening != null),
        backupDue = engine.prefs.wordsDue,
        unprotected = unprotected,
    ) ?: return
    if (next == Next.Fund) {
        StepCard(setupWords(stage(ui)), Glyphs.vault, "setup-card", setup)
        return
    }
    val hub = when (next) {
        is Next.Renew -> name(next.hub)
        is Next.Protect -> name(next.hub)
        else -> ""
    }
    val words = stepWords(next, hub, LocalBlockSeconds.current) ?: return
    val (icon, tag) = when (next) {
        Next.Confirm -> Glyphs.vault to "offer"
        is Next.OnBitcoin -> Glyphs.bitcoin to "waiting"
        Next.Backup -> Glyphs.key to "backup-due"
        is Next.Renew -> Glyphs.shield to "renew"
        is Next.Protect -> Glyphs.shieldOff to "unprotected"
        Next.Fund -> return
    }
    StepCard(words, icon, tag) {
        when (next) {
            is Next.OnBitcoin -> money(ON_BITCOIN)
            is Next.Renew -> money(next.hub)
            is Next.Protect -> money(next.hub)
            else -> sheet = next
        }
    }
    when (sheet) {
        Next.Confirm -> ui.offer?.let { q -> OfferSheet(engine, q, !behind(ui)) { sheet = null } }
        Next.Backup -> Phrase(engine) { sheet = null }
        else -> {}
    }
}
