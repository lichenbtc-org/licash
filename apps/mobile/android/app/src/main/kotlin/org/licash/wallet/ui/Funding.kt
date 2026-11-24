package org.licash.wallet.ui

import android.content.ClipData
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.ContractQuote
import org.licash.core.ContractState
import org.licash.core.Kind
import org.licash.core.contractFit
import org.licash.core.contractPrice
import org.licash.core.contractSizes
import org.licash.wallet.Engine
import org.licash.wallet.Ui
import org.licash.wallet.behind
import org.licash.wallet.sat

/** Where a first funding stands, in the order it goes. */
internal enum class FundingStage(val title: String) {
    WAITING("Waiting"),
    SEEN("Seen"),
    IN_BLOCK("In a block"),
    OPENING("Opening vault"),
    READY("Ready"),
}

/**
 * Whether Home guides the first funding: a hub chosen, and nothing
 * protected, held in notes or paid in or out with them yet. A wallet that
 * ever did more is never guided again.
 */
internal fun guiding(ui: Ui): Boolean =
    ui.hubs.isNotEmpty() && ui.contracts.isEmpty() && ui.paid.isEmpty() &&
        ui.balance.notes == 0uL && ui.balance.notesPending == 0uL && ui.balance.moving == 0uL &&
        ui.history.all { it.kind == Kind.ONCHAIN || it.kind == Kind.CONTRACT }

/**
 * Whether the guide asked for again at `since` (seconds since 1970) still
 * shows: with a hub, until a vault asked for since then protects (or did,
 * and ended). Never asked: no.
 */
internal fun guideAsked(ui: Ui, since: Long?): Boolean =
    since != null && ui.hubs.isNotEmpty() && ui.contracts.none {
        it.createdAt >= since &&
            (it.state == ContractState.Protecting || it.state == ContractState.Ending || it.state == ContractState.Closed)
    }

/** Where the first funding of `ui` stands. Ready is past it: no longer guided. */
internal fun stage(ui: Ui): FundingStage = when {
    ui.opening != null -> FundingStage.OPENING
    ui.balance.onchain > ui.balance.kept -> FundingStage.IN_BLOCK
    ui.incoming.isNotEmpty() -> FundingStage.SEEN
    else -> FundingStage.WAITING
}

/** What `stage` says under its title, once at it: `coming`, the sat on their way. */
internal fun stageSays(stage: FundingStage, coming: ULong): String = when (stage) {
    FundingStage.WAITING -> "Send bitcoin to this address, from any wallet or exchange."
    FundingStage.SEEN -> "${sat(coming)} on its way. It needs a block, about 10 minutes."
    FundingStage.IN_BLOCK -> "Your bitcoin is here. Open your vault to pay with it."
    FundingStage.OPENING -> "This takes a few minutes. You can leave the app."
    FundingStage.READY -> "Protected. Pay and receive in a tap."
}

/**
 * The least coin a contract of `cap` takes whole with [FIXED_PART] of it
 * hers, as `price` and `fit` say ([contractPrice], [contractFit]): none if
 * a contract of that cap does not take it.
 */
internal fun leastFor(
    cap: ULong,
    price: (cap: ULong, funded: ULong) -> ULong,
    fit: (coin: ULong, least: ULong) -> ULong?,
): ULong? {
    val coin = price(cap, FIXED_PART) + FIXED_PART
    return coin.takeIf { fit(it, cap) == cap }
}

/** The size of a vault with room to be paid mostly: four times the smallest, or the largest. */
internal fun receivingCap(sizes: List<ULong>): ULong? = sizes.getOrNull(2) ?: sizes.lastOrNull()

/** What to send for `intent`, the least for any vault `least`, and for one mostly to be paid `receiving`. */
internal fun howMuch(intent: Intent, least: ULong?, receiving: Pair<ULong, ULong>?): String? = when {
    intent == Intent.RECEIVE && receiving != null ->
        "Send at least ${sat(receiving.first)} for room to receive about ${sat(receiving.second)}."
    least != null -> "Send at least ${sat(least)}. Send what you plan to spend."
    else -> null
}

/**
 * Home's guide to a first vault: what it is mostly for, the address to send
 * bitcoin to and a copy of it, then where it stands, step by step, and once
 * it is in a block the vault to open, on a tap: nothing opens unasked.
 */
@Composable
internal fun FirstFunding(engine: Engine, ui: Ui, hide: (() -> Unit)? = null) {
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val at = stage(ui)
    var address by remember { mutableStateOf<String?>(null) }
    var intent by remember { mutableStateOf(intentOf(engine.prefs.intent)) }
    var quote by remember { mutableStateOf<ContractQuote?>(null) }
    var copied by remember { mutableStateOf(false) }
    var choosing by remember { mutableStateOf(false) }
    val hub = ui.hubs.firstOrNull { it.contracts?.range != null }
    LaunchedEffect(Unit) { engine.bitcoinAddress().onSuccess { address = it } }
    LaunchedEffect(hub?.url) { hub?.let { engine.contractQuote(it.url).onSuccess { q -> quote = q } } }
    val amounts = quote?.let { q ->
        val range = q.range ?: return@let null
        val blocks = q.suggestedBlocks
        val price = { cap: ULong, funded: ULong -> contractPrice(range, cap, blocks, funded) }
        val fit = { coin: ULong, least: ULong ->
            contractFit(range, blocks, coin, least, q.dust, q.denominations, q.fundedNotes)?.cap
        }
        val sizes = contractSizes(range)
        val least = sizes.firstOrNull()?.let { leastFor(it, price, fit) }
        val receiving = receivingCap(sizes)?.let { cap -> leastFor(cap, price, fit)?.let { it to cap } }
        least to receiving
    }
    Column(
        Modifier.fillMaxWidth().padding(top = 16.dp).clip(RoundedCornerShape(20.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer).padding(16.dp)
            .testTag("funding"),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            if (at == FundingStage.WAITING) "Fill your vault" else at.title,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.testTag("funding-title"),
        )
        Text(
            stageSays(at, ui.incoming.sumOf { it.amount }),
            modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        when (at) {
            FundingStage.WAITING -> {
                Segmented(Intent.entries.map { it.label }, intent.ordinal, Modifier.fillMaxWidth()) {
                    intent = Intent.entries[it]
                    engine.prefs.intent = intent.name
                }
                Text(
                    listOfNotNull(intent.says, howMuch(intent, amounts?.first, amounts?.second)).joinToString(" "),
                    modifier = Modifier.padding(top = 8.dp, bottom = 12.dp).testTag("funding-how-much"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
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
            FundingStage.IN_BLOCK -> ui.offer?.let { q ->
                BigButton("Open your vault", Modifier.fillMaxWidth().testTag("open-vault")) { choosing = true }
                if (choosing) OfferSheet(engine, q, !behind(ui)) { choosing = false }
            }
            else -> {}
        }
        Spacer(Modifier.height(12.dp))
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.Top) {
            for (step in FundingStage.entries) {
                Step(
                    mark = when {
                        step.ordinal < at.ordinal -> Mark.DONE
                        step == at -> Mark.NOW
                        else -> Mark.NEXT
                    },
                    title = step.title,
                    last = step == FundingStage.READY,
                    tag = "funding-step",
                )
            }
        }
        // Asked for again: hidden as it was asked for.
        hide?.let {
            TextButton(onClick = it, modifier = Modifier.testTag("funding-hide")) { Text("Hide guide") }
        }
    }
}
