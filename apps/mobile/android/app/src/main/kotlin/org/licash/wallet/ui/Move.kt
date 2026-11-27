package org.licash.wallet.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Activity
import org.licash.core.Holding
import org.licash.core.LicashException
import org.licash.core.MoveQuote
import org.licash.wallet.Engine
import org.licash.wallet.explain
import org.licash.wallet.feeOf
import org.licash.wallet.host
import org.licash.wallet.sat

/**
 * Move notes from `from` to another of the wallet's hubs, through a swap
 * provider, in a sheet: the hub to move to and the amount (all, if none),
 * then the providers' offers to choose from, the cheapest first. If the
 * chosen one fails before locking the notes, the next costing no more is
 * tried. It stays open while a move is under way.
 */
@Composable
fun MoveSheet(engine: Engine, from: Holding, hubs: List<Holding>, moved: (Activity) -> Unit, dismiss: () -> Unit) {
    val others = hubs.filter { it.hub != from.hub }
    var to by remember { mutableStateOf(others.firstOrNull()?.hub) }
    var text by remember { mutableStateOf("") }
    var offers by remember { mutableStateOf<List<MoveQuote>?>(null) }
    var chosen by remember { mutableStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val feel = rememberFeel()
    val shown = offers
    Sheet("Move from ${name(from.hub)}", dismiss = dismiss, dismissable = !busy) {
        if (shown == null) {
            Group("To") {
                others.forEachIndexed { i, other ->
                    if (i > 0) Divider()
                    Choice(to == other.hub, name(other.hub), sat(other.available)) { to = other.hub }
                }
            }
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it.filter(Char::isDigit).take(15) },
                modifier = Modifier.fillMaxWidth().testTag("move-amount"),
                label = { Text("Amount") },
                suffix = { Text("sat") },
                supportingText = { Text("All ${sat(from.available)} if empty") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                shape = RoundedCornerShape(14.dp),
            )
        } else {
            Group("Offers") {
                shown.forEachIndexed { i, o ->
                    if (i > 0) Divider()
                    Choice(
                        chosen == i,
                        "${sat(o.amount)} arrive",
                        "Fee ${feeOf(o.fee, o.amount)}",
                        "Through ${o.providerName ?: host(o.provider)}",
                    ) { chosen = i }
                }
            }
            shown.getOrNull(chosen)?.let { quote ->
                val split = if (quote.lockFee <= quote.fee) listOf(
                    "Hub lock fee" to quote.lockFee,
                    "Swap provider" to quote.fee - quote.lockFee,
                ) else emptyList()
                FeeLine("Fee", quote.fee, quote.amount, breakdown = FeeBreakdown(
                    quote.amount, quote.fee, split,
                    explanation = "The hub lock fee is separate from the provider's quoted cost. No separate miner fee or base/rate terms were supplied.",
                ))
            }
            Say("If it never arrives, your notes come back once the lock expires.")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth().padding(vertical = 12.dp))
        Waited(rememberWait(busy))
        error?.let { Problem(it) }
        Spacer(Modifier.height(8.dp))
        val target = to
        BigButton(
            if (shown == null) "See offers" else "Move",
            Modifier.fillMaxWidth().testTag("move-go"),
            enabled = !busy && target != null,
        ) {
            busy = true
            error = null
            scope.launch {
                if (shown == null && target != null) {
                    val amount = text.toULongOrNull()?.takeIf { it > 0uL }
                    engine.moveOffers(from.hub, target, amount)
                        .onSuccess { offers = it; chosen = 0 }
                        .onFailure { error = explain(it) }
                } else if (shown != null) {
                    // The chosen first, then the rest as preferred.
                    val order = listOf(shown[chosen]) + shown.filterIndexed { i, _ -> i != chosen }
                    engine.moveNotes(order).onSuccess { feel.confirm(); moved(it) }.onFailure { e ->
                        feel.reject()
                        error = explain(e)
                        // Its fee rose: offered again at the new price, to accept or not.
                        if (e is LicashException.FeeRose) {
                            val amount = text.toULongOrNull()?.takeIf { it > 0uL }
                            engine.moveOffers(from.hub, shown[chosen].to, amount).onSuccess {
                                offers = it
                                chosen = 0
                                error = feeRose(e.agreed, e.asked)
                            }
                        }
                    }
                }
                busy = false
            }
        }
    }
}

/** One of a few to pick, as a row: a dot, what it is and a line under it, and its value. */
@Composable
private fun Choice(on: Boolean, title: String, value: String, sub: String? = null, pick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = pick).heightIn(min = 56.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = on, onClick = pick)
        Spacer(Modifier.width(4.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            sub?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Text(value, style = Amounts, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
