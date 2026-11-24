package org.licash.wallet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Network
import org.licash.wallet.Engine
import org.licash.wallet.Ui
import org.licash.wallet.explain

/**
 * No wallet yet: the tour, then on its last page make one, on Bitcoin
 * unless a test network is chosen first ([networksShown]): the network is
 * the wallet's for good. A wallet that could not be opened says why
 * instead, and nothing is made over it.
 */
@Composable
fun Onboarding(engine: Engine, ui: Ui) {
    val unopened = ui.unopened
    if (unopened != null) {
        Unopened(unopened)
        return
    }
    val scope = rememberCoroutineScope()
    var testing by rememberSaveable { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var restoring by remember { mutableStateOf(false) }
    Tour {
        val shown = networksShown(testing, ui)
        if (shown) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally)) {
                for (network in Network.entries) {
                    FilterChip(
                        selected = ui.network == network,
                        onClick = { scope.launch { engine.setNetwork(network) } },
                        label = { Text(named(network)) },
                        modifier = Modifier.testTag("network ${network.name.lowercase()}"),
                    )
                }
            }
            Text(
                TEST_NETWORKS,
                modifier = Modifier.padding(bottom = 12.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center) }
        Waited(rememberWait(busy), Modifier.padding(bottom = 8.dp), center = true)
        BigButton(
            if (busy) "Creating…" else "Create wallet",
            Modifier.fillMaxWidth().testTag("create"),
            enabled = !busy,
        ) {
            busy = true
            error = null
            scope.launch {
                engine.create().onFailure { error = explain(it) }
                busy = false
            }
        }
        Row(horizontalArrangement = Arrangement.Center, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            TextButton(
                onClick = { restoring = true },
                modifier = Modifier.testTag("restore-wallet"),
                enabled = !busy,
            ) { Text("Restore a wallet") }
            // Advanced mode shows the networks anyway.
            if (!ui.developer) {
                TextButton(
                    onClick = {
                        testing = !shown
                        if (shown && ui.network != Network.BITCOIN) scope.launch { engine.setNetwork(Network.BITCOIN) }
                    },
                    modifier = Modifier.testTag("test-network"),
                    enabled = !busy,
                ) { Text(if (shown) "Use Bitcoin" else "Use a test network") }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
    if (restoring) {
        Restore(engine) { restoring = false }
    }
}

/** A wallet is on the device but could not be opened: why, and how to start over. */
@Composable
private fun Unopened(reason: String) {
    Column(
        Modifier.fillMaxSize().padding(horizontal = 32.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Wordmark(size = 56)
        Spacer(Modifier.height(32.dp))
        Text(UNOPENED, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        Text(
            unopenedWords(reason),
            modifier = Modifier.padding(top = 8.dp).testTag("unopened"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

/**
 * Whether the networks to choose from show: once asked for, while one
 * other than Bitcoin is chosen (so it is never chosen unseen), or in
 * advanced mode.
 */
internal fun networksShown(asked: Boolean, ui: Ui): Boolean =
    asked || ui.developer || ui.network != Network.BITCOIN

/** Said where the wallet on the device could not be opened. */
internal const val UNOPENED = "This wallet can't be opened"

/** Why the wallet on the device could not be opened, `reason`, and the way to start over instead. */
internal fun unopenedWords(reason: String): String =
    "${reason.trimEnd('.')}. To start over instead, clear this app's storage in Android's settings: what the wallet holds is then lost, " +
        "unless you saved a backup file."

/** What a test network is, said beside them. */
internal const val TEST_NETWORKS = "Test networks use coins of no value: Mutinynet's are free from its faucet. " +
    "A wallet keeps the network it is made on."
