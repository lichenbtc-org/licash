package org.licash.wallet.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.licash.core.Contract
import org.licash.core.ContractState
import org.licash.wallet.Ui
import org.licash.wallet.sat
import org.licash.wallet.total

/**
 * The one thing Home suggests doing next, the most pressing first: fund a
 * first vault; open one for bitcoin that arrived; back up a wallet made
 * here; renew a vault about to end; protect what a hub holds beyond its
 * vaults. Nothing if all is well.
 */
internal sealed interface Next {
    /** No vault yet: Home guides the first funding. */
    data object Fund : Next

    /** Bitcoin arrived that a vault is offered for. */
    data object Confirm : Next

    /** Bitcoin arrived that no vault is offered for: `coin` sat, to pay with once moved in. */
    data class OnBitcoin(val coin: ULong) : Next

    /** A wallet made here, never backed up, holding something. */
    data object Backup : Next

    /** The vault at `hub` stops protecting in `blocks` blocks. */
    data class Renew(val hub: String, val blocks: UInt) : Next

    /** `missing` sat at `hub` not protected, as [suggestProtecting] says. */
    data class Protect(val hub: String, val missing: ULong) : Next
}

/** Blocks before a vault stops protecting that Home suggests renewing it: two weeks of Bitcoin's. */
internal const val RENEW_BLOCKS = 2_016u

/**
 * The vault to renew in `contracts` at chain `height`: one protecting that
 * stops within `within` blocks, at a hub with no other vault protecting
 * longer nor one being opened (`opening`). The soonest to end first.
 */
internal fun renewing(contracts: List<Contract>, height: UInt, opening: String?, within: UInt = RENEW_BLOCKS): Next.Renew? {
    if (height == 0u) return null
    // A vault on its way, or one protecting past the window, at that hub: renewed already.
    fun renewed(hub: String) = opening?.let { sameHub(it, hub) } == true || contracts.any {
        sameHub(it.hub, hub) && (
            it.state == ContractState.Opening || it.state == ContractState.Confirming ||
                (it.state == ContractState.Protecting && it.protectsUntil > height + within)
            )
    }
    return contracts
        .filter { it.state == ContractState.Protecting && it.protectsUntil > height && it.protectsUntil - height <= within }
        .filter { !renewed(it.hub) }
        .minByOrNull { it.protectsUntil }
        ?.let { Next.Renew(it.hub, it.protectsUntil - height) }
}

/**
 * The next step for `ui`, of those [Next] lists, in its order: `guided`
 * while [guiding], `onBitcoin` a coin no vault is offered for ([waiting]),
 * `backupDue` for a wallet made here not backed up yet, `unprotected` what
 * a hub holds beyond its vaults, if suggested.
 */
internal fun nextStep(
    ui: Ui,
    guided: Boolean,
    onBitcoin: ULong?,
    backupDue: Boolean,
    unprotected: Next.Protect?,
): Next? = when {
    guided -> Next.Fund
    ui.offer != null && !ui.offerDeclined && ui.opening == null -> Next.Confirm
    onBitcoin != null -> Next.OnBitcoin(onBitcoin)
    backupDue && ui.balance.total > 0uL -> Next.Backup
    else -> renewing(ui.contracts, ui.chain.height.toUInt(), ui.opening) ?: unprotected
}

/** What a step says: its title and a line under it, and its button. */
internal data class StepWords(val title: String, val line: String, val action: String)

/** The words of `next`, at `hub` as named to her, `blockSecs` a block. */
internal fun stepWords(next: Next, hub: String = "", blockSecs: UInt = BITCOIN_BLOCK_SECONDS): StepWords? = when (next) {
    Next.Fund -> null
    Next.Confirm -> StepWords("Your bitcoin arrived", "Open a vault for it to pay with it, protected.", "Review")
    is Next.OnBitcoin -> StepWords(
        "${sat(next.coin)} on Bitcoin",
        "Too little for a vault. Move it into your balance to pay with it.",
        "See it",
    )
    Next.Backup -> StepWords(
        "Back up your wallet",
        "Save your 24 recovery words. Without them, a lost phone is lost money.",
        "Back up",
    )
    is Next.Renew -> StepWords(
        "Your vault at $hub ends in ${span(next.blocks.toLong(), blockSecs)}",
        "Open a new one to stay protected.",
        "Renew",
    )
    is Next.Protect -> StepWords(
        "${sat(next.missing)} at $hub not protected",
        "Beyond your vault, you trust the hub.",
        "Protect",
    )
}

/** A step Home suggests, in a card: `tag` names it for the tests. */
@Composable
internal fun StepCard(words: StepWords, icon: ImageVector, tag: String, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    Column(
        Modifier.fillMaxWidth().padding(top = 16.dp).clip(RoundedCornerShape(20.dp))
            .background(colors.surfaceContainer).clickable(onClick = onClick).padding(16.dp).testTag(tag),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, Modifier.size(24.dp), tint = colors.primary)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(words.title, style = MaterialTheme.typography.titleMedium)
                Text(words.line, style = MaterialTheme.typography.bodySmall, color = colors.onSurfaceVariant)
            }
        }
        Spacer(Modifier.height(12.dp))
        BigButton(words.action, Modifier.fillMaxWidth().testTag("$tag-go"), quiet = true, onClick = onClick)
    }
}

/**
 * How much of the balance is protected, as a gauge: gold for what the
 * vaults protect, the rest of the track what the hubs hold on their word.
 * Its words, under it, tagged `protection`.
 */
@Composable
internal fun VaultGauge(held: Protection, onClick: () -> Unit) {
    val label = held.label ?: return
    val colors = MaterialTheme.colorScheme
    Column(
        Modifier.padding(top = 12.dp).clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(Modifier.width(180.dp).height(8.dp).clip(RoundedCornerShape(4.dp)).background(colors.surfaceContainerHighest)) {
            val share = if (held.shield == Shield.ALL) 1f else held.percent / 100f
            if (share > 0f) {
                Box(Modifier.fillMaxWidth(share).fillMaxHeight().clip(RoundedCornerShape(4.dp)).background(colors.primary))
            }
        }
        Row(Modifier.padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(
                if (held.shield == Shield.NONE) Glyphs.shieldOff else Glyphs.shield,
                contentDescription = null,
                Modifier.size(16.dp),
                tint = if (held.shield == Shield.ALL) colors.primary else colors.onSurfaceVariant,
            )
            Spacer(Modifier.width(6.dp))
            Text(
                label,
                modifier = Modifier.testTag("protection"),
                style = MaterialTheme.typography.labelLarge,
                color = colors.onSurfaceVariant,
            )
        }
    }
}
