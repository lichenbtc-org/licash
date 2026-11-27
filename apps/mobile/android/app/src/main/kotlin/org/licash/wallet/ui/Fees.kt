package org.licash.wallet.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import org.licash.core.ContractFee
import org.licash.core.ContractRange
import org.licash.core.InvoiceQuote
import org.licash.core.Rate
import org.licash.wallet.digits
import org.licash.wallet.percent
import org.licash.wallet.sat
import org.licash.wallet.share
import java.math.BigInteger

/** Only supplied or recorded components, never inferred from current terms. */
internal data class FeeBreakdown(
    val amount: ULong,
    val fee: ULong,
    val components: List<Pair<String, ULong>> = emptyList(),
    val rate: Rate? = null,
    val explanation: String = "This total includes the quoted costs. Separate hub, provider and miner charges were not supplied.",
    val title: String = "Fee breakdown",
    val totalLabel: String = "Total fee",
    val amountLabel: String = "Amount",
)

internal fun recordedFee(amount: ULong, fee: ULong, components: List<Pair<String, ULong>> = emptyList()) = FeeBreakdown(
    amount, fee, components,
    explanation = "Recorded cost only. Base/rate terms and any further recipient split were not saved. A pending or refunded cost may not be final.",
)

internal fun setupCost(amount: ULong, cost: ULong) = FeeBreakdown(
    amount, cost,
    explanation = "Setup cost relative to the maximum payout, not a payment fee. A separate hub-fee and reserve split is not supplied here; reserves may return during recovery.",
    title = "Setup cost", totalLabel = "Total cost", amountLabel = "Maximum payout",
)

/** What protection costs, `fee`: its opening fee and interest, the reserve apart, as it is not spent. */
internal fun ContractFee.cost(): ULong = opening + interest + interestFunded

/**
 * What protection of `cap` sat chosen within `range` costs, itemized as its
 * hub prices it: its opening fee, and its interest by the year on the part
 * it funds and on the `funded` part hers. Not the reserve, which is hers
 * and comes back ([RESERVE_MEANS]), nor her part, which joins her balance.
 */
internal fun contractCost(range: ContractRange, cap: ULong, fee: ContractFee, funded: ULong): FeeBreakdown {
    val hubs = cap - funded.coerceAtMost(cap)
    val parts = listOf(
        "Hub's opening fee" to fee.opening,
        "Interest on the hub's part" to fee.interest,
        "Interest on your part" to fee.interestFunded,
    )
    val yours = if (funded == 0uL) "" else
        " and ${percent(range.ppmYearFunded.toULong())} a year on the ${digits(funded)} sat you fund yourself, " +
            "paid from your coin and joining your balance once its funding confirms"
    return FeeBreakdown(
        cap, fee.cost(), feeParts(fee.cost(), parts),
        explanation = "Interest: ${percent(range.ppmYear.toULong())} a year on the ${digits(hubs)} sat the hub " +
            "funds$yours. Not in this cost: your reserve, which comes back to you.",
        title = "Cost", totalLabel = "Total cost", amountLabel = "Covers up to",
    )
}

/** What the hub's interest is for, said behind the (i) of the cost. */
internal const val INTEREST_MEANS = "To protect your balance at a hub, the hub locks its own bitcoin on " +
    "Bitcoin beside yours, for as long as the protection lasts: if the hub ever stops, the app claims " +
    "what you hold there from it. Interest pays the hub for locking it. Part of the cover can be your own " +
    "coin instead, which costs less and joins your balance once confirmed."

/** What the reserve is, said behind its (i). */
internal const val RESERVE_MEANS = "The reserve is yours, not a fee. It stays in the contract and pays the " +
    "Bitcoin fees if you ever recover your money without the hub. Otherwise it comes back to you when " +
    "the protection ends."

/**
 * A fee's parts by who gets them, as quoted or recorded: those of 0 left
 * out, and none at all unless they add up to the whole fee.
 */
internal fun feeParts(fee: ULong, parts: List<Pair<String, ULong>>): List<Pair<String, ULong>> {
    val shown = parts.filter { it.second > 0uL }
    val sum = shown.fold(0uL) { total, (_, part) -> if (ULong.MAX_VALUE - total < part) ULong.MAX_VALUE else total + part }
    return if (shown.isNotEmpty() && sum == fee) shown else emptyList()
}

/**
 * A payout's fee: the hub's on the lock, the payout provider's (its coin's
 * miners in it) and the claim's miners; `quoted`, before it is made.
 */
internal fun payoutFee(amount: ULong, fee: ULong, hub: ULong, provider: ULong, network: ULong, quoted: Boolean): FeeBreakdown {
    val parts = feeParts(fee, listOf("Hub" to hub, "Payout provider" to provider, "Bitcoin network" to network))
    val provided = "The payout provider's fee includes the miners of its own coin."
    return when {
        parts.isEmpty() -> if (quoted) FeeBreakdown(amount, fee) else recordedFee(amount, fee)
        quoted -> FeeBreakdown(amount, fee, parts, explanation = provided)
        else -> FeeBreakdown(amount, fee, parts, explanation = "As recorded. $provided Base and rate terms were not saved.")
    }
}

/**
 * A Lightning invoice's fee as quoted: the hub's on the lock and the swap
 * provider's, Lightning routing in it.
 */
internal fun invoiceFee(quote: InvoiceQuote): FeeBreakdown {
    val provider = quote.provider
    val parts = feeParts(quote.fee, listOf("Hub" to provider.lockFee, "Swap provider" to provider.fee))
    return if (parts.isEmpty()) FeeBreakdown(quote.amount, quote.fee)
    else FeeBreakdown(quote.amount, quote.fee, parts, explanation = "The swap provider's fee includes Lightning routing.")
}

/** A move's fee as recorded: the hub's on the lock and the swap provider's. */
internal fun swapFee(amount: ULong, fee: ULong, hub: ULong, provider: ULong): FeeBreakdown {
    val parts = feeParts(fee, listOf("Hub" to hub, "Swap provider" to provider))
    return if (parts.isEmpty()) recordedFee(amount, fee)
    else FeeBreakdown(amount, fee, parts, explanation = "As recorded. Base and rate terms were not saved.")
}

/** Match the SDK's base plus relative fee, rounded up and saturating. */
internal fun relativeFee(amount: ULong, ppm: ULong): ULong {
    val numerator = amount.toString().toBigInteger() * ppm.toString().toBigInteger()
    return ((numerator + BigInteger.valueOf(999_999)) / BigInteger.valueOf(1_000_000))
        .min(ULong.MAX_VALUE.toString().toBigInteger()).toString().toULong()
}

internal fun feeDue(amount: ULong, rate: Rate): ULong {
    val relative = relativeFee(amount, rate.ppm)
    return if (ULong.MAX_VALUE - relative < rate.base) ULong.MAX_VALUE else relative + rate.base
}

@Composable
internal fun FeeLine(
    label: String,
    fee: ULong,
    amount: ULong,
    tag: String = "fee",
    value: String = if (fee == 0uL) "None" else sat(fee),
    breakdown: FeeBreakdown = FeeBreakdown(amount, fee),
    modifier: Modifier = Modifier,
) {
    var showing by remember { mutableStateOf(false) }
    Line(label, value, modifier, tag = tag, share = share(fee, amount), onClick = { showing = true })
    if (showing) FeeSheet(breakdown) { showing = false }
}

@Composable
internal fun FeeSheet(fee: FeeBreakdown, dismiss: () -> Unit) {
    Sheet(fee.title, dismiss) {
        Line(fee.amountLabel, sat(fee.amount))
        fee.components.forEach { (recipient, amount) ->
            Line(recipient, sat(amount), share = share(amount, fee.amount))
        }
        fee.rate?.let { rate ->
            Line("Base fee", sat(rate.base))
            Line("Rate", percent(rate.ppm))
            val relative = relativeFee(fee.amount, rate.ppm)
            Line("${percent(rate.ppm)} × ${sat(fee.amount)}", sat(relative))
            Say("The relative fee is rounded up to a whole satoshi.")
        }
        Line(fee.totalLabel, sat(fee.fee), share = share(fee.fee, fee.amount))
        Say(fee.explanation)
    }
}
