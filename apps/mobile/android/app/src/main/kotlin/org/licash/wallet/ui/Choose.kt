package org.licash.wallet.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.licash.core.ContractFit
import org.licash.core.ContractQuote
import org.licash.core.ContractRange
import org.licash.core.DepositCoin
import org.licash.core.Holding
import org.licash.core.contractFee
import org.licash.core.contractFit
import org.licash.core.contractPrice
import org.licash.core.contractSizes
import org.licash.wallet.Chosen
import org.licash.wallet.Engine
import org.licash.wallet.digits
import org.licash.wallet.percent
import org.licash.wallet.sat
import kotlin.math.roundToInt
import kotlin.math.roundToLong

/** The coins of `q` a contract within its hub's range takes whole: none if none does, or it has no range. */
internal fun fitting(q: ContractQuote): List<DepositCoin> {
    val range = q.range ?: return emptyList()
    return q.coins.filter { fitOf(q, range, q.suggestedBlocks, it) != null }
}

/**
 * The protection offered for what was paid on Bitcoin ([org.licash.wallet.Ui.offer]),
 * in a sheet ([Offered]). None if no coin is taken whole by a contract
 * within its hub's range.
 */
@Composable
internal fun OfferSheet(engine: Engine, q: ContractQuote, ready: Boolean, dismiss: () -> Unit) {
    if (fitting(q).isEmpty()) return
    Sheet("Add to balance, protected", dismiss) { Offered(engine, q, ready, done = dismiss) }
}

/**
 * The protection offered for what was paid on Bitcoin, as [Choosing], in
 * a sheet or on a page: a coin on Bitcoin added to the balance, protected,
 * once accepted, or declined so it is not offered unasked again; `done`
 * either way. `verb` names accepting it. Not `sized` by what it is mostly
 * for, a first one: its size is still chosen under More.
 */
@Composable
internal fun Offered(
    engine: Engine,
    q: ContractQuote,
    ready: Boolean,
    verb: String = "Add",
    sized: Boolean = true,
    done: () -> Unit,
) {
    val range = q.range ?: return
    val ui by engine.ui.collectAsState()
    var holding by remember(q.hub) { mutableStateOf<Holding?>(null) }
    LaunchedEffect(q.hub, ui.balance) {
        engine.holdings().onSuccess { all -> holding = all.find { sameHub(it.hub, q.hub) } }
    }
    Choosing(
        q,
        range,
        fitting(q),
        ready,
        hubCover(q.hub, holding, ui.contracts, emptyList()),
        hub = engine.called(q.hub),
        verb = verb,
        intent = intentOf(engine.prefs.intent),
        chooseIntent = { engine.prefs.intent = it.name },
        sized = sized,
        open = { chosen, price ->
            done()
            engine.openContract(q.hub, price, chosen)
        },
        decline = {
            engine.declineOffer(q)
            done()
        },
    )
}

/**
 * The contracts within `range` over `blocks` that `coin` pays for whole
 * ([contractFit]), one of each cap, smallest first: none if no contract
 * takes the coin. The coin is spent whole, the price and the rest of it her
 * part, issued back to her as notes; the rest of the cap is the hub's.
 */
internal fun fitsOf(q: ContractQuote, range: ContractRange, blocks: UInt, coin: DepositCoin): List<ContractFit> =
    fitsFrom(range.minCap) { least ->
        contractFit(range, blocks, coin.value, least, q.dust, q.denominations, q.fundedNotes)
    }

/** Each contract `fit` gives of `least` sat at least and above, the smallest it finds above the last. */
internal fun fitsFrom(least: ULong, fit: (least: ULong) -> ContractFit?): List<ContractFit> = buildList {
    var from = least
    while (true) {
        val found = fit(from)?.takeIf { it.cap >= from } ?: break
        add(found)
        if (found.cap == ULong.MAX_VALUE) break
        from = found.cap + 1uL
    }
}

/**
 * What protection is mostly for, which sizes it at first: room for what
 * she puts in and holds at the hub (`halves` of it, in halves), to pay
 * with; half as much again, to be paid too; or three times it, to be paid
 * mostly. The hub funds the room beyond her part.
 */
internal enum class Intent(val label: String, val says: String, val halves: ULong) {
    PAY("Mostly pay", "Room for what you put in, to pay with.", 2uL),
    BOTH("Both", "Room for half as much again, to receive.", 3uL),
    RECEIVE("Mostly receive", "Room to receive twice what you put in.", 6uL),
}

/** The intent the owner last chose: [Intent.BOTH], as before there was a choice, if none. */
internal fun intentOf(saved: String?): Intent = Intent.entries.find { it.name == saved } ?: Intent.BOTH

/**
 * The contract offered at first of `fits` for a coin of `coin` sat, with
 * `missing` sat at its hub not protected yet, for `intent`: the smallest
 * covering both as [Intent.halves] says, else the largest the hub allows
 * for it.
 */
internal fun intentFit(fits: List<ContractFit>, coin: ULong, missing: ULong, intent: Intent): ContractFit? {
    val wanted = (coin + missing) * intent.halves / 2uL
    return fits.firstOrNull { it.cap >= wanted } ?: fits.lastOrNull()
}

/**
 * The contract offered at first of `fits` for a coin of `coin` sat, with
 * `missing` sat at its hub not protected yet: the smallest covering half
 * again both, room to be paid more, else the largest the hub allows for it.
 */
internal fun suggestedFit(fits: List<ContractFit>, coin: ULong, missing: ULong = 0uL): ContractFit? =
    intentFit(fits, coin, missing, Intent.BOTH)

/** The contract offered at first for `coin`, if one takes it whole. */
internal fun fitOf(q: ContractQuote, range: ContractRange, blocks: UInt, coin: DepositCoin): ContractFit? =
    suggestedFit(fitsOf(q, range, blocks, coin), coin.value)

/**
 * Each cover some coin of `fits` (each coin's contracts, as [fitsOf])
 * opens whole, smallest first, with the coins paying it, smallest first:
 * the cover is chosen, then a coin that pays it.
 */
internal fun coversOf(fits: List<Pair<DepositCoin, List<ContractFit>>>): List<Pair<ULong, List<DepositCoin>>> =
    fits.flatMap { (coin, its) -> its.map { it.cap to coin } }
        .groupBy({ it.first }, { it.second })
        .toSortedMap()
        .map { (cap, coins) -> cap to coins.sortedBy { it.value } }

/**
 * The cover offered at first: the one suggested for the smallest coin a
 * contract takes whole, with `missing` sat at its hub not protected yet.
 */
internal fun suggestedCover(
    fits: List<Pair<DepositCoin, List<ContractFit>>>,
    missing: ULong = 0uL,
    intent: Intent = Intent.BOTH,
): ULong? =
    fits.filter { it.second.isNotEmpty() }.minByOrNull { it.first.value }
        ?.let { (coin, its) -> intentFit(its, coin.value, missing, intent)?.cap }

/** What to cash out to herself to protect what she holds at a hub: a coin of `coin` sat opening `cap`. */
internal data class CashOutFirst(val cap: ULong, val coin: ULong)

/**
 * With no coin on Bitcoin that pays for it, the coin to cash out to herself
 * first to protect the `missing` sat at a hub not protected yet: one paying
 * the price of the smallest of `sizes` covering half again them (else the
 * largest) and [FIXED_PART], her part, the hub funding the rest. If a
 * contract of that cap does not take it whole (`fit` of a coin at a least
 * cap, as [contractFit]), as an older hub bounding the cap by the coin
 * refuses, the next smaller that does. None with nothing missing.
 */
internal fun cashOutFirst(
    sizes: List<ULong>,
    missing: ULong,
    price: (cap: ULong, funded: ULong) -> ULong,
    fit: (coin: ULong, least: ULong) -> ContractFit?,
): CashOutFirst? {
    if (missing == 0uL) return null
    val wanted = sizes.firstOrNull { it >= missing + missing / 2uL } ?: sizes.lastOrNull() ?: return null
    return sizes.filter { it <= wanted }.asReversed().firstNotNullOfOrNull { cap ->
        val coin = price(cap, FIXED_PART) + FIXED_PART
        fit(coin, cap)?.takeIf { it.cap == cap }?.let { CashOutFirst(cap, coin) }
    }
}

/**
 * Protection of terms chosen within what its hub allows, in a sheet: see
 * [Choosing].
 */
@Composable
internal fun ChooseSheet(
    q: ContractQuote,
    range: ContractRange,
    coins: List<DepositCoin>,
    ready: Boolean,
    cover: HubCover,
    open: (Chosen, price: ULong) -> Unit,
    dismiss: () -> Unit,
    // The hub, as named to her ([called]).
    hub: String,
    title: String = "Protect at $hub",
    verb: String = "Protect",
    decline: (() -> Unit)? = null,
    payWithNotes: ((cap: ULong, blocks: UInt) -> Unit)? = null,
    cashOut: ((ULong) -> Unit)? = null,
    intent: Intent = Intent.BOTH,
    chooseIntent: (Intent) -> Unit = {},
) {
    Sheet(title, dismiss) {
        Choosing(q, range, coins, ready, cover, open, hub, verb, decline, payWithNotes, cashOut, intent, chooseIntent)
    }
}

/**
 * Protection of terms chosen within what its hub allows, as rows of the
 * column it is in, a sheet's or a page's. First what is
 * protected at the hub once it opens (`cover`, the hub's now, with it), then
 * what it covers, chosen first, which decides the coins on Bitcoin that pay
 * it whole: the smallest at first. Then what it costs, the reserve, hers and
 * refundable, and what of the coin joins her balance once its funding
 * confirms: the coin is spent whole. How long, and the cost itemized, under
 * More. Offered unasked, it can be declined. Not paid for until the app is
 * caught up with Bitcoin (`ready`), as opening it needs.
 *
 * With no coin to pay it, she is told to cash out to herself first.
 */
@Composable
internal fun Choosing(
    q: ContractQuote,
    range: ContractRange,
    coins: List<DepositCoin>,
    ready: Boolean,
    cover: HubCover,
    open: (Chosen, price: ULong) -> Unit,
    // The hub, as named to her ([called]).
    hub: String,
    verb: String = "Protect",
    decline: (() -> Unit)? = null,
    // With no coin paying it: one paid for with notes, of so large a cover over so many blocks.
    payWithNotes: ((cap: ULong, blocks: UInt) -> Unit)? = null,
    // With no coin paying it: cashing out a coin of so many sat to herself first, to pay it.
    cashOut: ((ULong) -> Unit)? = null,
    // What it is mostly for, sizing it at first, and where her choice is kept.
    intent: Intent = Intent.BOTH,
    chooseIntent: (Intent) -> Unit = {},
    // Whether what it is mostly for is asked, sizing it: else its size is only under More.
    sized: Boolean = true,
) {
    val colors = MaterialTheme.colorScheme
    val download = android.text.format.Formatter.formatShortFileSize(LocalContext.current, q.download.toLong())
    val blockSecs = LocalBlockSeconds.current
    var blocks by remember(q) { mutableStateOf(q.suggestedBlocks.coerceIn(range.minBlocks, range.maxBlocks)) }
    val fits = coins.map { it to fitsOf(q, range, blocks, it) }
    val covers = coversOf(fits)
    // The cover chosen, kept while some coin opens it; at first, or once
    // none does, the one suggested.
    var chosenCap by remember(q) { mutableStateOf<ULong?>(null) }
    var chosenCoin by remember(q) { mutableStateOf<DepositCoin?>(null) }
    var picked by remember(q) { mutableStateOf(intent) }
    val cap = chosenCap?.takeIf { c -> covers.any { it.first == c } } ?: suggestedCover(fits, cover.missing, picked)
    val payers = covers.firstOrNull { it.first == cap }?.second.orEmpty()
    val coin = chosenCoin?.takeIf { it in payers } ?: payers.firstOrNull()
    val fit = coin?.let { c -> fits.first { it.first == c }.second.firstOrNull { it.cap == cap } }
    val capped = fit?.cap ?: range.minCap
    val funded = fit?.funded ?: 0uL
    // What the hub is paid: its fee and interest, then the reserve, hers.
    val price = contractPrice(range, capped, blocks, funded)
    val fee = contractFee(range, capped, blocks, funded)
    val cost = fee.cost()
    // It stops protecting a little before it ends.
    val protectsFor = if (blocks > q.afterAssert) blocks - q.afterAssert else 0u
    // None paying it: what she holds here protected by a coin cashed out to herself first.
    val first = if (fit == null && cashOut != null) {
        cashOutFirst(
            contractSizes(range),
            cover.missing,
            price = { c, f -> contractPrice(range, c, blocks, f) },
            fit = { v, least -> contractFit(range, blocks, v, least, q.dust, q.denominations, q.fundedNotes) },
        )
    } else {
        null
    }
    if (fit != null || first != null) {
        // Cashed out first, what she holds here less the coin, her part of it back.
        val after = if (first != null) {
            coverAfter(cover.copy(held = cover.held - minOf(cover.held, first.coin)), first.cap, FIXED_PART)
        } else {
            coverAfter(cover, capped, funded)
        }
        CoverBar(after, Modifier.padding(top = 4.dp, bottom = 6.dp))
        after.says?.let {
            Text(
                "At $hub then: ${it.replaceFirstChar { c -> c.lowercase() }}",
                modifier = Modifier.padding(bottom = 8.dp).testTag("contract-after"),
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant,
            )
        }
    }
    // What it is for sizes it: the exact size, and the coin, under More.
    if (sized && fit != null && covers.size > 1) {
        Segmented(Intent.entries.map { it.label }, picked.ordinal, Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            picked = Intent.entries[it]
            chosenCap = null
            chooseIntent(picked)
        }
        Text(
            if (chosenCap == null) picked.says else "$PROTECTED_AMOUNT chosen under More.",
            modifier = Modifier.padding(bottom = 4.dp).testTag("intent-says"),
            style = MaterialTheme.typography.bodySmall,
            color = colors.onSurfaceVariant,
        )
    }
    Line("Covers up to", sat(first?.cap ?: capped), tag = "quote-cap")
    if (fit != null && coin != null) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FeeLine(
                "Cost", cost, capped, tag = "quote-price", value = sat(cost),
                breakdown = contractCost(range, capped, fee, funded), modifier = Modifier.weight(1f),
            )
            Info("Interest", INTEREST_MEANS)
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Line("Reserve, refundable", sat(range.reserve), Modifier.weight(1f), tag = "contract-reserve")
            Info("Reserve", RESERVE_MEANS)
        }
        Line("Into your balance", sat(funded), tag = "contract-funded")
    }
    Line("For", span(protectsFor.toLong(), blockSecs), tag = "quote-for")
    if (first != null && cashOut != null) {
        val firstFee = contractFee(range, first.cap, blocks, FIXED_PART)
        FeeLine(
            "Cost", firstFee.cost(), first.cap, tag = "quote-price", value = sat(firstFee.cost()),
            breakdown = contractCost(range, first.cap, firstFee, FIXED_PART),
        )
        Line("Reserve, refundable", sat(range.reserve), tag = "contract-reserve")
        if (payWithNotes != null) {
            Say(PAY_WITH_NOTES)
            BigButton("Pay ${sat(first.coin)} from notes", Modifier.fillMaxWidth().testTag("pay-with-notes")) {
                payWithNotes(first.cap, blocks)
            }
            Spacer(Modifier.height(8.dp))
        }
        Say(CASH_OUT_FIRST)
        BigButton(
            "Cash out ${sat(first.coin)} to yourself",
            Modifier.fillMaxWidth().testTag("cash-out-first"),
            quiet = payWithNotes != null,
        ) {
            cashOut(first.coin)
        }
    } else if (coin == null && coins.isEmpty()) {
        Say("Paid from Bitcoin you hold, and you hold none yet. Receive some on Bitcoin, or cash out to yourself, then protect.")
    } else if (fit == null) {
        Text(
            NO_FIT,
            modifier = Modifier.padding(vertical = 8.dp).testTag("contract-problem"),
            style = MaterialTheme.typography.bodyMedium,
            color = colors.error,
        )
    }
    More(modifier = Modifier.testTag("contract-more")) {
        if (range.maxBlocks > range.minBlocks) {
            Text("How long", modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
            Slider(
                value = blocks.toFloat(),
                onValueChange = { blocks = blocksAt(it, range.minBlocks, range.maxBlocks) },
                valueRange = range.minBlocks.toFloat()..range.maxBlocks.toFloat(),
                modifier = Modifier.testTag("contract-blocks"),
            )
        }
        if (fit != null) {
            Line("The hub's part", sat(capped - funded), tag = "contract-hub-part")
            Line("Opening fee", sat(fee.opening), tag = "contract-opening-fee")
            Line(
                "Interest",
                "${sat(fee.interest)} · ${percent(range.ppmYear.toULong())} a year of ${digits(capped - funded)}",
                tag = "contract-interest",
            )
            if (funded > 0uL && (range.ppmYearFunded > 0u || fee.interestFunded > 0uL)) {
                Line(
                    "Interest on yours",
                    "${sat(fee.interestFunded)} · ${percent(range.ppmYearFunded.toULong())} a year",
                    tag = "contract-interest-funded",
                )
            }
        }
        // Its size, after what it costs: larger, the hub funds more of it, room to be paid more at its interest.
        if (fit != null && covers.size > 1) {
            Text(PROTECTED_AMOUNT, modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
            val at = covers.indexOfFirst { it.first == capped }
            Slider(
                value = at.toFloat(),
                onValueChange = { chosenCap = covers[it.roundToInt().coerceIn(covers.indices)].first },
                valueRange = 0f..covers.lastIndex.toFloat(),
                steps = covers.size - 2,
                modifier = Modifier.testTag("contract-cap"),
            )
        }
        if (fit != null && coin != null) {
            if (payers.size > 1) {
                Text("Paid with", modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    for (c in payers) {
                        FilterChip(
                            selected = c == coin,
                            onClick = { chosenCoin = c },
                            label = { Text(sat(c.value)) },
                            modifier = Modifier.padding(end = 8.dp).testTag("contract-coin"),
                        )
                    }
                }
            } else {
                Line("Paid with", "${sat(coin.value)} on Bitcoin", tag = "contract-paid-with")
            }
        }
        Line("Takes", "$SETUP_TAKES · $download")
    }
    val now = System.currentTimeMillis() / 1000
    Text(
        duty(day(now + protectsFor.toLong() * blockSecs.toLong(), now)),
        modifier = Modifier.padding(vertical = 8.dp).testTag("contract-duty"),
        style = MaterialTheme.typography.bodySmall,
        color = colors.onSurfaceVariant,
    )
    Worth(q.mock)
    Spacer(Modifier.height(8.dp))
    if (coin != null) {
        BigButton(
            if (ready) "$verb for ${sat(cost)}" else "Waiting for Bitcoin",
            Modifier.fillMaxWidth().testTag("protect"),
            enabled = fit != null && ready,
        ) {
            open(Chosen(capped, blocks, coin.outpoint), price)
        }
    }
    decline?.let {
        Spacer(Modifier.height(8.dp))
        BigButton("Not now", Modifier.fillMaxWidth().testTag("decline-offer"), quiet = true, onClick = it)
    }
}

/** What a protection's size is called where it is chosen: the most it protects. */
internal const val PROTECTED_AMOUNT = "Protected amount"

/** How protecting what she holds is paid for with no coin on Bitcoin: one cashed out to herself, then. */
internal const val CASH_OUT_FIRST = "None of your bitcoin pays for this. Cash out this much to yourself, then " +
    "protect with it once it arrives. Beyond the cost and the reserve, it comes back to your balance."

/** Paying for a coin with notes, then protecting with it, in one step. */
internal const val PAY_WITH_NOTES = "Or pay for it with your notes here: a swap provider sends this much to " +
    "this wallet on Bitcoin, and protection is set up on it once it confirms. Should it not be, the coin stays yours."

/** Why no coin pays for a contract: each is spent whole, so short of the price or beyond what the largest takes. */
internal const val NO_FIT = "No contract of this hub takes a coin of yours whole: each is short of the price, " +
    "or beyond what the largest contract takes."

/** What protection asks of its owner, said before it is paid for: its end, `ends`, as a day. */
internal fun duty(ends: String): String = "Open Licash now and then, and before it ends on $ends."

/** The blocks at `value` of a slider from `least` to `most`, in whole days but at its ends. */
internal fun blocksAt(value: Float, least: UInt, most: UInt): UInt {
    val days = (value / DAY_BLOCKS).roundToLong().coerceAtLeast(0L) * DAY_BLOCKS
    return days.toUInt().coerceIn(least, most)
}

/** Blocks in a day, about. */
private const val DAY_BLOCKS = 144L
