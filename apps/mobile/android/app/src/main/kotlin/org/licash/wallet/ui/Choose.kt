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
import org.licash.core.contractCapAtLeast
import org.licash.core.contractFee
import org.licash.core.contractFit
import org.licash.core.contractMaxCap
import org.licash.core.contractPrice
import org.licash.wallet.Chosen
import org.licash.wallet.Engine
import org.licash.wallet.digits
import org.licash.wallet.percent
import org.licash.wallet.sat
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
 * either way. `verb` names accepting it.
 */
@Composable
internal fun Offered(
    engine: Engine,
    q: ContractQuote,
    ready: Boolean,
    verb: String = "Add",
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
 * The contract within `range` over `blocks` that `coin` pays for whole
 * ([contractFit]), of `least` sat at least: none if none takes the coin.
 * The coin is spent whole, the price and the rest of it her part, issued
 * back to her as notes; the rest of the cap, what she asks past her part,
 * is the hub's. Of no `least`, her part only, the hub adding no more than
 * makes a cap.
 */
internal fun fitAt(q: ContractQuote, range: ContractRange, blocks: UInt, coin: DepositCoin, least: ULong = 0uL): ContractFit? =
    contractFit(range, blocks, coin.value, least, 0uL, q.dust, q.denominations, q.fundedNotes)

/**
 * What protection is mostly for, which sizes it at first: her part only,
 * the hub adding as little as it can, at its interest (`halves` none); or
 * room for what she puts in and holds at the hub (`halves` of it, in
 * halves), to pay with; half as much again, to be paid too; or three times
 * it, to be paid mostly. The hub funds the room beyond her part.
 */
internal enum class Intent(val label: String, val says: String, val halves: ULong) {
    FITS("Yours", "Your deposit only, the hub adding nothing. It costs the least.", 0uL),
    PAY("Pay", "Room for what you put in, to pay with.", 2uL),
    BOTH("Both", "Room for half as much again, to receive.", 3uL),
    RECEIVE("Receive", "Room to receive twice what you put in.", 6uL),
}

/**
 * The intent the owner last chose, kept only once she taps one: [Intent.FITS]
 * if none, the hub funding as little as it can.
 */
internal fun intentOf(saved: String?): Intent = Intent.entries.find { it.name == saved } ?: Intent.FITS

/**
 * The cap asked at least of a coin of `coin` sat, with `missing` sat at its
 * hub not protected yet, for `intent`: both as [Intent.halves] says.
 */
internal fun intentLeast(coin: ULong, missing: ULong, intent: Intent): ULong = (coin + missing) * intent.halves / 2uL

/**
 * The contract offered of a coin, `fit` of a least cap (as [fitAt]), with
 * `least` sat asked: of that cap, else of the largest the hub allows for
 * the coin (`most`, [contractMaxCap]), else of her part only.
 */
internal fun fitFor(least: ULong, most: ULong, fit: (least: ULong) -> ContractFit?): ContractFit? =
    fit(least) ?: fit(minOf(least, most)) ?: fit(0uL)

/**
 * The contract offered at first of a coin of `coin` sat, with `missing`
 * sat at its hub not protected yet, for `intent` ([intentLeast], [fitFor]).
 */
internal fun intentFit(coin: ULong, missing: ULong, intent: Intent, most: ULong, fit: (least: ULong) -> ContractFit?): ContractFit? =
    fitFor(intentLeast(coin, missing, intent), most, fit)

/** The contract that takes `coin` whole of her part only, if one does. */
internal fun fitOf(q: ContractQuote, range: ContractRange, blocks: UInt, coin: DepositCoin): ContractFit? =
    fitAt(q, range, blocks, coin)

/**
 * The cap asked at `value` of a slider from `low` to `high`: in steps of
 * 1,000 sat but at its ends, any she likes between.
 */
internal fun capAt(value: Float, low: ULong, high: ULong): ULong {
    if (high <= low) return low
    val at = value.toDouble().coerceIn(low.toDouble(), high.toDouble())
    val rounded = (at / CAP_STEP).roundToLong().toULong() * CAP_STEP.toULong()
    return rounded.coerceIn(low, high)
}

/** The steps of [capAt], in sat. */
private const val CAP_STEP = 1_000.0

/** What to cash out to herself to protect what she holds at a hub: a coin of `coin` sat opening `cap`, `funded` of it hers. */
internal data class CashOutFirst(val cap: ULong, val coin: ULong, val funded: ULong)

/**
 * What is left at a hub of what a coin cashed out of it to protect it
 * takes, for the cash-out's own fees, from `missing` sat: a hundredth and
 * 5,000 sat, more than a provider and miners ask. What is left is covered
 * all the same: the size rounds up.
 */
internal fun cashOutRoom(missing: ULong): ULong = minOf(missing, missing / 100uL + 5_000uL)

/**
 * With no coin on Bitcoin that pays for it, the coin to cash out to herself
 * first to protect the `missing` sat at a hub not protected yet, of her
 * own: those sat but for the cash-out's fees ([cashOutRoom]), the cost and
 * reserve paid from them and the rest her part, issued back, in the
 * contract of her part (`fit` of a coin at a least cap, as [contractFit]),
 * the hub adding what makes a cap of `least` sat at least, as a coin she
 * holds is sized at first ([Intent.FITS]). The price paid from what she
 * holds, the rest is covered. At least what the smallest takes,
 * [FIXED_PART] hers; at most what the `largest` cap takes, all hers. None
 * with nothing missing, or if no contract takes it.
 */
internal fun cashOutOwn(
    least: ULong,
    largest: ULong,
    missing: ULong,
    price: (cap: ULong, funded: ULong) -> ULong,
    fit: (coin: ULong, least: ULong) -> ContractFit?,
): CashOutFirst? {
    if (missing == 0uL || largest < least) return null
    val own = missing - cashOutRoom(missing)
    val coin = own.coerceIn(price(least, FIXED_PART) + FIXED_PART, price(largest, largest) + largest)
    return fit(coin, least)?.let { CashOutFirst(it.cap, coin, it.funded) }
}

/**
 * With no coin on Bitcoin that pays for it, the coin to cash out to herself
 * first to protect the `missing` sat at a hub not protected yet, mostly of
 * the hub's funds (under More: [cashOutOwn] at first): one paying the price
 * of a cap of half again them (`capAtLeast`, as [contractCapAtLeast]; else
 * the `largest`) and [FIXED_PART], her part, the hub funding the rest. If a
 * contract of that cap does not take it whole (`fit` of a coin at a least
 * cap, as [contractFit]), as a hub bounding the cap by the coin refuses,
 * the `least`. None with nothing missing.
 */
internal fun cashOutFirst(
    least: ULong,
    largest: ULong,
    missing: ULong,
    price: (cap: ULong, funded: ULong) -> ULong,
    capAtLeast: (sat: ULong) -> ULong?,
    fit: (coin: ULong, least: ULong) -> ContractFit?,
): CashOutFirst? {
    if (missing == 0uL || largest < least) return null
    val wanted = capAtLeast(missing + missing / 2uL) ?: largest
    return listOf(wanted, least).distinct().firstNotNullOfOrNull { cap ->
        val coin = price(cap, FIXED_PART) + FIXED_PART
        fit(coin, cap)?.takeIf { it.cap == cap }?.let { CashOutFirst(cap, coin, it.funded) }
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
    payWithNotes: ((cap: ULong, blocks: UInt, coin: ULong) -> Unit)? = null,
    cashOut: ((ULong) -> Unit)? = null,
    intent: Intent = Intent.FITS,
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
 * what it covers: of the coin on Bitcoin paying it whole, the smallest at
 * first, her part of it only unless she asks the hub for more (her intent,
 * or as much as she likes). Then what it costs, the reserve, hers and
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
    // With no coin paying it: one paid for with notes, of so large a cover over so many blocks, a coin of so many sat at least.
    payWithNotes: ((cap: ULong, blocks: UInt, coin: ULong) -> Unit)? = null,
    // With no coin paying it: cashing out a coin of so many sat to herself first, to pay it.
    cashOut: ((ULong) -> Unit)? = null,
    // What it is mostly for, sizing it at first, and where her choice is kept.
    intent: Intent = Intent.FITS,
    chooseIntent: (Intent) -> Unit = {},
) {
    val colors = MaterialTheme.colorScheme
    val download = android.text.format.Formatter.formatShortFileSize(LocalContext.current, q.download.toLong())
    val blockSecs = LocalBlockSeconds.current
    var blocks by remember(q) { mutableStateOf(q.suggestedBlocks.coerceIn(range.minBlocks, range.maxBlocks)) }
    // The coins a contract of her part takes whole, the smallest first: it
    // at first, or once the one chosen is not.
    val payers = coins.filter { fitAt(q, range, blocks, it) != null }.sortedBy { it.value }
    var chosenCoin by remember(q) { mutableStateOf<DepositCoin?>(null) }
    val coin = chosenCoin?.takeIf { it in payers } ?: payers.firstOrNull()
    // The cover asked, past her part the hub's at its interest: as she
    // chose it, else as her intent sizes it.
    var chosenCap by remember(q) { mutableStateOf<ULong?>(null) }
    var picked by remember(q) { mutableStateOf(intent) }
    val ownFit = coin?.let { fitAt(q, range, blocks, it) }
    val most = coin?.let { contractMaxCap(range, it.value) } ?: range.minCap
    val fit = coin?.let { c ->
        val at = { least: ULong -> fitAt(q, range, blocks, c, least) }
        when (val asked = chosenCap) {
            null -> intentFit(c.value, cover.missing, picked, most, at)
            else -> fitFor(asked, most, at)
        }
    }
    // The covers she may ask of it, from her part's own to the largest the hub allows.
    val low = ownFit?.cap ?: range.minCap
    val high = maxOf(low, minOf(most, range.maxCap))
    val capped = fit?.cap ?: range.minCap
    val funded = fit?.funded ?: 0uL
    // What the hub is paid: its fee and interest, then the reserve, hers.
    val price = contractPrice(range, capped, blocks, funded)
    val fee = contractFee(range, capped, blocks, funded)
    val cost = fee.cost()
    // It stops protecting a little before it ends.
    val protectsFor = if (blocks > q.afterAssert) blocks - q.afterAssert else 0u
    // None paying it: what she holds here protected by a coin cashed out to
    // herself first, of her own at first; mostly the hub's under More.
    val priced = { c: ULong, f: ULong -> contractPrice(range, c, blocks, f) }
    val fitted = { v: ULong, least: ULong ->
        contractFit(range, blocks, v, least, 0uL, q.dust, q.denominations, q.fundedNotes)
    }
    val capAtLeast = { sat: ULong -> contractCapAtLeast(range, sat) }
    val (least, largest) = range.minCap to range.maxCap
    val own = if (fit == null && cashOut != null) cashOutOwn(least, largest, cover.missing, priced, fitted) else null
    val hubs = if (fit == null && cashOut != null) {
        cashOutFirst(least, largest, cover.missing, priced, capAtLeast, fitted)
    } else {
        null
    }
    val first = own ?: hubs
    val mostlyHubs = hubs?.takeIf { own != null && it != own }
    if (fit != null || first != null) {
        // Cashed out first, what she holds here less the coin, her part of it back.
        val after = if (first != null) {
            coverAfter(cover.copy(held = cover.held - minOf(cover.held, first.coin)), first.cap, first.funded)
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
        val firstFee = contractFee(range, first.cap, blocks, first.funded)
        FeeLine(
            "Cost", firstFee.cost(), first.cap, tag = "quote-price", value = sat(firstFee.cost()),
            breakdown = contractCost(range, first.cap, firstFee, first.funded),
        )
        Line("Reserve, refundable", sat(range.reserve), tag = "contract-reserve")
        if (payWithNotes != null) {
            Say(PAY_WITH_NOTES)
            BigButton("Pay ${sat(first.coin)} from notes", Modifier.fillMaxWidth().testTag("pay-with-notes")) {
                payWithNotes(first.cap, blocks, first.coin)
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
        // Its size, after what it costs: at first her part only; larger, by
        // what it is for or as much as she likes, the hub funds more of it,
        // room to be paid more at its interest.
        if (fit != null && high > low) {
            Text("What it is for", modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
            Segmented(
                Intent.entries.map { it.label },
                picked.ordinal,
                Modifier.fillMaxWidth().padding(vertical = 8.dp).testTag("contract-intent"),
            ) {
                picked = Intent.entries[it]
                chosenCap = null
                chooseIntent(picked)
            }
            Text(
                if (chosenCap == null) picked.says else "$PROTECTED_AMOUNT chosen below.",
                modifier = Modifier.padding(bottom = 4.dp).testTag("intent-says"),
                style = MaterialTheme.typography.bodySmall,
                color = colors.onSurfaceVariant,
            )
            Text(PROTECTED_AMOUNT, modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
            Slider(
                value = capped.coerceIn(low, high).toFloat(),
                onValueChange = { chosenCap = capAt(it, low, high) },
                valueRange = low.toFloat()..high.toFloat(),
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
        // Cashed out first: less of hers, the hub funding nearly all of it at its interest.
        if (mostlyHubs != null && cashOut != null) {
            val fee = contractFee(range, mostlyHubs.cap, blocks, mostlyHubs.funded)
            Text("Mostly the hub's", modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodyLarge)
            Say(MOSTLY_THE_HUBS)
            Line("Covers up to", sat(mostlyHubs.cap), tag = "hubs-cap")
            Line("Cost", sat(fee.cost()), tag = "hubs-price")
            if (payWithNotes != null) {
                BigButton(
                    "Pay ${sat(mostlyHubs.coin)} from notes",
                    Modifier.fillMaxWidth().padding(top = 8.dp).testTag("pay-hubs-with-notes"),
                    quiet = true,
                ) {
                    payWithNotes(mostlyHubs.cap, blocks, mostlyHubs.coin)
                }
            }
            BigButton(
                "Cash out ${sat(mostlyHubs.coin)} to yourself",
                Modifier.fillMaxWidth().padding(top = 8.dp).testTag("cash-out-hubs"),
                quiet = true,
            ) {
                cashOut(mostlyHubs.coin)
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

/** Protecting what she holds at a hub mostly with the hub's funds, under More. */
internal const val MOSTLY_THE_HUBS = "Or move out only the cost, the reserve and 1,000 sat: the hub funds nearly " +
    "all of the protection and charges its interest on it. It costs more, but less of your money moves."

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
