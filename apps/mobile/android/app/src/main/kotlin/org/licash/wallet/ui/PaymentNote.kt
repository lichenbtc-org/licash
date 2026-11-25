package org.licash.wallet.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import org.licash.core.ExtraCode

/** The most bytes of a payment's note, in UTF-8, as the wallet takes it. */
internal const val MAX_NOTE_BYTES = 200

/** What is typed as a note: its words, one space apart, none if blank. */
internal fun noteOf(typed: String): String? =
    typed.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ").ifEmpty { null }

/** `typed`, cut to what a note holds: whole characters, [MAX_NOTE_BYTES] in UTF-8 at most. */
internal fun fitNote(typed: String): String {
    var bytes = 0
    val kept = StringBuilder()
    var i = 0
    while (i < typed.length) {
        val point = typed.codePointAt(i)
        val size = String(Character.toChars(point)).toByteArray(Charsets.UTF_8).size
        if (bytes + size > MAX_NOTE_BYTES) break
        bytes += size
        kept.appendCodePoint(point)
        i += Character.charCount(point)
    }
    return kept.toString()
}

/** The most characters of an extra code's label, as the wallet takes it. */
internal const val MAX_CODE_LABEL = 40

/** What is typed as an extra code's label: its words, one space apart, none if blank. */
internal fun labelOf(typed: String): String? =
    typed.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ").take(MAX_CODE_LABEL).ifEmpty { null }

/** The name of the code `index` among `codes`: 0 the wallet's own. */
internal fun codeName(index: UInt, codes: List<ExtraCode>): String =
    if (index == 0u) MAIN_IDENTITY else codes.firstOrNull { it.index == index }?.label ?: "Identity $index"

/**
 * A note for the payee, and whether to tell them a code of this wallet's,
 * `shareAs` (0 its own, else one of its extra `codes`): sealed for the
 * payee alone, neither read by the hub nor the relays. Sharing a code tells
 * them who paid, and lets them pay back or keep it as a contact.
 */
@Composable
internal fun NoteFields(
    note: String,
    onNote: (String) -> Unit,
    share: Boolean,
    onShare: (Boolean) -> Unit,
    codes: List<ExtraCode> = emptyList(),
    shareAs: UInt = 0u,
    onShareAs: (UInt) -> Unit = {},
) {
    var picking by remember { mutableStateOf(false) }
    if (picking) {
        Sheet("Share which address", dismiss = { picking = false }) {
            Entry(MAIN_IDENTITY, sub = "The one your contacts know", tag = "share-as-0") {
                picking = false
                onShareAs(0u)
            }
            codes.forEach { code ->
                Entry(code.label, sub = "A separate code", tag = "share-as-${code.index}") {
                    picking = false
                    onShareAs(code.index)
                }
            }
        }
    }
    Column(Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = note,
            onValueChange = { onNote(fitNote(it)) },
            modifier = Modifier.fillMaxWidth().testTag("note-field"),
            singleLine = true,
            label = { Text("Note (optional)") },
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Sentences,
                imeAction = ImeAction.Done,
            ),
            shape = RoundedCornerShape(14.dp),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Only they can read it.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        Toggle(
            "Share my address",
            share,
            sub = if (share) "They'll know it's you" else "They won't know who paid",
            means = "Tells them your Licash address, so they know the payment is from you and can pay you back. " +
                "Anyone they show it to can link it to you.",
            set = onShare,
        )
        if (share && codes.isNotEmpty()) {
            Entry(
                "Share as",
                value = codeName(shareAs, codes),
                tag = "share-as",
                onClick = { picking = true },
            )
        }
    }
}
