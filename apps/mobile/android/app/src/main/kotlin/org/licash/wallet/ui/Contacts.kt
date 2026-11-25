package org.licash.wallet.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.licash.core.Contact
import org.licash.wallet.Engine
import org.licash.wallet.explain

/*
 * Contacts: the people the wallet pays, by name, each a payment code
 * kept. Picked to pay instead of scanning; kept after paying a code.
 */

/** The contacts to pay, by name: a tap pays one; each may be forgotten. Nothing while there are none. */
@Composable
internal fun Contacts(engine: Engine, pay: (Contact) -> Unit) {
    val scope = rememberCoroutineScope()
    var contacts by remember { mutableStateOf<List<Contact>>(emptyList()) }
    var forgetting by remember { mutableStateOf<Contact?>(null) }
    LaunchedEffect(Unit) { engine.contacts().onSuccess { contacts = it } }
    if (contacts.isEmpty()) return
    Text(
        "Contacts",
        modifier = Modifier.padding(top = 24.dp, bottom = 4.dp),
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    for (c in contacts) {
        Row(
            Modifier.fillMaxWidth().clickable { pay(c) }.padding(start = 4.dp).testTag("contact ${c.name}"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(c.name, Modifier.weight(1f), style = MaterialTheme.typography.bodyLarge)
            IconButton(onClick = { forgetting = c }) {
                Icon(Icons.Filled.Close, contentDescription = "Forget ${c.name}")
            }
        }
    }
    forgetting?.let { c ->
        Sheet("Forget ${c.name}?", { forgetting = null }) {
            Say("Their address is forgotten: to pay them again, scan it again.")
            BigButton("Forget", Modifier.fillMaxWidth().testTag("forget-contact"), danger = true) {
                forgetting = null
                scope.launch {
                    engine.removeContact(c.name)
                    engine.contacts().onSuccess { contacts = it }
                }
            }
        }
    }
}

/**
 * After paying the code `code`, or being paid by its wallet if `payer`:
 * whom, if a contact, else keeping it as one, by a name.
 */
@Composable
internal fun SaveContact(engine: Engine, code: String, payer: Boolean = false) {
    val scope = rememberCoroutineScope()
    var looked by remember { mutableStateOf(false) }
    var known by remember { mutableStateOf<Contact?>(null) }
    var naming by remember { mutableStateOf(false) }
    var name by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(code) {
        known = engine.contactOf(code).getOrNull()
        looked = true
    }
    if (!looked) return
    Column(Modifier.fillMaxWidth().padding(top = 12.dp)) {
        val contact = known
        when {
            contact != null -> Text(
                if (payer) "From ${contact.name}" else "To ${contact.name}",
                modifier = Modifier.fillMaxWidth().testTag("contact"),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            naming -> {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    modifier = Modifier.fillMaxWidth().testTag("contact-name"),
                    singleLine = true,
                    label = { Text("Their name") },
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.Words,
                        imeAction = ImeAction.Done,
                    ),
                    shape = RoundedCornerShape(14.dp),
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Spacer(Modifier.height(12.dp))
                BigButton("Save", Modifier.fillMaxWidth().testTag("save-contact-name"), enabled = name.isNotBlank()) {
                    scope.launch {
                        engine.saveContact(name, code).fold(
                            { known = it; naming = false },
                            { error = explain(it) },
                        )
                    }
                }
            }
            else -> BigButton("Save as a contact", Modifier.fillMaxWidth().testTag("save-contact"), quiet = true) {
                naming = true
            }
        }
    }
}
