package org.licash.wallet

import android.content.Context
import org.licash.core.Network

/** What the app keeps besides the wallet: settings, mostly for developers. */
class Prefs(context: Context) {
    private val prefs = context.getSharedPreferences("licash", Context.MODE_PRIVATE)

    /** Shows the test networks and the light client's settings. */
    var developer: Boolean
        get() = prefs.getBoolean("developer", false)
        set(on) = prefs.edit().putBoolean("developer", on).apply()

    /** The network a new wallet is made for. */
    var network: Network
        get() = runCatching { Network.valueOf(prefs.getString("network", null)!!) }
            .getOrDefault(Network.BITCOIN)
        set(network) = prefs.edit().putString("network", network.name).apply()

    /** The only peers of the light client, comma separated, or none. */
    var peers: String
        get() = prefs.getString("peers", "")!!
        set(peers) = prefs.edit().putString("peers", peers.trim()).apply()

    /** The block-dn server to sync from: "default", a URL, or empty. */
    var cdn: String
        get() = prefs.getString("cdn", "default")!!
        set(cdn) = prefs.edit().putString("cdn", cdn.trim()).apply()

    /** The block explorer transactions link to: "default", a URL, or empty for none. */
    var explorer: String
        get() = prefs.getString("explorer", "default")!!
        set(url) = prefs.edit().putString("explorer", url.trim()).apply()

    /**
     * Hubs and relays reached through Tor: by default but on regtest, whose
     * services are local. [network] is that of the wallet, chosen once.
     */
    var tor: Boolean
        get() = prefs.getBoolean("tor", network != Network.REGTEST)
        set(on) = prefs.edit().putBoolean("tor", on).apply()

    /**
     * What the owner said protection is mostly for, by name, if ever said:
     * the size offered at first. None, as in a wallet of an earlier
     * version, means the size offered before there was a choice.
     */
    var intent: String?
        get() = prefs.getString("intent", null)
        set(name) = prefs.edit().putString("intent", name).apply()

    /** The coin on Bitcoin (`txid:vout`) whose offer of protection was last declined, if any. */
    var offerDeclined: String?
        get() = prefs.getString("offer_declined", null)
        set(coin) = prefs.edit().putString("offer_declined", coin).apply()

    /**
     * How much was not protected at `hub` when the owner last dismissed the
     * suggestion to protect it or cash part out: suggested again only once
     * more is not protected.
     */
    fun unprotectedDismissed(hub: String): ULong? =
        prefs.getLong(dismissedKey(hub), -1L).takeIf { it >= 0 }?.toULong()

    fun dismissUnprotected(hub: String, amount: ULong) =
        prefs.edit().putLong(dismissedKey(hub), amount.toLong()).apply()

    private fun dismissedKey(hub: String) = "unprotected_dismissed:" + hub.trimEnd('/')

    /** The name the hub at `url` announced itself under when it was added from those found, if it was. */
    fun hubName(url: String): String? = prefs.getString(hubNameKey(url), null)

    fun nameHub(url: String, name: String) = prefs.edit().putString(hubNameKey(url), name).apply()

    private fun hubNameKey(hub: String) = "hub_name:" + hub.trimEnd('/')

    /** Whether [tor] was set rather than the default. */
    val torChosen: Boolean
        get() = prefs.contains("tor")

    /**
     * The most paid to renew notes a hub that restarted no longer unlinks,
     * in parts per million of them: none if never set, the wallet's own.
     */
    var renewPpm: UInt?
        get() = prefs.getLong("renew_ppm", -1L).takeIf { it >= 0 }?.toUInt()
        set(ppm) = prefs.edit().putLong("renew_ppm", ppm?.toLong() ?: -1L).apply()

    /**
     * Local planning only. A missing preference never authorizes a close.
     * Stored under its name as the proof margin, so upgrades keep it.
     */
    var exitMarginDays: Int
        get() = prefs.getInt("proof_margin_days", 14).takeIf { it in 1..30 } ?: 14
        set(days) {
            require(days in 1..30)
            prefs.edit().putInt("proof_margin_days", days).apply()
        }

    /**
     * The lines of the history under way when last looked, by key: none
     * kept yet (`null`, as before the app kept them) tells of none finished.
     */
    var watched: Set<String>?
        get() = prefs.getStringSet("watched", null)?.toSet()
        set(keys) = prefs.edit().apply { if (keys == null) remove("watched") else putStringSet("watched", keys) }.apply()

    /** Whether the wallet looked for its payments up to the chain's tip once: its first catching up over. */
    var caughtUp: Boolean
        get() = prefs.getBoolean("caught_up", false)
        set(value) = prefs.edit().putBoolean("caught_up", value).apply()

    /** The exits and disputes already told of, by [ExitNotice.key]. */
    var exitsTold: Set<String>
        get() = prefs.getStringSet("exits_told", null)?.toSet().orEmpty()
        set(keys) = prefs.edit().putStringSet("exits_told", keys).apply()

    /** The payouts already warned of as their deadline neared, by key. */
    var warned: Set<String>
        get() = prefs.getStringSet("warned", null)?.toSet().orEmpty()
        set(keys) = prefs.edit().putStringSet("warned", keys).apply()

    /** When a Lightning invoice was last asked, in seconds since the epoch, if ever since kept. */
    var askedAt: Long?
        get() = prefs.getLong("asked_at", -1L).takeIf { it >= 0 }
        set(at) = prefs.edit().putLong("asked_at", at ?: -1L).apply()

    /** The folder (a document tree's URI) automatic backups go to: none if off. */
    var backupFolder: String?
        get() = prefs.getString("backup_folder", null)
        set(uri) = prefs.edit().putString("backup_folder", uri).apply()

    /** When an automatic backup was last written whole, in ms since the epoch, if ever. */
    var backupAt: Long?
        get() = prefs.getLong("backup_at", -1L).takeIf { it >= 0 }
        set(at) = prefs.edit().putLong("backup_at", at ?: -1L).apply()
}
