package org.licash.wallet

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.licash.core.Activity
import org.licash.core.blockSeconds
import org.licash.wallet.ui.ActivityDetails
import org.licash.wallet.ui.History
import org.licash.wallet.ui.Home
import org.licash.wallet.ui.LocalBlockSeconds
import org.licash.wallet.ui.LicashTheme
import org.licash.wallet.ui.Money
import org.licash.wallet.ui.Onboarding
import org.licash.wallet.ui.Receive
import org.licash.wallet.ui.Send
import org.licash.wallet.ui.Settings
import org.licash.wallet.ui.StatsScreen
import org.licash.wallet.ui.Wordmark

private sealed interface Screen {
    data object Home : Screen
    data object Receive : Screen

    /**
     * Sending, or with `cashOut`, a hub, paying notes there out: all of
     * them, or as much as chosen, `amount` suggested.
     */
    data class Send(
        val link: String?,
        val cashOut: String? = null,
        val from: Screen = Home,
        /** The address of this wallet's that `link` pays, if it does. */
        val own: String? = null,
        val amount: ULong? = null,
    ) : Screen
    data object Settings : Screen

    /**
     * Where the money is, opened from `from`: all of it, or `at` one
     * place, a hub's URL or what is on Bitcoin.
     */
    data class Money(val from: Screen = Home, val at: String? = null) : Screen

    /** The history: what came in and went out. */
    data object History : Screen

    /** What the history came to: counts, fees and times, by period. */
    data object Stats : Screen

    /** One line of the history, opened from `from`. */
    data class Details(val activity: Activity, val from: Screen = History) : Screen
}

/** The screen back goes to from `screen`. */
private fun parent(screen: Screen): Screen = when (screen) {
    is Screen.Send -> screen.from
    is Screen.Money -> if (screen.at != null) screen.copy(at = null) else screen.from
    is Screen.Details -> screen.from
    Screen.Stats -> Screen.History
    else -> Screen.Home
}

/** How deep in the app `screen` is: Home, a page of it, what a page opens. */
private fun depth(screen: Screen): Int = when (screen) {
    Screen.Home -> 0
    is Screen.Details, Screen.Stats -> 2
    is Screen.Send -> if (screen.from is Screen.Money) 2 else 1
    else -> 1
}

/**
 * How one screen gives way to another: a fade, and a short slide the way
 * it goes, deeper from the right and back from the left. The system's
 * setting for animations scales it, or ends it.
 */
private fun AnimatedContentTransitionScope<Screen>.moving(): ContentTransform {
    val way = if (depth(targetState) >= depth(initialState)) 1 else -1
    return (fadeIn(tween(210, delayMillis = 70)) + slideInHorizontally(tween(280)) { it / 14 * way }) togetherWith
        (fadeOut(tween(70)) + slideOutHorizontally(tween(280)) { -it / 14 * way })
}

class MainActivity : ComponentActivity() {
    /** A `bitcoin:` link the app was opened with, not yet shown. */
    private var link by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        link = linkOf(intent)
        val engine = (application as LicashApp).engine
        setContent {
            LicashTheme { App(engine, link) { link = null } }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        linkOf(intent)?.let { link = it }
    }

    private fun linkOf(intent: Intent?): String? =
        intent?.takeIf { it.action == Intent.ACTION_VIEW }?.dataString
}

@Composable
private fun App(engine: Engine, link: String?, linkShown: () -> Unit) {
    val ui by engine.ui.collectAsStateWithLifecycle()
    var screen by remember { mutableStateOf<Screen>(Screen.Home) }
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(Unit) { engine.events.collect { snackbar.showSnackbar(it.text) } }
    // Asked once there is a wallet, before its first catching up, to tell of
    // it and of payments out of sight: Android asks at most twice, then no
    // more once refused.
    val context = LocalContext.current
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        AppLog.info(if (granted) "notifications allowed" else "notifications not allowed")
    }
    val watching = ui.watch != Watch.NONE
    LaunchedEffect(ui.wallet, watching) {
        val missing = Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        if ((ui.wallet || watching) && missing) ask.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
    LaunchedEffect(ui.wallet) { if (!ui.wallet) screen = Screen.Home }
    LaunchedEffect(link, ui.wallet) {
        if (link != null && ui.wallet) {
            screen = Screen.Send(link)
            linkShown()
        }
    }
    BackHandler(enabled = screen != Screen.Home) { screen = parent(screen) }
    // Counts of blocks are told in the time of the wallet's network.
    CompositionLocalProvider(LocalBlockSeconds provides blockSeconds(ui.network)) {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            // Test tags as resource ids, for the end-to-end tests to find.
            // Above the keyboard, as it shows: what a screen asks to type and its button in sight.
            Box(
                Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding()
                    .semantics { testTagsAsResourceId = true },
            ) {
                when {
                    !ui.loaded -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Wordmark(size = 40)
                    }
                    !ui.wallet -> Onboarding(engine, ui)
                    else -> AnimatedContent(
                        targetState = screen,
                        modifier = Modifier.fillMaxSize(),
                        transitionSpec = { moving() },
                        // A page that only changes what it shows keeps its state, and does not animate.
                        contentKey = { it::class },
                        label = "screen",
                    ) { s ->
                        when (s) {
                            Screen.Home -> Home(
                                engine,
                                ui,
                                receive = { screen = Screen.Receive },
                                send = { screen = Screen.Send(null) },
                                settings = { screen = Screen.Settings },
                                money = { screen = Screen.Money(at = it) },
                                history = { screen = Screen.History },
                                open = { screen = Screen.Details(it, Screen.Home) },
                            )
                            Screen.History -> History(
                                engine,
                                ui,
                                open = { screen = Screen.Details(it) },
                                stats = { screen = Screen.Stats },
                            ) { screen = Screen.Home }
                            Screen.Stats -> StatsScreen(engine, ui) { screen = Screen.History }
                            Screen.Receive -> Receive(engine) { screen = Screen.Home }
                            is Screen.Send -> Send(
                                engine,
                                ui,
                                s.link,
                                s.cashOut,
                                s.own,
                                s.amount,
                                toReceive = { screen = Screen.Receive },
                            ) { screen = s.from }
                            Screen.Settings -> Settings(engine, ui, balance = { screen = Screen.Money(Screen.Settings) }) {
                                screen = Screen.Home
                            }
                            is Screen.Money -> Money(
                                engine,
                                ui,
                                at = s.at,
                                go = { screen = s.copy(at = it) },
                                cashOut = { hub, amount -> screen = Screen.Send(null, hub, s, amount = amount) },
                                payOwn = { link, own -> screen = Screen.Send(link, from = s, own = own) },
                                open = { screen = Screen.Details(it, s) },
                            ) { screen = s.from }
                            is Screen.Details -> ActivityDetails(engine, ui, s.activity) { screen = s.from }
                        }
                    }
                }
            }
        }
    }
}
