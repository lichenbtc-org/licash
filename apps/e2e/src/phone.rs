//! The Android app on an emulator or a phone, driven through adb for the
//! end-to-end tests: screens read with uiautomator, codes from screenshots,
//! links opened in it. The device is the one adb picks (`ANDROID_SERIAL`);
//! the app the APK at `$LICASH_E2E_APP`, installed afresh for each test.

use std::{cell::Cell, ops::RangeInclusive, path::PathBuf, time::Duration};

use anyhow::{ensure, Context};
use tokio::process::Command;

use crate::{until, Eco};

/// The app's package.
pub const PACKAGE: &str = "org.licash.wallet";

/// The app on a device, its data cleared.
pub struct Phone {
    apk: PathBuf,
}

/// A view on screen: its text or description, its test tag, whether it
/// has the focus (a field typed in), and where.
#[derive(Clone, Debug)]
pub struct View {
    pub text: String,
    pub id: String,
    pub focused: bool,
    bounds: [i32; 4],
}

impl View {
    fn center(&self) -> (i32, i32) {
        let [l, t, r, b] = self.bounds;
        ((l + r) / 2, (t + b) / 2)
    }
}

/// The digits of `text`, as a number: an amount as the app shows it.
pub fn amount(text: &str) -> u64 {
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// The port of a URL or an address, after its last colon.
fn port(url: &str) -> anyhow::Result<u16> {
    let rest = url.rsplit(':').next().context("no port")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Ok(digits.parse()?)
}

/// What `text` holds, the entities uiautomator writes undone.
fn unescape(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';') else { break };
        let entity = &rest[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match ch {
            Some(ch) => {
                out.push(ch);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The value of attribute `name` in the attributes `node` of an element.
fn attribute(node: &str, name: &str) -> String {
    let key = format!(" {name}=\"");
    let Some(at) = node.find(&key) else {
        return String::new();
    };
    let value = &node[at + key.len()..];
    unescape(&value[..value.find('"').unwrap_or(value.len())])
}

/// The views in the layout uiautomator dumped, those with a text, a
/// description or a test tag.
fn views_in(xml: &str) -> Vec<View> {
    let mut views = Vec::new();
    for node in xml.split("<node").skip(1) {
        let node = &node[..node.find('>').unwrap_or(node.len())];
        let mut text = attribute(node, "text");
        if text.is_empty() {
            text = attribute(node, "content-desc");
        }
        let id = attribute(node, "resource-id");
        if text.is_empty() && id.is_empty() {
            continue;
        }
        let bounds = attribute(node, "bounds");
        let numbers: Vec<i32> = bounds
            .split(|c: char| !c.is_ascii_digit())
            .filter(|n| !n.is_empty())
            .filter_map(|n| n.parse().ok())
            .collect();
        let Ok(bounds) = <[i32; 4]>::try_from(numbers) else {
            continue;
        };
        let focused = attribute(node, "focused") == "true";
        views.push(View {
            text,
            id,
            focused,
            bounds,
        });
    }
    views
}

/// The text of the first QR code in the PNG `image`, if any.
fn qr_in(image: &[u8]) -> anyhow::Result<Option<String>> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(image));
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info()?;
    let mut pixels = vec![0; reader.output_buffer_size().context("too big")?];
    let info = reader.next_frame(&mut pixels)?;
    let channels = info.color_type.samples();
    let (width, height) = (info.width as usize, info.height as usize);
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let at = (y * width + x) * channels;
        if channels < 3 {
            return pixels[at];
        }
        let [r, g, b] = [0, 1, 2].map(|i| u32::from(pixels[at + i]));
        ((r * 299 + g * 587 + b * 114) / 1000) as u8
    });
    for grid in prepared.detect_grids() {
        if let Ok((_, text)) = grid.decode() {
            return Ok(Some(text));
        }
    }
    Ok(None)
}

impl Phone {
    /// The app of the APK at `$LICASH_E2E_APP`; none if unset, for the
    /// tests to skip.
    pub fn from_env() -> Option<Self> {
        let apk = std::env::var_os("LICASH_E2E_APP")?;
        Some(Self { apk: apk.into() })
    }

    /// Install the app, its data cleared, and have the device reach the
    /// hubs, the relay, the swap provider, the bridges and Bitcoin Core of
    /// `eco` at the ports published on this host. Bitcoin Core's
    /// peer-to-peer port is 18444 on the device.
    pub async fn fresh(&self, eco: &Eco) -> anyhow::Result<()> {
        let apk = self.apk.to_str().context("the APK's path")?;
        self.adb(&["install", "-r", "-g", apk]).await?;
        self.shell(&format!("pm clear {PACKAGE}")).await?;
        // Cleared with its data: granted again, so that no dialog covers
        // the app (notifications from Android 13, as the emulators run).
        for permission in ["CAMERA", "POST_NOTIFICATIONS"] {
            self.shell(&format!(
                "pm grant {PACKAGE} android.permission.{permission}"
            ))
            .await?;
        }
        let reached = [eco.hub(1), eco.hub(2), eco.relay(), eco.swaps()];
        for url in reached.into_iter().chain([eco.bridge(), eco.bridge2()]) {
            let at = format!("tcp:{}", port(url)?);
            self.adb(&["reverse", &at, &at]).await?;
        }
        let p2p = format!("tcp:{}", port(eco.p2p())?);
        self.adb(&["reverse", "tcp:18444", &p2p]).await?;
        Ok(())
    }

    async fn adb(&self, args: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = Command::new("adb")
            .args(args)
            .kill_on_drop(true)
            .output()
            .await
            .context("adb, of the Android SDK's platform tools")?;
        ensure!(
            output.status.success(),
            "adb {}: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    /// `command` run in the device's shell, and what it prints.
    pub async fn shell(&self, command: &str) -> anyhow::Result<String> {
        let out = self.adb(&["shell", command]).await?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Whether the app shows a notification in its channel `channel`.
    pub async fn notifying(&self, channel: &str) -> anyhow::Result<bool> {
        let shown = self.shell("dumpsys notification --noredact").await?;
        let (app, channel) = (
            format!("pkg={PACKAGE} "),
            format!("Notification(channel={channel} "),
        );
        Ok(shown
            .lines()
            .any(|l| l.contains("NotificationRecord(") && l.contains(&app) && l.contains(&channel)))
    }

    /// The views on screen.
    pub async fn views(&self) -> anyhow::Result<Vec<View>> {
        // uiautomator fails now and then while the screen changes.
        let mut failed = None;
        for _ in 0..5 {
            match self.dump().await {
                Ok(views) => return Ok(views),
                Err(e) => failed = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err(failed.context("never dumped")?)
    }

    async fn dump(&self) -> anyhow::Result<Vec<View>> {
        let file = "/sdcard/licash-e2e-ui.xml";
        self.shell(&format!("uiautomator dump {file}")).await?;
        let xml = String::from_utf8(self.adb(&["exec-out", "cat", file]).await?)?;
        ensure!(xml.contains("<hierarchy"), "no layout dumped: {xml}");
        Ok(views_in(&xml))
    }

    /// The first view on screen whose text is `text`, else the first whose
    /// text starts with it.
    pub async fn find(&self, text: &str) -> anyhow::Result<Option<View>> {
        let views = self.views().await?;
        let exact = views.iter().position(|v| v.text == text);
        let at = exact.or_else(|| views.iter().position(|v| v.text.starts_with(text)));
        Ok(at.map(|at| views[at].clone()))
    }

    /// Wait up to `secs` for a view whose text is or starts with `text`.
    pub async fn wait(&self, text: &str, secs: u64) -> anyhow::Result<View> {
        let what = format!("{text:?} on screen");
        until(&what, secs, || self.find(text)).await
    }

    /// Tap `view`.
    pub async fn tap_view(&self, view: &View) -> anyhow::Result<()> {
        let (x, y) = view.center();
        self.shell(&format!("input tap {x} {y}")).await?;
        Ok(())
    }

    /// Tap the view whose text is or starts with `text`, waiting up to 30 s
    /// for it.
    pub async fn tap(&self, text: &str) -> anyhow::Result<()> {
        let view = self.wait(text, 30).await?;
        self.tap_view(&view).await
    }

    /// The view tagged `id`, waiting up to `secs` for it.
    pub async fn by_id(&self, id: &str, secs: u64) -> anyhow::Result<View> {
        until(&format!("view {id:?}"), secs, || async {
            Ok(self.views().await?.into_iter().find(|v| v.id == id))
        })
        .await
    }

    /// Tap the view tagged `id`, waiting up to 30 s for it.
    pub async fn tap_id(&self, id: &str) -> anyhow::Result<()> {
        let view = self.by_id(id, 30).await?;
        self.tap_view(&view).await
    }

    /// Wait for the app to say it copied something, then for the
    /// system's clipboard preview to go: from Android 13 it covers the
    /// bottom left for some 6 s, and a tap there opens its editor instead.
    pub async fn copied(&self) -> anyhow::Result<()> {
        self.wait("Copied", 10).await?;
        let shown = || async {
            let windows = self.shell("dumpsys window windows").await?;
            Ok::<_, anyhow::Error>(windows.contains("ClipboardOverlay"))
        };
        // Shown once the clip changed, a moment after the app says so.
        let _ = until("the clipboard preview", 3, || async {
            Ok(shown().await?.then_some(()))
        })
        .await;
        until("the clipboard preview gone", 20, || async {
            Ok((!shown().await?).then_some(()))
        })
        .await
    }

    /// Whether a view tagged `id` is on screen now.
    pub async fn has(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.views().await?.iter().any(|v| v.id == id))
    }

    /// Wait up to `secs` for no view to be tagged `id`.
    pub async fn gone(&self, id: &str, secs: u64) -> anyhow::Result<()> {
        until(&format!("view {id:?} gone"), secs, || async {
            Ok((!self.has(id).await?).then_some(()))
        })
        .await
    }

    /// Wait up to `secs` for the view tagged `id` to say `text`, or to
    /// start with it: the view.
    pub async fn tagged(&self, id: &str, text: &str, secs: u64) -> anyhow::Result<View> {
        let shown = std::cell::RefCell::new(None);
        until(&format!("view {id:?} saying {text:?}"), secs, || async {
            let view = self.views().await?.into_iter().find(|v| v.id == id);
            *shown.borrow_mut() = view.as_ref().map(|v| v.text.clone());
            Ok(view.filter(|v| v.text.starts_with(text)))
        })
        .await
        .with_context(|| format!("{:?} shown", shown.borrow()))
    }

    /// Drag the slider tagged `id` from its middle to `at`, from 0 (its
    /// start) to 1 (its end), waiting up to 30 s for it. Its track is
    /// narrower than the view, and a drag's first pixels only start it:
    /// to its very start or end, past the view, halfway to the screen's
    /// edge (a dialog's slider is as far from either).
    pub async fn slide_id(&self, id: &str, at: f32) -> anyhow::Result<()> {
        let view = self.by_id(id, 30).await?;
        let [left, _, right, _] = view.bounds;
        let (from, y) = view.center();
        let to = if at <= 0.0 {
            left / 2
        } else if at >= 1.0 {
            right + left / 2
        } else {
            left + ((right - left) as f32 * at) as i32
        };
        self.shell(&format!("input swipe {from} {y} {to} {y} 500"))
            .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        // A swipe may stop short of an end: a tap at it clamps there,
        // where the slider is now (a sheet shrinking as it moved, say).
        let end = match at {
            at if at <= 0.0 => Some(left + 1),
            at if at >= 1.0 => Some(right - 1),
            _ => None,
        };
        if let Some(x) = end {
            let (_, y) = self.by_id(id, 10).await?.center();
            self.shell(&format!("input tap {x} {y}")).await?;
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Ok(())
    }

    /// Type `text` into the field in focus.
    pub async fn type_text(&self, text: &str) -> anyhow::Result<()> {
        ensure!(!text.contains('\''), "no quotes to type: {text}");
        let text = text.replace(' ', "%s");
        self.shell(&format!("input text '{text}'")).await?;
        Ok(())
    }

    /// Tap the field tagged `id` and type `text` in it, the keyboard
    /// hidden after.
    pub async fn fill_id(&self, id: &str, text: &str) -> anyhow::Result<()> {
        self.tap_id(id).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.type_text(text).await?;
        self.hide_keyboard().await?;
        // Its screen still up: a keyboard closed, not a sheet typed in.
        ensure!(
            self.has(id).await?,
            "{id:?} gone once its keyboard was hidden: its screen dismissed"
        );
        Ok(())
    }

    /// Tap the field tagged `id` and paste what was copied into it, as a
    /// keyboard's paste key does: what the field then holds, the keyboard
    /// hidden after.
    pub async fn paste_id(&self, id: &str) -> anyhow::Result<String> {
        self.tap_id(id).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        // KEYCODE_PASTE.
        self.shell("input keyevent 279").await?;
        let field = until(&format!("something pasted in {id:?}"), 10, || async {
            let field = self.views().await?.into_iter().find(|v| v.id == id);
            Ok(field.filter(|v| !v.text.is_empty()))
        })
        .await?;
        self.hide_keyboard().await?;
        Ok(field.text)
    }

    pub async fn hide_keyboard(&self) -> anyhow::Result<()> {
        // Escape closes an on-screen keyboard, not the screen, but only if
        // one is drawn: typed through a hardware keyboard, as on CI, none
        // is, and a sheet, a dialog, takes Escape as back and is dismissed.
        // The input method says it is shown then all the same
        // (`mInputShown=true`): its keyboard's view and window say whether
        // it is drawn, as `InputMethodService::isInputViewShown` does.
        let ime = self.shell("dumpsys input_method").await?;
        let said = |what: &str| ime.split_whitespace().any(|w| w == what);
        if !(said("mIsInputViewShown=true") && said("mWindowVisible=true")) {
            return Ok(());
        }
        self.shell("input keyevent 111").await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok(())
    }

    /// Scroll down until a view tagged `id` shows: it.
    pub async fn scroll_to_id(&self, id: &str) -> anyhow::Result<View> {
        self.scroll_to(&format!("view {id:?}"), false, |v| v.id == id)
            .await
    }

    /// Scroll down until a view whose text starts with `start` shows: it.
    /// A view partly in sight may show no text yet, only its tag.
    pub async fn scroll_to_text(&self, start: &str) -> anyhow::Result<View> {
        self.scroll_to(&format!("text {start:?}"), false, |v| {
            v.text.starts_with(start)
        })
        .await
    }

    /// [`Self::scroll_to_text`] on Home, where a swipe up of 64 dp beyond
    /// the end of its middle opens the history: swipes of 48 dp, many.
    pub async fn scroll_home_to_text(&self, start: &str) -> anyhow::Result<View> {
        self.scroll_to(&format!("text {start:?} on Home"), true, |v| {
            v.text.starts_with(start)
        })
        .await
    }

    async fn scroll_to(
        &self,
        what: &str,
        short: bool,
        wanted: impl Fn(&View) -> bool,
    ) -> anyhow::Result<View> {
        let size = self.shell("wm size").await?;
        let size = size.rsplit(' ').next().context("no screen size")?.trim();
        let (width, height) = size.split_once('x').context("no screen size")?;
        let (x, height): (i32, i32) = (width.parse::<i32>()? / 2, height.parse()?);
        // The density in use: the override, printed last, if any.
        let density = self.shell("wm density").await?;
        let density: i32 = density
            .rsplit(' ')
            .next()
            .context("no screen density")?
            .trim()
            .parse()?;
        let dp48 = 48 * density / 160;
        // Above the navigation bar, 48 dp at most: a view lower, cut off
        // under it or still sliding in, a tap on it would go to Home.
        let clear = height - dp48;
        let (from, to, tries) = if short {
            (height / 2 + dp48 / 2, height / 2 - dp48 / 2, 40)
        } else {
            (height * 7 / 10, height * 3 / 10, 8)
        };
        for _ in 0..tries {
            let found = self.settled(&wanted).await?;
            if let Some(view) = found.filter(|v| v.bounds[3] <= clear) {
                return Ok(view);
            }
            // Slow when short: no fling to carry it further.
            let ms = if short { 600 } else { 300 };
            self.shell(&format!("input swipe {x} {from} {x} {to} {ms}"))
                .await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        anyhow::bail!("no {what} in sight however far scrolled")
    }

    /// The view `wanted`, once at rest: where two dumps in a row show it,
    /// not moving with a sheet sliding up or a list still flung. None if
    /// not on screen; where last seen if it never rests in 3 s.
    async fn settled(&self, wanted: impl Fn(&View) -> bool) -> anyhow::Result<Option<View>> {
        let mut seen = self.views().await?.into_iter().find(&wanted);
        for _ in 0..10 {
            let Some(before) = seen else { return Ok(None) };
            tokio::time::sleep(Duration::from_millis(300)).await;
            seen = self.views().await?.into_iter().find(&wanted);
            if seen.as_ref().is_some_and(|now| now.bounds == before.bounds) {
                return Ok(seen);
            }
        }
        Ok(seen)
    }

    pub async fn back(&self) -> anyhow::Result<()> {
        self.shell("input keyevent 4").await?;
        Ok(())
    }

    /// Open the `bitcoin:` link `uri` in the app, as a link tapped elsewhere.
    pub async fn link(&self, uri: &str) -> anyhow::Result<()> {
        ensure!(!uri.contains('\''), "no quotes in a link: {uri}");
        let start = format!("am start -W -a android.intent.action.VIEW -d '{uri}' {PACKAGE}");
        let out = self.shell(&start).await?;
        ensure!(!out.contains("Error"), "{out}");
        Ok(())
    }

    /// Stop the app and start it again: how long it took to show.
    pub async fn launch(&self) -> anyhow::Result<Duration> {
        self.shell(&format!("am force-stop {PACKAGE}")).await?;
        let start = format!("am start -W -n {PACKAGE}/.MainActivity");
        let out = self.shell(&start).await?;
        let total = out
            .lines()
            .find_map(|l| l.trim().strip_prefix("TotalTime: "));
        let total: u64 = total.context("no TotalTime")?.trim().parse()?;
        Ok(Duration::from_millis(total))
    }

    /// The text of the QR code on screen, waiting up to `secs` for one.
    pub async fn qr(&self, secs: u64) -> anyhow::Result<String> {
        until("a QR code on screen", secs, || async {
            let image = self.adb(&["exec-out", "screencap", "-p"]).await?;
            qr_in(&image)
        })
        .await
    }

    /// The app's file at `path`, relative to its data directory.
    pub async fn file(&self, path: &str) -> anyhow::Result<String> {
        let out = self
            .adb(&["exec-out", "run-as", PACKAGE, "cat", path])
            .await?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// The balance Home shows, in sat.
    pub async fn balance(&self) -> anyhow::Result<u64> {
        Ok(amount(&self.by_id("balance", 30).await?.text))
    }

    /// Wait up to `secs` for Home to show a balance within `sat`.
    pub async fn wait_balance(&self, sat: RangeInclusive<u64>, secs: u64) -> anyhow::Result<()> {
        let shown = Cell::new(0);
        let what = format!("a balance of {sat:?}");
        until(&what, secs, || async {
            shown.set(self.balance().await?);
            Ok(sat.contains(&shown.get()).then_some(()))
        })
        .await
        .with_context(|| format!("{} shown", shown.get()))
    }

    /// The first screen with no wallet, past the tour: Create and Restore
    /// in sight.
    pub async fn past_tour(&self) -> anyhow::Result<()> {
        until("the tour", 60, || async {
            let views = self.views().await?;
            Ok(views
                .iter()
                .any(|v| v.id == "tour-skip" || v.id == "create")
                .then_some(()))
        })
        .await?;
        if self.has("tour-skip").await? {
            self.tap_id("tour-skip").await?;
        }
        self.by_id("create", 30).await?;
        Ok(())
    }

    /// Make a wallet on regtest, its light client reaching Bitcoin Core
    /// only, chosen behind "Use a test network", then turn on advanced
    /// mode in Settings, for the views the tests read. It is then set up
    /// a screen at a time: its backup, put off, then a hub asked for. The
    /// tour comes first: a page of it, then skipped.
    pub async fn onboard(&self) -> anyhow::Result<()> {
        self.tagged("tour-title", "Bitcoin is gold in a vault", 60)
            .await?;
        self.tap_id("tour-next").await?;
        self.tagged("tour-title", "A gold bar for a loaf of bread?", 30)
            .await?;
        self.past_tour().await?;
        // Advanced mode, kept from a wallet deleted before, shows them already.
        if !self.has("network regtest").await? {
            self.tap_id("test-network").await?;
        }
        // Regtest's node is 127.0.0.1:18444, Core's reversed to the phone.
        self.tap_id("network regtest").await?;
        self.tap_id("create").await?;
        // The light client of the network first chosen stops first. A
        // wallet made here is asked to back up before anything else.
        self.by_id("setup-backup", 180).await?;
        self.tap_id("backup-later").await?;
        self.by_id("choose-hub", 30).await?;
        self.tap("Settings").await?;
        self.by_id("hubs", 30).await?;
        if !self.has("advanced").await? {
            let toggle = self.scroll_to_id("toggle Advanced mode").await?;
            self.tap_view(&toggle).await?;
            self.by_id("advanced", 30).await?;
        }
        self.back_to("choose-hub").await
    }

    /// Connect to the hub at `url`, by its address, where a wallet with no
    /// hub yet is asked for one: Home then shows what it holds.
    pub async fn connect(&self, url: &str) -> anyhow::Result<()> {
        self.fill_id("hub-address", url).await?;
        self.tap_id("add-address").await?;
        self.home(60).await
    }

    /// Wait up to `secs` for Home, with a hub: to receive and to send. A
    /// wallet holding nothing yet is shown its first funding in Home's
    /// place: left, for Home, whose card leads back to it.
    pub async fn home(&self, secs: u64) -> anyhow::Result<()> {
        until("Home", secs, || async {
            if self.has("receive").await? {
                return Ok(Some(()));
            }
            if self.has("funding-hide").await? {
                self.tap_id("funding-hide").await?;
            }
            Ok(None)
        })
        .await
    }

    /// Go back a screen, to the one showing a view tagged `id`.
    pub async fn back_to(&self, id: &str) -> anyhow::Result<()> {
        self.back().await?;
        self.by_id(id, 30).await?;
        Ok(())
    }

    /// The payment code Receive shows, for any amount, back on Home after.
    pub async fn code(&self) -> anyhow::Result<String> {
        self.tap_id("receive").await?;
        self.wait("QR code", 30).await?;
        let code = self.qr(30).await?;
        self.tap("Back").await?;
        self.home(30).await?;
        Ok(code)
    }

    /// The address on Bitcoin any wallet pays, bare, as Receive's Bitcoin
    /// tab shows it, back on Home after.
    pub async fn bitcoin_code(&self) -> anyhow::Result<String> {
        self.tap_id("receive").await?;
        self.tap_id("segment Bitcoin").await?;
        self.tagged("way", "Bitcoin address", 30).await?;
        // The code shown before it gives way once the address is made.
        let code = until("a code with an address on Bitcoin", 30, || async {
            let shown = self.qr(30).await?;
            Ok((!shown.to_lowercase().starts_with("bitcoin:?")).then_some(shown))
        })
        .await?;
        self.tap("Back").await?;
        self.home(30).await?;
        Ok(code)
    }

    /// The silent payment address Receive shows under More, back on Home
    /// after.
    pub async fn silent_address(&self) -> anyhow::Result<String> {
        self.tap_id("receive").await?;
        self.tap_id("other-ways").await?;
        self.tap_id("way-silent").await?;
        let silent = self.by_id("silent", 30).await?.text;
        self.tap("Back").await?;
        self.home(30).await?;
        Ok(silent)
    }

    /// Save what the screen shows to `path`, to see why a test failed.
    pub async fn screenshot(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let image = self.adb(&["exec-out", "screencap", "-p"]).await?;
        std::fs::write(path, image)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_are_read_from_the_layout_dumped() {
        let xml = r#"<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation="0"><node index="0" text="" resource-id="" bounds="[0,0][1080,2400]"><node index="1" text="48&#8201;778" resource-id="balance" content-desc="" focused="false" bounds="[63,380][501,552]" /><node text="" content-desc="QR code" resource-id="" bounds="[173,385][908,1120]" /><node text="A &amp; B &quot;x&quot;" resource-id="" focused="true" bounds="[1,2][3,4]" /></node></hierarchy>"#;
        let views = views_in(xml);
        assert_eq!(views.len(), 3);
        assert_eq!(
            (views[0].id.as_str(), amount(&views[0].text)),
            ("balance", 48_778)
        );
        assert_eq!(views[0].center(), (282, 466));
        assert_eq!(views[1].text, "QR code");
        assert_eq!(views[2].text, "A & B \"x\"");
        assert_eq!(
            views.iter().map(|v| v.focused).collect::<Vec<_>>(),
            [false, false, true]
        );
    }

    #[test]
    fn ports_are_read_from_urls_and_addresses() {
        assert_eq!(port("http://127.0.0.1:38338").unwrap(), 38338);
        assert_eq!(port("ws://127.0.0.1:38390/").unwrap(), 38390);
        assert_eq!(port("127.0.0.1:32768").unwrap(), 32768);
    }
}
