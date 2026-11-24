# Android app

The Licash wallet for Android. It is a private checking account with
Lightning, onchain payments and recovery on Bitcoin, without running a node.
Home shows your balance and how much of it is protected. Payments, cash-outs
to cold storage and contracts are a tap away. A built-in light client (with
Tor) watches Bitcoin for you.

## Try it

Install `licash-main.apk` from the
[`main-build` release](https://github.com/lichenbtc-org/licash/releases/tag/main-build).
To try it on Mutinynet or signet, swipe to the last slide of the tour, tap
"Use a test network", pick the network, create the wallet and use the hub it
recommends (or choose another). A wallet keeps the network it is made on.

## Build

You need JDK 17+, the Android SDK (platform 37) with the NDK at
`ANDROID_NDK_HOME`, Rust with the `aarch64-linux-android` and
`x86_64-linux-android` targets, Go and gomobile.

```sh
./native.sh                 # the Rust core, its Kotlin bindings and the Go light client
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Backup and restore, test networks, releases and tests are covered in
[docs/android.md](../../../docs/android.md). The app's look and wording follow
[apps/DESIGN.md](../../DESIGN.md).
