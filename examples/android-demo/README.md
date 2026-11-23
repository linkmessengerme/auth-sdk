# Link Auth Android demo

A small app that uses the real `LinkAuth` API from the SDK Maven bundle. It imports a
public Console config, opens Link, handles the callback, shows the verified profile and
lets you check, refresh and end the session. There is no mock sign-in and no built-in
test user.

## Register the app in Console

| Field | Value |
|---|---|
| Platform | `android` |
| Package name | `me.linkmessenger.auth.demo` |
| Redirect URI | `me.linkmessenger.auth.demo://oauth/callback` |
| Scopes | `openid`, `profile`, `offline_access` |
| SHA-256 | From `./gradlew signingReport`, variant `debug` |

Gradle creates `.local/debug.keystore` once and reuses it, so later debug builds keep
the same certificate. The key is excluded from Git and is meant for this demo only.
Deleting it, or building on another machine, changes the fingerprint; update it in
Console when that happens.

The demo's callback uses a custom scheme, so the demo needs no domain of its own. For a
production app prefer a verified HTTPS App Link.

## Build and run

Requires JDK 17 and Android SDK platform and build-tools 34. Build the SDK bundle
first if `platforms/android/build/repository` does not exist yet
(see the [Android guide](../../platforms/android/README.md#install)).

```sh
./gradlew assembleDebug signingReport
./gradlew installDebug
adb shell am start -n me.linkmessenger.auth.demo/.MainActivity
```

Without a connected device `assembleDebug` still produces
`build/outputs/apk/debug/link-auth-android-demo-debug.apk`. If the build cannot find
the Android SDK, set `ANDROID_HOME` or `sdk.dir` in a local `local.properties`.

`me.linkmessenger:link-auth:0.2.0` resolves **only** from the local bundle; all other
dependencies come from Google Maven and Maven Central and are pinned in
`gradle.lockfile`.

To check minification and lint:

```sh
./gradlew assembleRelease lint
```

The release APK is unsigned and exists to exercise R8. Install the debug APK on a device.

## Connect a configuration

Download the **public JSON for Android** (`link_oauth_client_config`) from Console.
Transfer it to the phone and choose "Import JSON file", or use "Paste JSON". The demo
checks the platform and the callback; the SDK validates the rest. Files that contain
`client_secret` or `private_key` are rejected.

To bundle a config at build time, place it at `.local/assets/link-login.json` and
rebuild. A config imported on the device takes precedence over the bundled one; sign
out before replacing it.

## Try it on a device

A signed-in Link app must be installed on the same device.

1. Import the config, tap "Sign in with Link" and approve. Check the return to the
   demo, the profile, the granted scopes and the token expiry.
2. Sign out and repeat with a decline in Link: no profile should appear.
3. Start a sign-in, return to the demo and cancel. A late callback must not sign in.
4. Rotate the screen during a sign-in, continue in Link and get the result in the demo.
5. While Link is in the foreground, run `adb shell am kill me.linkmessenger.auth.demo`,
   then approve. The new demo process restores the pending sign-in.
6. Restart the demo after a successful sign-in: the saved session appears.
   "Check session" calls `getSession()`; "Refresh tokens" forces a refresh.
7. Sign out without a connection: the profile disappears and "Retry server sign-out"
   is offered. Restore the connection and retry.

## Data and lifecycle

The config is stored in `noBackupFilesDir`. Tokens and the pending sign-in live only in
the SDK's protected storage. The on-screen log contains safe messages without callback
URLs, codes, `state`, verifier or tokens. The name and ID come from claims verified by
the SDK; the demo creates no session on any application backend.
