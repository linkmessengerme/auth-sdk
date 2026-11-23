# Link Auth for Android

Android library `me.linkmessenger:link-auth`: a Kotlin coroutine API over the shared
Rust core, with OkHttp transport and storage encrypted by an AndroidKeyStore key.

> Requires **Android API 23+** and **Java 17**. Native libraries are built for
> `arm64-v8a`, `armeabi-v7a` and `x86_64`.

## Install

The artifact is not on a public Maven repository yet. Build the local Maven bundle
from the repository root:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
export ANDROID_HOME=/path/to/android-sdk        # platform and build-tools 34
export ANDROID_NDK_HOME=/path/to/android-ndk    # r28 or newer
bash scripts/build-android.sh
```

Then add the bundle to your app. Using the Maven bundle, rather than the bare AAR,
brings in the JNA, coroutines and OkHttp dependencies:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven { url = uri("/absolute/path/to/auth-sdk/platforms/android/build/repository") }
        google()
        mavenCentral()
    }
}

// build.gradle.kts of the app module
android {
    defaultConfig {
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
}
dependencies { implementation("me.linkmessenger:link-auth:0.2.0") }
```

Limit your app to these ABIs or a subset: JNA ships additional legacy ABIs for which
the core is not built. Consumer ProGuard rules are included; a release build with R8
is checked by `examples/android-package-check`.

## Quickstart

Create one instance per configuration and keep it in application scope. `configJson`
is the public `link_oauth_client_config` from Link Console; `redirectUri` must match a
registered redirect URI exactly.

```kotlin
import me.linkmessenger.auth.AndroidLinkOpener
import me.linkmessenger.auth.LinkAuth

val auth = LinkAuth.create(applicationContext, configJson, "https://app.example.com/link/callback")
val status = auth.restore()                 // once at startup

// Create the opener outside a long-lived coroutine: it holds the Activity weakly.
val opener = AndroidLinkOpener(activity)

// In viewModelScope or an application scope that outlives the switch to Link:
auth.signIn(listOf("openid", "profile", "offline_access"), opener).use { session ->
    val user = session.user
    val idToken = session.idToken
}

// In a separate handler for the initial intent and onNewIntent:
val callbackUser = auth.handleCallback(incomingUrl)
// null: a foreign or already handled callback. After process recreation a valid
// callback returns the identity even without a waiting signIn coroutine.

val currentIdToken = auth.getIdToken()      // refreshes expiring credentials itself
val info = auth.getUserInfo()               // fresh data; the SDK supplies the token
val logout = auth.signOut()
auth.close()                                // releases the SDK; a stored session remains
```

These are fragments of different lifecycle events. `signIn` waits for a separate
`handleCallback` call. Close the returned `LinkSession` with `use`; the API never
exposes the refresh token.

## Receiving the callback

Pass `intent.dataString` from both `onCreate` and `onNewIntent`. On a cold start, wait
for `LinkAuth.create` and `restore()` before passing the original URL. Keep the SDK and
the waiting sign-in in an app coordinator or ViewModel so that rotation does not lose
the handler. The SDK adds no Activity of its own and does not choose a launch mode.

For an HTTPS callback add a filter to your Activity (`android:exported="true"`):

```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="app.example.com" android:path="/link/callback" />
</intent-filter>
```

Host `assetlinks.json` on that domain with your package name and signing certificate
SHA-256. For a custom scheme use a separate filter without `autoVerify` and register
the exact URI in Console. The SDK does not publish domain associations for you.

`AndroidLinkOpener` opens the authorization URL from verified discovery with
`ACTION_VIEW`. Android routes it to the Link app, or to a browser page that asks the
person to open or install Link. A returned `true` means the system accepted the Intent,
not that the person signed in. The SDK does not query installed packages, so it needs
no `<queries>` entry.

The authorization URL `https://linkm.me/oauth/authorize` is associated with the Link
app itself. Your app only needs its own callback filter. Use `issuer`, `api_base_url`
and `token_url` exactly as they appear in the Console config.

## User data

Add `"phone"` to the scopes of `signIn` and allow it in Console to read the phone number.
`getUserInfo()` takes no scopes, user ID or token and never opens a consent sheet. The
result has `subject` and the optional `name`, `preferredUsername`, `picture`,
`phoneNumber` and `phoneNumberVerified`. Declining an optional `phone` keeps the
sign-in; `phoneNumber` is then `null`. Data is read again on every call and is not
stored by the SDK. Do not log it.

## Device attestation

The SDK creates a signing key in the AndroidKeyStore and proves to Link, with the
key's certificate chain, that it was created by your app on a real device. The code
exchange and every token refresh are then signed by this key. Nothing needs to be
called and no permission or manifest entry is needed.

- The key is EC P-256, sign-only, created in StrongBox when the device has one and in
  the TEE otherwise. No device identifiers are requested and no user confirmation is
  shown. It is created once, before Link is opened for the first sign-in, and is
  reused until the app is uninstalled; it survives sign-out.
- Link requires attestation: only a verified device signs in. Key attestation needs
  Android 7 (API 24). Android 6, the emulator, a rooted device or an unlocked
  bootloader, and a device whose Keystore fails are refused with
  `ErrorCode.AttestationRequired`.
- In Console, the SHA-256 fingerprint must be that of the key your **installed** app
  is signed with. With Play App Signing that is the app signing key from Play Console,
  not your upload key. Add the fingerprint of every key your test builds are signed
  with too: a build signed with any other key is refused.
- `session.user.deviceTrust` is `"verified"` for every signed-in user.
- Do not create `LinkAuth` with `attestation = false`: requests are not signed and Link
  refuses the sign-in.

With attestation, a token refresh whose answer was lost in the network is repeated on
the next call instead of ending the session.

## Sign-in with your own backend

Your backend first creates and stores a one-time challenge with a cryptographically
random nonce (32 bytes, base64url). Pass the nonce to a **fresh** sign-in:

```kotlin
auth.signIn(listOf("openid", "profile", "phone"), opener, nonce = challenge.nonce).use { session ->
    // Send challenge_id, session.idToken and session.accessToken to your backend over HTTPS.
}
```

The backend consumes the challenge, verifies the ID token against the stored nonce with
a [server SDK](https://github.com/linkmessengerme/console-sdk-node), reads UserInfo for
the same `sub` and issues its own tokens.

Without the `nonce` argument the SDK generates one. A custom nonce must be 32–256
base64url characters; anything else fails with `ErrorCode.InvalidNonce`. An ID token
obtained by refresh carries no nonce, so `getIdToken(forceRefresh)` does not replace a
new sign-in. End an existing session deliberately before signing in again.

## Cancellation and errors

- `auth.cancelSignIn()` clears a pending sign-in. Cancelling the coroutine that waits in
  `signIn` clears it too. Do not tie the sign-in to `repeatOnLifecycle(STARTED)` or
  `onStop`: switching to the Link app stops your Activity.
- Cancelling one caller of `getSession` or `getIdToken` does not cancel a shared refresh.
- `LinkAuthException.Protocol.code` carries a typed, safe-to-log code: a declined
  consent is `ErrorCode.AuthorizationDenied`, an explicit cancel `ErrorCode.Cancelled`,
  a timeout `ErrorCode.Expired`. `CannotOpenLink` and `Closed` are separate exceptions.
  Always rethrow `CancellationException`.
- `ErrorCode.AttestationRequired` means the application requires device attestation
  and this device did not pass; a retry on the same device will not help.
- A callback with a wrong `state` or issuer does not end the real attempt; a duplicate
  callback returns `null`. Do not poll `restore()` during an operation.
- On `LogoutStatus.REVOCATION_PENDING` call `signOut()` again once a connection is available.

Never log incoming OAuth URLs, pending secrets or tokens. The session journal and the
record of the attested key live in `noBackupFilesDir`; their keys stay in the
AndroidKeyStore.

## Example

[`examples/android-demo`](../../examples/android-demo/README.md) is a complete app:
import a Console config, sign in through Link, view the profile, refresh and sign out.

## License

[MIT](../../LICENSE)
