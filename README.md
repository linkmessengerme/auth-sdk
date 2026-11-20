# Link Auth SDK

Native SDK for **Login with Link**: let people sign in to your iOS or Android app
with their Link account. The SDK opens the Link app for confirmation, verifies the
result on the device and keeps the session in platform secure storage.

- OAuth 2.1 Authorization Code with PKCE (S256) and OpenID Connect.
- ID tokens are verified on the device: signature (EdDSA), issuer, audience, expiry and nonce.
- Sessions survive app restarts; tokens are refreshed and rotated automatically.
- One protocol core in Rust, with idiomatic Swift (`actor`) and Kotlin (`suspend`) APIs.
- No secrets in the app: mobile clients are public clients and use PKCE only.
- Typed errors you can branch on.

> Version **0.1.0** is the first public release. Sign-in requires a current version
> of the Link app on the same device.

## Packages

| Platform | Package | Requirements | Guide |
|---|---|---|---|
| iOS | Swift package [`auth-sdk-swift`](https://github.com/linkmessengerme/auth-sdk-swift), product `LinkAuth` | iOS 13+, arm64 | [iOS guide](https://github.com/linkmessengerme/auth-sdk-swift#readme) |
| Android | `me.linkmessenger:link-auth` | API 23+, Java 17, `arm64-v8a` / `armeabi-v7a` / `x86_64` | [Android guide](platforms/android/README.md) |

The Android artifact is not on a public Maven repository yet. Until it is, build the
local Maven bundle from this repository as described in the Android guide.

For your backend, use the server SDKs to verify ID tokens and read user data:
[Go](https://github.com/linkmessengerme/console-sdk-go),
[Node.js](https://github.com/linkmessengerme/console-sdk-node),
[Python](https://github.com/linkmessengerme/console-sdk-python).

## How it works

1. Register your app in Link Console and download its public JSON config
   (`link_oauth_client_config`). It contains no secrets.
2. Your app calls `signIn`. The SDK opens `https://linkm.me/oauth/authorize` and the
   Link app shows the consent sheet: your app name, logo and the requested scopes.
3. Link returns to your registered callback with a one-time code. Your app passes the
   incoming URL to `handleCallback`.
4. The SDK exchanges the code using PKCE, verifies the ID token and stores the session.
5. Later calls such as `getIdToken()` and `getUserInfo()` reuse the session and refresh
   tokens when needed.

## Quickstart

Swift:

```swift
import LinkAuth

let auth = try await LinkAuth.create(
    configJson: configJson,
    redirectUri: "https://app.example.com/link/callback"
)
_ = try await auth.restore()                      // once at startup

let session = try await auth.signIn(scopes: ["openid", "profile", "offline_access"])
print(session.user.subject)

// In your incoming-URL handler:
_ = try await auth.handleCallback(incomingURL)
```

Kotlin:

```kotlin
import me.linkmessenger.auth.AndroidLinkOpener
import me.linkmessenger.auth.LinkAuth

val auth = LinkAuth.create(applicationContext, configJson, "https://app.example.com/link/callback")
auth.restore()                                    // once at startup

auth.signIn(listOf("openid", "profile", "offline_access"), AndroidLinkOpener(activity)).use { session ->
    println(session.user.subject)
}

// In onCreate / onNewIntent:
auth.handleCallback(intent.dataString ?: return)
```

`signIn` suspends until a separate `handleCallback` call delivers the result, so the
two snippets run at different points of your app lifecycle. The platform guides cover
callbacks after process death, cancellation and error handling.

## Scopes and user data

| Scope | Gives your app |
|---|---|
| `openid` | A stable user identifier (`sub`) for your project. Required. |
| `profile` | Name, username and avatar. |
| `offline_access` | A long-lived session that is refreshed without a new sign-in. |
| `phone` | The phone number, read through `getUserInfo()`. Requires approval in Console. |

`sub` is specific to your project: the same person has a different `sub` in another
project. A person can decline an optional scope and still sign in; always use the
scopes that were actually granted.

`getUserInfo()` takes no arguments. It reads fresh data with the current session, is
never cached by the SDK and returns `phoneNumber` only while the grant is active.

## Sign-in with your own backend

Create a one-time challenge with a random nonce on your backend, pass that nonce to
`signIn`, then send the resulting ID token and access token to your backend over HTTPS.
The backend verifies the ID token against the stored nonce with a server SDK, reads
UserInfo and issues its own session. The phone number is never inside the ID token.

A runnable backend example lives in the
[Node.js SDK](https://github.com/linkmessengerme/console-sdk-node/tree/main/examples).

## Security model

- The authorization code and each refresh token are single-use. They are marked as used
  in the local journal **before** the network request, so a retry cannot replay them.
- New tokens are handed to your code only after they are stored.
- A callback with a wrong `state` or issuer is rejected without ending the real attempt.
- Sign-out disables the local session first and then revokes it on the server. Without a
  connection the SDK reports a pending revocation that you retry later.
- Tokens are kept in the Keychain (iOS) or encrypted with an AndroidKeyStore key (Android).
  Refresh tokens are never exposed to your code.
- The core contains no HTTP stack, runtime, UI or file storage of its own; it calls the
  platform transport and storage adapters.

Never log incoming OAuth URLs, tokens or user data.

## Repository layout

```text
crates/auth-core/      protocol, token verification, session journal and lifecycle
crates/auth-ffi/       UniFFI objects and the async interface
platforms/apple/       Swift API, URLSession and Keychain adapters, Swift package
platforms/android/     Kotlin API, OkHttp and Keystore adapters, Gradle library
bindings/fixtures/     public test configuration and discovery documents
bindings/smoke/        Swift and Kotlin checks of bindings, adapters and the API
examples/              Android and iOS demo apps, package consumer checks
scripts/               builds, smoke checks and a local OAuth test fixture
```

## Building from source

Requirements: Rust 1.91+, and for each platform the toolchain listed in its guide.

```sh
# iOS: XCFramework and the local Swift package
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
bash scripts/build-apple.sh

# Android: AAR and a local Maven bundle
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME=/path/to/android-ndk
bash scripts/build-android.sh
```

## Tests

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --features bindgen --locked -- -D warnings
```

`cargo test` needs no network. The Swift and Kotlin smoke scripts in `scripts/`
additionally exercise the generated bindings and the platform adapters; the native
smoke checks start a temporary OAuth fixture on `127.0.0.1` and stop it afterwards.

## License

[MIT](LICENSE)
