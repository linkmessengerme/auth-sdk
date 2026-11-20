# Link Auth iOS demo

A small SwiftUI app for trying sign-in through the installed Link app: approve or
decline, view the profile, restore the session, refresh tokens and sign out. It uses
the real Swift API and Rust core from `../../platforms/apple`.

The demo requires iOS 17+ and arm64; the SDK itself supports iOS 13+.

## Register the app in Console

| Field | Value |
|---|---|
| Platform | `ios` |
| Bundle ID | `me.linkmessenger.auth.demo.ios` |
| Redirect URI | `me.linkmessenger.auth.demo.ios://oauth/callback` |
| Scopes | `openid`, `profile`, `offline_access` |

Export the public `link_oauth_client_config`. The demo checks the platform, Bundle ID
and callback, and rejects a file that contains `client_secret` or `private_key`. The
SDK validates the protocol fields.

A config can be connected in two ways:

- Before building, place the export at `.local/link-login.json`; only this file is
  bundled. `.local/` is excluded from Git.
- In the demo, choose "Import JSON file" or "Paste JSON". An imported config is kept
  between launches and takes precedence over the bundled one. End the session and any
  unfinished access revocation before replacing it.

SDK initialization is in `Sources/DemoAuthClient.swift`:

```swift
let auth = try await LinkAuth.create(
    configJson: config.json,
    redirectUri: DemoConfiguration.callback,
    keychainService: DemoConfiguration.bundleID,
    opener: SystemLinkOpener(allowBrowserFallback: false)
)
```

## Build

Requires Xcode with Swift 6 and a built local Apple package. From the repository root:

```sh
bash scripts/build-apple.sh
open examples/ios-demo/LinkAuthDemo.xcodeproj
```

In Xcode select the `LinkAuthDemo` scheme, your Development Team under Signing &
Capabilities and a connected, unlocked iPhone with Developer Mode. The Bundle ID must
match the registration in Console. No Team ID is stored in the project; you can also
pass `DEVELOPMENT_TEAM` to `xcodebuild`.

Compile for a device without signing, from this directory:

```sh
xcodebuild -project LinkAuthDemo.xcodeproj -scheme LinkAuthDemo \
  -configuration Release -destination 'generic/platform=iOS' \
  -derivedDataPath build/DerivedData CODE_SIGNING_ALLOWED=NO build
```

Run the tests on an installed arm64 simulator:

```sh
xcodebuild -project LinkAuthDemo.xcodeproj -scheme LinkAuthDemo \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' \
  -derivedDataPath build/DerivedData -parallel-testing-enabled NO \
  DEVELOPMENT_TEAM=YOUR_TEAM_ID test
```

Keep Xcode signing enabled when you need the real Keychain, even on a simulator:
`CODE_SIGNING_ALLOWED=NO` is enough to check compilation but removes the Keychain
entitlements.

The tests cover the boundary between the UI and the SDK with a fake client: a callback
at launch, duplicates, a wrong `state`, decline, cancel, refresh, offline sign-out and
config import. One test uses the system Keychain with the real SDK.

## Try it on an iPhone

A signed-in Link app must be installed on the same device.

1. In the demo check the client ID and the API, then tap "Sign in with Link". Link
   opens and shows the app and the requested scopes.
2. Approve: Link returns to the demo and the profile appears with `sub`, the issuer and
   the scopes that were actually granted.
3. Tap "Refresh tokens", then "Check session". Restart the demo: the session is
   restored from the Keychain.
4. Tap "Sign out". Try a new attempt with a decline in Link, and one cancelled in the demo.
5. During a new attempt, while Link is open, terminate the **demo** and then approve:
   the cold callback restores the attempt and the profile.
6. Sign in, disable the network and sign out: the profile is hidden and a retry of the
   access revocation remains. Restore the network and tap "Retry access revocation".

The demo opens Link through Universal Links only (`allowBrowserFallback: false`). If iOS
does not hand the link to the Link app, the demo shows an error instead of opening a
browser, which makes association problems visible. Associated Domains for the
authorization URL belong to the **Link** app; the demo receives the return through its
own registered custom scheme.

## Data and lifecycle

Tokens are kept by the SDK in the Keychain. The on-screen log never contains tokens,
authorization codes or callback links.
