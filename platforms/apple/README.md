# Link Auth for iOS — package sources

This directory holds the sources of the Swift package: the `LinkAuth` actor, the
URLSession and Keychain adapters, and the manifest used for local development.

To **use** the SDK in an app, add the published package and follow its guide:
[`auth-sdk-swift`](https://github.com/linkmessengerme/auth-sdk-swift).

## Device attestation (App Attest)

The SDK creates an App Attest key in the Secure Enclave, has Apple attest it once at
the first sign-in, and signs the code exchange and every token refresh with it.
Nothing needs to be called in code, but two things must be set up:

1. **Add the App Attest capability** to the app target in Xcode (Signing &
   Capabilities → + Capability → App Attest). It adds the entitlement
   `com.apple.developer.devicecheck.appattest-environment`. Xcode sets it to
   `development`; builds distributed through TestFlight and the App Store use
   `production`. Without the capability the key cannot be attested and the device
   cannot sign in.
2. **Enter your Team ID in Link Console** for the application (10 characters, shown in
   your Apple Developer account under Membership). Link compares the attestation with
   `TeamID.bundleID`. Development builds are accepted only when development builds are
   allowed for the application; ask Link to allow them while you test.

- Link requires attestation: only a verified device signs in. App Attest needs iOS 14
  and a real device. On iOS 13, in the simulator, in an app extension, without the
  capability or when Apple's servers cannot be reached there is no key, and the sign-in
  is refused with `ErrorCode.attestationRequired`.
- The key is attested only at the first sign-in, never at app launch, and is reused
  until the app is uninstalled; it survives sign-out.
- `session.user.deviceTrust` is `"verified"` for every signed-in user.
- Do not create `LinkAuth` with `attestation: false`: requests are not signed and Link
  refuses the sign-in.

With attestation, a token refresh whose answer was lost in the network is repeated on
the next call instead of ending the session.

## Building from source

From the repository root, with Rust 1.91+, Xcode and the iOS targets installed:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
bash scripts/build-apple.sh
swift run --package-path examples/apple-package-check --configuration release LinkAuthPackageCheck
```

The script generates the UniFFI bindings into `Generated/`, builds the core for the
iOS device, the arm64 simulator and the host Mac, and assembles
`Artifacts/LinkAuthCoreFFI.xcframework`. Both directories are build output and are
not committed. The macOS slice exists for host checks only.

To try a local build in an app, add `platforms/apple` as a local package in Xcode and
link the `LinkAuth` product.

## Notes

- UniFFI 0.31.2 callback trampolines compile in Swift 5 language mode. A Swift 6 app
  can consume the package; `examples/apple-package-check` verifies exactly that,
  including real linking of the Rust static library.
- The Intel simulator slice is not built.
- Host builds and smoke checks do not cover entitlements, App Attest, the system
  hand-off to Link, Keychain lock state, backups or process death. Test those on a
  device with the [iOS demo](../../examples/ios-demo/README.md).

## License

[MIT](../../LICENSE)
