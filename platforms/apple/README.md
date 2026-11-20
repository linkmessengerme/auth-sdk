# Link Auth for iOS — package sources

This directory holds the sources of the Swift package: the `LinkAuth` actor, the
URLSession and Keychain adapters, and the manifest used for local development.

To **use** the SDK in an app, add the published package and follow its guide:
[`auth-sdk-swift`](https://github.com/linkmessengerme/auth-sdk-swift).

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
- Host builds and smoke checks do not cover entitlements, the system hand-off to Link,
  Keychain lock state, backups or process death. Test those on a device with the
  [iOS demo](../../examples/ios-demo/README.md).

## License

[MIT](../../LICENSE)
