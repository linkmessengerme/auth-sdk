# Releasing

Use `Link Messenger <dev@linkmessenger.me>` for Git authors, committers and
taggers. Publish through the Link Messenger account. Review source, history and
built binaries for personal names, local paths and credentials before every release.

1. Update the workspace version in `Cargo.toml`, the Android library version in
   `platforms/android/build.gradle.kts` and date the changelog.
2. Run the release checks:

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --features bindgen --locked -- -D warnings
```

3. Build both platforms with `scripts/build-apple.sh` and `scripts/build-android.sh`.
   The scripts remap local paths, so the binaries must not contain the build
   machine's home directory. Verify it:

```sh
strings -a platforms/apple/Artifacts/LinkAuthCoreFFI.xcframework/ios-arm64/liblink_auth_ffi.a | grep -c "$HOME"   # expect 0
```

4. Check the packages as a consumer: `examples/apple-package-check` and
   `examples/android-package-check`, then both demo apps on a device with Link installed.
5. Commit the reviewed changes and tag `vX.Y.Z` on `main`. Existing tags are never moved.
6. Publish the Swift package: zip the XCFramework, attach it to a release of
   [`auth-sdk-swift`](https://github.com/linkmessengerme/auth-sdk-swift) and update the
   URL and checksum in its `Package.swift`.
7. Publish the Android Maven artifact.
