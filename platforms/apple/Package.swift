// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LinkAuth",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [.library(name: "LinkAuth", targets: ["LinkAuth"])],
    targets: [
        .binaryTarget(name: "LinkAuthCoreFFI", path: "Artifacts/LinkAuthCoreFFI.xcframework"),
        .target(name: "LinkAuthCore", dependencies: ["LinkAuthCoreFFI"], path: "Generated/LinkAuthCore",
            linkerSettings: [.linkedFramework("Security"), .linkedLibrary("resolv")]),
        .target(name: "LinkAuth", dependencies: ["LinkAuthCore"], path: "Sources/LinkAuthAdapters"),
    ],
    // UniFFI 0.31.2 callback trampolines compile in Swift 5 mode. Its public
    // types are Sendable; clients can consume this package from Swift 6.
    swiftLanguageVersions: [.v5]
)
