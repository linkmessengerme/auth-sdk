// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LinkAuthPackageCheck",
    platforms: [.macOS(.v10_15)],
    dependencies: [.package(name: "LinkAuth", path: "../../platforms/apple")],
    targets: [.executableTarget(name: "LinkAuthPackageCheck", dependencies: [.product(name: "LinkAuth", package: "LinkAuth")])],
    swiftLanguageVersions: [.version("6")]
)
