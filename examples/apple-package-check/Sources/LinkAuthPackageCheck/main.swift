import Foundation
import LinkAuth

@main struct PackageCheck {
    // This unused entry point is compiled and linked to check the consumer API
    // under Swift 6. No Keychain, browser or real backend is accessed by main().
    static func integrate(config: String, callback: URL) async throws {
        let auth = try await LinkAuth.create(configJson: config, redirectUri: "com.example.app://oauth/callback")
        _ = try await auth.restore()
        _ = try await auth.handleCallback(callback)
        _ = try await auth.getIdToken()
        // "verified", "unlocked", "mismatch", "none", or nil while attestation is off.
        _ = try await auth.getSession().user.deviceTrust
        _ = try await auth.getUserInfo().phoneNumber
        _ = try await auth.signOut()
        try await auth.close()
        let plain = try await LinkAuth.create(configJson: config, redirectUri: "com.example.app://oauth/callback",
            attestation: false)
        try await plain.close()
    }
    static func main() {
        let failure = LinkAuthFailure.protocolFailure(.invalidConfig)
        if case .protocolFailure(.invalidConfig) = failure {
            print("Swift 6 consumer linked LinkAuth and Rust XCFramework successfully")
        }
    }
}
