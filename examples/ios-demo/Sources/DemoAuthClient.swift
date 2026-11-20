import Foundation
import LinkAuth
import LinkAuthCore

/// The UI-facing boundary intentionally exposes no raw tokens.
protocol DemoAuthClient: Sendable {
    func restore() async throws -> SessionStatus
    func signIn(scopes: [String]) async throws
    func handleCallback(_ url: URL) async throws -> UserIdentity?
    func checkSession(forceRefresh: Bool) async throws
    func cancelSignIn() async throws
    func signOut() async throws -> LogoutStatus
    func close() async throws
}

struct SDKDemoClient: DemoAuthClient {
    let auth: LinkAuth

    static func create(_ config: DemoConfiguration) async throws -> SDKDemoClient {
        let auth = try await LinkAuth.create(configJson: config.json,
            redirectUri: DemoConfiguration.callback,
            keychainService: DemoConfiguration.bundleID,
            // A failed association must be visible during device testing.
            opener: SystemLinkOpener(allowBrowserFallback: false))
        return SDKDemoClient(auth: auth)
    }

    func restore() async throws -> SessionStatus { try await auth.restore() }
    func signIn(scopes: [String]) async throws { _ = try await auth.signIn(scopes: scopes) }
    func handleCallback(_ url: URL) async throws -> UserIdentity? { try await auth.handleCallback(url) }
    func checkSession(forceRefresh: Bool) async throws { _ = try await auth.getSession(forceRefresh: forceRefresh) }
    func cancelSignIn() async throws { try await auth.cancelSignIn() }
    func signOut() async throws -> LogoutStatus { try await auth.signOut() }
    func close() async throws { try await auth.close() }
}
