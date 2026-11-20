import XCTest
import LinkAuth
import LinkAuthCore
@testable import LinkAuthDemo

@MainActor
final class DemoTests: XCTestCase {
    private static let callback = URL(string: DemoConfiguration.callback + "?code=test-code&state=test-state")!

    private func configData(_ changes: [String: Any] = [:]) throws -> Data {
        var object: [String: Any] = [
            "type": "link_oauth_client_config", "platform": "ios",
            "app_id": "00000000-0000-0000-0000-000000000001", "bundle_id": DemoConfiguration.bundleID,
            "client_id": "lk_client_demo_fixture", "issuer": "https://api-sdk.linkmessenger.me",
            "api_base_url": "https://api-sdk-fr.linkmessenger.me",
            "token_url": "https://api-sdk-fr.linkmessenger.me/oauth/v1/token",
            "redirect_uris": [DemoConfiguration.callback], "pkce_method": "S256",
            "grant_types": ["authorization_code", "refresh_token"], "scope_mode": "inherit",
            "scopes": ["openid", "profile", "offline_access"], "required_scopes": ["openid"],
        ]
        object.merge(changes) { _, new in new }
        return try JSONSerialization.data(withJSONObject: object)
    }

    private func store(withConfig: Bool = true) async throws -> DemoConfigStore {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        let store = DemoConfigStore(directory: directory, bundled: nil)
        if withConfig { try await store.save(DemoConfiguration.parse(configData())) }
        return store
    }

    func testConfigAcceptsRegionalAPIAndPreservesJSON() throws {
        let data = try configData()
        let config = try DemoConfiguration.parse(data)
        XCTAssertEqual(Data(config.json.utf8), data)
        XCTAssertNotEqual(config.issuer, config.apiBaseURL)
        XCTAssertEqual(config.clientID, "lk_client_demo_fixture")
    }

    func testNativeSDKWithSystemKeychain() async throws {
        // Exercise the real signed app's entitlements, not the fake lifecycle client.
        let service = DemoConfiguration.bundleID + ".tests." + UUID().uuidString
        let storage = try KeychainStorage(service: service)
        let key = "link.auth.v1." + UUID().uuidString.replacingOccurrences(of: "-", with: "") + "aaaaaaaaaaa"
        let revision = String(repeating: "r", count: 43)
        XCTAssertNil(try storage.load(key: key))
        XCTAssertTrue(try storage.compareExchange(key: key, expectedRevision: nil,
            replacement: StorageEntry(revision: revision, payload: "public-test-payload")))
        defer { _ = try? storage.compareExchange(key: key, expectedRevision: revision, replacement: nil) }
        let reopened = try KeychainStorage(service: service)
        XCTAssertEqual(try reopened.load(key: key)?.payload(), "public-test-payload")
        XCTAssertFalse(try reopened.compareExchange(key: key, expectedRevision: nil, replacement: nil))
        XCTAssertTrue(try reopened.compareExchange(key: key, expectedRevision: revision, replacement: nil))
        XCTAssertNil(try reopened.load(key: key))

        let auth = try await LinkAuth.create(configJson: String(decoding: configData(), as: UTF8.self),
            redirectUri: DemoConfiguration.callback, keychainService: service)
        let status = try await auth.restore()
        let logout = try await auth.signOut()
        try await auth.close()
        XCTAssertEqual(status, .signedOut)
        XCTAssertEqual(logout, .localOnly)
    }

    func testConfigRejectsWrongRegistrationAndPrivateMaterial() throws {
        for changes: [String: Any] in [
            ["platform": "android"], ["bundle_id": "org.other.app"],
            ["redirect_uris": [DemoConfiguration.callback + "/other"]],
            ["client_secret": NSNull()], ["private_key": "never-embed-private-material"],
        ] {
            let data = try configData(changes)
            XCTAssertThrowsError(try DemoConfiguration.parse(data))
        }
        XCTAssertThrowsError(try DemoConfiguration.parse(Data(repeating: 32, count: DemoConfiguration.maximumBytes + 1)))
    }

    func testImportPersistsConfigAndRejectsOversizedFile() async throws {
        let store = try await store(withConfig: false)
        let fake = FakeAuthClient()
        let coordinator = AuthCoordinator(store: store, makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        XCTAssertFalse(coordinator.canSignIn)
        coordinator.importJSON(String(decoding: try configData(), as: UTF8.self))
        await coordinator.waitForOperations()
        XCTAssertTrue(coordinator.canSignIn)
        let saved = try await store.load()
        XCTAssertEqual(saved?.clientID, coordinator.config?.clientID)

        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        try Data(repeating: 32, count: DemoConfiguration.maximumBytes + 1).write(to: file)
        coordinator.importFile(file)
        await coordinator.waitForOperations()
        XCTAssertTrue(coordinator.isError)
        XCTAssertEqual(coordinator.config?.clientID, saved?.clientID)
        XCTAssertTrue(coordinator.canSignIn)
    }

    func testColdStartQueuesCallbackUntilRestoreAndDeduplicates() async throws {
        let fake = FakeAuthClient(status: .pendingLogin(expiresAt: FakeAuthClient.expiry))
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        coordinator.receive(Self.callback)
        coordinator.receive(Self.callback)
        await coordinator.waitForOperations()
        XCTAssertEqual(coordinator.session?.user.subject, FakeAuthClient.user.subject)
        XCTAssertFalse(coordinator.pending)
        let calls = await fake.calls()
        XCTAssertEqual(calls.callbacks, 1)
        XCTAssertEqual(calls.restores, 2)
        coordinator.receive(Self.callback)
        await coordinator.waitForOperations()
        XCTAssertEqual(coordinator.session?.user.subject, FakeAuthClient.user.subject)
        XCTAssertFalse(coordinator.isError)
    }

    func testInvalidCallbackKeepsRealLoginAndIgnoresUnrelatedURL() async throws {
        let fake = FakeAuthClient()
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        coordinator.signIn()
        await fake.waitForSignIn()
        coordinator.receive(URL(string: "other-app://oauth/callback?code=private-code")!)
        coordinator.receive(URL(string: DemoConfiguration.callback + "?state=wrong&code=private-code")!)
        await coordinator.waitForOperations()
        XCTAssertTrue(coordinator.pending)
        XCTAssertTrue(coordinator.isError)
        XCTAssertFalse(coordinator.canConfigure)
        XCTAssertFalse(coordinator.events.contains { $0.message.contains("private-code") })
        let before = await fake.calls()
        XCTAssertEqual(before.callbacks, 1)
        // restore() must not run while the signIn waiter is still active.
        XCTAssertEqual(before.restores, 1)
        coordinator.receive(Self.callback)
        await coordinator.waitForOperations()
        XCTAssertNotNil(coordinator.session)
        XCTAssertFalse(coordinator.pending)
        XCTAssertFalse(coordinator.isError)
    }

    func testExplicitCancellationSettlesPendingWaiter() async throws {
        let fake = FakeAuthClient()
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        coordinator.signIn()
        await fake.waitForSignIn()
        coordinator.cancelSignIn()
        await coordinator.waitForOperations()
        XCTAssertFalse(coordinator.pending)
        XCTAssertTrue(coordinator.canSignIn)
        XCTAssertFalse(coordinator.isError)
        let calls = await fake.calls()
        XCTAssertEqual(calls.cancellations, 1)
    }

    func testDenialClearsPendingAndAllowsRetry() async throws {
        let fake = FakeAuthClient()
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        coordinator.signIn()
        await fake.waitForSignIn()
        coordinator.receive(URL(string: DemoConfiguration.callback + "?error=access_denied&state=test-state")!)
        await coordinator.waitForOperations()
        XCTAssertNil(coordinator.session)
        XCTAssertFalse(coordinator.pending)
        XCTAssertTrue(coordinator.canSignIn)
        XCTAssertTrue(coordinator.isError)
    }

    func testRefreshPublishesUpdatedExpiry() async throws {
        let fake = FakeAuthClient(status: FakeAuthClient.signedIn)
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        let oldExpiry = try XCTUnwrap(coordinator.session?.expiresAt)
        coordinator.checkSession(forceRefresh: true)
        await coordinator.waitForOperations()
        XCTAssertGreaterThan(try XCTUnwrap(coordinator.session?.expiresAt), oldExpiry)
        XCTAssertEqual(coordinator.session?.user.subject, FakeAuthClient.user.subject)
    }

    func testOfflineLogoutHidesProfileAndBlocksNewLoginUntilRetry() async throws {
        let fake = FakeAuthClient(status: FakeAuthClient.signedIn, logoutOffline: true)
        let coordinator = AuthCoordinator(store: try await store(), makeClient: { _ in fake })
        await coordinator.waitUntilReady()
        coordinator.signOut()
        await coordinator.waitForOperations()
        XCTAssertNil(coordinator.session)
        XCTAssertTrue(coordinator.revocationPending)
        XCTAssertFalse(coordinator.canSignIn)
        XCTAssertFalse(coordinator.canConfigure)
        XCTAssertTrue(coordinator.canSignOut)
        coordinator.signOut()
        await coordinator.waitForOperations()
        XCTAssertFalse(coordinator.revocationPending)
        XCTAssertTrue(coordinator.canSignIn)
    }
}

/// Tests the app's lifecycle boundary. Protocol/crypto tests live in the SDK.
private actor FakeAuthClient: DemoAuthClient {
    static let expiry = UInt64(Date().timeIntervalSince1970) + 300
    static let user = UserIdentity(issuer: "https://api-sdk.linkmessenger.me", subject: "pairwise-sub-test",
        grantedScopes: ["openid", "profile", "offline_access"], name: "Demo User", preferredUsername: "demo", picture: nil)
    static var signedIn: SessionStatus { .signedIn(user: user, expiresAt: expiry, canRefresh: true) }
    private var status: SessionStatus
    private var logoutOffline: Bool
    private var login: CheckedContinuation<Void, Error>?
    private var started: CheckedContinuation<Void, Never>?
    private var didStart = false
    private var callbacks = 0
    private var restores = 0
    private var cancellations = 0

    init(status: SessionStatus = .signedOut, logoutOffline: Bool = false) {
        self.status = status
        self.logoutOffline = logoutOffline
    }

    func calls() -> (callbacks: Int, restores: Int, cancellations: Int) { (callbacks, restores, cancellations) }

    func waitForSignIn() async {
        if didStart { return }
        await withCheckedContinuation { started = $0 }
    }

    func restore() throws -> SessionStatus {
        restores += 1
        guard login == nil else { throw LinkAuthFailure.protocolFailure(.alreadyInProgress) }
        return status
    }

    func signIn(scopes: [String]) async throws {
        status = .pendingLogin(expiresAt: Self.expiry)
        didStart = true
        started?.resume(); started = nil
        try await withCheckedThrowingContinuation { login = $0 }
    }

    func handleCallback(_ url: URL) throws -> UserIdentity? {
        callbacks += 1
        guard case .pendingLogin = status else { return nil }
        if url.query?.contains("state=wrong") == true { throw LinkAuthFailure.protocolFailure(.stateMismatch) }
        if url.query?.contains("error=access_denied") == true {
            status = .signedOut
            let failure = LinkAuthFailure.protocolFailure(.authorizationDenied)
            login?.resume(throwing: failure); login = nil
            throw failure
        }
        status = Self.signedIn
        login?.resume(); login = nil
        return Self.user
    }

    func checkSession(forceRefresh: Bool) {
        status = .signedIn(user: Self.user, expiresAt: Self.expiry + (forceRefresh ? 300 : 0), canRefresh: true)
    }

    func cancelSignIn() {
        cancellations += 1
        status = .signedOut
        login?.resume(throwing: LinkAuthFailure.protocolFailure(.cancelled)); login = nil
    }

    func signOut() -> LogoutStatus {
        status = logoutOffline ? .revocationPending : .signedOut
        let result: LogoutStatus = logoutOffline ? .revocationPending : .revoked
        logoutOffline = false
        return result
    }

    func close() { if login != nil { cancelSignIn() } }
}
