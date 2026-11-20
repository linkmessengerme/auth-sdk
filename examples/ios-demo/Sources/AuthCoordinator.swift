import Combine
import Foundation
import LinkAuth
import LinkAuthCore

struct DemoSession {
    let user: UserIdentity
    let expiresAt: Date
    let canRefresh: Bool
}

struct DemoEvent: Identifiable {
    let id = UUID()
    let time = Date()
    let message: String
}

@MainActor
final class AuthCoordinator: ObservableObject {
    @Published private(set) var config: DemoConfiguration?
    @Published private(set) var session: DemoSession?
    @Published private(set) var pending = false
    @Published private(set) var revocationPending = false
    @Published private(set) var recoveryRequired = false
    @Published private(set) var message = "Preparing the SDK…"
    @Published private(set) var isError = false
    @Published private(set) var events: [DemoEvent] = []
    @Published private var bootstrapping = true
    @Published private var operationCount = 0

    var isBusy: Bool { bootstrapping || operationCount > 0 }
    var canConfigure: Bool { !isBusy && !pending && session == nil && !revocationPending && !recoveryRequired }
    var canSignIn: Bool { canConfigure && config != nil }
    var canSignOut: Bool { !isBusy && !pending && (session != nil || revocationPending || recoveryRequired) }

    private let store: DemoConfigStore
    private let makeClient: @Sendable (DemoConfiguration) async throws -> any DemoAuthClient
    private var client: (any DemoAuthClient)?
    private var startup: Task<Void, Never>?
    private var operationTail: Task<Void, Never>?
    private var loginTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var queuedCallbacks = Set<String>()
    private var handlingCallback = false
    private var generation: UInt64 = 0

    init(store: DemoConfigStore = DemoConfigStore(),
         makeClient: @escaping @Sendable (DemoConfiguration) async throws -> any DemoAuthClient = { try await SDKDemoClient.create($0) }) {
        self.store = store
        self.makeClient = makeClient
        startup = Task { [weak self] in
            guard let self else { return }
            await self.bootstrap()
        }
    }

    func waitUntilReady() async { await startup?.value }

    // Also used by lifecycle tests; pending signIn is deliberately not awaited.
    func waitForOperations() async { await startup?.value; await operationTail?.value }

    func importJSON(_ json: String) {
        guard canConfigure else { return }
        configure { try DemoConfiguration.parse(Data(json.utf8)) }
    }

    func importFile(_ url: URL) {
        guard canConfigure else { return }
        configure { [store] in try await store.read(url) }
    }

    func fileImportFailed() { notice("The file could not be imported.", error: true) }

    func signIn() {
        guard canSignIn, let client, let config else { return }
        generation &+= 1
        let ticket = generation
        pending = true
        notice("Opening Link. Confirm the sign-in and return to the demo.")
        // This task belongs to the app, not a view or its foreground lifetime.
        loginTask = Task {
            do { try await client.signIn(scopes: config.scopes) }
            catch {
                if generation == ticket && !handlingCallback {
                    enqueue {
                        guard self.generation == ticket else { return }
                        await self.recover(client)
                        self.notice(Self.safeMessage(error), error: true)
                    }
                }
            }
            if generation == ticket { loginTask = nil }
        }
    }

    func receive(_ url: URL) {
        guard url.absoluteString.utf8.count <= 16 * 1024,
              url.scheme == DemoConfiguration.bundleID, url.host == "oauth", url.path == "/callback",
              queuedCallbacks.count < 4, queuedCallbacks.insert(url.absoluteString).inserted else { return }
        enqueue {
            defer { self.queuedCallbacks.remove(url.absoluteString) }
            guard let client = self.client else {
                self.notice("The callback needs the config that the sign-in started with.", error: true)
                return
            }
            self.handlingCallback = true
            defer { self.handlingCallback = false }
            do {
                if try await client.handleCallback(url) != nil {
                    self.apply(try await client.restore())
                    self.notice("Sign-in confirmed. The SDK verified the token signatures.")
                }
            } catch {
                if !Self.keepsPendingLogin(error) { await self.recover(client) }
                self.notice(Self.safeMessage(error), error: true)
            }
        }
    }

    func cancelSignIn() {
        guard !isBusy && pending else { return }
        enqueue { await self.cancelPending(message: "Sign-in cancelled.") }
    }

    func checkSession(forceRefresh: Bool) {
        guard !isBusy, let client, let session, !forceRefresh || session.canRefresh else { return }
        enqueue {
            do {
                try await client.checkSession(forceRefresh: forceRefresh)
                self.apply(try await client.restore())
                self.notice(forceRefresh ? "Tokens refreshed, session checked." : "The SDK checked the session.")
            } catch {
                await self.recover(client)
                self.notice(Self.safeMessage(error), error: true)
            }
        }
    }

    func signOut() {
        guard canSignOut, let client else { return }
        enqueue {
            self.generation &+= 1
            self.expiryTask?.cancel()
            self.session = nil
            self.recoveryRequired = false
            self.revocationPending = true
            do {
                let result = try await client.signOut()
                self.revocationPending = result == .revocationPending
                self.notice(self.revocationPending
                    ? "Signed out locally. Retry the access revocation when a connection is available."
                    : "Signed out.")
            } catch { self.notice(Self.safeMessage(error), error: true) }
        }
    }

    private func bootstrap() async {
        defer { bootstrapping = false }
        do {
            guard let loaded = try await store.load() else {
                notice("Import the public iOS config from Console.")
                return
            }
            let restoredClient = try await makeClient(loaded)
            config = loaded
            client = restoredClient
            apply(try await restoredClient.restore())
            notice(pending ? "Waiting for the return from Link. The attempt was restored." : "The SDK is ready. Session state restored.")
        } catch {
            if client != nil { recoveryRequired = true }
            notice(Self.safeMessage(error), error: true)
        }
    }

    private func configure(_ load: @escaping @MainActor () async throws -> DemoConfiguration) {
        enqueue {
            do {
                let config = try await load()
                let candidate = try await self.makeClient(config)
                do {
                    let status = try await candidate.restore()
                    try await self.store.save(config)
                    try await self.client?.close()
                    self.client = candidate
                    self.config = config
                    self.generation &+= 1
                    self.apply(status)
                    self.notice("Config loaded. You can start the sign-in.")
                } catch {
                    try? await candidate.close()
                    throw error
                }
            } catch { self.notice(Self.safeMessage(error), error: true) }
        }
    }

    /// Serialize short operations, including callbacks arriving during startup.
    /// The long-running signIn waiter stays outside this queue.
    private func enqueue(_ action: @escaping @MainActor () async -> Void) {
        operationCount += 1
        let previous = operationTail
        operationTail = Task {
            await startup?.value
            await previous?.value
            await action()
            operationCount -= 1
        }
    }

    private func recover(_ client: any DemoAuthClient) async {
        do { apply(try await client.restore()) }
        catch {
            session = nil
            pending = false
            recoveryRequired = true
        }
    }

    private func cancelPending(message: String) async {
        generation &+= 1
        expiryTask?.cancel()
        expiryTask = nil
        do {
            try await client?.cancelSignIn()
            pending = false
            loginTask = nil
            notice(message)
        } catch {
            if let client { await recover(client) }
            notice(Self.safeMessage(error), error: true)
        }
    }

    private func apply(_ status: SessionStatus) {
        expiryTask?.cancel()
        expiryTask = nil
        session = nil
        pending = false
        revocationPending = false
        recoveryRequired = false
        switch status {
        case .signedOut: break
        case let .signedIn(user, expiresAt, canRefresh):
            session = DemoSession(user: user, expiresAt: Date(timeIntervalSince1970: Double(expiresAt)), canRefresh: canRefresh)
        case let .pendingLogin(expiresAt):
            pending = true
            let ticket = generation
            let delay = min(600, max(0, Double(expiresAt) - Date().timeIntervalSince1970))
            expiryTask = Task {
                do { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
                catch { return }
                enqueue {
                    guard self.generation == ticket && self.pending else { return }
                    await self.cancelPending(message: "The sign-in timed out. Start a new attempt.")
                }
            }
        case .revocationPending: revocationPending = true
        case .reauthenticationRequired: recoveryRequired = true
        }
    }

    private func notice(_ message: String, error: Bool = false) {
        self.message = message
        isError = error
        events.insert(DemoEvent(message: message), at: 0)
        events = Array(events.prefix(12))
    }

    private static func keepsPendingLogin(_ error: Error) -> Bool {
        guard case LinkAuthFailure.protocolFailure(let code) = error else { return false }
        return code == .invalidCallback || code == .stateMismatch || code == .issuerMismatch
    }

    private static func safeMessage(_ error: Error) -> String {
        if let error = error as? DemoConfigError { return error.message }
        guard let error = error as? LinkAuthFailure else { return "The operation failed. Try again." }
        switch error {
        case .cannotOpenLink: return "iOS did not open Link. Check the Link build and its Universal Links association."
        case .closed: return "The SDK is closed. Restart the demo."
        case .protocolFailure(let code):
            switch code {
            case .invalidConfig: return "The SDK rejected the config. Check the public JSON from Console."
            case .invalidScopes: return "The requested scopes do not match the config."
            case .authorizationDenied: return "The user declined the sign-in in Link."
            case .cancelled: return "Sign-in cancelled."
            case .expired: return "The sign-in timed out. Start a new attempt."
            case .transport: return "Network error. Check the connection and try again."
            case .invalidDiscovery: return "Discovery does not match the config. Check the issuer and the regional API."
            case .invalidCallback, .stateMismatch, .issuerMismatch: return "Callback rejected. The current sign-in attempt is preserved."
            case .storage, .invalidStoredState: return "Session storage is unavailable. Unlock the iPhone and restart the demo."
            case .reauthenticationRequired: return "Sign in again. End the previous session first."
            case .revocationPending: return "Finish revoking the previous session when a connection is available."
            case .alreadyInProgress: return "Wait for the current operation to finish."
            case .invalidIdToken, .invalidSigningKey, .invalidTokenResponse: return "The SDK rejected the tokens. Sign-in is not confirmed."
            case .http(let status): return "The server returned HTTP \(status)."
            case .oAuth: return "The authorization server rejected the request. Start a new attempt."
            default: return "The operation failed. Try again."
            }
        }
    }
}
