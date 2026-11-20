import Foundation

// Exercises KeychainStorage's serialization/locking/CAS through an injected
// backend. Real Keychain accessibility/entitlements require signed device tests.
private final class MemoryKeychain: KeychainBackend, @unchecked Sendable {
    var values: [String: Data] = [:]
    var fail = false
    func read(service: String, account: String) throws -> Data? {
        if fail { throw StorageFailure.Unavailable }; return values[service + account]
    }
    func write(service: String, account: String, data: Data) throws {
        if fail { throw StorageFailure.Unavailable }; values[service + account] = data
    }
    func delete(service: String, account: String) throws {
        if fail { throw StorageFailure.Unavailable }; values.removeValue(forKey: service + account)
    }
}

private func check(_ condition: Bool, _ message: String = "native Swift smoke assertion") {
    precondition(condition, message)
}
private func expect(_ expected: ErrorCode, _ action: () async throws -> Void) async {
    do { try await action(); preconditionFailure("expected authentication error") }
    catch AuthError.Failure(let code) { check(code == expected, "unexpected auth error: \(code)") }
    catch { preconditionFailure("unexpected native error") }
}
private func callback(_ request: AuthorizationRequest, issuer: String) throws -> String {
    let query = URLComponents(string: request.authorizationUrl())!.queryItems!
    let params = Dictionary(uniqueKeysWithValues: query.map { ($0.name, $0.value!) })
    let data = try JSONSerialization.data(withJSONObject: ["Nonce": params["nonce"]!, "Challenge": params["code_challenge"]!])
    let code = data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    var url = URLComponents(string: params["redirect_uri"]!)!
    url.queryItems = [URLQueryItem(name: "code", value: code), URLQueryItem(name: "state", value: params["state"]!), URLQueryItem(name: "iss", value: issuer)]
    return url.string!
}

@main struct NativeSmoke {
    static func main() async throws {
        let base = CommandLine.arguments[1]
        let template = try String(contentsOfFile: "bindings/fixtures/console-config.json", encoding: .utf8)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("link-native-swift-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let backend = MemoryKeychain()
        func storage() throws -> KeychainStorage { try KeychainStorage(service: "native-fixture", directory: directory, backend: backend) }
        func client(_ path: String, _ transport: URLSessionTransport) throws -> LinkSessionClient {
            try LinkSessionClient(configJson: template.replacingOccurrences(of: "https://login.example.test", with: base + path),
                redirectUri: "com.example.app://oauth/callback", transport: transport, storage: storage())
        }
        let transport = URLSessionTransport(); defer { transport.close() }
        let first = try client("/swift", transport)
        check(try first.restore() == .signedOut)
        let pending = try await first.beginSignIn(scopes: ["openid", "profile", "offline_access"])
        let restarted = try client("/swift", transport)
        if case .pendingLogin = try restarted.restore() {} else { preconditionFailure("pending flow not restored") }
        let signedIn = try await restarted.completeSignIn(callbackUrl: callback(pending, issuer: base + "/swift"))
        check(signedIn.user().subject == "native-test-sub")
        let resumed = try client("/swift", transport)
        if case .signedIn(_, _, true) = try resumed.restore() {} else { preconditionFailure("session not restored") }
        check(try await resumed.validSession().accessToken() == signedIn.accessToken())
        let refreshed = try await resumed.refresh()
        check(refreshed.refreshToken() != signedIn.refreshToken())
        check(refreshed.user().subject == signedIn.user().subject)
        check(try await resumed.logout() == .revoked)
        check(try resumed.restore() == .signedOut)

        // Storage failures are distinct from SignedOut; concurrent CAS has one winner.
        backend.fail = true
        await expect(.storage) { _ = try resumed.restore() }
        backend.fail = false
        let key = "link.auth.v1." + String(repeating: "A", count: 43)
        let stores = try (0..<16).map { _ in try storage() }
        let wins = try await withThrowingTaskGroup(of: Bool.self) { group in
            for store in stores {
                group.addTask { try store.compareExchange(key: key, expectedRevision: nil,
                    replacement: StorageEntry(revision: String(repeating: "B", count: 43), payload: "test")) }
            }
            var wins = 0; for try await won in group { if won { wins += 1 } }; return wins
        }
        check(wins == 1)
        check(try stores[0].load(key: key)?.payload() == "test")
        // Same-device backup restore/reinstall: Keychain can survive, but the
        // installation locator does not. Never select the old record again.
        try FileManager.default.removeItem(at: directory.appendingPathComponent(key + ".installation"))
        check(try storage().load(key: key) == nil)
        check(backend.values.values.contains { (try? JSONSerialization.jsonObject(with: $0) as? [String: String])?["payload"] == "test" })

        for variant in ["drop", "retry"] {
            let path = "/swift/" + variant, broken = try client(path, transport)
            let request = try await broken.beginSignIn(scopes: ["openid", "profile", "offline_access"])
            _ = try await broken.completeSignIn(callbackUrl: callback(request, issuer: base + path))
            await expect(variant == "drop" ? .transport : .http(status: 503)) { _ = try await broken.refresh() }
            check(try client(path, transport).restore() == .reauthenticationRequired)
            await expect(.reauthenticationRequired) { _ = try await broken.validSession() }
            check(try await broken.logout() == .revoked)
        }
        await expect(.http(status: 302)) {
            _ = try await client("/swift/redirect", transport).beginSignIn(scopes: ["openid"])
        }
        await expect(.transport) {
            _ = try await client("/swift/oversize", transport).beginSignIn(scopes: ["openid"])
        }
        let impatient = URLSessionTransport(maximumTimeout: 0.2); defer { impatient.close() }
        let start = Date()
        await expect(.transport) { _ = try await client("/swift/slow", impatient).beginSignIn(scopes: ["openid"]) }
        check(Date().timeIntervalSince(start) < 2)

        let cancelling = try client("/swift/cancel/slow", transport)
        let operation = Task { try await cancelling.beginSignIn(scopes: ["openid"]) }
        let waitStart = Date()
        while true {
            let (data, _) = try await URLSession.shared.data(from: URL(string: base + "/stats")!)
            let snapshot = try JSONSerialization.jsonObject(with: data) as! [String: Int]
            if snapshot["/swift/cancel/slow/.well-known/openid-configuration"] != nil { break }
            check(Date().timeIntervalSince(waitStart) < 2, "request did not reach fixture")
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        let cancelStart = Date()
        try cancelling.cancelSignIn(); transport.cancelRequests()
        await expect(.cancelled) { _ = try await operation.value }
        check(Date().timeIntervalSince(cancelStart) < 1)
        check(try cancelling.restore() == .signedOut)
        _ = try await resumed.beginSignIn(scopes: ["openid"])
        try resumed.cancelSignIn() // The cancelled transport can be reused.

        let (bytes, _) = try await URLSession.shared.data(from: URL(string: base + "/stats")!)
        let counts = try JSONSerialization.jsonObject(with: bytes) as! [String: Int]
        check(counts["/followed"] == nil)
        for path in ["/swift", "/swift/drop", "/swift/retry"] {
            check(counts[path + "/oauth/v1/token/authorization_code"] == 1)
            check(counts[path + "/oauth/v1/token/refresh_token"] == 1, "native POST was retried")
            check(counts[path + "/oauth/v1/revoke"] == 1)
        }
        print("Swift native smoke passed: PKCE/JWT, restore, refresh, revoke, CAS, backup isolation, storage failures, no POST retries/redirects, limits, cancellation")
    }
}
