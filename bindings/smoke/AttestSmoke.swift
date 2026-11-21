import CryptoKit
import Foundation

// Device attestation end to end: Swift -> UniFFI -> Rust -> HTTP -> the Go
// fixture, which checks every proof with its own implementation of the signed
// string. The hardware key is replaced by a software P-256 key; real App
// Attest needs a signed app on a device.
private final class SoftAttestor: DeviceAttestor, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private var createdCount = 0, deletedCount = 0
    private var supported = true
    private func locked<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }
    var created: Int { locked { createdCount } }
    var deleted: Int { locked { deletedCount } }
    var alive: Int { locked { keys.count } }
    func setSupported(_ value: Bool) { locked { supported = value } }

    func isAvailable() -> Bool { locked { supported } }
    func createKey(name: String, challenge: Data, timeoutMillis: UInt32) async throws -> AttestedKey {
        precondition(name.hasPrefix("link.attest.v1.") && challenge.count == 32 && timeoutMillis <= 10_000)
        let key = P256.Signing.PrivateKey()
        let reference = name + ".k." + UUID().uuidString
        locked { keys[reference] = key; createdCount += 1 }
        // What the fixture accepts in place of a certificate chain.
        return AttestedKey(keyRef: reference,
            attestation: .android(certificateChain: [key.publicKey.derRepresentation, challenge]))
    }
    func sign(keyRef: String, message: Data) async throws -> Data {
        guard let key = locked({ keys[keyRef] }) else { throw AttestationFailure.KeyLost }
        return try key.signature(for: message).derRepresentation
    }
    func deleteKey(keyRef: String) async throws {
        locked { keys[keyRef] = nil; deletedCount += 1 }
    }
}

private final class MemoryKeychain: KeychainBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: Data] = [:]
    func read(service: String, account: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }; return values[service + account]
    }
    func write(service: String, account: String, data: Data) throws {
        lock.lock(); defer { lock.unlock() }; values[service + account] = data
    }
    func delete(service: String, account: String) throws {
        lock.lock(); defer { lock.unlock() }; values.removeValue(forKey: service + account)
    }
    /// Accounts are "<record name>.<installation id>".
    func accounts(_ prefix: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return values.keys.filter { $0.contains(prefix) }.count
    }
}

private func check(_ condition: Bool, _ message: String = "attestation smoke assertion",
    line: UInt = #line) {
    precondition(condition, "\(message) (line \(line))")
}
private func expect(_ expected: ErrorCode, line: UInt = #line, _ action: () async throws -> Void) async {
    do { try await action(); preconditionFailure("expected \(expected) (line \(line))") }
    catch AuthError.Failure(let code) { check(code == expected, "unexpected auth error: \(code)", line: line) }
    catch { preconditionFailure("unexpected native error (line \(line))") }
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

@main struct AttestSmoke {
    static func main() async throws {
        let base = CommandLine.arguments[1]
        let template = try String(contentsOfFile: "bindings/fixtures/console-config.json", encoding: .utf8)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("link-attest-swift-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let keychain = MemoryKeychain()
        let transport = URLSessionTransport(); defer { transport.close() }
        let scopes = ["openid", "profile", "offline_access"]

        func control(_ path: String) async throws {
            _ = try await URLSession.shared.data(from: URL(string: base + path)!)
        }
        func arm(_ prefix: String, _ fault: String, _ times: Int = 1) async throws {
            try await control("/arm?prefix=\(prefix)&fault=\(fault)&times=\(times)")
        }
        func stats() async throws -> [String: Int] {
            let (data, _) = try await URLSession.shared.data(from: URL(string: base + "/stats")!)
            return try JSONSerialization.jsonObject(with: data) as! [String: Int]
        }
        // attestor == nil is the application's `attestation: false`.
        func client(_ path: String, _ attestor: SoftAttestor?) throws -> LinkSessionClient {
            let config = template.replacingOccurrences(of: "https://login.example.test", with: base + path)
            let storage = try KeychainStorage(service: "attest-fixture", directory: directory, backend: keychain)
            guard let attestor else {
                return try LinkSessionClient(configJson: config, redirectUri: "com.example.app://oauth/callback",
                    transport: transport, storage: storage)
            }
            return try LinkSessionClient.withAttestation(configJson: config, redirectUri: "com.example.app://oauth/callback",
                transport: transport, storage: storage, attestor: attestor)
        }
        func signIn(_ sdk: LinkSessionClient, _ path: String) async throws -> SignInResult {
            let request = try await sdk.beginSignIn(scopes: scopes)
            return try await sdk.completeSignIn(callbackUrl: callback(request, issuer: base + path))
        }

        // 1. "Report" mode: the key is registered before Link is opened and
        //    signs the code exchange and every refresh.
        var path = "/swift/attest-report"
        var attestor = SoftAttestor()
        var sdk = try client(path, attestor)
        let request = try await sdk.beginSignIn(scopes: scopes)
        var counts = try await stats()
        check(counts[path + "/oauth/v1/attest/challenge"] == 1 && counts[path + "/oauth/v1/attest/keys"] == 1)
        check(counts[path + "/oauth/v1/token"] == nil)
        var session = try await sdk.completeSignIn(callbackUrl: callback(request, issuer: base + path))
        // The fixture verified the proof: only then is the session "verified".
        check(session.user().deviceTrust == "verified")
        check(keychain.accounts("link.auth.v1.") == 1 && keychain.accounts("link.attest.v1.") == 1)
        session = try await sdk.refresh()
        check(session.user().deviceTrust == "verified")

        // 2. The answer to a refresh is lost: the session survives a restart and
        //    the same token is sent again under the next attempt number.
        try await arm(path, "refresh-lose")
        let before = session.accessToken()
        await expect(.transport) { _ = try await sdk.refresh() }
        sdk = try client(path, attestor)
        if case .signedIn(_, _, true) = try sdk.restore() {} else { preconditionFailure("session lost with the answer") }
        session = try await sdk.validSession()
        check(session.accessToken() != before && session.user().deviceTrust == "verified")
        try await arm(path, "refresh-503")
        await expect(.http(status: 503)) { _ = try await sdk.refresh() }
        _ = try await sdk.refresh()
        try await arm(path, "refresh-429")
        await expect(.oAuth(code: "temporarily_unavailable")) { _ = try await sdk.refresh() }
        _ = try await sdk.refresh()
        // A refused signature is made once more.
        try await arm(path, "proof-invalid")
        _ = try await sdk.refresh()
        counts = try await stats()
        // 1 plain + 2 (lost, repeated) + 2 (503) + 2 (429) + 2 (proof refused once)
        check(counts[path + "/oauth/v1/token/refresh_token"] == 9)

        // 3. The key outlives sign-out and is not registered again.
        check(try await sdk.logout() == .revoked)
        check(keychain.accounts("link.auth.v1.") == 0 && keychain.accounts("link.attest.v1.") == 1)
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "verified")
        counts = try await stats()
        check(counts[path + "/oauth/v1/attest/keys"] == 1 && attestor.created == 1 && attestor.deleted == 0)

        // 4. Refusals that end the session.
        try await arm(path, "proof-invalid", 2)
        await expect(.oAuth(code: "invalid_client")) { _ = try await sdk.refresh() }
        check(try client(path, attestor).restore() == .reauthenticationRequired)
        check(try await sdk.logout() == .revoked)
        _ = try await signIn(sdk, path)
        try await arm(path, "retry-refused")
        await expect(.oAuth(code: "invalid_grant")) { _ = try await sdk.refresh() }
        await expect(.reauthenticationRequired) { _ = try await sdk.validSession() }
        check(try await sdk.logout() == .revoked)

        // 5. The answer to the key upload is lost: a new key with a new challenge.
        path = "/swift/attest-report/lost-upload"; attestor = SoftAttestor(); sdk = try client(path, attestor)
        try await arm(path, "keys-lose")
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "verified")
        counts = try await stats()
        check(counts[path + "/oauth/v1/attest/keys"] == 2 && attestor.created == 2 && attestor.deleted == 1 && attestor.alive == 1)

        // 6. Registration that fails does not fail the sign-in.
        path = "/swift/attest-report/refused-upload"; attestor = SoftAttestor(); sdk = try client(path, attestor)
        try await arm(path, "keys-400")
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "none" && attestor.alive == 0)
        _ = try await sdk.refresh()

        // 7. Mode "off": no key is created.
        path = "/swift/attest-off"; attestor = SoftAttestor(); sdk = try client(path, attestor)
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == nil && attestor.created == 0)

        // 8. "Required": a sign-in without a key is refused before the code is
        //    spent, the SDK registers a key and repeats the exchange.
        path = "/swift/attest-required"; attestor = SoftAttestor(); sdk = try client(path, attestor)
        try await arm(path, "challenge-503")
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "verified")
        counts = try await stats()
        check(counts[path + "/oauth/v1/token/authorization_code"] == 2 && counts[path + "/oauth/v1/attest/challenge"] == 2)
        // A key the server no longer knows is replaced within the same sign-in.
        check(try await sdk.logout() == .revoked)
        try await control("/act?prefix=\(path)&do=forget-keys")
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "verified" && attestor.created == 2 && attestor.deleted == 1)
        // A revoked key is deleted; the person signs in again with a new one.
        check(try await sdk.logout() == .revoked)
        try await control("/act?prefix=\(path)&do=revoke-keys")
        await expect(.reauthenticationRequired) { _ = try await signIn(sdk, path) }
        check(try sdk.restore() == .signedOut && attestor.alive == 0)
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == "verified" && attestor.created == 3)
        // A session bound to a key that the server then revokes cannot be refreshed.
        try await control("/act?prefix=\(path)&do=revoke-keys")
        await expect(.oAuth(code: "invalid_client")) { _ = try await sdk.refresh() }
        check(try sdk.restore() == .reauthenticationRequired && attestor.alive == 0)
        check(try await sdk.logout() == .revoked)

        // 9. "Required" and no key possible: a typed error, nothing stored.
        path = "/swift/attest-required/no-hardware"; attestor = SoftAttestor(); attestor.setSupported(false)
        sdk = try client(path, attestor)
        await expect(.attestationRequired) { _ = try await signIn(sdk, path) }
        check(try sdk.restore() == .signedOut)
        path = "/swift/attest-required/sdk-off"; sdk = try client(path, nil)
        await expect(.attestationRequired) { _ = try await signIn(sdk, path) }

        // 10. A server that does not advertise attestation: the SDK behaves as
        //     0.1.0 even with an attestor, including the lost-answer case.
        path = "/swift/plain/drop"; attestor = SoftAttestor(); sdk = try client(path, attestor)
        session = try await signIn(sdk, path)
        check(session.user().deviceTrust == nil && attestor.created == 0)
        await expect(.transport) { _ = try await sdk.refresh() }
        check(try client(path, attestor).restore() == .reauthenticationRequired)
        counts = try await stats()
        check(counts[path + "/oauth/v1/attest/challenge"] == nil && counts[path + "/oauth/v1/token/refresh_token"] == 1)
        check(try await sdk.logout() == .revoked)

        print("Swift attestation smoke passed: key registration, signed exchange and refresh, repeat after a lost answer, 503/429, re-signed proof, key reuse after sign-out, lost and refused key upload, modes off/report/required, key_unknown, key_revoked, retry_refused, AttestationRequired, unchanged behaviour without link_attestation")
    }
}
