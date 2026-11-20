import Foundation

private func check(_ value: Bool) { precondition(value, "facade smoke assertion") }
private func expect(_ code: ErrorCode, _ action: () async throws -> Void) async {
    do { try await action(); preconditionFailure("expected protocol failure") }
    catch LinkAuthFailure.protocolFailure(let actual) { check(actual == code) }
    catch { preconditionFailure("unexpected failure type") }
}
private final class Store: SecureStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: (String, String)] = [:]
    func load(key: String) throws -> StorageEntry? {
        check(!Thread.isMainThread)
        lock.lock(); defer { lock.unlock() }
        return values[key].map { StorageEntry(revision: $0.0, payload: $0.1) }
    }
    func compareExchange(key: String, expectedRevision: String?, replacement: StorageEntry?) throws -> Bool {
        check(!Thread.isMainThread)
        lock.lock(); defer { lock.unlock() }
        guard values[key]?.0 == expectedRevision else { return false }
        values[key] = replacement.map { ($0.revision(), $0.payload()) }
        return true
    }
}
@MainActor private final class Opener: LinkAuthorizationOpener {
    var urls: [URL] = []
    var accepts = true
    func open(_ url: URL) async -> Bool {
        check(url.scheme == "https" && url.host == "linkm.me" && url.path == "/oauth/authorize")
        urls.append(url)
        return accepts
    }
    func next() async throws -> URL {
        for _ in 0..<300 {
            if !urls.isEmpty { return urls.removeFirst() }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        preconditionFailure("authorization was not opened")
    }
}
private func callback(_ url: URL, issuer: String, deny: Bool = false, wrongState: Bool = false) throws -> URL {
    let params = Dictionary(uniqueKeysWithValues: URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!.map { ($0.name, $0.value!) })
    let bytes = try JSONSerialization.data(withJSONObject: ["Nonce": params["nonce"]!, "Challenge": params["code_challenge"]!])
    let code = bytes.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    var result = URLComponents(string: params["redirect_uri"]!)!
    result.queryItems = [URLQueryItem(name: deny ? "error" : "code", value: deny ? "access_denied" : code),
        URLQueryItem(name: "state", value: wrongState ? "bad-state" : params["state"]!), URLQueryItem(name: "iss", value: issuer)]
    return result.url!
}

@main struct FacadeSmoke {
    static func main() async throws {
        let base = CommandLine.arguments[1]
        let template = try String(contentsOfFile: "bindings/fixtures/console-config.json", encoding: .utf8)
        let store = Store()
        let scopes = ["openid", "profile", "offline_access"]
        func make(_ path: String, _ opener: Opener, timeout: TimeInterval = 600) async throws -> LinkAuth {
            try await Task.detached {
                let transport = URLSessionTransport()
                let core = try LinkSessionClient(configJson: template.replacingOccurrences(of: "https://login.example.test", with: base + path),
                    redirectUri: "com.example.app://oauth/callback", transport: transport, storage: store)
                return LinkAuth(core: core, transport: transport, opener: opener, signInTimeout: timeout)
            }.value
        }
        let opener = Opener(), path = "/facade/swift"
        let auth = try await make(path, opener)
        check(try await auth.restore() == .signedOut)
        let backendNonce = String(repeating: "n", count: 64)
        let signingIn = Task { try await auth.signIn(scopes: scopes, nonce: backendNonce) }
        let url = try await opener.next()
        precondition(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "nonce" })?.value == backendNonce)
        await expect(.alreadyInProgress) { _ = try await auth.signIn(scopes: scopes) }
        check(try await auth.handleCallback(URL(string: "https://unrelated.example.test/page")!) == nil)
        await expect(.stateMismatch) { _ = try await auth.handleCallback(callback(url, issuer: base + path, wrongState: true)) }
        let user = try await auth.handleCallback(callback(url, issuer: base + path))
        let session = try await signingIn.value
        check(user?.subject == session.user.subject)
        check(try await auth.getIdToken() == session.idToken)
        let info = try await auth.getUserInfo()
        check(info.subject == session.user.subject && info.name == "Fresh Native Name")
        check(info.phoneNumber == nil && info.phoneNumberVerified == nil)
        check(try await auth.handleCallback(callback(url, issuer: base + path)) == nil)
        try await auth.close()
        do { _ = try await auth.getIdToken(); preconditionFailure("closed SDK was used") }
        catch LinkAuthFailure.closed {}
        do { _ = try await auth.getUserInfo(); preconditionFailure("closed SDK returned user info") }
        catch LinkAuthFailure.closed {}
        let resumed = try await make(path, opener)
        if case .signedIn = try await resumed.restore() {} else { preconditionFailure("session lost on disposal") }
        check(try await resumed.signOut() == .revoked)
        await expect(.reauthenticationRequired) { _ = try await resumed.getUserInfo() }

        let phonePath = "/facade/swift/phone", phone = try await make(phonePath, opener)
        let phoneLogin = Task { try await phone.signIn(scopes: scopes + ["phone"]) }
        let phoneURL = try await opener.next()
        _ = try await phone.handleCallback(callback(phoneURL, issuer: base + phonePath))
        _ = try await phoneLogin.value
        let phoneInfo = try await phone.getUserInfo()
        check(phoneInfo.phoneNumber == "+12025550123" && phoneInfo.phoneNumberVerified == nil)
        check(try await phone.signOut() == .revoked)
        try await phone.close()

        let denied = Task { try await resumed.signIn(scopes: scopes) }
        let deniedURL = try await opener.next()
        await expect(.authorizationDenied) { _ = try await resumed.handleCallback(callback(deniedURL, issuer: base + path, deny: true)) }
        await expect(.authorizationDenied) { _ = try await denied.value }
        check(try await resumed.restore() == .signedOut)

        let cancelled = Task { try await resumed.signIn(scopes: scopes) }
        _ = try await opener.next(); cancelled.cancel()
        await expect(.cancelled) { _ = try await cancelled.value }
        check(try await resumed.restore() == .signedOut)
        opener.accepts = false
        do { _ = try await resumed.signIn(scopes: scopes); preconditionFailure("unhandled URL succeeded") }
        catch LinkAuthFailure.cannotOpenLink {}
        _ = try await opener.next()
        check(try await resumed.restore() == .signedOut)
        opener.accepts = true
        let timeoutClient = try await make("/facade/swift/timeout", opener, timeout: 0.1)
        await expect(.expired) { _ = try await timeoutClient.signIn(scopes: scopes) }
        _ = try await opener.next()
        check(try await timeoutClient.restore() == .signedOut)
        try await timeoutClient.close()

        // Restored pending flow has no in-memory facade waiter.
        let coldPath = "/facade/swift/cold"
        let pendingURL = try await Task.detached {
            let transport = URLSessionTransport(); defer { transport.close() }
            let core = try LinkSessionClient(configJson: template.replacingOccurrences(of: "https://login.example.test", with: base + coldPath),
                redirectUri: "com.example.app://oauth/callback", transport: transport, storage: store)
            return try await core.beginSignIn(scopes: scopes).authorizationUrl()
        }.value
        let cold = try await make(coldPath, opener)
        if case .pendingLogin = try await cold.restore() {} else { preconditionFailure("pending not restored") }
        check(try await cold.handleCallback(callback(URL(string: pendingURL)!, issuer: base + coldPath))?.subject == "native-test-sub")
        check(try await cold.getIdToken().contains("."))
        check(try await cold.signOut() == .revoked)
        try await cold.close()

        // Cancelling one token consumer does not interrupt another's rotation.
        let refreshPath = "/facade/swift/slow-refresh", refresh = try await make(refreshPath, opener)
        let login = Task { try await refresh.signIn(scopes: scopes) }
        let refreshURL = try await opener.next()
        _ = try await refresh.handleCallback(callback(refreshURL, issuer: base + refreshPath))
        let old = try await login.value
        let first = Task { try await refresh.getSession(forceRefresh: true) }
        let second = Task { try await refresh.getSession(forceRefresh: true) }
        try await Task.sleep(nanoseconds: 100_000_000); first.cancel()
        do { _ = try await first.value; preconditionFailure("cancelled waiter succeeded") }
        catch is CancellationError {}
        let rotated = try await second.value
        check(rotated.accessToken != old.accessToken)
        let (statsData, _) = try await URLSession.shared.data(from: URL(string: base + "/stats")!)
        let counts = try JSONSerialization.jsonObject(with: statsData) as! [String: Int]
        check(counts[refreshPath + "/oauth/v1/token/refresh_token"] == 1)
        let interruptedRefresh = Task { try await refresh.getSession(forceRefresh: true) }
        try await Task.sleep(nanoseconds: 100_000_000)
        check(try await refresh.signOut() == .revoked)
        do { _ = try await interruptedRefresh.value; preconditionFailure("refresh survived logout") }
        catch LinkAuthFailure.protocolFailure(let code) { check(code == .transport || code == .cancelled) }
        check(try await refresh.restore() == .signedOut)
        try await refresh.close()

        let pendingLogout = Task { try await resumed.signIn(scopes: scopes) }
        _ = try await opener.next()
        check(try await resumed.signOut() == .localOnly)
        await expect(.cancelled) { _ = try await pendingLogout.value }
        let pendingClose = Task { try await resumed.signIn(scopes: scopes) }
        _ = try await opener.next(); try await resumed.close()
        do { _ = try await pendingClose.value; preconditionFailure("closed login succeeded") }
        catch LinkAuthFailure.closed {}
        // Every network request uses loopback, while signed issuer stays canonical.
        let regional = try await Task.detached {
            let config = template.replacingOccurrences(of: "\"token_url\": \"https://login.example.test",
                with: "\"api_base_url\": \"\(base)\", \"token_url\": \"\(base)")
            let transport = URLSessionTransport()
            let core = try LinkSessionClient(configJson: config, redirectUri: "com.example.app://oauth/callback",
                transport: transport, storage: store)
            return LinkAuth(core: core, transport: transport, opener: opener)
        }.value
        let regionalLogin = Task { try await regional.signIn(scopes: scopes) }
        let regionalURL = try await opener.next()
        check(try await regional.handleCallback(callback(regionalURL, issuer: "https://login.example.test"))?.issuer == "https://login.example.test")
        _ = try await regionalLogin.value
        check(try await regional.getSession(forceRefresh: true).user.issuer == "https://login.example.test")
        check(try await regional.getUserInfo().name == "Fresh Native Name")
        check(try await regional.signOut() == .revoked)
        try await regional.close()
        print("Swift facade smoke passed: regional API/shared issuer, signIn/callback, invalid and duplicate links, cold restore, denial, task cancellation, launch failure, timeout, shared refresh, logout during refresh, disposal, storage off main thread")
    }
}
