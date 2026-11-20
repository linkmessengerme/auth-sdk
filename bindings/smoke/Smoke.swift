import Foundation

// This is a binding test, not a production URLSession adapter.
final class FixtureTransport: HttpTransport, @unchecked Sendable {
    let discovery: Data
    let fail: Bool

    init(discovery: Data, fail: Bool = false) {
        self.discovery = discovery
        self.fail = fail
    }

    func execute(request: HttpRequest) async throws -> HttpResponse {
        try await Task.sleep(nanoseconds: 1_000_000)
        if fail { throw TransportFailure.RequestFailed }
        precondition(request.timeoutMillis() == 15_000)
        precondition(request.maxResponseBytes() == 262_144)
        if request.method() == "GET" {
            return HttpResponse(status: 200, url: request.url(), contentType: "application/json", body: discovery)
        }
        precondition(request.method() == "POST")
        precondition(!request.body().isEmpty)
        return HttpResponse(
            status: 400, url: request.url(), contentType: "application/json",
            body: Data(#"{"error":"invalid_grant","error_description":"DO-NOT-LOG-THIS"}"#.utf8)
        )
    }
}

func expectError(_ expected: ErrorCode, _ action: () async throws -> Void) async {
    do {
        try await action()
        preconditionFailure("expected a typed authentication error")
    } catch AuthError.Failure(let code) {
        precondition(code == expected)
    } catch {
        preconditionFailure("unexpected error type")
    }
}

func callback(_ request: AuthorizationRequest, denied: Bool, wrongState: Bool = false) -> String {
    let authorize = URLComponents(string: request.authorizationUrl())!
    let parameters = Dictionary(uniqueKeysWithValues: authorize.queryItems!.map { ($0.name, $0.value!) })
    precondition(parameters["code_challenge_method"] == "S256")
    precondition(parameters["code_challenge"]!.count == 43)
    precondition(parameters["nonce"]!.count == 43)
    var redirect = URLComponents(string: parameters["redirect_uri"]!)!
    redirect.queryItems = [
        URLQueryItem(name: denied ? "error" : "code", value: denied ? "access_denied" : "smoke-code"),
        URLQueryItem(name: "state", value: wrongState ? "wrong" : parameters["state"]!),
        URLQueryItem(name: "iss", value: "https://login.example.test")
    ]
    return redirect.string!
}

@main struct Smoke {
    static func main() async throws {
        let directory = URL(fileURLWithPath: CommandLine.arguments[1])
        let config = try String(contentsOf: directory.appendingPathComponent("console-config.json"), encoding: .utf8)
        let discovery = try Data(contentsOf: directory.appendingPathComponent("discovery.json"))
        let client = try LinkAuthClient(
            configJson: config, redirectUri: "com.example.app://oauth/callback",
            transport: FixtureTransport(discovery: discovery)
        )
        let pending = try await client.beginSignIn(scopes: ["openid", "profile"])
        precondition(pending.transactionId().count == 43)
        await expectError(.alreadyInProgress) { _ = try await client.beginSignIn(scopes: ["openid"]) }
        await expectError(.stateMismatch) {
            _ = try await client.completeSignIn(callbackUrl: callback(pending, denied: true, wrongState: true))
        }
        await expectError(.authorizationDenied) {
            _ = try await client.completeSignIn(callbackUrl: callback(pending, denied: true))
        }
        await expectError(.noPendingLogin) {
            _ = try await client.completeSignIn(callbackUrl: callback(pending, denied: true))
        }
        let exchanging = try await client.beginSignIn(scopes: ["openid"])
        await expectError(.oAuth(code: "invalid_grant")) {
            _ = try await client.completeSignIn(callbackUrl: callback(exchanging, denied: false))
        }
        let cancelled = try await client.beginSignIn(scopes: ["openid"])
        try client.cancelSignIn()
        await expectError(.noPendingLogin) {
            _ = try await client.completeSignIn(callbackUrl: callback(cancelled, denied: true))
        }
        let failing = try LinkAuthClient(
            configJson: config, redirectUri: "com.example.app://oauth/callback",
            transport: FixtureTransport(discovery: discovery, fail: true)
        )
        await expectError(.transport) { _ = try await failing.beginSignIn(scopes: ["openid"]) }
        print("Swift binding smoke passed: async transport, PKCE, callbacks, typed errors, cancellation")
    }
}
