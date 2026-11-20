import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import me.linkmessenger.auth.generated.*

// This is a binding test, not a production OkHttp adapter.
private class FixtureTransport(private val discovery: ByteArray, private val fail: Boolean = false) : HttpTransport {
    override suspend fun execute(request: HttpRequest): HttpResponse {
        delay(1)
        if (fail) throw TransportFailure.RequestFailed()
        check(request.timeoutMillis() == 15_000u)
        check(request.maxResponseBytes() == 262_144u)
        if (request.method() == "GET") {
            return HttpResponse(200u.toUShort(), request.url(), "application/json", discovery)
        }
        check(request.method() == "POST")
        check(request.body().isNotEmpty())
        return HttpResponse(
            400u.toUShort(), request.url(), "application/json",
            """{"error":"invalid_grant","error_description":"DO-NOT-LOG-THIS"}""".toByteArray()
        )
    }
}

private suspend fun expectError(expected: ErrorCode, action: suspend () -> Unit) {
    try {
        action()
        error("expected a typed authentication error")
    } catch (e: AuthException.Failure) {
        check(e.code == expected)
    }
}

private fun callback(request: AuthorizationRequest, denied: Boolean, wrongState: Boolean = false): String {
    val parameters = URI(request.authorizationUrl()).rawQuery.split('&').associate {
        val pair = it.split('=', limit = 2)
        URLDecoder.decode(pair[0], "UTF-8") to URLDecoder.decode(pair[1], "UTF-8")
    }
    check(parameters["code_challenge_method"] == "S256")
    check(parameters.getValue("code_challenge").length == 43)
    check(parameters.getValue("nonce").length == 43)
    val response = linkedMapOf(
        (if (denied) "error" else "code") to (if (denied) "access_denied" else "smoke-code"),
        "state" to (if (wrongState) "wrong" else parameters.getValue("state")),
        "iss" to "https://login.example.test"
    )
    return parameters.getValue("redirect_uri") + "?" + response.entries.joinToString("&") {
        "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}"
    }
}

fun main(args: Array<String>) = runBlocking {
    val directory = Path.of(args[0])
    val config = Files.readString(directory.resolve("console-config.json"))
    val discovery = Files.readAllBytes(directory.resolve("discovery.json"))
    LinkAuthClient(config, "com.example.app://oauth/callback", FixtureTransport(discovery)).use { client ->
        val pending = client.beginSignIn(listOf("openid", "profile"))
        check(pending.transactionId().length == 43)
        expectError(ErrorCode.AlreadyInProgress) { client.beginSignIn(listOf("openid")) }
        expectError(ErrorCode.StateMismatch) { client.completeSignIn(callback(pending, true, true)) }
        expectError(ErrorCode.AuthorizationDenied) { client.completeSignIn(callback(pending, true)) }
        expectError(ErrorCode.NoPendingLogin) { client.completeSignIn(callback(pending, true)) }
        pending.close()
        val exchanging = client.beginSignIn(listOf("openid"))
        expectError(ErrorCode.OAuth("invalid_grant")) { client.completeSignIn(callback(exchanging, false)) }
        exchanging.close()
        val cancelled = client.beginSignIn(listOf("openid"))
        client.cancelSignIn()
        expectError(ErrorCode.NoPendingLogin) { client.completeSignIn(callback(cancelled, true)) }
        cancelled.close()
    }
    LinkAuthClient(config, "com.example.app://oauth/callback", FixtureTransport(discovery, true)).use { client ->
        expectError(ErrorCode.Transport) { client.beginSignIn(listOf("openid")) }
    }
    println("Kotlin binding smoke passed: async transport, PKCE, callbacks, typed errors, cancellation")
}
