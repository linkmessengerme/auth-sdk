package me.linkmessenger.auth

import java.io.File
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.Base64
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import me.linkmessenger.auth.generated.*

private class FacadeStore : SecureStorage {
    private val entries = mutableMapOf<String, Pair<String, String>>()
    @Synchronized override fun load(key: String): StorageEntry? {
        check(Thread.currentThread().name != "main")
        return entries[key]?.let { StorageEntry(it.first, it.second) }
    }
    @Synchronized override fun compareExchange(key: String, expectedRevision: String?, replacement: StorageEntry?): Boolean {
        check(Thread.currentThread().name != "main")
        if (entries[key]?.first != expectedRevision) return false
        if (replacement == null) entries.remove(key) else entries[key] = replacement.revision() to replacement.payload()
        return true
    }
}
private class Opener : LinkAuthorizationOpener {
    private val urls = Channel<String>(Channel.UNLIMITED)
    @Volatile var accepts = true
    override suspend fun open(url: String): Boolean {
        check(url.substringBefore('?') == "https://linkm.me/oauth/authorize")
        urls.send(url)
        return accepts
    }
    suspend fun next(): String = withTimeout(3_000) { urls.receive() }
}
private suspend fun expect(code: ErrorCode, action: suspend () -> Unit) {
    try { action(); error("expected protocol failure") }
    catch (e: LinkAuthException.Protocol) { check(e.code == code) }
}
private suspend fun restored(auth: LinkAuth, step: String): SessionStatus = try { auth.restore() }
catch (e: Exception) { throw AssertionError("restore after $step", e) }
private fun callback(url: String, issuer: String, denied: Boolean = false, wrongState: Boolean = false): String {
    val params = URI(url).rawQuery.split('&').associate {
        val pair = it.split('=', limit = 2)
        URLDecoder.decode(pair[0], "UTF-8") to URLDecoder.decode(pair[1], "UTF-8")
    }
    val data = """{"Nonce":"${params.getValue("nonce")}","Challenge":"${params.getValue("code_challenge")}"}"""
    val code = Base64.getUrlEncoder().withoutPadding().encodeToString(data.toByteArray())
    val query = mapOf((if (denied) "error" else "code") to (if (denied) "access_denied" else code),
        "state" to (if (wrongState) "bad-state" else params.getValue("state")), "iss" to issuer)
    return params.getValue("redirect_uri") + "?" + query.entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
}

fun main(args: Array<String>) = runBlocking {
    supervisorScope {
        val base = args[0]
        val template = File("bindings/fixtures/console-config.json").readText().replace("\"ios\"", "\"android\"")
        val store = FacadeStore()
        val scopes = listOf("openid", "profile", "offline_access")
        suspend fun make(path: String, timeout: Long = 600_000) = withContext(Dispatchers.IO) {
            val transport = OkHttpTransport()
            LinkAuth(LinkSessionClient(template.replace("https://login.example.test", base + path),
                "com.example.app://oauth/callback", transport, store), transport, signInTimeoutMillis = timeout)
        }
        val opener = Opener(); val path = "/facade/kotlin"
        val auth = make(path)
        check(restored(auth, "creation") == SessionStatus.SignedOut)
        val backendNonce = "n".repeat(64)
        val signingIn = async { auth.signIn(scopes, opener, nonce = backendNonce) }
        val url = opener.next()
        check(url.contains("nonce=$backendNonce"))
        expect(ErrorCode.AlreadyInProgress) { auth.signIn(scopes, opener) }
        check(auth.handleCallback("https://unrelated.example.test/page") == null)
        expect(ErrorCode.StateMismatch) { auth.handleCallback(callback(url, base + path, wrongState = true)) }
        val user = auth.handleCallback(callback(url, base + path))
        signingIn.await().use { session ->
            check(user?.subject == session.user.subject)
            check(auth.getIdToken() == session.idToken)
            val info = auth.getUserInfo()
            check(info.subject == session.user.subject && info.name == "Fresh Native Name")
            check(info.phoneNumber == null && info.phoneNumberVerified == null)
        }
        check(auth.handleCallback(callback(url, base + path)) == null)
        auth.close()
        try { auth.getIdToken(); error("closed SDK was used") } catch (_: LinkAuthException.Closed) {}
        try { auth.getUserInfo(); error("closed SDK returned user info") } catch (_: LinkAuthException.Closed) {}
        val resumed = make(path)
        check(restored(resumed, "disposal/recreation") is SessionStatus.SignedIn)
        check(resumed.signOut() == LogoutStatus.REVOKED)
        expect(ErrorCode.ReauthenticationRequired) { resumed.getUserInfo() }

        val phonePath = "/facade/kotlin/phone"; val phone = make(phonePath)
        val phoneLogin = async { phone.signIn(scopes + "phone", opener) }
        val phoneURL = opener.next()
        phone.handleCallback(callback(phoneURL, base + phonePath))
        phoneLogin.await().close()
        val phoneInfo = phone.getUserInfo()
        check(phoneInfo.phoneNumber == "+12025550123" && phoneInfo.phoneNumberVerified == null)
        check(phone.signOut() == LogoutStatus.REVOKED); phone.close()
        val denied = async { resumed.signIn(scopes, opener) }
        val deniedURL = opener.next()
        expect(ErrorCode.AuthorizationDenied) { resumed.handleCallback(callback(deniedURL, base + path, denied = true)) }
        expect(ErrorCode.AuthorizationDenied) { denied.await() }
        check(restored(resumed, "denial") == SessionStatus.SignedOut)

        val cancelled = async { resumed.signIn(scopes, opener) }
        opener.next(); cancelled.cancelAndJoin()
        check(restored(resumed, "coroutine cancellation") == SessionStatus.SignedOut)
        opener.accepts = false
        try { resumed.signIn(scopes, opener); error("unhandled URL succeeded") } catch (_: LinkAuthException.CannotOpenLink) {}
        opener.next()
        check(restored(resumed, "launch failure") == SessionStatus.SignedOut)
        opener.accepts = true
        val timeout = make("/facade/kotlin/timeout", 100)
        expect(ErrorCode.Expired) { timeout.signIn(scopes, opener) }
        opener.next(); check(restored(timeout, "timeout") == SessionStatus.SignedOut); timeout.close()

        val coldPath = "/facade/kotlin/cold"
        val pendingURL = withContext(Dispatchers.IO) {
            OkHttpTransport().use { transport ->
                LinkSessionClient(template.replace("https://login.example.test", base + coldPath),
                    "com.example.app://oauth/callback", transport, store).use { core ->
                    core.beginSignIn(scopes).use { it.authorizationUrl() }
                }
            }
        }
        val cold = make(coldPath)
        check(cold.restore() is SessionStatus.PendingLogin)
        check(cold.handleCallback(callback(pendingURL, base + coldPath))?.subject == "native-test-sub")
        check(cold.getIdToken().contains('.'))
        check(cold.signOut() == LogoutStatus.REVOKED); cold.close()

        val refreshPath = "/facade/kotlin/slow-refresh"; val refresh = make(refreshPath)
        val login = async { refresh.signIn(scopes, opener) }
        val refreshURL = opener.next()
        refresh.handleCallback(callback(refreshURL, base + refreshPath))
        val oldAccess = login.await().use { it.accessToken }
        val first = async { refresh.getSession(forceRefresh = true) }
        val second = async { refresh.getSession(forceRefresh = true) }
        delay(100); first.cancelAndJoin()
        second.await().use { check(it.accessToken != oldAccess) }
        val stats = URL("$base/stats").readText()
        val counts = Regex("\"([^\"]+)\":(\\d+)").findAll(stats).associate { it.groupValues[1] to it.groupValues[2].toInt() }
        check(counts["$refreshPath/oauth/v1/token/refresh_token"] == 1)
        val interruptedRefresh = async { refresh.getSession(forceRefresh = true) }
        delay(100)
        check(refresh.signOut() == LogoutStatus.REVOKED)
        try { interruptedRefresh.await().use { error("refresh survived logout") } }
        catch (e: LinkAuthException.Protocol) { check(e.code == ErrorCode.Transport || e.code == ErrorCode.Cancelled) }
        check(refresh.restore() == SessionStatus.SignedOut)
        refresh.close()

        val pendingLogout = async { resumed.signIn(scopes, opener) }
        opener.next(); check(resumed.signOut() == LogoutStatus.LOCAL_ONLY)
        expect(ErrorCode.Cancelled) { pendingLogout.await() }
        val pendingClose = async { resumed.signIn(scopes, opener) }
        opener.next(); resumed.close()
        try { pendingClose.await(); error("closed login succeeded") } catch (_: LinkAuthException.Closed) {}
        // A canonical issuer need not be the address used for any HTTP request.
        val regional = withContext(Dispatchers.IO) {
            val config = template.replace("\"token_url\": \"https://login.example.test",
                "\"api_base_url\": \"$base\", \"token_url\": \"$base")
            val transport = OkHttpTransport()
            LinkAuth(LinkSessionClient(config, "com.example.app://oauth/callback", transport, store), transport)
        }
        val regionalLogin = async { regional.signIn(scopes, opener) }
        val regionalURL = opener.next()
        check(regional.handleCallback(callback(regionalURL, "https://login.example.test"))?.issuer == "https://login.example.test")
        regionalLogin.await().close()
        regional.getSession(forceRefresh = true).use { check(it.user.issuer == "https://login.example.test") }
        check(regional.signOut() == LogoutStatus.REVOKED)
        regional.close()
        println("Kotlin facade smoke passed: regional API/shared issuer, signIn/callback, invalid and duplicate links, cold restore, denial, coroutine cancellation, launch failure, timeout, shared refresh, logout during refresh, disposal, storage off main thread")
    }
}
