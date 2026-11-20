package me.linkmessenger.auth

import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.io.File
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import me.linkmessenger.auth.generated.*

// Test store only. AndroidKeyStore/AtomicFile need instrumented device tests;
// the production Android sources are compiled in this JVM smoke as well.
private class MemoryStorage : SecureStorage {
    private val values = mutableMapOf<String, Pair<String, String>>()
    var fail = false
    @Synchronized override fun load(key: String): StorageEntry? {
        if (fail) throw StorageFailure.Unavailable()
        return values[key]?.let { StorageEntry(it.first, it.second) }
    }
    @Synchronized override fun compareExchange(key: String, expectedRevision: String?, replacement: StorageEntry?): Boolean {
        if (fail) throw StorageFailure.Unavailable()
        if (values[key]?.first != expectedRevision) return false
        if (replacement == null) values.remove(key) else values[key] = replacement.revision() to replacement.payload()
        return true
    }
}

private suspend fun expect(expected: ErrorCode, action: suspend () -> Unit) {
    try { action(); error("expected authentication error") }
    catch (e: AuthException.Failure) { check(e.code == expected) { "Unexpected auth error: ${e.code}" } }
}

private fun callback(request: AuthorizationRequest, issuer: String): String {
    val params = URI(request.authorizationUrl()).rawQuery.split('&').associate {
        val pair = it.split('=', limit = 2)
        URLDecoder.decode(pair[0], "UTF-8") to URLDecoder.decode(pair[1], "UTF-8")
    }
    val data = """{"Nonce":"${params.getValue("nonce")}","Challenge":"${params.getValue("code_challenge")}"}"""
    val code = Base64.getUrlEncoder().withoutPadding().encodeToString(data.toByteArray())
    val query = mapOf("code" to code, "state" to params.getValue("state"), "iss" to issuer)
    return params.getValue("redirect_uri") + "?" + query.entries.joinToString("&") { "${it.key}=${URLEncoder.encode(it.value, "UTF-8")}" }
}

fun main(args: Array<String>) = runBlocking {
    val base = args[0]
    val template = File("bindings/fixtures/console-config.json").readText().replace("\"ios\"", "\"android\"")
    val store = MemoryStorage()
    fun client(path: String, transport: OkHttpTransport) = LinkSessionClient(
        template.replace("https://login.example.test", base + path), "com.example.app://oauth/callback", transport, store)
    OkHttpTransport().use { transport ->
        client("/kotlin", transport).use { first ->
            check(first.restore() == SessionStatus.SignedOut)
            first.beginSignIn(listOf("openid", "profile", "offline_access")).use { pending ->
                client("/kotlin", transport).use { restarted ->
                    check(restarted.restore() is SessionStatus.PendingLogin)
                    restarted.completeSignIn(callback(pending, "$base/kotlin")).use { signedIn ->
                        check(signedIn.user().subject == "native-test-sub")
                        client("/kotlin", transport).use { resumed ->
                            check((resumed.restore() as SessionStatus.SignedIn).canRefresh)
                            resumed.validSession().use { check(it.accessToken() == signedIn.accessToken()) }
                            resumed.refresh().use {
                                check(it.refreshToken() != signedIn.refreshToken())
                                check(it.user().subject == signedIn.user().subject)
                            }
                            check(resumed.logout() == LogoutStatus.REVOKED)
                            check(resumed.restore() == SessionStatus.SignedOut)
                            store.fail = true
                            expect(ErrorCode.Storage) { resumed.restore() }
                            store.fail = false
                        }
                    }
                }
            }
        }
        for (variant in listOf("drop", "retry")) {
            val path = "/kotlin/$variant"
            client(path, transport).use { broken ->
                broken.beginSignIn(listOf("openid", "profile", "offline_access")).use { request ->
                    broken.completeSignIn(callback(request, base + path)).close()
                }
                expect(if (variant == "drop") ErrorCode.Transport else ErrorCode.Http(503u.toUShort())) { broken.refresh() }
                client(path, transport).use { check(it.restore() == SessionStatus.ReauthenticationRequired) }
                expect(ErrorCode.ReauthenticationRequired) { broken.validSession() }
                check(broken.logout() == LogoutStatus.REVOKED)
            }
        }
        client("/kotlin/redirect", transport).use { broken ->
            expect(ErrorCode.Http(302u.toUShort())) { broken.beginSignIn(listOf("openid")) }
        }
        client("/kotlin/oversize", transport).use { broken ->
            expect(ErrorCode.Transport) { broken.beginSignIn(listOf("openid")) }
        }
        OkHttpTransport(maximumTimeoutMillis = 200).use { impatient ->
            client("/kotlin/slow", impatient).use { slow ->
                val start = System.nanoTime()
                expect(ErrorCode.Transport) { slow.beginSignIn(listOf("openid")) }
                check(System.nanoTime() - start < 2_000_000_000)
            }
        }
        client("/kotlin/cancel/slow", transport).use { cancelling ->
            val operation = async { runCatching { cancelling.beginSignIn(listOf("openid")) } }
            val waitStart = System.nanoTime()
            while (!URL("$base/stats").readText().contains("/kotlin/cancel/slow/.well-known/openid-configuration")) {
                check(System.nanoTime() - waitStart < 2_000_000_000) { "request did not reach fixture" }
                delay(20)
            }
            val cancelStart = System.nanoTime()
            cancelling.cancelSignIn(); transport.cancelRequests()
            expect(ErrorCode.Cancelled) { operation.await().getOrThrow() }
            check(System.nanoTime() - cancelStart < 1_000_000_000)
            check(cancelling.restore() == SessionStatus.SignedOut)
        }
        client("/kotlin", transport).use { reused ->
            reused.beginSignIn(listOf("openid")).close()
            reused.cancelSignIn()
        }
    }

    // Same AES-GCM envelope used with the AndroidKeyStore key: roundtrip,
    // fresh nonce, authenticated namespace, corruption and wrong-key rejection.
    val aes = SecretKeySpec(ByteArray(32) { 42 }, "AES")
    StorageEntry("A".repeat(43), "secret-test-payload").use { value ->
        val encrypted = JournalCipher.seal(aes, "namespace", value)
        check(!encrypted.contentEquals(JournalCipher.seal(aes, "namespace", value)))
        JournalCipher.open(aes, "namespace", encrypted).use { check(it.payload() == value.payload() && it.revision() == value.revision()) }
        check(runCatching { JournalCipher.open(aes, "other", encrypted) }.isFailure)
        check(runCatching { JournalCipher.open(SecretKeySpec(ByteArray(32), "AES"), "namespace", encrypted) }.isFailure)
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()
        check(runCatching { JournalCipher.open(aes, "namespace", encrypted) }.isFailure)
    }
    val stats = URL("$base/stats").readText()
    val counts = Regex("\"([^\"]+)\":(\\d+)").findAll(stats).associate { it.groupValues[1] to it.groupValues[2].toInt() }
    check(counts["/followed"] == null)
    for (path in listOf("/kotlin", "/kotlin/drop", "/kotlin/retry")) {
        check(counts["$path/oauth/v1/token/authorization_code"] == 1)
        check(counts["$path/oauth/v1/token/refresh_token"] == 1) { "Native POST was retried" }
        check(counts["$path/oauth/v1/revoke"] == 1)
    }
    println("Kotlin native smoke passed: PKCE/JWT, restore, refresh, revoke, AES-GCM integrity, storage failures, no POST retries/redirects, limits, cancellation")
}
