package me.linkmessenger.auth

import java.io.File
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import kotlinx.coroutines.runBlocking
import me.linkmessenger.auth.generated.*

// Device attestation end to end: Kotlin -> UniFFI -> Rust -> OkHttp -> the Go
// fixture, which checks every proof with its own implementation of the signed
// string. The key is a software P-256 key signing SHA256withECDSA in DER, the
// algorithm of the Android adapter; AndroidKeyStore itself needs a device.
private class SoftAttestor : DeviceAttestor {
    private val lock = Any()
    private val keys = mutableMapOf<String, KeyPair>()
    private var createdCount = 0
    private var deletedCount = 0
    @Volatile var supported = true
    val created: Int get() = synchronized(lock) { createdCount }
    val deleted: Int get() = synchronized(lock) { deletedCount }
    val alive: Int get() = synchronized(lock) { keys.size }

    override fun isAvailable(): Boolean = supported
    override suspend fun createKey(name: String, challenge: ByteArray, timeoutMillis: UInt): AttestedKey {
        check(name.startsWith("link.attest.v1.") && challenge.size == 32 && timeoutMillis <= 10_000u)
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val reference = "$name.k.${UUID.randomUUID()}"
        synchronized(lock) { keys[reference] = pair; createdCount++ }
        // What the fixture accepts in place of a certificate chain.
        return AttestedKey(reference, KeyAttestation.Android(listOf(pair.public.encoded, challenge)))
    }
    override suspend fun sign(keyRef: String, message: ByteArray): ByteArray {
        val pair = synchronized(lock) { keys[keyRef] } ?: throw AttestationFailure.KeyLost()
        return Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(message); sign() }
    }
    override suspend fun deleteKey(keyRef: String) { synchronized(lock) { keys.remove(keyRef); deletedCount++ } }
}

private class AttestStore : SecureStorage {
    private val values = mutableMapOf<String, Pair<String, String>>()
    @Synchronized fun records(prefix: String) = values.keys.count { it.startsWith(prefix) }
    @Synchronized override fun load(key: String): StorageEntry? = values[key]?.let { StorageEntry(it.first, it.second) }
    @Synchronized override fun compareExchange(key: String, expectedRevision: String?, replacement: StorageEntry?): Boolean {
        check(Regex("link\\.(auth|attest)\\.v1\\.[A-Za-z0-9_-]{43}").matches(key))
        if (values[key]?.first != expectedRevision) return false
        if (replacement == null) values.remove(key) else values[key] = replacement.revision() to replacement.payload()
        return true
    }
}

private suspend fun expectCode(expected: ErrorCode, action: suspend () -> Unit) {
    try { action(); error("expected $expected") }
    catch (e: AuthException.Failure) { check(e.code == expected) { "Unexpected auth error: ${e.code}, expected $expected" } }
}

private fun attestCallback(request: AuthorizationRequest, issuer: String): String {
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
    val store = AttestStore()
    val scopes = listOf("openid", "profile", "offline_access")
    fun control(path: String) { URL(base + path).readText() }
    fun arm(prefix: String, fault: String, times: Int = 1) = control("/arm?prefix=$prefix&fault=$fault&times=$times")
    fun stats(): Map<String, Int> = Regex("\"([^\"]+)\":(\\d+)").findAll(URL("$base/stats").readText())
        .associate { it.groupValues[1] to it.groupValues[2].toInt() }
    OkHttpTransport().use { transport ->
        // attestor == null is the application's `attestation = false`.
        fun client(path: String, attestor: SoftAttestor?): LinkSessionClient {
            val config = template.replace("https://login.example.test", base + path)
            return if (attestor == null) LinkSessionClient(config, "com.example.app://oauth/callback", transport, store)
            else LinkSessionClient.withAttestation(config, "com.example.app://oauth/callback", transport, store, attestor)
        }
        suspend fun signIn(sdk: LinkSessionClient, path: String): String? =
            sdk.beginSignIn(scopes).use { request ->
                sdk.completeSignIn(attestCallback(request, base + path)).use { it.user().deviceTrust }
            }
        suspend fun refresh(sdk: LinkSessionClient): String? = sdk.refresh().use { it.user().deviceTrust }

        // 1. "Report" mode: the key is registered before Link is opened and
        //    signs the code exchange and every refresh.
        var path = "/kotlin/attest-report"
        var attestor = SoftAttestor()
        var sdk = client(path, attestor)
        sdk.beginSignIn(scopes).use { request ->
            val counts = stats()
            check(counts["$path/oauth/v1/attest/challenge"] == 1 && counts["$path/oauth/v1/attest/keys"] == 1)
            check(counts["$path/oauth/v1/token"] == null)
            // The fixture verified the proof: only then is the session "verified".
            sdk.completeSignIn(attestCallback(request, base + path)).use { check(it.user().deviceTrust == "verified") }
        }
        check(store.records("link.auth.v1.") == 1 && store.records("link.attest.v1.") == 1)
        check(refresh(sdk) == "verified")

        // 2. The answer to a refresh is lost: the session survives a restart and
        //    the same token is sent again under the next attempt number.
        arm(path, "refresh-lose")
        val before = sdk.validSession().use { it.accessToken() }
        expectCode(ErrorCode.Transport) { sdk.refresh().close() }
        sdk.close(); sdk = client(path, attestor)
        check((sdk.restore() as SessionStatus.SignedIn).canRefresh)
        sdk.validSession().use { check(it.accessToken() != before && it.user().deviceTrust == "verified") }
        arm(path, "refresh-503")
        expectCode(ErrorCode.Http(503u)) { sdk.refresh().close() }
        refresh(sdk)
        arm(path, "refresh-429")
        expectCode(ErrorCode.OAuth("temporarily_unavailable")) { sdk.refresh().close() }
        refresh(sdk)
        // A refused signature is made once more.
        arm(path, "proof-invalid")
        refresh(sdk)
        // 1 plain + 2 (lost, repeated) + 2 (503) + 2 (429) + 2 (proof refused once)
        check(stats()["$path/oauth/v1/token/refresh_token"] == 9)

        // 3. The key outlives sign-out and is not registered again.
        check(sdk.logout() == LogoutStatus.REVOKED)
        check(store.records("link.auth.v1.") == 0 && store.records("link.attest.v1.") == 1)
        check(signIn(sdk, path) == "verified")
        check(stats()["$path/oauth/v1/attest/keys"] == 1 && attestor.created == 1 && attestor.deleted == 0)

        // 4. Refusals that end the session.
        arm(path, "proof-invalid", 2)
        expectCode(ErrorCode.OAuth("invalid_client")) { sdk.refresh().close() }
        client(path, attestor).use { check(it.restore() == SessionStatus.ReauthenticationRequired) }
        check(sdk.logout() == LogoutStatus.REVOKED)
        signIn(sdk, path)
        arm(path, "retry-refused")
        expectCode(ErrorCode.OAuth("invalid_grant")) { sdk.refresh().close() }
        expectCode(ErrorCode.ReauthenticationRequired) { sdk.validSession().close() }
        check(sdk.logout() == LogoutStatus.REVOKED)
        sdk.close()

        // 5. The answer to the key upload is lost: a new key with a new challenge.
        path = "/kotlin/attest-report/lost-upload"; attestor = SoftAttestor(); sdk = client(path, attestor)
        arm(path, "keys-lose")
        check(signIn(sdk, path) == "verified")
        check(stats()["$path/oauth/v1/attest/keys"] == 2 && attestor.created == 2 && attestor.deleted == 1 && attestor.alive == 1)
        sdk.close()

        // 6. Registration that fails does not fail the sign-in.
        path = "/kotlin/attest-report/refused-upload"; attestor = SoftAttestor(); sdk = client(path, attestor)
        arm(path, "keys-400")
        check(signIn(sdk, path) == "none" && attestor.alive == 0)
        refresh(sdk)
        sdk.close()

        // 7. Mode "off": no key is created.
        path = "/kotlin/attest-off"; attestor = SoftAttestor(); sdk = client(path, attestor)
        check(signIn(sdk, path) == null && attestor.created == 0)
        sdk.close()

        // 8. "Required": a sign-in without a key is refused before the code is
        //    spent, the SDK registers a key and repeats the exchange.
        path = "/kotlin/attest-required"; attestor = SoftAttestor(); sdk = client(path, attestor)
        arm(path, "challenge-503")
        check(signIn(sdk, path) == "verified")
        stats().let { check(it["$path/oauth/v1/token/authorization_code"] == 2 && it["$path/oauth/v1/attest/challenge"] == 2) }
        // A key the server no longer knows is replaced within the same sign-in.
        check(sdk.logout() == LogoutStatus.REVOKED)
        control("/act?prefix=$path&do=forget-keys")
        check(signIn(sdk, path) == "verified" && attestor.created == 2 && attestor.deleted == 1)
        // A revoked key is deleted; the person signs in again with a new one.
        check(sdk.logout() == LogoutStatus.REVOKED)
        control("/act?prefix=$path&do=revoke-keys")
        expectCode(ErrorCode.ReauthenticationRequired) { signIn(sdk, path) }
        check(sdk.restore() == SessionStatus.SignedOut && attestor.alive == 0)
        check(signIn(sdk, path) == "verified" && attestor.created == 3)
        // A session bound to a key that the server then revokes cannot be refreshed.
        control("/act?prefix=$path&do=revoke-keys")
        expectCode(ErrorCode.OAuth("invalid_client")) { sdk.refresh().close() }
        check(sdk.restore() == SessionStatus.ReauthenticationRequired && attestor.alive == 0)
        check(sdk.logout() == LogoutStatus.REVOKED)
        sdk.close()

        // 9. "Required" and no key possible: a typed error, nothing stored.
        path = "/kotlin/attest-required/no-hardware"; attestor = SoftAttestor(); attestor.supported = false
        sdk = client(path, attestor)
        expectCode(ErrorCode.AttestationRequired) { signIn(sdk, path) }
        check(sdk.restore() == SessionStatus.SignedOut)
        sdk.close()
        path = "/kotlin/attest-required/sdk-off"; sdk = client(path, null)
        expectCode(ErrorCode.AttestationRequired) { signIn(sdk, path) }
        sdk.close()

        // 10. A server that does not advertise attestation: the SDK behaves as
        //     0.1.0 even with an attestor, including the lost-answer case.
        path = "/kotlin/plain/drop"; attestor = SoftAttestor(); sdk = client(path, attestor)
        check(signIn(sdk, path) == null && attestor.created == 0)
        expectCode(ErrorCode.Transport) { sdk.refresh().close() }
        client(path, attestor).use { check(it.restore() == SessionStatus.ReauthenticationRequired) }
        stats().let { check(it["$path/oauth/v1/attest/challenge"] == null && it["$path/oauth/v1/token/refresh_token"] == 1) }
        check(sdk.logout() == LogoutStatus.REVOKED)
        sdk.close()
    }
    println("Kotlin attestation smoke passed: key registration, signed exchange and refresh, repeat after a lost answer, 503/429, re-signed proof, key reuse after sign-out, lost and refused key upload, modes off/report/required, key_unknown, key_revoked, retry_refused, AttestationRequired, unchanged behaviour without link_attestation")
}
