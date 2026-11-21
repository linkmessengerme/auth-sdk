package me.linkmessenger.auth

import android.annotation.TargetApi
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import me.linkmessenger.auth.generated.AttestationFailure
import me.linkmessenger.auth.generated.AttestedKey
import me.linkmessenger.auth.generated.DeviceAttestor
import me.linkmessenger.auth.generated.KeyAttestation

/** Android Key Attestation, API 24+. The key is EC P-256 in AndroidKeyStore,
 * sign-only with SHA-256, and its certificate chain carries the server's
 * challenge. StrongBox is tried first, then the TEE. No device identifiers and
 * no user confirmation are requested. Every failure means "no key": the
 * sign-in goes on and the server decides.
 */
internal class KeystoreAttestor(context: Context) : DeviceAttestor {
    private val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    private val keys: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    // Key generation cannot be interrupted; a late result is cleaned up here.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun isAvailable(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N

    override suspend fun createKey(name: String, challenge: ByteArray, timeoutMillis: UInt): AttestedKey = guarded {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N || challenge.size != 32 || !NAMESPACE.matches(name)) {
            throw AttestationFailure.Unavailable()
        }
        val suffix = ByteArray(8).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val alias = "$name.k.$suffix"
        val generation = scope.async { generate(alias, challenge) }
        val chain = withTimeoutOrNull(timeoutMillis.toLong()) { generation.await() }
        if (chain == null) {
            generation.invokeOnCompletion { delete(alias) }
            throw AttestationFailure.Unavailable()
        }
        AttestedKey(alias, KeyAttestation.Android(chain))
    }

    @TargetApi(Build.VERSION_CODES.N)
    private fun generate(alias: String, challenge: ByteArray): List<ByteArray> {
        var failure: Exception? = null
        for (inStrongBox in if (strongBox) listOf(true, false) else listOf(false)) {
            try {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                if (inStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(true)
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                    .apply { initialize(spec.build()) }.generateKeyPair()
                val chain = keys.getCertificateChain(alias)?.map { it.encoded }
                // The server accepts at most eight certificates, the key's own first.
                check(chain != null && chain.size in 1..8)
                return chain
            } catch (error: Exception) {
                // StrongBox missing, busy or unable to attest: the TEE is next.
                delete(alias)
                failure = error
            }
        }
        throw failure ?: IllegalStateException()
    }

    override suspend fun sign(keyRef: String, message: ByteArray): ByteArray = guarded {
        if (!ALIAS.matches(keyRef)) throw AttestationFailure.KeyLost()
        withContext(Dispatchers.IO) {
            if (!keys.containsAlias(keyRef)) throw AttestationFailure.KeyLost()
            val key = keys.getKey(keyRef, null) as? PrivateKey ?: throw AttestationFailure.Unavailable()
            try {
                Signature.getInstance("SHA256withECDSA").run { initSign(key); update(message); sign() }
            } catch (_: KeyPermanentlyInvalidatedException) {
                throw AttestationFailure.KeyLost()
            }
        }
    }

    override suspend fun deleteKey(keyRef: String) {
        if (ALIAS.matches(keyRef)) withContext(Dispatchers.IO) { delete(keyRef) }
    }

    private fun delete(alias: String) {
        try { keys.deleteEntry(alias) } catch (_: Exception) {}
    }

    private suspend fun <T> guarded(action: suspend () -> T): T =
        try { action() }
        catch (error: AttestationFailure) { throw error }
        catch (error: CancellationException) { throw error }
        catch (_: Exception) { throw AttestationFailure.Unavailable() }

    private companion object {
        // The SDK's own aliases only: a stored reference never selects another key of the app.
        val NAMESPACE = Regex("link\\.attest\\.v1\\.[A-Za-z0-9_-]{43}")
        val ALIAS = Regex("link\\.attest\\.v1\\.[A-Za-z0-9_-]{43}\\.k\\.[0-9a-f]{16}")
    }
}
