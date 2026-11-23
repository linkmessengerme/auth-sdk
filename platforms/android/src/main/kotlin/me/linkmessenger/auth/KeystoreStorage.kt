package me.linkmessenger.auth

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlin.concurrent.withLock
import me.linkmessenger.auth.generated.SecureStorage
import me.linkmessenger.auth.generated.StorageEntry
import me.linkmessenger.auth.generated.StorageFailure

/** API 23+. AES-GCM data in noBackupFilesDir; the AES key never leaves AndroidKeyStore.
 * Holds the session journal (`link.auth.v1.*`) and the record of the attested
 * key (`link.attest.v1.*`), each under its own AES key.
 */
class KeystoreStorage(context: Context) : SecureStorage {
    private val directory = File(context.applicationContext.noBackupFilesDir, "link-auth-v1")
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun load(key: String): StorageEntry? = transaction(key) { read(key) }

    override fun compareExchange(key: String, expectedRevision: String?, replacement: StorageEntry?): Boolean = transaction(key) {
        val old = read(key)
        val revision = old?.revision()
        old?.close()
        if (revision != expectedRevision) return@transaction false
        val file = AtomicFile(File(directory, "$key.bin"))
        if (replacement == null) {
            file.delete()
            check(!file.baseFile.exists() && !File(directory, "$key.bin.bak").exists())
        } else {
            val encrypted = JournalCipher.seal(secretKey(key, create = true), key, replacement)
            val stream = file.startWrite()
            try {
                stream.write(encrypted)
                stream.fd.sync() // AtomicFile otherwise only logs some sync failures.
                file.finishWrite(stream)
                val actual = file.openRead().use { readBounded(it, JournalCipher.MAX_RECORD) }
                check(actual.contentEquals(encrypted))
            } catch (error: Exception) { file.failWrite(stream); throw error }
        }
        val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
        try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
        true
    }

    private fun read(key: String): StorageEntry? {
        val file = AtomicFile(File(directory, "$key.bin"))
        if (!file.baseFile.exists() && !File(directory, "$key.bin.bak").exists()) return null
        val bytes = file.openRead().use { readBounded(it, JournalCipher.MAX_RECORD) }
        return JournalCipher.open(secretKey(key, create = false), key, bytes)
    }

    private fun secretKey(alias: String, create: Boolean): SecretKey {
        (keys.getKey(alias, null) as? SecretKey)?.let { return it }
        check(create) // Never replace a missing key while ciphertext still exists.
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }

    private fun <T> transaction(key: String, action: () -> T): T {
        try {
            require(key.matches(Regex("link\\.(auth|attest)\\.v1\\.[A-Za-z0-9_-]{43}")))
            check(directory.isDirectory || directory.mkdirs())
            val path = File(directory, "$key.lock").absolutePath
            val gate = synchronized(locks) { locks.getOrPut(path) { ReentrantLock() } }
            return gate.withLock {
                RandomAccessFile(path, "rw").use { file -> file.channel.lock().use { action() } }
            }
        } catch (_: Exception) { throw StorageFailure.Unavailable() }
    }

    companion object { private val locks = HashMap<String, ReentrantLock>() }
}
