package me.linkmessenger.auth

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import me.linkmessenger.auth.generated.StorageEntry

/** Internal binary envelope. The storage namespace is authenticated as GCM AAD. */
internal object JournalCipher {
    const val MAX_PAYLOAD = 64 * 1024
    const val MAX_RECORD = MAX_PAYLOAD + 1024

    fun seal(key: SecretKey, namespace: String, value: StorageEntry): ByteArray {
        val payload = value.payload().toByteArray(Charsets.UTF_8)
        require(payload.size <= MAX_PAYLOAD && value.revision().length == 43)
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { it.writeByte(1); it.writeUTF(value.revision()); it.writeInt(payload.size); it.write(payload) }
        val plain = buffer.toByteArray()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(namespace.toByteArray(Charsets.UTF_8))
            check(cipher.iv.size == 12)
            return byteArrayOf(1) + cipher.iv + cipher.doFinal(plain)
        } finally { payload.fill(0); plain.fill(0) }
    }

    fun open(key: SecretKey, namespace: String, value: ByteArray): StorageEntry {
        require(value.size in 30..MAX_RECORD && value[0] == 1.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, value.copyOfRange(1, 13)))
        cipher.updateAAD(namespace.toByteArray(Charsets.UTF_8))
        val plain = cipher.doFinal(value, 13, value.size - 13)
        try {
            DataInputStream(ByteArrayInputStream(plain)).use { input ->
                require(input.readUnsignedByte() == 1)
                val revision = input.readUTF()
                val length = input.readInt()
                require(revision.length == 43 && length in 0..MAX_PAYLOAD && input.available() == length)
                val payload = ByteArray(length)
                try { input.readFully(payload); return StorageEntry(revision, payload.toString(Charsets.UTF_8)) }
                finally { payload.fill(0) }
            }
        } finally { plain.fill(0) }
    }
}
