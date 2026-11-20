package me.linkmessenger.auth.demo

import android.content.Context
import android.net.Uri
import android.util.AtomicFile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.InputStream
import org.json.JSONObject

const val DEMO_CALLBACK = "me.linkmessenger.auth.demo://oauth/callback"
private const val MAX_CONFIG_BYTES = 64 * 1024

class DemoConfigException(val messageId: Int) : Exception()

/** Only public Console configuration. Protocol validation remains in the SDK. */
class DemoConfiguration private constructor(
    val json: String,
    val clientId: String,
    val issuer: String,
    val scopes: List<String>,
) {
    companion object {
        fun parse(json: String): DemoConfiguration {
            if (json.toByteArray(Charsets.UTF_8).size > MAX_CONFIG_BYTES) {
                throw DemoConfigException(R.string.config_too_large)
            }
            val value = try { JSONObject(json) } catch (_: Exception) {
                throw DemoConfigException(R.string.config_invalid)
            }
            if (value.has("client_secret") || value.has("private_key")) {
                throw DemoConfigException(R.string.config_public_only)
            }
            if (value.optString("type") != "link_oauth_client_config" || value.optString("platform") != "android") {
                throw DemoConfigException(R.string.config_android_only)
            }
            val redirects = value.optJSONArray("redirect_uris")
            if (redirects == null || (0 until redirects.length()).none { redirects.optString(it) == DEMO_CALLBACK }) {
                throw DemoConfigException(R.string.config_callback_missing)
            }
            return try {
                val scopes = value.getJSONArray("scopes")
                DemoConfiguration(json, value.getString("client_id"), value.getString("issuer"),
                    List(scopes.length()) { scopes.getString(it) })
            } catch (_: Exception) { throw DemoConfigException(R.string.config_invalid) }
        }
    }

    override fun toString() = "DemoConfiguration"
}

/** Call on IO. The imported config survives restarts and is excluded from backup. */
class DemoConfigStore(private val context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "demo-config.json"))

    fun load(): DemoConfiguration? {
        val saved = try { file.openRead() } catch (_: FileNotFoundException) { null }
        if (saved != null) return saved.use { DemoConfiguration.parse(readBounded(it)) }
        val bundled = try { context.assets.open("link-login.json") } catch (_: FileNotFoundException) { null }
        return bundled?.use { DemoConfiguration.parse(readBounded(it)) }
    }

    fun read(uri: Uri): String = context.contentResolver.openInputStream(uri)?.use(::readBounded)
        ?: throw DemoConfigException(R.string.config_unreadable)

    fun save(config: DemoConfiguration) {
        val output = file.startWrite()
        try {
            output.write(config.json.toByteArray(Charsets.UTF_8))
            output.fd.sync()
            file.finishWrite(output)
        } catch (error: Exception) { file.failWrite(output); throw error }
    }

    private fun readBounded(input: InputStream): String {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (output.size() + count > MAX_CONFIG_BYTES) throw DemoConfigException(R.string.config_too_large)
            output.write(buffer, 0, count)
        }
        return output.toString(Charsets.UTF_8.name())
    }
}
