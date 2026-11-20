package me.linkmessenger.auth.packagecheck

import android.app.Activity
import android.os.Bundle
import android.widget.TextView
import me.linkmessenger.auth.AndroidLinkOpener
import me.linkmessenger.auth.LinkAuth

/** Package/link check, not a configured OAuth sample. No backend is contacted
 * on launch. The unused entry points verify the public API and R8 integration.
 */
class PackageCheckActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = "Link Auth package check" })
    }

    suspend fun integrate(config: String, callback: String) {
        val auth = LinkAuth.create(applicationContext, config, "com.example.app://oauth/callback")
        auth.restore()
        auth.handleCallback(callback)
        auth.getSession().use { check(it.idToken.isNotEmpty()) }
        auth.getIdToken()
        auth.getUserInfo().phoneNumber
        auth.signOut()
        auth.close()
    }

    suspend fun signIn(auth: LinkAuth) {
        auth.signIn(listOf("openid", "profile", "offline_access"), AndroidLinkOpener(this)).use {
            check(it.user.subject.isNotEmpty())
        }
    }
}
