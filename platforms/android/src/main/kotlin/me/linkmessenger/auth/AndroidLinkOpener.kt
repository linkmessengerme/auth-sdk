package me.linkmessenger.auth

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import java.lang.ref.WeakReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Lets Android route the HTTPS App Link to Link, or its V1 install/open page
 * when no associated app handles it. No WebView, package pin or chooser bypass.
 * Only a weak Activity reference is retained while discovery is in progress.
 */
class AndroidLinkOpener(activity: Activity) : LinkAuthorizationOpener {
    private val activity = WeakReference(activity)
    override suspend fun open(url: String): Boolean = withContext(Dispatchers.Main.immediate) {
        val current = activity.get() ?: return@withContext false
        if (current.isFinishing || current.isDestroyed) return@withContext false
        val uri = Uri.parse(url)
        if (uri.scheme != "https" && uri.scheme != "http") return@withContext false
        try {
            current.startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
            true
        } catch (_: ActivityNotFoundException) { false }
        catch (_: SecurityException) { false }
    }
}
