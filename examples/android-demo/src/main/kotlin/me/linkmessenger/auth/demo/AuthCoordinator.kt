package me.linkmessenger.auth.demo

import android.content.Context
import android.net.Uri
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import me.linkmessenger.auth.LinkAuth
import me.linkmessenger.auth.LinkAuthException
import me.linkmessenger.auth.LinkAuthorizationOpener
import me.linkmessenger.auth.generated.ErrorCode
import me.linkmessenger.auth.generated.LogoutStatus
import me.linkmessenger.auth.generated.SessionStatus
import me.linkmessenger.auth.generated.UserIdentity

data class DemoSession(val user: UserIdentity, val expiresAt: ULong, val canRefresh: Boolean)

data class DemoState(
    val config: DemoConfiguration? = null,
    val session: DemoSession? = null,
    val busy: Boolean = true,
    val pending: Boolean = false,
    val revocationPending: Boolean = false,
    val recoveryRequired: Boolean = false,
    val message: String = "",
    val error: Boolean = false,
    val events: List<String> = emptyList(),
) {
    val canConfigure: Boolean get() = !busy && !pending && session == null && !revocationPending && !recoveryRequired
    val canSignIn: Boolean get() = !busy && config != null && !pending && session == null && !revocationPending
}

/** All UI state is main-thread owned. Only short SDK operations use the mutex;
 * signIn waits outside it so a callback or explicit cancellation can complete it.
 * Activity lifecycle cancels UI observation, never this application's login job.
 */
class AuthCoordinator(private val context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val operations = Mutex()
    private val store = DemoConfigStore(context)
    private val mutableState = MutableStateFlow(DemoState(message = text(R.string.starting)))
    val state = mutableState.asStateFlow()
    private var auth: LinkAuth? = null
    private var loginJob: Job? = null
    private var pendingExpiry: Job? = null
    private var generation = 0L
    private var processingCallback = false

    private val ready = scope.async {
        try {
            val config = withContext(Dispatchers.IO) { store.load() }
            if (config == null) {
                notice(text(R.string.needs_config))
            } else {
                auth = LinkAuth.create(context, config.json, DEMO_CALLBACK)
                mutableState.value = state.value.copy(config = config)
                applyStatus(auth!!.restore())
                notice(text(R.string.restored))
            }
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            notice(safeMessage(error), error = true)
        } finally { mutableState.value = state.value.copy(busy = false) }
    }

    fun importFile(uri: Uri) = configure { withContext(Dispatchers.IO) { store.read(uri) } }
    fun importJson(json: String) = configure { json }

    private fun configure(read: suspend () -> String) {
        if (!state.value.canConfigure) return
        action {
            val config = withContext(Dispatchers.IO) { DemoConfiguration.parse(read()) }
            val candidate = LinkAuth.create(context, config.json, DEMO_CALLBACK)
            try {
                val restored = candidate.restore()
                withContext(Dispatchers.IO) { store.save(config) }
                auth?.close()
                auth = candidate
                generation++
                mutableState.value = state.value.copy(config = config)
                applyStatus(restored)
                notice(text(R.string.config_loaded))
            } catch (error: Exception) { candidate.close(); throw error }
        }
    }

    fun signIn(opener: LinkAuthorizationOpener) {
        if (!state.value.canSignIn) return
        val client = auth ?: return
        val config = state.value.config ?: return
        val ticket = ++generation
        mutableState.value = state.value.copy(pending = true, recoveryRequired = false)
        notice(text(R.string.waiting_for_link))
        loginJob = scope.launch {
            try {
                // handleCallback publishes the session after the SDK finishes its
                // callback operation. The waiter only releases its native result.
                client.signIn(config.scopes, opener).use { }
            } catch (error: Exception) {
                if (error is CancellationException) throw error
                if (generation == ticket && !processingCallback) {
                    operations.withLock {
                        if (generation == ticket) {
                            restoreAfterOperation(client)
                            notice(safeMessage(error), error = true)
                        }
                    }
                }
            } finally { if (generation == ticket) loginJob = null }
        }
    }

    fun handleCallback(url: String) {
        // Route only this demo's callback. The SDK validates the complete URI,
        // duplicate query parameters, state, issuer, PKCE and signed tokens.
        val uri = Uri.parse(url)
        if (uri.scheme != BuildConfig.APPLICATION_ID || uri.host != "oauth" || uri.path != "/callback") return
        if (url.length > 16 * 1024) return
        scope.launch {
            ready.await()
            operations.withLock {
                val client = auth
                if (client == null) {
                    notice(text(R.string.callback_without_config), error = true)
                    return@withLock
                }
                processingCallback = true
                mutableState.value = state.value.copy(busy = true)
                try {
                    if (client.handleCallback(url) != null) {
                        applyStatus(client.restore())
                        notice(text(R.string.sign_in_complete))
                    }
                } catch (error: Exception) {
                    if (error is CancellationException) throw error
                    // Invalid callbacks must not cancel a legitimate pending login.
                    val code = (error as? LinkAuthException.Protocol)?.code
                    if (code != ErrorCode.InvalidCallback && code != ErrorCode.StateMismatch && code != ErrorCode.IssuerMismatch) {
                        restoreAfterOperation(client)
                    }
                    notice(safeMessage(error), error = true)
                } finally {
                    processingCallback = false
                    mutableState.value = state.value.copy(busy = false)
                }
            }
        }
    }

    fun cancelSignIn() {
        if (state.value.busy || !state.value.pending) return
        action { cancelPending(R.string.sign_in_cancelled) }
    }

    fun checkSession(forceRefresh: Boolean) {
        if (state.value.busy || state.value.session == null) return
        action {
            val client = auth ?: return@action
            try {
                client.getSession(forceRefresh).use { /* Do not print or persist tokens in the demo. */ }
                applyStatus(client.restore())
                notice(text(if (forceRefresh) R.string.session_refreshed else R.string.session_checked))
            } catch (error: Exception) {
                if (error is CancellationException) throw error
                restoreAfterOperation(client)
                throw error
            }
        }
    }

    fun signOut() {
        if (state.value.busy || state.value.pending) return
        action {
            val client = auth ?: return@action
            generation++
            pendingExpiry?.cancel()
            mutableState.value = state.value.copy(session = null, recoveryRequired = false, revocationPending = true)
            val result = client.signOut()
            mutableState.value = state.value.copy(revocationPending = result == LogoutStatus.REVOCATION_PENDING)
            notice(text(if (result == LogoutStatus.REVOCATION_PENDING) R.string.revoke_pending else R.string.signed_out))
        }
    }

    private fun action(block: suspend () -> Unit) {
        if (state.value.busy) return
        mutableState.value = state.value.copy(busy = true)
        scope.launch {
            ready.await()
            operations.withLock {
                try { block() }
                catch (error: Exception) {
                    if (error is CancellationException) throw error
                    notice(safeMessage(error), error = true)
                } finally { mutableState.value = state.value.copy(busy = false) }
            }
        }
    }

    private suspend fun cancelPending(message: Int) {
        generation++
        pendingExpiry?.cancel()
        pendingExpiry = null
        auth?.cancelSignIn()
        // The SDK releases the waiter. Do not join it while holding operations:
        // an already-failing waiter may be queued on that same mutex.
        loginJob = null
        mutableState.value = state.value.copy(pending = false)
        notice(text(message))
    }

    private suspend fun restoreAfterOperation(client: LinkAuth) {
        try { applyStatus(client.restore()) }
        catch (error: Exception) {
            if (error is CancellationException) throw error
            // If storage cannot be read, do not keep displaying an authenticated user.
            mutableState.value = state.value.copy(session = null, pending = false, recoveryRequired = true)
        }
    }

    private fun applyStatus(status: SessionStatus) {
        pendingExpiry?.cancel()
        pendingExpiry = null
        mutableState.value = state.value.copy(
            session = (status as? SessionStatus.SignedIn)?.let { DemoSession(it.user, it.expiresAt, it.canRefresh) },
            pending = status is SessionStatus.PendingLogin,
            revocationPending = status == SessionStatus.RevocationPending,
            recoveryRequired = status == SessionStatus.ReauthenticationRequired,
        )
        if (status is SessionStatus.PendingLogin) {
            // A cold-start restored login no longer has the old signIn waiter/timer.
            val ticket = generation
            pendingExpiry = scope.launch {
                delay((status.expiresAt.toLong() * 1000 - System.currentTimeMillis()).coerceAtLeast(1))
                operations.withLock {
                    if (generation == ticket && state.value.pending) {
                        // Avoid cancelling this timer from inside cancelPending.
                        pendingExpiry = null
                        mutableState.value = state.value.copy(busy = true)
                        try { cancelPending(R.string.sign_in_expired) }
                        catch (error: Exception) {
                            if (error is CancellationException) throw error
                            notice(safeMessage(error), error = true)
                        } finally { mutableState.value = state.value.copy(busy = false) }
                    }
                }
            }
        }
    }

    private fun notice(message: String, error: Boolean = false) {
        val time = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date())
        mutableState.value = state.value.copy(message = message, error = error,
            events = (listOf("$time  $message") + state.value.events).take(12))
    }

    private fun text(id: Int) = context.getString(id)

    private fun safeMessage(error: Exception): String {
        if (error is DemoConfigException) return text(error.messageId)
        return text(when (error) {
            is LinkAuthException.CannotOpenLink -> R.string.cannot_open_link
            is LinkAuthException.Closed -> R.string.sdk_closed
            is LinkAuthException.Protocol -> when (error.code) {
                ErrorCode.InvalidConfig -> R.string.config_invalid
                ErrorCode.InvalidScopes -> R.string.invalid_scopes
                ErrorCode.AuthorizationDenied -> R.string.sign_in_denied
                ErrorCode.Cancelled -> R.string.sign_in_cancelled
                ErrorCode.Expired -> R.string.sign_in_expired
                ErrorCode.Transport -> R.string.network_error
                ErrorCode.InvalidDiscovery -> R.string.discovery_error
                ErrorCode.InvalidCallback, ErrorCode.StateMismatch, ErrorCode.IssuerMismatch -> R.string.callback_rejected
                ErrorCode.Storage, ErrorCode.InvalidStoredState -> R.string.storage_error
                ErrorCode.ReauthenticationRequired -> R.string.reauthentication_required
                ErrorCode.RevocationPending -> R.string.revoke_pending
                ErrorCode.AlreadyInProgress -> R.string.already_in_progress
                ErrorCode.InvalidIdToken, ErrorCode.InvalidSigningKey, ErrorCode.InvalidTokenResponse -> R.string.token_rejected
                is ErrorCode.Http -> R.string.http_error
                is ErrorCode.OAuth -> R.string.oauth_error
                else -> R.string.operation_failed
            }
            else -> R.string.operation_failed
        })
    }
}
