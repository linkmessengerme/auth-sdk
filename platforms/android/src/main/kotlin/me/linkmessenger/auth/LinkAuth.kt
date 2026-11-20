package me.linkmessenger.auth

import android.content.Context
import java.util.UUID
import kotlinx.coroutines.*
import me.linkmessenger.auth.generated.*

sealed class LinkAuthException(message: String) : Exception(message) {
    class Protocol(val code: ErrorCode) : LinkAuthException("Link authentication failed")
    class CannotOpenLink : LinkAuthException("No handler accepted the Link authorization URL")
    class Closed : LinkAuthException("LinkAuth is closed")
}

/** Opaque credentials. No refresh-token getter; close after use. */
class LinkSession internal constructor(private val result: SignInResult) : AutoCloseable {
    val user: UserIdentity get() = result.user()
    val expiresAt: ULong get() = result.expiresAt()
    val accessToken: String get() = result.accessToken()
    val idToken: String get() = result.idToken()
    override fun close() = result.close()
    override fun toString() = "LinkSession(redacted)"
}

fun interface LinkAuthorizationOpener {
    /** True only means the OS accepted opening; it is not authentication success. */
    suspend fun open(url: String): Boolean
}

/** One application-owned instance per configuration. FFI/storage run on IO;
 * token work belongs to this SDK so cancelling one waiter cannot cancel a
 * shared refresh. Login cancellation is explicit and removes its pending flow.
 */
class LinkAuth internal constructor(
    private val core: LinkSessionClient,
    private val transport: OkHttpTransport,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val signInTimeoutMillis: Long = 600_000,
) {
    private class Login(val id: String, val result: CompletableDeferred<LinkSession>) { var expiry: Job? = null }
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val lock = Any()
    private var login: Login? = null
    private var generation = 0L
    private var sessionCalls = 0
    private var callbackCalls = 0
    private var loggingOut = false
    private var closed = false

    companion object {
        suspend fun create(context: Context, configJson: String, redirectUri: String): LinkAuth {
            var created: LinkAuth? = null
            try {
                return withContext(Dispatchers.IO) {
                    val transport = OkHttpTransport()
                    try {
                        LinkAuth(LinkSessionClient(configJson, redirectUri, transport, KeystoreStorage(context.applicationContext)), transport)
                            .also { created = it }
                    } catch (e: Exception) { transport.close(); throw normalized(e) }
                }
            } catch (e: Exception) {
                // withContext can discard its result if cancellation happens
                // during the dispatch back to the caller.
                withContext(NonCancellable + Dispatchers.IO) { created?.close() }
                throw e
            }
        }
        private fun normalized(error: Exception): Exception = when (error) {
            is LinkAuthException -> error
            is AuthException.Failure -> LinkAuthException.Protocol(error.code)
            is CancellationException -> error
            else -> LinkAuthException.Protocol(ErrorCode.Internal)
        }
    }

    suspend fun restore(): SessionStatus = owned {
        synchronized(lock) { requireIdle(); core.restore() }
    }

    /** Pass a fresh backend nonce when exchanging Link identity for your own session. */
    suspend fun signIn(scopes: List<String>, opener: LinkAuthorizationOpener, nonce: String? = null): LinkSession {
        currentCoroutineContext().ensureActive()
        val current = synchronized(lock) {
            requireIdle()
            Login(UUID.randomUUID().toString(), CompletableDeferred()).also { login = it }
        }
        scope.launch { prepare(current.id, scopes.toList(), opener, nonce) }
        try { return current.result.await() }
        catch (e: CancellationException) {
            withContext(NonCancellable + dispatcher) { cancelLogin(current.id) }
            throw e
        }
    }

    private suspend fun prepare(id: String, scopes: List<String>, opener: LinkAuthorizationOpener, nonce: String?) {
        if (synchronized(lock) { login?.id != id }) return
        try {
            (if (nonce == null) core.beginSignIn(scopes) else core.beginSignInWithNonce(scopes, nonce)).use { request ->
                synchronized(lock) {
                    if (login?.id != id) return
                    val remaining = minOf(request.expiresAt().toLong() * 1000 - System.currentTimeMillis(), signInTimeoutMillis)
                    if (remaining <= 0) { cancelLogin(id, LinkAuthException.Protocol(ErrorCode.Expired)); return }
                    login?.expiry = scope.launch {
                        delay(remaining)
                        cancelLogin(id, LinkAuthException.Protocol(ErrorCode.Expired))
                    }
                }
                // AndroidLinkOpener performs the launch on Dispatchers.Main.
                if (!opener.open(request.authorizationUrl())) cancelLogin(id, LinkAuthException.CannotOpenLink())
            }
        } catch (e: Exception) { synchronized(lock) { finishFailure(id, normalized(e)) } }
    }

    /** Forward Activity intent.dataString here, including the initial intent.
     * Returns identity on success, null for unrelated/duplicate callbacks. After
     * process recreation there need not be a waiting signIn coroutine.
     */
    suspend fun handleCallback(url: String): UserIdentity? = owned {
        val (id, ticket) = synchronized(lock) {
            requireOpen()
            if (loggingOut) throw LinkAuthException.Protocol(ErrorCode.AlreadyInProgress)
            if (!core.isCallbackUrl(url)) return@owned null
            callbackCalls++
            login?.id to generation
        }
        var result: SignInResult? = null
        try {
            result = core.completeSignIn(url)
            synchronized(lock) {
                requireGeneration(ticket)
                val user = result!!.user()
                if (id != null && login?.id == id) {
                    val current = login!!
                    login = null; current.expiry?.cancel()
                    current.result.complete(LinkSession(result!!)); result = null
                }
                user
            }
        } catch (e: Exception) {
            val failure = normalized(e)
            if (failure is LinkAuthException.Protocol) {
                when (failure.code) {
                    ErrorCode.NoPendingLogin -> return@owned null
                    ErrorCode.InvalidCallback, ErrorCode.StateMismatch, ErrorCode.IssuerMismatch -> throw failure
                    else -> Unit
                }
            }
            synchronized(lock) { finishFailure(id, failure) }
            throw failure
        } finally {
            result?.close()
            synchronized(lock) { callbackCalls-- }
        }
    }

    suspend fun getSession(forceRefresh: Boolean = false): LinkSession = owned {
        val ticket = synchronized(lock) {
            requireOpen()
            if (login != null || loggingOut || callbackCalls > 0) throw LinkAuthException.Protocol(ErrorCode.AlreadyInProgress)
            sessionCalls++; generation
        }
        var result: SignInResult? = null
        try {
            result = if (forceRefresh) core.refresh() else core.validSession()
            synchronized(lock) { requireGeneration(ticket) }
            LinkSession(result).also { result = null }
        } finally {
            result?.close()
            synchronized(lock) { sessionCalls-- }
        }
    }

    suspend fun getIdToken(forceRefresh: Boolean = false): String = getSession(forceRefresh).use { it.idToken }

    /** Fresh authorized data; phoneNumber is null when unavailable or not granted. */
    suspend fun getUserInfo(): UserInfo = owned {
        val ticket = synchronized(lock) {
            requireOpen()
            if (login != null || loggingOut || callbackCalls > 0) throw LinkAuthException.Protocol(ErrorCode.AlreadyInProgress)
            sessionCalls++; generation
        }
        try {
            val info = core.getUserInfo()
            synchronized(lock) { requireGeneration(ticket) }
            info
        } finally { synchronized(lock) { sessionCalls-- } }
    }

    suspend fun cancelSignIn() = withContext(dispatcher) {
        synchronized(lock) {
            requireOpen()
            val id = login?.id
            try {
                core.cancelSignIn()
                if (id != null || callbackCalls > 0) transport.cancelRequests()
                finishFailure(id, LinkAuthException.Protocol(ErrorCode.Cancelled))
            } catch (e: Exception) {
                val failure = normalized(e); finishFailure(id, failure); throw failure
            }
        }
    }

    suspend fun signOut(): LogoutStatus = owned {
        synchronized(lock) {
            requireOpen()
            if (loggingOut) throw LinkAuthException.Protocol(ErrorCode.AlreadyInProgress)
            loggingOut = true; generation++
        }
        try {
            cancelSignIn()
            transport.cancelRequests()
            core.logout()
        } finally { synchronized(lock) { loggingOut = false } }
    }

    /** Disposes this instance; a completed stored session survives. */
    suspend fun close() = withContext(NonCancellable + dispatcher) {
        synchronized(lock) {
            if (closed) return@withContext
            closed = true; generation++
            val id = login?.id
            try {
                if (id != null || callbackCalls > 0) core.cancelSignIn()
                finishFailure(id, LinkAuthException.Closed())
            } catch (e: Exception) {
                val failure = normalized(e); finishFailure(id, failure); throw failure
            } finally {
                transport.close(); scope.cancel()
                // Running UniFFI calls retain their own native reference.
                core.close()
            }
        }
    }

    private fun cancelLogin(id: String, reason: Exception = LinkAuthException.Protocol(ErrorCode.Cancelled)) {
        synchronized(lock) {
            if (login?.id != id) return
            try { core.cancelSignIn(); transport.cancelRequests(); finishFailure(id, reason) }
            catch (e: Exception) { finishFailure(id, normalized(e)) }
        }
    }
    private fun finishFailure(id: String?, error: Exception) {
        val current = login ?: return
        if (id != current.id) return
        login = null; current.expiry?.cancel(); current.result.completeExceptionally(error)
    }
    private fun requireOpen() { if (closed) throw LinkAuthException.Closed() }
    private fun requireIdle() {
        requireOpen()
        if (login != null || loggingOut || sessionCalls > 0 || callbackCalls > 0) throw LinkAuthException.Protocol(ErrorCode.AlreadyInProgress)
    }
    private fun requireGeneration(value: Long) {
        requireOpen()
        if (generation != value) throw LinkAuthException.Protocol(ErrorCode.Cancelled)
    }
    private suspend fun <T> owned(action: suspend () -> T): T {
        currentCoroutineContext().ensureActive()
        val task = synchronized(lock) {
            requireOpen()
            scope.async { try { action() } catch (e: Exception) { throw normalized(e) } }
        }
        return task.await()
    }
}
