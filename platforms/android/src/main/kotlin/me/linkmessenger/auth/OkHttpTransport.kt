package me.linkmessenger.auth

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import me.linkmessenger.auth.generated.*
import okhttp3.Authenticator
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CookieJar
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink

/** Dedicated OAuth transport. Does not inherit application interceptors or credentials. */
class OkHttpTransport(private val maximumTimeoutMillis: Long = 15_000) : HttpTransport, AutoCloseable {
    private val client = OkHttpClient.Builder()
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
        .cookieJar(CookieJar.NO_COOKIES).cache(null).build()

    init { require(maximumTimeoutMillis > 0) }

    override suspend fun execute(request: HttpRequest): HttpResponse {
        val body = request.body()
        try {
            val method = request.method()
            val maximumBytes = request.maxResponseBytes().toInt()
            val timeout = minOf(request.timeoutMillis().toLong(), maximumTimeoutMillis)
            val sent = AtomicBoolean(false)
            val callClient = client.newBuilder().callTimeout(timeout, TimeUnit.MILLISECONDS)
                // This also blocks HTTP-level follow-ups (408/503/auth challenges).
                .addNetworkInterceptor { chain ->
                    if (!sent.compareAndSet(false, true)) throw IOException("OAuth retry disabled")
                    chain.proceed(chain.request())
                }.build()
            val builder = Request.Builder().url(request.url())
            request.headers().forEach { builder.header(it.name, it.value) }
            when (method) {
                "GET" -> builder.get()
                "POST" -> builder.post(object : RequestBody() {
                    override fun contentType() = "application/x-www-form-urlencoded".toMediaType()
                    override fun contentLength() = body.size.toLong()
                    override fun isOneShot() = true
                    override fun writeTo(sink: BufferedSink) { sink.write(body) }
                })
                else -> throw IOException("Unsupported OAuth method")
            }
            val call = callClient.newCall(builder.build())
            return suspendCancellableCoroutine { continuation ->
                continuation.invokeOnCancellation { call.cancel() }
                call.enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        if (continuation.isActive) continuation.resumeWithException(TransportFailure.RequestFailed())
                    }
                    override fun onResponse(call: Call, response: Response) {
                        response.use {
                            if (!continuation.isActive) return
                            try {
                                val responseBody = response.body
                                if ((responseBody?.contentLength() ?: 0L) > maximumBytes) throw IOException("OAuth response too large")
                                val bytes = responseBody?.byteStream()?.let { readBounded(it, maximumBytes) } ?: byteArrayOf()
                                val result = try {
                                    HttpResponse(response.code.toUShort(), response.request.url.toString(), response.header("Content-Type") ?: "", bytes)
                                } finally { bytes.fill(0) }
                                continuation.resume(result)
                            } catch (_: Exception) {
                                if (continuation.isActive) continuation.resumeWithException(TransportFailure.RequestFailed())
                            }
                        }
                    }
                })
            }
        } catch (_: Exception) {
            throw TransportFailure.RequestFailed()
        } finally {
            body.fill(0)
            request.close()
        }
    }

    /** Pair with core.cancelSignIn() for login cancellation. The transport remains usable. */
    fun cancelRequests() { client.dispatcher.cancelAll() }

    /** Use when disposing this SDK instance; do not cancel another caller's shared refresh. */
    override fun close() {
        cancelRequests()
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }
}

internal fun readBounded(input: InputStream, maximum: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val chunk = ByteArray(8192)
    try {
        while (true) {
            val count = input.read(chunk)
            if (count < 0) break
            if (output.size() + count > maximum) throw IOException("Response too large")
            output.write(chunk, 0, count)
        }
        return output.toByteArray()
    } finally { chunk.fill(0) }
}
