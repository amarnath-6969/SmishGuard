package com.smishguard

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException

/**
 * SslChecker — validates SSL/TLS configuration of a URL.
 *
 * Checks:
 *  - Whether URL uses HTTPS
 *  - Whether SSL certificate is valid (no handshake error)
 *  - Whether HTTPS site redirects to HTTP (SSL stripping)
 */
object SslChecker {

    data class SslResult(
        val hasSSL: Boolean,
        val isHTTPS: Boolean,
        val flagged: Boolean,
        val reason: String? = null
    )

    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .followRedirects(false) // Detect SSL-stripping redirects
        .build()

    suspend fun check(url: String): SslResult = withContext(Dispatchers.IO) {
        val isHTTPS = url.lowercase().startsWith("https://")

        if (!isHTTPS) {
            return@withContext SslResult(
                hasSSL = false,
                isHTTPS = false,
                flagged = true,
                reason = "Link uses HTTP — connection is unencrypted"
            )
        }

        return@withContext try {
            val request = Request.Builder().url(url).head().build()
            val response = client.newCall(request).execute()
            response.use { resp ->
                val location = resp.header("Location") ?: ""
                if (resp.code in 300..399 && location.startsWith("http://")) {
                    SslResult(
                        hasSSL = false,
                        isHTTPS = true,
                        flagged = true,
                        reason = "HTTPS site redirects to HTTP — possible SSL stripping attack"
                    )
                } else {
                    SslResult(hasSSL = true, isHTTPS = true, flagged = false)
                }
            }
        } catch (e: SSLHandshakeException) {
            SslResult(
                hasSSL = false,
                isHTTPS = true,
                flagged = true,
                reason = "SSL certificate is invalid or untrusted"
            )
        } catch (e: Exception) {
            // Network error — don't penalize for connectivity issues
            SslResult(hasSSL = true, isHTTPS = true, flagged = false)
        }
    }
}
