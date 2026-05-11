package com.smishguard

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * DomainAgeChecker — queries RDAP to determine domain registration age.
 *
 * Domains registered less than 30 days ago are flagged as high-risk.
 * Phishing campaigns typically use freshly registered "throwaway" domains.
 *
 * Uses rdap.org public API — requires internet connection.
 * Returns gracefully if offline.
 */
object DomainAgeChecker {

    data class DomainAgeResult(
        val ageInDays: Int?,
        val registrar: String?,
        val flagged: Boolean,
        val error: String? = null
    )

    private const val FLAG_THRESHOLD_DAYS = 30
    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    suspend fun check(domain: String): DomainAgeResult = withContext(Dispatchers.IO) {
        return@withContext try {
            val request = Request.Builder()
                .url("https://rdap.org/domain/$domain")
                .header("Accept", "application/rdap+json")
                .build()

            val response = client.newCall(request).execute()
            if (!response.isSuccessful) {
                return@withContext DomainAgeResult(null, null, false, "RDAP lookup failed: ${response.code}")
            }

            val body = response.body?.string() ?: return@withContext DomainAgeResult(null, null, false, "Empty response")
            val json = JSONObject(body)
            val events = json.optJSONArray("events") ?: JSONArray()

            var registrationDate: String? = null
            for (i in 0 until events.length()) {
                val event = events.getJSONObject(i)
                val action = event.optString("eventAction", "")
                if (action == "registration" || action == "domain registration") {
                    registrationDate = event.optString("eventDate", null)
                    break
                }
            }

            if (registrationDate == null) {
                return@withContext DomainAgeResult(null, null, false, "Registration date not found")
            }

            val regTime = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US)
                .parse(registrationDate.take(19))?.time ?: 0L
            val ageInDays = ((System.currentTimeMillis() - regTime) / (1000 * 60 * 60 * 24)).toInt()

            DomainAgeResult(
                ageInDays = ageInDays,
                registrar = null,
                flagged = ageInDays < FLAG_THRESHOLD_DAYS
            )
        } catch (e: Exception) {
            DomainAgeResult(null, null, false, "RDAP error: ${e.message}")
        }
    }
}
