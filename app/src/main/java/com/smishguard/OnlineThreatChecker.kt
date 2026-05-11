package com.smishguard

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/**
 * OnlineThreatChecker uses the Google Safe Browsing API v4 to check if a URL
 * is currently blacklisted as phishing or malware in the cloud.
 */
object OnlineThreatChecker {

    private val client = OkHttpClient()

    data class CloudResult(
        val isThreat: Boolean,
        val threatTypes: List<String>
    )

    fun checkUrl(url: String, apiKey: String): CloudResult {
        if (apiKey.isBlank()) return CloudResult(false, emptyList())

        val apiUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$apiKey"
        
        val jsonBody = """
        {
          "client": {
            "clientId": "com.smishguard",
            "clientVersion": "1.0.0"
          },
          "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM", "ANDROID"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
              {"url": "$url"}
            ]
          }
        }
        """.trimIndent()

        val request = Request.Builder()
            .url(apiUrl)
            .post(jsonBody.toRequestBody("application/json".toMediaType()))
            .build()

        return try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return CloudResult(false, emptyList())
                }
                
                val responseBody = response.body?.string() ?: "{}"
                val json = JSONObject(responseBody)
                
                if (json.has("matches")) {
                    val matches = json.getJSONArray("matches")
                    val threatTypes = mutableListOf<String>()
                    
                    for (i in 0 until matches.length()) {
                        val match = matches.getJSONObject(i)
                        threatTypes.add(match.getString("threatType"))
                    }
                    
                    CloudResult(true, threatTypes)
                } else {
                    CloudResult(false, emptyList())
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
            CloudResult(false, emptyList())
        }
    }
}
