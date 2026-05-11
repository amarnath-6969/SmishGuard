package com.smishguard

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.coroutineScope
import java.net.URL
import java.util.regex.Pattern

enum class ThreatLevel { SAFE, SUSPICIOUS, DANGER }

data class ScanResult(
    val url: String,
    val domain: String,
    val smsSender: String,
    val smsBody: String,
    val threatLevel: ThreatLevel,
    val threatScore: Int,
    val humanizedWarning: String,
    val rawFlags: List<String>,
    val scanDurationMs: Long,
    val scannedAt: Long = System.currentTimeMillis()
)

/**
 * ScanEngine — orchestrates parallel on-device threat analysis.
 *
 * Runs 4 analyzers concurrently using Kotlin coroutines:
 *   ① HeuristicAnalyzer  — instant, zero network, pattern matching
 *   ② ThreatDatabase     — instant, local SQLite lookup
 *   ③ SslChecker         — fast OkHttp check (optional internet)
 *   ④ DomainAgeChecker   — RDAP lookup (optional internet)
 *
 * Then routes results to Humanizer for plain-English explanation.
 */
object ScanEngine {

    private val URL_REGEX = Pattern.compile(
        """https?://[^\s<>"{}|\\\^`\[\]]+""",
        Pattern.CASE_INSENSITIVE
    )

    fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = URL_REGEX.matcher(text)
        while (matcher.find()) {
            urls.add(matcher.group())
        }
        return urls
    }

    fun extractDomain(url: String): String {
        return try {
            URL(url).host.removePrefix("www.")
        } catch (e: Exception) {
            url.removePrefix("https://").removePrefix("http://")
                .split("/").first().removePrefix("www.")
        }
    }

    private fun calcThreatLevel(score: Int): ThreatLevel = when {
        score >= 60 -> ThreatLevel.DANGER
        score >= 25 -> ThreatLevel.SUSPICIOUS
        else        -> ThreatLevel.SAFE
    }

    suspend fun scan(
        url: String,
        smsSender: String,
        smsBody: String,
        context: Context
    ): ScanResult = coroutineScope {
        val startTime = System.currentTimeMillis()
        val domain = extractDomain(url)

        val prefs = context.getSharedPreferences("smishguard_prefs", Context.MODE_PRIVATE)
        val cloudScanningEnabled = prefs.getBoolean("cloud_scanning_enabled", true)
        val safeBrowsingKey = prefs.getString("safe_browsing_key", "") ?: ""

        // ── PARALLEL ANALYSIS ──────────────────────────────────────────────
        val heuristicDeferred   = async(Dispatchers.Default) { HeuristicAnalyzer.analyze(url, domain) }
        val threatDbDeferred    = async(Dispatchers.IO)      { ThreatDatabase.getInstance(context).lookup(domain) }
        val sslDeferred         = async(Dispatchers.IO)      { SslChecker.check(url) }
        val domainAgeDeferred   = async(Dispatchers.IO)      { DomainAgeChecker.check(domain) }
        
        val cloudDeferred = if (cloudScanningEnabled && safeBrowsingKey.isNotBlank()) {
            async(Dispatchers.IO) { OnlineThreatChecker.checkUrl(url, safeBrowsingKey) }
        } else {
            null
        }

        val heuristic   = heuristicDeferred.await()
        val threatRecord= threatDbDeferred.await()
        val ssl         = sslDeferred.await()
        val domainAge   = domainAgeDeferred.await()
        val cloudResult = cloudDeferred?.await()
        // ──────────────────────────────────────────────────────────────────

        // Aggregate flags and score
        val rawFlags = mutableListOf<String>()
        var totalScore = 0

        // Cloud Check — Definitive Live Database
        if (cloudResult != null && cloudResult.isThreat) {
            val types = cloudResult.threatTypes.joinToString(", ")
            rawFlags.add("[LIVE THREAT DETECTED via Safe Browsing] ($types)")
            totalScore += 100 // Instant DANGER level
        }

        // Threat DB — highest weight (known bad = definitive)
        if (threatRecord != null) {
            rawFlags.add("Domain is in the local threat database as \"${threatRecord.type}\"")
            totalScore += 60
        }

        // SSL
        if (ssl.flagged) {
            rawFlags.add(ssl.reason ?: "SSL/TLS issue detected")
            totalScore += 20
        }

        // Domain Age
        if (domainAge.flagged && domainAge.ageInDays != null) {
            rawFlags.add("Domain registered only ${domainAge.ageInDays} days ago — very new")
            totalScore += 25
        }

        // Heuristic
        rawFlags.addAll(heuristic.flags)
        totalScore += heuristic.score

        val threatScore = minOf(totalScore, 100)
        val threatLevel = calcThreatLevel(threatScore)

        // AI humanization (uses Gemini if key set, fallback otherwise)
        val humanizedWarning = Humanizer.humanize(rawFlags, threatLevel, domain, context)

        val duration = System.currentTimeMillis() - startTime

        ScanResult(
            url             = url,
            domain          = domain,
            smsSender       = smsSender,
            smsBody         = smsBody,
            threatLevel     = threatLevel,
            threatScore     = threatScore,
            humanizedWarning= humanizedWarning,
            rawFlags        = rawFlags,
            scanDurationMs  = duration
        )
    }
}
