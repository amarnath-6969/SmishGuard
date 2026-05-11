package com.smishguard

/**
 * HeuristicAnalyzer — On-device URL pattern analysis engine.
 *
 * Pure Kotlin implementation — zero network calls, zero latency.
 * Ported and expanded from the SmishGuard web heuristic engine.
 *
 * Checks:
 *  1. IP address in URL
 *  2. URL shortener detection
 *  3. Brand typosquatting (PayPal, Amazon, banks, etc.)
 *  4. Shannon entropy (obfuscated/random domains)
 *  5. @ symbol in URL
 *  6. Excessive subdomains
 *  7. Suspicious keywords (login, verify, otp, reward, etc.)
 *  8. Excessively long URL
 *  9. Hyphen abuse in domain
 * 10. Suspicious TLDs (.xyz, .tk, .top, .click, etc.)
 * 11. Numeric domain abuse
 */
object HeuristicAnalyzer {

    data class HeuristicResult(
        val score: Int,              // 0–100
        val flags: List<String>,
        val ipInUrl: Boolean,
        val isShortener: Boolean,
        val typosquatDetected: Boolean,
        val brandImpersonation: String?,
        val urlEntropy: Double,
        val suspiciousKeywords: List<String>
    )

    // ── Brand Typosquatting Patterns ─────────────────────────────────────────

    private val brandPatterns: Map<String, List<Regex>> = mapOf(
        "PayPal"          to listOf(Regex("paypa[l1]", RegexOption.IGNORE_CASE), Regex("pay-pal", RegexOption.IGNORE_CASE)),
        "Amazon"          to listOf(Regex("amaz[o0]n", RegexOption.IGNORE_CASE), Regex("amazone", RegexOption.IGNORE_CASE)),
        "Apple"           to listOf(Regex("app[l1]e-id", RegexOption.IGNORE_CASE), Regex("appleid", RegexOption.IGNORE_CASE)),
        "Microsoft"       to listOf(Regex("micros[o0]ft", RegexOption.IGNORE_CASE), Regex("microsoft-", RegexOption.IGNORE_CASE)),
        "Google"          to listOf(Regex("g[o0][o0]gle", RegexOption.IGNORE_CASE), Regex("g00gle", RegexOption.IGNORE_CASE)),
        "Netflix"         to listOf(Regex("netf[l1]ix", RegexOption.IGNORE_CASE)),
        "Facebook"        to listOf(Regex("faceb[o0][o0]k", RegexOption.IGNORE_CASE)),
        "Instagram"       to listOf(Regex("instagr[a@]m", RegexOption.IGNORE_CASE)),
        "WhatsApp"        to listOf(Regex("whatsapp-", RegexOption.IGNORE_CASE), Regex("whatssapp", RegexOption.IGNORE_CASE)),
        "DHL"             to listOf(Regex("dhl-", RegexOption.IGNORE_CASE), Regex("dhl\\.(?!com$)", RegexOption.IGNORE_CASE)),
        "FedEx"           to listOf(Regex("fedex-", RegexOption.IGNORE_CASE)),
        "SBI"             to listOf(Regex("sbi-", RegexOption.IGNORE_CASE), Regex("sbionline", RegexOption.IGNORE_CASE)),
        "HDFC"            to listOf(Regex("hdfc-", RegexOption.IGNORE_CASE), Regex("hdfcbank(?!\\.com)", RegexOption.IGNORE_CASE)),
        "ICICI"           to listOf(Regex("icici-", RegexOption.IGNORE_CASE)),
        "Bank of America" to listOf(Regex("bankofamerica", RegexOption.IGNORE_CASE)),
        "Chase"           to listOf(Regex("chase-", RegexOption.IGNORE_CASE), Regex("chasebank", RegexOption.IGNORE_CASE))
    )

    // ── URL Shorteners ────────────────────────────────────────────────────────

    private val urlShorteners = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.io",
        "rebrand.ly", "cutt.ly", "is.gd", "tiny.cc", "lnkd.in", "buff.ly",
        "ift.tt", "adf.ly", "bc.vc", "shorte.st"
    )

    // ── Suspicious Keywords ───────────────────────────────────────────────────

    private val suspiciousKeywords = listOf(
        "login", "signin", "sign-in", "verify", "verification", "account",
        "secure", "security", "update", "confirm", "password", "reset",
        "bank", "credit", "debit", "otp", "urgent", "alert", "suspend",
        "locked", "click", "limited", "expire", "wallet", "prize", "winner",
        "free", "reward", "claim", "delivery", "parcel", "tracking", "kyc"
    )

    // ── Suspicious TLDs ───────────────────────────────────────────────────────

    private val suspiciousTLDs = setOf(
        "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "pw",
        "cc", "su", "ru", "cn", "info", "biz", "online", "site", "website"
    )

    // ── Shannon Entropy ───────────────────────────────────────────────────────

    private fun shannonEntropy(input: String): Double {
        if (input.isEmpty()) return 0.0
        val freq = input.groupBy { it }.mapValues { it.value.size.toDouble() / input.length }
        return -freq.values.sumOf { p -> p * (Math.log(p) / Math.log(2.0)) }
    }

    // ── Main Analysis ─────────────────────────────────────────────────────────

    fun analyze(url: String, domain: String): HeuristicResult {
        val flags = mutableListOf<String>()
        var score = 0

        // 1. IP address in URL
        val ipPattern = Regex("""^(\d{1,3}\.){3}\d{1,3}(:\d+)?$""")
        val ipInUrl = ipPattern.matches(domain)
        if (ipInUrl) {
            flags.add("IP address used instead of a real domain — classic phishing tactic")
            score += 35
        }

        // 2. URL shortener
        val isShortener = urlShorteners.contains(domain.lowercase())
        if (isShortener) {
            flags.add("URL shortener detected ($domain) — hides the real destination")
            score += 20
        }

        // 3. Brand typosquatting
        var brandImpersonation: String? = null
        for ((brand, patterns) in brandPatterns) {
            if (patterns.any { it.containsMatchIn(domain) }) {
                brandImpersonation = brand
                flags.add("Possible impersonation of \"$brand\" detected in domain")
                score += 40
                break
            }
        }

        val typosquatDetected = brandImpersonation != null

        // 4. Shannon entropy
        val urlEntropy = shannonEntropy(domain)
        if (urlEntropy > 4.0 && !isShortener) {
            flags.add("High domain entropy (${"%.2f".format(urlEntropy)}) — may be randomly generated")
            score += 15
        }

        // 5. @ symbol in URL
        if (url.contains("@")) {
            flags.add("\"@\" character in URL — used to disguise the real destination")
            score += 25
        }

        // 6. Excessive subdomains
        val subdomainCount = domain.split(".").size - 2
        if (subdomainCount >= 3) {
            flags.add("Excessive subdomains ($subdomainCount) — common phishing pattern")
            score += 15
        }

        // 7. Suspicious keywords
        val lowerUrl = url.lowercase()
        val foundKeywords = suspiciousKeywords.filter { lowerUrl.contains(it) }
        if (foundKeywords.isNotEmpty()) {
            flags.add("Suspicious keywords: ${foundKeywords.take(5).joinToString(", ")}")
            score += minOf(foundKeywords.size * 8, 30)
        }

        // 8. Excessively long URL
        if (url.length > 100) {
            flags.add("Unusually long URL (${url.length} chars)")
            score += 10
        }

        // 9. Hyphen abuse
        val hyphenCount = domain.count { it == '-' }
        if (hyphenCount >= 3) {
            flags.add("Domain has $hyphenCount hyphens — common phishing pattern")
            score += 10
        }

        // 10. Suspicious TLD
        val tld = domain.substringAfterLast(".")
        if (suspiciousTLDs.contains(tld.lowercase())) {
            flags.add("Suspicious top-level domain (.$tld) — commonly used in scams")
            score += 15
        }

        // 11. Numeric domain (e.g. 192-168-1-1.xyz)
        val numericDomain = Regex("""^\d[\d\-]+\d\.""")
        if (numericDomain.containsMatchIn(domain)) {
            flags.add("Domain starts with numbers — suspicious obfuscation pattern")
            score += 15
        }

        return HeuristicResult(
            score = minOf(score, 100),
            flags = flags,
            ipInUrl = ipInUrl,
            isShortener = isShortener,
            typosquatDetected = typosquatDetected,
            brandImpersonation = brandImpersonation,
            urlEntropy = urlEntropy,
            suspiciousKeywords = foundKeywords
        )
    }
}
