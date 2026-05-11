package com.smishguard

import android.content.Context
import com.google.ai.client.generativeai.GenerativeModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Humanizer — converts raw technical threat flags into plain-English warnings.
 *
 * Primary: Google Gemini API (requires GEMINI_API_KEY in app settings)
 * Fallback: Deterministic template engine (works fully offline, zero API key)
 */
object Humanizer {

    suspend fun humanize(
        flags: List<String>,
        threatLevel: ThreatLevel,
        domain: String,
        context: Context
    ): String = withContext(Dispatchers.IO) {

        if (threatLevel == ThreatLevel.SAFE || flags.isEmpty()) {
            return@withContext "✅ This link appears safe. No known threats or phishing patterns were detected."
        }

        val prefs = context.getSharedPreferences("smishguard_prefs", Context.MODE_PRIVATE)
        val apiKey = prefs.getString("gemini_api_key", "") ?: ""

        // Try Gemini AI first
        if (apiKey.isNotBlank()) {
            try {
                val model = GenerativeModel(
                    modelName = "gemini-1.5-flash",
                    apiKey = apiKey
                )
                val prompt = """You are a cybersecurity assistant helping everyday people understand phishing threats.

A link analysis system detected these threat indicators for "$domain":
${flags.mapIndexed { i, f -> "${i + 1}. $f" }.joinToString("\n")}

Threat Level: ${threatLevel.name}

Write a single, clear warning (2-3 sentences max) that:
- Explains what the attacker is trying to do in plain English
- Tells the person exactly what action to take
- Starts with ${if (threatLevel == ThreatLevel.DANGER) "🚨" else "⚠️"}
- Feels like advice from a knowledgeable friend
- Has NO bullet points

Only output the warning message, nothing else."""

                val response = model.generateContent(prompt)
                val text = response.text?.trim()
                if (!text.isNullOrBlank()) return@withContext text
            } catch (e: Exception) {
                // Fall through to template
            }
        }

        // Fallback template engine
        return@withContext buildFallbackWarning(flags, threatLevel, domain)
    }

    private fun buildFallbackWarning(
        flags: List<String>,
        threatLevel: ThreatLevel,
        domain: String
    ): String {
        val topFlag = flags.firstOrNull() ?: ""

        return when (threatLevel) {
            ThreatLevel.DANGER -> when {
                topFlag.contains("bank", true) || topFlag.contains("SBI", true) ||
                topFlag.contains("HDFC", true) || topFlag.contains("ICICI", true) ->
                    "🚨 DANGER: This link is pretending to be your bank to steal your username, password, and OTP. Do NOT tap it — your bank will never send you links like this."

                topFlag.contains("DHL", true) || topFlag.contains("FedEx", true) ||
                topFlag.contains("parcel", true) || topFlag.contains("delivery", true) ->
                    "🚨 DANGER: This is a fake delivery notification designed to steal your payment details. Real delivery companies never ask for payment via SMS links."

                topFlag.contains("IP address", true) ->
                    "🚨 DANGER: This link uses a raw IP address instead of a real website name — a classic sign of a phishing attack. Do NOT open it."

                topFlag.contains("PayPal", true) ->
                    "🚨 DANGER: This link is impersonating PayPal to steal your account credentials and payment information. Do NOT proceed."

                topFlag.contains("Apple", true) || topFlag.contains("iCloud", true) ->
                    "🚨 DANGER: This link is pretending to be Apple to steal your Apple ID. Do NOT enter your password."

                else ->
                    "🚨 DANGER: This SMS link shows strong signs of being a phishing attack (${flags.take(2).joinToString("; ")}). Do NOT tap it — delete the message immediately."
            }

            ThreatLevel.SUSPICIOUS ->
                "⚠️ WARNING: This link has suspicious characteristics (${flags.take(2).joinToString("; ")}). Verify independently that this is from a trusted source before tapping."

            ThreatLevel.SAFE ->
                "✅ This link appears safe. No known threats or phishing patterns were detected."
        }
    }
}
