package com.smishguard

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * ScanHistoryStore — persists scan results securely using EncryptedSharedPreferences.
 *
 * Keeps last 50 scan results. Thread-safe via synchronized block.
 */
object ScanHistoryStore {

    private const val KEY_HISTORY = "scan_history"
    private const val MAX_ENTRIES = 50
    private val gson = Gson()
    
    @Volatile
    private var encryptedPrefs: SharedPreferences? = null

    data class HistoryEntry(
        val url: String,
        val domain: String,
        val smsSender: String,
        val smsBody: String,
        val threatLevel: String,
        val threatScore: Int,
        val humanizedWarning: String,
        val rawFlags: List<String>,
        val scanDurationMs: Long,
        val scannedAt: Long
    )

    private fun getPrefs(context: Context): SharedPreferences {
        return encryptedPrefs ?: synchronized(this) {
            encryptedPrefs ?: run {
                val masterKey = MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build()

                val prefs = EncryptedSharedPreferences.create(
                    context,
                    "smishguard_secure_prefs",
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                )
                encryptedPrefs = prefs
                prefs
            }
        }
    }

    fun save(context: Context, result: ScanResult) {
        synchronized(this) {
            val prefs = getPrefs(context)
            val existing = getAll(context).toMutableList()

            val entry = HistoryEntry(
                url              = result.url,
                domain           = result.domain,
                smsSender        = result.smsSender,
                smsBody          = result.smsBody,
                threatLevel      = result.threatLevel.name,
                threatScore      = result.threatScore,
                humanizedWarning = result.humanizedWarning,
                rawFlags         = result.rawFlags,
                scanDurationMs   = result.scanDurationMs,
                scannedAt        = result.scannedAt
            )

            existing.add(0, entry)
            val trimmed = existing.take(MAX_ENTRIES)
            prefs.edit().putString(KEY_HISTORY, gson.toJson(trimmed)).apply()
        }
    }

    fun getAll(context: Context): List<HistoryEntry> {
        val prefs = getPrefs(context)
        val json = prefs.getString(KEY_HISTORY, "[]") ?: "[]"
        return try {
            val type = object : TypeToken<List<HistoryEntry>>() {}.type
            gson.fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    fun clear(context: Context) {
        getPrefs(context).edit().remove(KEY_HISTORY).apply()
    }
}
