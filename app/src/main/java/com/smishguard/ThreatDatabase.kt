package com.smishguard

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.io.File
import java.io.FileOutputStream

/**
 * ThreatDatabase — SQLite database of known phishing domains.
 *
 * Bundled as assets/threats.db and copied to private app storage on first run.
 * Uses raw SQLite (no Room) for simplicity and asset-bundling compatibility.
 */
class ThreatDatabase private constructor(private val db: SQLiteDatabase) {

    data class ThreatRecord(
        val domain: String,
        val type: String,
        val source: String
    )

    fun lookup(domain: String): ThreatRecord? {
        val cursor = db.rawQuery(
            "SELECT domain, type, source FROM threats WHERE domain = ? COLLATE NOCASE LIMIT 1",
            arrayOf(domain)
        )
        return cursor.use {
            if (it.moveToFirst()) {
                ThreatRecord(
                    domain = it.getString(0),
                    type   = it.getString(1),
                    source = it.getString(2)
                )
            } else null
        }
    }

    fun getThreatCount(): Int {
        val cursor = db.rawQuery("SELECT COUNT(*) FROM threats", null)
        return cursor.use { if (it.moveToFirst()) it.getInt(0) else 0 }
    }

    companion object {
        private const val DB_NAME = "threats.db"
        private var instance: ThreatDatabase? = null

        fun getInstance(context: Context): ThreatDatabase {
            return instance ?: synchronized(this) {
                instance ?: createFromAssets(context).also { instance = it }
            }
        }

        private fun createFromAssets(context: Context): ThreatDatabase {
            val dbFile = File(context.filesDir, DB_NAME)

            if (!dbFile.exists()) {
                // Copy threats.db from assets to private storage on first run
                try {
                    context.assets.open(DB_NAME).use { input ->
                        FileOutputStream(dbFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                } catch (e: Exception) {
                    // Asset not found — create empty DB and seed programmatically
                    createAndSeedDb(dbFile)
                }
            }

            val db = SQLiteDatabase.openDatabase(
                dbFile.absolutePath, null, SQLiteDatabase.OPEN_READONLY
            )
            return ThreatDatabase(db)
        }

        private fun createAndSeedDb(dbFile: File) {
            val db = SQLiteDatabase.openOrCreateDatabase(dbFile, null)
            db.execSQL("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    type TEXT NOT NULL DEFAULT 'phishing',
                    source TEXT DEFAULT 'bundled'
                )
            """)
            db.execSQL("CREATE INDEX IF NOT EXISTS idx_domain ON threats(domain)")

            val threats = listOf(
                // PayPal phishing
                Triple("paypal-secure.com", "phishing", "bundled"),
                Triple("paypa1.com", "phishing", "bundled"),
                Triple("pay-pal-verify.com", "phishing", "bundled"),
                Triple("paypalservice.net", "phishing", "bundled"),
                Triple("secure-paypal.xyz", "phishing", "bundled"),
                Triple("paypal-login.top", "phishing", "bundled"),
                // Bank phishing
                Triple("bankofamerica-secure.com", "phishing", "bundled"),
                Triple("chase-secure-login.com", "phishing", "bundled"),
                Triple("sbi-online-verify.xyz", "phishing", "bundled"),
                Triple("hdfc-secure-login.com", "phishing", "bundled"),
                Triple("icici-alert.net", "phishing", "bundled"),
                Triple("axisbank-verify.com", "phishing", "bundled"),
                Triple("hsbc-verify.net", "phishing", "bundled"),
                // Amazon phishing
                Triple("amazon-prime-offer.com", "phishing", "bundled"),
                Triple("amaz0n-verify.com", "phishing", "bundled"),
                Triple("amazon-account-update.net", "phishing", "bundled"),
                Triple("amazon-gift-claim.xyz", "phishing", "bundled"),
                // Apple phishing
                Triple("apple-id-verify.com", "phishing", "bundled"),
                Triple("appleid-locked.net", "phishing", "bundled"),
                Triple("icloud-verify.top", "phishing", "bundled"),
                // Microsoft phishing
                Triple("microsoft365-login.com", "phishing", "bundled"),
                Triple("outlook-verify.net", "phishing", "bundled"),
                Triple("microsoftsecure.xyz", "phishing", "bundled"),
                // Delivery scams
                Triple("dhl-parcel-track.com", "scam", "bundled"),
                Triple("fedex-delivery-alert.net", "scam", "bundled"),
                Triple("ups-tracking-fee.com", "scam", "bundled"),
                Triple("royalmail-redelivery.com", "scam", "bundled"),
                Triple("indiapost-track.xyz", "scam", "bundled"),
                Triple("package-track-now.com", "scam", "bundled"),
                // Social media phishing
                Triple("facebook-login-verify.com", "phishing", "bundled"),
                Triple("instagram-verify-account.net", "phishing", "bundled"),
                Triple("whatsapp-gold.com", "phishing", "bundled"),
                // Crypto scams
                Triple("bitcoin-reward-claim.com", "scam", "bundled"),
                Triple("crypto-doubler.net", "scam", "bundled"),
                Triple("binance-airdrop.xyz", "scam", "bundled"),
                // Tax / Govt phishing
                Triple("irs-refund-verify.com", "phishing", "bundled"),
                Triple("taxrefund-now.xyz", "phishing", "bundled"),
                Triple("incometax-refund.top", "phishing", "bundled"),
                // Prize scams
                Triple("you-won-prize.com", "scam", "bundled"),
                Triple("amazon-lucky-winner.net", "scam", "bundled"),
                Triple("free-iphone-winner.com", "scam", "bundled"),
                Triple("claim-reward-now.xyz", "scam", "bundled"),
                // Malware
                Triple("malware-drop.xyz", "malware", "bundled"),
                Triple("trojan-host.net", "malware", "bundled")
            )

            db.beginTransaction()
            try {
                for ((domain, type, source) in threats) {
                    db.execSQL(
                        "INSERT OR IGNORE INTO threats (domain, type, source) VALUES (?, ?, ?)",
                        arrayOf(domain, type, source)
                    )
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
                db.close()
            }
        }
    }
}
