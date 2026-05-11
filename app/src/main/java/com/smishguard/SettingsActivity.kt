package com.smishguard

import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    private val prefs by lazy { getSharedPreferences("smishguard_prefs", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Prevent screenshots of API key
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        
        setContentView(R.layout.activity_settings)

        val etGeminiKey = findViewById<EditText>(R.id.etGeminiKey)
        val etSafeBrowsingKey = findViewById<EditText>(R.id.etSafeBrowsingKey)
        val switchAiWarnings = findViewById<Switch>(R.id.switchAiWarnings)
        val switchCloudScanning = findViewById<Switch>(R.id.switchCloudScanning)
        val switchScanSafe = findViewById<Switch>(R.id.switchScanSafe)
        val btnSave = findViewById<Button>(R.id.btnSave)
        val btnClearHistory = findViewById<Button>(R.id.btnClearHistory)

        // Load saved values
        etGeminiKey.setText(prefs.getString("gemini_api_key", ""))
        etSafeBrowsingKey.setText(prefs.getString("safe_browsing_key", ""))
        switchAiWarnings.isChecked = prefs.getBoolean("ai_warnings_enabled", true)
        switchCloudScanning.isChecked = prefs.getBoolean("cloud_scanning_enabled", true)
        switchScanSafe.isChecked = prefs.getBoolean("log_safe_links", false)

        btnSave.setOnClickListener {
            val geminiKey = etGeminiKey.text.toString().trim()
            val safeBrowsingKey = etSafeBrowsingKey.text.toString().trim()
            prefs.edit()
                .putString("gemini_api_key", geminiKey)
                .putString("safe_browsing_key", safeBrowsingKey)
                .putBoolean("ai_warnings_enabled", switchAiWarnings.isChecked)
                .putBoolean("cloud_scanning_enabled", switchCloudScanning.isChecked)
                .putBoolean("log_safe_links", switchScanSafe.isChecked)
                .apply()
            Toast.makeText(this, "Settings saved", Toast.LENGTH_SHORT).show()
            finish()
        }

        btnClearHistory.setOnClickListener {
            ScanHistoryStore.clear(this)
            Toast.makeText(this, "Scan history cleared", Toast.LENGTH_SHORT).show()
        }

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "SmishGuard Settings"
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }
}
