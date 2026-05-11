package com.smishguard

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var switchMonitoring: Switch
    private lateinit var tvStatus: TextView
    private lateinit var tvEmptyState: TextView
    private lateinit var tvThreatCount: TextView
    
    private var isAuthenticated = false

    private val prefs by lazy { getSharedPreferences("smishguard_prefs", MODE_PRIVATE) }

    companion object {
        private const val REQ_SMS_PERMISSION = 101
        private const val REQ_NOTIF_PERMISSION = 102
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Prevent screenshots and screen recording
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        
        setContentView(R.layout.activity_main)

        recyclerView     = findViewById(R.id.recyclerHistory)
        switchMonitoring = findViewById(R.id.switchMonitoring)
        tvStatus         = findViewById(R.id.tvStatus)
        tvEmptyState     = findViewById(R.id.tvEmptyState)
        tvThreatCount    = findViewById(R.id.tvThreatCount)
        
        // Hide UI elements until authenticated
        recyclerView.visibility = View.GONE
        switchMonitoring.visibility = View.GONE

        NotificationHelper.createChannels(this)
        requestPermissions()
        
        if (!isAuthenticated) {
            authenticateUser()
        } else {
            setupUI()
        }
    }

    private fun authenticateUser() {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(applicationContext, "Authentication error: $errString", Toast.LENGTH_SHORT).show()
                    finish() // Close app if they cancel or fail
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    isAuthenticated = true
                    setupUI()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Authentication failed", Toast.LENGTH_SHORT).show()
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("SmishGuard Locked")
            .setSubtitle("Verify identity to view scanned messages")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun setupUI() {
        switchMonitoring.visibility = View.VISIBLE
        setupToggle()
        setupSettingsButton()
        loadHistory()
    }

    override fun onResume() {
        super.onResume()
        if (isAuthenticated) {
            loadHistory()
            updateStatusUI()
        }
    }

    private fun requestPermissions() {
        val permsNeeded = mutableListOf<String>()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
            != PackageManager.PERMISSION_GRANTED)
            permsNeeded.add(Manifest.permission.RECEIVE_SMS)

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS)
            != PackageManager.PERMISSION_GRANTED)
            permsNeeded.add(Manifest.permission.READ_SMS)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED)
                permsNeeded.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        if (permsNeeded.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permsNeeded.toTypedArray(), REQ_SMS_PERMISSION)
        }
    }

    private fun setupToggle() {
        val enabled = prefs.getBoolean("monitoring_enabled", true)
        switchMonitoring.isChecked = enabled
        updateStatusUI()

        switchMonitoring.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("monitoring_enabled", isChecked).apply()
            updateStatusUI()
            val msg = if (isChecked) "SmishGuard protection enabled" else "SmishGuard protection paused"
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateStatusUI() {
        val enabled = prefs.getBoolean("monitoring_enabled", true)
        val hasSmsPermission = ContextCompat.checkSelfPermission(
            this, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED

        tvStatus.text = when {
            !hasSmsPermission -> "⚠️ SMS Permission Required"
            enabled           -> "🟢 Protection Active"
            else              -> "🔴 Protection Paused"
        }
    }

    private fun setupSettingsButton() {
        findViewById<View>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    private fun loadHistory() {
        val history = ScanHistoryStore.getAll(this)
        val dangerCount = history.count { it.threatLevel == "DANGER" }
        val suspiciousCount = history.count { it.threatLevel == "SUSPICIOUS" }
        tvThreatCount.text = "🚨 $dangerCount Danger  ⚠️ $suspiciousCount Suspicious  (${history.size} total)"

        if (history.isEmpty()) {
            tvEmptyState.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else {
            tvEmptyState.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
            recyclerView.layoutManager = LinearLayoutManager(this)
            recyclerView.adapter = HistoryAdapter(history)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        updateStatusUI()
        if (grantResults.any { it == PackageManager.PERMISSION_DENIED }) {
            Toast.makeText(this,
                "SMS permission is required for SmishGuard to work",
                Toast.LENGTH_LONG).show()
        }
    }
}

// ─── RecyclerView Adapter ─────────────────────────────────────────────────────

class HistoryAdapter(private val items: List<ScanHistoryStore.HistoryEntry>) :
    RecyclerView.Adapter<HistoryAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvDomain: TextView       = view.findViewById(R.id.tvDomain)
        val tvSender: TextView       = view.findViewById(R.id.tvSender)
        val tvWarning: TextView      = view.findViewById(R.id.tvWarning)
        val tvScore: TextView        = view.findViewById(R.id.tvScore)
        val tvTime: TextView         = view.findViewById(R.id.tvTime)
        val ivThreatIcon: ImageView  = view.findViewById(R.id.ivThreatIcon)
        val threatBar: View          = view.findViewById(R.id.threatBar)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_scan_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        val sdf = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())

        holder.tvDomain.text  = item.domain
        holder.tvSender.text  = "From: ${item.smsSender}"
        holder.tvWarning.text = item.humanizedWarning
        holder.tvScore.text   = "${item.threatScore}/100"
        holder.tvTime.text    = sdf.format(Date(item.scannedAt))

        val (emoji, colorRes) = when (item.threatLevel) {
            "DANGER"     -> Pair("🚨", android.R.color.holo_red_dark)
            "SUSPICIOUS" -> Pair("⚠️", android.R.color.holo_orange_dark)
            else         -> Pair("✅", android.R.color.holo_green_dark)
        }

        holder.ivThreatIcon.contentDescription = item.threatLevel
        holder.tvDomain.setTextColor(
            holder.itemView.context.getColor(colorRes)
        )
    }

    override fun getItemCount() = items.size
}
