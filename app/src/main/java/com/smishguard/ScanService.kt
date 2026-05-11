package com.smishguard

import android.app.Service
import android.content.Intent
import android.os.IBinder
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicInteger

/**
 * ScanService — Foreground service that processes incoming SMS.
 *
 * Runs in background even when app is closed.
 * Triggered by SmsReceiver when a new message arrives.
 */
class ScanService : Service() {

    private val job = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Default + job)
    private val notifIdCounter = AtomicInteger(1000)

    companion object {
        private const val FOREGROUND_NOTIF_ID = 1
        private const val FOREGROUND_CHANNEL  = "smishguard_service"
    }

    override fun onCreate() {
        super.onCreate()
        NotificationHelper.createChannels(this)
        createServiceChannel()
        startForeground(FOREGROUND_NOTIF_ID, buildServiceNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val smsBody   = intent?.getStringExtra("sms_body")   ?: return START_NOT_STICKY
        val smsSender = intent.getStringExtra("sms_sender")  ?: "Unknown"

        scope.launch {
            processSms(smsBody, smsSender)
            stopSelf(startId)
        }

        return START_NOT_STICKY
    }

    private suspend fun processSms(smsBody: String, smsSender: String) {
        val urls = ScanEngine.extractUrls(smsBody)
        if (urls.isEmpty()) return

        // Scan each URL found in the message
        for (url in urls) {
            val result = ScanEngine.scan(url, smsSender, smsBody, applicationContext)

            // Save to history
            ScanHistoryStore.save(applicationContext, result)

            // Notify user
            if (result.threatLevel != ThreatLevel.SAFE) {
                NotificationHelper.notify(
                    applicationContext,
                    result,
                    notifIdCounter.getAndIncrement()
                )
            }
        }
    }

    private fun createServiceChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager
        val channel = android.app.NotificationChannel(
            FOREGROUND_CHANNEL,
            "SmishGuard Protection",
            android.app.NotificationManager.IMPORTANCE_MIN
        ).apply {
            description = "Persistent notification showing SmishGuard is active"
            setShowBadge(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildServiceNotification(): android.app.Notification {
        return NotificationCompat.Builder(this, FOREGROUND_CHANNEL)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SmishGuard Active")
            .setContentText("Monitoring incoming SMS for phishing links")
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setSilent(true)
            .setOngoing(true)
            .build()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        job.cancel()
    }
}
