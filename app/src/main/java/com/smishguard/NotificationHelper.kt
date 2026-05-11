package com.smishguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * NotificationHelper — builds and fires threat notifications.
 *
 * Three severity tiers:
 *  SAFE       → No notification (silent log only)
 *  SUSPICIOUS → High priority warning notification (sound + vibrate)
 *  DANGER     → MAX priority full-screen alert (alarm sound + long vibrate + red LED)
 */
object NotificationHelper {

    private const val CHANNEL_DANGER     = "smishguard_danger"
    private const val CHANNEL_SUSPICIOUS = "smishguard_suspicious"
    private const val CHANNEL_SAFE       = "smishguard_safe"

    fun createChannels(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // DANGER channel — max importance, alarm sound
        val dangerChannel = NotificationChannel(
            CHANNEL_DANGER,
            "🚨 Phishing Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "High-priority alerts for detected phishing links"
            enableLights(true)
            lightColor = Color.RED
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 500, 200, 500, 200, 500)
            val audioAttrs = AudioAttributes.Builder()
                .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                .build()
            setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM), audioAttrs)
        }

        // SUSPICIOUS channel — high importance, default sound
        val suspiciousChannel = NotificationChannel(
            CHANNEL_SUSPICIOUS,
            "⚠️ Suspicious Link Warnings",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Warnings for suspicious links in messages"
            enableLights(true)
            lightColor = Color.YELLOW
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 300, 150, 300)
        }

        // SAFE channel — low importance, silent
        val safeChannel = NotificationChannel(
            CHANNEL_SAFE,
            "✅ Safe Scan Logs",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Silent logs of safe messages (optional)"
        }

        nm.createNotificationChannels(listOf(dangerChannel, suspiciousChannel, safeChannel))
    }

    fun notify(context: Context, result: ScanResult, notifId: Int) {
        if (result.threatLevel == ThreatLevel.SAFE) return // Silent for safe links

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("open_scan_id", notifId)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, notifId, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val (channelId, emoji, title, smallIconColor) = when (result.threatLevel) {
            ThreatLevel.DANGER ->
                Quad(CHANNEL_DANGER, "🚨", "Phishing Link Detected!", Color.RED)
            ThreatLevel.SUSPICIOUS ->
                Quad(CHANNEL_SUSPICIOUS, "⚠️", "Suspicious Link Warning", Color.parseColor("#FF8C00"))
            ThreatLevel.SAFE ->
                Quad(CHANNEL_SAFE, "✅", "Safe Link", Color.GREEN)
        }

        val notification = NotificationCompat.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setColor(smallIconColor)
            .setContentTitle("$emoji SmishGuard: $title")
            .setContentText("From: ${result.smsSender} · ${result.domain}")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(result.humanizedWarning)
                    .setBigContentTitle("$emoji $title")
                    .setSummaryText("From: ${result.smsSender}")
            )
            .setPriority(
                if (result.threatLevel == ThreatLevel.DANGER)
                    NotificationCompat.PRIORITY_MAX
                else
                    NotificationCompat.PRIORITY_HIGH
            )
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()

        // Vibrate for DANGER
        if (result.threatLevel == ThreatLevel.DANGER) {
            vibrate(context)
        }

        try {
            NotificationManagerCompat.from(context).notify(notifId, notification)
        } catch (e: SecurityException) {
            // POST_NOTIFICATIONS permission not granted — handle gracefully
        }
    }

    private fun vibrate(context: Context) {
        val pattern = longArrayOf(0, 500, 200, 500, 200, 500)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val vm = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as VibratorManager
            vm.defaultVibrator.vibrate(VibrationEffect.createWaveform(pattern, -1))
        } else {
            @Suppress("DEPRECATION")
            val v = context.getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                v.vibrate(VibrationEffect.createWaveform(pattern, -1))
            } else {
                @Suppress("DEPRECATION")
                v.vibrate(pattern, -1)
            }
        }
    }

    private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
}
