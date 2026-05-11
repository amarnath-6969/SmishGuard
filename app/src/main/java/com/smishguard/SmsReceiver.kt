package com.smishguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SmsMessage

/**
 * SmsReceiver — BroadcastReceiver that intercepts every incoming SMS.
 *
 * Registered in AndroidManifest with priority 999 so it runs before
 * any other SMS app. Extracts the message body and sender, then
 * hands off to ScanService for analysis.
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        // Check if SmishGuard monitoring is enabled
        val prefs = context.getSharedPreferences("smishguard_prefs", Context.MODE_PRIVATE)
        val enabled = prefs.getBoolean("monitoring_enabled", true)
        if (!enabled) return

        // Parse SMS PDU messages
        val messages: Array<SmsMessage> = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isEmpty()) return

        // Reconstruct full message body (multi-part SMS)
        val sender = messages[0].displayOriginatingAddress ?: "Unknown"
        val fullBody = messages.joinToString("") { it.messageBody ?: "" }

        if (fullBody.isBlank()) return

        // Launch background scan service
        val serviceIntent = Intent(context, ScanService::class.java).apply {
            putExtra("sms_body", fullBody)
            putExtra("sms_sender", sender)
        }
        context.startForegroundService(serviceIntent)
    }
}
