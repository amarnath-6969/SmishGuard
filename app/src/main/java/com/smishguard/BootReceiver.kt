package com.smishguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * BootReceiver — Restarts SmishGuard protection after device reboot.
 * Ensures monitoring is always-on even if phone restarts.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = context.getSharedPreferences("smishguard_prefs", Context.MODE_PRIVATE)
            val enabled = prefs.getBoolean("monitoring_enabled", true)
            if (enabled) {
                // Protection is passively active via the BroadcastReceiver
                // No explicit service start needed — system will trigger SmsReceiver on new SMS
            }
        }
    }
}
