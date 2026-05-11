# SmishGuard Android App

A standalone Android app that automatically reads incoming SMS messages,
detects phishing links in real-time, and fires instant notifications.

**No PC. No server. Everything runs on your phone.**

---

## How It Works

```
📱 You receive an SMS
    └── SmishGuard wakes up instantly (BroadcastReceiver)
        └── Extracts any URL from the message
            └── Runs 4 parallel on-device analyzers:
                  ① Heuristic patterns (zero network)
                  ② Local threats database (45+ known phishing domains)
                  ③ SSL certificate check
                  ④ Domain age lookup (RDAP)
                └── DANGER → 🚨 Full alarm notification
                └── SUSPICIOUS → ⚠️ Warning notification
                └── SAFE → Silent log
```

---

## Build & Install Steps

### Requirements
- **Android Studio** (latest version) — [download here](https://developer.android.com/studio)
- Android phone running Android 8.0+ (API 26+)
- USB cable for first install

### Steps

1. **Open the project** in Android Studio:
   - File → Open → select the `android-app/` folder

2. **Sync Gradle**:
   - Android Studio will prompt to sync. Click "Sync Now".
   - Wait for dependencies to download (~2 min first time)

3. **Connect your phone**:
   - Enable USB Debugging: Settings → Developer Options → USB Debugging
   - Connect via USB cable

4. **Run the app**:
   - Click the green ▶ Run button in Android Studio
   - Select your connected phone
   - App installs automatically

5. **Grant permissions** when the app opens:
   - SMS (required for monitoring)
   - Notifications (required for alerts)

6. **Optional — Enable AI Warnings**:
   - Open Settings (⚙️ icon in app)
   - Paste your free Gemini API key from [aistudio.google.com](https://aistudio.google.com/app/apikey)
   - AI warnings work without this (fallback templates used)

---

## Permissions Explained

| Permission | Why |
|---|---|
| RECEIVE_SMS | To intercept incoming SMS in real-time |
| READ_SMS | To read message content |
| INTERNET | SSL check + optional domain age lookup + Gemini AI |
| POST_NOTIFICATIONS | To show threat alerts |
| RECEIVE_BOOT_COMPLETED | Monitoring auto-resumes after phone restart |
| VIBRATE | Vibration for DANGER alerts |

---

## Features

- ✅ **Fully on-device** — works offline (heuristics + threats DB)
- ✅ **45+ phishing domains** bundled in local SQLite database
- ✅ **Parallel analysis** — 4 checks run simultaneously via Kotlin coroutines
- ✅ **3-tier alerts** — SAFE (silent) / SUSPICIOUS (warning) / DANGER (alarm)
- ✅ **AI humanizer** — Gemini explains threats in plain English
- ✅ **Always-on** — survives phone restarts via BootReceiver
- ✅ **History dashboard** — see all scanned messages + results
- ✅ **Enable/Disable toggle** — pause monitoring anytime

---

## Architecture

```
android-app/
├── SmsReceiver.kt          ← Intercepts every SMS (BroadcastReceiver)
├── BootReceiver.kt         ← Restarts after reboot
├── ScanService.kt          ← Background service, runs analysis
├── ScanEngine.kt           ← Parallel coroutines orchestrator
├── HeuristicAnalyzer.kt    ← 11 pattern checks (offline, instant)
├── ThreatDatabase.kt       ← SQLite lookup (45+ domains, offline)
├── SslChecker.kt           ← SSL/HTTPS validation
├── DomainAgeChecker.kt     ← RDAP domain age (optional internet)
├── Humanizer.kt            ← Gemini AI + fallback templates
├── NotificationHelper.kt   ← 3-tier notification system
├── ScanHistoryStore.kt     ← SharedPreferences history
├── MainActivity.kt         ← Dashboard UI
└── SettingsActivity.kt     ← Gemini key + preferences
```
