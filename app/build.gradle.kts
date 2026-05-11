plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.smishguard"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.smishguard"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.recyclerview)

    // OkHttp (SSL check + domain age RDAP lookup)
    implementation(libs.okhttp)

    // JSON parsing
    implementation(libs.gson)

    // Coroutines (parallel analysis)
    implementation(libs.coroutines.android)

    // Gemini AI (humanized warnings)
    implementation(libs.generativeai)

    // Security & Biometrics
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)

    // Lifecycle (foreground service)
    implementation(libs.lifecycle.service)
}
