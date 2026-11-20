import java.util.Properties

plugins {
    id("com.android.application") version "8.6.1"
    id("org.jetbrains.kotlin.android") version "1.9.21"
}
android {
    namespace = "me.linkmessenger.auth.packagecheck"
    compileSdk = 34
    providers.environmentVariable("ANDROID_NDK_HOME").orNull?.let { ndkHome ->
        ndkPath = ndkHome
        val ndkProperties = Properties().apply {
            file("$ndkHome/source.properties").inputStream().use { load(it) }
        }
        ndkVersion = ndkProperties.getProperty("Pkg.Revision")
    }
    defaultConfig {
        applicationId = "me.linkmessenger.auth.packagecheck"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17"; allWarningsAsErrors = true }
    buildTypes.getByName("release") {
        isMinifyEnabled = true
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
    }
}
dependencies { implementation("me.linkmessenger:link-auth:0.1.0") }
