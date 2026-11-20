plugins {
    id("com.android.application") version "8.6.1"
    id("org.jetbrains.kotlin.android") version "1.9.21"
}

val demoKeyStore = layout.projectDirectory.file(".local/debug.keystore")
val prepareDemoKey by tasks.registering(Exec::class) {
    description = "Create a local debug certificate for this demo, once."
    outputs.file(demoKeyStore)
    onlyIf { !demoKeyStore.asFile.exists() }
    doFirst { demoKeyStore.asFile.parentFile.mkdirs() }
    commandLine(
        "${System.getProperty("java.home")}/bin/keytool", "-genkeypair", "-noprompt",
        "-keystore", demoKeyStore.asFile.absolutePath, "-storepass", "android",
        "-alias", "androiddebugkey", "-keypass", "android", "-keyalg", "RSA",
        "-keysize", "2048", "-validity", "10000", "-dname", "CN=Link Auth Demo, O=Android, C=US",
    )
}

android {
    namespace = "me.linkmessenger.auth.demo"
    compileSdk = 34
    defaultConfig {
        applicationId = "me.linkmessenger.auth.demo"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-local"
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
        manifestPlaceholders["authCallbackScheme"] = applicationId!!
    }
    signingConfigs.getByName("debug") {
        storeFile = demoKeyStore.asFile
        storePassword = "android"
        keyAlias = "androiddebugkey"
        keyPassword = "android"
    }
    buildTypes.getByName("release") {
        isMinifyEnabled = true
        proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17"; allWarningsAsErrors = true }
    buildFeatures { viewBinding = true; buildConfig = true }
    // The SDK bundle already contains release binaries. Consuming it needs no NDK.
    packaging { jniLibs { keepDebugSymbols += "**/*.so" } }
    // Optional local Console config. It is intentionally outside tracked sources.
    sourceSets["main"].assets.srcDir(".local/assets")
}

tasks.matching { it.name == "preBuild" || it.name == "signingReport" || it.name == "validateSigningDebug" }
    .configureEach { dependsOn(prepareDemoKey) }

dependencies {
    implementation("me.linkmessenger:link-auth:0.1.0")
    implementation("androidx.activity:activity-ktx:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}

dependencyLocking { lockAllConfigurations() }
