import java.util.Properties

plugins {
    id("com.android.library") version "8.6.1"
    id("org.jetbrains.kotlin.android") version "1.9.21"
    id("maven-publish")
}

group = "me.linkmessenger"
version = "0.2.0"

android {
    namespace = "me.linkmessenger.auth"
    compileSdk = 34
    providers.environmentVariable("ANDROID_NDK_HOME").orNull?.let { ndkHome ->
        ndkPath = ndkHome
        val ndkProperties = Properties().apply {
            file("$ndkHome/source.properties").inputStream().use { load(it) }
        }
        ndkVersion = ndkProperties.getProperty("Pkg.Revision")
    }
    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") }
    }
    sourceSets["main"].java.srcDir("../../bindings/generated")
    sourceSets["main"].jniLibs.srcDir(layout.buildDirectory.dir("generated/jniLibs"))
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17"; allWarningsAsErrors = true }
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    api("net.java.dev.jna:jna:5.17.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

val verifyNativeLibraries by tasks.registering {
    doLast {
        for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86_64")) {
            val library = layout.buildDirectory.file("generated/jniLibs/$abi/liblink_auth_ffi.so").get().asFile
            check(library.isFile && library.length() > 0) {
                "Missing Rust library for $abi. Run scripts/build-android.sh from the SDK root."
            }
        }
        check(file("../../bindings/generated/me/linkmessenger/auth/generated/link_auth_ffi.kt").isFile) {
            "Generate UniFFI bindings first."
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyNativeLibraries) }

publishing {
    repositories { maven { name = "sdkBundle"; url = uri(layout.buildDirectory.dir("repository")) } }
    publications {
        register<MavenPublication>("release") {
            artifactId = "link-auth"
            pom {
                name.set("Link Auth Android")
                description.set("Login with Link: Kotlin facade and Rust protocol core")
            }
            afterEvaluate { from(components["release"]) }
        }
    }
}
dependencyLocking { lockAllConfigurations() }
