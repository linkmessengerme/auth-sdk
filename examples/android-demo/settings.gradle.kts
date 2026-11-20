pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository { maven { url = uri("../../platforms/android/build/repository") } }
            filter { includeGroup("me.linkmessenger") }
        }
        google()
        mavenCentral()
    }
}
rootProject.name = "link-auth-android-demo"
