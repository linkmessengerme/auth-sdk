pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri("../../platforms/android/build/repository") }
        google()
        mavenCentral()
    }
}
rootProject.name = "link-auth-package-check"
