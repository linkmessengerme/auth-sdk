package me.linkmessenger.auth.demo

import android.app.Application

class DemoApplication : Application() {
    // The SDK and pending signIn outlive Activity recreation and the switch to Link.
    val coordinator: AuthCoordinator by lazy { AuthCoordinator(this) }
}
