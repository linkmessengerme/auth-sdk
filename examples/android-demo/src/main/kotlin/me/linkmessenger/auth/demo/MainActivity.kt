package me.linkmessenger.auth.demo

import android.app.AlertDialog
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputFilter
import android.text.InputType
import android.view.View
import android.widget.EditText
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch
import me.linkmessenger.auth.AndroidLinkOpener
import me.linkmessenger.auth.demo.databinding.ActivityMainBinding

class MainActivity : ComponentActivity() {
    private lateinit var binding: ActivityMainBinding
    private val coordinator get() = (application as DemoApplication).coordinator
    private val importConfig = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) coordinator.importFile(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.callback.text = getString(R.string.callback_details, BuildConfig.APPLICATION_ID, DEMO_CALLBACK)
        binding.importConfig.setOnClickListener { importConfig.launch(arrayOf("*/*")) }
        binding.pasteConfig.setOnClickListener { showConfigDialog() }
        binding.signIn.setOnClickListener { coordinator.signIn(AndroidLinkOpener(this)) }
        binding.cancelSignIn.setOnClickListener { coordinator.cancelSignIn() }
        binding.checkSession.setOnClickListener { coordinator.checkSession(forceRefresh = false) }
        binding.refreshSession.setOnClickListener { coordinator.checkSession(forceRefresh = true) }
        binding.signOut.setOnClickListener { coordinator.signOut() }
        lifecycleScope.launch {
            // Only collection stops in the background; the login belongs to Application.
            repeatOnLifecycle(Lifecycle.State.STARTED) { coordinator.state.collect(::render) }
        }
        consumeCallback(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        consumeCallback(intent)
    }

    private fun consumeCallback(incoming: Intent) {
        if (incoming.action != Intent.ACTION_VIEW) return
        val url = incoming.dataString ?: return
        // Do not replay this Activity's URL on rotation or retain a code in its intent.
        setIntent(Intent(incoming).setData(null))
        coordinator.handleCallback(url)
    }

    private fun showConfigDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.config_hint)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            typeface = Typeface.MONOSPACE
            minLines = 6
            maxLines = 12
            filters = arrayOf(InputFilter.LengthFilter(64 * 1024))
            isSaveEnabled = false
            setPadding(32, 16, 32, 16)
            contentDescription = getString(R.string.paste_config)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.paste_config)
            .setMessage(R.string.public_config_hint)
            .setView(input)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.apply_config) { _, _ -> coordinator.importJson(input.text.toString()) }
            .show()
    }

    private fun render(state: DemoState) = with(binding) {
        progress.visibility = if (state.busy) View.VISIBLE else View.INVISIBLE
        status.text = getString(when {
            state.busy -> R.string.status_working
            state.pending -> R.string.status_waiting
            state.revocationPending -> R.string.status_revoke_pending
            state.recoveryRequired -> R.string.status_reauthentication
            state.session != null -> R.string.status_signed_in
            state.config != null -> R.string.status_ready
            else -> R.string.status_setup
        })
        message.text = state.message
        message.setTextColor(getColor(if (state.error) R.color.error else R.color.text_secondary))
        val config = state.config
        configDetails.text = if (config == null) getString(R.string.config_instructions) else
            getString(R.string.config_details, config.clientId, config.issuer, config.scopes.joinToString(" · "))
        importConfig.isEnabled = state.canConfigure
        pasteConfig.isEnabled = state.canConfigure
        signIn.visibility = if (state.session == null && !state.pending && !state.revocationPending) View.VISIBLE else View.GONE
        signIn.isEnabled = state.canSignIn
        cancelSignIn.visibility = if (state.pending) View.VISIBLE else View.GONE
        cancelSignIn.isEnabled = !state.busy
        profileCard.visibility = if (state.session != null) View.VISIBLE else View.GONE
        state.session?.let { session ->
            val user = session.user
            val name = user.name?.takeIf { it.isNotBlank() } ?: getString(R.string.link_account)
            profileName.text = name
            profileInitial.text = name.take(1).uppercase()
            profileUsername.text = user.preferredUsername?.takeIf { it.isNotBlank() }?.let { "@$it" }
                ?: getString(R.string.no_username)
            profileDetails.text = getString(R.string.profile_details, user.subject,
                user.grantedScopes.joinToString(" · "),
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM)
                    .format(Date(session.expiresAt.toLong() * 1000)),
                // device_trust of the ID token: "verified" for a signed-in user.
                user.deviceTrust ?: getString(R.string.device_trust_absent))
        }
        checkSession.isEnabled = !state.busy && state.session != null
        refreshSession.isEnabled = !state.busy && state.session?.canRefresh == true
        signOut.visibility = if (state.session != null || state.revocationPending || state.recoveryRequired) View.VISIBLE else View.GONE
        signOut.isEnabled = !state.busy && !state.pending
        signOut.setText(if (state.revocationPending) R.string.retry_sign_out else R.string.sign_out)
        eventLog.text = state.events.joinToString("\n\n").ifEmpty { getString(R.string.no_events) }
        listOf(importConfig, pasteConfig, signIn, cancelSignIn, checkSession, refreshSession, signOut).forEach {
            it.alpha = if (it.isEnabled) 1f else 0.45f
        }
    }
}
