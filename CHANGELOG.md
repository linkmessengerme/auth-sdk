# Changelog

## 0.2.0 — 2026-11-23

Device attestation. Requires a Link server that advertises `link_attestation`; with
any other server the SDK behaves as 0.1.0.

- A hardware key per installation: Android Key Attestation (EC P-256 in the
  AndroidKeyStore, StrongBox first, then the TEE) and Apple App Attest. It is
  registered once, before Link is opened for the first sign-in, and survives sign-out.
- The code exchange and every token refresh are signed by this key, which binds the
  session to the device.
- A signed refresh whose answer was lost is repeated under the next attempt number,
  up to 8 times, instead of ending the session. A session without a key behaves as
  before.
- The server's signing keys are fetched before the code or the refresh token is sent.
- `UserIdentity.deviceTrust`: the `device_trust` claim of the ID token.
- New error code `AttestationRequired`.
- `LinkAuth.create(..., attestation = false)` turns attestation off.
- Devices that cannot attest (Android 6, iOS 13, the simulator, hardware or Apple
  service failures) sign in without a key; the server decides.
- iOS apps need the App Attest capability and a Team ID in Link Console.

Notes for upgrading:

- No code changes are required. `ErrorCode` has a new case; add it to exhaustive
  `when` / `switch` statements.
- Custom `SecureStorage` implementations must accept a second record name,
  `link.attest.v1.<digest>`, next to `link.auth.v1.<digest>`.
- A session with an attested key cannot be read by 0.1.0; sign in again after a
  downgrade.

## 0.1.0 — 2026-11-20

First public release.

- Login with Link for iOS and Android: Authorization Code with PKCE (S256) and
  OpenID Connect, with the consent shown in the Link app.
- ID token verification on the device: EdDSA signature by `kid`, issuer, audience,
  `azp`, expiry, `iat`, nonce and `at_hash` when present.
- Sessions restored from secure storage after a restart, including a sign-in that was
  pending when the process died.
- Refresh with token rotation; the previous subject and scope reduction are checked.
- Durable journal: a one-time code or refresh token is marked as used before the
  request, and new tokens are returned only after they are stored.
- `getUserInfo()` for fresh profile data and the phone number under the `phone` scope.
- Optional backend nonce for sign-in with your own backend.
- Sign-out that disables the local session first and reports a pending revocation
  when the server cannot be reached.
- Swift package with URLSession and Keychain adapters; Android library with OkHttp
  and AndroidKeyStore adapters.
- Demo apps for both platforms.
