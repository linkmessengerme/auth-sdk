# Changelog

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
