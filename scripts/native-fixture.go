//go:build ignore

// Loopback-only fixture, using a PUBLIC TEST signing seed. Never run as a service.
// Exercises native HTTP -> UniFFI -> Rust with Go's Ed25519/JWT wire format.
//
// Device attestation (contract version 1) is served under path prefixes that
// contain /attest-report, /attest-required or /attest-off; every other prefix
// behaves like a server that knows nothing about attestation. The fixture
// follows the server's rules for token requests: proofs are checked before
// anything is spent, a session is bound to its key, and a refresh whose answer
// was lost may be repeated by the same key under a higher attempt number.
// It does NOT verify a real attestation: a test client uploads its public key
// (SubjectPublicKeyInfo) followed by the challenge in place of a certificate chain.
//
//	GET /arm?prefix=P&fault=F&times=N   the next N matching requests fail:
//	    challenge-503, keys-400, keys-lose, refresh-lose, refresh-503,
//	    refresh-429, proof-invalid, retry-refused
//	GET /act?prefix=P&do=forget-keys|revoke-keys
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

func encoded(value any) string {
	data, _ := json.Marshal(value)
	return b64.EncodeToString(data)
}

type attestedKey struct {
	prefix  string
	public  *ecdsa.PublicKey
	revoked bool
}

type refreshRow struct {
	prefix  string
	session int
	used    bool
	revoked bool
	attempt int // attempt number of the accepted proof, -1 without one
	parent  string
}

type sessionRow struct {
	key     string // key_id the session is bound to
	revoked bool
}

func attestMode(prefix string) string {
	switch {
	case strings.Contains(prefix, "/attest-required"):
		return "required"
	case strings.Contains(prefix, "/attest-report"):
		return "report"
	case strings.Contains(prefix, "/attest-off"):
		return "off"
	}
	return ""
}

// The string a token request is signed over, built independently of the SDK.
func proofMessage(purpose, clientID, keyID, secret string, attempt int) []byte {
	digest := sha256.Sum256([]byte(secret))
	return []byte(strings.Join([]string{"link-login-attest-v1", purpose, clientID, keyID,
		b64.EncodeToString(digest[:]), strconv.Itoa(attempt)}, "\n"))
}

func dropConnection(w http.ResponseWriter) {
	if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
		_ = conn.Close()
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: native-fixture READY_FILE")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	base := "http://" + listener.Addr().String()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("*", ed25519.SeedSize)))
	pub := key.Public().(ed25519.PublicKey)
	var gate sync.Mutex
	counts := map[string]int{}
	consumed := map[string]bool{}
	refreshes := map[string]*refreshRow{}
	accesses := map[string]string{}
	sessions := []*sessionRow{}
	challenges := map[string]string{}
	keys := map[string]*attestedKey{}
	armed := map[string]int{}
	sequence := 0
	// Call with the gate held.
	take := func(prefix, fault string) bool {
		if armed[prefix+"|"+fault] > 0 {
			armed[prefix+"|"+fault]--
			return true
		}
		return false
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/stats" {
			gate.Lock()
			defer gate.Unlock()
			_ = json.NewEncoder(w).Encode(counts)
			return
		}
		if r.URL.Path == "/arm" || r.URL.Path == "/act" {
			gate.Lock()
			defer gate.Unlock()
			query := r.URL.Query()
			prefix := query.Get("prefix")
			if r.URL.Path == "/arm" {
				times, _ := strconv.Atoi(query.Get("times"))
				armed[prefix+"|"+query.Get("fault")] = times
			} else {
				for id, key := range keys {
					if key.prefix != prefix {
						continue
					}
					switch query.Get("do") {
					case "forget-keys":
						delete(keys, id)
					case "revoke-keys":
						key.revoked = true
					}
				}
			}
			_, _ = w.Write([]byte("{}"))
			return
		}
		gate.Lock()
		counts[r.URL.Path]++
		gate.Unlock()
		prefix, endpoint, found := strings.Cut(r.URL.Path, "/oauth/v1/")
		if !found {
			prefix = strings.TrimSuffix(r.URL.Path, "/.well-known/openid-configuration")
		}
		apiBase := base + prefix
		issuer := apiBase
		// The root fixture models regional ingress to a shared AS. Its issuer
		// is deliberately unreachable: native clients must use api_base_url.
		if prefix == "" {
			issuer = "https://login.example.test"
		}
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration") {
			switch {
			case strings.HasSuffix(prefix, "/redirect"):
				http.Redirect(w, r, base+"/followed", http.StatusFound)
				return
			case strings.HasSuffix(prefix, "/oversize"):
				// Chunked response, so the adapter must enforce the limit while reading.
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte(strings.Repeat("x", 262_145)))
				return
			case strings.HasSuffix(prefix, "/slow"):
				select {
				case <-r.Context().Done():
					return
				case <-time.After(3 * time.Second):
				}
			}
			discovery := map[string]any{
				"issuer": issuer, "authorization_endpoint": "https://linkm.me/oauth/authorize",
				"token_endpoint": apiBase + "/oauth/v1/token", "jwks_uri": apiBase + "/oauth/v1/jwks.json",
				"revocation_endpoint": apiBase + "/oauth/v1/revoke", "response_types_supported": []string{"code"},
				"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
				"id_token_signing_alg_values_supported":          []string{"EdDSA"},
				"token_endpoint_auth_methods_supported":          []string{"none"},
				"code_challenge_methods_supported":               []string{"S256"},
				"scopes_supported":                               []string{"openid", "profile", "offline_access", "phone"},
				"authorization_response_iss_parameter_supported": true,
			}
			if attestMode(prefix) != "" {
				discovery["link_attestation"] = map[string]any{"versions": []string{"1"},
					"challenge_endpoint": apiBase + "/oauth/v1/attest/challenge",
					"keys_endpoint":      apiBase + "/oauth/v1/attest/keys"}
			}
			_ = json.NewEncoder(w).Encode(discovery)
			return
		}
		mode := attestMode(prefix)
		refuse := func(reason string) {
			status, code := 401, "invalid_client"
			switch reason {
			case "retry_refused":
				status, code = 400, "invalid_grant"
			case "challenge_invalid", "attestation_invalid":
				status, code = 400, "invalid_request"
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "attestation_error": reason})
		}
		unavailable := func(status int) {
			if status == 429 {
				w.Header().Set("Retry-After", "60")
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		}
		if endpoint == "attest/challenge" || endpoint == "attest/keys" {
			r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
			if r.Method != "POST" || r.ParseForm() != nil {
				w.WriteHeader(400)
				return
			}
			gate.Lock()
			defer gate.Unlock()
			if r.Form.Get("client_id") != "lk_client_sdk_test" {
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			if endpoint == "attest/challenge" {
				if take(prefix, "challenge-503") {
					unavailable(503)
					return
				}
				if mode != "report" && mode != "required" {
					_, _ = w.Write([]byte(`{"mode":"off"}`))
					return
				}
				raw := make([]byte, 32)
				_, _ = rand.Read(raw)
				challenge := b64.EncodeToString(raw)
				challenges[challenge] = prefix
				_ = json.NewEncoder(w).Encode(map[string]any{"mode": mode, "challenge": challenge, "expires_in": 300})
				return
			}
			challenge := r.Form.Get("challenge")
			if challenges[challenge] != prefix || mode == "" {
				refuse("challenge_invalid")
				return
			}
			delete(challenges, challenge)
			// Stand-in for a certificate chain: the public key, then the challenge.
			parts := strings.Split(r.Form.Get("certificate_chain"), ".")
			var public *ecdsa.PublicKey
			if r.Form.Get("platform") == "android" && len(parts) == 2 {
				spki, err1 := b64.DecodeString(parts[0])
				bound, err2 := b64.DecodeString(parts[1])
				if parsed, err := x509.ParsePKIXPublicKey(spki); err == nil && err1 == nil && err2 == nil &&
					b64.EncodeToString(bound) == challenge {
					if key, ok := parsed.(*ecdsa.PublicKey); ok && key.Curve == elliptic.P256() {
						public = key
					}
				}
			}
			if public == nil || take(prefix, "keys-400") {
				refuse("attestation_invalid")
				return
			}
			raw := make([]byte, 16)
			_, _ = rand.Read(raw)
			id := "ak_" + b64.EncodeToString(raw)
			keys[id] = &attestedKey{prefix: prefix, public: public}
			if take(prefix, "keys-lose") {
				dropConnection(w)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"key_id": id, "level": "verified"})
			return
		}
		if endpoint == "jwks.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(pub), "kid": "native-fixture", "alg": "EdDSA", "use": "sig",
			}}})
			return
		}
		if endpoint == "revoke" {
			w.Header().Del("Content-Type")
			w.WriteHeader(200)
			return
		}
		if endpoint == "userinfo" {
			gate.Lock()
			defer gate.Unlock()
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			bound, exists := accesses[token]
			if r.Method != http.MethodGet || !ok || !exists || bound != prefix {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			data := map[string]any{"sub": "native-test-sub", "name": "Fresh Native Name"}
			if strings.HasSuffix(prefix, "/phone") {
				data["phone_number"] = "+12025550123"
			}
			_ = json.NewEncoder(w).Encode(data)
			return
		}
		if endpoint != "token" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
		if r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		gate.Lock()
		defer gate.Unlock()
		counts[r.URL.Path+"/"+r.Form.Get("grant_type")]++
		fail := func() { w.WriteHeader(400); _, _ = w.Write([]byte(`{"error":"invalid_grant"}`)) }
		if r.Form.Get("client_id") != "lk_client_sdk_test" {
			fail()
			return
		}
		// The proof of this request: key "" means it carries none; a reason
		// means it must be refused. Nothing is spent while it is checked.
		proof := func(purpose, secret string) (key string, attempt int, reason string) {
			key, number, value := r.Form.Get("attest_key_id"), r.Form.Get("attest_attempt"), r.Form.Get("attest_proof")
			if key == "" && number == "" && value == "" {
				return "", 0, ""
			}
			attempt, err := strconv.Atoi(number)
			if err != nil || attempt < 0 || attempt > 8 || strconv.Itoa(attempt) != number || key == "" || value == "" ||
				(purpose == "code" && attempt != 0) {
				return "", 0, "proof_invalid"
			}
			stored := keys[key]
			if stored == nil || stored.prefix != prefix {
				return "", 0, "key_unknown"
			}
			if stored.revoked {
				return "", 0, "key_revoked"
			}
			signature, err := b64.DecodeString(value)
			digest := sha256.Sum256(proofMessage(purpose, r.Form.Get("client_id"), key, secret, attempt))
			if err != nil || !ecdsa.VerifyASN1(stored.public, digest[:], signature) {
				return "", 0, "proof_invalid"
			}
			return key, attempt, ""
		}
		attesting := mode == "report" || mode == "required"
		nonce := ""
		session := 0
		parent := ""
		lose := false
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			code := r.Form.Get("code")
			bound := ""
			if attesting {
				key, _, reason := proof("code", code)
				switch {
				case mode == "report":
					if reason == "" {
						bound = key
					}
				case reason != "":
					refuse(reason)
					return
				case key == "":
					refuse("required")
					return
				default:
					bound = key
				}
			}
			bytes, err := b64.DecodeString(code)
			var data struct{ Nonce, Challenge string }
			if err != nil || json.Unmarshal(bytes, &data) != nil || consumed[code] {
				fail()
				return
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if data.Challenge != b64.EncodeToString(challenge[:]) || data.Nonce == "" || r.Form.Get("redirect_uri") != "com.example.app://oauth/callback" {
				fail()
				return
			}
			consumed[code] = true
			nonce = data.Nonce
			sessions = append(sessions, &sessionRow{key: bound})
			session = len(sessions) - 1
		case "refresh_token":
			token := r.Form.Get("refresh_token")
			row := refreshes[token]
			if row == nil || row.prefix != prefix || row.revoked || sessions[row.session].revoked {
				fail()
				return
			}
			switch {
			case take(prefix, "refresh-503"):
				unavailable(503)
				return
			case take(prefix, "refresh-429"):
				unavailable(429)
				return
			case take(prefix, "proof-invalid"):
				refuse("proof_invalid")
				return
			case take(prefix, "retry-refused"):
				refuse("retry_refused")
				return
			}
			session = row.session
			current := sessions[session]
			proven, attempt, bind := false, 0, ""
			if current.key != "" || attesting {
				key, number, reason := proof("refresh", token)
				if current.key != "" {
					if reason != "" {
						refuse(reason)
						return
					}
					if key != current.key {
						refuse("proof_invalid")
						return
					}
					proven, attempt = true, number
				} else if reason == "" && key != "" {
					proven, attempt, bind = true, number, key
				}
			}
			if row.used {
				// Only the key the session is bound to may repeat a spent token.
				if !proven || bind != "" {
					current.revoked = true
					fail()
					return
				}
				if row.attempt >= 0 && attempt <= row.attempt {
					refuse("retry_refused")
					return
				}
				for _, next := range refreshes {
					if next.parent == token && next.used {
						current.revoked = true
						fail()
						return
					}
				}
				for _, next := range refreshes {
					if next.parent == token {
						next.revoked = true
					}
				}
			}
			row.used = true
			if proven {
				row.attempt = attempt
				if bind != "" {
					current.key = bind
				}
			}
			parent = token
			if strings.HasSuffix(prefix, "/slow-refresh") {
				time.Sleep(400 * time.Millisecond)
			}
			if strings.HasSuffix(prefix, "/drop") {
				dropConnection(w)
				return
			}
			if strings.HasSuffix(prefix, "/retry") {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(503)
				return
			}
			// The answer is lost after the new token has been issued.
			lose = take(prefix, "refresh-lose")
		default:
			fail()
			return
		}
		sequence++
		refresh := fmt.Sprintf("native-test-refresh-%d", sequence)
		refreshes[refresh] = &refreshRow{prefix: prefix, session: session, attempt: -1, parent: parent}
		if lose {
			dropConnection(w)
			return
		}
		now := time.Now().Unix()
		claims := map[string]any{"iss": issuer, "sub": "native-test-sub", "aud": []string{"lk_client_sdk_test"},
			"azp": "lk_client_sdk_test", "iat": now, "exp": now + 3600, "name": "Native Fixture"}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		if attesting {
			claims["device_trust"] = "none"
			if sessions[session].key != "" {
				claims["device_trust"] = "verified"
			}
			// A claim no SDK version knows: it must be ignored.
			claims["link_future_claim"] = map[string]any{"version": 2}
		}
		input := encoded(map[string]string{"alg": "EdDSA", "kid": "native-fixture", "typ": "JWT"}) + "." + encoded(claims)
		token := input + "." + b64.EncodeToString(ed25519.Sign(key, []byte(input)))
		access := fmt.Sprintf("native-test-access-%d", sequence)
		accesses[access] = prefix
		scopes := "openid profile offline_access"
		if strings.HasSuffix(prefix, "/phone") {
			scopes += " phone"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access,
			"id_token": token, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 3600, "scope": scopes})
	})
	if err := os.WriteFile(os.Args[1], []byte(base), 0600); err != nil {
		panic(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
