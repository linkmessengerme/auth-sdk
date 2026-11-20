//go:build ignore

// Loopback-only fixture, using a PUBLIC TEST signing seed. Never run as a service.
// Exercises native HTTP -> UniFFI -> Rust with Go's Ed25519/JWT wire format.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

func encoded(value any) string {
	data, _ := json.Marshal(value)
	return b64.EncodeToString(data)
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
	refreshes := map[string]bool{}
	accesses := map[string]string{}
	sequence := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/stats" {
			gate.Lock()
			defer gate.Unlock()
			_ = json.NewEncoder(w).Encode(counts)
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
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": "https://linkm.me/oauth/authorize",
				"token_endpoint": apiBase + "/oauth/v1/token", "jwks_uri": apiBase + "/oauth/v1/jwks.json",
				"revocation_endpoint": apiBase + "/oauth/v1/revoke", "response_types_supported": []string{"code"},
				"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
				"id_token_signing_alg_values_supported":          []string{"EdDSA"},
				"token_endpoint_auth_methods_supported":          []string{"none"},
				"code_challenge_methods_supported":               []string{"S256"},
				"scopes_supported":                               []string{"openid", "profile", "offline_access", "phone"},
				"authorization_response_iss_parameter_supported": true,
			})
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
		nonce := ""
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			code := r.Form.Get("code")
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
		case "refresh_token":
			token := r.Form.Get("refresh_token")
			if !refreshes[token] {
				fail()
				return
			}
			delete(refreshes, token)
			if strings.HasSuffix(prefix, "/slow-refresh") {
				time.Sleep(400 * time.Millisecond)
			}
			if strings.HasSuffix(prefix, "/drop") {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			if strings.HasSuffix(prefix, "/retry") {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(503)
				return
			}
		default:
			fail()
			return
		}
		sequence++
		refresh := fmt.Sprintf("native-test-refresh-%d", sequence)
		refreshes[refresh] = true
		now := time.Now().Unix()
		claims := map[string]any{"iss": issuer, "sub": "native-test-sub", "aud": []string{"lk_client_sdk_test"},
			"azp": "lk_client_sdk_test", "iat": now, "exp": now + 3600, "name": "Native Fixture"}
		if nonce != "" {
			claims["nonce"] = nonce
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
