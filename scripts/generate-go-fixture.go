//go:build ignore

// Generates a public test fixture with Go's standard crypto/ed25519, matching
// the Link authorization server's signer and claims format. The fixed seed is TEST MATERIAL ONLY.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 42
	}
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, x)
	thumbprint := sha256.Sum256([]byte(canonical))
	kid := base64.RawURLEncoding.EncodeToString(thumbprint[:])
	header := map[string]any{"alg": "EdDSA", "kid": kid, "typ": "JWT"}
	claims := map[string]any{
		"iss": "https://login.example.test", "sub": "go-signed-pairwise-sub",
		"aud": []string{"lk_client_sdk_test"}, "azp": "lk_client_sdk_test",
		"iat": 1790000000, "exp": 1790003600, "nonce": "go-fixture-nonce",
		"name": "Go Fixture", "preferred_username": "go_fixture",
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input)))
	fixture := map[string]any{
		"now": 1790000000, "nonce": "go-fixture-nonce",
		"jwks":     map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "EdDSA", "use": "sig", "kid": kid}}},
		"response": map[string]any{"access_token": "go-fixture-access-token", "id_token": token, "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile"},
	}
	output, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		panic(err)
	}
	if len(os.Args) != 2 {
		panic("usage: go run generate-go-fixture.go OUTPUT.json")
	}
	if err = os.WriteFile(os.Args[1], append(output, '\n'), 0644); err != nil {
		panic(err)
	}
}
