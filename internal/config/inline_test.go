package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The environment-carried configuration is the same document, only base64'd, so
// what matters is that it goes through the same parsing, defaults and validation
// as a file — including the ${VAR} expansion, which is the whole reason secrets
// are not embedded in it.
func TestParseAcceptsBase64EncodedDocument(t *testing.T) {
	t.Setenv("TEST_INLINE_TOKEN", "client-token-from-environment")

	document := `
providers:
  main:
    type: memory
    zones: ["example.com"]
clients:
  panel:
    token: ${TEST_INLINE_TOKEN}
    provider: main
    allow: ["*.edge.example.com"]
`

	encoded := base64.StdEncoding.EncodeToString([]byte(document))

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	cfg, err := Parse(decoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	name, client, ok := cfg.Lookup("client-token-from-environment")
	if !ok || name != "panel" {
		t.Fatalf("lookup returned %q, %v", name, ok)
	}

	if client.Provider != "main" {
		t.Fatalf("provider = %q", client.Provider)
	}

	if cfg.Listen != DefaultListen || cfg.RateLimit.PerClientPerMinute != DefaultRatePerMinute {
		t.Fatalf("defaults were not applied: %+v", cfg)
	}
}
