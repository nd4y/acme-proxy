package config

import (
	"strings"
	"testing"
)

const validConfig = `
listen: ":9000"
ttl_seconds: 30
providers:
  main:
    type: memory
    api_token: ${TEST_PROVIDER_TOKEN}
    zones: ["Example.COM."]
clients:
  panel:
    token: ${TEST_CLIENT_TOKEN}
    provider: main
    allow:
      - "*.Edge.Example.com"
rate_limit:
  per_client_per_minute: 10
`

func TestParseValid(t *testing.T) {
	t.Setenv("TEST_PROVIDER_TOKEN", "provider-secret")
	t.Setenv("TEST_CLIENT_TOKEN", "client-secret-token-1234")

	cfg, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != ":9000" {
		t.Fatalf("listen = %q", cfg.Listen)
	}

	if got := cfg.Providers["main"].APIToken; got != "provider-secret" {
		t.Fatalf("provider token was not expanded: %q", got)
	}

	if got := cfg.Providers["main"].Zones[0]; got != "example.com" {
		t.Fatalf("zone was not normalized: %q", got)
	}

	if got := cfg.Clients["panel"].Allow[0]; got != "*.edge.example.com" {
		t.Fatalf("allow pattern was not normalized: %q", got)
	}

	name, client, ok := cfg.Lookup("client-secret-token-1234")
	if !ok || name != "panel" || client.Provider != "main" {
		t.Fatalf("Lookup returned %q, %+v, %v", name, client, ok)
	}

	if _, _, ok := cfg.Lookup("wrong"); ok {
		t.Fatal("Lookup accepted a wrong token")
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
providers:
  main:
    type: memory
    zones: ["example.com"]
clients:
  panel:
    token: "0123456789abcdef"
    provider: main
    allow: ["example.com"]
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != DefaultListen {
		t.Fatalf("listen default = %q", cfg.Listen)
	}

	if cfg.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl default = %d", cfg.TTLSeconds)
	}

	if cfg.RateLimit.PerClientPerMinute != DefaultRatePerMinute {
		t.Fatalf("rate limit default = %d", cfg.RateLimit.PerClientPerMinute)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown key",
			yaml: "providers:\n  main:\n    type: memory\n    zones: [\"example.com\"]\n    tokne: x\n",
			want: "field tokne not found",
		},
		{
			name: "unknown provider type",
			yaml: "providers:\n  main:\n    type: bind9\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"0123456789abcdef\"\n    provider: main\n    allow: [\"example.com\"]\n",
			want: "unknown type",
		},
		{
			name: "short token",
			yaml: "providers:\n  main:\n    type: memory\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"short\"\n    provider: main\n    allow: [\"example.com\"]\n",
			want: "at least 16 characters",
		},
		{
			name: "unknown provider reference",
			yaml: "providers:\n  main:\n    type: memory\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"0123456789abcdef\"\n    provider: other\n    allow: [\"example.com\"]\n",
			want: "unknown provider",
		},
		{
			name: "too broad pattern",
			yaml: "providers:\n  main:\n    type: memory\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"0123456789abcdef\"\n    provider: main\n    allow: [\"*.com\"]\n",
			want: "too broad",
		},
		{
			name: "shared token",
			yaml: "providers:\n  main:\n    type: memory\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"0123456789abcdef\"\n    provider: main\n    allow: [\"example.com\"]\n  b:\n    token: \"0123456789abcdef\"\n    provider: main\n    allow: [\"example.com\"]\n",
			want: "share the same token",
		},
		{
			name: "missing env",
			yaml: "providers:\n  main:\n    type: memory\n    api_token: ${DEFINITELY_UNSET_VAR_FOR_TEST}\n    zones: [\"example.com\"]\nclients:\n  a:\n    token: \"0123456789abcdef\"\n    provider: main\n    allow: [\"example.com\"]\n",
			want: "undefined environment variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected an error")
			}

			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}
