package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nd4y/acme-proxy/internal/audit"
	"github.com/nd4y/acme-proxy/internal/config"
	"github.com/nd4y/acme-proxy/internal/ratelimit"
	"github.com/nd4y/acme-proxy/internal/state"
)

const testToken = "test-client-token-0123456789"

const testConfig = `
providers:
  main:
    type: memory
    zones: ["example.com"]
clients:
  panel:
    token: "test-client-token-0123456789"
    provider: main
    allow:
      - "*.edge.example.com"
      - "svc1.example.com"
`

func newTestServer(t *testing.T) (http.Handler, *state.Store) {
	t.Helper()

	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	snapshot, err := state.Build(cfg)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	store := state.NewStore(snapshot)

	srv := New(Options{
		Store:   store,
		Limiter: ratelimit.New(cfg.RateLimit.PerClientPerMinute),
		Audit:   audit.New(io.Discard),
		Log:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})

	return srv.Handler(), store
}

func do(t *testing.T, handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return rec
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not an error object: %s", rec.Body.String())
	}

	return body.Error
}

func TestAuth(t *testing.T) {
	handler, _ := newTestServer(t)

	rec := do(t, handler, http.MethodGet, "/v1/policy", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: status %d", rec.Code)
	}

	rec = do(t, handler, http.MethodGet, "/v1/policy", "nope", "")
	if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != CodeUnauthorized {
		t.Fatalf("wrong token: status %d body %s", rec.Code, rec.Body)
	}
}

func TestPolicyEndpoint(t *testing.T) {
	handler, _ := newTestServer(t)

	rec := do(t, handler, http.MethodGet, "/v1/policy", testToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}

	var body policyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.Client != "panel" || len(body.Allow) != 2 || body.Provider.Type != "memory" {
		t.Fatalf("unexpected policy: %+v", body)
	}
}

func TestPresentAndCleanup(t *testing.T) {
	handler, store := newTestServer(t)

	const (
		fqdn  = "_acme-challenge.edge.example.com"
		value = "token-value"
	)

	rec := do(t, handler, http.MethodPost, "/v1/dns-01/present", testToken,
		`{"fqdn":"`+fqdn+`","value":"`+value+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("present: status %d body %s", rec.Code, rec.Body)
	}

	if !hasRecord(t, store, fqdn, value) {
		t.Fatal("record was not created")
	}

	// The same pair again must be accepted without creating a duplicate.
	rec = do(t, handler, http.MethodPost, "/v1/dns-01/present", testToken,
		`{"fqdn":"`+fqdn+`","value":"`+value+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeat present: status %d body %s", rec.Code, rec.Body)
	}

	if got := countRecords(t, store, fqdn); got != 1 {
		t.Fatalf("present is not idempotent: %d records", got)
	}

	rec = do(t, handler, http.MethodPost, "/v1/dns-01/cleanup", testToken,
		`{"fqdn":"`+fqdn+`","value":"`+value+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cleanup: status %d body %s", rec.Code, rec.Body)
	}

	if hasRecord(t, store, fqdn, value) {
		t.Fatal("record was not removed")
	}

	// Cleaning up something that is gone is not an error: the issuance flow
	// calls cleanup from a defer and must not fail because of it.
	rec = do(t, handler, http.MethodPost, "/v1/dns-01/cleanup", testToken,
		`{"fqdn":"`+fqdn+`","value":"`+value+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("repeat cleanup: status %d body %s", rec.Code, rec.Body)
	}
}

func TestPersistUpsert(t *testing.T) {
	handler, store := newTestServer(t)

	const fqdn = "_validation-persist.edge.example.com"

	rec := do(t, handler, http.MethodPut, "/v1/persist", testToken,
		`{"fqdn":"`+fqdn+`","value":"letsencrypt.org; accounturi=https://acme/acct/1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish: status %d body %s", rec.Code, rec.Body)
	}

	rec = do(t, handler, http.MethodPut, "/v1/persist", testToken,
		`{"fqdn":"`+fqdn+`","value":"letsencrypt.org; accounturi=https://acme/acct/2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("republish: status %d body %s", rec.Code, rec.Body)
	}

	if got := countRecords(t, store, fqdn); got != 1 {
		t.Fatalf("persist record must be unique per name, got %d", got)
	}

	if !hasRecord(t, store, fqdn, "letsencrypt.org; accounturi=https://acme/acct/2") {
		t.Fatal("persist record was not replaced")
	}

	rec = do(t, handler, http.MethodDelete, "/v1/persist", testToken, `{"fqdn":"`+fqdn+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d body %s", rec.Code, rec.Body)
	}

	if got := countRecords(t, store, fqdn); got != 0 {
		t.Fatalf("persist record was not deleted, got %d", got)
	}
}

func TestPolicyEnforcement(t *testing.T) {
	handler, _ := newTestServer(t)

	tests := []struct {
		name   string
		path   string
		method string
		body   string
		status int
		code   string
	}{
		{
			name:   "domain outside the allow list",
			method: http.MethodPost,
			path:   "/v1/dns-01/present",
			body:   `{"fqdn":"_acme-challenge.other.example.com","value":"v"}`,
			status: http.StatusForbidden,
			code:   CodeForbidden,
		},
		{
			name:   "name without the acme prefix",
			method: http.MethodPost,
			path:   "/v1/dns-01/present",
			body:   `{"fqdn":"svc1.example.com","value":"v"}`,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidFQDN,
		},
		{
			name:   "persist name is not a challenge name",
			method: http.MethodPost,
			path:   "/v1/dns-01/present",
			body:   `{"fqdn":"_validation-persist.edge.example.com","value":"v"}`,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidFQDN,
		},
		{
			name:   "challenge name is not a persist name",
			method: http.MethodPut,
			path:   "/v1/persist",
			body:   `{"fqdn":"_acme-challenge.edge.example.com","value":"v"}`,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidFQDN,
		},
		{
			name:   "unknown field in the body",
			method: http.MethodPost,
			path:   "/v1/dns-01/present",
			body:   `{"fqdn":"_acme-challenge.edge.example.com","value":"v","type":"A"}`,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidBody,
		},
		{
			name:   "missing value",
			method: http.MethodPost,
			path:   "/v1/dns-01/present",
			body:   `{"fqdn":"_acme-challenge.edge.example.com"}`,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, handler, tt.method, tt.path, testToken, tt.body)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.status, rec.Body)
			}

			if got := errorCode(t, rec); got != tt.code {
				t.Fatalf("error code = %q, want %q", got, tt.code)
			}
		})
	}
}

func TestUnknownZoneIsRejected(t *testing.T) {
	cfg, err := config.Parse([]byte(`
providers:
  main:
    type: memory
    zones: ["other.test"]
clients:
  panel:
    token: "test-client-token-0123456789"
    provider: main
    allow: ["*.edge.example.com"]
`))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	snapshot, err := state.Build(cfg)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	srv := New(Options{
		Store:   state.NewStore(snapshot),
		Limiter: ratelimit.New(cfg.RateLimit.PerClientPerMinute),
		Audit:   audit.New(io.Discard),
		Log:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})

	rec := do(t, srv.Handler(), http.MethodPost, "/v1/dns-01/present", testToken,
		`{"fqdn":"_acme-challenge.edge.example.com","value":"v"}`)

	if rec.Code != http.StatusUnprocessableEntity || errorCode(t, rec) != CodeNoZone {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestRateLimit(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig + "rate_limit:\n  per_client_per_minute: 1\n"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	snapshot, err := state.Build(cfg)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	srv := New(Options{
		Store:   state.NewStore(snapshot),
		Limiter: ratelimit.New(cfg.RateLimit.PerClientPerMinute),
		Audit:   audit.New(io.Discard),
		Log:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})

	handler := srv.Handler()

	if rec := do(t, handler, http.MethodGet, "/v1/policy", testToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("first request: status %d", rec.Code)
	}

	rec := do(t, handler, http.MethodGet, "/v1/policy", testToken, "")
	if rec.Code != http.StatusTooManyRequests || errorCode(t, rec) != CodeRateLimited {
		t.Fatalf("second request: status %d body %s", rec.Code, rec.Body)
	}
}

func TestHealth(t *testing.T) {
	handler, _ := newTestServer(t)

	if rec := do(t, handler, http.MethodGet, "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz: status %d", rec.Code)
	}
}

func TestClientDisconnectDoesNotCancelWrite(t *testing.T) {
	handler, store := newTestServer(t)

	const (
		fqdn  = "_acme-challenge.edge.example.com"
		value = "abandoned-token"
	)

	// The client gave up before the provider finished: its request context is
	// already cancelled when the mutation starts. The write must still happen —
	// an aborted DNS operation leaves the zone in a state neither side knows
	// about. The memory provider honors cancellation, so without the detached
	// context this returns a provider error and no record.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := httptest.NewRequest(http.MethodPost, "/v1/dns-01/present",
		strings.NewReader(`{"fqdn":"`+fqdn+`","value":"`+value+`"}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testToken)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}

	if !hasRecord(t, store, fqdn, value) {
		t.Fatal("the write was cancelled together with the client")
	}
}

func hasRecord(t *testing.T, store *state.Store, fqdn, value string) bool {
	t.Helper()

	for _, rr := range zoneRecords(t, store, fqdn) {
		if rr.Data == value {
			return true
		}
	}

	return false
}

func countRecords(t *testing.T, store *state.Store, fqdn string) int {
	t.Helper()

	return len(zoneRecords(t, store, fqdn))
}

// zoneRecords reads back what the memory provider stored for the record name.
func zoneRecords(t *testing.T, store *state.Store, fqdn string) []libdnsRR {
	t.Helper()

	snapshot := store.Get()

	entry, ok := snapshot.Providers["main"]
	if !ok {
		t.Fatal("provider main is missing")
	}

	records, err := entry.TXTRecords(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("records: %v", err)
	}

	out := make([]libdnsRR, 0, len(records))
	for _, record := range records {
		rr := record.RR()
		out = append(out, libdnsRR{Name: rr.Name, Type: rr.Type, Data: rr.Data})
	}

	return out
}

type libdnsRR struct {
	Name string
	Type string
	Data string
}
