// Package server exposes the acme-proxy HTTP API.
package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/nd4y/acme-proxy/internal/audit"
	"github.com/nd4y/acme-proxy/internal/config"
	"github.com/nd4y/acme-proxy/internal/ratelimit"
	"github.com/nd4y/acme-proxy/internal/state"
)

// maxBodyBytes caps request bodies. The largest legitimate body is a persistent
// authorization record value, which is a few hundred bytes.
const maxBodyBytes = 8 << 10

// Machine-readable error codes returned in the "error" field.
const (
	CodeUnauthorized  = "unauthorized"
	CodeForbidden     = "forbidden_domain"
	CodeInvalidBody   = "invalid_request"
	CodeInvalidFQDN   = "invalid_fqdn"
	CodeNoZone        = "no_zone"
	CodeRateLimited   = "rate_limited"
	CodeProviderError = "provider_error"
	CodeNotFound      = "not_found"
)

// Options configures a Server.
type Options struct {
	Store   *state.Store
	Limiter *ratelimit.Limiter
	Audit   *audit.Logger
	Log     *slog.Logger
}

// Server implements the API.
type Server struct {
	store    *state.Store
	limiter  *ratelimit.Limiter
	audit    *audit.Logger
	log      *slog.Logger
	metrics  *metrics
	registry *prometheus.Registry
}

// New builds a server from options.
func New(opts Options) *Server {
	registry := prometheus.NewRegistry()

	return &Server{
		store:    opts.Store,
		limiter:  opts.Limiter,
		audit:    opts.Audit,
		log:      opts.Log,
		metrics:  newMetrics(registry),
		registry: registry,
	}
}

// Handler returns the routed handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}))

	mux.HandleFunc("GET /v1/policy", s.authenticated("policy", s.handlePolicy))
	mux.HandleFunc("POST /v1/dns-01/present", s.authenticated("present", s.handlePresent))
	mux.HandleFunc("POST /v1/dns-01/cleanup", s.authenticated("cleanup", s.handleCleanup))
	mux.HandleFunc("PUT /v1/persist", s.authenticated("persist_publish", s.handlePersistPublish))
	mux.HandleFunc("DELETE /v1/persist", s.authenticated("persist_delete", s.handlePersistDelete))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, CodeNotFound, "no such endpoint")
	})

	return mux
}

// requestContext is what an authenticated handler gets: the caller, its
// configuration and the snapshot the whole request is served from.
type requestContext struct {
	ClientName string
	Client     config.Client
	State      *state.State
	Action     string
}

type authenticatedHandler func(http.ResponseWriter, *http.Request, *requestContext)

// authenticated resolves the bearer token, applies the rate limit and hands the
// request to fn. Both failures are audited: an unauthenticated caller is exactly
// what one wants to see in the audit trail.
func (s *Server) authenticated(action string, fn authenticatedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snapshot := s.store.Get()

		token := bearerToken(r)
		if token == "" {
			s.deny(w, r, action, "", CodeUnauthorized, http.StatusUnauthorized, "missing bearer token")
			return
		}

		name, client, ok := snapshot.Config.Lookup(token)
		if !ok {
			s.deny(w, r, action, "", CodeUnauthorized, http.StatusUnauthorized, "unknown token")
			return
		}

		if !s.limiter.Allow(name) {
			s.deny(w, r, action, name, CodeRateLimited, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		fn(w, r, &requestContext{
			ClientName: name,
			Client:     client,
			State:      snapshot,
			Action:     action,
		})
	}
}

func (s *Server) deny(
	w http.ResponseWriter,
	_ *http.Request,
	action, client, code string,
	status int,
	message string,
) {
	s.audit.Log(audit.Event{
		Client:  client,
		Action:  action,
		Verdict: audit.VerdictDenied,
		Reason:  message,
	})

	s.metrics.observeRequest(action, client, code)

	writeError(w, status, code, message)
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")

	value, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if body == nil {
		return
	}

	_ = json.NewEncoder(w).Encode(body)
}

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message})
}

// decodeJSON reads a small, strictly typed body.
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	return dec.Decode(target)
}

// timeSince is a small indirection so tests can keep durations out of goldens.
var timeSince = time.Since
