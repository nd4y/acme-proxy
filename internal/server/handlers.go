package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nd4y/acme-proxy/internal/audit"
	"github.com/nd4y/acme-proxy/internal/policy"
	"github.com/nd4y/acme-proxy/internal/providers"
)

// maxValueLength bounds the record data. Real values are an ACME key
// authorization digest (43 characters) or a persistent authorization record
// (a couple hundred).
const maxValueLength = 1024

type recordRequest struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

type recordResponse struct {
	RecordID string `json:"record_id"`
}

type policyResponse struct {
	Client     string         `json:"client"`
	Allow      []string       `json:"allow"`
	Provider   providerInfo   `json:"provider"`
	TTLSeconds int            `json:"ttl_seconds"`
	Prefixes   prefixResponse `json:"prefixes"`
}

type providerInfo struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Zones []string `json:"zones"`
}

type prefixResponse struct {
	Challenge string `json:"challenge"`
	Persist   string `json:"persist"`
}

// handlePolicy tells the caller what it is allowed to do. The panel shows this
// in its UI so an operator can see the allow list without shell access to the
// proxy host.
func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request, rc *requestContext) {
	entry, ok := rc.State.Providers[rc.Client.Provider]
	if !ok {
		s.fail(w, rc, "", CodeProviderError, http.StatusInternalServerError, "provider is not configured")
		return
	}

	s.metrics.observeRequest(rc.Action, rc.ClientName, "ok")

	writeJSON(w, http.StatusOK, policyResponse{
		Client: rc.ClientName,
		Allow:  rc.Client.Allow,
		Provider: providerInfo{
			Name:  entry.Name,
			Type:  entry.Type,
			Zones: entry.Zones,
		},
		TTLSeconds: rc.State.Config.TTLSeconds,
		Prefixes: prefixResponse{
			Challenge: policy.ChallengePrefix,
			Persist:   policy.PersistPrefix,
		},
	})
}

// handlePresent publishes a DNS-01 challenge record.
func (s *Server) handlePresent(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.mutate(w, r, rc, policy.KindChallenge, true,
		func(ctx context.Context, entry *providers.Entry, fqdn, value string, ttl time.Duration) error {
			return entry.Append(ctx, fqdn, value, ttl)
		})
}

// handleCleanup removes a DNS-01 challenge record.
func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.mutate(w, r, rc, policy.KindChallenge, true,
		func(ctx context.Context, entry *providers.Entry, fqdn, value string, _ time.Duration) error {
			return entry.Delete(ctx, fqdn, value)
		})
}

// handlePersistPublish upserts the persistent authorization record used by
// dns-persist-01. There must be exactly one such record per name, so this
// replaces rather than appends.
func (s *Server) handlePersistPublish(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.mutate(w, r, rc, policy.KindPersist, true,
		func(ctx context.Context, entry *providers.Entry, fqdn, value string, ttl time.Duration) error {
			return entry.Set(ctx, fqdn, value, ttl)
		})
}

// handlePersistDelete withdraws the persistent authorization for a name.
func (s *Server) handlePersistDelete(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	s.mutate(w, r, rc, policy.KindPersist, false,
		func(ctx context.Context, entry *providers.Entry, fqdn, _ string, _ time.Duration) error {
			return entry.Delete(ctx, fqdn, "")
		})
}

type mutation func(ctx context.Context, entry *providers.Entry, fqdn, value string, ttl time.Duration) error

// mutate is the shared body of every write endpoint: decode, check the policy,
// call the provider, audit the outcome. The order matters — the policy decision
// happens before anything is sent to the provider.
func (s *Server) mutate(
	w http.ResponseWriter,
	r *http.Request,
	rc *requestContext,
	kind policy.Kind,
	valueRequired bool,
	apply mutation,
) {
	var req recordRequest

	if err := decodeJSON(w, r, &req); err != nil {
		s.fail(w, rc, "", CodeInvalidBody, http.StatusUnprocessableEntity, "malformed request body: "+err.Error())
		return
	}

	if valueRequired && req.Value == "" {
		s.fail(w, rc, req.FQDN, CodeInvalidBody, http.StatusUnprocessableEntity, "value is required")
		return
	}

	if len(req.Value) > maxValueLength {
		s.fail(w, rc, req.FQDN, CodeInvalidBody, http.StatusUnprocessableEntity, "value is too long")
		return
	}

	fqdn := policy.Normalize(req.FQDN)

	if _, err := policy.Check(fqdn, kind, rc.Client.Allow); err != nil {
		code, status := classifyPolicyError(err)
		s.fail(w, rc, fqdn, code, status, err.Error())

		return
	}

	entry, ok := rc.State.Providers[rc.Client.Provider]
	if !ok {
		s.fail(w, rc, fqdn, CodeProviderError, http.StatusInternalServerError, "provider is not configured")
		return
	}

	started := time.Now()
	err := apply(r.Context(), entry, fqdn, req.Value, rc.State.Config.TTL())
	elapsed := timeSince(started)

	s.metrics.observeProvider(entry.Name, rc.Action, elapsed.Seconds())

	if err != nil {
		code, status := classifyProviderError(err)

		s.audit.Log(audit.Event{
			Client:   rc.ClientName,
			Action:   rc.Action,
			FQDN:     fqdn,
			Verdict:  audit.VerdictError,
			Reason:   err.Error(),
			Provider: entry.Name,
			Duration: elapsed,
		})

		s.metrics.observeRequest(rc.Action, rc.ClientName, code)
		s.log.Error("dns write failed",
			"client", rc.ClientName, "action", rc.Action, "fqdn", fqdn, "error", err)

		writeError(w, status, code, err.Error())

		return
	}

	s.audit.Log(audit.Event{
		Client:   rc.ClientName,
		Action:   rc.Action,
		FQDN:     fqdn,
		Verdict:  audit.VerdictAllowed,
		Provider: entry.Name,
		Duration: elapsed,
	})

	s.metrics.observeRequest(rc.Action, rc.ClientName, "ok")

	writeJSON(w, http.StatusOK, recordResponse{RecordID: recordID(fqdn, req.Value)})
}

// fail audits a rejected request and answers with the error code.
func (s *Server) fail(w http.ResponseWriter, rc *requestContext, fqdn, code string, status int, message string) {
	s.audit.Log(audit.Event{
		Client:  rc.ClientName,
		Action:  rc.Action,
		FQDN:    fqdn,
		Verdict: audit.VerdictDenied,
		Reason:  message,
	})

	s.metrics.observeRequest(rc.Action, rc.ClientName, code)

	writeError(w, status, code, message)
}

func classifyPolicyError(err error) (code string, status int) {
	switch {
	case errors.Is(err, policy.ErrNotAllowed):
		return CodeForbidden, http.StatusForbidden
	case errors.Is(err, policy.ErrBadPrefix), errors.Is(err, policy.ErrBadDomain):
		return CodeInvalidFQDN, http.StatusUnprocessableEntity
	default:
		return CodeInvalidBody, http.StatusUnprocessableEntity
	}
}

func classifyProviderError(err error) (code string, status int) {
	if errors.Is(err, providers.ErrNoZone) {
		return CodeNoZone, http.StatusUnprocessableEntity
	}

	return CodeProviderError, http.StatusBadGateway
}

// recordID is an opaque handle for a record. Providers differ in whether they
// expose their own identifiers, and cleanup is addressed by name and value
// anyway, so a stable digest is both sufficient and portable.
func recordID(fqdn, value string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s", fqdn, value)))

	return hex.EncodeToString(sum[:8])
}
