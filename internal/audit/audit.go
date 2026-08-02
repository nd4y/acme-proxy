// Package audit records every attempt to touch DNS, allowed or not.
//
// This is the only place where the record name a client asked for is written
// down, so it is deliberately separate from the application log: it is meant to
// be shipped and kept.
package audit

import (
	"io"
	"log/slog"
	"time"
)

// Verdicts an attempt can end with.
const (
	VerdictAllowed = "allowed"
	VerdictDenied  = "denied"
	VerdictError   = "error"
)

// Event is one attempt.
type Event struct {
	Client   string
	Action   string
	FQDN     string
	Verdict  string
	Reason   string
	Provider string
	Duration time.Duration
}

// Logger writes audit events as JSON lines.
type Logger struct {
	log *slog.Logger
}

// New returns a logger writing to w.
func New(w io.Writer) *Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})

	return &Logger{log: slog.New(handler).With("log", "audit")}
}

// Log records the event. Values are never truncated: a denied request is
// exactly the case where the full name matters.
func (a *Logger) Log(event Event) {
	attrs := []any{
		"client", event.Client,
		"action", event.Action,
		"fqdn", event.FQDN,
		"verdict", event.Verdict,
	}

	if event.Provider != "" {
		attrs = append(attrs, "provider", event.Provider)
	}

	if event.Reason != "" {
		attrs = append(attrs, "reason", event.Reason)
	}

	if event.Duration > 0 {
		attrs = append(attrs, "duration_ms", event.Duration.Milliseconds())
	}

	if event.Verdict == VerdictAllowed {
		a.log.Info("dns write", attrs...)
		return
	}

	a.log.Warn("dns write", attrs...)
}
