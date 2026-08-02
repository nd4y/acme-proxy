// Package policy decides whether a client is allowed to write a given DNS
// record. It is deliberately dependency-free so that both the config loader
// (pattern validation) and the HTTP layer (request checks) can use it.
//
// Two invariants are enforced here and cannot be relaxed by configuration:
//
//   - only TXT records are ever written (the record type is not part of the API);
//   - the record name must start with one of the ACME service prefixes below.
//
// Everything else — which domains a client may touch — comes from the client's
// allow list.
package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Prefixes of the only record names acme-proxy is ever allowed to touch.
const (
	ChallengePrefix = "_acme-challenge."
	PersistPrefix   = "_validation-persist."
)

// Kind is the challenge family a request belongs to.
type Kind string

const (
	KindChallenge Kind = "dns-01"
	KindPersist   Kind = "dns-persist-01"
)

// Prefix returns the mandatory record name prefix for the kind.
func (k Kind) Prefix() string {
	switch k {
	case KindPersist:
		return PersistPrefix
	default:
		return ChallengePrefix
	}
}

var (
	// ErrBadPrefix means the record name is not an ACME validation name.
	ErrBadPrefix = errors.New("record name is not an ACME validation name")
	// ErrBadDomain means the name left after stripping the prefix is not a domain.
	ErrBadDomain = errors.New("invalid domain name")
	// ErrNotAllowed means the domain is not covered by the client's allow list.
	ErrNotAllowed = errors.New("domain is not allowed for this client")
	// ErrBadPattern means an allow-list entry is malformed.
	ErrBadPattern = errors.New("invalid allow pattern")
)

// Normalize lowercases a name and drops the trailing dot, so that
// "_acme-challenge.A.Example.COM." and "_acme-challenge.a.example.com" compare
// equal.
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// BaseDomain validates fqdn for the given kind and returns the domain the
// validation record belongs to: "_acme-challenge.a.example.com" -> "a.example.com".
func BaseDomain(fqdn string, kind Kind) (string, error) {
	n := Normalize(fqdn)
	prefix := kind.Prefix()

	if !strings.HasPrefix(n, prefix) {
		return "", fmt.Errorf("%w: %q must start with %q", ErrBadPrefix, n, prefix)
	}

	base := strings.TrimPrefix(n, prefix)
	if err := ValidateDomain(base); err != nil {
		return "", err
	}

	return base, nil
}

// Check runs the full decision: prefix invariant, domain sanity, allow list.
// It returns the base domain so callers can log or reuse it.
func Check(fqdn string, kind Kind, allow []string) (string, error) {
	base, err := BaseDomain(fqdn, kind)
	if err != nil {
		return "", err
	}

	for _, pattern := range allow {
		if Match(base, pattern) {
			return base, nil
		}
	}

	return "", fmt.Errorf("%w: %s", ErrNotAllowed, base)
}

// Match reports whether domain is covered by a single allow pattern.
//
// Supported forms:
//
//	example.com          exact match, nothing else
//	*.example.com        example.com itself and any subdomain at any depth
//	node?-*.example.com  glob inside a label; label count must match exactly
//
// The wildcard form covers the bare suffix on purpose: the DNS-01 challenge for
// a wildcard certificate "*.example.com" is published at
// "_acme-challenge.example.com", so a pattern that did not cover the suffix
// itself would make wildcard certificates impossible to issue.
func Match(domain, pattern string) bool {
	domain = Normalize(domain)
	pattern = Normalize(pattern)

	if domain == "" || pattern == "" {
		return false
	}

	if suffix, ok := strings.CutPrefix(pattern, "*."); ok && !hasGlob(suffix) {
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}

	domainLabels := strings.Split(domain, ".")
	patternLabels := strings.Split(pattern, ".")

	if len(domainLabels) != len(patternLabels) {
		return false
	}

	for i := range patternLabels {
		if !globMatch(patternLabels[i], domainLabels[i]) {
			return false
		}
	}

	return true
}

// ValidateDomain checks that s looks like a hostname: at least two labels, each
// 1..63 characters of [a-z0-9-] without leading or trailing dashes.
func ValidateDomain(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrBadDomain)
	}

	if len(s) > 253 {
		return fmt.Errorf("%w: %q is longer than 253 characters", ErrBadDomain, s)
	}

	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: %q must have at least two labels", ErrBadDomain, s)
	}

	for _, label := range labels {
		if err := validateLabel(label, false); err != nil {
			return fmt.Errorf("%w: %q: %s", ErrBadDomain, s, err)
		}
	}

	return nil
}

// ValidatePattern checks an allow-list entry. Patterns covering a whole public
// suffix ("*.com") are rejected: a single typo there would hand out the right to
// write into somebody else's zone.
func ValidatePattern(pattern string) error {
	p := Normalize(pattern)
	if p == "" {
		return fmt.Errorf("%w: empty", ErrBadPattern)
	}

	body := strings.TrimPrefix(p, "*.")
	labels := strings.Split(body, ".")

	if len(labels) < 2 {
		return fmt.Errorf("%w: %q is too broad, at least two labels are required", ErrBadPattern, pattern)
	}

	for _, label := range labels {
		if err := validateLabel(label, true); err != nil {
			return fmt.Errorf("%w: %q: %s", ErrBadPattern, pattern, err)
		}
	}

	return nil
}

func validateLabel(label string, allowGlob bool) error {
	if label == "" {
		return errors.New("empty label")
	}

	if len(label) > 63 {
		return errors.New("label is longer than 63 characters")
	}

	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return errors.New("label must not start or end with a dash")
	}

	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		case allowGlob && (r == '*' || r == '?'):
		default:
			return fmt.Errorf("unexpected character %q", r)
		}
	}

	return nil
}

func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?")
}

// globMatch matches a single label against a glob pattern where '*' stands for
// any run of characters and '?' for exactly one.
func globMatch(pattern, s string) bool {
	var (
		p, i      int
		star      = -1
		starMatch int
	)

	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			starMatch = i
			p++
		case star >= 0:
			p = star + 1
			starMatch++
			i = starMatch
		default:
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}
