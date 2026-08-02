package policy

import (
	"errors"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		pattern string
		want    bool
	}{
		{"exact", "example.com", "example.com", true},
		{"exact is not a suffix rule", "sub.example.com", "example.com", false},
		{"wildcard covers subdomain", "sub.example.com", "*.example.com", true},
		{"wildcard covers the suffix itself", "example.com", "*.example.com", true},
		{"wildcard covers deep subdomain", "a.b.example.com", "*.example.com", true},
		{"wildcard does not cross the suffix", "example.org", "*.example.com", false},
		{"wildcard does not match a sibling", "notexample.com", "*.example.com", false},
		{"glob in label", "node1-ru.example.com", "node?-*.example.com", true},
		{"glob in label rejects wrong depth", "x.node1-ru.example.com", "node?-*.example.com", false},
		{"glob in label rejects mismatch", "gw1-ru.example.com", "node?-*.example.com", false},
		{"case and trailing dot are normalized", "SUB.Example.COM.", "*.example.com", true},
		{"empty domain", "", "*.example.com", false},
		{"empty pattern", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.domain, tt.pattern); got != tt.want {
				t.Fatalf("Match(%q, %q) = %v, want %v", tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		name    string
		fqdn    string
		kind    Kind
		want    string
		wantErr error
	}{
		{
			name: "challenge",
			fqdn: "_acme-challenge.a.example.com",
			kind: KindChallenge,
			want: "a.example.com",
		},
		{
			name: "persist",
			fqdn: "_validation-persist.example.com",
			kind: KindPersist,
			want: "example.com",
		},
		{
			name:    "challenge prefix is mandatory",
			fqdn:    "a.example.com",
			kind:    KindChallenge,
			wantErr: ErrBadPrefix,
		},
		{
			name:    "persist name is not accepted as a challenge",
			fqdn:    "_validation-persist.example.com",
			kind:    KindChallenge,
			wantErr: ErrBadPrefix,
		},
		{
			name:    "single label after the prefix",
			fqdn:    "_acme-challenge.localhost",
			kind:    KindChallenge,
			wantErr: ErrBadDomain,
		},
		{
			name:    "underscores are not allowed in the base domain",
			fqdn:    "_acme-challenge._dmarc.example.com",
			kind:    KindChallenge,
			wantErr: ErrBadDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BaseDomain(tt.fqdn, tt.kind)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("BaseDomain(%q) error = %v, want %v", tt.fqdn, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("BaseDomain(%q) unexpected error: %v", tt.fqdn, err)
			}

			if got != tt.want {
				t.Fatalf("BaseDomain(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	allow := []string{"*.edge.example.com", "svc1.example.com"}

	if _, err := Check("_acme-challenge.edge.example.com", KindChallenge, allow); err != nil {
		t.Fatalf("wildcard base name must be allowed: %v", err)
	}

	if _, err := Check("_acme-challenge.svc1.example.com", KindChallenge, allow); err != nil {
		t.Fatalf("exact name must be allowed: %v", err)
	}

	_, err := Check("_acme-challenge.other.example.com", KindChallenge, allow)
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("domain outside the allow list must be denied, got %v", err)
	}

	// A name that is in the allow list but has no ACME prefix must still fail:
	// the prefix invariant is checked before the allow list.
	_, err = Check("svc1.example.com", KindChallenge, allow)
	if !errors.Is(err, ErrBadPrefix) {
		t.Fatalf("missing prefix must be rejected, got %v", err)
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{"example.com", "*.example.com", "node?-*.example.com", "a.b.example.com"}
	for _, p := range valid {
		if err := ValidatePattern(p); err != nil {
			t.Fatalf("ValidatePattern(%q) unexpected error: %v", p, err)
		}
	}

	invalid := []string{"", "*.com", "com", "exa mple.com", "-bad.example.com", "example..com"}
	for _, p := range invalid {
		if err := ValidatePattern(p); err == nil {
			t.Fatalf("ValidatePattern(%q) must fail", p)
		}
	}
}
