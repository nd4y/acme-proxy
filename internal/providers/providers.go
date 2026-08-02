// Package providers turns configured DNS backends into a small API that works
// in terms of fully qualified names: the HTTP layer never has to know about
// zones, relative record names or libdns types.
package providers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/libdns/cloudflare"
	"github.com/libdns/libdns"

	"github.com/nd4y/acme-proxy/internal/config"
)

// ErrNoZone means none of the provider's configured zones owns the name.
var ErrNoZone = errors.New("no configured zone matches the name")

// dnsProvider is the subset of the libdns interfaces acme-proxy needs.
type dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
	libdns.RecordDeleter
}

// Entry is one configured provider.
type Entry struct {
	Name  string
	Type  string
	Zones []string

	provider dnsProvider
}

// Registry maps provider names to entries.
type Registry map[string]*Entry

// Build instantiates every provider in the configuration. A failure here means
// the whole configuration is unusable, which is exactly when a hot reload must
// be rejected.
func Build(cfg *config.Config) (Registry, error) {
	registry := make(Registry, len(cfg.Providers))

	for name, providerCfg := range cfg.Providers {
		entry, err := newEntry(name, providerCfg)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}

		registry[name] = entry
	}

	return registry, nil
}

func newEntry(name string, cfg config.Provider) (*Entry, error) {
	var provider dnsProvider

	switch cfg.Type {
	case "cloudflare":
		provider = &cloudflare.Provider{APIToken: cfg.APIToken}
	case "memory":
		provider = NewMemory()
	default:
		return nil, fmt.Errorf("unknown provider type %q", cfg.Type)
	}

	// Longest zone first, so that a delegated sub-zone wins over its parent.
	zones := append([]string(nil), cfg.Zones...)
	sort.Slice(zones, func(i, j int) bool { return len(zones[i]) > len(zones[j]) })

	return &Entry{Name: name, Type: cfg.Type, Zones: zones, provider: provider}, nil
}

// Zone resolves which configured zone owns fqdn and the record name relative to
// that zone, as libdns expects it.
func (e *Entry) Zone(fqdn string) (zone, relative string, err error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")

	for _, candidate := range e.Zones {
		if name == candidate || strings.HasSuffix(name, "."+candidate) {
			zone = candidate + "."
			return zone, libdns.RelativeName(name, zone), nil
		}
	}

	return "", "", fmt.Errorf("%w: %s", ErrNoZone, name)
}

// Append creates a TXT record, leaving any other record with the same name
// alone. A DNS-01 order for several identifiers under one name legitimately
// produces several TXT values, so this must never replace the set.
//
// The call is idempotent: an identical record already present is a success.
func (e *Entry) Append(ctx context.Context, fqdn, value string, ttl time.Duration) error {
	zone, relative, err := e.Zone(fqdn)
	if err != nil {
		return err
	}

	present, err := e.exists(ctx, zone, relative, value)
	if err != nil {
		return err
	}

	if present {
		return nil
	}

	_, err = e.provider.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: relative, TTL: ttl, Text: value},
	})

	return err
}

// Set makes the TXT records at the name be exactly the given value. This is the
// right semantics for the persistent authorization record, of which there must
// be exactly one.
func (e *Entry) Set(ctx context.Context, fqdn, value string, ttl time.Duration) error {
	zone, relative, err := e.Zone(fqdn)
	if err != nil {
		return err
	}

	_, err = e.provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: relative, TTL: ttl, Text: value},
	})

	return err
}

// Delete removes TXT records at the name. An empty value removes every TXT
// record at that name; a non-empty one removes only the matching record.
// Deleting something that is not there is not an error.
func (e *Entry) Delete(ctx context.Context, fqdn, value string) error {
	zone, relative, err := e.Zone(fqdn)
	if err != nil {
		return err
	}

	existing, err := e.txtRecords(ctx, zone, relative)
	if err != nil {
		return err
	}

	victims := make([]libdns.Record, 0, len(existing))

	for _, record := range existing {
		if value == "" || record.RR().Data == value {
			victims = append(victims, record)
		}
	}

	if len(victims) == 0 {
		return nil
	}

	_, err = e.provider.DeleteRecords(ctx, zone, victims)

	return err
}

// TXTRecords returns the TXT records currently published at fqdn. Nothing in the
// request path needs it; it exists for diagnostics and tests.
func (e *Entry) TXTRecords(ctx context.Context, fqdn string) ([]libdns.Record, error) {
	zone, relative, err := e.Zone(fqdn)
	if err != nil {
		return nil, err
	}

	return e.txtRecords(ctx, zone, relative)
}

func (e *Entry) exists(ctx context.Context, zone, relative, value string) (bool, error) {
	records, err := e.txtRecords(ctx, zone, relative)
	if err != nil {
		return false, err
	}

	for _, record := range records {
		if record.RR().Data == value {
			return true, nil
		}
	}

	return false, nil
}

func (e *Entry) txtRecords(ctx context.Context, zone, relative string) ([]libdns.Record, error) {
	records, err := e.provider.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	out := make([]libdns.Record, 0, 4)

	for _, record := range records {
		rr := record.RR()
		if rr.Type != "TXT" {
			continue
		}

		if !sameName(rr.Name, relative) {
			continue
		}

		out = append(out, record)
	}

	return out, nil
}

// sameName compares record names tolerantly: providers differ in whether they
// return names relative to the zone, absolute, or with a trailing dot.
func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}
