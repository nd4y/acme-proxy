package providers

import (
	"context"
	"strings"
	"sync"

	"github.com/libdns/libdns"
)

// Memory is an in-process DNS backend. It exists so the service can be run and
// tested end to end without touching a real zone; it never persists anything and
// must not be used for real issuance.
type Memory struct {
	mu      sync.Mutex
	records map[string][]libdns.RR
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory {
	return &Memory{records: make(map[string][]libdns.RR)}
}

// GetRecords returns everything stored for the zone.
func (m *Memory) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := m.records[key(zone)]
	out := make([]libdns.Record, 0, len(stored))

	for _, rr := range stored {
		out = append(out, rr)
	}

	return out, nil
}

// AppendRecords adds records without touching existing ones.
func (m *Memory) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	z := key(zone)

	for _, record := range recs {
		m.records[z] = append(m.records[z], record.RR())
	}

	return recs, nil
}

// SetRecords replaces every record sharing a name and type with the input.
func (m *Memory) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	z := key(zone)

	for _, record := range recs {
		rr := record.RR()

		kept := make([]libdns.RR, 0, len(m.records[z]))

		for _, existing := range m.records[z] {
			if sameName(existing.Name, rr.Name) && existing.Type == rr.Type {
				continue
			}

			kept = append(kept, existing)
		}

		m.records[z] = append(kept, rr)
	}

	return recs, nil
}

// DeleteRecords removes records matching name, type and data.
func (m *Memory) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	z := key(zone)

	for _, record := range recs {
		rr := record.RR()

		kept := make([]libdns.RR, 0, len(m.records[z]))

		for _, existing := range m.records[z] {
			if sameName(existing.Name, rr.Name) && existing.Type == rr.Type && existing.Data == rr.Data {
				continue
			}

			kept = append(kept, existing)
		}

		m.records[z] = kept
	}

	return recs, nil
}

func key(zone string) string {
	return strings.ToLower(strings.TrimSuffix(zone, "."))
}
