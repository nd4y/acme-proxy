// Package state holds the currently active configuration together with the
// providers built from it, and swaps both atomically on reload.
package state

import (
	"sync/atomic"

	"github.com/nd4y/acme-proxy/internal/config"
	"github.com/nd4y/acme-proxy/internal/providers"
)

// State is an immutable snapshot: a configuration and the providers built from
// exactly that configuration. Handlers take one snapshot per request, so a
// reload can never make them see a client pointing at a provider that no longer
// exists.
type State struct {
	Config    *config.Config
	Providers providers.Registry
}

// Build instantiates providers for the configuration.
func Build(cfg *config.Config) (*State, error) {
	registry, err := providers.Build(cfg)
	if err != nil {
		return nil, err
	}

	return &State{Config: cfg, Providers: registry}, nil
}

// Store keeps the active snapshot.
type Store struct {
	current atomic.Pointer[State]
}

// NewStore returns a store holding the given snapshot.
func NewStore(initial *State) *Store {
	store := &Store{}
	store.current.Store(initial)

	return store
}

// Get returns the active snapshot.
func (s *Store) Get() *State {
	return s.current.Load()
}

// Set replaces the active snapshot.
func (s *Store) Set(next *State) {
	s.current.Store(next)
}

// Apply builds a snapshot from cfg and installs it. It matches config.Applier,
// so a configuration that parses but cannot produce working providers is
// rejected instead of being installed half-broken.
func (s *Store) Apply(cfg *config.Config) error {
	next, err := Build(cfg)
	if err != nil {
		return err
	}

	s.Set(next)

	return nil
}
