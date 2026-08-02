// Package config loads, validates and holds the acme-proxy configuration.
//
// Secrets are never written in the file itself in practice: token fields accept
// the ${VAR} form and are resolved from the environment after parsing. The
// substitution is done on individual fields rather than on the raw YAML text, so
// a token containing YAML-special characters cannot break the document.
package config

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nd4y/acme-proxy/internal/policy"
)

// Defaults applied when the corresponding key is absent.
const (
	DefaultListen        = ":8080"
	DefaultTTLSeconds    = 60
	DefaultRatePerMinute = 30

	// MinTokenLength is the shortest client token accepted. Short tokens are a
	// configuration mistake, not a preference.
	MinTokenLength = 16
)

// KnownProviderTypes lists the provider backends compiled into the binary.
// "memory" is a non-persistent stub for tests and dry runs.
var KnownProviderTypes = []string{"cloudflare", "memory"}

// Config is the whole configuration file.
type Config struct {
	Listen     string              `yaml:"listen"`
	TTLSeconds int                 `yaml:"ttl_seconds"`
	Providers  map[string]Provider `yaml:"providers"`
	Clients    map[string]Client   `yaml:"clients"`
	RateLimit  RateLimit           `yaml:"rate_limit"`
}

// Provider is a DNS backend together with the zones it is allowed to serve.
// Zones are explicit on purpose: guessing the zone from an FQDN means guessing
// wrong on the first multi-level domain and getting a confusing provider error.
type Provider struct {
	Type     string   `yaml:"type"`
	APIToken string   `yaml:"api_token"`
	Zones    []string `yaml:"zones"`
}

// Client is an API consumer: a bearer token, one provider and an allow list.
type Client struct {
	Token    string   `yaml:"token"`
	Provider string   `yaml:"provider"`
	Allow    []string `yaml:"allow"`
}

// RateLimit caps how often a single client may ask for DNS writes.
type RateLimit struct {
	PerClientPerMinute int `yaml:"per_client_per_minute"`
}

// TTL is the TTL used for every record acme-proxy creates.
func (c *Config) TTL() time.Duration {
	return time.Duration(c.TTLSeconds) * time.Second
}

// Lookup finds the client owning the token. Every configured token is compared
// with a constant-time comparison, so neither the match nor the number of
// comparisons depends on the secret.
func (c *Config) Lookup(token string) (string, Client, bool) {
	var (
		name   string
		client Client
		found  bool
	)

	for candidateName, candidate := range c.Clients {
		if subtle.ConstantTimeCompare([]byte(candidate.Token), []byte(token)) == 1 {
			name, client, found = candidateName, candidate, true
		}
	}

	return name, client, found
}

// Load reads, expands and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return Parse(raw)
}

// Parse is Load without the file system, so tests and hot reload share one path.
func Parse(raw []byte) (*Config, error) {
	var cfg Config

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // a typo in a key must fail loudly, not be ignored

	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.expand(); err != nil {
		return nil, err
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func (c *Config) expand() error {
	var missing []string

	expand := func(s string) string {
		return envRef.ReplaceAllStringFunc(s, func(ref string) string {
			name := envRef.FindStringSubmatch(ref)[1]

			value, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
				return ""
			}

			return value
		})
	}

	c.Listen = expand(c.Listen)

	for name, provider := range c.Providers {
		provider.APIToken = expand(provider.APIToken)
		c.Providers[name] = provider
	}

	for name, client := range c.Clients {
		client.Token = expand(client.Token)
		c.Clients[name] = client
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("undefined environment variables: %s", strings.Join(dedupe(missing), ", "))
	}

	return nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}

	if c.TTLSeconds == 0 {
		c.TTLSeconds = DefaultTTLSeconds
	}

	if c.RateLimit.PerClientPerMinute == 0 {
		c.RateLimit.PerClientPerMinute = DefaultRatePerMinute
	}

	for name, provider := range c.Providers {
		for i, zone := range provider.Zones {
			provider.Zones[i] = policy.Normalize(zone)
		}

		c.Providers[name] = provider
	}

	for name, client := range c.Clients {
		for i, pattern := range client.Allow {
			client.Allow[i] = policy.Normalize(pattern)
		}

		c.Clients[name] = client
	}
}

func (c *Config) validate() error {
	var problems []error

	if c.TTLSeconds < 1 {
		problems = append(problems, errors.New("ttl_seconds must be positive"))
	}

	if c.RateLimit.PerClientPerMinute < 1 {
		problems = append(problems, errors.New("rate_limit.per_client_per_minute must be positive"))
	}

	if len(c.Providers) == 0 {
		problems = append(problems, errors.New("no providers configured"))
	}

	if len(c.Clients) == 0 {
		problems = append(problems, errors.New("no clients configured"))
	}

	for name, provider := range c.Providers {
		problems = append(problems, provider.validate(name)...)
	}

	for name, client := range c.Clients {
		problems = append(problems, client.validate(name, c.Providers)...)
	}

	problems = append(problems, c.validateTokenUniqueness()...)

	return errors.Join(problems...)
}

func (p Provider) validate(name string) []error {
	var problems []error

	if !contains(KnownProviderTypes, p.Type) {
		problems = append(problems, fmt.Errorf(
			"provider %q: unknown type %q (known: %s)",
			name, p.Type, strings.Join(KnownProviderTypes, ", "),
		))
	}

	if p.Type != "memory" && strings.TrimSpace(p.APIToken) == "" {
		problems = append(problems, fmt.Errorf("provider %q: api_token is empty", name))
	}

	if len(p.Zones) == 0 {
		problems = append(problems, fmt.Errorf("provider %q: no zones configured", name))
	}

	for _, zone := range p.Zones {
		if err := policy.ValidateDomain(zone); err != nil {
			problems = append(problems, fmt.Errorf("provider %q: %w", name, err))
		}
	}

	return problems
}

func (c Client) validate(name string, providers map[string]Provider) []error {
	var problems []error

	if len(c.Token) < MinTokenLength {
		problems = append(problems, fmt.Errorf(
			"client %q: token must be at least %d characters", name, MinTokenLength,
		))
	}

	if _, ok := providers[c.Provider]; !ok {
		problems = append(problems, fmt.Errorf("client %q: unknown provider %q", name, c.Provider))
	}

	if len(c.Allow) == 0 {
		problems = append(problems, fmt.Errorf("client %q: allow list is empty", name))
	}

	for _, pattern := range c.Allow {
		if err := policy.ValidatePattern(pattern); err != nil {
			problems = append(problems, fmt.Errorf("client %q: %w", name, err))
		}
	}

	return problems
}

func (c *Config) validateTokenUniqueness() []error {
	var problems []error

	owners := make(map[string]string, len(c.Clients))

	for _, name := range sortedKeys(c.Clients) {
		token := c.Clients[name].Token
		if token == "" {
			continue
		}

		if other, seen := owners[token]; seen {
			problems = append(problems, fmt.Errorf(
				"clients %q and %q share the same token", other, name,
			))

			continue
		}

		owners[token] = name
	}

	return problems
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}

	return false
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))

	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		out = append(out, v)
	}

	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
