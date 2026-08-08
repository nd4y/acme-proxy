// Command acme-proxy is a DNS-01 broker: it holds the DNS provider credentials
// and a per-client policy, and publishes only ACME validation records on behalf
// of clients that never see the provider token.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nd4y/acme-proxy/internal/audit"
	"github.com/nd4y/acme-proxy/internal/config"
	"github.com/nd4y/acme-proxy/internal/ratelimit"
	"github.com/nd4y/acme-proxy/internal/server"
	"github.com/nd4y/acme-proxy/internal/state"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// inlineConfigEnv carries the whole configuration, base64-encoded, for hosts
// where a file cannot be mounted.
const inlineConfigEnv = "ACME_PROXY_CONFIG_B64"

const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 90 * time.Second
	shutdownTimeout   = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "acme-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "/etc/acme-proxy/config.yaml", "path to the configuration file")
		listenAddr  = flag.String("listen", "", "listen address, overrides the configuration file")
		showVersion = flag.Bool("version", false, "print the version and exit")
		healthcheck = flag.Bool("healthcheck", false, "probe the health endpoint and exit, for container healthchecks")
	)

	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	if *healthcheck {
		return probeHealth()
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	auditLog := audit.New(os.Stdout)

	// Some hosts cannot hand a file to a container: the image has no shell to
	// write one, and bind-mounting a path that does not exist yet creates a
	// directory instead of a file. There the configuration arrives base64-encoded
	// in the environment.
	inlineConfig := os.Getenv(inlineConfigEnv)

	var (
		cfg *config.Config
		err error
	)

	if inlineConfig != "" {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(inlineConfig))
		if decodeErr != nil {
			return fmt.Errorf("%s is not valid base64: %w", inlineConfigEnv, decodeErr)
		}

		cfg, err = config.Parse(decoded)
	} else {
		cfg, err = config.Load(*configPath)
	}

	if err != nil {
		return err
	}

	snapshot, err := state.Build(cfg)
	if err != nil {
		return err
	}

	store := state.NewStore(snapshot)
	limiter := ratelimit.New(cfg.RateLimit.PerClientPerMinute)

	// A reload must swap the rate limit together with everything else, so the
	// applier goes through the store and then updates the limiter.
	apply := func(next *config.Config) error {
		if err := store.Apply(next); err != nil {
			return err
		}

		limiter.SetRate(next.RateLimit.PerClientPerMinute)

		return nil
	}

	// There is nothing to watch when the configuration came from the
	// environment: it can only change by recreating the container.
	var watcher *config.Watcher

	if inlineConfig == "" {
		watcher, err = config.NewWatcher(*configPath, apply, log)
		if err != nil {
			return err
		}

		defer watcher.Close()
	}

	addr := cfg.Listen
	if *listenAddr != "" {
		addr = *listenAddr
	}

	api := server.New(server.Options{
		Store:   store,
		Limiter: limiter,
		Audit:   auditLog,
		Log:     log,
	})

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if watcher != nil {
		go handleSighup(ctx, watcher)
	}

	errc := make(chan error, 1)

	configSource := *configPath
	if inlineConfig != "" {
		configSource = inlineConfigEnv
	}

	go func() {
		log.Info("acme-proxy started",
			"version", version,
			"listen", addr,
			"config", configSource,
			"clients", len(cfg.Clients),
			"providers", len(cfg.Providers),
		)

		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return httpServer.Shutdown(shutdownCtx)
}

// probeHealth is the container healthcheck. The image has no shell and no curl,
// so the binary probes itself; the URL is overridable because the listen address
// is configurable.
func probeHealth() error {
	url := os.Getenv("HEALTHCHECK_URL")
	if url == "" {
		url = "http://127.0.0.1:8080/healthz"
	}

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: %s returned %s", url, resp.Status)
	}

	return nil
}

// handleSighup gives operators a way to reload without touching the file, which
// matters when the configuration is mounted read-only.
func handleSighup(ctx context.Context, watcher *config.Watcher) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)

	defer signal.Stop(signals)

	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			watcher.Reload()
		}
	}
}
