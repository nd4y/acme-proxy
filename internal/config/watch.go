package config

import (
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// reloadDebounce collapses the burst of events an editor or a container
// orchestrator produces while replacing a file.
const reloadDebounce = 250 * time.Millisecond

// Applier receives a freshly parsed configuration. Returning an error means the
// configuration is rejected and the previous one stays in effect — the same rule
// as for a parse failure.
type Applier func(*Config) error

// Watcher reloads the configuration file when it changes.
//
// The directory is watched rather than the file itself: replacing a file (the
// usual write-to-temp-then-rename dance, and how Kubernetes and Docker configs
// are updated) breaks a per-file watch immediately.
type Watcher struct {
	path    string
	apply   Applier
	log     *slog.Logger
	watcher *fsnotify.Watcher

	mu    sync.Mutex
	timer *time.Timer
}

// NewWatcher starts watching the directory holding path.
func NewWatcher(path string, apply Applier, log *slog.Logger) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := fsw.Add(dir); err != nil {
		fsw.Close()
		return nil, err
	}

	w := &Watcher{
		path:    filepath.Clean(path),
		apply:   apply,
		log:     log,
		watcher: fsw,
	}

	go w.run()

	return w, nil
}

// Reload re-reads the file immediately. It is also what SIGHUP is wired to.
func (w *Watcher) Reload() {
	cfg, err := Load(w.path)
	if err != nil {
		w.log.Error("config reload rejected, keeping the previous configuration",
			"path", w.path, "error", err)

		return
	}

	if err := w.apply(cfg); err != nil {
		w.log.Error("config reload rejected, keeping the previous configuration",
			"path", w.path, "error", err)

		return
	}

	w.log.Info("configuration reloaded", "path", w.path)
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.timer != nil {
		w.timer.Stop()
	}
	w.mu.Unlock()

	return w.watcher.Close()
}

func (w *Watcher) run() {
	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			if filepath.Clean(event.Name) != w.path {
				continue
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}

			w.schedule()

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}

			w.log.Error("config watcher error", "error", err)
		}
	}
}

func (w *Watcher) schedule() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.timer != nil {
		w.timer.Stop()
	}

	w.timer = time.AfterFunc(reloadDebounce, w.Reload)
}
