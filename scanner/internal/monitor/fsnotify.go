package monitor

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/scanner"
	"github.com/fsnotify/fsnotify"
)

const maxWatchedDirs = 2000

type FsMonitor struct {
	cfg        *config.Config
	engine     *scanner.ScannerEngine
	watcher    *fsnotify.Watcher
	watchedDirs map[string]bool
}

func NewFsMonitor(cfg *config.Config, engine *scanner.ScannerEngine) *FsMonitor {
	return &FsMonitor{
		cfg:         cfg,
		engine:      engine,
		watchedDirs: make(map[string]bool),
	}
}

func (m *FsMonitor) Start(ctx context.Context) {
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		slog.Error("failed to create watcher", "error", err)
		return
	}
	defer m.watcher.Close()

	// Watch root directories recursively
	for _, dir := range m.cfg.Scan.QuickPaths {
		// Expand glob patterns like C:\Users\*\AppData to real paths
		expanded := expandGlobPath(dir)
		for _, expandedDir := range expanded {
			m.addDirRecursive(expandedDir)
		}
	}

	slog.Info("filesystem monitor started",
		"root_dirs", len(m.cfg.Scan.QuickPaths),
		"watched_dirs", len(m.watchedDirs),
	)

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			// Skip excluded paths
			if m.isExcluded(event.Name) {
				continue
			}

			// Handle file events
			switch {
			case event.Op&fsnotify.Create != 0:
				// If a new directory was created, watch it recursively
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					m.addDirRecursive(event.Name)
				}
				slog.Debug("file created", "path", event.Name)
				m.engine.EnqueueScan(event.Name)

			case event.Op&fsnotify.Write != 0:
				slog.Debug("file modified", "path", event.Name)
				m.engine.EnqueueScan(event.Name)

			case event.Op&fsnotify.Rename != 0:
				slog.Debug("file renamed", "path", event.Name)
			case event.Op&fsnotify.Remove != 0:
				delete(m.watchedDirs, event.Name)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("watcher error", "error", err)

		case <-ctx.Done():
			slog.Info("filesystem monitor stopped")
			return
		}
	}
}

func (m *FsMonitor) addDirRecursive(root string) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			slog.Debug("cannot access path", "path", path, "error", err)
			return nil
		}
		if !info.IsDir() {
			return nil
		}

		// Skip excluded directories
		for _, excluded := range m.cfg.Scan.ExcludedPaths {
			lowerPath := strings.ToLower(path)
			if strings.HasPrefix(lowerPath, strings.ToLower(excluded)) {
				return filepath.SkipDir
			}
		}

		// Skip already-watched directories
		if m.watchedDirs[path] {
			return nil
		}

		// Enforce max watched directories to avoid resource exhaustion
		if len(m.watchedDirs) >= maxWatchedDirs {
			slog.Warn("max watched directories reached, skipping", "dir", path)
			return filepath.SkipDir
		}

		if err := m.watcher.Add(path); err != nil {
			slog.Debug("failed to watch directory", "dir", path, "error", err)
			return nil
		}

		m.watchedDirs[path] = true
		return nil
	})
}

func (m *FsMonitor) Stop() {
	if m.watcher != nil {
		m.watcher.Close()
	}
}

func (m *FsMonitor) isExcluded(path string) bool {
	lower := strings.ToLower(path)
	for _, excluded := range m.cfg.Scan.ExcludedPaths {
		if strings.HasPrefix(lower, strings.ToLower(excluded)) {
			return true
		}
	}

	// Skip known safe extensions
	ext := filepath.Ext(lower)
	switch ext {
	case ".log", ".tmp", ".bak", ".dmp":
		return true
	}

	return false
}

// expandGlobPath expands patterns like C:\Users\*\AppData into real paths.
// If no glob pattern is present, returns the path as-is.
func expandGlobPath(pattern string) []string {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}
	}

	matches, err := filepath.Glob(pattern)
	if err != nil {
		slog.Debug("glob expansion failed", "pattern", pattern, "error", err)
		return []string{pattern}
	}
	if len(matches) == 0 {
		return []string{pattern}
	}
	return matches
}
