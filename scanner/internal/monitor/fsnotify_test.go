package monitor

import (
	"testing"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/scanner"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Scan: config.ScanConfig{
			ExcludedPaths: []string{
				"C:\\Windows\\WinSxS",
				"C:\\$Recycle.Bin",
			},
		},
	}
}

func TestIsExcluded(t *testing.T) {
	cfg := newTestConfig()
	engine := scanner.NewScannerEngine(&config.Config{
		Scanner: config.ScannerConfig{Concurrency: 1, ThrottleIOPS: 100},
		Scan:    config.ScanConfig{MaxFileSizeMB: 100},
	})
	defer engine.Stop()

	monitor := NewFsMonitor(cfg, engine)

	tests := []struct {
		path     string
		excluded bool
	}{
		{"C:\\Windows\\WinSxS\\amd64_microsoft-windows-some-package", true},
		{"C:\\$Recycle.Bin\\S-1-5-21-...\\file.exe", true},
		{"C:\\Windows\\System32\\notepad.exe", false},
		{"C:\\Users\\user\\Downloads\\setup.exe", false},
		{"C:\\ProgramData\\app.log", true},
		{"C:\\temp\\backup.tmp", true},
		{"C:\\temp\\crash.dmp", true},
	}

	for _, tt := range tests {
		got := monitor.isExcluded(tt.path)
		if got != tt.excluded {
			t.Errorf("isExcluded(%q) = %v, want %v", tt.path, got, tt.excluded)
		}
	}
}

func TestIsExcludedCaseInsensitive(t *testing.T) {
	cfg := newTestConfig()
	engine := scanner.NewScannerEngine(&config.Config{
		Scanner: config.ScannerConfig{Concurrency: 1, ThrottleIOPS: 100},
		Scan:    config.ScanConfig{MaxFileSizeMB: 100},
	})
	defer engine.Stop()

	monitor := NewFsMonitor(cfg, engine)

	// Paths should be matched case-insensitively
	tests := []struct {
		path     string
		excluded bool
	}{
		{"c:\\windows\\winsxs\\some-file.dll", true},
		{"C:\\WINDOWS\\WinSxS\\another.dll", true},
	}

	for _, tt := range tests {
		got := monitor.isExcluded(tt.path)
		if got != tt.excluded {
			t.Errorf("isExcluded(%q) = %v, want %v", tt.path, got, tt.excluded)
		}
	}
}

func TestNewFsMonitor(t *testing.T) {
	cfg := newTestConfig()
	engine := scanner.NewScannerEngine(&config.Config{
		Scanner: config.ScannerConfig{Concurrency: 1, ThrottleIOPS: 100},
		Scan:    config.ScanConfig{MaxFileSizeMB: 100},
	})
	defer engine.Stop()

	monitor := NewFsMonitor(cfg, engine)
	if monitor == nil {
		t.Fatal("expected non-nil monitor")
	}
	if monitor.cfg != cfg {
		t.Error("config should be stored")
	}
	if monitor.engine != engine {
		t.Error("engine should be stored")
	}
}
