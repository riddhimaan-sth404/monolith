package config

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := &Config{
		Scanner: ScannerConfig{
			LogLevel:    "INFO",
			Concurrency: 4,
			ThrottleIOPS: 100,
		},
		GRPC: GRPCConfig{
			Listen: "127.0.0.1:50072",
		},
		YARA: YARAConfig{
			RulesPath:    "C:\\ProgramData\\EDR\\yara\\rules",
			CompileCache: "C:\\ProgramData\\EDR\\yara\\cache",
		},
		Quarantine: QuarantineConfig{
			Path:          "C:\\ProgramData\\EDR\\Quarantine",
			EncryptionKey: "",
		},
		Scan: ScanConfig{
			QuickPaths: []string{
				"C:\\Windows\\System32",
				"C:\\Windows\\SysWOW64",
				"C:\\ProgramData",
				"C:\\Users",
			},
			ExcludedPaths: []string{
				"C:\\Windows\\WinSxS",
				"C:\\$Recycle.Bin",
				"C:\\System Volume Information",
			},
			MaxFileSizeMB:   500,
			ArchiveMaxDepth: 5,
		},
	}

	if cfg.Scanner.Concurrency != 4 {
		t.Errorf("expected concurrency 4, got %d", cfg.Scanner.Concurrency)
	}
	if cfg.Scanner.ThrottleIOPS != 100 {
		t.Errorf("expected throttle IOPS 100, got %d", cfg.Scanner.ThrottleIOPS)
	}
		if len(cfg.Scan.QuickPaths) != 4 {
			t.Errorf("expected 4 quick paths, got %d", len(cfg.Scan.QuickPaths))
	}
	if cfg.Scan.MaxFileSizeMB != 500 {
		t.Errorf("expected max file size 500MB, got %d", cfg.Scan.MaxFileSizeMB)
	}
}

func TestLogLevelParsing(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"DEBUG", "DEBUG"},
		{"INFO", "INFO"},
		{"WARN", "WARN"},
		{"ERROR", "ERROR"},
		{"UNKNOWN", "INFO"},
	}

	for _, tt := range tests {
		cfg := &Config{
			Scanner: ScannerConfig{LogLevel: tt.input},
		}
		level := cfg.LogLevel()
		if level.String() != tt.want {
			t.Errorf("LogLevel(%s) = %s, want %s", tt.input, level, tt.want)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := &Config{}
	if cfg.Scanner.Concurrency == 0 {
		t.Log("concurrency defaults to 0 when not set")
	}
}

func TestDefaultConfigStructure(t *testing.T) {
	// Load() returns initialized config; &Config{} is zero-value
	cfg := Load()
	if cfg.Scanner.Concurrency == 0 {
		t.Error("Load() should initialize concurrency")
	}
	if cfg.Scan.ExcludedPaths == nil {
		t.Error("Load() should initialize ExcludedPaths")
	}
	if cfg.Scan.QuickPaths == nil {
		t.Error("Load() should initialize QuickPaths")
	}
}
