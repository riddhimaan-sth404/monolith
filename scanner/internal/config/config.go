package config

import (
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Scanner    ScannerConfig    `yaml:"scanner"`
	GRPC       GRPCConfig       `yaml:"grpc"`
	YARA       YARAConfig       `yaml:"yara"`
	Quarantine QuarantineConfig `yaml:"quarantine"`
	Scan       ScanConfig       `yaml:"scan"`
	Backend    BackendConfig    `yaml:"backend"`
}

type BackendConfig struct {
	URL                string `yaml:"url"`
	AgentURL           string `yaml:"agent_url"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CACertPath         string `yaml:"ca_cert_path"`
}

type ScannerConfig struct {
	LogLevel       string `yaml:"log_level"`
	Concurrency    int    `yaml:"concurrency"`
	ThrottleIOPS   int    `yaml:"throttle_iops"`
	EmberModelPath string `yaml:"ember_model_path"`
	ModelsDir      string `yaml:"models_dir"`
}

type GRPCConfig struct {
	Listen string `yaml:"listen"`
}

type YARAConfig struct {
	RulesPath    string `yaml:"rules_path"`
	CompileCache string `yaml:"compile_cache"`
}

type QuarantineConfig struct {
	Path          string `yaml:"path"`
	EncryptionKey string `yaml:"encryption_key"`
}

type ScanConfig struct {
	QuickPaths      []string `yaml:"quick_paths"`
	FullScanDrives  []string `yaml:"full_scan_drives"`
	ExcludedPaths   []string `yaml:"excluded_paths"`
	MaxFileSizeMB   int      `yaml:"max_file_size_mb"`
	ArchiveMaxDepth int      `yaml:"archive_max_depth"`
}

func Load() *Config {
	cfg := &Config{
		Scanner: ScannerConfig{
			LogLevel:       "INFO",
			Concurrency:    4,
			ThrottleIOPS:   100,
			EmberModelPath: "configs/ember_model.json",
		ModelsDir:      "ember",
		},
		GRPC: GRPCConfig{
			Listen: "127.0.0.1:50072",
		},
		YARA: YARAConfig{
			RulesPath:    "scanner/yara/rules",
			CompileCache: "scanner/yara/cache",
		},
		Quarantine: QuarantineConfig{
			Path:          "${ProgramData}\\EDR\\Quarantine",
			EncryptionKey: "",
		},
		Scan: ScanConfig{
			QuickPaths: []string{
				"{Desktop}",
				"{Downloads}",
				"{Documents}",
				"{LocalAppData}\\Temp",
				"{StartMenu}",
			},
			FullScanDrives: []string{
				"C:\\",
			},
			ExcludedPaths: []string{
				"C:\\Windows\\WinSxS",
				"C:\\$Recycle.Bin",
				"C:\\System Volume Information",
			},
			MaxFileSizeMB:   500,
			ArchiveMaxDepth: 5,
		},
		Backend: BackendConfig{
			URL:                "https://127.0.0.1:8443",
			AgentURL:           "http://127.0.0.1:8090",
			InsecureSkipVerify: false,
		},
	}

	var data []byte
	var err error
	for _, p := range []string{"configs/scanner.yaml", "../configs/scanner.yaml"} {
		data, err = os.ReadFile(p)
		if err == nil {
			slog.Info("loaded config", "path", p)
			break
		}
	}
	if err != nil {
		slog.Warn("config file not found, using defaults", "error", err)
		return cfg
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		slog.Warn("failed to parse config, using defaults", "error", err)
	}

	// Expand environment variables in string fields
	cfg.Quarantine.Path = os.ExpandEnv(cfg.Quarantine.Path)

	return cfg
}

func (c *Config) LogLevel() slog.Level {
	switch c.Scanner.LogLevel {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
