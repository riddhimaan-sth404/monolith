//go:build integration

package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edr/scanner/internal/config"
	"github.com/edr/scanner/internal/monitor"
	"github.com/edr/scanner/internal/scanner"
)

const testPattern = "MONOLITH-EDR-INTEGRATION-TEST-PATTERN-2026"

func setupYARATestDir(t *testing.T) (string, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "yara")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create yara dir: %v", err)
	}
	yaraRule := `rule MONOLITH_TEST {
    meta:
        description = "Monolith EDR integration test pattern"
        author = "Monolith EDR"
        severity = "critical"
    strings:
        $test = "` + testPattern + `"
    condition:
        $test
}`
	if err := os.WriteFile(filepath.Join(rulesDir, "monolith_test.yar"), []byte(yaraRule), 0644); err != nil {
		t.Fatalf("failed to write monolith_test.yar: %v", err)
	}

	emberModel := `{
		"name":"test","task":"binary","num_classes":1,"num_features":2568,
		"trees":[{"split_feature":0,"split_threshold":0.5,"default_left":true,"left":{"leaf_value":-0.3},"right":{"leaf_value":0.3}}]
	}`
	configsDir := filepath.Join(tmpDir, "configs")
	if err := os.MkdirAll(configsDir, 0755); err != nil {
		t.Fatalf("failed to create configs dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configsDir, "ember_model.json"), []byte(emberModel), 0644); err != nil {
		t.Fatalf("failed to write ember_model.json: %v", err)
	}

	cleanup := func() {}
	return tmpDir, cleanup
}

func makeTestConfig(yaraDir string) *config.Config {
	return &config.Config{
		Backend: config.BackendConfig{URL: ""},
		Scan: config.ScanConfig{
			MaxFileSizeMB: 100,
			ExcludedPaths: []string{},
		},
		Scanner: config.ScannerConfig{
			Concurrency:     2,
			ThrottleIOPS:    1000,
			EmberModelPath:  filepath.Join(yaraDir, "configs", "ember_model.json"),
		},
		YARA: config.YARAConfig{
			RulesPath:    filepath.Join(yaraDir, "yara"),
			CompileCache: filepath.Join(yaraDir, "yara"),
		},
	}
}

func TestMonolithPatternViaFsNotify(t *testing.T) {
	yaraDir, cleanup := setupYARATestDir(t)
	defer cleanup()

	cfg := makeTestConfig(yaraDir)
	cfg.Scan.QuickPaths = []string{t.TempDir()}
	watchDir := cfg.Scan.QuickPaths[0]

	engine := scanner.NewScannerEngine(cfg)
	defer engine.Stop()

	mon := monitor.NewFsMonitor(cfg, engine)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go mon.Start(ctx)

	time.Sleep(500 * time.Millisecond)

	testPath := filepath.Join(watchDir, "test-pattern.txt")
	if err := os.WriteFile(testPath, []byte(testPattern), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	select {
	case result := <-engine.Results():
		if result.FilePath != testPath {
			t.Errorf("expected path %s, got %s", testPath, result.FilePath)
		}
		if result.Hashes == nil {
			t.Error("expected hashes to be computed")
		}
		t.Logf("verdict=%s score=%.2f quarantined=%v matched_rules=%v",
			result.Verdict, result.Score, result.Quarantined, result.MatchedRules)
		if result.Verdict == "clean" {
			t.Error("expected threat detection for test pattern match")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for fsnotify scan")
	}
}

func TestMonolithPatternDirect(t *testing.T) {
	yaraDir, cleanup := setupYARATestDir(t)
	defer cleanup()

	cfg := makeTestConfig(yaraDir)
	cfg.Scan.QuickPaths = []string{}

	engine := scanner.NewScannerEngine(cfg)
	defer engine.Stop()

	dir := t.TempDir()
	testPath := filepath.Join(dir, "test-pattern.txt")
	if err := os.WriteFile(testPath, []byte(testPattern), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	engine.EnqueueScan(testPath)

	select {
	case result := <-engine.Results():
		if result.FilePath != testPath {
			t.Errorf("expected path %s, got %s", testPath, result.FilePath)
		}
		if result.Hashes == nil || result.Hashes.SHA256 == "" {
			t.Fatal("expected non-empty SHA256 hash")
		}
		t.Logf("verdict=%s score=%.2f sha256=%s matched_rules=%v",
			result.Verdict, result.Score, result.Hashes.SHA256, result.MatchedRules)
		if result.Verdict == "clean" {
			t.Error("expected threat detection for test pattern match")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for scan result")
	}
}
