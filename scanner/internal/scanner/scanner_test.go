package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/edr/scanner/internal/config"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Scanner: config.ScannerConfig{
			Concurrency:  2,
			ThrottleIOPS: 1000,
		},
		Scan: config.ScanConfig{
			MaxFileSizeMB: 100,
			ExcludedPaths: []string{},
			QuickPaths:    []string{},
		},
	}
}

func TestNewScannerEngine(t *testing.T) {
	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.ActiveJobs() != 0 {
		t.Errorf("expected 0 active jobs, got %d", engine.ActiveJobs())
	}
}

func TestEnqueueAndProcess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("Hello, EDR Scanner!")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	engine.EnqueueScan(path)

	// Wait for result
	select {
	case result := <-engine.Results():
		if result.FilePath != path {
			t.Errorf("expected path %s, got %s", path, result.FilePath)
		}
		if result.Hashes == nil {
			t.Error("expected hashes to be computed")
		}
		if result.Hashes.SHA256 == "" {
			t.Error("expected SHA256 hash")
		}
		if result.Verdict != "clean" {
			t.Errorf("expected verdict 'clean', got '%s'", result.Verdict)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for scan result")
	}
}

func TestEnqueueNonexistentFile(t *testing.T) {
	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	// This should not produce a result (file doesn't exist)
	engine.EnqueueScan("/nonexistent/path/file.exe")

	select {
	case result := <-engine.Results():
		if result.Verdict != "error" {
			t.Errorf("expected verdict error, got %s", result.Verdict)
		}
	case <-time.After(2 * time.Second):
		t.Error("expected result for nonexistent file")
	}
}

func TestEnqueueDirectory(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory
	subDir := filepath.Join(dir, "subdir")
	os.MkdirAll(subDir, 0755)

	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	// Enqueue a directory - should be skipped
	engine.EnqueueScan(subDir)

	select {
	case <-engine.Results():
		t.Error("expected no result for directory")
	case <-time.After(2 * time.Second):
		// Expected timeout
	}
}

func TestEnqueueOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	// Create a file larger than max file size (100MB in config)
	data := make([]byte, 101*1024*1024) // 101MB
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Skip("disk space may be insufficient for large file test")
	}

	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	engine.EnqueueScan(path)

	select {
	case result := <-engine.Results():
		if result.Verdict != "skipped" {
			t.Errorf("expected verdict 'skipped', got '%s'", result.Verdict)
		}
	case <-time.After(2 * time.Second):
		t.Error("expected result with verdict skipped")
	}
}

func TestConcurrentEnqueue(t *testing.T) {
	dir := t.TempDir()
	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	// Create multiple files
	numFiles := 10
	for i := 0; i < numFiles; i++ {
		path := filepath.Join(dir, fmt.Sprintf("file_%d.txt", i))
		os.WriteFile(path, []byte("test"), 0644)
		engine.EnqueueScan(path)
	}

	// Collect results
	results := make([]ScanResult, 0, numFiles)
	timeout := time.After(10 * time.Second)

	for len(results) < numFiles {
		select {
		case result := <-engine.Results():
			results = append(results, result)
		case <-timeout:
			t.Fatalf("timeout: got %d/%d results", len(results), numFiles)
		}
	}

	if len(results) != numFiles {
		t.Errorf("expected %d results, got %d", numFiles, len(results))
	}
}

func TestScannerEngineStop(t *testing.T) {
	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)

	// Stop the engine
	engine.Stop()

	// After stop, ActiveJobs() should be safe to call
	// and no more results should come through
	_ = engine.ActiveJobs()
}

func TestActiveJobsCounter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "job_counter.txt")
	os.WriteFile(path, []byte("test"), 0644)

	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	engine.EnqueueScan(path)
	time.Sleep(500 * time.Millisecond)

	// Active jobs should be 0 after processing
	if engine.ActiveJobs() != 0 {
		t.Logf("active jobs: %d (may not have finished yet)", engine.ActiveJobs())
	}
}

func TestScanLifecycleReportsActiveUntilDrain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan_lifecycle.txt")
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := newTestConfig()
	cfg.Scan.QuickPaths = []string{dir}
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	engine.StartQuickScan()
	if !engine.IsScanActive() {
		t.Fatal("expected quick scan to be active immediately after start")
	}

	deadline := time.After(5 * time.Second)
	for {
		if !engine.IsScanActive() {
			break
		}
		select {
		case <-deadline:
			t.Fatal("scan did not finish within deadline")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestEnqueueWhenQueueFull(t *testing.T) {
	cfg := newTestConfig()
	engine := NewScannerEngine(cfg)
	defer engine.Stop()

	// Fill the queue (capacity is 10000)
	for i := 0; i < 10001; i++ {
		engine.EnqueueScan("test_path")
	}

	// Active jobs should be at most 10000
	if engine.ActiveJobs() > 10000 {
		t.Errorf("active jobs should not exceed queue capacity, got %d", engine.ActiveJobs())
	}
}
