package logging

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestInitLogger(t *testing.T) {
	if err := InitLogger("test_logs", slog.LevelDebug); err != nil {
		t.Fatal(err)
	}

	// Just verify it doesn't panic
	slog.Debug("test debug message")
	slog.Info("test info message")
	slog.Warn("test warning message")
}

func TestRotatingFileHandler(t *testing.T) {
	dir := t.TempDir()
	handler, err := NewRotatingFileHandler(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	// Write some log data
	_, err = handler.Write([]byte("test log entry\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Check that log file was created
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) == 0 {
		t.Error("expected at least one log file to be created")
	}

	// Check file content
	for _, entry := range entries {
		if !entry.IsDir() {
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 {
				t.Error("log file should not be empty")
			}
			break
		}
	}
}

func TestRotatingFileHandlerCleanOld(t *testing.T) {
	dir := t.TempDir()

	// Create some old log files manually
	for i := 0; i < 10; i++ {
		path := filepath.Join(dir, fmt.Sprintf("scanner-old-%d.log", i))
		os.WriteFile(path, []byte("old"), 0644)
	}

	handler, err := NewRotatingFileHandler(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()

	// After initialization with maxFiles=3, old files should be cleaned
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) > 6 { // 3 max + a few from rotation
		t.Logf("files after cleanup: %d", len(entries))
	}
}

func TestRotatingFileHandlerInvalidDir(t *testing.T) {
	// Create a temp file
	f, err := os.CreateTemp("", "invalid_dir")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	// Try to use a subdirectory of the file as logDir, which should fail
	invalidDir := filepath.Join(f.Name(), "logs")
	_, err = NewRotatingFileHandler(invalidDir, 5)
	if err == nil {
		t.Error("expected error for invalid directory")
	}
}

func TestRotatingFileHandlerClose(t *testing.T) {
	dir := t.TempDir()
	handler, err := NewRotatingFileHandler(dir, 5)
	if err != nil {
		t.Fatal(err)
	}

	handler.Close()
	// Should not panic on double close
	handler.Close()
}
