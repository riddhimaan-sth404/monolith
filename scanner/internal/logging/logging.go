package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type RotatingFileHandler struct {
	dir       string
	maxFiles  int
	current   *os.File
	writer    io.Writer
	closeChan chan struct{}
	once      sync.Once
}

func NewRotatingFileHandler(dir string, maxFiles int) (*RotatingFileHandler, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	h := &RotatingFileHandler{
		dir:       dir,
		maxFiles:  maxFiles,
		closeChan: make(chan struct{}),
	}

	if err := h.rotate(); err != nil {
		return nil, err
	}

	// Start rotation timer
	go h.rotationLoop()

	return h, nil
}

func (h *RotatingFileHandler) Write(p []byte) (n int, err error) {
	return h.writer.Write(p)
}

func (h *RotatingFileHandler) rotate() error {
	// Close current file
	if h.current != nil {
		h.current.Close()
	}

	// Create new log file with timestamp
	timestamp := time.Now().Format("2006-01-02-150405")
	logPath := filepath.Join(h.dir, "scanner-"+timestamp+".log")

	f, err := os.Create(logPath)
	if err != nil {
		return err
	}

	h.current = f
	h.writer = io.MultiWriter(f, os.Stdout)

	// Clean old log files
	h.cleanOld()

	return nil
}

func (h *RotatingFileHandler) cleanOld() {
	glob := filepath.Join(h.dir, "scanner-*.log")
	files, err := filepath.Glob(glob)
	if err != nil {
		return
	}

	if len(files) > h.maxFiles {
		// Keep the newest N files
		filesToRemove := len(files) - h.maxFiles
		for i := 0; i < filesToRemove; i++ {
			os.Remove(files[i])
		}
	}
}

func (h *RotatingFileHandler) rotationLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.rotate()
		case <-h.closeChan:
			return
		}
	}
}

func (h *RotatingFileHandler) Close() {
	h.once.Do(func() {
		close(h.closeChan)
		if h.current != nil {
			h.current.Close()
		}
	})
}

func InitLogger(logDir string, level slog.Level) error {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
	return nil
}
