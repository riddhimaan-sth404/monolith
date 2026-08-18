package throttle

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

type Throttle struct {
	maxIOPS    int
	ticker     *time.Ticker
	opsCount   int
	lastReset  time.Time
	mu         sync.Mutex
}

func NewThrottle(maxIOPS int) *Throttle {
	return &Throttle{
		maxIOPS:   maxIOPS,
		ticker:    time.NewTicker(time.Second),
		lastReset: time.Now(),
	}
}

func (t *Throttle) Acquire(ctx context.Context) error {
	for {
	err := ctx.Err()
		if err != nil {
			return err
		}

		t.mu.Lock()
		now := time.Now()
		if now.Sub(t.lastReset) >= time.Second {
			t.opsCount = 0
			t.lastReset = now
		}

		if t.opsCount < t.maxIOPS {
			t.opsCount++
			t.mu.Unlock()
			return nil
		}
		t.mu.Unlock()

		select {
		case <-t.ticker.C:
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *Throttle) Stop() {
	t.ticker.Stop()
}

// Monitor system resources and suggest throttling adjustments
func MonitorResources() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			memUsed := m.Alloc / 1024 / 1024
			cpuUsage := runtime.NumGoroutine()

			slog.Debug("system resources",
				"memory_mb", memUsed,
				"goroutines", cpuUsage,
			)

			// Suggest GC if memory is high
			if memUsed > 500 {
				runtime.GC()
				slog.Warn("triggered GC due to high memory usage", "memory_mb", memUsed)
			}
		}
	}()
}
