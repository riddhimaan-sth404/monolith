package throttle

import (
	"context"
	"testing"
	"time"
)

func TestNewThrottle(t *testing.T) {
	tl := NewThrottle(100)
	if tl == nil {
		t.Fatal("expected non-nil throttle")
	}
	if tl.maxIOPS != 100 {
		t.Errorf("expected maxIOPS=100, got %d", tl.maxIOPS)
	}
	tl.Stop()
}

func TestAcquireWithinLimit(t *testing.T) {
	tl := NewThrottle(10)
	defer tl.Stop()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := tl.Acquire(ctx); err != nil {
			t.Errorf("expected no error on acquire %d, got %v", i, err)
		}
	}
}

func TestAcquireExceedsLimit(t *testing.T) {
	tl := NewThrottle(5)
	defer tl.Stop()

	ctx := context.Background()
	// Consume all tokens
	for i := 0; i < 5; i++ {
		tl.Acquire(ctx)
	}

	// Next acquire should block or return error with cancelled context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := tl.Acquire(ctx)
	if err == nil {
		t.Error("expected error when exceeding throttle limit with short timeout")
	}
}

func TestAcquireResetsAfterSecond(t *testing.T) {
	tl := NewThrottle(5)
	defer tl.Stop()

	ctx := context.Background()
	// Consume all tokens
	for i := 0; i < 5; i++ {
		tl.Acquire(ctx)
	}

	// Wait for reset
	time.Sleep(1100 * time.Millisecond)

	// Should be able to acquire again
	if err := tl.Acquire(ctx); err != nil {
		t.Errorf("expected no error after reset, got %v", err)
	}
}

func TestAcquireContextCancelled(t *testing.T) {
	tl := NewThrottle(1)
	defer tl.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	tl.Acquire(ctx) // consume the only token

	// Cancel context and try to acquire
	cancel()
	err := tl.Acquire(ctx)
	if err == nil {
		t.Error("expected error with cancelled context")
	}
}

func TestMonitorResources(t *testing.T) {
	// Just ensure it doesn't panic
	MonitorResources()
	time.Sleep(100 * time.Millisecond)
}
