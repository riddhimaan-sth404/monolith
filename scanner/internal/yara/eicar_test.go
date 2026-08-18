//go:build integration

package yara

import (
	"testing"
)

const testPattern = "MONOLITH-EDR-INTEGRATION-TEST-PATTERN-2026"

func TestMonolithTestPattern(t *testing.T) {
	engine := NewEngine("testdata", "testdata")
	err := engine.LoadRules()
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	matches, err := engine.MatchBytes([]byte(testPattern))
	if err != nil {
		t.Fatalf("MatchBytes failed: %v", err)
	}

	if len(matches) == 0 {
		t.Error("expected YARA match for test pattern, got none")
	} else {
		t.Logf("matched: rule=%s tags=%v metadata=%v",
			matches[0].RuleName, matches[0].Tags, matches[0].Metadata)
		if matches[0].RuleName != "MONOLITH_TEST" {
			t.Errorf("expected rule MONOLITH_TEST, got %s", matches[0].RuleName)
		}
	}
}

func TestMonolithTestPatternNegative(t *testing.T) {
	engine := NewEngine("testdata", "testdata")
	err := engine.LoadRules()
	if err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	matches, err := engine.MatchBytes([]byte("this is a benign test file with no suspicious content"))
	if err != nil {
		t.Fatalf("MatchBytes failed: %v", err)
	}

	if len(matches) != 0 {
		t.Errorf("expected 0 matches for benign content, got %d", len(matches))
	}
}
