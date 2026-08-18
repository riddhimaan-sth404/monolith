package scanner

import (
	"encoding/base64"
	"log/slog"
)

type MemoryScanRequest struct {
	ProcessID   int    `json:"process_id"`
	ProcessName string `json:"process_name"`
	RegionBase  uint64 `json:"region_base"`
	RegionSize  uint64 `json:"region_size"`
	Protection  uint32 `json:"protection"`
	Data        string `json:"data"` // base64-encoded raw bytes
}

type MemoryScanResult struct {
	ProcessID    int      `json:"process_id"`
	ProcessName  string   `json:"process_name"`
	RegionBase   uint64   `json:"region_base"`
	MatchedRules []string `json:"matched_rules"`
	YaraMatches  int      `json:"yara_matches"`
	ContainsPE   bool     `json:"contains_pe"`
	Verdict      string   `json:"verdict"` // "clean" | "suspicious" | "malicious"
}

func (e *ScannerEngine) ScanMemory(req MemoryScanRequest) MemoryScanResult {
	result := MemoryScanResult{
		ProcessID:   req.ProcessID,
		ProcessName: req.ProcessName,
		RegionBase:  req.RegionBase,
		Verdict:     "clean",
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		slog.Error("failed to decode base64 memory data", "process", req.ProcessName, "pid", req.ProcessID, "error", err)
		result.Verdict = "clean"
		return result
	}

	if len(data) == 0 {
		return result
	}

	// 1. PE structure check (reflective DLL check)
	// Check MZ magic bytes at offset 0
	if len(data) >= 2 && data[0] == 0x4D && data[1] == 0x5A {
		result.ContainsPE = true
		result.MatchedRules = append(result.MatchedRules, "reflective_pe_header")
	}

	// 2. YARA scanning on raw bytes
	yaraMatches, err := e.yaraEngine.MatchBytes(data)
	if err != nil {
		slog.Debug("YARA memory scan failed", "pid", req.ProcessID, "error", err)
	} else {
		for _, m := range yaraMatches {
			result.MatchedRules = append(result.MatchedRules, m.RuleName)
			result.YaraMatches++
		}
	}

	// 3. Verdict: any YARA match or reflective PE -> malicious
	if result.YaraMatches > 0 || result.ContainsPE {
		result.Verdict = "malicious"
	}

	return result
}
