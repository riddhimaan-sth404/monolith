package scanner

import (
	"testing"

	"github.com/edr/scanner/internal/hasher"
	"github.com/edr/scanner/internal/parser"
)

func makePE(machine string, subsystem string, sections []parser.SectionDetail, imports []string, exported []string, opts map[string]interface{}) *parser.PEInfo {
	pe := &parser.PEInfo{
		MachineType:        machine,
		Subsystem:          subsystem,
		Sections:           sections,
		ImportedDLLs:       imports,
		ExportedFunctions:  exported,
		Characteristics:    "EXECUTABLE",
		NumberOfSections:   len(sections),
		HasAuthenticode:    true,
		HasRelocations:     true,
		HasResources:       false,
		HasTLS:             false,
		IsDLL:              false,
		IsDriver:           false,
		Packed:             false,
		EntryPoint:         "0x1000",
		CompileTimestamp:   "2024-01-01T00:00:00Z",
		LinkerMajor:        14,
		LinkerMinor:        28,
		OSMajor:            10,
		OSMinor:            0,
		SizeOfCode:         10000,
		SizeOfInitData:     5000,
		SizeOfUninitData:   1000,
		ImageSize:          100000,
	}
	for k, v := range opts {
		switch k {
		case "packed":
			pe.Packed = v.(bool)
		case "has_authenticode":
			pe.HasAuthenticode = v.(bool)
		case "has_relocations":
			pe.HasRelocations = v.(bool)
		case "is_dll":
			pe.IsDLL = v.(bool)
		case "has_resources":
			pe.HasResources = v.(bool)
		case "entry_point":
			pe.EntryPoint = v.(string)
		case "compile_timestamp":
			pe.CompileTimestamp = v.(string)
		case "dll_characteristics":
			pe.DllCharacteristics = v.(string)
		}
	}
	return pe
}

func makeHashes(entropy float64) *hasher.FileHashes {
	return &hasher.FileHashes{
		SHA256:  "abc123",
		SHA1:    "def456",
		MD5:     "789ghi",
		Entropy: entropy,

	}
}

func TestHeuristicCleanNoFlags(t *testing.T) {
	pe := makePE("AMD64", "WINDOWS_GUI", []parser.SectionDetail{
		{Name: ".text", VirtualSize: 4096, RawDataSize: 2048, Entropy: 5.0},
	}, []string{"kernel32.dll"}, []string{"DllMain"}, nil)
	hashes := makeHashes(5.0)
	score, _ := computeHeuristics(pe, hashes)
	if score != 0.0 {
		t.Errorf("expected 0 for clean PE, got %f", score)
	}
}

func TestHeuristicPackedDetected(t *testing.T) {
	pe := makePE("AMD64", "WINDOWS_GUI", []parser.SectionDetail{
		{Name: ".UPX0", VirtualSize: 65536, RawDataSize: 0, Entropy: 7.8},
	}, []string{"kernel32.dll"}, []string{"DllMain"}, map[string]interface{}{"packed": true})
	hashes := makeHashes(7.9)
	score, rules := computeHeuristics(pe, hashes)
	if score != 0.0 {
		t.Errorf("expected 0 for packed PE, got %f, rules: %v", score, rules)
	}
}

func TestFuseVerdictMalicious(t *testing.T) {
	r := ScanResult{
		Score:        11.5,
		EmberScore:   0.0,
		PEInfo: &parser.PEInfo{},
	}
	r = fuseVerdict(r)
	if r.Verdict != "malicious" {
		t.Errorf("expected malicious for score 11.5, got %s", r.Verdict)
	}
}

func TestFuseVerdictSuspicious(t *testing.T) {
	r := ScanResult{
		Score:        8.5,
		EmberScore:   0.0,
		PEInfo: &parser.PEInfo{},
	}
	r = fuseVerdict(r)
	if r.Verdict != "suspicious" {
		t.Errorf("expected suspicious for score 8.5, got %s", r.Verdict)
	}
}

func TestFuseVerdictClean(t *testing.T) {
	r := ScanResult{
		Score:      1.0,
		EmberScore: 0.0,
		PEInfo:     &parser.PEInfo{},
	}
	r = fuseVerdict(r)
	if r.Verdict != "clean" {
		t.Errorf("expected clean for score 1.0, got %s", r.Verdict)
	}
}

func TestFuseVerdictHighEmber(t *testing.T) {
	r := ScanResult{
		Score:      1.0,
		EmberScore: 0.96,
		PEInfo:     &parser.PEInfo{},
	}
	r = fuseVerdict(r)
	if r.Verdict != "malicious" {
		t.Errorf("expected malicious for EMBER 0.96, got %s", r.Verdict)
	}
}

func TestFuseVerdictMediumEmber(t *testing.T) {
	r := ScanResult{
		Score:      1.0,
		EmberScore: 0.85,
		PEInfo:     &parser.PEInfo{},
	}
	r = fuseVerdict(r)
	if r.Verdict != "suspicious" {
		t.Errorf("expected suspicious for EMBER 0.85, got %s", r.Verdict)
	}
}

func TestFuseVerdictSandboxTrigger(t *testing.T) {
	r := ScanResult{
		Score:      2.0,
		EmberScore: 0.85,
		PEInfo:     &parser.PEInfo{},
	}
	r.NeedsSandbox = r.EmberScore > 0.80 && r.EmberScore < 0.96
	if !r.NeedsSandbox {
		t.Error("expected NeedsSandbox for EMBER score 0.85")
	}
}
