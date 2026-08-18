package ember

import (
	"math"
	"testing"

	"github.com/edr/scanner/internal/parser"
)

func TestFeatureCount(t *testing.T) {
	if FeatureCount != 2568 {
		t.Fatalf("expected 2568 features, got %d", FeatureCount)
	}
}

func TestExtractEmptyData(t *testing.T) {
	features := Extract(nil, nil)
	if len(features) != FeatureCount {
		t.Fatalf("expected %d features, got %d", FeatureCount, len(features))
	}
	for _, f := range features {
		if f != 0.0 {
			t.Fatal("expected all zeros for nil input")
			break
		}
	}
}

func TestExtractBasicPE(t *testing.T) {
	// Minimal PE-like data: DOS header + PE signature + empty sections
	data := make([]byte, 512)
	// DOS header: "MZ" at offset 0
	data[0] = 'M'
	data[1] = 'Z'
	// e_lfanew at offset 0x3C = 0x80
	data[0x3C] = 0x80
	// PE signature at offset 0x80
	data[0x80] = 'P'
	data[0x81] = 'E'
	// File header at offset 0x84
	// Machine: 0x8664 (AMD64)
	data[0x84] = 0x64
	data[0x85] = 0x86

	peInfo := &parser.PEInfo{
		MachineType:      "AMD64",
		Subsystem:        "WINDOWS_CUI",
		NumberOfSections: 3,
		SectionNames:     []string{".text", ".data", ".rsrc"},
		Sections: []parser.SectionDetail{
			{Name: ".text", VirtualSize: 4096, RawDataSize: 2048, Entropy: 5.5},
			{Name: ".data", VirtualSize: 1024, RawDataSize: 512, Entropy: 3.2},
			{Name: ".rsrc", VirtualSize: 2048, RawDataSize: 2048, Entropy: 6.8},
		},
		ImportedDLLs:      []string{"kernel32.dll", "user32.dll"},
		ImportedFunctions: []string{"CreateFile", "ReadFile", "MessageBoxA"},
		IsDLL:             false,
		IsDriver:          false,
		Packed:            false,
		LinkerMajor:       10,
		LinkerMinor:       0,
		OSMajor:           6,
		OSMinor:           1,
		HasRelocations:    true,
		HasResources:      true,
		HasTLS:            false,
		HasAuthenticode:   true,
		EntryPoint:        "0x1000",
		ImageBase:         0x140000000,
		ImageSize:         0x10000,
		SizeOfCode:        4096,
		SizeOfInitData:    1024,
		SizeOfUninitData:  512,
		StackReserve:      1048576,
		StackCommit:       4096,
		HeapReserve:       1048576,
		HeapCommit:        4096,
		CompileTimestamp:  "2024-01-15T10:00:00Z",
	}

	features := Extract(data, peInfo)
	if len(features) != FeatureCount {
		t.Fatalf("expected %d features, got %d", FeatureCount, len(features))
	}

	// Byte histogram should have non-zero values
	var byteHistSum float32
	for i := 0; i < 256; i++ {
		byteHistSum += features[i]
	}
	if byteHistSum <= 0 {
		t.Fatal("expected non-zero byte histogram sum")
	}
	if math.Abs(float64(byteHistSum)-1.0) > 0.01 {
		t.Fatalf("expected byte histogram to sum to ~1.0, got %f", byteHistSum)
	}

	// Section features should be populated
	var sectionSum float32
	for i := 512; i < 612; i++ {
		sectionSum += features[i]
	}
	if sectionSum <= 0 {
		t.Fatal("expected non-zero section features sum")
	}

	// Import features for kernel32.dll should be 1.0
	if features[612] != 1.0 {
		t.Fatalf("expected kernel32.dll import feature to be 1.0, got %f", features[612])
	}
}

func TestComputeByteHistogram(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00}
	hist := computeByteHistogram(data)

	if math.Abs(float64(hist[0]-3.0/7.0)) > 1e-6 {
		t.Fatalf("expected freq[0]=%f, got %f", 3.0/7.0, hist[0])
	}
	if math.Abs(float64(hist[1]-2.0/7.0)) > 1e-6 {
		t.Fatalf("expected freq[1]=%f, got %f", 2.0/7.0, hist[1])
	}
	if math.Abs(float64(hist[2]-1.0/7.0)) > 1e-6 {
		t.Fatalf("expected freq[2]=%f, got %f", 1.0/7.0, hist[2])
	}
	if math.Abs(float64(hist[3]-1.0/7.0)) > 1e-6 {
		t.Fatalf("expected freq[3]=%f, got %f", 1.0/7.0, hist[3])
	}
	if hist[4] != 0 {
		t.Fatalf("expected freq[4]=0, got %f", hist[4])
	}

	var total float32
	for _, f := range hist {
		total += f
	}
	if math.Abs(float64(total)-1.0) > 0.001 {
		t.Fatalf("expected total ~1.0, got %f", total)
	}
}

func TestComputeByteEntropyHistogram(t *testing.T) {
	// All same bytes = zero entropy
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0x90
	}
	entropy := computeByteEntropyHistogram(data)

	// Low entropy should concentrate in first few bins
	var lowEntropyBins float32
	for i := 0; i < 10; i++ {
		lowEntropyBins += entropy[i]
	}
	if lowEntropyBins < 0.5 {
		t.Fatalf("expected low-entropy data to have most mass in early bins, got %f", lowEntropyBins)
	}
}

func TestComputeSectionFeatures(t *testing.T) {
	peInfo := &parser.PEInfo{
		Sections: []parser.SectionDetail{
			{Name: ".text", VirtualSize: 4096, RawDataSize: 2048, Entropy: 6.0},
			{Name: ".UPX0", VirtualSize: 65536, RawDataSize: 0, Entropy: 0.0},
		},
	}
	feat := computeSectionFeatures(peInfo)

	if feat[0] != 6.0/8.0 {
		t.Fatalf("expected .text entropy feature %f, got %f", 6.0/8.0, feat[0])
	}
	if feat[10] != 0 {
		t.Fatalf("expected .UPX0 entropy feature 0, got %f", feat[10])
	}
}

func TestComputeImportFeatures(t *testing.T) {
	peInfo := &parser.PEInfo{
		ImportedDLLs: []string{
			"KERNEL32.DLL",
			"USER32.DLL",
			"WININET.DLL",
		},
	}
	feat := computeImportFeatures(peInfo)

	// kernel32.dll should be first in CommonWindowsDLLs
	if feat[0] != 1.0 {
		t.Fatalf("expected kernel32.dll at index 0, got %f", feat[0])
	}
	// Unknown DLL should not be present
	if feat[5*255] != 0 {
		t.Fatalf("expected unknown DLL at last slot to be 0, got %f", feat[5*255])
	}
}

func TestComputeMiscFeatures(t *testing.T) {
	data := make([]byte, 4096)
	peInfo := &parser.PEInfo{
		MachineType:      "AMD64",
		Subsystem:        "WINDOWS_GUI",
		Characteristics:  "EXECUTABLE|DLL",
		DllCharacteristics: "DYNAMIC_BASE|NX_COMPAT",
		NumberOfSections: 4,
		IsDLL:            false,
		IsDriver:         false,
		Packed:           false,
		HasAuthenticode:  false,
		HasRelocations:   true,
		HasTLS:           false,
		HasResources:     true,
		LinkerMajor:      14,
		LinkerMinor:      28,
		OSMajor:          10,
		OSMinor:          0,
		ImageMajor:       0,
		ImageMinor:       0,
		SizeOfCode:       10000,
		SizeOfInitData:   5000,
		SizeOfUninitData: 1000,
		ImageSize:        100000,
		CompileTimestamp: "2022-06-15T12:00:00Z",
	}

	feat := computeMiscFeatures(data, peInfo)

	if feat[0] <= 0 {
		t.Fatal("expected non-zero file size feature")
	}
	if feat[5] != 1.0 {
		t.Fatalf("expected AMD64 machine type, got %f", feat[5])
	}
	if feat[8] != 1.0 {
		t.Fatalf("expected WINDOWS_GUI subsystem, got %f", feat[8])
	}
	if feat[14+1] != 1.0 { // EXECUTABLE at index 1
		t.Fatal("expected EXECUTABLE characteristic flag")
	}
	if feat[30+0] != 1.0 { // DYNAMIC_BASE at index 0
		t.Fatal("expected DYNAMIC_BASE DLL characteristic flag")
	}
	if feat[30+2] != 1.0 { // NX_COMPAT at index 2
		t.Fatal("expected NX_COMPAT DLL characteristic flag")
	}
}

func TestComputeStringFeatures(t *testing.T) {
	data := []byte("hello world this is a test string with enough length for analysis\x00")
	feat := computeStringFeatures(data)

	if feat[0] <= 0 {
		t.Fatal("expected non-zero string count feature")
	}
}
