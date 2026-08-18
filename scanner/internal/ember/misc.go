package ember

import (
	"math"
	"regexp"
	"strings"

	"github.com/edr/scanner/internal/parser"
)

var (
	rePath     = regexp.MustCompile(`[a-zA-Z]:\\[\\\w\s\.\-]+`)
	reURL      = regexp.MustCompile(`https?://[^\s]+`)
	reRegistry = regexp.MustCompile(`[HKCU|HKLM|HKCR|HKU|HKCC]\\[\\\w\s\.\-]+`)
	reIP       = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
)

func computeExportFeatures(peInfo *parser.PEInfo) []float32 {
	feat := make([]float32, 144)
	if peInfo == nil {
		return feat
	}
	exportCount := len(peInfo.ExportedFunctions)
	feat[0] = float32(math.Min(float64(exportCount)/1000.0, 1.0))
	if exportCount > 0 {
		feat[1] = 1.0
	}
	// Count exports with common names
	var suspiciousExports int
	for _, exp := range peInfo.ExportedFunctions {
		expLower := strings.ToLower(exp)
		if strings.Contains(expLower, "install") || strings.Contains(expLower, "hook") ||
			strings.Contains(expLower, "inject") || strings.Contains(expLower, "bypass") {
			suspiciousExports++
		}
	}
	feat[2] = float32(math.Min(float64(suspiciousExports)/100.0, 1.0))
	feat[3] = float32(exportCount % 256) / 255.0
	return feat
}

func computeStringFeatures(data []byte) []float32 {
	feat := make([]float32, 224)
	if len(data) == 0 {
		return feat
	}

	// Extract printable strings of length >= 5
	var strs []string
	var current []byte
	for _, b := range data {
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			if len(current) >= 5 {
				strs = append(strs, string(current))
			}
			current = nil
		}
	}
	if len(current) >= 5 {
		strs = append(strs, string(current))
	}

	if len(strs) == 0 {
		return feat
	}

	// Count string types
	var totalLen int64
	var pathCount, urlCount, regCount, ipCount int
	for _, s := range strs {
		totalLen += int64(len(s))
		if rePath.MatchString(s) {
			pathCount++
		}
		if reURL.MatchString(s) {
			urlCount++
		}
		if reRegistry.MatchString(s) {
			regCount++
		}
		if reIP.MatchString(s) {
			ipCount++
		}
	}

	maxStrs := 10000.0
	feat[0] = float32(math.Min(float64(len(strs))/maxStrs, 1.0))
	feat[1] = float32(math.Min(float64(totalLen)/1e6, 1.0))
	avgLen := float64(totalLen) / float64(len(strs))
	feat[2] = float32(math.Min(avgLen/100.0, 1.0))
	feat[3] = float32(math.Min(float64(pathCount)/100.0, 1.0))
	feat[4] = float32(math.Min(float64(urlCount)/100.0, 1.0))
	feat[5] = float32(math.Min(float64(regCount)/100.0, 1.0))
	feat[6] = float32(math.Min(float64(ipCount)/100.0, 1.0))

	// Average string entropy histogram (10 bins)
	var entBins [10]int
	for _, s := range strs {
		e := windowEntropy([]byte(s))
		bin := int(e * 10.0 / 8.0)
		if bin >= 10 {
			bin = 9
		}
		entBins[bin]++
	}
	for i := 0; i < 10; i++ {
		feat[7+i] = float32(entBins[i]) / float32(len(strs))
	}

	// String length histogram (20 bins)
	var lenBins [20]int
	for _, s := range strs {
		bin := len(s) / 10
		if bin >= 20 {
			bin = 19
		}
		lenBins[bin]++
	}
	for i := 0; i < 20; i++ {
		feat[17+i] = float32(lenBins[i]) / float32(len(strs))
	}

	return feat
}

func computeMiscFeatures(data []byte, peInfo *parser.PEInfo) []float32 {
	feat := make([]float32, 121)
	if peInfo == nil || len(data) == 0 {
		return feat
	}

	// File size features (5)
	feat[0] = float32(math.Min(float64(len(data))/1e8, 1.0))
	feat[1] = float32(math.Log2(float64(len(data))+1) / 30.0)

	// Machine type (6)
	machineCodes := map[string]int{
		"I386": 0, "IA64": 1, "ARM64": 2, "AMD64": 3, "ARMNT": 4, "THUMB": 5,
	}
	if idx, ok := machineCodes[peInfo.MachineType]; ok {
		feat[2+idx] = 1.0
	}

	// Subsystem (6)
	subsystemCodes := map[string]int{
		"WINDOWS_GUI": 0, "NATIVE": 1, "WINDOWS_CUI": 2, "EFI_APPLICATION": 3, "EFI_BOOT": 4, "EFI_RUNTIME": 5,
	}
	if idx, ok := subsystemCodes[peInfo.Subsystem]; ok {
		feat[8+idx] = 1.0
	}

	// Characteristics (16 bits tracked, 9 named)
	for i, charName := range fileChars {
		for _, s := range strings.Split(peInfo.Characteristics, "|") {
			if s == charName {
				feat[14+i] = 1.0
			}
		}
	}

	// DLL characteristics (10)
	for i := 0; i < 10; i++ {
		for _, s := range strings.Split(peInfo.DllCharacteristics, "|") {
			if s == dllChars[i] {
				feat[30+i] = 1.0
			}
		}
	}

	// Compile timestamp features (3)
	if peInfo.CompileTimestamp != "" {
		feat[40] = 1.0
	}

	// Entry point features (2)
	if peInfo.EntryPoint != "" && peInfo.EntryPoint != "0x0" {
		feat[42] = 1.0
	}

	// Image base (1)
	if peInfo.ImageBase > 0x400000 {
		feat[43] = 1.0
	}

	// Is driver, DLL, packed (3)
	feat[44] = boolToFloat32(peInfo.IsDriver)
	feat[45] = boolToFloat32(peInfo.IsDLL)
	feat[46] = boolToFloat32(peInfo.Packed)

	// Authenticode, relocations, TLS, resources (4)
	feat[47] = boolToFloat32(peInfo.HasAuthenticode)
	feat[48] = boolToFloat32(peInfo.HasRelocations)
	feat[49] = boolToFloat32(peInfo.HasTLS)
	feat[50] = boolToFloat32(peInfo.HasResources)

	// Section count (1)
	feat[51] = float32(math.Min(float64(peInfo.NumberOfSections)/40.0, 1.0))

	// Linker version (2)
	feat[52] = float32(peInfo.LinkerMajor) / 255.0
	feat[53] = float32(peInfo.LinkerMinor) / 255.0

	// OS version (2)
	feat[54] = float32(peInfo.OSMajor) / 100.0
	feat[55] = float32(peInfo.OSMinor) / 100.0

	// Image version (2)
	feat[56] = float32(peInfo.ImageMajor) / 100.0
	feat[57] = float32(peInfo.ImageMinor) / 100.0

	// Size of code, init data, uninit data (3)
	feat[58] = float32(math.Min(float64(peInfo.SizeOfCode)/1e7, 1.0))
	feat[59] = float32(math.Min(float64(peInfo.SizeOfInitData)/1e7, 1.0))
	feat[60] = float32(math.Min(float64(peInfo.SizeOfUninitData)/1e7, 1.0))

	// Image size (1)
	feat[61] = float32(math.Min(float64(peInfo.ImageSize)/1e8, 1.0))

	// Rich header hash presence (1)
	if peInfo.RichHeaderHash != "" {
		feat[62] = 1.0
	}

	// Stall/reserve features (8)
	feat[63] = float32(math.Min(float64(peInfo.StackReserve)/1e8, 1.0))
	feat[64] = float32(math.Min(float64(peInfo.StackCommit)/1e8, 1.0))
	feat[65] = float32(math.Min(float64(peInfo.HeapReserve)/1e8, 1.0))
	feat[66] = float32(math.Min(float64(peInfo.HeapCommit)/1e8, 1.0))

	// Import DLL count (1)
	importCount := len(peInfo.ImportedDLLs)
	feat[67] = float32(math.Min(float64(importCount)/200.0, 1.0))

	// Import function count (1)
	funcCount := len(peInfo.ImportedFunctions)
	feat[68] = float32(math.Min(float64(funcCount)/2000.0, 1.0))

	// Export count (1)
	exportCount := len(peInfo.ExportedFunctions)
	feat[69] = float32(math.Min(float64(exportCount)/500.0, 1.0))

	return feat
}

var (
	fileChars = []string{
		"RELOCS_STRIPPED", "EXECUTABLE", "LINE_NUMS_STRIPPED", "LOCAL_SYMS_STRIPPED",
		"LARGE_ADDRESS_AWARE", "32BIT_MACHINE", "DEBUG_STRIPPED", "DLL",
		"SYSTEM",
	}
	dllChars = []string{
		"DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION", "NO_SEH",
		"NO_BIND", "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE",
	}
)

func boolToFloat32(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}
