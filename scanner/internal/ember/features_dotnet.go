package ember

import (
	"strings"

	"github.com/edr/scanner/internal/parser"
)

// ExtractDotNet produces the 2568-dimensional feature vector from .NET assembly bytes
// using .NET-specific feature extraction (assembly refs, method counts, strings, etc.).
func ExtractDotNet(data []byte, peInfo *parser.PEInfo) []float32 {
	features := make([]float32, FeatureCount)
	offset := 0

	byteHist := computeByteHistogram(data)
	copy(features[offset:], byteHist)
	offset += 256

	byteEntropy := computeByteEntropyHistogram(data)
	copy(features[offset:], byteEntropy)
	offset += 256

	sectionFeat := computeSectionFeatures(peInfo)
	copy(features[offset:], sectionFeat)
	offset += 100

	// [612..1891] .NET-specific import/assembly features
	dotnetImportFeat := computeDotNetImportFeatures(data, peInfo)
	copy(features[offset:], dotnetImportFeat)
	offset += 1280

	// [1892..2035] .NET export features (metadata tokens)
	dotnetExportFeat := computeDotNetExportFeatures(data)
	copy(features[offset:], dotnetExportFeat)
	offset += 144

	// [2036..2259] string features
	stringFeat := computeDotNetStringFeatures(data)
	copy(features[offset:], stringFeat)
	offset += 224

	// [2260..2380] misc features
	miscFeat := computeDotNetMiscFeatures(data)
	copy(features[offset:], miscFeat)

	return features
}

func computeDotNetImportFeatures(data []byte, peInfo *parser.PEInfo) []float32 {
	f := make([]float32, 1280)

	// Encode which .NET assemblies are referenced as import-like features
	dotnetAsm := extractDotNetAssemblyRefs(data)
	for i, asm := range dotnetAsm[:minInt(len(dotnetAsm), 200)] {
		if i < len(f) {
			f[i] = clampF32(float32(len(asm)) / 100)
		}
	}

	// Common .NET assembly presence flags
	commonASMs := []string{
		"mscorlib", "System", "System.Core", "System.Data",
		"System.Windows.Forms", "System.Web", "System.Xml",
		"System.Drawing", "System.Configuration", "System.ServiceModel",
		"System.Runtime", "System.Linq", "System.IO",
		"System.Net", "System.Security", "System.Text",
		"System.Threading", "System.Collections", "System.Diagnostics",
		"System.Reflection",
	}
	asmNames := parseDotNetAssemblyNames(string(data))
	for i, casm := range commonASMs {
		for _, name := range asmNames {
			if strings.Contains(name, casm) && 200+i < len(f) {
				f[200+i] = 1.0
			}
		}
	}

	_ = peInfo
	return f
}

func computeDotNetExportFeatures(data []byte) []float32 {
	f := make([]float32, 144)
	text := string(data)

	// Count method definitions as export-like features
	methodCount := strings.Count(text, ".method")
	f[0] = clampF32(float32(methodCount) / 500)

	classCount := strings.Count(text, ".class")
	f[1] = clampF32(float32(classCount) / 200)

	propertyCount := strings.Count(text, ".property")
	f[2] = clampF32(float32(propertyCount) / 100)

	eventCount := strings.Count(text, ".event")
	f[3] = clampF32(float32(eventCount) / 50)

	fieldCount := strings.Count(text, ".field")
	f[4] = clampF32(float32(fieldCount) / 300)

	_ = text
	_ = data
	return f
}

func computeDotNetStringFeatures(data []byte) []float32 {
	f := make([]float32, 224)
	strs := extractDotNetStrings(string(data))

	f[0] = clampF32(float32(len(strs)) / 1000)

	var totalLen int
	for _, s := range strs {
		totalLen += len(s)
	}
	if len(strs) > 0 {
		f[1] = clampF32(float32(totalLen) / float32(len(strs)) / 100)
	}

	// String length histogram
	bins := make([]int, 10)
	for _, s := range strs {
		idx := len(s) / 20
		if idx > 9 {
			idx = 9
		}
		bins[idx]++
	}
	for i, v := range bins {
		f[10+i] = clampF32(float32(v) / 500)
	}

	return f
}

func computeDotNetMiscFeatures(data []byte) []float32 {
	f := make([]float32, 121)
	text := string(data)

	// Assembly metadata
	f[0] = clampF32(float32(len(data)) / 10e6)

	// Count of .custom attribute declarations
	customAttrCount := strings.Count(text, ".custom")
	f[1] = clampF32(float32(customAttrCount) / 200)

	// Count of .permission declarations
	permCount := strings.Count(text, ".permission")
	f[2] = clampF32(float32(permCount) / 50)

	// Count of .entrypoint
	if strings.Contains(text, ".entrypoint") {
		f[3] = 1.0
	}

	// Count of P/Invoke declarations
	pinvokeCount := strings.Count(text, "pinvokeimpl")
	f[4] = clampF32(float32(pinvokeCount) / 50)

	// Count of generic type parameters
	genericCount := strings.Count(text, "`")
	f[5] = clampF32(float32(genericCount) / 200)

	// Count of inheritance markers (extends, implements)
	extendsCount := strings.Count(text, "extends") + strings.Count(text, "implements")
	f[6] = clampF32(float32(extendsCount) / 100)

	_ = text
	_ = data
	return f
}

func extractDotNetAssemblyRefs(data []byte) []string {
	var refs []string
	text := string(data)
	start := 0
	for {
		idx := strings.Index(text[start:], ".assembly extern")
		if idx < 0 {
			break
		}
		lineEnd := strings.IndexByte(text[start+idx:], '\n')
		if lineEnd < 0 {
			break
		}
		line := strings.TrimSpace(text[start+idx : start+idx+lineEnd])
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			refs = append(refs, parts[2])
		}
		start = start + idx + lineEnd + 1
	}
	return refs
}

func parseDotNetAssemblyNames(text string) []string {
	var names []string
	start := 0
	for {
		idx := strings.Index(text[start:], ".assembly")
		if idx < 0 {
			break
		}
		lineEnd := strings.IndexByte(text[start+idx:], '\n')
		if lineEnd < 0 {
			break
		}
		line := strings.TrimSpace(text[start+idx : start+idx+lineEnd])
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == ".assembly" {
			names = append(names, parts[1])
		}
		start = start + idx + lineEnd + 1
	}
	return names
}

func extractDotNetStrings(text string) []string {
	var out []string
	start := 0
	for {
		idx := strings.Index(text[start:], `"`)
		if idx < 0 {
			break
		}
		start += idx + 1
		end := strings.IndexByte(text[start:], '"')
		if end < 0 {
			break
		}
		s := text[start : start+end]
		if len(s) >= 3 && len(s) < 500 {
			out = append(out, s)
		}
		start += end + 1
	}
	return out
}


