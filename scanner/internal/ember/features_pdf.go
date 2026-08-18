package ember

import (
	"fmt"
	"strings"

	"github.com/edr/scanner/internal/parser"
)

// ExtractPDF produces the 2568-dimensional feature vector from PDF file bytes
// using PDF-specific feature extraction (object counts, filters, actions, etc.).
func ExtractPDF(data []byte, pdfInfo *parser.PDFInfo) []float32 {
	features := make([]float32, FeatureCount)
	offset := 0

	byteHist := computeByteHistogram(data)
	copy(features[offset:], byteHist)
	offset += 256

	byteEntropy := computeByteEntropyHistogram(data)
	copy(features[offset:], byteEntropy)
	offset += 256

	pdfObjFeat := computePDFObjectFeatures(pdfInfo, data)
	copy(features[offset:], pdfObjFeat)
	offset += 100

	pdfImportFeat := computePDFImportFeatures(pdfInfo)
	copy(features[offset:], pdfImportFeat)
	offset += 1280

	pdfActionFeat := computePDFActionFeatures(pdfInfo)
	copy(features[offset:], pdfActionFeat)
	offset += 144

	stringFeat := computePDFStringFeatures(data)
	copy(features[offset:], stringFeat)
	offset += 224

	miscFeat := computePDFMiscFeatures(data, pdfInfo)
	copy(features[offset:], miscFeat)

	return features
}

func computePDFObjectFeatures(info *parser.PDFInfo, data []byte) []float32 {
	f := make([]float32, 100)
	f[0] = clampF32(float32(info.ObjectCount) / 5000)
	f[1] = clampF32(float32(info.StreamCount) / 2000)
	f[2] = clampF32(float32(info.PageCount) / 500)
	if info.ObjectCount > 0 {
		f[3] = clampF32(float32(info.StreamCount) / float32(info.ObjectCount))
	}
	objTypes := countPDFObjectTypes(string(data))
	for i, v := range objTypes[:minInt(len(objTypes), 96)] {
		f[4+i] = clampF32(float32(v) / 1000)
	}
	return f
}

func countPDFObjectTypes(text string) []int {
	types := make([]int, 96)
	objMarkers := []struct {
		marker string
		idx    int
	}{
		{"/Type /Page", 0},
		{"/Type /Pages", 1},
		{"/Type /Catalog", 2},
		{"/Type /Metadata", 3},
		{"/Type /Font", 4},
		{"/Type /FontDescriptor", 5},
		{"/Type /XObject", 6},
		{"/Type /Annot", 7},
		{"/Type /Action", 8},
		{"/Type /Outlines", 9},
		{"/Type /Pattern", 10},
		{"/Type /Shading", 11},
		{"/Type /ExtGState", 12},
		{"/Type /Encoding", 13},
		{"/Subtype /Image", 14},
		{"/Subtype /Form", 15},
		{"/Subtype /Font", 16},
		{"/Subtype /TrueType", 17},
		{"/Subtype /Type1", 18},
		{"/Subtype /CIDFontType0", 19},
		{"/Subtype /CIDFontType2", 20},
		{"/Subtype /Link", 21},
		{"/Subtype /Widget", 22},
		{"/Subtype /RichMedia", 23},
		{"/Subtype /Movie", 24},
		{"/Subtype /Sound", 25},
		{"/Subtype /FileAttachment", 26},
		{"/Subtype /Popup", 27},
		{"/Length ", 28},
		{"/Filter", 29},
		{"/FontFile", 30},
		{"/FontDescriptor", 31},
		{"/ToUnicode", 32},
	}
	for _, om := range objMarkers {
		count := strings.Count(text, om.marker)
		if count > 0 && om.idx < len(types) {
			types[om.idx] = count
		}
	}
	return types
}

func computePDFImportFeatures(info *parser.PDFInfo) []float32 {
	f := make([]float32, 1280)
	commonFilters := []string{
		"FlateDecode", "ASCIIHexDecode", "ASCII85Decode", "LZWDecode",
		"RunLengthDecode", "CCITTFaxDecode", "JBIG2Decode", "DCTDecode",
		"JPXDecode", "Crypt", "RL", "AHx", "A85", "LZW",
	}
	for i, cf := range commonFilters {
		for _, fName := range info.Filters {
			if fName == cf && i < len(f) {
				f[i] = 1.0
			}
		}
	}
	f[64] = clampF32(float32(info.ObjectCount) / 1000)
	f[65] = clampF32(float32(info.StreamCount) / 500)
	return f
}

func computePDFActionFeatures(info *parser.PDFInfo) []float32 {
	f := make([]float32, 144)
	if info.HasJS {
		f[0] = 1.0
	}
	if info.HasOpenAction {
		f[1] = 1.0
	}
	if info.HasLaunch {
		f[2] = 1.0
	}
	if info.HasEmbedded {
		f[3] = 1.0
	}
	if info.HasURI {
		f[4] = 1.0
	}
	if info.Encrypted {
		f[5] = 1.0
	}
	if info.Linearized {
		f[6] = 1.0
	}
	f[7] = clampF32(float32(info.URLCount) / 100)
	f[8] = clampF32(float32(info.JSSnippets) / 50)
	f[9] = clampF32(float32(info.PageCount) / 100)

	versionVal := parsePDFVersion(info.Version)
	f[10] = clampF32(float32(versionVal) / 2.0)
	return f
}

func parsePDFVersion(v string) float64 {
	if v == "" {
		return 1.0
	}
	var major, minor float64
	n, _ := fmt.Sscanf(v, "%f.%f", &major, &minor)
	if n >= 2 {
		return major + minor/10.0
	}
	return 1.0
}

func computePDFStringFeatures(data []byte) []float32 {
	f := make([]float32, 224)
	avgLen, entropy, count := parser.ComputePDFStringStats(data)
	f[0] = clampF32(float32(avgLen) / 100)
	f[1] = clampF32(float32(entropy) / 8)
	f[2] = clampF32(float32(count) / 1000)

	strs := parser.ExtractPDFStrings(data)
	bins := make([]int, 10)
	for _, s := range strs {
		idx := len(s) / 10
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

func computePDFMiscFeatures(data []byte, info *parser.PDFInfo) []float32 {
	f := make([]float32, 121)
	fileSize := len(data)
	f[0] = clampF32(float32(fileSize) / 10e6)

	if info.StreamCount > 0 && len(info.StreamSizes) > 0 {
		var totalStreamSize int64
		for _, s := range info.StreamSizes {
			totalStreamSize += s
		}
		if fileSize > 0 {
			f[1] = clampF32(float32(float64(totalStreamSize) / float64(fileSize)))
		}
	}

	f[2] = clampF32(float32(info.XrefTableSize) / 10)
	f[3] = clampF32(float32(len(info.Filters)) / 20)

	firstObj := strings.Index(string(data), " obj")
	if firstObj > 0 {
		f[4] = clampF32(float32(firstObj) / 1000)
	}

	return f
}

func clampF32(v float32) float32 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}


