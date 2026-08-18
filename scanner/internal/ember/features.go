package ember

import "github.com/edr/scanner/internal/parser"

const FeatureCount = 2568

// Extract produces a 2568-dimensional feature vector from PE file bytes.
// Layout (EMBER 2024):
//   [0..255]    byte_histogram: 256
//   [256..511]  byte_entropy: 256
//   [512..611]  section: 100 (10 sections × 10 features)
//   [612..1891] imports: 1280 (256 common DLLs × 5 features)
//   [1892..2035] exports: 144
//   [2036..2259] strings: 224
//   [2260..2380] misc: 121
//   [2381..2567] reserved: 187 (EMBER 2024 additional features, zero-padded)
func Extract(data []byte, peInfo *parser.PEInfo) []float32 {
	features := make([]float32, FeatureCount)
	if len(data) == 0 {
		return features
	}
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

	importFeat := computeImportFeatures(peInfo)
	copy(features[offset:], importFeat)
	offset += 1280

	exportFeat := computeExportFeatures(peInfo)
	copy(features[offset:], exportFeat)
	offset += 144

	stringFeat := computeStringFeatures(data)
	copy(features[offset:], stringFeat)
	offset += 224

	miscFeat := computeMiscFeatures(data, peInfo)
	copy(features[offset:], miscFeat)

	return features
}
