package ember

import (
	"math"

	"github.com/edr/scanner/internal/parser"
)

func computeSectionFeatures(peInfo *parser.PEInfo) []float32 {
	feat := make([]float32, 100)
	if peInfo == nil {
		return feat
	}
	for i, s := range peInfo.Sections {
		if i >= 10 {
			break
		}
		base := i * 10
		feat[base+0] = float32(math.Min(s.Entropy, 8.0) / 8.0)
		feat[base+1] = float32(math.Min(float64(s.VirtualSize)/1e7, 1.0))
		feat[base+2] = float32(math.Min(float64(s.RawDataSize)/1e7, 1.0))
		// ratio of virtual size to raw size
		if s.RawDataSize > 0 {
			feat[base+3] = float32(math.Min(float64(s.VirtualSize)/float64(s.RawDataSize), 10.0) / 10.0)
		}
		// has characteristics flags
		feat[base+4] = b2f(s.Characteristics != "")
		feat[base+5] = b2f(s.VirtualSize > 0 && s.RawDataSize == 0)
		feat[base+6] = b2f(s.VirtualSize == 0 && s.RawDataSize > 0)
		feat[base+7] = b2f(s.VirtualSize > s.RawDataSize*3)
		feat[base+8] = float32(math.Min(float64(len(peInfo.SectionNames))/40.0, 1.0))
		feat[base+9] = float32(s.Entropy * s.Entropy / 64.0) // squared entropy feature
	}
	return feat
}

func b2f(b bool) float32 {
	if b {
		return 1.0
	}
	return 0.0
}
