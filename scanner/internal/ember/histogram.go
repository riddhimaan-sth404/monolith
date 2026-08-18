package ember

import "math"

func computeByteHistogram(data []byte) []float32 {
	hist := make([]float32, 256)
	if len(data) == 0 {
		return hist
	}
	for _, b := range data {
		hist[b]++
	}
	invLen := 1.0 / float32(len(data))
	for i := range hist {
		hist[i] *= invLen
	}
	return hist
}

func computeByteEntropyHistogram(data []byte) []float32 {
	hist := make([]float32, 256)
	if len(data) < 256 {
		return hist
	}
	windowSize := 2048
	step := 256
	stride := len(data) / 256
	if stride < step {
		stride = step
	}
	var entropies []float64
	for i := 0; i+windowSize <= len(data); i += stride {
		e := windowEntropy(data[i : i+windowSize])
		entropies = append(entropies, e)
		if len(entropies) >= 256 {
			break
		}
	}
	for _, e := range entropies {
		idx := int(math.Round(e * 255.0 / 8.0))
		if idx < 0 {
			idx = 0
		}
		if idx > 255 {
			idx = 255
		}
		hist[idx]++
	}
	if len(entropies) > 0 {
		inv := 1.0 / float32(len(entropies))
		for i := range hist {
			hist[i] *= inv
		}
	}
	return hist
}

func windowEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}
	e := 0.0
	length := float64(len(data))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			e -= p * math.Log2(p)
		}
	}
	return e
}
