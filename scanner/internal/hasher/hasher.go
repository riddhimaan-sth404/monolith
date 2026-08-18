package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"os"
)

type FileHashes struct {
	SHA256  string  `json:"sha256"`
	SHA1    string  `json:"sha1"`
	MD5     string  `json:"md5"`
	Entropy float64 `json:"entropy"`
}

func ComputeHashes(path string) (*FileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sha256h := sha256.New()
	sha1h := sha1.New()
	md5h := md5.New()

	// Compute all hashes in a single pass using multi-writer
	multiWriter := io.MultiWriter(sha256h, sha1h, md5h)

	// Also compute entropy by counting byte frequencies
	freq := make([]int, 256)
	totalBytes := 0
	buf := make([]byte, 32768)

	for {
		n, err := f.Read(buf)
		if n > 0 {
			multiWriter.Write(buf[:n])
			for _, b := range buf[:n] {
				freq[b]++
				totalBytes++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	// Calculate entropy
	entropy := 0.0
	if totalBytes > 0 {
		for _, count := range freq {
			if count > 0 {
				p := float64(count) / float64(totalBytes)
				entropy -= p * math.Log2(p)
			}
		}
	}

	return &FileHashes{
		SHA256:  hex.EncodeToString(sha256h.Sum(nil)),
		SHA1:    hex.EncodeToString(sha1h.Sum(nil)),
		MD5:     hex.EncodeToString(md5h.Sum(nil)),
		Entropy: math.Round(entropy*100) / 100,
	}, nil
}

func ComputeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func ComputeSHA1(data []byte) string {
	h := sha1.Sum(data)
	return hex.EncodeToString(h[:])
}

func ComputeMD5(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}
