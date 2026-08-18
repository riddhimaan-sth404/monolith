package hasher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeHashes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	content := []byte("Hello, EDR Scanner!")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	hashes, err := ComputeHashes(path)
	if err != nil {
		t.Fatal(err)
	}

	if hashes.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}
	if hashes.SHA1 == "" {
		t.Error("SHA1 should not be empty")
	}
	if hashes.MD5 == "" {
		t.Error("MD5 should not be empty")
	}
	if hashes.Entropy <= 0 {
		t.Error("entropy should be > 0")
	}
}

func TestComputeHashesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	hashes, err := ComputeHashes(path)
	if err != nil {
		t.Fatal(err)
	}

	if hashes.Entropy != 0 {
		t.Errorf("entropy should be 0 for empty file, got %f", hashes.Entropy)
	}
}

func TestComputeHashesLargeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.bin")
	data := make([]byte, 100000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	hashes, err := ComputeHashes(path)
	if err != nil {
		t.Fatal(err)
	}

	if hashes.SHA256 == "" {
		t.Error("SHA256 should not be empty for large file")
	}
}

func TestComputeHashesNonexistentFile(t *testing.T) {
	_, err := ComputeHashes("/nonexistent/path/file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestComputeSHA256(t *testing.T) {
	data := []byte("test data")
	hash := ComputeSHA256(data)
	if len(hash) != 64 {
		t.Errorf("SHA256 hex should be 64 chars, got %d", len(hash))
	}

	hash2 := ComputeSHA256(data)
	if hash != hash2 {
		t.Error("SHA256 should be deterministic")
	}
}

func TestComputeSHA1(t *testing.T) {
	data := []byte("test data")
	hash := ComputeSHA1(data)
	if len(hash) != 40 {
		t.Errorf("SHA1 hex should be 40 chars, got %d", len(hash))
	}
}

func TestComputeMD5(t *testing.T) {
	data := []byte("test data")
	hash := ComputeMD5(data)
	if len(hash) != 32 {
		t.Errorf("MD5 hex should be 32 chars, got %d", len(hash))
	}
}

func TestEntropyCalculation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "random.bin")
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	var repeated []byte
	for i := 0; i < 100; i++ {
		repeated = append(repeated, data...)
	}
	if err := os.WriteFile(path, repeated, 0644); err != nil {
		t.Fatal(err)
	}

	hashes, err := ComputeHashes(path)
	if err != nil {
		t.Fatal(err)
	}
	if hashes.Entropy < 7.5 {
		t.Errorf("expected high entropy for uniform data, got %f", hashes.Entropy)
	}
}

func TestFileHashesJSONRoundTrip(t *testing.T) {
	h := FileHashes{
		SHA256:  "abc",
		SHA1:    "def",
		MD5:     "ghi",
		Entropy: 7.5,
	}

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}

	var h2 FileHashes
	if err := json.Unmarshal(data, &h2); err != nil {
		t.Fatal(err)
	}

	if h2.SHA256 != h.SHA256 {
		t.Error("JSON round-trip failed for SHA256")
	}
}
