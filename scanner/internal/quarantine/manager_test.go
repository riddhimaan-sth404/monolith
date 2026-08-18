package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	dir := t.TempDir()
	mgr := NewManager(dir, "test-encryption-key")
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	if mgr.quarantinePath != dir {
		t.Errorf("expected quarantine path %s, got %s", dir, mgr.quarantinePath)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	mgr := NewManager(t.TempDir(), "test-key-32-bytes-long-here!!!!!")
	original := []byte("This is sensitive file content that should be encrypted")

	encrypted, err := mgr.encrypt(original)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypted data should be different from original
	if string(encrypted) == string(original) {
		t.Error("encrypted data should differ from original")
	}

	// Encrypted data should be longer (nonce + ciphertext)
	if len(encrypted) <= len(original) {
		t.Error("encrypted data should be longer than original")
	}

	decrypted, err := mgr.decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(original) {
		t.Errorf("decrypted data mismatch: got %s, expected %s", decrypted, original)
	}
}

func TestEncryptDeterministic(t *testing.T) {
	mgr := NewManager(t.TempDir(), "test-key-32-bytes-long-here!!!!!")
	data := []byte("Same data")

	enc1, _ := mgr.encrypt(data)
	enc2, _ := mgr.encrypt(data)

	// Each encryption should produce different ciphertext (due to random nonce)
	if string(enc1) == string(enc2) {
		t.Error("encryption should not be deterministic (nonce should differ)")
	}
}

func TestDecryptInvalidData(t *testing.T) {
	mgr := NewManager(t.TempDir(), "test-key-32-bytes-long-here!!!!!")

	_, err := mgr.decrypt([]byte("too short"))
	if err == nil {
		t.Error("expected error decrypting invalid data")
	}
}

func TestQuarantineFileRoundtrip(t *testing.T) {
	quarantineDir := t.TempDir()
	sourceDir := t.TempDir()

	mgr := NewManager(quarantineDir, "test-key-32-bytes-long-here!!!!!")

	// Create a source file
	sourcePath := filepath.Join(sourceDir, "test.exe")
	content := []byte("This is a malicious executable")
	if err := os.WriteFile(sourcePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Quarantine the file
	qPath, err := mgr.QuarantineFile(sourcePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Original should be removed
	if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Error("original file should be removed after quarantine")
	}

	// Quarantine file should exist
	if _, err := os.Stat(qPath); os.IsNotExist(err) {
		t.Error("quarantine file should exist")
	}

	// Metadata file should exist
	if _, err := os.Stat(qPath + ".meta"); os.IsNotExist(err) {
		t.Error("metadata file should exist")
	}

	// Restore the file
	if err := mgr.RestoreFile(qPath); err != nil {
		t.Fatal(err)
	}

	// Original should be restored
	restored, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(content) {
		t.Errorf("restored content mismatch: got %s, expected %s", restored, content)
	}

	// Quarantine files should be removed
	if _, err := os.Stat(qPath); !os.IsNotExist(err) {
		t.Error("quarantine file should be removed after restore")
	}
}

func TestQuarantineNonexistentFile(t *testing.T) {
	mgr := NewManager(t.TempDir(), "test-key-32-bytes-long-here!!!!!")
	_, err := mgr.QuarantineFile("/nonexistent/file.exe", nil)
	if err == nil {
		t.Error("expected error quarantining nonexistent file")
	}
}

func TestDeleteQuarantine(t *testing.T) {
	quarantineDir := t.TempDir()
	sourceDir := t.TempDir()

	mgr := NewManager(quarantineDir, "test-key")
	sourcePath := filepath.Join(sourceDir, "test.exe")
	os.WriteFile(sourcePath, []byte("test"), 0644)

	qPath, err := mgr.QuarantineFile(sourcePath, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := mgr.DeleteQuarantine(qPath); err != nil {
		t.Fatal(err)
	}

	// Quarantine file should be removed
	if _, err := os.Stat(qPath); !os.IsNotExist(err) {
		t.Error("quarantine file should be deleted")
	}
}

func TestDifferentKeys(t *testing.T) {
	mgr1 := NewManager(t.TempDir(), "key-one-32-bytes-long-for-test!!!!")
	mgr2 := NewManager(t.TempDir(), "key-two-32-bytes-long-for-test!!!!")

	data := []byte("sensitive data")
	encrypted, _ := mgr1.encrypt(data)

	// mgr2 should NOT be able to decrypt mgr1's data
	_, err := mgr2.decrypt(encrypted)
	if err == nil {
		t.Error("expected error when decrypting with different key")
	}
}
