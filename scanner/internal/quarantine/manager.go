package quarantine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Manager struct {
	quarantinePath string
	encryptionKey  []byte
}

func NewManager(path, encryptionKey string) *Manager {
	// Derive 256-bit key from the provided key
	key := sha256.Sum256([]byte(encryptionKey))

	if err := os.MkdirAll(path, 0700); err != nil {
		slog.Warn("failed to create quarantine directory", "path", path, "error", err)
	}

	return &Manager{
		quarantinePath: path,
		encryptionKey:  key[:],
	}
}

func (m *Manager) QuarantineFile(sourcePath string, data []byte) (string, error) {
	slog.Info("quarantining file", "source", sourcePath)

	// Generate unique quarantine path
	hash := sha256.Sum256([]byte(sourcePath))
	quarantineName := base64.URLEncoding.EncodeToString(hash[:16]) + ".quarantine"
	quarantinePath := filepath.Join(m.quarantinePath, quarantineName)

	var err error
	// Read source file if not provided
	if len(data) == 0 {
		data, err = os.ReadFile(sourcePath)
		if err != nil {
			return "", err
		}
	}

	// Encrypt data
	encrypted, err := m.encrypt(data)
	if err != nil {
		return "", err
	}

	// Write quarantine file
	if err := os.WriteFile(quarantinePath, encrypted, 0600); err != nil {
		return "", err
	}

	// Save metadata
	metaPath := quarantinePath + ".meta"
	metadata := []byte(sourcePath)
	if err := os.WriteFile(metaPath, metadata, 0600); err != nil {
		return "", err
	}

	// Delete original file
	if err := os.Remove(sourcePath); err != nil {
		slog.Warn("failed to remove original file", "path", sourcePath, "error", err)
	}

	slog.Info("file quarantined", "source", sourcePath, "quarantine", quarantinePath)
	return quarantinePath, nil
}

func (m *Manager) RestoreFile(quarantinePath string) error {
	slog.Info("restoring file from quarantine", "path", quarantinePath)

	// Read metadata for original path
	metaPath := quarantinePath + ".meta"
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return err
	}
	originalPath := strings.TrimSpace(string(metaData))

	// Read encrypted data
	encrypted, err := os.ReadFile(quarantinePath)
	if err != nil {
		return err
	}

	// Decrypt data
	data, err := m.decrypt(encrypted)
	if err != nil {
		return err
	}

	// Write to original location
	if err := os.MkdirAll(filepath.Dir(originalPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(originalPath, data, 0644); err != nil {
		return err
	}

	// Clean up quarantine
	os.Remove(quarantinePath)
	os.Remove(metaPath)

	slog.Info("file restored from quarantine", "quarantine", quarantinePath, "original", originalPath)
	return nil
}

func (m *Manager) DeleteQuarantine(quarantinePath string) error {
	slog.Info("deleting quarantine file", "path", quarantinePath)

	// Securely wipe
	if err := m.secureWipe(quarantinePath); err != nil {
		return err
	}

	metaPath := quarantinePath + ".meta"
	os.Remove(metaPath)

	slog.Info("quarantine file deleted", "path", quarantinePath)
	return nil
}

func (m *Manager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, data, nil), nil
}

func (m *Manager) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, io.ErrUnexpectedEOF
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func (m *Manager) secureWipe(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	size := info.Size()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	buf := make([]byte, 4096)
	for i := int64(0); i < size; i += int64(len(buf)) {
		if _, err := rand.Read(buf); err != nil {
			f.Close()
			return err
		}
		if i+int64(len(buf)) > size {
			buf = buf[:size-i]
		}
		if _, err := f.Write(buf); err != nil {
			f.Close()
			return err
		}
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	f.Close()
	return os.Remove(path)
}
