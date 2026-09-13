package service

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/ReCasaOS/CasaOS-Common/utils/jwt"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
)

// The key tokens are signed with.
//
// It was generated at every start and kept in memory only, so every restart of
// this service -- a reboot, an upgrade, a backup of the box that stops it for
// the copy -- signed everybody out. It lives on disk now, readable by root
// only, under the database directory the box backup already carries: a restart
// keeps every session, and a box put back from a backup keeps the sessions it
// had. The key for the window between a password and a second factor is still
// made at start; nothing of it should outlive a restart.

// KeyFilename is the file under the database directory that holds the key.
const KeyFilename = "user-service.key"

// loadOrCreateKeyPair reads the key at path, or makes one and writes it there.
// A file that cannot be read as a key is replaced, with a line in the log:
// every session is signed out once, rather than nobody ever again.
func loadOrCreateKeyPair(path string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(raw); block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, &key.PublicKey, nil
			}
		}
		logger.Warn("the signing key on disk could not be read; a new one is made and every session is signed out", zap.String("path", path))
	}

	private, public, err := jwt.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, nil, err
	}

	return private, public, nil
}
