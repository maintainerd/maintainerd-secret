package crypto

import (
	"fmt"
	"os"
	"strings"
)

// newFileProvider builds the root of trust from a sealed key file.
//
// This exists because an env var is visible in a process listing, in a container
// inspect, in a crash dump, and in whatever orchestrator rendered it. A file can be
// mounted with restricted permissions and read once. That advantage is entirely
// contingent on the permissions actually being restricted, so this provider REFUSES
// a file any group or other user can read rather than warning about it: a warning on
// a boot path is a warning nobody reads, and the whole point of choosing the file
// provider over env was to narrow who can see the key.
func newFileProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	if cfg.KeyFile == "" {
		return nil, fmt.Errorf("crypto: SECRET_ROOT_KEY_FILE is required for the file root key provider")
	}
	key, err := loadSealedKeyFile(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return newAESKEK(ProviderFile, key)
}

// loadSealedKeyFile reads and validates a key file. Stat (not Lstat) is used on
// purpose: a symlink is a legitimate way to mount a key, and what matters is the
// permission of the file the read will actually land on.
func loadSealedKeyFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read root key file: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("crypto: root key file %s is a directory", path)
	}
	// 0o077 is group + other, read/write/execute. Anything set there means someone
	// besides the owner can read the root key of the entire vault.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"crypto: root key file %s has mode %04o and is readable beyond its owner; run chmod 600 on it",
			path, perm)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crypto: read root key file: %w", err)
	}
	// Trim so a file written with a trailing newline (which is to say, a file
	// written by any normal tool) is not rejected for it.
	encoded := strings.TrimSpace(string(raw))
	Zero(raw)

	key, err := ParseKeyMaterial(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: root key file %s is invalid: %w", path, err)
	}
	return key, nil
}
