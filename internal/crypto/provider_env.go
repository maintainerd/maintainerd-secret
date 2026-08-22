package crypto

import (
	"fmt"
	"log/slog"
)

// newEnvProvider builds the root of trust from SECRET_ROOT_KEY.
//
// THE EPHEMERAL REFUSAL LIVES HERE, and it is the single most consequential branch
// in this package. The prototype, finding no root key, generated a random one and
// carried on with a warning. That is worse than failing: the service starts, accepts
// writes, and appears healthy — and then a restart produces a different random key
// and every one of those secrets is permanently undecryptable. The failure is
// silent, deferred, and total.
//
// So outside APP_ENV=development an absent or malformed key is a boot error, full
// stop. Inside development an ephemeral key is allowed, because a dev database is
// disposable and the alternative is making every contributor provision a key before
// they can run the service — but it is registered as provider 'ephemeral' rather
// than masquerading as 'env', so the fingerprint in root_keys tells the truth about
// what encrypted those rows.
func newEnvProvider(cfg ProviderConfig) (RootKeyProvider, error) {
	if cfg.Key == "" {
		if cfg.AppEnv != EnvDevelopment {
			return nil, fmt.Errorf(
				"crypto: SECRET_ROOT_KEY is not set and APP_ENV is %q — a generated key would make every secret written before the next restart permanently undecryptable, so this is a boot error; set a %d-byte key as hex or base64",
				cfg.AppEnv, KeySize)
		}
		return newEphemeralProvider()
	}

	key, err := ParseKeyMaterial(cfg.Key)
	if err != nil {
		// The error from ParseKeyMaterial reports the length and the expected
		// encoding, never the value.
		return nil, fmt.Errorf("crypto: SECRET_ROOT_KEY is invalid: %w", err)
	}
	return newAESKEK(ProviderEnv, key)
}

// newEphemeralProvider generates a throwaway root key. Development only — reachable
// solely through newEnvProvider's guarded branch, never from the registry directly.
func newEphemeralProvider() (RootKeyProvider, error) {
	key, err := NewRandomKey()
	if err != nil {
		return nil, err
	}
	p, err := newAESKEK(ProviderEphemeral, key)
	if err != nil {
		return nil, err
	}
	slog.Warn("SECRET_ROOT_KEY is not set; generated an EPHEMERAL root key",
		"app_env", EnvDevelopment,
		"kek_id", p.KeyID(),
		"consequence", "every secret written under this key becomes undecryptable when this process exits")
	return p, nil
}
