package crypto

import "fmt"

// The cloud KMS providers are REGISTERED BUT NOT BUILT.
//
// They are in the registry — and their names are in the config validator and in the
// root_keys.provider CHECK constraint — because the seam is what had to be designed,
// not the client calls. A KMS root key differs from an env root key in exactly one
// respect: Wrap and Unwrap become network round-trips to a service that never hands
// over the key material. Nothing else in this service changes. The DEK is still
// 32 bytes, secret_versions still stores the wrapped DEK and a kek_id, and RewrapAll
// still rotates by re-wrapping DEKs. Proving that by building the interface first,
// and letting an operator's config for aws_kms be *validated* today, is the point.
//
// Construction fails with a clear message rather than returning a provider that
// errors on every operation. A vault that boots and then refuses every read is a
// worse outcome than one that refuses to boot: the second is a config error an
// operator fixes in a minute, the first looks like an outage.
func notBuilt(provider, label string) providerFactory {
	return func(ProviderConfig) (RootKeyProvider, error) {
		return nil, fmt.Errorf(
			"crypto: root key provider %q (%s) is not built yet; the interface seam exists but the client does not — use %q or %q",
			provider, label, ProviderEnv, ProviderFile)
	}
}
