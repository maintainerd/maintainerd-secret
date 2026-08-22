package crypto

import (
	"fmt"
	"sync"
)

// KeyRing resolves which root key can open a given version, and names the one new
// writes must use.
//
// A store in the middle of a root-key rotation legitimately holds versions wrapped
// under several keys at once — that is what makes rotation an online operation
// rather than a maintenance window. So a single "the root key" is not enough: a read
// must be able to ask "which key wrapped THIS row" and get the right provider back.
// The keyring is that lookup, keyed by the kek_id stored on the version.
//
// Retired keys must stay on the ring until a rewrap has actually moved every row off
// them. Dropping one early does not surface as an error at rotation time; it
// surfaces later, as reads that fail on old rows.
type KeyRing struct {
	mu     sync.RWMutex
	active RootKeyProvider
	byID   map[string]RootKeyProvider
}

// NewKeyRing builds a ring with active as the write key. previous holds the
// superseded keys still needed to read existing rows; the active key is registered
// for reads too.
func NewKeyRing(active RootKeyProvider, previous ...RootKeyProvider) (*KeyRing, error) {
	if active == nil {
		return nil, fmt.Errorf("crypto: key ring needs an active root key")
	}
	r := &KeyRing{active: active, byID: make(map[string]RootKeyProvider, len(previous)+1)}
	r.byID[active.KeyID()] = active
	for _, p := range previous {
		if p == nil {
			continue
		}
		r.byID[p.KeyID()] = p
	}
	return r, nil
}

// Active returns the provider new writes wrap under.
func (r *KeyRing) Active() RootKeyProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.active
}

// Provider returns the provider that can unwrap a DEK recorded under kekID.
//
// The error names the missing key id, because that is precisely the fact an operator
// needs: rows exist that were wrapped under a key this process was not given, and
// the fix is to supply it (not to re-encrypt anything).
func (r *KeyRing) Provider(kekID string) (RootKeyProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[kekID]
	if !ok {
		return nil, fmt.Errorf("crypto: no root key provider for %s is loaded; versions wrapped under it cannot be read until it is supplied", kekID)
	}
	return p, nil
}

// Add registers an additional readable key — used when an operator supplies a
// superseded key so a rewrap can drain it.
func (r *KeyRing) Add(p RootKeyProvider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[p.KeyID()] = p
}

// KeyIDs lists every readable key on the ring.
func (r *KeyRing) KeyIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	return ids
}
