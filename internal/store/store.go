// Package store is the encrypted secret store. Values are encrypted at rest with
// AES-256-GCM under a root key supplied at boot (env/KMS) — a store cannot unlock
// itself, so the root key always comes from outside. v1 is in-memory; a durable
// backend plugs in behind the same API.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound is returned when a key is absent.
var ErrNotFound = errors.New("secret not found")

// Store is a concurrency-safe encrypted key/value store.
type Store struct {
	mu   sync.RWMutex
	aead cipher.AEAD
	data map[string][]byte // key -> nonce||ciphertext
}

// New builds a store. rootKey must be 16, 24, or 32 bytes (AES-128/192/256).
func New(rootKey []byte) (*Store, error) {
	block, err := aes.NewCipher(rootKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{aead: aead, data: make(map[string][]byte)}, nil
}

// Put encrypts and stores value under key. The key is bound as additional
// authenticated data, so a ciphertext cannot be moved to another key.
func (s *Store) Put(key string, value []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := s.aead.Seal(nonce, nonce, value, []byte(key))
	s.mu.Lock()
	s.data[key] = sealed
	s.mu.Unlock()
	return nil
}

// Get decrypts and returns the value for key.
func (s *Store) Get(key string) ([]byte, error) {
	s.mu.RLock()
	sealed, ok := s.data[key]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	ns := s.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("store: corrupt ciphertext")
	}
	nonce, ct := sealed[:ns], sealed[ns:]
	return s.aead.Open(nil, nonce, ct, []byte(key))
}

// List returns the sorted keys with the given prefix.
func (s *Store) List(prefix string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		if prefix == "" || strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Delete removes a key (no error if absent).
func (s *Store) Delete(key string) {
	s.mu.Lock()
	delete(s.data, key)
	s.mu.Unlock()
}
