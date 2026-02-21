package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// StateStore is an in-memory store for OIDC state parameters with TTL cleanup.
type StateStore struct {
	mu       sync.Mutex
	states   map[string]time.Time
	ttl      time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewStateStore creates a new state store with the given TTL and starts
// a background goroutine that periodically purges expired entries.
func NewStateStore(ttl time.Duration) *StateStore {
	s := &StateStore{
		states: make(map[string]time.Time),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Generate creates a new cryptographically random state and stores it.
func (s *StateStore) Generate() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating state: %w", err)
	}
	state := hex.EncodeToString(b)

	s.mu.Lock()
	s.states[state] = time.Now().Add(s.ttl)
	s.mu.Unlock()

	return state, nil
}

// Validate checks that the state exists and has not expired.
// It is single-use: calling Validate consumes the state.
func (s *StateStore) Validate(state string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.states[state]
	if !ok {
		return false
	}
	delete(s.states, state)
	return time.Now().Before(expiry)
}

// Stop halts the background cleanup goroutine. Safe to call multiple times.
func (s *StateStore) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(s.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for state, expiry := range s.states {
				if now.After(expiry) {
					delete(s.states, state)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}
