package adinkra

import (
	"sync"
	"time"
)

// NonceCache implements a thread-safe cache to detect replay attacks.
// It stores nonces until they expire.
type NonceCache struct {
	seen map[string]time.Time
	mu   sync.Mutex
}

// NewNonceCache initializes the cache and starts the cleanup goroutine
func NewNonceCache() *NonceCache {
	nc := &NonceCache{
		seen: make(map[string]time.Time),
	}
	go nc.cleanupLoop()
	return nc
}

// CheckAndMark verifies if a nonce is fresh. Returns true if fresh (and marks it), false if seen.
func (nc *NonceCache) CheckAndMark(nonce string, expiresAt time.Time) bool {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// If already seen, it's a replay
	if _, exists := nc.seen[nonce]; exists {
		return false
	}

	// Mark as seen
	nc.seen[nonce] = expiresAt
	return true
}

func (nc *NonceCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		nc.mu.Lock()
		now := time.Now()
		for nonce, expiry := range nc.seen {
			if now.After(expiry) {
				delete(nc.seen, nonce)
			}
		}
		nc.mu.Unlock()
	}
}
