package fingerprint

import "time"

const (
	DefaultWorkers        = 25
	DefaultTimeout        = 5 * time.Second
	DefaultConnectTimeout = 3 * time.Second
	// DefaultMatchCacheSize bounds the response-match LRU. Entries are small
	// (a hash key plus a match outcome pointer), so this caps the cache at a
	// few MB regardless of how many distinct banners a scan encounters.
	DefaultMatchCacheSize = 32768
)

// Option configures the Engine.
type Option func(*Engine)

func WithWorkers(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.workers = n
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.timeout = d
		}
	}
}

func WithFastMode(fast bool) Option {
	return func(e *Engine) {
		e.fastMode = fast
	}
}

// WithDialer sets a custom dialer for TCP connections (e.g. SOCKS5 proxy).
func WithDialer(d DialFunc) Option {
	return func(e *Engine) {
		e.dialer = d
	}
}

// WithIntensity sets the maximum probe rarity to use (1-9, default 7).
func WithIntensity(level int) Option {
	return func(e *Engine) {
		if level >= 1 && level <= 9 {
			e.intensityMax = level
		}
	}
}

// WithMatchCacheSize sets the maximum number of cached response-match
// outcomes. Identical banners still hit the cache; once the bound is reached
// the least-recently-used entries are evicted. A non-positive value disables
// caching.
func WithMatchCacheSize(n int) Option {
	return func(e *Engine) {
		e.matchCacheSize = n
	}
}
