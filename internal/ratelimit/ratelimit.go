// Package ratelimit implements a per-client token bucket.
package ratelimit

import (
	"sync"
	"time"
)

// idleTTL is how long an unused bucket is kept before being dropped, so that a
// long-lived process does not accumulate one entry per client name forever.
const idleTTL = time.Hour

// Limiter allows a configured number of requests per minute per key, letting a
// full minute's worth through as a burst.
type Limiter struct {
	now func() time.Time

	mu        sync.Mutex
	perMinute int
	buckets   map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New returns a limiter allowing perMinute requests per key per minute.
func New(perMinute int) *Limiter {
	return &Limiter{
		now:       time.Now,
		perMinute: perMinute,
		buckets:   make(map[string]*bucket),
	}
}

// SetRate updates the limit, e.g. after a configuration reload.
func (l *Limiter) SetRate(perMinute int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.perMinute = perMinute
}

// Allow consumes one token for the key and reports whether it was available.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	capacity := float64(l.perMinute)
	refillPerSecond := capacity / 60

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}

	b.tokens += now.Sub(b.last).Seconds() * refillPerSecond
	if b.tokens > capacity {
		b.tokens = capacity
	}

	b.last = now

	l.evictIdle(now)

	if b.tokens < 1 {
		return false
	}

	b.tokens--

	return true
}

func (l *Limiter) evictIdle(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.last) > idleTTL {
			delete(l.buckets, key)
		}
	}
}
