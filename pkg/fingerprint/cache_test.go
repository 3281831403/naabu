package fingerprint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const cacheTestProbes = `
Probe TCP NULL q||
totalwaitms 2000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/
match http m|^HTTP/1\.[01] \d+.*Server: ([\w/._-]+)|s p/$1/
`

// TestMatchCacheBounded ensures the response-match cache has a hard memory
// ceiling: feeding it many distinct banners must not grow it beyond the
// configured size, and matching must stay correct while evictions happen.
func TestMatchCacheBounded(t *testing.T) {
	db := buildTestDB(cacheTestProbes)
	engine := New(db, WithMatchCacheSize(4))
	matches := db.Probes[0].Matches

	for i := 0; i < 200; i++ {
		response := []byte(fmt.Sprintf("SSH-2.0-OpenSSH_9.%d\r\n", i))
		got := engine.tryMatches(matches, response)
		if got == nil || got.Service != "ssh" {
			t.Fatalf("expected ssh match for %q, got %+v", response, got)
		}
	}
	if n := engine.matchCache.Len(false); n > 4 {
		t.Fatalf("cache grew beyond its bound: %d entries (max 4)", n)
	}

	// A banner evicted earlier is simply re-matched, with the same result.
	got := engine.tryMatches(matches, []byte("SSH-2.0-OpenSSH_9.0\r\n"))
	if got == nil || got.Service != "ssh" || got.Product != "OpenSSH" {
		t.Fatalf("expected correct re-match after eviction, got %+v", got)
	}
	if n := engine.matchCache.Len(false); n > 4 {
		t.Fatalf("cache grew beyond its bound after re-match: %d entries", n)
	}
}

// TestMatchCacheHitSendsNoExtraProbes verifies that a warm cache never causes
// additional probe connections: fingerprinting the same banner twice must
// identify the service both times while the second pass sends no more probe
// packets than the first.
func TestMatchCacheHitSendsNoExtraProbes(t *testing.T) {
	var conns atomic.Int64
	addr, cleanup := startTCPServer(t, func(conn net.Conn) {
		conns.Add(1)
		defer conn.Close() //nolint:errcheck
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	db := buildTestDB(cacheTestProbes)
	engine := New(db, WithTimeout(2*time.Second), WithWorkers(1))

	// TLSChecked skips the TLS-detection dial so every pass is exactly one
	// NULL-probe connection.
	targets := []Target{{Host: host, IP: host, Port: port, TLSChecked: true}}
	key := fmt.Sprintf("%s:%d", host, port)

	first := engine.Fingerprint(context.Background(), targets)
	if svc := first[key]; svc == nil || svc.Name != "ssh" {
		t.Fatalf("cold pass: expected ssh, got %+v", first[key])
	}
	cold := conns.Load()
	if cold != 1 {
		t.Fatalf("cold pass: expected exactly 1 probe connection, got %d", cold)
	}
	if engine.matchCache.Len(false) == 0 {
		t.Fatal("expected the cold pass to populate the match cache")
	}

	second := engine.Fingerprint(context.Background(), targets)
	if svc := second[key]; svc == nil || svc.Name != "ssh" {
		t.Fatalf("warm pass: expected ssh, got %+v", second[key])
	}
	warm := conns.Load() - cold
	if warm > cold {
		t.Fatalf("cache-hit pass sent extra probe packets: cold=%d warm=%d", cold, warm)
	}
}

// TestMatchCacheNotSharedAcrossEngines guards SDK-style reuse: a second scan
// (new engine, possibly sharing the parsed probe database) must start with an
// empty cache and must not observe services identified in a previous run.
func TestMatchCacheNotSharedAcrossEngines(t *testing.T) {
	db := buildTestDB(cacheTestProbes)

	sshAddr, sshCleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close() //nolint:errcheck
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer sshCleanup()

	httpAddr, httpCleanup := startTCPServer(t, func(conn net.Conn) {
		defer conn.Close() //nolint:errcheck
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n"))
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
	})
	defer httpCleanup()

	target := func(addr string) Target {
		host, portStr, _ := net.SplitHostPort(addr)
		port := 0
		_, _ = fmt.Sscanf(portStr, "%d", &port)
		return Target{Host: host, IP: host, Port: port, TLSChecked: true}
	}

	// Round 1: first engine identifies SSH.
	engine1 := New(db, WithTimeout(2*time.Second), WithWorkers(1))
	t1 := target(sshAddr)
	res1 := engine1.Fingerprint(context.Background(), []Target{t1})
	key1 := fmt.Sprintf("%s:%d", t1.IP, t1.Port)
	if svc := res1[key1]; svc == nil || svc.Name != "ssh" {
		t.Fatalf("round 1: expected ssh, got %+v", res1[key1])
	}
	if engine1.matchCache.Len(false) == 0 {
		t.Fatal("round 1: expected a populated cache")
	}

	// Round 2: a fresh engine (new SDK run) starts with an empty cache and
	// identifies its own target instead of replaying round 1 results.
	engine2 := New(db, WithTimeout(2*time.Second), WithWorkers(1))
	if n := engine2.matchCache.Len(false); n != 0 {
		t.Fatalf("round 2: expected an empty cache, found %d entries", n)
	}
	t2 := target(httpAddr)
	res2 := engine2.Fingerprint(context.Background(), []Target{t2})
	key2 := fmt.Sprintf("%s:%d", t2.IP, t2.Port)
	svc := res2[key2]
	if svc == nil || svc.Name != "http" {
		t.Fatalf("round 2: expected http, got %+v", svc)
	}
	if strings.Contains(svc.Product, "OpenSSH") || svc.Name == "ssh" {
		t.Fatalf("round 2 leaked round 1 service: %+v", svc)
	}
}
