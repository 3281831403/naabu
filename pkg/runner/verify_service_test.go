package runner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"github.com/projectdiscovery/naabu/v2/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// verifyTestProbes is a self-contained nmap-service-probes file used by the
// verify + service-version tests.
const verifyTestProbes = `
Probe TCP NULL q||
totalwaitms 2000
match ssh m|^SSH-([\d.]+)-OpenSSH[_-]([\w._-]+)| p/OpenSSH/ v/$2/ i/protocol $1/
`

// startBannerListener starts a local TCP listener that serves the given banner
// on every connection and then drains. If banner is empty the connection is
// closed immediately (no service match). The returned closer stops the listener.
func startBannerListener(t *testing.T, banner string) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if banner == "" {
					return
				}
				_, _ = conn.Write([]byte(banner))
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { _ = ln.Close() }
}

// newVerifyServiceRunner builds a runner configured like `-verify -sV` with a
// custom probes file, plus JSON/XML/gnmap outputs under a temp dir.
func newVerifyServiceRunner(t *testing.T, probesFile string) *Runner {
	t.Helper()
	dir := t.TempDir()
	options := &Options{
		Host:                  []string{"127.0.0.1"},
		Ports:                 "80",
		ScanType:              ConnectScan,
		IPVersion:             []string{"4"},
		Rate:                  100,
		Verify:                true,
		ServiceVersion:        true,
		ServiceProbesFile:     probesFile,
		ServiceVersionWorkers: 4,
		DisableStdout:         true,
		JSON:                  true,
		Output:                filepath.Join(dir, "out.json"),
		XMLOutput:             filepath.Join(dir, "out.xml"),
		GrepOutput:            filepath.Join(dir, "out.gnmap"),
	}
	r, err := NewRunner(options)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func writeProbesFile(t *testing.T) string {
	t.Helper()
	probesFile := filepath.Join(t.TempDir(), "nmap-service-probes")
	require.NoError(t, os.WriteFile(probesFile, []byte(verifyTestProbes), 0600))
	return probesFile
}

// TestVerifyMergesServiceInfo reproduces the on-call report: with `-sV -verify`
// the verified ports kept their port but lost the whole service column. The
// verified result set must now carry the same service information as a scan
// without -verify, across the result object and every output format.
func TestVerifyMergesServiceInfo(t *testing.T) {
	openPort, _ := startBannerListener(t, "SSH-2.0-OpenSSH_9.6\r\n")
	r := newVerifyServiceRunner(t, writeProbesFile(t))

	r.initServiceDetection(context.Background())
	require.True(t, r.options.ServiceVersion, "custom probes file must load")

	openP := &port.Port{Port: openPort, Protocol: protocol.TCP}
	r.scanner.ScanResults.AddPort("127.0.0.1", openP)

	r.ConnectVerification()
	require.True(t, r.scanner.ScanResults.IPHasPort("127.0.0.1", openP),
		"open port must survive verification")

	r.waitServiceDetection(r.scanner.ScanResults)

	hostResult := <-r.scanner.ScanResults.GetIPsPorts()
	require.Len(t, hostResult.Ports, 1)
	svc := hostResult.Ports[0].Service
	require.NotNil(t, svc, "verified port must carry service information")
	require.Equal(t, "ssh", svc.Name)
	require.Equal(t, "OpenSSH", svc.Product)
	require.Equal(t, "9.6", svc.Version)

	// All output sinks must agree with the merged result set.
	r.handleOutput(r.scanner.ScanResults)

	jsonData, err := os.ReadFile(r.options.Output)
	require.NoError(t, err)
	require.Contains(t, string(jsonData), `"name":"ssh"`)
	require.Contains(t, string(jsonData), `"product":"OpenSSH"`)
	require.Contains(t, string(jsonData), `"version":"9.6"`)

	xmlData, err := os.ReadFile(r.options.XMLOutput)
	require.NoError(t, err)
	require.Contains(t, string(xmlData), `name="ssh"`)
	require.Contains(t, string(xmlData), `product="OpenSSH"`)

	grepData, err := os.ReadFile(r.options.GrepOutput)
	require.NoError(t, err)
	require.Contains(t, string(grepData), "ssh")
}

// TestVerifyServiceInfoMatchesTerminalOutput checks the plain-text terminal
// rendering path (no JSON/CSV) shows the verified service inline.
func TestVerifyServiceInfoMatchesTerminalOutput(t *testing.T) {
	openPort, _ := startBannerListener(t, "SSH-2.0-OpenSSH_9.6\r\n")
	r := newVerifyServiceRunner(t, writeProbesFile(t))
	// Plain terminal output instead of JSON.
	r.options.JSON = false
	r.options.Output = ""

	r.initServiceDetection(context.Background())
	r.scanner.ScanResults.AddPort("127.0.0.1", &port.Port{Port: openPort, Protocol: protocol.TCP})
	r.ConnectVerification()
	r.waitServiceDetection(r.scanner.ScanResults)

	hostResult := <-r.scanner.ScanResults.GetIPsPorts()
	require.Len(t, hostResult.Ports, 1)
	require.NotNil(t, hostResult.Ports[0].Service)
	require.Equal(t, "ssh", hostResult.Ports[0].Service.Name)
	require.Equal(t, "ssh OpenSSH/9.6", formatServiceInfo(hostResult.Ports[0].Service))
}

// TestVerifyServiceInfoNotLeakedAcrossRuns runs two consecutive SDK-style
// rounds on the same Runner: the second round must not observe services
// identified during the first one.
func TestVerifyServiceInfoNotLeakedAcrossRuns(t *testing.T) {
	probesFile := writeProbesFile(t)
	r := newVerifyServiceRunner(t, probesFile)

	// Round 1: an SSH banner is identified.
	sshPort, closeSSH := startBannerListener(t, "SSH-2.0-OpenSSH_9.6\r\n")
	r.initServiceDetection(context.Background())
	r.scanner.ScanResults.AddPort("127.0.0.1", &port.Port{Port: sshPort, Protocol: protocol.TCP})
	r.ConnectVerification()
	r.waitServiceDetection(r.scanner.ScanResults)

	hostResult1 := <-r.scanner.ScanResults.GetIPsPorts()
	require.Len(t, hostResult1.Ports, 1)
	require.NotNil(t, hostResult1.Ports[0].Service)
	require.Equal(t, "ssh", hostResult1.Ports[0].Service.Name)
	sshKey := net.JoinHostPort("127.0.0.1", fmt.Sprint(sshPort))
	require.Contains(t, r.fpServices, sshKey)

	// The round 1 service goes away before the next run.
	closeSSH()

	// Round 2: a fresh enumeration cycle (as the SDK would run it) against a
	// port that serves nothing. No trace of round 1 may leak in.
	silentPort, _ := startBannerListener(t, "")
	r.initServiceDetection(context.Background())
	require.NotContains(t, r.fpServices, sshKey,
		"a new enumeration cycle must start with an empty service table")
	r.scanner.ScanResults.AddPort("127.0.0.1", &port.Port{Port: silentPort, Protocol: protocol.TCP})
	r.ConnectVerification()
	r.waitServiceDetection(r.scanner.ScanResults)

	hostResult2 := <-r.scanner.ScanResults.GetIPsPorts()
	require.Len(t, hostResult2.Ports, 1)
	require.Equal(t, silentPort, hostResult2.Ports[0].Port)
	require.Nil(t, hostResult2.Ports[0].Service,
		"round 2 must not inherit round 1 services")
	for key := range r.fpServices {
		require.NotEqual(t, sshKey, key, "round 1 service entry leaked into round 2")
		require.False(t, strings.HasSuffix(key, fmt.Sprint(sshPort)),
			"round 1 service entry leaked into round 2")
	}
}
