package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func names(c *clock) *Names {
	if c == nil {
		c = &clock{time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	}
	return &Names{Rand: rand.Reader, Now: c.now}
}

func of(t *testing.T, n *Names, s string) netip.Addr {
	t.Helper()
	a, err := n.Of(netip.MustParseAddr(s))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSameDaySameNameNextDayAnother(t *testing.T) {
	c := &clock{time.Date(2026, 10, 26, 0, 0, 1, 0, time.UTC)}
	n := names(c)
	first := of(t, n, "203.0.113.7")
	c.t = time.Date(2026, 10, 26, 23, 59, 59, 0, time.UTC)
	if got := of(t, n, "203.0.113.7"); got != first {
		t.Fatalf("same day: %s then %s", first, got)
	}
	if other := of(t, n, "203.0.113.8"); other == first {
		t.Fatalf("two visitors share %s", first)
	}
	c.t = time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	if got := of(t, n, "203.0.113.7"); got == first {
		t.Fatalf("next day: still %s", got)
	}
}

func TestNameIsInFd00Slash8AndNotTheAddress(t *testing.T) {
	n := names(nil)
	for _, s := range []string{"203.0.113.7", "2001:db8:1:2::5"} {
		got := of(t, n, s)
		if got.As16()[0] != 0xfd || got == Unknown || strings.Contains(got.String(), "203.0.113") {
			t.Fatalf("%s -> %s", s, got)
		}
	}
}

func TestIPv6IsNamedByItsSlash64(t *testing.T) {
	n := names(nil)
	a := of(t, n, "2001:db8:1:2::5")
	if b := of(t, n, "2001:db8:1:2:ffff:1:2:3"); b != a {
		t.Fatalf("one /64, two names: %s %s", a, b)
	}
	if c := of(t, n, "2001:db8:1:3::5"); c == a {
		t.Fatalf("two /64s, one name: %s", a)
	}
	if v4, mapped := of(t, n, "203.0.113.7"), of(t, n, "::ffff:203.0.113.7"); v4 != mapped {
		t.Fatalf("an IPv4 address and its mapped form differ: %s %s", v4, mapped)
	}
}

// upstream records what strfry would receive.
type upstream struct {
	mu      sync.Mutex
	headers []http.Header
	hosts   []string
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.headers = append(u.headers, r.Header.Clone())
	u.hosts = append(u.hosts, r.Host)
	u.mu.Unlock()
	if r.Header.Get("Upgrade") == "websocket" {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw) // echo
		return
	}
	if r.Header.Get("Accept") == "application/nostr+json" {
		w.Header().Set("Content-Type", "application/nostr+json")
		w.Write([]byte(`{"name":"relay.ochk.io","software":"git+https://github.com/hoytech/strfry.git","version":"0.9.7","supported_nips":[1,2,4]}`))
		return
	}
	w.Write([]byte("landing"))
}

func (u *upstream) last() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.headers[len(u.headers)-1]
}

func serve(t *testing.T, n *Names) (*Front, *upstream, *httptest.Server) {
	t.Helper()
	up := &upstream{}
	s := httptest.NewServer(up)
	t.Cleanup(s.Close)
	u, _ := url.Parse(s.URL)
	f := NewFront(n, u)
	front := httptest.NewServer(f)
	t.Cleanup(front.Close)
	return f, up, front
}

func get(t *testing.T, base string, h map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/", nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func TestStrfryGetsThePseudonymAndNoHeaderNamingTheVisitor(t *testing.T) {
	n := names(nil)
	_, up, front := serve(t, n)
	get(t, front.URL, map[string]string{
		"Fly-Client-IP":    "203.0.113.7",
		"X-Forwarded-For":  "198.51.100.1, 203.0.113.7",
		"Forwarded":        "for=203.0.113.7",
		"X-Real-IP":        "203.0.113.7",
		"X-Oc-Source":      "fd99::1",
		"True-Client-IP":   "203.0.113.7",
		"CF-Connecting-IP": "203.0.113.7",
	})
	h := up.last()
	if host := up.hosts[len(up.hosts)-1]; host != strings.TrimPrefix(front.URL, "http://") {
		t.Fatalf("strfry saw Host %q, not the visitor's", host)
	}
	if got, want := h.Get(SourceHeader), of(t, n, "203.0.113.7").String(); got != want {
		t.Fatalf("x-oc-source %q, want %q", got, want)
	}
	if v := h.Values(SourceHeader); len(v) != 1 {
		t.Fatalf("x-oc-source sent %d times: %v", len(v), v)
	}
	for k, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, "203.0.113") || strings.Contains(v, "198.51.100") {
				t.Fatalf("strfry received %s: %s", k, v)
			}
		}
	}
}

func TestNoUsableClientAddressIsFd00AndCounted(t *testing.T) {
	f, up, front := serve(t, names(nil))
	for _, h := range []map[string]string{{}, {"Fly-Client-IP": "not an address"}, {"X-Forwarded-For": "203.0.113.7"}} {
		get(t, front.URL, h)
		if got := up.last().Get(SourceHeader); got != "fd00::" {
			t.Fatalf("%v: x-oc-source %q", h, got)
		}
	}
	if got := f.unknown.Load(); got != 3 {
		t.Fatalf("counted %d", got)
	}
	var body struct {
		Source struct {
			Count  int     `json:"count"`
			LastAt *string `json:"last_at"`
		} `json:"source_unknown"`
	}
	resp, _ := http.Get(front.URL + "/health")
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body.Source.Count != 3 || body.Source.LastAt == nil {
		t.Fatalf("health says %+v", body.Source)
	}
}

func TestNoSaltNoForward(t *testing.T) {
	n := names(nil)
	n.Rand = failing{}
	_, up, front := serve(t, n)
	resp := get(t, front.URL, map[string]string{"Fly-Client-IP": "203.0.113.7"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(up.headers) != 0 {
		t.Fatal("forwarded without a salt")
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestWebSocketUpgradeCarriesThePseudonymAndPassesBytes(t *testing.T) {
	n := names(nil)
	_, up, front := serve(t, n)
	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	nonce := make([]byte, 16)
	rand.Read(nonce)
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: relay.ochk.io\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(nonce) +
		"\r\nFly-Client-IP: 2001:db8:1:2::5\r\n\r\n"))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	conn.Write([]byte("frame bytes"))
	buf := make([]byte, len("frame bytes"))
	if _, err := io.ReadFull(br, buf); err != nil || !bytes.Equal(buf, []byte("frame bytes")) {
		t.Fatalf("echo %q %v", buf, err)
	}
	if got, want := up.last().Get(SourceHeader), of(t, n, "2001:db8:1:2::9").String(); got != want {
		t.Fatalf("x-oc-source %q, want the /64's %q", got, want)
	}
}

func TestHealthReadsNip11ThroughLoopback(t *testing.T) {
	_, _, front := serve(t, names(nil))
	resp, err := http.Get(front.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != 200 || body["ok"] != true || body["name"] != "relay.ochk.io" || body["version"] != "0.9.7" {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
}

func TestHealthFailsWhenStrfryDoesNotAnswer(t *testing.T) {
	dead, _ := url.Parse("http://127.0.0.1:1")
	front := httptest.NewServer(NewFront(names(nil), dead))
	defer front.Close()
	resp, err := http.Get(front.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusServiceUnavailable || body["ok"] != false {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
}

func TestStrfryExitingStopsTheFrontWithAFailure(t *testing.T) {
	f := NewFront(names(nil), &url.URL{Scheme: "http", Host: "127.0.0.1:1"})
	done := make(chan int, 1)
	go func() { done <- Run([]string{"/bin/sh", "-c", "sleep 0.2; exit 0"}, "127.0.0.1:0", f) }()
	select {
	case code := <-done:
		if code == 0 {
			t.Fatal("exited 0 after strfry stopped")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("still running after strfry stopped")
	}
}

func TestAFrontThatCannotListenStopsStrfry(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A child no other process runs, found again by its arguments.
	wait := fmt.Sprintf("%d.%03d", 40+time.Now().Nanosecond()%50, time.Now().Nanosecond()%1000)
	f := NewFront(names(nil), &url.URL{Scheme: "http", Host: "127.0.0.1:1"})
	if code := Run([]string{"sleep", wait}, l.Addr().String(), f); code == 0 {
		t.Fatal("exited 0 without a listener")
	}
	if running("sleep\x00" + wait) {
		exec.Command("pkill", "-f", "sleep "+wait).Run()
		t.Fatal("strfry was left running")
	}
}

// running says whether a process's NUL-separated command line holds cmdline.
func running(cmdline string) bool {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), cmdline) {
			return true
		}
	}
	return false
}
