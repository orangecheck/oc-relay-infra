// oc-relay-front stands in front of strfry and gives it a daily pseudonym for
// each visitor in place of the visitor's address. It runs strfry as its child:
//
//	oc-relay-front /app/strfry --config=/etc/strfry.conf relay
//
// It listens on FRONT_LISTEN (default 0.0.0.0:7777, the port Fly forwards to)
// and forwards every request, WebSocket upgrades included, to strfry on
// FRONT_UPSTREAM (default http://127.0.0.1:7778). Each forwarded request
// carries x-oc-source: an address in fd00::/8 made from HMAC-SHA256 over the
// visitor's address (its /64 for IPv6) under a salt that lives only in this
// process and is replaced on the first request of each UTC day. No header
// naming the visitor reaches strfry.
//
// GET /health is answered here: strfry's NIP-11 document read over loopback,
// plus how many requests came without a usable Fly-Client-IP.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SourceHeader is the header strfry.conf names as realIpHeader.
const SourceHeader = "X-Oc-Source"

// Unknown is every visitor's source when Fly-Client-IP is missing or unreadable:
// one shared bucket, never the socket's address (Fly's proxy).
var Unknown = netip.MustParseAddr("fd00::")

// clientHeaders name the visitor; none of them reaches strfry.
var clientHeaders = []string{
	"Fly-Client-Ip", "X-Forwarded-For", "Forwarded", "X-Real-Ip", "True-Client-Ip", "Cf-Connecting-Ip",
}

// Names turns an address into the day's pseudonym.
type Names struct {
	mu   sync.Mutex
	day  string
	salt []byte
	Rand io.Reader
	Now  func() time.Time
}

// key is the day's salt, made on the first call of each UTC day.
func (n *Names) key() ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	day := n.Now().UTC().Format(time.DateOnly)
	if day != n.day {
		salt := make([]byte, 32)
		if _, err := io.ReadFull(n.Rand, salt); err != nil {
			return nil, fmt.Errorf("no salt: %w", err)
		}
		n.day, n.salt = day, salt
	}
	return n.salt, nil
}

// Of is addr's pseudonym for today: an IPv4 address whole, an IPv6 one by its /64.
func (n *Names) Of(addr netip.Addr) (netip.Addr, error) {
	salt, err := n.key()
	if err != nil {
		return netip.Addr{}, err
	}
	addr = addr.Unmap().WithZone("")
	var input []byte
	if addr.Is4() {
		a := addr.As4()
		input = append([]byte{4}, a[:]...)
	} else {
		a := addr.As16()
		input = append([]byte{6}, a[:8]...)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(input)
	var out [16]byte
	out[0] = 0xfd
	copy(out[1:], mac.Sum(nil)[:15])
	return netip.AddrFrom16(out), nil
}

type sourceKey struct{}

// Front is the HTTP handler: /health here, everything else to strfry.
type Front struct {
	Names    *Names
	Upstream *url.URL
	proxy    *httputil.ReverseProxy
	client   *http.Client

	unknown   atomic.Int64
	unknownAt atomic.Int64
	loggedAt  atomic.Int64
}

func NewFront(names *Names, upstream *url.URL) *Front {
	f := &Front{Names: names, Upstream: upstream, client: &http.Client{Timeout: 3 * time.Second}}
	f.proxy = &httputil.ReverseProxy{
		// Rewrite (not Director) starts from a request with no X-Forwarded-* headers.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			for _, h := range clientHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Set(SourceHeader, pr.In.Context().Value(sourceKey{}).(string))
		},
		ErrorLog: log.Default(),
	}
	return f
}

func (f *Front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" && r.Header.Get("Upgrade") == "" {
		f.health(w, r)
		return
	}
	source := Unknown
	if addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("Fly-Client-Ip"))); err == nil {
		name, err := f.Names.Of(addr)
		if err != nil {
			log.Printf("oc-relay-front: %v; refusing the request", err)
			http.Error(w, "relay unavailable", http.StatusServiceUnavailable)
			return
		}
		source = name
	} else {
		f.noteUnknown()
	}
	ctx := context.WithValue(r.Context(), sourceKey{}, source.String())
	f.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// noteUnknown counts a request without a usable Fly-Client-IP, and says so at most once a minute.
func (f *Front) noteUnknown() {
	now := time.Now().Unix()
	f.unknown.Add(1)
	f.unknownAt.Store(now)
	if last := f.loggedAt.Load(); now-last >= 60 && f.loggedAt.CompareAndSwap(last, now) {
		log.Printf("oc-relay-front: a request without a usable Fly-Client-IP; its source is %s (%d since start)", Unknown, f.unknown.Load())
	}
}

func (f *Front) health(w http.ResponseWriter, r *http.Request) {
	body := map[string]any{"ok": false}
	status := http.StatusServiceUnavailable
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, f.Upstream.String()+"/", nil)
	req.Header.Set("Accept", "application/nostr+json")
	if resp, err := f.client.Do(req); err == nil {
		var nip11 map[string]any
		if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&nip11) == nil {
			body["ok"] = true
			status = http.StatusOK
			for _, k := range []string{"name", "software", "version", "supported_nips"} {
				if v, ok := nip11[k]; ok {
					body[k] = v
				}
			}
		}
		resp.Body.Close()
	}
	var at any
	if ts := f.unknownAt.Load(); ts > 0 {
		at = time.Unix(ts, 0).UTC().Format(time.RFC3339)
	}
	body["source_unknown"] = map[string]any{"count": f.unknown.Load(), "last_at": at}
	body["ts"] = time.Now().UTC().Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// Run starts strfry and the front and returns when either stops: 1 when one of
// them failed or exited, 0 on SIGTERM or SIGINT.
func Run(args []string, listen string, f *Front) int {
	if len(args) == 0 {
		log.Print("oc-relay-front: no strfry command given")
		return 2
	}
	// Pdeathsig follows the thread that starts the child, so keep it.
	runtime.LockOSThread()
	if _, err := f.Names.key(); err != nil {
		log.Printf("oc-relay-front: %v", err)
		return 1
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// If this process dies, so does strfry.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		log.Printf("oc-relay-front: strfry did not start: %v", err)
		return 1
	}
	srv := &http.Server{Addr: listen, Handler: f, ReadHeaderTimeout: 10 * time.Second}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)

	select {
	case err := <-exited:
		log.Printf("oc-relay-front: strfry exited (%v); stopping", err)
		srv.Close()
		return 1
	case err := <-served:
		log.Printf("oc-relay-front: listener stopped (%v); stopping strfry", err)
		stop(cmd, exited, syscall.SIGTERM)
		return 1
	case s := <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		stop(cmd, exited, s)
		return 0
	}
}

// stop signals strfry and waits up to 10 seconds before killing it.
func stop(cmd *exec.Cmd, exited <-chan error, s os.Signal) {
	cmd.Process.Signal(s)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-exited
	}
}

func main() {
	log.SetFlags(0)
	raw := env("FRONT_UPSTREAM", "http://127.0.0.1:7778")
	upstream, err := url.Parse(raw)
	if err != nil || upstream.Host == "" {
		log.Fatalf("oc-relay-front: FRONT_UPSTREAM %q is not a URL with a host", raw)
	}
	names := &Names{Rand: rand.Reader, Now: time.Now}
	os.Exit(Run(os.Args[1:], env("FRONT_LISTEN", "0.0.0.0:7777"), NewFront(names, upstream)))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
