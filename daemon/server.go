package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// A handshake older than this means the peer is gone (WireGuard's
// REJECT_AFTER_TIME; active peers rekey every 2 minutes).
const handshakeStale = 180 * time.Second

// loadPrivateKey returns the configured key, or the one persisted in dataDir,
// generating and saving a new one on first start.
func loadPrivateKey(param, dataDir string) ([32]byte, bool, error) {
	if param != "" {
		k, err := parseKey(param)
		if err != nil {
			return k, false, fmt.Errorf("invalid PrivateKey parameter: %w", err)
		}
		return k, false, nil
	}

	path := filepath.Join(dataDir, "server.key")
	if b, err := os.ReadFile(path); err == nil {
		k, err := parseKey(strings.TrimSpace(string(b)))
		if err != nil {
			return k, false, fmt.Errorf("corrupt %s: %w", path, err)
		}
		return k, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return [32]byte{}, false, err
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return [32]byte{}, false, err
	}
	var k [32]byte
	copy(k[:], priv.Bytes())
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return k, false, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(k[:])+"\n"), 0o600); err != nil {
		return k, false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return k, false, err
	}
	return k, true, nil
}

func publicKey(priv [32]byte) ([32]byte, error) {
	var pub [32]byte
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return pub, err
	}
	copy(pub[:], k.PublicKey().Bytes())
	return pub, nil
}

func buildUAPI(priv [32]byte, cfg *config) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(priv[:]))
	fmt.Fprintf(&sb, "listen_port=%d\n", cfg.ListenPort)
	sb.WriteString("replace_peers=true\n")
	for _, p := range cfg.Peers {
		fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		fmt.Fprintf(&sb, "allowed_ip=%s/32\n", p.Address)
	}
	return sb.String()
}

// ── server state ────────────────────────────────────────────────────────────

type server struct {
	mu        sync.Mutex
	cfg       *config
	state     string // "disabled", "running" or "error"
	lastErr   string
	pub       [32]byte
	hasKey    bool
	routes    []netip.Prefix
	cameraIP  string
	dev       *device.Device
	gw        *gateway
	connected map[[32]byte]bool
}

func (s *server) setError(err error) {
	s.mu.Lock()
	s.state = "error"
	s.lastErr = err.Error()
	s.mu.Unlock()
	log.Printf("error: %v", err)
}

// start brings the WireGuard device up with the gateway as its TUN device.
func (s *server) start(priv [32]byte, dial dialFunc, cameraAddr func() (netip.Addr, error), lan func() (netip.Prefix, error)) error {
	cfg := s.cfg
	routes, err := resolveRoutes(cfg.RouteSubnets, cfg.Address.Masked(), lan)
	if err != nil {
		return err
	}
	pol := &policy{serverIP: cfg.Address.Addr(), tunnel: cfg.Address.Masked(), routes: routes, cameraAddr: cameraAddr}

	gw, err := newGateway(cfg.Address, cfg.MTU, cfg.PeerToPeer, pol, dial)
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("wireguard: "+f, a...) },
	}
	if debugEnabled {
		logger.Verbosef = func(f string, a ...any) { log.Printf("wireguard: "+f, a...) }
	}
	dev := device.NewDevice(gw, conn.NewStdNetBind(), logger)
	if err := dev.IpcSet(buildUAPI(priv, cfg)); err != nil {
		dev.Close()
		return fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring device up (is UDP port %d free?): %w", cfg.ListenPort, err)
	}

	camera := ""
	if a, err := cameraAddr(); err == nil {
		camera = a.String()
	}
	s.mu.Lock()
	s.dev, s.gw, s.routes, s.cameraIP = dev, gw, routes, camera
	s.state, s.lastErr = "running", ""
	s.connected = map[[32]byte]bool{}
	s.mu.Unlock()

	log.Printf("listening on UDP %d, tunnel %s, %d peer(s), routes %v, peer-to-peer %v",
		cfg.ListenPort, cfg.Address, len(cfg.Peers), routes, cfg.PeerToPeer)
	return nil
}

func (s *server) stop() {
	s.mu.Lock()
	dev := s.dev
	s.dev, s.gw = nil, nil
	s.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
}

type peerStats struct {
	Endpoint      string
	LastHandshake int64
	RxBytes       uint64
	TxBytes       uint64
}

func parseIpcGet(s string) map[[32]byte]*peerStats {
	stats := map[[32]byte]*peerStats{}
	var cur *peerStats
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				cur = nil
				continue
			}
			var key [32]byte
			copy(key[:], b)
			cur = &peerStats{}
			stats[key] = cur
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				cur.LastHandshake, _ = strconv.ParseInt(v, 10, 64)
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	return stats
}

func (s *server) peerStats() map[[32]byte]*peerStats {
	s.mu.Lock()
	dev := s.dev
	s.mu.Unlock()
	if dev == nil {
		return nil
	}
	out, err := dev.IpcGet()
	if err != nil {
		return nil
	}
	return parseIpcGet(out)
}

// logHandshakes logs peers connecting and disconnecting, for the UI's log view.
func (s *server) logHandshakes() {
	stats := s.peerStats()
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil || s.connected == nil {
		return
	}
	for _, p := range s.cfg.Peers {
		st := stats[p.PublicKey]
		up := st != nil && st.LastHandshake > 0 && now.Sub(time.Unix(st.LastHandshake, 0)) < handshakeStale
		if up && !s.connected[p.PublicKey] {
			log.Printf("peer %s (%s) connected from %s", p.Name, p.Address, st.Endpoint)
		} else if !up && s.connected[p.PublicKey] {
			log.Printf("peer %s (%s) disconnected", p.Name, p.Address)
		}
		s.connected[p.PublicKey] = up
	}
}

// ── status API ──────────────────────────────────────────────────────────────

type peerStatus struct {
	Name          string `json:"name"`
	PublicKey     string `json:"publicKey"`
	Address       string `json:"address"`
	Endpoint      string `json:"endpoint"`
	LastHandshake int64  `json:"lastHandshake"`
	Connected     bool   `json:"connected"`
	RxBytes       uint64 `json:"rxBytes"`
	TxBytes       uint64 `json:"txBytes"`
}

type status struct {
	State        string       `json:"state"`
	Error        string       `json:"error,omitempty"`
	PublicKey    string       `json:"publicKey,omitempty"`
	ListenPort   int          `json:"listenPort,omitempty"`
	Address      string       `json:"address,omitempty"`
	Subnet       string       `json:"subnet,omitempty"`
	RouteSubnets []string     `json:"routeSubnets"`
	PeerToPeer   bool         `json:"peerToPeer"`
	CameraIP     string       `json:"cameraIP,omitempty"`
	LANSubnet    string       `json:"lanSubnet,omitempty"`
	PeerErrors   []string     `json:"peerErrors"`
	Peers        []peerStatus `json:"peers"`
}

func (s *server) snapshot() status {
	stats := s.peerStats()
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	st := status{State: s.state, Error: s.lastErr, RouteSubnets: []string{}, PeerErrors: []string{}, Peers: []peerStatus{}}
	if s.hasKey {
		st.PublicKey = base64.StdEncoding.EncodeToString(s.pub[:])
	}
	if lan, err := lanSubnet(); err == nil {
		st.LANSubnet = lan.String()
	}
	st.CameraIP = s.cameraIP
	if st.CameraIP == "" {
		if a, err := primaryIPv4(); err == nil {
			st.CameraIP = a.String()
		}
	}
	for _, r := range s.routes {
		st.RouteSubnets = append(st.RouteSubnets, r.String())
	}
	if s.cfg == nil {
		return st
	}
	st.ListenPort = s.cfg.ListenPort
	st.PeerToPeer = s.cfg.PeerToPeer
	if s.cfg.Address.IsValid() {
		st.Address = s.cfg.Address.String()
		st.Subnet = s.cfg.Address.Masked().String()
	}
	st.PeerErrors = append(st.PeerErrors, s.cfg.PeerErrors...)
	for _, p := range s.cfg.Peers {
		ps := peerStatus{
			Name:      p.Name,
			PublicKey: base64.StdEncoding.EncodeToString(p.PublicKey[:]),
			Address:   p.Address.String(),
		}
		if x := stats[p.PublicKey]; x != nil {
			ps.Endpoint = x.Endpoint
			ps.LastHandshake = x.LastHandshake
			ps.RxBytes, ps.TxBytes = x.RxBytes, x.TxBytes
			ps.Connected = x.LastHandshake > 0 && now.Sub(time.Unix(x.LastHandshake, 0)) < handshakeStale
		}
		st.Peers = append(st.Peers, ps)
	}
	return st
}

// serveStatus serves the status on loopback only; the camera's authenticated
// reverse proxy exposes it to admins as /local/<app>/status.
func (s *server) serveStatus(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(s.snapshot())
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	return ln, nil
}
