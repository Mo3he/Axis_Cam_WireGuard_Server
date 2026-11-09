package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hexString(b []byte) string { return hex.EncodeToString(b) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func genKey(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

const (
	testCamera = "198.51.100.7" // what the server tunnel IP maps to
	testLANIP  = "192.0.2.10"   // a host inside the routed subnet
)

// harness is a server plus loopback stand-ins for the camera and its LAN.
type harness struct {
	t       *testing.T
	srv     *server
	srvPub  [32]byte
	port    int
	mu      sync.Mutex
	dialed  []string
	clients map[string][32]byte // tunnel address -> private key
}

func newHarness(t *testing.T, peerToPeer bool, clients ...string) *harness {
	t.Helper()
	h := &harness{t: t, port: freeUDPPort(t), clients: map[string][32]byte{}}

	var peers []string
	for i, addr := range clients {
		priv, pub := genKey(t)
		h.clients[addr] = priv
		peers = append(peers, fmt.Sprintf("client%d,%s,%s", i, b64(pub[:]), addr))
	}
	env := map[string]string{
		"ENABLED":      "yes",
		"ADDRESS":      "10.66.0.1/24",
		"LISTENPORT":   strconv.Itoa(h.port),
		"ROUTESUBNETS": "lan",
		"PEERS":        strings.Join(peers, ";"),
	}
	if peerToPeer {
		env["PEERTOPEER"] = "yes"
	}
	cfg, err := parseConfig(envMap(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PeerErrors) > 0 {
		t.Fatal(cfg.PeerErrors)
	}

	var priv [32]byte
	priv, h.srvPub = genKey(t)
	h.srv = &server{cfg: cfg}
	camera := func() (netip.Addr, error) { return netip.MustParseAddr(testCamera), nil }
	lan := func() (netip.Prefix, error) { return netip.MustParsePrefix("192.0.2.1/24"), nil }
	if err := h.srv.start(priv, h.dial, camera, lan); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.srv.stop)
	return h
}

// dial stands in for the host network: the camera and LAN host are loopback.
func (h *harness) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(address)
	h.mu.Lock()
	h.dialed = append(h.dialed, network+" "+address)
	h.mu.Unlock()
	if host != testCamera && host != testLANIP {
		return nil, fmt.Errorf("unexpected dial to %s", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
}

func (h *harness) dialedTo(address string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, d := range h.dialed {
		if strings.HasSuffix(d, " "+address) {
			return true
		}
	}
	return false
}

// client starts a WireGuard client using a netstack, routing everything to the server.
func (h *harness) client(addr string) *netstack.Net {
	h.t.Helper()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, nil, 1420)
	if err != nil {
		h.t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	priv := h.clients[addr]
	uapi := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=1\n",
		hexString(priv[:]), hexString(h.srvPub[:]), h.port)
	if err := dev.IpcSet(uapi); err != nil {
		h.t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(dev.Close)
	return tnet
}

func (h *harness) waitConnected(n int) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connected := 0
		for _, p := range h.srv.snapshot().Peers {
			if p.Connected {
				connected++
			}
		}
		if connected >= n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.t.Fatalf("fewer than %d peers connected: %+v", n, h.srv.snapshot().Peers)
}

func httpGet(t *testing.T, tnet *netstack.Net, url string) string {
	t.Helper()
	c := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: tnet.DialContext},
	}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestGatewayTCP(t *testing.T) {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello from the camera")
	}))
	defer web.Close()
	_, port, _ := net.SplitHostPort(web.Listener.Addr().String())

	h := newHarness(t, false, "10.66.0.2")
	tnet := h.client("10.66.0.2")

	if got := httpGet(t, tnet, "http://10.66.0.1:"+port+"/"); got != "hello from the camera" {
		t.Fatalf("via server IP: %q", got)
	}
	if !h.dialedTo(testCamera + ":" + port) {
		t.Fatal("server tunnel IP was not mapped to the camera LAN address")
	}
	if got := httpGet(t, tnet, "http://"+testLANIP+":"+port+"/"); got != "hello from the camera" {
		t.Fatalf("via LAN route: %q", got)
	}

	// Outside the route subnets: refused without any host dial.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := tnet.DialContext(ctx, "tcp", "203.0.113.5:"+port); err == nil {
		c.Close()
		t.Fatal("dial outside route subnets succeeded")
	} else if ctx.Err() != nil {
		t.Fatal("denied dial timed out instead of being reset")
	}
	if h.dialedTo("203.0.113.5:" + port) {
		t.Fatal("denied destination was dialed on the host")
	}

	h.waitConnected(1)
	st := h.srv.snapshot()
	if st.State != "running" || st.Peers[0].RxBytes == 0 || st.Peers[0].Endpoint == "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestGatewayUDP(t *testing.T) {
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo([]byte("echo:"+string(buf[:n])), addr)
		}
	}()
	port := strconv.Itoa(echo.LocalAddr().(*net.UDPAddr).Port)

	h := newHarness(t, false, "10.66.0.2")
	tnet := h.client("10.66.0.2")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := tnet.DialContext(ctx, "udp", testLANIP+":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	buf := make([]byte, 64)
	for i := 0; i < 20; i++ {
		_, _ = c.Write([]byte("ping"))
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err == nil {
			if got := string(buf[:n]); got != "echo:ping" {
				t.Fatalf("reply %q", got)
			}
			return
		}
	}
	t.Fatal("no UDP reply through the gateway")
}

func peerTCP(t *testing.T, peerToPeer bool) error {
	h := newHarness(t, peerToPeer, "10.66.0.2", "10.66.0.3")
	a := h.client("10.66.0.2")
	b := h.client("10.66.0.3")
	h.waitConnected(2)

	ln, err := b.ListenTCPAddrPort(netip.MustParseAddrPort("10.66.0.3:8000"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, "hi from peer b")
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := a.DialContext(ctx, "tcp", "10.66.0.3:8000")
	if err != nil {
		return err
	}
	defer c.Close()
	got, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if string(got) != "hi from peer b" {
		t.Fatalf("peer reply %q", got)
	}
	return nil
}

func TestPeerToPeerEnabled(t *testing.T) {
	if err := peerTCP(t, true); err != nil {
		t.Fatalf("peer-to-peer connection failed: %v", err)
	}
}

func TestPeerToPeerDisabled(t *testing.T) {
	if err := peerTCP(t, false); err == nil {
		t.Fatal("peers reached each other with peer-to-peer disabled")
	}
}

func ping(tnet *netstack.Net, dst string) error {
	c, err := tnet.Dial("ping4", dst)
	if err != nil {
		return err
	}
	defer c.Close()
	req, _ := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("ping")},
	}).Marshal(nil)
	buf := make([]byte, 1500)
	for i := 0; i < 5; i++ {
		if _, err := c.Write(req); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			continue
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err == nil && msg.Type == ipv4.ICMPTypeEchoReply {
			return nil
		}
	}
	return fmt.Errorf("no echo reply from %s", dst)
}

func TestGatewayPing(t *testing.T) {
	h := newHarness(t, false, "10.66.0.2")
	tnet := h.client("10.66.0.2")
	if err := ping(tnet, "10.66.0.1"); err != nil {
		t.Fatalf("server tunnel IP: %v", err)
	}
	// gVisor would answer for any address; the gateway must not fake LAN replies.
	if err := ping(tnet, testLANIP); err == nil {
		t.Fatal("got a fabricated echo reply for a LAN host")
	}
}
