package main

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func testKey(b byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return base64.StdEncoding.EncodeToString(k)
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := parseConfig(envMap(map[string]string{"ADDRESS": "10.66.0.1/24", "ENABLED": "yes"}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.ListenPort != defaultListenPort || cfg.MTU != defaultMTU || cfg.PeerToPeer {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"no address":       {},
		"ipv6 address":     {"ADDRESS": "fd00::1/64"},
		"network address":  {"ADDRESS": "10.66.0.0/24"},
		"broadcast":        {"ADDRESS": "10.66.0.255/24"},
		"prefix too long":  {"ADDRESS": "10.66.0.1/31"},
		"bad port":         {"ADDRESS": "10.66.0.1/24", "LISTENPORT": "70000"},
		"bad mtu":          {"ADDRESS": "10.66.0.1/24", "MTU": "100"},
		"bad route":        {"ADDRESS": "10.66.0.1/24", "ROUTESUBNETS": "192.168.1.0"},
		"overlapping road": {"ADDRESS": "10.66.0.1/24", "ROUTESUBNETS": "10.0.0.0/8"},
	}
	for name, env := range cases {
		if _, err := parseConfig(envMap(env)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseConfigRoutes(t *testing.T) {
	cfg, err := parseConfig(envMap(map[string]string{
		"ADDRESS":      "10.66.0.1/24",
		"ROUTESUBNETS": "lan, 192.168.10.0/24;172.16.0.0/12",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"lan", "192.168.10.0/24", "172.16.0.0/12"}
	if strings.Join(cfg.RouteSubnets, " ") != strings.Join(want, " ") {
		t.Fatalf("routes %v, want %v", cfg.RouteSubnets, want)
	}
}

func TestParsePeers(t *testing.T) {
	server := netip.MustParsePrefix("10.66.0.1/24")
	raw := strings.Join([]string{
		"laptop," + testKey(1) + ",10.66.0.2",
		"phone," + testKey(2) + ",10.66.0.3/32",
		"dupkey," + testKey(1) + ",10.66.0.4",
		"dupaddr," + testKey(3) + ",10.66.0.2",
		"server," + testKey(4) + ",10.66.0.1",
		"outside," + testKey(5) + ",10.67.0.2",
		"broadcast," + testKey(6) + ",10.66.0.255",
		"badkey,abc,10.66.0.9",
		"short," + testKey(7),
		"",
	}, ";")
	peers, problems := parsePeers(raw, server)
	if len(peers) != 2 || peers[0].Name != "laptop" || peers[1].Address != netip.MustParseAddr("10.66.0.3") {
		t.Fatalf("peers = %+v", peers)
	}
	if len(problems) != 7 {
		t.Fatalf("problems = %d: %v", len(problems), problems)
	}
}

func TestBroadcast(t *testing.T) {
	for in, want := range map[string]string{
		"10.66.0.1/24":   "10.66.0.255",
		"10.0.0.1/8":     "10.255.255.255",
		"192.168.4.5/30": "192.168.4.7",
	} {
		if got := broadcast(netip.MustParsePrefix(in)).String(); got != want {
			t.Errorf("broadcast(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestPolicyResolve(t *testing.T) {
	camera := netip.MustParseAddr("192.168.1.20")
	p := &policy{
		serverIP:   netip.MustParseAddr("10.66.0.1"),
		tunnel:     netip.MustParsePrefix("10.66.0.0/24"),
		routes:     []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("0.0.0.0/0")},
		cameraAddr: func() (netip.Addr, error) { return camera, nil },
	}
	for dst, want := range map[string]string{
		"10.66.0.1":       "192.168.1.20", // camera, via its LAN address
		"192.168.1.50":    "192.168.1.50",
		"8.8.8.8":         "8.8.8.8",
		"127.0.0.1":       "", // loopback is never reachable, even with 0.0.0.0/0
		"10.66.0.5":       "", // peers are not reached through the stack
		"224.0.0.1":       "",
		"255.255.255.255": "",
		"0.0.0.0":         "",
	} {
		got, ok := p.resolve(netip.MustParseAddr(dst))
		if want == "" {
			if ok {
				t.Errorf("resolve(%s) = %s, want denied", dst, got)
			}
			continue
		}
		if !ok || got.String() != want {
			t.Errorf("resolve(%s) = %s %v, want %s", dst, got, ok, want)
		}
	}

	p.routes = nil
	if _, ok := p.resolve(netip.MustParseAddr("192.168.1.50")); ok {
		t.Error("LAN reachable without route subnets")
	}
}

func TestResolveRoutes(t *testing.T) {
	tunnel := netip.MustParsePrefix("10.66.0.0/24")
	lan := func() (netip.Prefix, error) { return netip.MustParsePrefix("192.168.1.20/24"), nil }
	routes, err := resolveRoutes([]string{"LAN", "172.16.5.9/16"}, tunnel, lan)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].String() != "192.168.1.0/24" || routes[1].String() != "172.16.0.0/16" {
		t.Fatalf("routes = %v", routes)
	}
	overlap := func() (netip.Prefix, error) { return netip.MustParsePrefix("10.66.0.0/16"), nil }
	if _, err := resolveRoutes([]string{"lan"}, tunnel, overlap); err == nil {
		t.Fatal("expected overlap error for a LAN that contains the tunnel")
	}
}

func TestParseIpcGet(t *testing.T) {
	key := strings.Repeat("ab", 32)
	stats := parseIpcGet("private_key=00\nlisten_port=51820\npublic_key=" + key +
		"\nendpoint=1.2.3.4:5678\nlast_handshake_time_sec=1700000000\nrx_bytes=10\ntx_bytes=20\n")
	if len(stats) != 1 {
		t.Fatalf("stats = %v", stats)
	}
	for _, s := range stats {
		if s.Endpoint != "1.2.3.4:5678" || s.LastHandshake != 1700000000 || s.RxBytes != 10 || s.TxBytes != 20 {
			t.Fatalf("stats = %+v", s)
		}
	}
}

func TestLoadPrivateKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "localdata")
	k1, generated, err := loadPrivateKey("", dir)
	if err != nil || !generated {
		t.Fatalf("first load: generated=%v err=%v", generated, err)
	}
	info, err := os.Stat(filepath.Join(dir, "server.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	k2, generated, err := loadPrivateKey("", dir)
	if err != nil || generated || k1 != k2 {
		t.Fatal("key was not persisted")
	}
	k3, _, err := loadPrivateKey(testKey(9), dir)
	if err != nil || k3 == k1 {
		t.Fatal("parameter key does not take precedence")
	}
	if _, _, err := loadPrivateKey("nope", dir); err == nil {
		t.Fatal("expected an error for an invalid key parameter")
	}
}

// RFC 7748 section 6.1 test vector.
func TestPublicKey(t *testing.T) {
	priv, _ := parseKey(base64.StdEncoding.EncodeToString(mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")))
	pub, err := publicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got := hexString(pub[:]); got != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("public key %s", got)
	}
}
