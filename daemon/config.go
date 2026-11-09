package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	defaultListenPort = 51820
	defaultMTU        = 1420
	minMTU            = 576
	maxMTU            = 1500

	// lanKeyword in RouteSubnets expands to the subnet of the camera's primary interface.
	lanKeyword = "lan"
)

// config is the daemon configuration, passed in by the entry binary as
// ACAP_<PARAMETER> environment variables.
type config struct {
	Enabled      bool
	PrivateKey   string
	ListenPort   int
	Address      netip.Prefix // server tunnel address with the tunnel subnet, e.g. 10.66.0.1/24
	Peers        []peer
	PeerErrors   []string
	RouteSubnets []string // raw entries; resolved at start because "lan" depends on the host
	PeerToPeer   bool
	MTU          int
}

type peer struct {
	Name      string
	PublicKey [32]byte
	Address   netip.Addr
}

func loadConfigFromEnv() (*config, error) {
	return parseConfig(func(name string) string { return strings.TrimSpace(os.Getenv("ACAP_" + name)) })
}

// parseConfig validates the global settings strictly but skips individual bad
// peers, reporting them in PeerErrors, so one typo does not take every peer down.
func parseConfig(get func(string) string) (*config, error) {
	cfg := &config{
		Enabled:    get("ENABLED") == "yes",
		PrivateKey: get("PRIVATEKEY"),
		PeerToPeer: get("PEERTOPEER") == "yes",
		ListenPort: defaultListenPort,
		MTU:        defaultMTU,
	}

	if v := get("LISTENPORT"); v != "" {
		port, err := strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return cfg, fmt.Errorf("invalid listen port %q", v)
		}
		cfg.ListenPort = port
	}

	if v := get("MTU"); v != "" {
		mtu, err := strconv.Atoi(v)
		if err != nil || mtu < minMTU || mtu > maxMTU {
			return cfg, fmt.Errorf("invalid MTU %q (valid range %d to %d)", v, minMTU, maxMTU)
		}
		cfg.MTU = mtu
	}

	addr := get("ADDRESS")
	if addr == "" {
		return cfg, errors.New("server tunnel address is not configured")
	}
	prefix, err := netip.ParsePrefix(addr)
	if err != nil || !prefix.Addr().Is4() {
		return cfg, fmt.Errorf("invalid server tunnel address %q: expected IPv4 CIDR such as 10.66.0.1/24", addr)
	}
	if prefix.Bits() < 8 || prefix.Bits() > 30 {
		return cfg, fmt.Errorf("server tunnel address %q: prefix length must be between /8 and /30", addr)
	}
	if prefix.Addr() == prefix.Masked().Addr() || prefix.Addr() == broadcast(prefix) {
		return cfg, fmt.Errorf("server tunnel address %q is the network or broadcast address", addr)
	}
	cfg.Address = prefix

	for _, entry := range splitList(get("ROUTESUBNETS")) {
		if !strings.EqualFold(entry, lanKeyword) {
			p, err := netip.ParsePrefix(entry)
			if err != nil || !p.Addr().Is4() {
				return cfg, fmt.Errorf("invalid route subnet %q: expected IPv4 CIDR or %q", entry, lanKeyword)
			}
			if p.Masked().Overlaps(cfg.Address.Masked()) {
				return cfg, fmt.Errorf("route subnet %q overlaps the tunnel subnet %s", entry, cfg.Address.Masked())
			}
		}
		cfg.RouteSubnets = append(cfg.RouteSubnets, entry)
	}

	cfg.Peers, cfg.PeerErrors = parsePeers(get("PEERS"), cfg.Address)
	return cfg, nil
}

// parsePeers reads "name,publicKey,address" records separated by ";".
func parsePeers(raw string, server netip.Prefix) ([]peer, []string) {
	var peers []peer
	var problems []string
	seenKeys := map[[32]byte]bool{}
	seenAddrs := map[netip.Addr]bool{}

	for _, record := range strings.Split(raw, ";") {
		record = strings.TrimSpace(record)
		if record == "" {
			continue
		}
		fields := strings.Split(record, ",")
		if len(fields) != 3 {
			problems = append(problems, fmt.Sprintf("peer %q: expected name,publicKey,address", record))
			continue
		}
		name := strings.TrimSpace(fields[0])
		label := name
		if label == "" {
			label = "(unnamed)"
		}

		key, err := parseKey(strings.TrimSpace(fields[1]))
		if err != nil {
			problems = append(problems, fmt.Sprintf("peer %s: %v", label, err))
			continue
		}

		addrText := strings.TrimSuffix(strings.TrimSpace(fields[2]), "/32")
		addr, err := netip.ParseAddr(addrText)
		if err != nil || !addr.Is4() {
			problems = append(problems, fmt.Sprintf("peer %s: invalid IPv4 address %q", label, fields[2]))
			continue
		}
		if !server.Masked().Contains(addr) || addr == server.Addr() || addr == server.Masked().Addr() || addr == broadcast(server) {
			problems = append(problems, fmt.Sprintf("peer %s: address %s is not a free host address in %s", label, addr, server.Masked()))
			continue
		}
		if seenKeys[key] {
			problems = append(problems, fmt.Sprintf("peer %s: duplicate public key", label))
			continue
		}
		if seenAddrs[addr] {
			problems = append(problems, fmt.Sprintf("peer %s: duplicate address %s", label, addr))
			continue
		}
		seenKeys[key] = true
		seenAddrs[addr] = true
		peers = append(peers, peer{Name: name, PublicKey: key, Address: addr})
	}
	return peers, problems
}

func parseKey(s string) ([32]byte, error) {
	var key [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return key, errors.New("key must be 32 bytes of base64")
	}
	copy(key[:], b)
	return key, nil
}

func splitList(raw string) []string {
	var out []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	hostBits := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
