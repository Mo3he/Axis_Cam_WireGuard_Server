package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// policy decides which destinations a peer may reach through the gateway.
type policy struct {
	serverIP netip.Addr
	tunnel   netip.Prefix // masked tunnel subnet
	routes   []netip.Prefix
	// cameraAddr returns the address that the server's own tunnel IP maps to.
	cameraAddr func() (netip.Addr, error)
}

// resolve maps a destination seen inside the tunnel to the host-network address
// to dial. Traffic to the server tunnel IP goes to the camera's LAN address, not
// to loopback: loopback-only services (other apps' unauthenticated settings
// bridges, for instance) must never become reachable from the VPN.
func (p *policy) resolve(dst netip.Addr) (netip.Addr, bool) {
	dst = dst.Unmap()
	if dst == p.serverIP {
		addr, err := p.cameraAddr()
		if err != nil {
			return netip.Addr{}, false
		}
		return addr, true
	}
	if !dst.Is4() || dst.IsLoopback() || dst.IsUnspecified() || dst.IsMulticast() ||
		dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || p.tunnel.Contains(dst) {
		return netip.Addr{}, false
	}
	for _, r := range p.routes {
		if r.Contains(dst) {
			return dst, true
		}
	}
	return netip.Addr{}, false
}

// resolveRoutes expands the "lan" keyword and normalizes the route subnets.
func resolveRoutes(entries []string, tunnel netip.Prefix, lan func() (netip.Prefix, error)) ([]netip.Prefix, error) {
	var routes []netip.Prefix
	for _, entry := range entries {
		var p netip.Prefix
		if strings.EqualFold(entry, lanKeyword) {
			var err error
			if p, err = lan(); err != nil {
				return nil, fmt.Errorf("detect camera LAN subnet: %w", err)
			}
		} else {
			var err error
			if p, err = netip.ParsePrefix(entry); err != nil {
				return nil, err
			}
		}
		p = p.Masked()
		if p.Overlaps(tunnel) {
			return nil, fmt.Errorf("route subnet %s overlaps the tunnel subnet %s", p, tunnel)
		}
		routes = append(routes, p)
	}
	return routes, nil
}

// primaryIPv4 returns the camera's source address for off-link traffic. A UDP
// "connect" sends no packet; it only asks the kernel for the route.
func primaryIPv4() (netip.Addr, error) {
	if c, err := net.Dial("udp4", "192.0.2.1:9"); err == nil {
		defer c.Close()
		if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
			if addr, ok := netip.AddrFromSlice(ua.IP); ok && !addr.Unmap().IsLoopback() {
				return addr.Unmap(), nil
			}
		}
	}
	// No default route: fall back to the first global address on an up interface.
	p, err := firstInterfacePrefix(netip.Addr{})
	if err != nil {
		return netip.Addr{}, err
	}
	return p.Addr(), nil
}

// lanSubnet returns the subnet of the interface carrying the primary address.
func lanSubnet() (netip.Prefix, error) {
	addr, err := primaryIPv4()
	if err != nil {
		return netip.Prefix{}, err
	}
	p, err := firstInterfacePrefix(addr)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// firstInterfacePrefix finds the interface prefix holding want, or the first
// global IPv4 prefix on an up, non-loopback interface when want is invalid.
func firstInterfacePrefix(want netip.Addr) (netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Prefix{}, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLinkLocalUnicast() {
				continue
			}
			if want.IsValid() && ip != want {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			return netip.PrefixFrom(ip, ones), nil
		}
	}
	return netip.Prefix{}, errors.New("no IPv4 address on any up interface")
}
