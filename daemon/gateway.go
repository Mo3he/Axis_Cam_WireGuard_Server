package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1

	tcpDialTimeout = 5 * time.Second
	udpIdleTimeout = 2 * time.Minute
	dnsIdleTimeout = 15 * time.Second

	// Bounds on concurrent forwarded flows, to keep a misbehaving peer from
	// exhausting the camera's memory or file descriptors.
	maxTCPInFlight = 256
	maxTCPConns    = 1024
	maxUDPFlows    = 512
)

// tcpSendBuffer bounds the data gVisor pushes per connection towards a peer.
// Every packet waiting inside wireguard-go pins a 64 KiB buffer on Linux, so an
// unbounded (4 MiB) send buffer let one fast download hold ~100 MB.
var tcpSendBuffer = 512 << 10

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// gateway is a tun.Device for wireguard-go. Packets between peers are relayed
// directly (when allowed); everything else is terminated by a gVisor stack in
// promiscuous mode, whose forwarders re-originate the flows from the camera's
// own network stack. This is userspace NAT: no root, TUN device or ip_forward.
type gateway struct {
	ep       *channel.Endpoint
	stack    *stack.Stack
	events   chan tun.Event
	outbound chan []byte
	closed   chan struct{}
	once     sync.Once
	mtu      int

	serverIP   netip.Addr
	tunnel     netip.Prefix
	peerToPeer bool
	policy     *policy
	dial       dialFunc

	tcpConns atomic.Int32
	udpFlows atomic.Int32
}

func newGateway(server netip.Prefix, mtu int, peerToPeer bool, pol *policy, dial dialFunc) (*gateway, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	g := &gateway{
		ep:         channel.New(1024, uint32(mtu), ""),
		events:     make(chan tun.Event, 1),
		outbound:   make(chan []byte, 1024),
		closed:     make(chan struct{}),
		mtu:        mtu,
		serverIP:   server.Addr(),
		tunnel:     server.Masked(),
		peerToPeer: peerToPeer,
		policy:     pol,
		dial:       dial,
	}

	// HandleLocal stays off: with it on, a promiscuous NIC treats every source
	// address as its own and drops all peer traffic as martian.
	g.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	sack := tcpip.TCPSACKEnabled(true)
	if err := g.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enable TCP SACK: %v", err)
	}
	sndbuf := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: tcpSendBuffer, Max: tcpSendBuffer}
	if err := g.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sndbuf); err != nil {
		return nil, fmt.Errorf("set TCP send buffer: %v", err)
	}
	g.ep.AddNotify(g)
	if err := g.stack.CreateNIC(nicID, g.ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}
	// Promiscuous + spoofing lets the stack accept connections to any address
	// and answer from that address, which is what makes it a gateway.
	if err := g.stack.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("promiscuous mode: %v", err)
	}
	if err := g.stack.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("spoofing: %v", err)
	}
	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(server.Addr().As4()).WithPrefix(),
	}
	if err := g.stack.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %v", err)
	}
	g.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	tcpFwd := tcp.NewForwarder(g.stack, 0, maxTCPInFlight, g.handleTCP)
	g.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(g.stack, g.handleUDP)
	g.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	g.events <- tun.EventUp
	return g, nil
}

// ── tun.Device ──────────────────────────────────────────────────────────────

func (g *gateway) Name() (string, error)    { return "wg-gateway", nil }
func (g *gateway) File() *os.File           { return nil }
func (g *gateway) Events() <-chan tun.Event { return g.events }
func (g *gateway) MTU() (int, error)        { return g.mtu, nil }
func (g *gateway) BatchSize() int           { return 1 }

// Read hands wireguard-go the next packet to encrypt towards a peer.
func (g *gateway) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-g.outbound:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-g.closed:
		return 0, os.ErrClosed
	}
}

// Write receives packets that wireguard-go decrypted from a peer. wireguard-go
// has already checked the source address against that peer's allowed IPs.
func (g *gateway) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := buf[offset:]
		if len(pkt) < header.IPv4MinimumSize {
			continue
		}
		if pkt[0]>>4 != 4 {
			continue // IPv6 is not routed.
		}
		ip := header.IPv4(pkt)
		if !ip.IsValid(len(pkt)) {
			continue
		}
		dst := netip.AddrFrom4(ip.DestinationAddress().As4())

		if dst != g.serverIP && g.tunnel.Contains(dst) {
			if g.peerToPeer {
				g.relay(pkt)
			}
			continue
		}
		// gVisor in promiscuous mode would answer pings to every address, which
		// says nothing about the real host, so only the server itself answers.
		if ip.TransportProtocol() == header.ICMPv4ProtocolNumber && dst != g.serverIP {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		g.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		pkb.DecRef()
	}
	return len(bufs), nil
}

// relay sends a peer-to-peer packet straight back to wireguard-go, which routes
// it to the peer owning the destination address.
func (g *gateway) relay(pkt []byte) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case g.outbound <- cp:
	default: // queue full: drop, as a congested router would
	}
}

// WriteNotify is called by the channel endpoint when gVisor emits a packet.
func (g *gateway) WriteNotify() {
	pkt := g.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	data := view.AsSlice()
	cp := make([]byte, len(data))
	copy(cp, data)
	view.Release()
	select {
	case g.outbound <- cp:
	case <-g.closed:
	}
}

func (g *gateway) Close() error {
	g.once.Do(func() {
		close(g.closed)
		g.stack.RemoveNIC(nicID)
		g.stack.Close()
		g.ep.Close()
		close(g.events)
	})
	return nil
}

// ── forwarding ──────────────────────────────────────────────────────────────

func addrOf(a tcpip.Address) netip.Addr {
	return netip.AddrFrom4(a.As4())
}

func (g *gateway) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	src := netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
	dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)

	target, ok := g.policy.resolve(dst.Addr())
	if !ok || g.tcpConns.Load() >= maxTCPConns {
		r.Complete(true)
		return
	}

	// Dial before accepting, so an unreachable or closed port is reported to
	// the peer as a reset rather than as an accepted-then-dropped connection.
	ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
	out, err := g.dial(ctx, "tcp", net.JoinHostPort(target.String(), strconv.Itoa(int(dst.Port()))))
	cancel()
	if err != nil {
		debugf("tcp %s -> %s: dial failed: %v", src, dst, err)
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		out.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	ep.SocketOptions().SetKeepAlive(true)
	in := gonet.NewTCPConn(&wq, ep)

	g.tcpConns.Add(1)
	defer g.tcpConns.Add(-1)
	pipeTCP(in, out)
}

// pipeTCP copies both directions, propagating half-closes, until both end.
func pipeTCP(a, b net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func (g *gateway) handleUDP(r *udp.ForwarderRequest) {
	id := r.ID()
	dst := netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)

	target, ok := g.policy.resolve(dst.Addr())
	if !ok || g.udpFlows.Load() >= maxUDPFlows {
		return
	}

	// The request is only valid during this call, so the endpoint must be
	// created here; the dial and relay then run in their own goroutine.
	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return
	}
	in := gonet.NewUDPConn(&wq, ep)
	g.udpFlows.Add(1)

	go func() {
		defer g.udpFlows.Add(-1)
		defer in.Close()

		ctx, cancel := context.WithTimeout(context.Background(), tcpDialTimeout)
		out, err := g.dial(ctx, "udp", net.JoinHostPort(target.String(), strconv.Itoa(int(dst.Port()))))
		cancel()
		if err != nil {
			debugf("udp -> %s: dial failed: %v", dst, err)
			return
		}
		defer out.Close()

		idle := udpIdleTimeout
		if dst.Port() == 53 {
			idle = dnsIdleTimeout
		}
		pipeUDP(in, out, idle)
	}()
}

// pipeUDP relays datagrams until neither side has sent anything for idle.
func pipeUDP(a, b net.Conn, idle time.Duration) {
	var last atomic.Int64
	var stopped atomic.Bool
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				var ne net.Error
				if !stopped.Load() && errors.As(err, &ne) && ne.Timeout() &&
					time.Since(time.Unix(0, last.Load())) < idle {
					continue // the other direction is still active
				}
				done <- struct{}{}
				return
			}
			touch()
			if _, err := dst.Write(buf[:n]); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
				done <- struct{}{}
				return
			}
		}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Unblock the other copier.
	stopped.Store(true)
	_ = a.SetReadDeadline(time.Now())
	_ = b.SetReadDeadline(time.Now())
	<-done
}

var debugEnabled = os.Getenv("WGS_DEBUG") != ""

func debugf(format string, args ...any) {
	if debugEnabled {
		log.Printf(format, args...)
	}
}
