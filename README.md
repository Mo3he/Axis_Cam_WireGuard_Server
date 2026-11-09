# WireGuard Server ACAP for Axis Cameras

[![Release](https://img.shields.io/github/v/release/Mo3he/Axis_Cam_WireGuard_Server?style=flat)](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/releases)
[![Build](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/actions/workflows/build.yml/badge.svg)](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/actions/workflows/build.yml)
[![License](https://img.shields.io/github/license/Mo3he/Axis_Cam_WireGuard_Server?style=flat)](LICENSE)
[![Super-Linter](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/actions/workflows/super-linter.yml/badge.svg)](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/actions/workflows/super-linter.yml)
[![Sponsor](https://img.shields.io/badge/Sponsor%20My%20Work-EA4AAA?style=flat&logo=github&logoColor=white)](https://github.com/sponsors/Mo3he)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-FFDD00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/mo3he)

Turns an Axis camera into a [WireGuard](https://www.wireguard.com) VPN server.
Remote clients connect to the camera and reach the camera itself and,
optionally, the camera's LAN, with no root, kernel module, or TUN device.

> **Disclaimer:** Independent, community-developed ACAP package. Not an official
> Axis product and not affiliated with, endorsed by, or supported by Axis
> Communications AB or the WireGuard project. Use at your own risk.

> **WireGuard Notice:** WireGuard is a registered trademark of Jason A.
> Donenfeld. This package independently redistributes
> [wireguard-go](https://github.com/WireGuard/wireguard-go) and related
> components under the MIT License and is not affiliated with, endorsed by, or
> sponsored by Jason A. Donenfeld or the WireGuard project.

## Overview

The camera listens for WireGuard clients (laptops, phones, routers) and acts as
their gateway:

- **Camera access:** peers reach every camera service (web UI, RTSP, VAPIX) at
  the server's tunnel address, for example `http://10.66.0.1`.
- **LAN gateway (optional):** peers reach other devices on the camera's network,
  such as an NVR or other cameras, through the camera.
- **Peer-to-peer (optional):** peers reach each other through the camera.
- **Peer management in the camera UI:** add a peer and the settings page
  generates its key pair in your browser and hands you a ready-to-import client
  config. Client private keys never reach the camera.
- **Live status:** connected peers, last handshake, endpoint, and transfer.

Everything runs in userspace with
[wireguard-go](https://github.com/WireGuard/wireguard-go) and the
[gVisor](https://gvisor.dev/) network stack, as the unprivileged `sdk` user.

Looking for the camera to connect *out* to an existing WireGuard server instead?
Use the [WireGuard VPN ACAP](https://github.com/Mo3he/Axis_Cam_WireGuard).

## Compatibility

| Package | AXIS OS | Architecture | Status |
|---|---|---|---|
| ACAP 4 | 11.11 - 13 | aarch64 | Supported |
| ACAP 4 | 11.11 - 13 | armv7hf | Supported |

The app runs as the unprivileged `sdk` user. It does not require root access.

## Installation

Download the EAP matching the camera architecture from the
[Releases page](https://github.com/Mo3he/Axis_Cam_WireGuard_Server/releases),
install it under **Apps -> Add app**, start it, and open its settings page.

The camera must be reachable from your clients on the WireGuard UDP port:

1. Give the camera a fixed LAN address (static or a DHCP reservation).
2. On your router, forward UDP `51820` (or your chosen listen port) to the
   camera.
3. If the camera's host-based firewall is enabled, allow that UDP port.

A camera behind carrier-grade NAT (CGNAT) cannot accept incoming connections;
use a VPN client app such as the WireGuard VPN, Tailscale, or NetBird ACAP
instead.

## Configuration

1. Enter the **Public endpoint**: the public IP or DNS name and port of your
   router, for example `vpn.example.com:51820`.
2. Choose what peers may reach: tick **Let peers reach the camera's LAN** for
   gateway access, add any extra subnets, and decide whether peers may reach
   each other.
3. Tick **Enable the WireGuard server** and **Save**.
4. Under **Add peer**, enter a name and click **Add peer**. Download the client
   config (or copy it) and import it into the WireGuard client app. To use a key
   pair created on the client instead, paste the client's public key before
   adding it.

The server key pair is generated on the camera on first start and kept in the
app's `localdata` directory, so it survives upgrades. Its public key is shown on
the settings page.

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `Enabled` | `no` | Runs the WireGuard server when `yes`. |
| `ListenPort` | `51820` | UDP port the server listens on (1024 to 65535). |
| `Address` | `10.66.0.1/24` | Server tunnel address; the prefix is the client address pool. |
| `Peers` | empty | Peers as `name,publicKey,address` records separated by `;`. Up to 100 peers. |
| `RouteSubnets` | empty | Subnets peers may reach through the camera, comma separated. `lan` means the camera's own subnet. Empty means camera only. |
| `PeerToPeer` | `no` | Lets peers reach each other through the camera. |
| `MTU` | `1420` | Tunnel MTU (576 to 1500). |
| `PrivateKey` | empty | Overrides the generated server key, to migrate an existing server. Write-only. |
| `PublicEndpoint` | empty | Endpoint written into generated client configs. |
| `ClientDNS` | empty | DNS server written into generated client configs. |

Changing `PublicEndpoint` or `ClientDNS` does not restart the server; any other
change restarts it, and clients reconnect within seconds.

The camera's parameter store limits how long a value can be, which is what caps
the peer list at 100. If a value is refused, the settings endpoint answers
`422` and names the parameter rather than reporting success.

The settings page reads and writes through the app's own endpoint at
`/local/WireGuard_Server/api/settings`, served by the app itself and reachable
only through the camera's authenticated reverse proxy. Nothing depends on
`/axis-cgi/param.cgi`, which recorder, NVR, and access-control class devices do
not expose. `param.cgi` is used only as a fallback if the app's settings server
is unavailable.

## Ports & security

| Port | Bound to | Purpose |
|---|---|---|
| UDP `51820` (configurable) | all interfaces | WireGuard. Only when the server is enabled. |
| TCP `2211` | `127.0.0.1` | Settings endpoint, exposed as `/local/WireGuard_Server/api/settings` (admin only). |
| TCP `2212` | `127.0.0.1` | Status endpoint, exposed as `/local/WireGuard_Server/status` (admin only). |

- WireGuard answers only peers whose public key is configured; anything else is
  silently dropped, so the UDP port does not reveal itself to scanners.
- Peers are confined to what you allow: the camera, the routed subnets, and
  (optionally) each other. Everything else is refused.
- The camera's tunnel address maps to its **LAN address, never to loopback**.
  Services bound to `127.0.0.1`, such as other apps' unauthenticated settings
  servers, stay unreachable from the VPN. Loopback, multicast, and broadcast
  destinations are always refused.
- Peers still have to authenticate to camera services as usual: a VPN peer is
  treated like a device on the LAN, with no extra privileges.
- The server private key is stored with mode `0600` in the app's `localdata`
  directory and is never returned by any endpoint.

## How it works

wireguard-go decrypts packets from a peer and hands them to the app's own
network device, which routes them as follows:

- **To another peer:** sent straight back to wireguard-go, which encrypts it to
  that peer, if peer-to-peer is allowed.
- **To anything else:** handed to a gVisor TCP/IP stack running in promiscuous
  mode. It terminates each TCP connection and UDP flow addressed to an allowed
  destination and opens the matching connection from the camera's normal
  network stack. This is userspace NAT: LAN devices see connections coming from
  the camera's own address, so they need no route back to the VPN.

Because connections are re-originated rather than routed, a few things differ
from a kernel WireGuard server:

- **TCP and UDP only.** Pinging the server's tunnel address works; pinging LAN
  hosts does not.
- **IPv4 only**, for both the tunnel and the routed subnets.
- **LAN devices cannot open connections to peers.** Peers connect out to the
  LAN, not the other way round.
  This includes RTP over UDP, so RTSP clients must use TCP transport
  (interleaved RTP), which most clients fall back to automatically.
- **Bounded per-connection buffering:** each TCP connection towards a peer
  keeps at most 512 KiB in flight, which keeps memory use low on the camera and
  still allows roughly 80 Mbit/s per connection at 50 ms round-trip time.
- **Detected once per start:** the camera's LAN address and the `lan` subnet are
  read when the server starts, so restart the app after changing the camera's
  IP address.

### Roadmap

- QR codes for mobile client configs.
- Optional preshared keys per peer.
- IPv6 tunnel addresses.

## Build from source

Docker or Podman is required; the Axis ACAP Native SDK image does the build.

```sh
./build.sh                 # aarch64 and armv7hf into ./releases
ARCHES=aarch64 ./build.sh  # a single architecture
```

### Tests

```sh
sh tests/run.sh
```

The tests include end-to-end runs that start the server and real WireGuard
clients over loopback, then check camera access, LAN gateway TCP and UDP,
access denial, peer-to-peer relaying, and ping handling.

### CI

Every push builds both architectures, runs the tests, and uploads the packages
as workflow artifacts. Pushing a `v*` tag creates a release with the packages
attached.

## Links

- Releases: <https://github.com/Mo3he/Axis_Cam_WireGuard_Server/releases>
- Issues: <https://github.com/Mo3he/Axis_Cam_WireGuard_Server/issues>
- WireGuard VPN client ACAP: <https://github.com/Mo3he/Axis_Cam_WireGuard>
- WireGuard: <https://www.wireguard.com>
- ACAP documentation: <https://developer.axis.com/acap/>
- Axis Communications: <https://www.axis.com/>

## License

The packaging and app code in this repository is licensed under BSD 3-Clause
(see [LICENSE](LICENSE)). Bundled upstream components (wireguard-go, gVisor,
golang.org/x, google/btree, TweetNaCl.js) are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
