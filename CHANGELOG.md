# Changelog

## Unreleased

- Enforce the documented limit of 100 peers. Further peers are not added and
  are listed under peer errors, like other invalid peer entries. Before, any
  number was served.
- README: note that NetBird also uses UDP 51820 by default.

## 0.1.0

- Initial release: WireGuard server running in userspace (wireguard-go and
  gVisor), with camera access, optional LAN gateway and peer-to-peer access,
  peer management with in-browser key generation and client config download,
  and a live peer status view.
