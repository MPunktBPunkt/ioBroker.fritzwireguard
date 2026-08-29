# ioBroker.fritzwireguard

[![NPM version](https://img.shields.io/npm/v/iobroker.fritzwireguard.svg)](https://www.npmjs.com/package/iobroker.fritzwireguard)
[![Downloads](https://img.shields.io/npm/dm/iobroker.fritzwireguard.svg)](https://www.npmjs.com/package/iobroker.fritzwireguard)
![Test and Release](https://github.com/MPunktBPunkt/ioBroker.fritzwireguard/workflows/Test%20and%20Release/badge.svg)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

Connects ioBroker to a **remote FRITZ!Box** via **WireGuard VPN**. The adapter exposes network devices, WAN status and FritzBox info as ioBroker states and provides a **TCP tunnel manager** so selected adapters can reach devices in the remote network — without forcing a full-tunnel for all traffic.

> Device / manufacturer: [AVM FRITZ!Box](https://avm.de/produkte/fritzbox/) · WireGuard: [wireguard.com](https://www.wireguard.com/)

German documentation: [README.de.md](./README.de.md)

## Features

* WireGuard VPN via `wg-quick`, reload on config change
* Config sanitizer (DNS, full-tunnel, IPv6, `/24` address; narrows `AllowedIPs` to tunnel hosts)
* Optional TR-064 (WAN IP, uptime, model, firmware, host list)
* TCP tunnel manager: `127.0.0.1:<port>` → remote host:port over VPN
* Web-UI (data, nodes, tunnels, logs, system)
* Admin quick-start with live status and connection test
* Auto-reconnect when handshake is lost

## Requirements

### ioBroker host (Linux)

```bash
sudo apt update && sudo apt install -y wireguard

echo "iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg-quick" \
  | sudo tee /etc/sudoers.d/iobroker-wireguard
echo "iobroker ALL=(ALL) NOPASSWD: /usr/bin/wg *" \
  | sudo tee -a /etc/sudoers.d/iobroker-wireguard
sudo chmod 440 /etc/sudoers.d/iobroker-wireguard
```

On some hosts (Node with `setcap`, `sudo-rs`) the adapter also benefits from:

```bash
sudo setcap cap_net_admin+ep /usr/bin/wg
```

### Remote FRITZ!Box

1. **WireGuard VPN:** Internet → Permit Access → VPN (WireGuard) → create client → export `.conf`
2. **TR-064 (optional):** Home Network → Network → Network Settings → “Allow access for applications”
3. User with “FRITZ!Box settings” permission for TR-064

## Installation

```bash
iobroker url https://github.com/MPunktBPunkt/ioBroker.fritzwireguard
iobroker add fritzwireguard
```

## Configuration

Configure in the ioBroker admin on a **desktop** browser (WireGuard config is multi-line).

1. **WireGuard tab:** Paste the full `.conf`. Enable Auto-Connect / Auto-Reconnect.
2. **Connection tab:** Optional TR-064 credentials of the *remote* FritzBox.
3. **Port tunnels:** e.g. local `8085` → `192.168.178.30:80` for an inverter.
4. Save and restart the adapter.
5. Use **Test connection** or open the Web-UI (`http://<ioBroker-IP>:<webPort>/`).

### Same subnet locally and remotely

If both sites use `192.168.178.0/24`, do **not** route the whole subnet via VPN. Use host routes only:

```text
AllowedIPs = 192.168.178.30/32, 192.168.178.31/32
```

Never put real `PrivateKey` / `PresharedKey` values into issues, commits or screenshots — only placeholders.

### Example (placeholders only)

```ini
[Interface]
PrivateKey = <your-private-key>
Address = 192.168.178.206/32

[Peer]
PublicKey = <fritzbox-public-key>
PresharedKey = <your-preshared-key>
AllowedIPs = 192.168.178.30/32, 192.168.178.31/32
Endpoint = <your-myfritz-host>:<port>
PersistentKeepalive = 25
```

## States

| State | Description |
|-------|-------------|
| `fritzwireguard.0.info.connection` | Adapter connected (handshake) |
| `fritzwireguard.0.wireguard.status` | `connected` / `disconnected` |
| `fritzwireguard.0.wireguard.handshake` | Last handshake text |
| `fritzwireguard.0.fritzbox.*` | TR-064 FritzBox data (optional) |
| `fritzwireguard.0.devices.*` | Remote hosts via TR-064 (optional) |

## Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Admin shows “no handshake” but `wg show` is fine | Status read failed under Node/setcap | Update to ≥ 0.2.26 |
| Local SSH/ping to ioBroker lost | `AllowedIPs` too broad or `/24` address | Use `/32` tunnel hosts only |
| TR-064 without model / wrong box | Same subnet → local FritzBox answers | Optional; tunnels still work |
| Empty device list | Remote TR-064 not reachable | Expected with subnet conflict |

## Changelog

### 0.2.26
* **Fix:** WireGuard status under Node + setcap + sudo-rs (`wg show` captured empty)
* **Chore:** Align project with [ioBroker AI developer guide](https://github.com/Jey-Cee/iobroker-ai-developer-guide) (LICENSE, CI, i18n, English README, `protectedNative`)

### 0.2.25
* Fix Web-UI WG byte stats, refresh on tab switch, admin help, test button icon

### 0.2.24
* Reload WG on config change; handshake-based status; IPv4 `/24` sanitizer; TR-064 same-subnet hint

Older entries: see `io-package.json` news / git history.

## License

MIT © 2024-2026 MPunktBPunkt <martin@bchmnn.de>
