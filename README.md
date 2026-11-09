# Stratum FW

A self-hosted firewall and gateway appliance built on **FreeBSD 15.1-RELEASE** and **pf**, managed from a modern asynchronous web panel, in the spirit of pfSense and OPNsense. One declarative configuration file, a 60-second **Safe-Apply** with automatic rollback, and signed updates with atomic **ZFS Boot Environments**.

* **Current release:** `0.27.1` (November 2026) — [Release History (CHANGELOG.md)](CHANGELOG.md)
* **Live Browser Demo (FreeBSD 15.1 VM):** [https://demo.stratumfw.com](https://demo.stratumfw.com) *(Login: `demo` / `Stratum2026` — auto-filled)*
* **Official Website & Downloads (`.iso` VGA & `.img` Serial):** [https://stratumfw.com](https://stratumfw.com) · [Download v0.27.1](https://stratumfw.com/download/)

## Try It Live in Your Browser

You can explore the real Stratum FW `v0.27.1` management interface running on an isolated FreeBSD 15.1 virtual appliance without downloading or installing anything:

* **Launch Live Demo:** [https://demo.stratumfw.com](https://demo.stratumfw.com) ([Demo Overview](https://stratumfw.com/demo/))
* **Credentials:** Username `demo` · Password `Stratum2026` *(automatically filled on the sign-in screen; runs in a read-only Copy-on-Write sandbox)*

## Highlights

* **Safe Apply.** Every change is validated, pre-checked (`pfctl -n`, `nginx -t`, `sshd -t`, `unbound-checkconf`, `dnsmasq --test`) and applied with a 60-second automatic rollback unless confirmed in time. Settings that would lock out the administrator are refused when saving.
* **One Source of Truth.** All settings live in a single declarative JSON file; `pf`, `dnsmasq`, `Unbound`, `Suricata`, `mpd5`, `OpenVPN`, `WireGuard`, `nginx`, `sshd`, `stratum-netextra`, and `rc.conf` are generated cleanly from it.
* **Drop-In OPNsense & OpenVPN Migration (`v0.25.0` – `v0.27.1`).** Import an OPNsense `config.xml` with interactive interface mapping and pre-flight reporting. Optionally take over the entire **OpenVPN server** (CA, server & user certificates, `tls-crypt`/`tls-auth` keys, tunnel settings, and user password hashes including PHP `$2y$` bcrypt and `argon2id`) so existing client `.ovpn` profiles connect unchanged.
* **Signed Updates with ZFS Boot Environments.** Online signed repository (`update.stratumfw.com`) and offline update packages (`.sfu`) automatically snapshot the system into a new ZFS boot environment before every upgrade; the previous version can be booted again at any time.
* **Fast, Clean Web UI.** Server-rendered pages with lightweight vanilla JavaScript modules, dark and light themes, no heavy client-side build step, and full **English & Turkish** (`EN` / `TR`) localization.

## Features

### Interfaces, Virtual IPs & Routing
* **Interface Assignments:** `WAN`, `LAN`, `OPT1..N` (`OPT` as WAN or LAN type), static IPv4, DHCP, and PPPoE (`mpd5`), custom MTU, and 802.1Q VLANs.
* **Multi-WAN & Gateway Monitoring:** Gateway health monitoring, automatic failover, and policy-based routing.
* **Virtual IPs (`v0.27.0`):** Assign additional public or internal addresses (such as a routed `/29` WAN block) to any interface for Port Forwards (with NAT reflection) and Outbound NAT.
* **Static Routes (`v0.27.0`):** Route internal subnets behind downstream routers with automatic outbound NAT inclusion. Both Virtual IPs and static routes are synchronized cleanly without polluting `rc.conf` via `stratum-netextra`.

### Firewall, NAT & Dynamic Aliases
* **Stateful `pf` Rules:** Per-interface rules with visible system rules, live packet/byte hit counters, drag-and-drop ordering, and quick enable/disable toggles.
* **Port Forwards & Outbound NAT:** Automatic associated filter rules, NAT reflection, and Automatic / Hybrid / Manual outbound NAT modes.
* **Dynamic Hostname & Country (GeoIP) Aliases (`v0.26.0` – `v0.26.1`):**
  * **Hostname Aliases:** Resolved every 5 minutes via the local DNS resolver and retained for 60 minutes to handle CDN IP rotation smoothly.
  * **License-Free Country (GeoIP) Aliases:** Weekly country IPv4 blocks sourced directly from all five Regional Internet Registries (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) — no external API key required.
* **IP & DNS Blocklists:** 63 maintained IPv4 threat feeds loaded into `pf` tables (hourly live updates without reload) plus Unbound RPZ DNSBL sinkholing (pfBlockerNG & HaGeZi catalogs).

### Intrusion Detection & Prevention (Suricata IPS/IDS)
* **Per-Interface Dual-Engine Modes (`v0.24.3` – `v0.24.4`):** Independently select **Watch** (`pcap` IDS) or **Block** (`netmap` inline IPS) per interface. When mixed across interfaces, Stratum supervises separate `netmap` and `pcap` Suricata processes and reloads rule categories live via FreeBSD `SIGUSR2`.

### VPN (WireGuard & OpenVPN)
* **OpenVPN Remote Access:** Built-in CA (EC keys, CRL, `tls-crypt`), certificate + password authentication (`bcrypt` & `argon2id`), multi-WAN `multihome` reply routing, ordered multi-remote client profiles, `block-outside-dns` for Windows clients, and full OPNsense server takeover.
* **WireGuard (`if_wg`):** Kernel-level WireGuard with on-box key generation, downloadable `.conf` profiles and QR codes, per-VLAN access control, and zero-downtime peer updates.

### Diagnostics & System Management
* **Packet Capture (`v0.25.1`):** Capture interface traffic with protocol, host/network, and port filters into a downloadable `.pcap` file for Wireshark (automatically excluding your admin session).
* **ARP Table & Wake-on-LAN (`v0.25.1`):** Live neighbor table with DHCP/DNS hostname resolution, randomized mobile MAC detection, and one-click Wake-on-LAN.
* **Remote-Safe Power & Factory Reset (`v0.25.1`):** Reboot, halt, or reset to factory defaults while preserving active physical interface assignments so remote appliances stay reachable.
* **Role-Based Access Control (RBAC):** Administrator, Operator, Read-Only, and VPN-only user accounts, plus Let's Encrypt ACME & custom TLS certificate management.

## Architecture

```text
Browser ──HTTPS──> nginx ──> uvicorn / FastAPI panel ──> config.json (+ users, keys, certificates)
                                                               │
                                         stratum-config apply ◄┘
                                    validate · pre-check · snapshot
                                    apply · confirm / 60s auto-rollback
      ┌──────────────┬───────────────┬───────────────┬──────────────┬──────────────────┐
   pf.conf   dnsmasq / Unbound   Suricata    OpenVPN / wg0    nginx / sshd   stratum-netextra
```

| Layer | Component |
| :--- | :--- |
| **Operating System** | FreeBSD 15.1-RELEASE (`amd64`), ZFS root, atomic Boot Environments |
| **Packet Filter & IPS** | `pf` (stateful inspection, ALTQ shaping, live tables) + dual-engine Suricata (`netmap` / `pcap`) |
| **Web Panel** | Python 3.12, FastAPI, Jinja2, Uvicorn behind Nginx |
| **Frontend** | Server-rendered templates, modular vanilla JavaScript, dark/light theme, EN & TR |
| **Network Services** | `dnsmasq`, `Unbound` (DNSSEC & RPZ DNSBL), `mpd5` (PPPoE), `OpenVPN`, `WireGuard` (`if_wg`), `ntpd` |
| **Installers & Updates** | VGA `.iso` & Headless Serial `.img` installers, signed online repo & offline `.sfu` update packages |
| **CLI Utilities** | `stratum-config`, `stratum-menu`, `stratum-update`, `stratum-netextra`, `stratum-cert`, `stratum-ipbl`, `stratum-dnsbl` |

## Latest Articles & Release Notes

* 🇬🇧 [Stratum Firewall v0.27.1: Seamless OPNsense & OpenVPN Migration, Virtual IPs, Country Aliases, and Diagnostics](https://stratumfw.com/blog/stratum-firewall-v0-27-1-opnsense-migration/)
* 🇹🇷 [Stratum Firewall v0.27.1: Kesintisiz OPNsense ve OpenVPN Göçü, Sanal IP'ler, Ülke Takma Adları ve Tanılama Araçları](https://stratumfw.com/tr/blog/stratum-firewall-v0-27-1-opnsense-migration/)
* 🇬🇧 [Stratum FW vs pfSense: The AI-Powered (MCP) Next-Gen Firewall](https://stratumfw.com/blog/pfsense-alternative-stratum-fw/)
* 🇹🇷 [pfSense Alternatifi Stratum FW: Yapay Zeka Destekli Yeni Nesil Güvenlik](https://stratumfw.com/tr/blog/pfsense-alternatifi-stratum-fw/)
* 📄 Full release history: [Online Changelog](https://stratumfw.com/resources/changelog/) or [CHANGELOG.md](CHANGELOG.md)

© 2026 Kaan Özkan. All rights reserved.
