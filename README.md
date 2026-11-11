# Stratum FW

A self-hosted firewall and gateway appliance built on **FreeBSD 15.1-RELEASE** and **pf**, managed from a modern asynchronous web panel, in the spirit of pfSense and OPNsense. One declarative configuration file, a 60-second **Safe-Apply** with automatic rollback, and signed updates with atomic **ZFS Boot Environments**.

* **Current release:** `0.28.3` (November 2026) — [Release History (CHANGELOG.md)](CHANGELOG.md)
* **Live Browser Demo (FreeBSD 15.1 VM):** [https://demo.stratumfw.com](https://demo.stratumfw.com) *(Login: `demo` / `Stratum2026` — auto-filled)*
* **Official Website & Downloads (`.iso` VGA & `.img` Serial):** [https://stratumfw.com](https://stratumfw.com) · [Download Installers](https://stratumfw.com/download/)

## Try It Live in Your Browser

You can explore the real Stratum FW management interface running on an isolated FreeBSD 15.1 virtual appliance without downloading or installing anything:

* **Launch Live Demo:** [https://demo.stratumfw.com](https://demo.stratumfw.com) ([Demo Overview](https://stratumfw.com/demo/))
* **Credentials:** Username `demo` · Password `Stratum2026` *(automatically filled on the sign-in screen; runs in a read-only Copy-on-Write sandbox)*

## Highlights

* **Safe Apply & Sticky Workflow (`v0.28.0`).** Every change is validated, pre-checked (`pfctl -n`, `nginx -t`, `sshd -t`, `unbound-checkconf`, `dnsmasq --test`) and applied with a 60-second automatic rollback unless confirmed in time. Saving a real configuration change surfaces an inline **Apply changes** button beside Save and keeps the confirmation banner visible while scrolling.
* **One Source of Truth.** All settings live in a single declarative JSON file; `pf`, `dnsmasq`, `Unbound`, `Suricata`, `mpd5`, `OpenVPN`, `WireGuard`, `nginx`, `sshd`, `stratum-netextra`, and `rc.conf` are generated cleanly from it.
* **Unified Blocklist Reports (`v0.28.2` – `v0.28.3`).** pfBlockerNG-style reporting across DNSBL, category Web Filter, and inbound/outbound IP blocklists (`Firewall > Blocklists > Blocked` + Dashboard widget) with hourly/daily charts, list attribution, top blocked domains/IPs, per-device breakdowns, and full Unbound 1.26 RPZ compatibility.
* **Drop-In OPNsense & OpenVPN Migration (`v0.25.0` – `v0.27.2`).** Import an OPNsense `config.xml` with interactive interface mapping, rule-gateway Policy Routing translation, and optional complete **OpenVPN server takeover** (CA, certs, `tls-crypt`/`tls-auth`, and `$2y$` bcrypt / `argon2id` password hashes) so existing client `.ovpn` profiles connect unchanged.
* **Signed Updates with ZFS Boot Environments.** Online signed repository (`update.stratumfw.com`) and offline update packages (`.sfu`) automatically snapshot the system into a new ZFS boot environment before every upgrade; the previous version can be booted again at any time.
* **Fast, Clean Web UI.** Server-rendered pages with lightweight vanilla JavaScript modules, customizable 12-column drag-and-drop dashboard (`gridstack`), per-user notification queues, dark and light themes, and full **English & Turkish** (`EN` / `TR`) localization.

## Features

### Interfaces, Policy Routing & Virtual IPs
* **Interface Assignments & Groups:** `WAN`, `LAN`, `OPT1..N` (`OPT` as WAN or LAN type), interface groups (`Interfaces > Groups`), static IPv4, DHCP, PPPoE (`mpd5`), custom MTU, and 802.1Q VLANs.
* **Multi-WAN Failover & Policy Routing (`v0.27.2`):** Real-time 1-second gateway health probing, automatic default-route failover, and per-rule **Policy Routing** to steer specific LANs/VLANs over a chosen WAN while automatically preserving local/VPN/routed internal traffic.
* **Virtual IPs & Static Routes (`v0.27.0`):** Assign additional public or internal addresses (e.g., `/29` WAN blocks) for Port Forwards (with NAT reflection) and Outbound NAT, and route internal subnets behind downstream routers via `stratum-netextra` without polluting `rc.conf`.

### Firewall, NAT, Aliases & Blocklists
* **Stateful `pf` Rules & Dummynet Shaper:** Per-interface and group rules with visible system rules, live packet/byte hit counters, drag-and-drop ordering, and shared or per-device download/upload bandwidth limits (`Firewall > Shaper`).
* **Dynamic Hostname & Country (GeoIP) Aliases (`v0.26.0` – `v0.26.1`):** 5-minute local DNS hostname resolution (with 60-minute CDN IP retention) and license-free weekly Country IPv4 blocks sourced directly from all five RIRs (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC).
* **IP Blocklists, DNSBL & Category Web Filter (`v0.24.0`, `v0.28.2` – `v0.28.3`):** 63 maintained IPv4 threat feeds in live `pf` tables, Unbound RPZ DNS blocklists (pfBlockerNG & HaGeZi), 55-category per-network Web Filter with Safe Search enforcement, and unified 7-day block reporting.

### Intrusion Detection & Prevention (Suricata IPS/IDS)
* **Per-Interface Dual-Engine Modes (`v0.24.3` – `v0.24.4`):** Independently select **Watch** (`pcap` IDS) or **Block** (`netmap` inline IPS) per interface. When combined, Stratum supervises separate `netmap` and `pcap` Suricata processes and reloads rule categories live via FreeBSD `SIGUSR2`.

### VPN (WireGuard & OpenVPN)
* **OpenVPN Remote Access:** Built-in CA (EC keys, CRL, `tls-crypt`), certificate + password authentication (`bcrypt` & `argon2id`), multi-WAN `multihome` reply routing, ordered multi-remote client profiles, `block-outside-dns` for Windows clients, and full OPNsense server takeover.
* **WireGuard (`if_wg`):** Kernel-level WireGuard with on-box key generation, downloadable `.conf` profiles and QR codes, per-VLAN access control, and zero-downtime peer updates.

### Services, Diagnostics & System Management
* **Service Status & Supervision (`v0.28.1`):** Unified `Services > Service Status` dashboard displaying running/stopped/disabled state, uptime, memory usage, and `PID`, with guarded start/stop/restart actions.
* **Built-In Diagnostics (`v0.20.0`, `v0.25.1`):** Wireshark `.pcap` Packet Capture, ARP Table with randomized mobile MAC detection and one-click Wake-on-LAN, per-device Web Activity & DHCP history, and `pf` state table management.
* **Encrypted SFTP Backups, SNMP & MCP (`v0.14.0`, `v0.19.0`, `v0.22.0`):** AES-256-GCM encrypted `.stbk` backups (including keys & certificates) with scheduled SFTP upload, read-only `bsnmpd` SNMP agent, and optional read-only **Model Context Protocol (MCP)** server with 15+ tools for AI diagnostics.
* **Remote-Safe Power & RBAC:** Administrator, Operator, Read-Only, and VPN-only roles; per-user notifications (`v0.28.0`); and factory reset that preserves active physical NIC assignments.

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
| **Packet Filter & IPS** | `pf` (stateful inspection, policy routing, dummynet shaping, live tables) + Suricata (`netmap` / `pcap`) |
| **Web Panel** | Python 3.12, FastAPI, Jinja2, Uvicorn behind Nginx |
| **Frontend** | Server-rendered templates, modular vanilla JS (`gridstack` customizable dashboard), dark/light theme, EN & TR |
| **Network Services** | `dnsmasq`, `Unbound` (DNSSEC, RPZ DNSBL & 55-category Web Filter), `mpd5` (PPPoE), `OpenVPN`, `WireGuard` (`if_wg`), `bsnmpd`, `ntpd` |
| **Installers & Updates** | VGA `.iso` & Headless Serial `.img` installers, signed online repo & offline `.sfu` update packages |
| **CLI Utilities** | `stratum-config`, `stratum-menu`, `stratum-update`, `stratum-netextra`, `stratum-cert`, `stratum-ipbl`, `stratum-dnsbl` |

## Latest Articles & Release Notes

* 🇬🇧 [Stratum Firewall v0.28.3: Unified Blocklist Reports, Multi-WAN Policy Routing, and Service Control](https://stratumfw.com/blog/stratum-firewall-v0-28-3-blocklist-reports-policy-routing/)
* 🇹🇷 [Stratum Firewall v0.28.3: Engelleme Listesi Raporları, Politika Tabanlı Yönlendirme ve Servis Yönetimi](https://stratumfw.com/tr/blog/stratum-firewall-v0-28-3-blocklist-reports-policy-routing/)
* 🇬🇧 [Stratum Firewall v0.27.1: Seamless OPNsense & OpenVPN Migration, Virtual IPs, Country Aliases, and Diagnostics](https://stratumfw.com/blog/stratum-firewall-v0-27-1-opnsense-migration/)
* 🇹🇷 [Stratum Firewall v0.27.1: Kesintisiz OPNsense ve OpenVPN Göçü, Sanal IP'ler, Ülke Takma Adları ve Tanılama Araçları](https://stratumfw.com/tr/blog/stratum-firewall-v0-27-1-opnsense-migration/)
* 📄 Full release history: [Online Changelog](https://stratumfw.com/resources/changelog/) or [CHANGELOG.md](CHANGELOG.md)

© 2026 Kaan Özkan. All rights reserved.
