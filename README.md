# Stratum FW

A free, subscription-free firewall and gateway appliance OS built on **FreeBSD 15.1-RELEASE** and **pf**, managed from a modern asynchronous **Python 3.12 & FastAPI** web panel, in the spirit of pfSense and OPNsense *(core FastAPI panel source is kept closed during Beta; installer images, documentation, changelog, and issue tracking are public)*. One declarative configuration file, a 60-second **Safe-Apply** with automatic rollback, built-in **TOTP 2FA**, and signed updates with atomic **ZFS Boot Environments**.

* **Current release:** `0.30.0` (November 2026) — [Release History (CHANGELOG.md)](CHANGELOG.md)
* **Live Browser Demo (FreeBSD 15.1 QEMU VM):** <https://demo.stratumfw.com> *(Login: `demo` / `Stratum2026` — auto-filled, zero signup)*
* **Official Website & Downloads (`.iso` VGA & `.img` Serial):** <https://stratumfw.com> · [Download Installers](https://stratumfw.com/download/)
* **Documentation & Architecture Comparison:** [Documentation Hub](https://stratumfw.com/resources/documentation/) · [OPNsense Migration Guide](https://stratumfw.com/resources/documentation/opnsense-migration/) · [Firewall & UTM Comparison](https://stratumfw.com/compare/)

## Try It Live in Your Browser

Explore a real Stratum FW appliance running on an isolated FreeBSD 15.1 virtual machine before downloading media:

* **Launch Live Demo:** <https://demo.stratumfw.com> ([Demo Overview](https://stratumfw.com/demo/))
* **Credentials:** Username `demo` · Password `Stratum2026` *(automatically filled on sign-in; runs in a read-only Copy-on-Write sandbox)*

## Highlights (`v0.30.0`)

* **Built-In TOTP Two-Factor Sign-In (`v0.30.0`).** Protect panel accounts with 6-digit authenticator codes (*Google/Microsoft Authenticator, 1Password, Bitwarden*). QR codes render locally in the browser so secrets never leave the firewall, paired with single-use replay protection, 10 one-time recovery codes, session revocation, and console recovery (`stratum-menu`).
* **Force DNS with Active Directory Exceptions (`v0.29.2`).** Redirect client DNS queries on selected internal networks to Stratum's resolver regardless of hardcoded DNS (`8.8.8.8`) and block DNS over TLS (`TCP 853`) so DNSBL and the 55-category Web Filter cannot be bypassed—with an Exception alias for internal AD domain controllers and zero browsing history recorded.
* **Multi-WAN Failover, Dynamic DHCP `WAN2` & Policy Routing (`v0.16` – `v0.29.1`).** 1-second gateway health probes across Static, PPPoE, and secondary/tertiary **DHCP WANs** (cable, 4G/5G LTE, Starlink), symmetric `reply-to`, and per-rule Policy Routing that tracks ISP gateway lease renewals within seconds without an Apply.
* **Time-Based Firewall Schedules & Bidirectional 1:1 NAT (`v0.28.9` – `v0.29.0`).** Attach minute-accurate schedules (`stratum-pfrefresh`) that automatically close open states when a pass window ends, and map internal servers/subnets 1:1 to public WAN Virtual IPs or routed subnets with anti-lockout WAN IP protection.
* **Unified Threat Defense & Log Analytics (`v0.24` – `v0.28.8`).** 63 automated IP feeds, Unbound 1.26 RPZ DNSBL, 55-category Web Filter with forced Safe Search, per-interface dual-engine **Suricata 8 IPS/IDS** (`netmap` + `pcap`), pfBlockerNG-style **Unified Blocklist Reports**, and a **1h/24h Firewall Log Summary** with GeoIP countries and one-click live log drilldown.
* **Drop-In OPNsense & OpenVPN Migration (`v0.25.0` – `v0.29.2`).** Import an OPNsense `config.xml`—interfaces, VLANs, DHCP `WAN2`, rules, Force DNS redirects, catalog URL-table IP feeds, GeoIP/Hostname aliases, Virtual IPs, and optional complete **OpenVPN server takeover** (`$2y$` bcrypt & `argon2id` hashes + PKI) so existing client `.ovpn` profiles connect unchanged.
* **Safe-Apply & ZFS Boot Environments (`v0.28.0`).** Every change is syntax-checked (`pfctl -n`, `nginx -t`, `sshd -t`, `unbound-checkconf`, `dnsmasq --test`) and guarded by a 60-second automatic rollback timer; every online or `.sfu` air-gap update snapshots `zroot/ROOT/*` first.
* **Kernel WireGuard, Multi-WAN OpenVPN & Read-Only AI MCP.** On-box `if_wg` X25519 QR provisioning, built-in OpenVPN EC CA, Wireshark `.pcap` capture, Wake-on-LAN, encrypted `AES-256-GCM` SFTP backups (`.stbk`), SNMP monitoring, and a strictly read-only **Model Context Protocol (MCP)** server for AI-assisted troubleshooting.

## Installation Media

Download from <https://stratumfw.com/download/> and follow the [Installation Guide](https://stratumfw.com/resources/documentation/installation/):

| Variant | Target Hardware / Hypervisor | Default Console |
| :--- | :--- | :--- |
| **VGA ISO (`.iso`)** | Bare-metal servers with monitor/keyboard, Proxmox VE, VMware ESXi, KVM/QEMU, Hyper-V | VGA Display |
| **Serial IMG (`.img`)** | Headless network appliances, mini-PCs, RJ45/USB console cables, IPMI Serial-over-LAN | `115200 8N1` (`ttyu0`) |

After installing from `.iso` or `.img`, update directly to **`v0.30.0`** via **System → Update** (online or offline `.sfu` package).

## Feedback & Issue Reporting

Found a bug or want to request a feature during Beta? Open an issue in this repository or reach out via <https://stratumfw.com/company/contact/>.
