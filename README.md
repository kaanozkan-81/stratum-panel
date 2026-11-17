<div align="center">

# Stratum Firewall (Stratum FW)

**Free, Zero-Subscription Network Security & Routing Appliance OS on FreeBSD 15.1-RELEASE, Kernel `pf`, OpenZFS & FastAPI**

[[https://img.shields.io/badge/Live_Demo-demo.stratumfw.com-10b981?style=for-the-badge]](https://demo.stratumfw.com)
[[https://img.shields.io/badge/Download-v0.34.1_ISO_%26_IMG-f59e0b?style=for-the-badge]](https://stratumfw.com/download/)
[[https://img.shields.io/badge/Docs-stratumfw.com-0ea5e9?style=for-the-badge]](https://stratumfw.com/product/features/)
[[https://img.shields.io/badge/Changelog-v0.34.1-6366f1?style=for-the-badge]](./CHANGELOG.md)

<br>

<a href="https://demo.stratumfw.com">
  <img src="./docs/images/hero.jpg" alt="Stratum Firewall Flagship Showcase" width="100%">
</a>

</div>

## Overview

**Stratum Firewall** is a self-contained `amd64` firewall, VPN hub, and UTM gateway built on **FreeBSD 15.1-RELEASE**, stateful `pf`, and **OpenZFS**, managed through an asynchronous **Python 3.12 / FastAPI** web control plane with zero PHP and zero recurring license fees.

* **Current Release:** `v0.34.1` (November 2026) — [Release Notes & Changelog](./CHANGELOG.md)
* **Interactive Live Demo (Light & Dark UI, no signup):** [https://demo.stratumfw.com](https://demo.stratumfw.com)
* **Offline VGA `.iso` & Headless `115200 8N1` Serial `.img` Installers:** [https://stratumfw.com/download/](https://stratumfw.com/download/)
* **Repository Note:** Core FastAPI panel sources remain in a private build tree prior to `v1.0`; this public repository hosts architectural documentation, full release changelogs, and community issue tracking.

## Architecture & Visual Highlights

| Multi-Vendor IPsec & WireGuard S2S Hub | Live S2S Tunnel & Kernel Crypto Telemetry |
| :---: | :---: |
| <img src="./docs/images/s2s_topo.jpg" alt="Multi-Vendor Site-to-Site IPsec and WireGuard Topology" width="100%"> | <img src="./docs/images/s2s_panel.jpg" alt="Live IPsec and WireGuard S2S Status Panel" width="100%"> |
| **Appliance & Dual-Theme Control Plane** | **3-Tier FreeBSD 15.1 + OpenZFS + FastAPI Stack** |
| <img src="./docs/images/showcase.jpg" alt="Stratum Firewall Hardware and Dashboard Showcase" width="100%"> | <img src="./docs/images/stack.jpg" alt="Stratum Firewall 3-Tier Architecture Stack" width="100%"> |

## Key Capabilities (`v0.34.1`)

* **Declarative Single-File Config & 60s Safe-Apply:** Every rule, interface, and VPN change is pre-checked (`pfctl -n`, `unbound-checkconf`, `dnsmasq --test`, `nginx -t`) and applied inside a **60-second anti-lockout rollback window**, with private keys isolated in `0600` root-only files.
* **Atomic ZFS Boot Environments (`bectl`):** Every online package update or offline `.sfu` upgrade snapshots the root ZFS pool automatically for instant boot-menu or Web UI rollback.
* **Multi-Vendor Site-to-Site IPsec (`IKEv2` & `IKEv1`):** Policy-based `strongSwan` key negotiation with FreeBSD kernel ESP crypto (`enc0`), multi-subnet Phase 2 selectors, automatic `NAT-T` (UDP `4500`), TCP MSS `1360` clamping, and outbound NAT exemption for FortiGate, Cisco, OPNsense, and cloud VPC gateways.
* **Dedicated Kernel WireGuard S2S (`wg1, wg2...`) & Mobile VPN (`wg0`):** Isolated per-branch `if_wg` interfaces verified behind NAT against MikroTik RouterOS 7 with hitless `wg syncconf` reloads, alongside QR road-warrior WireGuard and Multi-WAN OpenVPN (EC PKI + `tls-crypt`).
* **Dual-Engine Suricata 8 IPS/IDS & Hitless Updates:** Per-interface `netmap` inline IPS and `pcap` IDS with zero `igb` hardware offload link flaps during engine reloads or OS updates.
* **Unbound 1.26 RPZ DNSBL, 55-Category Web Filter & 63 IPv4 Feeds:** Kernel `pf` threat tables, DNS blocklists, Force DNS enforcement (with Active Directory domain exceptions), and unified blocklist analytics at `$0/year`.
* **30-Day Inter-VLAN & VPN Traffic Matrix:** Rolling 30-day east-west subnet flow matrix (`Diagnostics -> Firewall Log -> Between networks`) across VLANs, `enc0` IPsec, and `wg1+` WireGuard links for confident micro-segmentation.
* **1-Click OPNsense Migration & Read-Only MCP Server:** Direct `config.xml` import (interfaces, VLANs, `/29` VIPs, aliases, rules, NAT, Unbound DNSBL, full-span DHCP pools, and OpenVPN PKI), local-QR TOTP 2FA, encrypted `.stbk` SFTP backups, and a 14-tool read-only Model Context Protocol (MCP) telemetry server.

## System Architecture

| Layer | Component |
| :--- | :--- |
| **Operating System** | FreeBSD 15.1-RELEASE (`amd64`), OpenZFS root, `bectl` Boot Environments |
| **Packet Filter & QoS** | Stateful FreeBSD `pf`, radix tables, policy routing, 1:1 NAT, time schedules |
| **Control Plane** | Asynchronous Python 3.12, FastAPI, Jinja2, Uvicorn behind hardened Nginx |
| **VPN & Crypto** | Kernel ESP (`enc0`) + `strongSwan` (`IKEv2`/`IKEv1`), Kernel `if_wg` (`wg0` + `wg1+` S2S), OpenVPN |
| **Threat & DNS Stack** | Suricata 8 (`netmap` + `pcap`), Unbound 1.26 RPZ, `dnsmasq`, 63 IPv4 blocklists |
| **Installers & Updates** | Offline VGA `.iso`, Headless Serial `.img` (`115200 8N1`), signed FreeBSD `pkg` repo & `.sfu` bundles |

## Latest Engineering Articles

* **EN:** [Stratum Firewall v0.34.1: Site-to-Site IPsec, Dedicated WireGuard S2S, 30-Day VLAN Traffic Matrix, and Hitless Suricata Updates](https://stratumfw.com/blog/stratum-firewall-v0-34-1-ipsec-wireguard-s2s-vlan-matrix-hitless-suricata/)
* **TR:** [Stratum Firewall v0.34.1: Merkezden Şubeye IPsec, Adanmış WireGuard S2S, 30 Günlük VLAN Trafik Matrisi ve Kesintisiz Suricata Güncellemeleri](https://stratumfw.com/tr/blog/stratum-firewall-v0-34-1-ipsec-wireguard-s2s-vlan-matrisi-kesintisiz-suricata/)

© 2026 Kaan Özkan. All rights reserved.
