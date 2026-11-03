# Changelog

All notable changes to Stratum FW are listed here, newest first. Stratum FW updates itself from the signed
update server (System > Update) or from an offline update file (`.sfu`); every update creates a ZFS boot
environment, so the previous version can be booted again at any time.

## 0.12.2 - 2026-11-03

### Added
- **System > Settings > Firewall & NAT**:
  - Blocked connections dropped silently or rejected; logging of the default block and of broadcast noise.
  - Bogon and private network blocking and ping on the WAN address (until now only in the configuration file).
  - State table size with a suggestion for the installed memory and the current usage, idle-connection timeouts
    (normal, high latency, conservative, aggressive), SYN flood protection.
  - Packet normalisation: random IP ID, clearing the don't-fragment bit.
  - **NAT reflection**: local devices reach a port forward through the public address. The redirected traffic
    is still filtered by the rules of the device's own interface.
  - Static source ports for automatic outbound NAT.
  - The defaults keep the generated pf configuration of earlier versions unchanged.

### Changed
- Settings the panel uses on its own (session timeout, sign-in notice, sign-in protection) no longer show the
  "Apply changes" bar, and Discard keeps them.

## 0.12.1 - 2026-11-03

### Fixed
- Clicking Apply could start the same apply twice: the apply bar's periodic refresh redrew an active Apply
  button while the first apply was still running, and the second one ran again right after Keep, asking to keep
  the same changes a second time. The bar now stays busy until the action has finished, and only one apply,
  confirm or rollback can run at a time (panel, console and rollback timer).
- A WAN port forward on a management port (for example 443) no longer blocks saving any configuration. The
  forwarded port is left out of the WAN management rule (pf sends it to the forwarded host anyway) and Admin
  Access shows a notice.

## 0.12.0 - 2026-11-03

### Added
- **System > Settings** with tabs, replacing System > General. More tabs (Firewall & NAT, Logging,
  Notifications, Networking, Tunables) follow in the next releases.
- **General**: hostname, local domain, time zone, and a sign-in notice shown on the sign-in page (for example a
  legal notice).
- **Admin Access**:
  - Web panel port and the HTTP-to-HTTPS redirect, session timeout.
  - Who may manage the firewall: all internal networks (firewall rules decide) or only selected interfaces;
    anti-lockout rule on LAN.
  - Access from WAN (until now only in the console menu), with a list of allowed source addresses.
  - Sign-in protection with adjustable attempts, period and block time, a list of blocked addresses and an
    Unblock button.
  - SSH: on or off, port, password or key-only sign-in, root's authorised public keys.
  - Saving is refused when the new settings would lock out the address you are connected from. nginx and sshd
    check the new settings before Apply; when the panel moves to another port, the apply bar links to the new
    address.
- Console menu 6) **Management access**: shows the current settings, opens or closes WAN access, and resets
  management access to the defaults.

### Changed
- The anti-lockout and WAN management rules follow the configured panel and SSH ports.
- Existing SSH keys of root are taken over by the panel on the first save after the update.

## 0.11.0 - 2026-11-03

### Added
- **Certificates** (System > Certificates): manage the TLS certificate of the web panel.
  - See the active certificate: names, issuer, expiry date with days left, key type and the SHA-256
    fingerprint to compare with the browser.
  - Install your own certificate (for example from a company CA), with intermediate certificates in the same
    file. It is checked before use: the key must match and have no passphrase, the certificate must be valid
    now, and nginx must accept it.
  - Create a new self-signed certificate for the host names and addresses the panel is opened with.
  - The previous certificate is kept and can be restored from the page or with `stratum-cert restore` on the
    console. A new certificate takes effect at once, without Apply and without dropping open connections.
- Alert for administrators when a CA-issued panel certificate expires within 21 days.
- `stratum-cert` command: `show`, `selfsigned`, `install`, `restore`.

## 0.10.0 - 2026-11-03

### Security
- **IPv6 safety baseline**: IPv6 is not supported yet, and now it is guaranteed to stay off - every IPv6 packet
  is dropped before any pass rule (in and out, not logged), IPv6 stays disabled on all interfaces and is never
  forwarded. An ISP that starts offering IPv6 can no longer open a path around the IPv4 rules.

### Added
- IPv6 design and release plan (`docs/ipv6.md`): WAN IPv6 with DHCPv6 prefix delegation first, then IPv6 for
  internal networks and firewall rules, services, and VPNs.

## 0.9.1 - 2026-11-03

### Changed
- When an Apply fails, the apply bar now says why: each failed check with its message (for example a pf syntax
  error), with a link to the full output under System Logs > Configuration. Failures are also written to the
  system log.
- `stratum-update run` on an up-to-date system reports "nothing to install" instead of an error.

## 0.9.0 - 2026-11-03

### Added
- **IP blocklists** (Firewall > Blocklists > IP): block known-bad addresses with pf.
  - Catalogue of 63 maintained IPv4 feeds derived from pfBlockerNG (PRI1-PRI5, Scanners, TOR, Mail, DoH, VPN,
    Proxy and more); Spamhaus DROP, Abuse.ch Feodo Tracker and Emerging Threats are recommended and preselected.
  - Direction: incoming from the internet, outgoing from local networks, or both. Incoming connections are
    dropped; outgoing ones are rejected so devices fail fast.
  - Own allow and block lists and custom list URLs. An allowed address inside a blocked network stays reachable.
  - Hourly updates without Apply (the pf table is replaced live), live progress bar and update log, blocked packet
    counters, and "Check an address" to see which list contains an IP.
  - Safety: private and reserved ranges and networks larger than /8 are never blocked, whatever a list contains;
    the firewall's DNS, update and package servers are always allowed.
- **Installation media in two variants**: `stratum-fw-v0.9.0-vga.iso` (monitor and keyboard) and
  `stratum-fw-v0.9.0-serial.iso` (serial console, 115200 8N1). Both are hybrid images for CD and USB sticks, and
  the installed system keeps the console of the media it was installed from.

## 0.8.0 - 2026-11-03

### Added
- **WireGuard** (VPN > WireGuard): remote access with WireGuard, built into FreeBSD - no extra packages.
  - Server settings: port, listening WAN, tunnel network, MTU, external address (detected automatically).
  - Choose exactly which LANs and VLANs peers may reach, plus extra networks; optional full tunnel and
    peer-to-peer traffic.
  - Peers (one per device) with key pairs generated on the firewall and preshared keys: the configuration is
    shown as a QR code for the WireGuard app or downloaded as a `.conf` file. Devices with their own keys are
    supported too.
  - Live status per peer: connected, endpoint, last handshake, received and sent data.
  - Adding or removing a peer does not disconnect the others.
- Private keys are kept outside the configuration file (root-only files); peer configurations are shown to
  administrators only.

## 0.7.3 - 2026-11-02

### Added
- **OpenVPN advanced settings**: UDP or TCP, listening WAN, which LANs and VLANs VPN clients may reach (per
  interface) and extra networks, client-to-client traffic, several devices per user, maximum connections, DNS
  servers and domains for clients, data ciphers, authentication digest, minimum TLS version, key renegotiation,
  keepalive, MTU/MSS, log level, and certificate-only login.
- **Fixed VPN address per user** (System > Users).
- The panel tells you when connection settings change and the users' profiles must be downloaded again.

### Changed
- VPN access checkboxes on the OpenVPN page take effect immediately; the Save button sits under the settings.

## 0.7.2 - 2026-11-01

### Changed
- System > Users: OpenVPN access shown in its own VPN column.

## 0.7.1 - 2026-11-01

### Added
- **VPN-only accounts**: users with OpenVPN access but no web panel sign-in, managed on System > Users.
- Users list: last VPN login and failed VPN password attempts; download the `.ovpn` profile from the list.

### Changed
- Removing VPN access, disabling or deleting a user revokes the user's certificate immediately.
- OpenVPN profiles no longer use the deprecated `persist-key` option (OpenVPN 2.7).

## 0.7.0 - 2026-11-01

### Added
- **OpenVPN remote access** (VPN > OpenVPN).
  - Built-in certificate authority (elliptic-curve keys, revocation list, tls-crypt).
  - Login with the user's certificate and password; the certificate must belong to the same user.
  - Per-user `.ovpn` profiles with everything embedded (administrators only), certificate revocation, list of
    connected clients.
  - Firewall and NAT rules and DNS for VPN clients are created automatically.

## 0.6.13 - 0.6.19 - 2026-10-31

### Added
- **Unbound DNS resolver** (Services > DNS): validating resolver with DNSSEC, forwarder or full-recursion mode;
  DHCP client names keep resolving. dnsmasq stays available and the switch between them is safe in both
  directions.
- **DNS blocklists** (Firewall > Blocklists > DNSBL), pfBlockerNG-style: catalogue derived from pfBlockerNG plus
  the HaGeZi lists, recommended defaults, own allow and block lists, custom lists, "Check a domain", nightly
  updates, and an update screen with a percentage bar, current step and live log.
- **Dashboard**: update badge next to the version, live uptime, CPU temperature, PPPoE session address and a
  traffic chart for the last hour.

### Fixed
- DNS blocklists: links in list comments are no longer treated as entries (popular sites such as github.com
  were blocked by some lists); list sources, the update server and shared hosting platforms are never blocked.
- Applying the configuration with DNS blocklists enabled failed on 0.6.15.
- The DNSSEC root trust anchor is created before the Unbound configuration is checked.

## 0.6.6 - 0.6.12 - 2026-10-31

### Added
- **Offline updates**: download a signed update file (`.sfu`) and upload it on System > Update - signature and
  checksum verification with a progress bar, then the same installation steps as an online update.
- The newest 5 boot environments are kept after every update; older ones are removed automatically.

### Fixed
- Booting an earlier boot environment works (installer and updater set the correct ZFS properties; existing
  installations are repaired automatically).
- Fresh installations report their version correctly (package database schema), so updates are offered.
- The online check fails fast without internet, and an interrupted package download can no longer hang the
  update.

## 0.6.1 - 0.6.5 - 2026-10-31

### Added
- Update progress: percentage bar, step checklist with times, in-progress banner, and a "restarting" page while
  the panel restarts.
- System alerts (IP forwarding off, update available) and an own account page with password change.

### Fixed
- IP forwarding always follows the configuration after apply, rollback and service starts.
- The web panel starts again by itself after an update.

## 0.6.0 - 2026-10-31

### Added
- **Users and roles** (System > Users): several accounts, administrator / operator / read-only roles, enable and
  disable, last login and failed attempts; sessions end when a password changes or an account is disabled.
- **General settings** (System > General): hostname, local domain, idle session timeout.
- **Light theme** and follow-the-system mode, chosen per user.
- **Backup and restore** (System > Backup): download the configuration (optionally with users), verified restore
  as pending changes, configuration history with differences.
- **Signed software updates** (System > Update) from update.stratumfw.com: signature-checked repository, a backup
  and a new ZFS boot environment before every update, live progress, rollback to the previous boot environment,
  daily update check.
- Branded boot menu.

## 0.5.0 - 2026-10-30

### Added
- **Firewall Log**: live view with filters and rule names.
- **System Logs**: system, DHCP/DNS, PPPoE, NTP, authentication, panel and configuration logs.
- **Ping, Traceroute and DNS lookup**, and the **pf state table** with the option to kill states.
- **Traffic Graphs** for every interface (last hour, 24 hours, 30 days).

### Changed
- Broadcast and multicast noise is blocked without filling the log (logging can be turned on).

## 0.4.0 - 2026-10-30

### Added
- **DHCP Server**: settings per interface, static mappings, active leases with "make static".
- **DNS Resolver**: local domain, upstream servers, host and domain overrides.
- **NTP**: time servers, time zone, optional time service for internal networks.
- Time zone question in the console setup wizard.

## 0.3.0 - 2026-10-30

### Added
- **Interface assignments**: map ports to WAN, LAN and additional (OPT) interfaces; OPT interfaces can be WAN or
  LAN type.
- Interface settings: static, DHCP or none, gateway, MTU.
- **PPPoE** on every WAN-type interface (the password is never shown again).
- **VLANs** (802.1Q), assignable as WAN or LAN.

### Changed
- An interface's description is shown as its name everywhere, with the role below it.

## 0.2.0 - 2026-10-30

### Added
- **Firewall rules** per interface with system rules shown, hit counters, drag-and-drop order, on/off switch.
- **Aliases** for hosts, networks and ports.
- **NAT**: port forwards (with automatic pass rules and hit counters) and outbound NAT modes with manual rules.
- Anti-lockout rule, bogon and private network blocking on WAN.
- **Safe apply**: every change is applied with an automatic rollback unless it is confirmed in time.

## 0.1.1 - 2026-10-30

### Changed
- Management access from WAN is closed by default (can be opened in the setup wizard or console menu).
- Overlapping interface networks are refused.

### Fixed
- Console selection on UEFI systems; serial console with both UEFI and BIOS.

## 0.1.0 - 2026-10-29

First release.

- FreeBSD-based firewall with a web panel (HTTPS) and a dashboard.
- One central configuration file, applied with automatic rollback.
- Console menu and first-boot setup wizard.
- Installer ISO: GPT for BIOS and UEFI, ZFS, fully offline installation.
