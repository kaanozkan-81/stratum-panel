# Changelog

All notable changes to Stratum FW are listed here, newest first. Stratum FW updates itself from the signed
update server (System > Update) or from an offline update file (`.sfu`); every update creates a ZFS boot
environment, so the previous version can be booted again at any time.

## 0.27.1 - 2026-11-07

### Added
- Import from OPNsense, "Also import OpenVPN": the OpenVPN server is taken over completely, so the profiles
  already on the users' computers connect unchanged. Tested with a real connection using an OPNsense-style
  profile.
  - What is taken over: the certificate authority with its key, the server certificate, the tls-crypt or
    tls-auth key, every user's certificate, and the VPN users with their OPNsense passwords.
  - VPN users become VPN-only accounts.
  - The settings are carried over too: port, protocol, tunnel network, ciphers, digest, DNS, full tunnel and
    block-outside-dns.
  - The earlier OpenVPN certificates of this firewall are kept in a separate folder.
  - A user who already exists here keeps the password set here.
- OpenVPN users can sign in with password hashes from other systems: bcrypt as PHP writes it (`$2y$`) and
  argon2id. An argon2id password is stored as bcrypt at the first sign-in.
- OpenVPN, several addresses for clients: new profiles get one `remote` line per address, tried in order.
- OpenVPN, Windows clients can be limited to the VPN's DNS servers (`block-outside-dns`).
- OpenVPN, the "TLS client" check of user certificates can be switched off for certificates made by other
  systems.

### Fixed
- OpenVPN with two WANs: a client connecting to the second WAN's address got its answers from the first WAN and
  could not connect. The server now answers from the address the client used (`multihome`), and pf sends the
  answers back through the WAN they came in on.
- OpenVPN profiles check the server's real certificate name instead of a fixed one, which matters with a server
  certificate taken over from another system.

## 0.27.0 - 2026-11-07

### Added
- Interfaces > Virtual IPs: extra addresses on an interface, for example more public addresses of a WAN block
  (/29).
  - A port forward can choose a virtual IP as its destination address, so each public address can forward to
    a different server. NAT reflection follows it.
  - Outbound NAT can translate to a virtual IP.
  - Inside the interface's own network an address is added as /32, as FreeBSD needs.
- Interfaces > Routes: static routes to networks behind another router, through a gateway on a directly
  connected network.
  - Networks reached through a router on an internal interface are NATed to the internet automatically, like
    the interface networks.
- Virtual IPs and routes are not written to rc.conf. `stratum-netextra` keeps the system in line with the
  applied list: it adds what is missing and removes only what it added itself.
  - It runs at boot and after every Apply and rollback, also after interface and routing restarts, which drop
    aliases and routes.
  - Each entry shows whether it is active on the firewall.
- Import from OPNsense: IP alias virtual IPs, static routes (gateways resolved by name) and port forwards to a
  virtual IP are carried over. CARP virtual IPs are listed as not supported.

## 0.26.1 - 2026-11-07

### Fixed
- Host name and country aliases: the update started by Apply or "Update now" could be skipped without a trace
  when the 5-minute host name update was running at that moment, so a new country alias stayed empty until the
  next daily run. Those updates now wait for the running one to finish. Only the 5-minute run still skips when
  another update is busy.

## 0.26.0 - 2026-11-07

### Added
- Firewall > Aliases, Host names: an alias of host names such as `update.example.com`, which may also hold
  addresses and networks.
  - The firewall resolves the names every 5 minutes through its own DNS, so it sees the same addresses as the
    clients.
  - An address stays in the alias for an hour after it was last seen, because CDNs rotate their addresses.
  - A name that cannot be resolved keeps its last addresses, and the page shows it.
- Firewall > Aliases, Countries: all address blocks of the chosen countries, picked from a searchable list.
  Typical use: "only Türkiye may reach this port forward" or "block these countries".
  - The data comes from the five regional internet registries (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC). It is
    free and needs no licence key.
  - It is downloaded weekly. A failed download keeps the previous data.
- Both alias types are pf tables loaded from a file. Every pf reload reads the last addresses, and updates
  replace the table while pf runs, without Apply.
- The alias list shows how many addresses each of these aliases holds and when it was last updated. The
  "Update now" button refreshes them at once.
- Import from OPNsense: aliases that contain host names become host name aliases, and GeoIP aliases become
  country aliases. They are no longer imported empty.

### Fixed
- The alias page tabs no longer overflow on phones.

## 0.25.1 - 2026-11-07

### Added
- System > Power:
  - Restart and power off, with a confirmation. After a restart the page reconnects by itself.
  - Reset to factory defaults. The reset uses the ports in use now, so a firewall far away comes back
    reachable: WAN by DHCP, LAN 192.168.1.1/24 with DHCP, panel only from the internal networks.
  - Reset options: keep the panel users or start over with a new "admin" password; erase certificates, keys
    and secrets; erase logs and statistics.
  - The reset is confirmed by typing the host name. It is applied without the rollback timer and the firewall
    restarts.
  - Administrators only; every action is logged.
- Diagnostics > ARP Table:
  - Every address the firewall knows, with MAC, interface, expiry and name (from DHCP reservations, leases and
    DNS overrides).
  - Private (random) MAC addresses of phones and laptops are marked.
  - An entry can be deleted.
- Wake-on-LAN, on the ARP Table page: wake a device by MAC address, or with one click from the devices that have
  a DHCP reservation. Operators may use it.
- Diagnostics > Packet Capture: capture one interface into a `.pcap` file for Wireshark.
  - The filter is built from fields (protocol, host or network, port), never free text.
  - Limits on duration, size and packets; one capture at a time.
  - The administrator's own panel and SSH traffic is left out by default.
  - The file is kept for 24 hours at most, in a root-only folder.
  - Administrators only; start, stop and download are logged.

### Fixed
- The search boxes of the States and ARP Table pages had no styling.

## 0.25.0 - 2026-11-07

### Added
- System > Backup > Import from OPNsense: an OPNsense `config.xml` becomes the pending configuration. The import
  carries over interfaces, VLANs, gateways and the default gateway, interface groups, aliases (nested aliases
  resolved), firewall rules (current and older rule format), port forwards, outbound NAT, DHCP ranges and
  reservations (dnsmasq and ISC dhcpd), DNS host and domain overrides, bandwidth limits, host name, domain,
  time zone and DNS and time servers.
- Before anything is saved, the import shows a preview:
  - the network ports of the OPNsense box are assigned to this system's ports, and any port can be left out;
  - a report lists what was imported, what changed on the way and what could not be imported, with the reason.
- Port forwards keep their access limits. In OPNsense a port forward is often allowed by separate WAN rules. In
  Stratum a port forward passes its own traffic, so its source is taken from those WAN rules, and a combined
  alias is created when several rules allow it. A forward that no rule allowed is imported switched off and
  never opened to everyone.
- Aliases that cannot be carried over (URL tables, host names) are imported empty, so block rules that use them
  block nothing and pass rules that use them allow nothing. They are listed in the report.
- The import warns when the LAN address changes, and when an imported network contains this firewall's current
  WAN address (applying would cut the firewall off).
- The file is only read. It is never stored, and nothing secret appears in the report. Users, certificates,
  OpenVPN, IPsec, WireGuard and plugins are listed as not imported. The import is administrator-only and
  logged.

### Fixed
- Form pages with wide tables no longer scroll sideways on phones.

## 0.24.4 - 2026-11-07

### Added
- Intrusion Detection: Watch and Block can now be set per interface, as in pfSense. For example, the WAN can
  only be watched while the local networks block. Mixing the two runs two Suricata engines: one on netmap for
  the blocking interfaces and one reading copies (pcap) for the watch-only interfaces. Suricata allows one
  capture method per process. Both engines load the same rules, and each is supervised and restarted on its
  own. Alerts and statistics of both are shown together, and log rotation and the WAN address update cover
  both.
- With two engines the rules are loaded twice, so memory use is about twice as high. Each engine gets smaller
  memory limits, and the settings page says so. Apply checks both configurations with Suricata before using
  them.

### Fixed
- AI assistant (MCP): the intrusion detection tool always reported "detection only". It now names the
  blocking interfaces and categories.

## 0.24.3 - 2026-11-07

### Fixed
- Intrusion Detection: changes to the rule categories (on, off, Block) did not reach a running Suricata
  until it restarted. The live rule reload sent signal 12, which is SIGUSR2 on Linux but SIGSYS on FreeBSD.
  It now uses SIGUSR2.
- Intrusion Detection: Block on some interfaces together with Watch on others is refused with a clear
  message. Suricata does not allow blocking and watch-only ports in one netmap process, so it failed to
  start and nothing was inspected while the traffic went on.
- Dashboard: an interface without a cable showed as Up; it now shows No cable.

### Added
- Intrusion Detection: the ET Open "Policy" category (software, tools and services a network may not
  allow), off by default.

## 0.24.2 - 2026-11-06

### Fixed
- Intrusion Detection, blocking mode (IPS): Suricata dropped every connection it had not seen start. These
  are connections open before it started, and long-lived connections that sat idle longer than its flow
  timeout, such as the push channels phones keep open. Phones on a blocking network lost their connection
  and dropped off Wi-Fi. Suricata now picks such connections up (midstream), and on any exception
  (`exception-policy: ignore`) it lets the traffic through instead of dropping the flow. Only matches of
  blocking rules are dropped.

## 0.24.1 - 2026-11-05

### Fixed
- Web Filter: the category lists were not downloaded after the first Apply, so the policies blocked nothing
  until the next scheduled update. The download now follows the saved configuration, as the DNS blocklists
  do, and Unbound only reloads the zones it has loaded.

## 0.24.0 - 2026-11-05

### Added
- **Web Filter** (Firewall > Web Filter) blocks site categories through the firewall's DNS resolver (Unbound
  RPZ), with different rules per network.
  - **Policies:** a policy gives one or more networks a set of blocked categories. VPN client networks can be
    policy networks too, and each network belongs to one policy.
  - **Categories:** 55 categories in groups (adult content, security threats, ways around the filter, social
    networks, entertainment, shopping and money, downloads and more), from the UT1 blacklists of Université
    Toulouse Capitole (CC BY-SA 4.0, updated daily) and the Block List Project. Adult content comes as a
    compact list and a very large full list, and the policy page estimates the resolver memory the chosen
    categories need.
  - **Safe Search:** each policy can force safe results on Google (also google.com.tr and other country
    domains), Bing and DuckDuckGo, and restricted mode on YouTube.
  - **Exceptions:** listed sites are never blocked by the web filter and take effect at once, with no
    Apply. The DNS blocklists still apply to them.
  - **Check a site:** shows which categories contain a name and which policies block it.
  - **Blocked report:** blocks per category, site and device for today, 7 or 30 days. It needs Web Activity,
    whose collector now also counts web filter and DNS blocklist blocks. Only administrators see the report,
    and viewing it is logged.
  - **Updates:** category lists update on a schedule (daily by default) and on demand, and a failed download
    keeps the previous list.

## 0.23.0 - 2026-11-05

### Changed
- **New dashboard:** every panel can be moved and resized. Customize lets you drag a panel by its title and resize it from its edges or corner on a 12-column grid. Each user has their own layout, saved at once with no Apply, and Reset layout brings back the default.
- **Dashboard > Add panels** (a full page) lists every panel, to add or remove. Panels:
  - System, WAN, CPU, Memory, Disk, Temperature, Connections, Blocked
  - Traffic, Protection, Interfaces, Services, DHCP, VPN connections
  - Top blocked sources, Top blocked ports, Recent changes
  - New: Intrusion detection, Gateways (latency, loss, failover), Bandwidth limits (limit and current rate), Backup and Web Activity. Backup and Web Activity are for administrators only, and viewing Web Activity on the dashboard is logged.
- Panel contents adapt to the panel size: long lists such as VPN connections scroll inside their panel, and the traffic graph fills its panel.
- **Notifications at the top right of every page:** a bell with the unread count, the latest events in a drop-down, and a short pop-up when a new event arrives. They replace the Alerts panel.
- **Update check icon** on the dashboard: it spins while checking, a click checks now, and it shows the result.
- The DHCP and VPN panels are separate. On phones the dashboard shows one column.
- gridstack 12.6.0 (MIT) ships with the panel. Nothing is loaded from the internet.

## 0.22.0 - 2026-11-05

### Added
- **Encrypted backups:** System > Backup can encrypt the downloaded backup with a password (AES-256-GCM, key from scrypt). An encrypted backup (.stbk) can also carry the **certificates and secrets** kept outside the configuration: OpenVPN CA and user certificates, WireGuard keys, notification secrets, the SNMP community, MCP tokens and the panel certificate. Restoring it on a new firewall brings back working VPN profiles.
- Restore asks for the password of an encrypted file and can put the certificates and secrets back. Files are only written to their known places.
- **Automatic backup to a server:** an encrypted backup is uploaded on a schedule over SFTP (NAS, Linux or Windows OpenSSH server).
  - The firewall uses its own SSH key, and the server's host key is recorded at the first connection.
  - Only the newest N backups of this firewall are kept on the server.
  - Test connection and Back up now buttons, and a last-backup status.
  - A failed backup is retried at the next hour and reported through Notifications.
  - It takes effect without Apply. The password stays in a root-only file and is never shown again.
- The stratum-fw package now depends on py312-cryptography.

## 0.21.1 - 2026-11-05

### Changed
- Intrusion Detection: each interface is now **Off**, **Watch** or **Block** on its own, as in pfSense. For example, the WAN can only raise alerts while the local networks block.
- With at least one blocking interface, one Suricata process inspects all watched ports through netmap, so the rules are loaded only once: blocking ports in IPS mode, watch-only ports in tap mode (every packet passes). VLANs on the same port share its mode.
- The alert list marks a packet as Blocked only on a blocking interface, and names netmap ports after their interfaces.
- Settings saved with 0.21.0 carry over: "Detect and block" becomes Block on every watched interface.

## 0.21.0 - 2026-11-05

### Added
- **Inline blocking (IPS)** in Services > Intrusion Detection: the mode "Detect and block" puts Suricata in the path of the packets (netmap with the host stack, as in OPNsense). The rules of the categories marked **Block** drop what they match; all other categories still only alert. Blocked packets show a "Blocked" badge in the alert list.
- Blocking categories take effect at once without a restart. Switching the mode needs Apply, with the usual automatic rollback if the firewall becomes unreachable.
- In blocking mode, VLAN and PPPoE interfaces are inspected on their physical port, and hardware offloading (TSO, LRO, checksums) is switched off. If Suricata stops, the ports fall back to normal forwarding (fail open).
- Apply checks that netmap is available before anything changes.

## 0.20.3 - 2026-11-05

### Changed
- Web Activity: a click anywhere on a device row opens the sites that device used, and a click on a site row opens the devices that used it. Ctrl / Cmd + click opens the page in a new tab.

## 0.20.2 - 2026-11-05

### Changed
- Web Activity names VPN clients: an OpenVPN address shows the user ("OpenVPN: name") and a WireGuard address the peer ("WireGuard: name"). Both are kept in the DHCP history too, so a VPN address used by different users over time stays apart.
- The device count sits next to the title.

## 0.20.1 - 2026-11-05

### Fixed
- Web Activity recorded nothing: syslogd writes only to log files that already exist, so the DNS query log was never started. Apply and the collector now create the file (root only) before syslogd reloads.

## 0.20.0 - 2026-11-05

### Added
- **Web Activity** (Diagnostics > Web Activity) shows which device looked up which sites, from the DNS queries the firewall's Unbound resolver answers. Each device, day and name is kept with a count and the first and last time.
- The Devices tab lists each address with its host name and MAC address, and opens a device page with the sites it used. The Sites tab lists each site with the devices that used it. Both tabs filter by period (today up to a year), network and search text.
- **DHCP history** records which device (MAC address, host name) held each address and when. It reads the DHCP leases and the ARP table, so devices with a fixed address are included. The history can be exported as CSV.
- **Send all DNS to the firewall** (optional): pf redirects DNS from the internal networks to the firewall, including queries aimed at 8.8.8.8 and the like. It also blocks DNS over TLS (port 853) and tells Firefox not to use its own DNS over HTTPS.
- Records are kept for 1 to 730 days (30 by default), in a root-only database on the firewall. The pages are open to administrators only, and every look at the data is written to the system log.
- The stratum-fw package now depends on py312-sqlite3.

## 0.19.0 - 2026-11-05

### Added
- **SNMP agent** (System > Settings > SNMP) for monitoring systems such as LibreNMS, Zabbix, PRTG, Observium or Cacti: SNMP v1 / v2c, read-only, with the interfaces and their 64-bit traffic counters (IF-MIB), CPU, memory, disks and processes (HOST-RESOURCES) and pf statistics. It uses FreeBSD's own bsnmpd.
- It answers only on the addresses of the chosen internal interfaces, never on a WAN, and pf lets queries in only from the allowed addresses. The community is stored root-only and never shown again; nothing can be changed over SNMP.
- The stratum-fw package now depends on FreeBSD-bsnmp, so updating installs the agent.

## 0.18.0 - 2026-11-05

### Added
- **Bandwidth limits** (Firewall > Shaper): a download and an upload limit for each internal network, shared by the whole network (for example 255 Mbit/s for the office VLAN) or for each device on its own (for example 20 Mbit/s per guest phone). Decimal values are allowed; an empty field means no limit in that direction.
- The limits use FreeBSD's dummynet directly from pf (no second firewall). The pipes are loaded before pf at every Apply and by FreeBSD at boot; an Apply that is not kept removes them again.

## 0.17.0 - 2026-11-05

### Added
- **Interface groups** (Interfaces > Groups): a group of interfaces, for example all VLANs or all WANs, gets its own tab on Firewall > Rules. Its rules apply to every member interface and are evaluated before each interface's own rules, as in pfSense and OPNsense. WAN members keep their reply-to.
- Groups can be renamed (their rules move with them) and deleted once they have no rules. When an interface is removed, it simply leaves its groups.
- The MCP tool firewall_rules lists group rules and the interfaces they apply to.

## 0.16.1 - 2026-11-05

### Added
- **WAN failover** (Interfaces > Gateways, shown with two or more WANs): when the gateway that carries the default route goes down, the default route moves at once to the best gateway that is up (lowest priority number). The preferred gateway takes over again only after it has been online for a set time (60 s by default), so a flapping line does not switch back and forth. The connections of the failed gateway can be closed so they reopen through the new one at once. Every switch is logged and reported.
- With two or more WANs, answers to connections that come in on a WAN (port forwards, management, pass rules) leave through that same WAN (reply-to), whatever the default route is. Static WANs use their gateway, PPPoE WANs their link. Systems with one WAN keep exactly the same firewall rules.

### Fixed
- After the update to 0.16.0 the gateway monitor started only with the next Apply or reboot, because the update tool of the previous version did not know it. The panel now starts it when it is enabled but not running.

## 0.16.0 - 2026-11-05

### Added
- **Gateways** (Interfaces > Gateways): every WAN-type interface has a gateway with live status (online,
  warning, down), latency, packet loss and the last hour as a small graph.
- A new gateway monitor service probes each gateway once per second from the WAN's own address, also when
  nobody has the panel open. A gateway is down when the packet loss or latency over the last 30 seconds
  reaches its limits (20 % and 500 ms by default, set per gateway), or when its interface has no link or
  address; half of a limit shows a warning.
- Per gateway: a description, a monitor address (for providers whose gateway does not answer pings; it is
  always reached through that gateway), the limits, and a priority for the WAN failover that follows in
  0.16.1.
- A gateway that goes down while its link is up, and its recovery, are reported by the notifications.

### Changed
- The dashboard's WAN panel and the MCP tool wan_status now use the gateway monitor (one probe per second
  instead of three every 30 seconds from the panel).

## 0.15.3 - 2026-11-05

### Fixed
- Intrusion detection on a WAN interface raised almost no alerts: the firewall's public address was not part
  of the protected networks (HOME_NET), so traffic from the internet to it did not match most rules. The WAN
  addresses are now included. When a PPPoE or DHCP address changes, the new address is taken over within
  five minutes and Suricata restarts; while a WAN is reconnecting, nothing changes.

## 0.15.2 - 2026-11-05

### Added
- Dashboard: the Protection card shows the intrusion alerts of the last 24 hours (high-severity ones in red)
  and the three most frequent rules, linked to the Alerts page.
- Notifications: a new event for high-severity intrusion alerts, by e-mail or Telegram. Each rule is reported
  at most once every 6 hours, disabled rules never. It can be switched off on System > Settings >
  Notifications like the other events, and the alerts appear in the dashboard's Alerts card.
- MCP: a new tool, ids_alerts, gives AI assistants the intrusion detection state, the last 24 hours in
  numbers, the most frequent rules and the latest alerts, filtered by severity or text.

## 0.15.1 - 2026-11-05

### Fixed
- Intrusion detection could not start on systems installed from the image: Suricata needs the netmap
  library, which the minimal base system did not include. The package now depends on it (FreeBSD-netmap),
  so updating installs it, and new installations include it. The pre-check had stopped the Apply, so no
  system was changed.

## 0.15.0 - 2026-11-05

### Added
- **Intrusion detection** (Services > Intrusion Detection) with Suricata 8 in IDS mode: the traffic of the
  chosen interfaces is compared with the ET Open rules and alerts are raised for malware calling home,
  exploits, scans, phishing, coin miners and more. Nothing is blocked yet; blocking (IPS) follows once the
  alerts have shown which rules fit the network.
- Rule categories in three groups, with a recommended selection (threats on, noisy policy and information
  rules off) and the number of rules in each category.
- Automatic rule updates on a schedule (daily by default), like the blocklists. A new rule set is downloaded
  only when it changed, and it is tested with Suricata before it is used. A failed download or test keeps
  the previous rules.
- Alerts page: newest first, with severity, rule, source, destination and interface, a search and a
  severity filter. A rule that alerts on normal traffic can be disabled with one click and enabled again
  on the Settings tab; the change takes effect at once, without Apply and without a gap in detection.
- Suricata runs supervised and is started again if it stops. Memory limits follow the installed memory.
  Its logs are rotated with the other logs, and failed rule downloads are reported by the notifications.

### Changed
- Opening the MCP address in a web browser now shows a short explanation instead of an empty error page.
- The stratum-fw package now depends on Suricata.

## 0.14.0 - 2026-11-04

### Added
- **MCP server** (Model Context Protocol, System > Settings > MCP): AI assistants such as Claude, ChatGPT,
  Gemini or DeepSeek (through an MCP client) can read the firewall's live state and answer questions like
  "what was blocked in the last hour?" or "which devices are on the guest network?". 14 read-only tools:
  system status, interfaces, WAN status, services, firewall log, blocked-traffic summary, firewall rules,
  NAT rules, DHCP leases, VPN sessions, alerts, configuration changes, blocklists and traffic statistics.
  Nothing can be changed through MCP.
- Access tokens for MCP, one per assistant or computer, optionally limited to given addresses. A token is
  shown once and stored only as a hash; last use, address and number of calls are shown, and a token can be
  revoked at any time. Wrong tokens count as failed sign-ins and block the address.
- Each tool can be switched off, so its data is never sent to an AI provider. Passwords, keys, tokens and
  VPN configurations are never returned.
- The panel certificate can be downloaded for MCP clients that must trust it.

## 0.13.2 - 2026-11-04

### Added
- Dashboard **Alerts**: the latest events (WAN down or up again, new WAN address, blocked sign-ins, failed
  applies, automatic rollbacks, available updates, full disk, high temperature, certificate and blocklist
  problems) with the time and whether each was sent by e-mail or Telegram. Events are now recorded even when
  no notification channel is set up; the last 100 are kept.
- Dashboard **DHCP**: per network, the devices with an active lease, how much of the address pool is in use
  (amber from 75 %, red from 90 %) and the number of static mappings.

## 0.13.1 - 2026-11-04

### Added
- Dashboard **WAN panel**: connection type, gateway, latency and packet loss to the gateway (measured every 30
  seconds, with a curve), how long the connection has been up, today's download and upload, and the live rate;
  latency to the internet (1.1.1.1) in the status strip.
- Dashboard **VPN connections**: every connected OpenVPN user and active WireGuard peer with the address it
  connects from, its VPN address, connection time or last handshake, and the data received and sent.
- Opening the dashboard checks for software updates (at most every 5 minutes), like pfSense, and shows the
  result as soon as it is there.

### Fixed
- Firewall log: on FreeBSD 15 every logged packet was given the name of the wrong rule (often "ipv6-off"),
  because pf now writes rule numbers as "3..1/0". The Firewall Log page, the dashboard and remote syslog
  show the right rule again; entries logged before the update keep their old names.
- Dashboard: the CPU tile no longer opens the traffic graphs; the live traffic under the chart uses the same
  measurement as the interface list.

## 0.13.0 - 2026-11-04

### Changed
- **New dashboard**:
  - Status strip: host name, version and update state, every WAN connection with its address and live
    download / upload, uptime, time of the last configuration change, firewall state.
  - Key figures: CPU with a 5-minute curve, memory, disk, temperature, connections against the state table
    limit, and packets blocked in the last hour with a curve; colours change at warning levels.
  - Traffic of the last hour per interface with average and peak.
  - Protection: IP and DNS blocklists, packets stopped by the IP blocklists, addresses blocked after failed
    sign-ins, OpenVPN users and WireGuard peers online, the rules that blocked most in the last hour.
  - Interfaces with their description as the name, status, link speed, address and live traffic; services
    with a running / stopped summary.
  - Top blocked sources and ports of the last hour, and the latest configuration changes (applied, kept,
    reverted, failed).
  - Works in the dark and light themes and on phones.

## 0.12.6 - 2026-11-04

### Added
- **System > Settings > Networking**: switch off hardware offload (LRO, TSO, checksum) on every physical port -
  set live without restarting the ports and kept after a reboot - with the current state per port; CPU power
  management (adaptive, maximum performance, economy); ARP logging and ARP entry lifetime; IPv6 status.
- **System > Settings > Tunables**: run-time system values (sysctl) that matter on a firewall, with the values
  pfSense uses as a recommendation and the current value of each, plus own run-time tunables. Values are set
  with Apply and kept after a reboot (/etc/sysctl.conf.local); a value set back to default gets the value it
  had before. Values Stratum FW manages itself cannot be changed here.
- All System > Settings tabs are now available.

### Changed
- An existing /etc/sysctl.conf.local is kept as /etc/sysctl.conf.local.stratum-orig; the file is now written
  from Settings > Tunables.

## 0.12.5 - 2026-11-04

### Added
- **Automatic blocklist updates on a schedule** (Firewall > Blocklists, IP and DNSBL): every hour, every 6 or
  12 hours, daily at a chosen hour, weekly on a chosen day, or off. The page shows the next automatic update. A
  missed update (firewall switched off) runs at the next hour, and after a failed update the next hour tries
  again. Schedule changes take effect at once, without Apply. Defaults keep the earlier rhythm (IP lists hourly,
  DNS lists daily at 03:00).

### Fixed
- The update log of the IP blocklists stayed hidden while an update ran (two elements on the page shared the
  same id).

## 0.12.4 - 2026-11-04

### Added
- **System > Settings > Notifications**: messages from the firewall by **Telegram** (bot) and **e-mail**
  (SMTP with STARTTLS or TLS), each with a test button that uses the values on the page.
  - Events, each can be switched off: software update available, applying the configuration failed, changes
    reverted automatically because they were not kept in time, WAN connection down / up again / new address,
    an address blocked after failed sign-ins, panel certificate expiring, IP or DNS blocklist downloads failing,
    disk almost full and CPU temperature high (adjustable thresholds).
  - Failed applies, automatic rollbacks and blocked sign-ins are reported at once; the rest is checked every 5
    minutes. The same problem is repeated only after a pause.
  - The bot token and the mail password are stored on the firewall only (root-only files) and never shown
    again. Notification settings take effect at once, without Apply.

## 0.12.3 - 2026-11-04

### Added
- **System > Settings > Logging**:
  - Firewall log rotation: file size and number of old files kept; current size of the firewall, system, DHCP/DNS
    and sign-in logs and the free space for logs.
  - **Remote syslog**: up to two servers (for example a NAS), each with its own choice of logs: system, sign-ins
    (panel, SSH, VPN), the firewall log (one readable line per packet, tag `filterlog`) and DHCP/DNS. Sent over
    UDP by the system's syslogd; the local logs stay as they are.
  - **Send test message** checks that a server receives syslog before anything is applied.

### Changed
- Rotation of the firewall and DHCP/DNS logs is generated from the settings (the defaults are unchanged).
- Software updates restart the firewall log and traffic collectors, so they run the new version at once.

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
