"""
system_info.py - Arayüz ve servis durumunu canlı olarak okuyan yardımcı fonksiyonlar.
"""
import subprocess
import re
import json
import ipaddress
import os
import csv
import datetime
import time

INTERFACES = []

SERVICES = [
    "systemd-networkd", "nftables", "kea-dhcp4-server", "unbound",
    "suricata", "crowdsec", "crowdsec-firewall-bouncer",
    "networkd-dispatcher", "snmpd", "nfcapd", "softflowd",
    "loki", "promtail", "grafana-server", "stratum-panel",
]


def get_dynamic_vlan_roles():
    """vlan-create ile sonradan olusturulan VLAN'larin rol adlarini okur."""
    roles = {}
    path = "/etc/nftables/vlan-roles.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|", 1)
                if len(parts) == 2:
                    roles[parts[0]] = parts[1]
    return roles


def get_interfaces():
    try:
        raw = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True, timeout=5)
        all_ifaces = json.loads(raw.stdout) if raw.returncode == 0 else []
    except Exception:
        all_ifaces = []

    by_name = {i.get("ifname"): i for i in all_ifaces}

    # sabit listeye ek olarak, canli sistemde bulunan ama listede olmayan
    # (orn. vlan-create ile sonradan eklenen) VLAN'lari da DINAMIK olarak dahil et
    known_names = {e["name"] for e in INTERFACES}
    dynamic_roles = get_dynamic_vlan_roles()
    dynamic_entries = []
    for name in by_name:
        if name in known_names:
            continue
        if re.match(r'^vlan\d+$', name):
            role = dynamic_roles.get(name, f"VLAN {name.replace('vlan', '')}")
            dynamic_entries.append({"name": name, "role": role})
        elif os.path.exists(f"/sys/class/net/{name}/device"):
            # gercek fiziksel NIC - rolünü /etc/nftables/interface-roles.conf'tan oku
            role = "Unused (available)"
            roles_file = "/etc/nftables/interface-roles.conf"
            role_type = "disabled"
            if os.path.exists(roles_file):
                with open(roles_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("|")
                        if len(parts) == 2 and parts[0] == name:
                            role_type = parts[1]
                            break
            if role_type == "lan":
                role = "LAN trunk (802.1Q)"
            elif role_type == "wan":
                role = "WAN — " + name
            elif role_type == "opt":
                role = "OPT — " + name
            dynamic_entries.append({"name": name, "role": role})

    all_entries = INTERFACES + sorted(dynamic_entries, key=lambda e: e["name"])

    def _role_type(name):
        roles_file = "/etc/nftables/interface-roles.conf"
        if os.path.exists(roles_file):
            with open(roles_file) as f:
                for line in f:
                    parts = line.strip().split("|")
                    if len(parts) == 2 and parts[0] == name:
                        return parts[1]
        if name == "lan-trunk":
            return "lan"
        if name.startswith("wan"):
            return "wan"
        if name.startswith("opt"):
            return "opt"
        return "disabled"

    result = []
    for entry in all_entries:
        name = entry["name"]
        iface = by_name.get(name)
        if iface is None:
            result.append({"name": name, "role": entry["role"], "role_type": _role_type(name), "status": "missing", "ip": None})
            continue

        operstate = iface.get("operstate", "UNKNOWN")
        addr_info = iface.get("addr_info", [])
        ipv4 = next((a for a in addr_info if a.get("family") == "inet"), None)
        ip_str = f'{ipv4["local"]}/{ipv4["prefixlen"]}' if ipv4 else None

        if operstate == "UP":
            status = "up"
        elif operstate == "DOWN":
            status = "down"
        else:
            status = "warn"

        result.append({"name": name, "role": entry["role"], "role_type": _role_type(name), "status": status, "ip": ip_str})

    return result


def get_services():
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", *SERVICES],
            capture_output=True, text=True, timeout=5,
        )
        states = proc.stdout.strip().split("\n")
    except Exception:
        states = []

    while len(states) < len(SERVICES):
        states.append("unknown")

    return [{"name": n, "active": (s.strip() == "active")} for n, s in zip(SERVICES, states)]


def get_dns_stats():
    stats = {"queries": None, "cache_hit_rate": None, "avg_response_ms": None, "rpz_domains": 0}

    try:
        proc = subprocess.run(
            ["/usr/sbin/unbound-control", "stats_noreset"],
            capture_output=True, text=True, timeout=5,
        )
        raw = {}
        for line in proc.stdout.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                raw[k] = v

        queries = int(raw.get("total.num.queries", 0))
        hits = int(raw.get("total.num.cachehits", 0))
        misses = int(raw.get("total.num.cachemiss", 0))
        hit_rate = round((hits / (hits + misses) * 100), 1) if (hits + misses) > 0 else 0
        avg_recursion_ms = round(float(raw.get("total.recursion.time.avg", 0)) * 1000, 1)

        stats["queries"] = queries
        stats["cache_hit_rate"] = hit_rate
        stats["avg_response_ms"] = avg_recursion_ms
    except Exception:
        pass

    rpz_dir = "/etc/unbound/rpz"
    rpz_total = 0
    try:
        for fname in os.listdir(rpz_dir):
            fpath = os.path.join(rpz_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    rpz_total += sum(1 for _ in f)
    except Exception:
        pass
    stats["rpz_domains"] = rpz_total

    return stats


def get_threat_stats():
    stats = {
        "crowdsec_bans": 0,
        "crowdsec_decisions": 0,
        "suricata_rules": 0,
        "suricata_alerts_today": 0
    }

    try:
        p1 = subprocess.run(["/usr/sbin/nft", "-j", "list", "set", "ip", "crowdsec", "crowdsec-blacklists"],
                             capture_output=True, text=True, timeout=5)
        if p1.returncode == 0:
            nft_data = json.loads(p1.stdout)
            for item in nft_data.get("nftables", []):
                if "set" in item and item["set"].get("name") == "crowdsec-blacklists":
                    stats["crowdsec_bans"] = len(item["set"].get("elem", []))
                    break
    except Exception:
        pass

    try:
        p2 = subprocess.run(["/usr/bin/cscli", "decisions", "list", "-o", "json"],
                             capture_output=True, text=True, timeout=5)
        if p2.returncode == 0:
            decisions = json.loads(p2.stdout)
            if isinstance(decisions, list):
                stats["crowdsec_decisions"] = len(decisions)
    except Exception:
        pass

    try:
        eve_path = "/var/log/suricata/eve.json"
        today_prefix = f'"timestamp":"{datetime.date.today().isoformat()}'

        file_size = os.path.getsize(eve_path)
        read_size = min(file_size, 2 * 1024 * 1024)

        with open(eve_path, "rb") as f:
            if file_size > read_size:
                f.seek(-read_size, os.SEEK_END)
            chunk = f.read().decode("utf-8", errors="ignore")

        alerts_today = 0
        last_stats_line = None
        for line in chunk.splitlines():
            if '"event_type":"alert"' in line and today_prefix in line:
                alerts_today += 1
            if '"event_type":"stats"' in line:
                last_stats_line = line

        stats["suricata_alerts_today"] = alerts_today

        if last_stats_line:
            stats_json = json.loads(last_stats_line)
            engines = stats_json.get("stats", {}).get("detect", {}).get("engines", [{}])
            stats["suricata_rules"] = engines[0].get("rules_loaded", 0) if engines else 0
    except Exception:
        pass

    return stats


def get_webfilter_stats():
    stats = {"categories": [], "total_domains": 0}

    sources_path = "/etc/unbound/rpz-sources.conf"
    rpz_dir = "/etc/unbound/rpz"

    categories = []
    try:
        with open(sources_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if parts:
                    categories.append(parts[0])
    except Exception:
        pass

    total = 0
    result = []
    for cat in categories:
        rpz_file = os.path.join(rpz_dir, f"{cat}.rpz")
        count = 0
        try:
            with open(rpz_file, "rb") as f:
                count = sum(1 for _ in f)
        except Exception:
            pass
        result.append({"name": cat, "domains": count})
        total += count

    stats["categories"] = result
    stats["total_domains"] = total
    return stats


_last_cpu_reading = {"idle": None, "total": None}


def get_system_stats():
    stats = {"cpu_percent": None, "ram_percent": None, "disk_percent": None, "uptime_seconds": None}

    # CPU: iki ardisik /api/status cagrisi arasindaki farktan hesaplanir
    # (blocking time.sleep() kullanmiyoruz - async event loop'u kilitlemez)
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        values = list(map(int, line.split()[1:]))
        idle = values[3] + values[4]
        total = sum(values)

        if _last_cpu_reading["idle"] is not None:
            idle_delta = idle - _last_cpu_reading["idle"]
            total_delta = total - _last_cpu_reading["total"]
            if total_delta > 0:
                stats["cpu_percent"] = round((1 - idle_delta / total_delta) * 100, 1)

        _last_cpu_reading["idle"] = idle
        _last_cpu_reading["total"] = total
    except Exception:
        pass

    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].strip().split()[0])
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        if total > 0:
            stats["ram_percent"] = round((1 - available / total) * 100, 1)
    except Exception:
        pass

    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        free = st.f_bfree * st.f_frsize
        if total > 0:
            stats["disk_percent"] = round((1 - free / total) * 100, 1)
    except Exception:
        pass

    try:
        with open("/proc/uptime") as f:
            stats["uptime_seconds"] = int(float(f.readline().split()[0]))
    except Exception:
        pass

    return stats


_traffic_cache = {"data": None, "computed_at": 0}


def get_traffic_stats():
    now = time.time()
    if _traffic_cache["data"] is not None and (now - _traffic_cache["computed_at"]) < 300:
        return _traffic_cache["data"]

    result = {"buckets": [], "total_mb_24h": 0}
    nfdump_dir = "/var/cache/nfdump"

    try:
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        hourly_bytes = {}

        for fname in sorted(os.listdir(nfdump_dir)):
            if not fname.startswith("nfcapd."):
                continue
            ts_str = fname[len("nfcapd."):]
            if len(ts_str) < 12:
                continue
            try:
                file_dt = datetime.datetime.strptime(ts_str[:12], "%Y%m%d%H%M")
            except ValueError:
                continue
            if file_dt < cutoff:
                continue

            hour_key = ts_str[:10]

            proc = subprocess.run(
                ["/usr/bin/nfdump", "-r", os.path.join(nfdump_dir, fname), "-I"],
                capture_output=True, text=True, timeout=5,
            )
            file_bytes = 0
            for line in proc.stdout.splitlines():
                if line.startswith("Bytes:"):
                    try:
                        file_bytes = int(line.split(":")[1].strip())
                    except ValueError:
                        file_bytes = 0
                    break

            hourly_bytes[hour_key] = hourly_bytes.get(hour_key, 0) + file_bytes

        buckets = []
        total = 0
        for hour_key in sorted(hourly_bytes.keys()):
            mb = round(hourly_bytes[hour_key] / (1024 * 1024), 3)
            hour_label = datetime.datetime.strptime(hour_key, "%Y%m%d%H").strftime("%H:00")
            buckets.append({"hour": hour_label, "mb": mb})
            total += hourly_bytes[hour_key]

        result["buckets"] = buckets
        result["total_mb_24h"] = round(total / (1024 * 1024), 2)
    except Exception:
        pass

    _traffic_cache["data"] = result
    _traffic_cache["computed_at"] = now
    return result


def get_interface_details():
    """get_interfaces()'in genisletilmis hali - VLAN ID, DHCP araligi, WAN modu dahil."""
    base = get_interfaces()

    # Kea config'ten interface -> DHCP pool eslemesi cikar
    dhcp_pools = {}
    try:
        with open("/etc/kea/kea-dhcp4.conf") as f:
            kea_conf = json.load(f)
        for subnet in kea_conf.get("Dhcp4", {}).get("subnet4", []):
            iface = subnet.get("interface")
            pools = subnet.get("pools", [])
            if iface and pools:
                dhcp_pools[iface] = pools[0].get("pool", "")
    except Exception:
        pass

    result = []
    for iface in base:
        name = iface["name"]
        vlan_id = None
        if name.startswith("vlan"):
            try:
                vlan_id = int(name.replace("vlan", ""))
            except ValueError:
                pass

        wan_mode = None
        if name in ("wan1", "wan2"):
            wan_mode = "pppoe" if os.path.exists(f"/etc/ppp/peers/{name}") else "dhcp"

        result.append({
            **iface,
            "vlan_id": vlan_id,
            "dhcp_pool": dhcp_pools.get(name),
            "wan_mode": wan_mode,
        })

    # ONEMLI: UI'da "up" olan arayuzler USTTE, "down"/"missing" olanlar
    # ALTTA gorunsun diye durum bazli siralama. sorted() STABIL oldugu
    # icin, AYNI durumdaki arayuzlerin kendi ARALARINDAKI mevcut sirasi
    # (orn. keşfedilme sirasi) KORUNUR - sadece gruplar arasi siralama
    # degisir.
    status_order = {"up": 0, "warn": 1, "down": 2, "missing": 3}
    result.sort(key=lambda i: status_order.get(i.get("status", "missing"), 99))

    return result


WAN_ROLE_IFACES = ("enp5s0", "wan1", "wan2")


def _current_role_of(name):
    """interface-roles.conf'a gore GUNCEL rolu doner (wan/lan/opt/disabled).
    Kayitli degilse isim desenine gore tahmin eder (VLAN'lar icin)."""
    roles_file = "/etc/nftables/interface-roles.conf"
    if os.path.exists(roles_file):
        with open(roles_file) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 2 and parts[0] == name:
                    return parts[1]
    if re.match(r'^vlan\d+$', name):
        return "lan"
    return "disabled"


def get_lan_ifaces_with_subnets():
    """WAN OLMAYAN (yani LAN/OPT/VLAN gibi dogrudan yerel erisim noktalari)
    tum arayuzleri, IP/CIDR bilgisiyle birlikte doner. Rol GUNCEL
    interface-roles.conf'tan okunur - sabit isim listesi KULLANILMAZ,
    boylece arayuzler yeniden adlandirilsa bile dogru calisir."""
    result = []
    for i in get_interface_details():
        if not i.get("ip"):
            continue
        role = _current_role_of(i["name"])
        if role in ("lan", "opt"):
            result.append({"name": i["name"], "role": i["role"], "cidr": i["ip"]})
    return result


ALL_WEBFILTER_CATEGORIES = ["ads", "social", "adult", "warez", "vpn_p2p", "violence", "gambling", "safesearch", "youtube_restricted"]


def get_webfilter_policies():
    """access-tags.conf'tan her ag/host icin hangi kategorilerin aktif oldugunu okur."""
    policies = []
    path = "/etc/unbound/unbound.conf.d/access-tags.conf"

    # CIDR -> VLAN adi/rolu eslemesi icin arayuz bilgisini al
    iface_by_cidr = {}
    for i in get_interface_details():
        if i.get("ip"):
            try:
                net = ipaddress.ip_network(i["ip"], strict=False)
                iface_by_cidr[str(net)] = f'{i["name"]} — {i["role"]}'
            except ValueError:
                pass

    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("access-control-tag:"):
                    continue
                rest = line[len("access-control-tag:"):].strip()
                parts = rest.split('"')
                cidr = parts[0].strip()
                tags_str = parts[1] if len(parts) > 1 else ""
                categories = tags_str.split() if tags_str else []

                label = iface_by_cidr.get(cidr)
                if not label:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        label = iface_by_cidr.get(str(net))
                        if not label:
                            label = "Custom host override" if net.num_addresses == 1 else "Unknown network"
                    except ValueError:
                        label = "Unknown"

                policies.append({"cidr": cidr, "label": label, "categories": categories})
    except FileNotFoundError:
        pass

    return policies


def get_live_chain_text(chain_name):
    """Verilen zincirin CANLI nftables cikitisini duz metin olarak doner (yorumlanmaz,
    oldugu gibi gosterilir - sahte bir parser ile yanlis temsil riskini onlemek icin)."""
    try:
        proc = subprocess.run(
            ["/usr/sbin/nft", "list", "chain", "ip", "fw", chain_name],
            capture_output=True, text=True, timeout=5,
        )
        return proc.stdout if proc.returncode == 0 else f"(okunamadi: {proc.stderr.strip()})"
    except Exception as e:
        return f"(hata: {e})"


def get_ip_blocklist():
    try:
        proc = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "set", "ip", "fw", "alias_blocklist"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout)
        for item in data.get("nftables", []):
            if "set" in item and item["set"].get("name") == "alias_blocklist":
                elems = item["set"].get("elem", [])
                return [e if isinstance(e, str) else e.get("val", str(e)) for e in elems]
    except Exception:
        pass
    return []


def get_mac_blocklist():
    try:
        proc = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "set", "ip", "fw", "alias_mac_block"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout)
        for item in data.get("nftables", []):
            if "set" in item and item["set"].get("name") == "alias_mac_block":
                elems = item["set"].get("elem", [])
                return [e if isinstance(e, str) else e.get("val", str(e)) for e in elems]
    except Exception:
        pass
    return []


def get_custom_rules():
    rules = []
    path = "/etc/nftables/custom-rules.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 11:
                    parts = parts + [""] * (13 - len(parts))
                    rules.append({
                        "id": parts[0], "enabled": parts[1] == "yes", "interface": parts[2],
                        "action": parts[3], "protocol": parts[4], "source": parts[5],
                        "src_port": parts[6], "destination": parts[7], "dst_port": parts[8],
                        "gateway": parts[9], "bandwidth_limit": parts[10], "description": parts[11],
                        "log": parts[12] == "yes",
                    })
    def _fmt_bytes(n):
        n = float(n)
        for unit in ["B", "KB", "MB", "GB"]:
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} TB"

    counters = get_custom_rule_counters()
    for r in rules:
        c = counters.get(r["id"], {"packets": 0, "bytes": 0})
        r["packets"] = c["packets"]
        r["bytes"] = c["bytes"]
        r["hits_display"] = f"{c['packets']} / {_fmt_bytes(c['bytes'])}"
    return rules


def get_objects():
    """Aliases/Objects listesini, her birinin gercek nftables degerleriyle birlikte doner."""
    objects = []
    path = "/etc/nftables/objects.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|", 2)
                if len(parts) >= 2:
                    name = parts[0]
                    otype = parts[1]
                    description = parts[2] if len(parts) > 2 else ""
                    import re as _re
                    setname = "obj_" + _re.sub(r'[^a-zA-Z0-9_]', '_', name).lower()

                    values = []
                    try:
                        proc = subprocess.run(
                            ["/usr/sbin/nft", "-j", "list", "set", "ip", "fw", setname],
                            capture_output=True, text=True, timeout=5,
                        )
                        if proc.returncode == 0:
                            data = json.loads(proc.stdout)
                            for item in data.get("nftables", []):
                                if "set" in item and item["set"].get("name") == setname:
                                    elems = item["set"].get("elem", [])
                                    values = [e if isinstance(e, (str, int)) else e.get("val") for e in elems]
                    except Exception:
                        pass

                    objects.append({
                        "name": name, "type": otype, "description": description,
                        "values": values,
                    })
    return objects


def get_custom_rule_counters():
    """Her ozel kuralin (comment='rule#<id>...') canli paket/bayt sayacini doner."""
    counters = {}
    try:
        proc = subprocess.run(
            ["/usr/sbin/nft", "-j", "list", "chain", "ip", "fw", "forward"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                comment = rule.get("comment", "")
                if not comment.startswith("rule#"):
                    continue
                rule_id = comment[len("rule#"):].split(":")[0].strip()
                for expr in rule.get("expr", []):
                    if "counter" in expr:
                        counters[rule_id] = {
                            "packets": expr["counter"].get("packets", 0),
                            "bytes": expr["counter"].get("bytes", 0),
                        }
                        break
    except Exception:
        pass
    return counters


DHCP_VLAN_NAMES = {
    10: "Guest Wi-Fi", 20: "Staff", 30: "Camera / IoT", 40: "Staff Housing",
    99: "Management", 250: "Test (lan-trunk)",
}


def get_dhcp_leases():
    """Kea'nin memfile CSV'lerini (canli + iki yedek) birlikte tarar, IP basina
    en guncel (en buyuk expire) kaydi alir. Sadece LFC rotasyonu anindaki
    yanlis 'hic lease yok' gorunumunu onlemek icin canli dosyayla sinirli
    kalmiyoruz - dhcp-leases CLI aracinin da ayni mantiga gecmesi faydali olur."""
    import csv as _csv
    import time as _time

    files = [
        "/var/lib/kea/kea-leases4.csv",
        "/var/lib/kea/kea-leases4.csv.1",
        "/var/lib/kea/kea-leases4.csv.2",
    ]

    now = _time.time()
    latest_by_ip = {}

    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, newline="") as f:
                reader = _csv.DictReader(f)
                for row in reader:
                    try:
                        expire = int(row.get("expire", 0))
                        state = row.get("state", "0")
                    except (ValueError, TypeError):
                        continue
                    if state != "0" or expire <= now:
                        continue
                    ip = row.get("address", "")
                    if not ip:
                        continue
                    if ip not in latest_by_ip or expire > latest_by_ip[ip]["expire"]:
                        subnet_id = int(row.get("subnet_id", 0)) if row.get("subnet_id") else 0
                        remaining = expire - int(now)
                        days, rem = divmod(remaining, 86400)
                        hours, rem = divmod(rem, 3600)
                        minutes, _ = divmod(rem, 60)
                        if days:
                            remaining_display = f"{days}d {hours}h"
                        elif hours:
                            remaining_display = f"{hours}h {minutes}m"
                        else:
                            remaining_display = f"{minutes}m"
                        latest_by_ip[ip] = {
                            "ip": ip,
                            "mac": row.get("hwaddr", "?"),
                            "hostname": row.get("hostname", "") or "",
                            "subnet_id": subnet_id,
                            "vlan_name": DHCP_VLAN_NAMES.get(subnet_id, f"subnet{subnet_id}"),
                            "expire": expire,
                            "remaining_seconds": remaining,
                            "remaining_display": remaining_display,
                        }
        except Exception:
            continue

    leases = list(latest_by_ip.values())
    leases.sort(key=lambda x: (x["subnet_id"], x["ip"]))
    return leases


def get_dhcp_reservations():
    reservations = []
    try:
        with open("/etc/kea/kea-dhcp4.conf") as f:
            data = json.load(f)
        for subnet in data.get("Dhcp4", {}).get("subnet4", []):
            vlan_id = subnet.get("id")
            for r in subnet.get("reservations", []):
                reservations.append({
                    "vlan_id": vlan_id,
                    "vlan_name": DHCP_VLAN_NAMES.get(vlan_id, f"subnet{vlan_id}"),
                    "mac": r.get("hw-address", ""),
                    "ip": r.get("ip-address", ""),
                    "hostname": r.get("hostname", ""),
                })
    except Exception:
        pass
    reservations.sort(key=lambda x: (x["vlan_id"], x["ip"]))
    return reservations


def get_dhcp_subnets():
    """dhcp-reserve'in bekledigi 'vlan_id' degerlerini (Kea'nin gercek subnet
    ID'lerini), ilgili arayuz adiyla birlikte, dogrudan Kea config'inden okur."""
    subnets = []
    try:
        with open("/etc/kea/kea-dhcp4.conf") as f:
            data = json.load(f)
        for subnet in data.get("Dhcp4", {}).get("subnet4", []):
            subnet_id = subnet.get("id")
            iface = subnet.get("interface", "")
            pools = subnet.get("pools", [])
            pool_str = pools[0].get("pool", "") if pools else ""
            pool_start, pool_end = "", ""
            if " - " in pool_str:
                pool_start, pool_end = [p.strip() for p in pool_str.split(" - ", 1)]
            subnets.append({
                "id": subnet_id,
                "interface": iface,
                "label": DHCP_VLAN_NAMES.get(subnet_id, f"{iface} (subnet {subnet_id})"),
                "subnet_cidr": subnet.get("subnet", ""),
                "pool": pool_str or "(no DHCP pool)",
                "pool_start": pool_start,
                "pool_end": pool_end,
                "has_pool": bool(pool_str),
            })
    except Exception:
        pass
    subnets.sort(key=lambda x: x["id"])
    return subnets


def get_dnsbl_feeds():
    """Ozel DNSBL feed'lerini (dnsbl-feed ile eklenenleri), gercek RPZ kayit
    sayilariyla birlikte doner."""
    feeds = []
    path = "/etc/unbound/custom-feeds.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) in (7, 8):
                    feed_id = parts[0]
                    scope = parts[7] if len(parts) == 8 else "all"
                    zone_path = f"/etc/unbound/rpz/feed_{feed_id}.rpz"
                    count = 0
                    if os.path.exists(zone_path):
                        try:
                            with open(zone_path) as zf:
                                count = sum(1 for line2 in zf if "CNAME ." in line2)
                        except Exception:
                            pass
                    feeds.append({
                        "id": feed_id, "name": parts[1], "group": parts[2],
                        "feed_url": parts[3], "format": parts[4],
                        "website": parts[5], "enabled": parts[6] == "yes",
                        "record_count": count,
                        "scope": scope,
                        "scope_display": "All networks" if scope == "all" else scope.replace(",", ", "),
                    })
    return feeds


def get_last_rpz_update_log():
    path = "/var/log/stratum-panel/rpz-update.log"
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None


def get_last_bulk_import_log():
    path = "/var/log/stratum-panel/bulk-import.log"
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return None


def get_feed_catalog():
    """Sabit feed kataloğunu okur, halihazırda eklenmiş feed'leri (URL eşleşmesiyle) işaretler."""
    path = "/etc/unbound/feed-catalog.json"
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            catalog = json.load(f)
    except Exception:
        return []

    existing_urls = {f["feed_url"] for f in get_dnsbl_feeds()}

    groups = []
    for group in catalog.get("groups", []):
        feeds = []
        for feed in group.get("feeds", []):
            feeds.append({**feed, "already_added": feed["url"] in existing_urls})
        groups.append({
            "name": group["name"],
            "feeds": feeds,
            "all_added": bool(feeds) and all(f["already_added"] for f in feeds),
        })
    return groups


def _derive_nic_role_label(name):
    """Rolü öncelikle /etc/nftables/interface-roles.conf dosyasından okur.
    Böylece Physical Interface Configuration ile Physical & WAN Interfaces
    bölümleri her zaman tutarlı olur."""
    roles_file = "/etc/nftables/interface-roles.conf"
    role = None
    if os.path.exists(roles_file):
        with open(roles_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) == 2 and parts[0] == name:
                    role = parts[1]
                    break
    if role is None:
        # Dosya yoksa veya isim bulunamadıysa, eski isim tabanlı tahmine düş
        if name == "lan-trunk":
            role = "lan"
        elif name.startswith("wan"):
            role = "wan"
        elif name.startswith("opt"):
            role = "opt"
        else:
            role = "disabled"
    # Görüntüleme için rolü insan dostu etikete çevir
    if role == "lan":
        return "LAN trunk (802.1Q)"
    elif role == "wan":
        return "WAN — " + name
    elif role == "opt":
        return "OPT — " + name
    else:
        return "Unused (available)"


def get_physical_nic_details():
    """Fiziksel Ethernet arayuzlerinin MAC/PCI/donanim modeli bilgisini doner.
    ONEMLI: isme gore DEGIL, canli sistemde device sembolik baglantisi olan
    (yani gercekten fiziksel) TUM arayuzleri MAC bazinda tarar - boylece
    nic-configure ile isim degisse bile (orn. spare -> spare1) kart hala
    dogru bulunur."""
    result = []
    names_and_roles = []
    for name in os.listdir("/sys/class/net"):
        device_path = f"/sys/class/net/{name}/device"
        if not os.path.exists(device_path):
            continue
        names_and_roles.append((name, _derive_nic_role_label(name)))

    # ONEMLI: fiziksel PCI slot adresine gore sirala - boylece isim degisse
    # bile (wan2 -> spare1 gibi) o kart tabloda HEP AYNI satirda kalir.
    def _pci_sort_key(item):
        name = item[0]
        try:
            device_path = f"/sys/class/net/{name}/device"
            real_path = os.readlink(device_path)
            return real_path.split("/")[-1]
        except Exception:
            return name
    names_and_roles.sort(key=_pci_sort_key)

    for name, role in names_and_roles:
        mac_path = f"/sys/class/net/{name}/address"
        device_path = f"/sys/class/net/{name}/device"
        if not os.path.exists(mac_path):
            continue
        try:
            with open(mac_path) as f:
                mac = f.read().strip()
        except Exception:
            mac = "?"

        pci_slot = "?"
        model = "?"
        try:
            real_path = os.readlink(device_path)
            pci_slot = real_path.split("/")[-1]
            lspci_out = subprocess.run(["lspci", "-s", pci_slot], capture_output=True, text=True, timeout=3)
            if lspci_out.returncode == 0 and lspci_out.stdout.strip():
                model = lspci_out.stdout.strip().split(": ", 1)[-1]
        except Exception:
            pass

        # role_type: wan/lan/opt/disabled (dosyadan veya isimden)
        roles_file = "/etc/nftables/interface-roles.conf"
        role_type = "disabled"
        if os.path.exists(roles_file):
            with open(roles_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) == 2 and parts[0] == name:
                        role_type = parts[1]
                        break
        else:
            if name == "lan-trunk":
                role_type = "lan"
            elif name.startswith("wan"):
                role_type = "wan"
            elif name.startswith("opt"):
                role_type = "opt"

        result.append({
            "name": name, "role": role, "role_type": role_type,
            "mac": mac, "pci_slot": pci_slot, "model": model,
        })
    return result


def get_temperature_stats():
    """CPU (coretemp paket) ve sistem (acpitz) sicakligini C cinsinden doner.
    hwmon numarasi boot'tan boot'a degisebilecegi icin 'name' dosyasina gore arar."""
    result = {"cpu": None, "system": None}
    try:
        for hwmon_dir in os.listdir("/sys/class/hwmon"):
            base = f"/sys/class/hwmon/{hwmon_dir}"
            name_path = f"{base}/name"
            if not os.path.exists(name_path):
                continue
            with open(name_path) as f:
                name = f.read().strip()

            if name == "coretemp" and result["cpu"] is None:
                temp_path = f"{base}/temp1_input"
                if os.path.exists(temp_path):
                    with open(temp_path) as f:
                        result["cpu"] = round(int(f.read().strip()) / 1000, 1)

            if name == "acpitz" and result["system"] is None:
                temp_path = f"{base}/temp1_input"
                if os.path.exists(temp_path):
                    with open(temp_path) as f:
                        result["system"] = round(int(f.read().strip()) / 1000, 1)
    except Exception:
        pass
    return result


def get_rpz_update_summary():
    """rpz-update.log'dan son calistirmanin ozetini (tarih, kategori basina
    kayit sayisi, toplam boyut) ve rpz-update.timer'dan sonraki calisma
    zamanini cikarir."""
    result = {
        "last_run": None,
        "exit_code": None,
        "categories": [],
        "total_records": 0,
        "total_size_mb": 0.0,
        "next_run": None,
    }

    log_path = "/var/log/stratum-panel/rpz-update.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            lines = f.readlines()

        pending_category = None
        for line in lines:
            line = line.strip()
            if line.startswith("Run at:"):
                result["last_run"] = line.replace("Run at:", "").strip()
            elif line.startswith("Exit code:"):
                result["exit_code"] = line.replace("Exit code:", "").strip()
            elif line.startswith("[rpz-update] downloading"):
                m = re.match(r'\[rpz-update\] downloading (\S+) \((\w+)\)', line)
                if m:
                    pending_category = m.group(1)
            elif line.startswith("->") and pending_category:
                m = re.match(r'-> (\d+) records', line)
                if m:
                    count = int(m.group(1))
                    result["categories"].append({"name": pending_category, "records": count})
                    result["total_records"] += count
                pending_category = None
            elif "manual list" in line:
                m = re.match(r'\[rpz-update\] (\S+):', line)
                if m:
                    result["categories"].append({"name": m.group(1), "records": None})
                pending_category = None

    rpz_dir = "/etc/unbound/rpz"
    if os.path.isdir(rpz_dir):
        total_bytes = 0
        for fname in os.listdir(rpz_dir):
            try:
                total_bytes += os.path.getsize(os.path.join(rpz_dir, fname))
            except OSError:
                pass
        result["total_size_mb"] = round(total_bytes / (1024 * 1024), 1)

    try:
        proc = subprocess.run(["systemctl", "list-timers", "rpz-update.timer", "--no-pager"], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            if "rpz-update.timer" in line and "NEXT" not in line:
                parts = line.split()
                if len(parts) >= 4:
                    result["next_run"] = " ".join(parts[0:4])
    except Exception:
        pass

    return result


def get_vlans_by_parent():
    """Her VLAN alt arayuzunun HANGI fiziksel/mantiksal ebeveyne bagli
    oldugunu cikarir (ip -j link show'daki 'link' alani dogrudan ebeveyn
    ismini icerir)."""
    result = {}
    try:
        raw = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True, timeout=5)
        all_ifaces = json.loads(raw.stdout) if raw.returncode == 0 else []
    except Exception:
        all_ifaces = []

    for iface in all_ifaces:
        name = iface.get("ifname", "")
        if re.match(r'^vlan\d+$', name):
            parent_name = iface.get("link")
            if parent_name:
                role_type = _current_role_of(name)
                result.setdefault(parent_name, []).append({"name": name, "role_type": role_type})
    return result


def get_vlan_parent_candidates():
    """VLAN olusturmak icin gecerli TUM ebeveyn adaylarini (WAN + LAN + OPT)
    dondurur - VLAN'lar HARIC tutulur (ic ice VLAN olusturulamaz)."""
    result = []
    for i in get_interface_details():
        if not i.get("ip") and _current_role_of(i["name"]) != "wan":
            continue
        if re.match(r'^vlan\d+$', i["name"]):
            continue
        role = _current_role_of(i["name"])
        if role in ("wan", "lan", "opt"):
            result.append({"name": i["name"], "role": i["role"], "role_type": role, "cidr": i.get("ip", "")})
    return result


def get_crowdsec_decisions():
    """cscli decisions list -o json'dan aktif engellemeleri duz bir listeye
    cevirir."""
    result = []
    try:
        proc = subprocess.run(["/usr/bin/cscli", "decisions", "list", "-o", "json"],
                               capture_output=True, text=True, timeout=8)
        if proc.returncode != 0:
            return result
        alerts = json.loads(proc.stdout)
        if not isinstance(alerts, list):
            return result
        for alert in alerts:
            for dec in alert.get("decisions", []) or []:
                result.append({
                    "id": dec.get("id"),
                    "ip": dec.get("value"),
                    "scenario": alert.get("scenario") or dec.get("scenario"),
                    "type": dec.get("type"),
                    "origin": dec.get("origin"),
                    "duration": dec.get("duration"),
                    "created_at": alert.get("created_at"),
                })
    except Exception:
        pass
    return result


def get_crowdsec_stats():
    decisions = get_crowdsec_decisions()
    manual = sum(1 for d in decisions if d.get("origin") == "cscli")
    automatic = len(decisions) - manual
    return {"total": len(decisions), "manual": manual, "automatic": automatic}


def get_suricata_alerts(limit=100):
    """eve.json'daki son 'alert' tipi olaylari okur. Dosya cok buyuk
    olabildigi ve alert olaylari nadir olabildigi icin (arada milyonlarca
    flow/stats olayi var), son N byte'i degil, grep ile TUM dosyada
    "event_type":"alert" satirlarini bulup en sonuncularini aliyoruz -
    bu hem dogru hem de grep'in hizindan dolayi buyuk dosyalarda bile
    performansli."""
    result = []
    eve_path = "/var/log/suricata/eve.json"
    if not os.path.exists(eve_path):
        return result
    try:
        proc = subprocess.run(
            ["grep", "-a", '"event_type":"alert"', eve_path],
            capture_output=True, text=True, timeout=15,
        )
        lines = proc.stdout.splitlines()[-limit:]
        for line in reversed(lines):
            try:
                d = json.loads(line)
            except Exception:
                continue
            if d.get("event_type") != "alert":
                continue
            alert = d.get("alert", {})
            result.append({
                "timestamp": d.get("timestamp"),
                "src_ip": d.get("src_ip"),
                "src_port": d.get("src_port"),
                "dest_ip": d.get("dest_ip"),
                "dest_port": d.get("dest_port"),
                "proto": d.get("proto"),
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "category": alert.get("category"),
                "severity": alert.get("severity"),
                "in_iface": d.get("in_iface") or d.get("interface"),
            })
    except Exception:
        pass
    return result


def get_suricata_stats():
    """suricata.log'daki son 'counters: Alerts' ve arayuz paket sayaclarini
    okur (calisma durumu ozeti icin)."""
    result = {"total_alerts_recent": 0, "interfaces": [], "rules_loaded": None, "running": False}
    result["running"] = subprocess.run(["systemctl", "is-active", "suricata"], capture_output=True, text=True).stdout.strip() == "active"

    log_path = "/var/log/suricata/suricata.log"
    if os.path.exists(log_path):
        proc = subprocess.run(["tail", "-n", "200", log_path], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            m = re.search(r'rule files processed\. (\d+) rules successfully loaded', line)
            if m:
                result["rules_loaded"] = int(m.group(1))
            m2 = re.search(r'device: (\S+): packets: (\d+), drops: (\d+)', line)
            if m2:
                iface = m2.group(1)
                if not any(i["name"] == iface for i in result["interfaces"]):
                    result["interfaces"].append({"name": iface, "packets": int(m2.group(2)), "drops": int(m2.group(3))})

    result["total_alerts_recent"] = len(get_suricata_alerts(limit=500))
    return result


def get_suricata_monitored_ifaces():
    """suricata.yaml'in af-packet bolumunde su an izlenen (default disinda)
    arayuz isimlerini doner."""
    path = "/etc/suricata/suricata.yaml"
    result = []
    if not os.path.exists(path):
        return result
    with open(path) as f:
        content = f.read()
    m = re.search(r'af-packet:\n(.*?)\n  - interface: default', content, re.DOTALL)
    if m:
        for line in m.group(1).splitlines():
            line = line.strip()
            if line.startswith("- interface:"):
                result.append(line.replace("- interface:", "").strip())
    return result



def get_suricata_suppressed():
    """threshold.config'teki yonetilen suppress kurallarini okur."""
    path = "/etc/suricata/threshold.config"
    result = []
    if not os.path.exists(path):
        return result
    with open(path) as f:
        content = f.read()
    if "# === STRATUM-SUPPRESS-START ===" not in content:
        return result
    managed = content.split("# === STRATUM-SUPPRESS-START ===")[1].split("# === STRATUM-SUPPRESS-END ===")[0]
    for line in managed.splitlines():
        line = line.strip()
        if not line.startswith("suppress "):
            continue
        sig_m = re.search(r'sig_id (\d+)', line)
        ip_m = re.search(r'ip ([\d./]+)', line)
        result.append({
            "sig_id": sig_m.group(1) if sig_m else None,
            "ip": ip_m.group(1) if ip_m else None,
            "raw": line,
        })
    return result

def get_snmp_config():
    """snmpd.conf'tan temel ayarlari (konum, iletisim, dinleme adresleri,
    salt-okunur kullanicilar) okur."""
    result = {"location": "", "contact": "", "agent_address": "", "rousers": [], "running": False}
    path = "/etc/snmp/snmpd.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("sysLocation"):
                    result["location"] = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                elif line.startswith("sysContact"):
                    result["contact"] = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                elif line.startswith("agentAddress"):
                    result["agent_address"] = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                elif line.startswith("rouser"):
                    parts = line.split()
                    if len(parts) >= 2:
                        result["rousers"].append(parts[1])
    result["running"] = subprocess.run(["systemctl", "is-active", "snmpd"], capture_output=True, text=True).stdout.strip() == "active"
    return result


def get_snmp_v3_users():
    """/var/lib/snmp/snmpd.conf'taki usmUser satirlarindan kullanici
    adlarini (sifre hash'lerini DEGIL) cikarir."""
    result = []
    path = "/var/lib/snmp/snmpd.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("usmUser"):
                    parts = line.split('"')
                    if len(parts) >= 4:
                        result.append(parts[1])
    return result


NFDUMP_DIR = "/var/cache/nfdump"


def _nfdump_time_filter(time_range):
    """Secilen zaman araligina gore nfdump'un -t bayragi icin baslangic
    zamanini hesaplar (bitis her zaman simdi)."""
    from datetime import datetime, timedelta
    now = datetime.now()
    deltas = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    if time_range not in deltas:
        return None
    start = now - deltas[time_range]
    return start.strftime("%Y/%m/%d.%H:%M:%S") + "-" + now.strftime("%Y/%m/%d.%H:%M:%S")


def get_netflow_summary(time_range="24h"):
    """nfdump'tan genel akis ozetini (toplam byte/paket/akis, zaman
    penceresi) cikarir."""
    result = {"total_flows": 0, "total_bytes": "0", "total_packets": "0", "avg_bps": 0, "time_window": "", "available": False}
    if not os.path.isdir(NFDUMP_DIR):
        return result
    cmd = ["nfdump", "-R", NFDUMP_DIR]
    tf = _nfdump_time_filter(time_range)
    if tf:
        cmd += ["-t", tf]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        for line in proc.stdout.splitlines():
            if line.startswith("Summary:"):
                m = re.search(r'total flows:\s*(\d+),\s*total bytes:\s*([\d.]+\s*\w?),.*avg bps:\s*(\d+)', line)
                if m:
                    result["total_flows"] = int(m.group(1))
                    result["total_bytes"] = m.group(2).strip()
                    result["avg_bps"] = int(m.group(3))
                    result["available"] = True
            elif line.startswith("Time window:"):
                result["time_window"] = line.replace("Time window:", "").strip()
    except Exception:
        pass
    return result


def _human_bytes(n):
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_netflow_top(kind="ip", time_range="24h", limit=10):
    """nfdump ile en cok trafik yapan IP'leri ya da en cok kullanilan
    portlari getirir. Guvenilir ayristirma icin CSV cikti modu kullanilir
    (insan-okunur tablo formati, degisken genislikli hizalama yuzunden
    bosluga gore ayristirmada hataliydi)."""
    result = []
    if not os.path.isdir(NFDUMP_DIR):
        return result
    stat_key = "ip/bytes" if kind == "ip" else "port/bytes"
    cmd = ["nfdump", "-R", NFDUMP_DIR, "-s", stat_key, "-n", str(limit), "-o", "csv"]
    tf = _nfdump_time_filter(time_range)
    if tf:
        cmd += ["-t", tf]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        reader = csv.DictReader(proc.stdout.splitlines())
        for row in reader:
            try:
                result.append({
                    "key": row["val"],
                    "flows": row["fl"],
                    "flows_pct": row["flP"],
                    "bytes": _human_bytes(row["byt"]),
                    "bytes_pct": row["bytP"],
                })
            except Exception:
                continue
    except Exception:
        pass
    return result


def get_qos_wan_bandwidth():
    """/etc/qos/wan-bandwidth.conf'tan WAN basina up/down kbit degerlerini
    okur (panelde Mbit olarak gosterilecek)."""
    result = {}
    path = "/etc/qos/wan-bandwidth.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 3:
                    result[parts[0]] = {"up_kbit": parts[1], "down_kbit": parts[2]}
    return result


def get_qos_shares():
    """/etc/qos/shares.conf'tan ag basina upload/download kbit
    sinirlarini okur (v2 mimari: guarantee/ceiling/oncelik degil,
    dogrudan Mbit siniri - her ag artik KENDI arayuzunde bagimsiz
    sekillendiriliyor)."""
    result = {}
    path = "/etc/qos/shares.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 3:
                    result[parts[0]] = {"up_kbit": parts[1], "down_kbit": parts[2]}
    return result


def get_qos_networks_with_shares():
    """Guncel LAN/OPT/VLAN aglarini (get_lan_ifaces_with_subnets ile ayni
    mantik) mevcut upload/download Mbit sinirlariyla birlestirir. ONEMLI:
    henuz ayarlanmamis bir ag icin TAHMINI/hesaplanmis bir varsayilan
    DEGER GOSTERILMEZ - bos birakilir. Boylece kullanici "Traffic
    Shaping" sayfasini actiginda, henuz HICBIR limit uygulanmamis
    aglarin GERCEKTEN bos oldugu acikca gorulur (canli ortamda
    dogrulanmis, gercek bir tasarim hatasiydi - tahmini bir sayi
    goruntulenmesi, kullanicinin YANLISLIKLA istemedigi bir limiti
    kaydetmesine yol acabiliyordu)."""
    networks = get_lan_ifaces_with_subnets()
    shares = get_qos_shares()
    result = []
    for net in networks:
        s = shares.get(net["name"])
        result.append({
            "name": net["name"],
            "role": net["role"],
            "cidr": net["cidr"],
            "up_mbit": round(int(s["up_kbit"]) / 1000, 1) if s else "",
            "down_mbit": round(int(s["down_kbit"]) / 1000, 1) if s else "",
        })
    return result


def get_qos_active_status():
    """tc'nin gercekten kurulu olup olmadigini (WAN'larda htb qdisc var mi)
    kontrol eder."""
    result = {"active": False, "wans": []}
    for iface in get_vlan_parent_candidates():
        if iface["role_type"] != "wan":
            continue
        proc = subprocess.run(["tc", "qdisc", "show", "dev", iface["name"]], capture_output=True, text=True)
        has_cake = "cake" in proc.stdout
        result["wans"].append({"name": iface["name"], "shaped": has_cake})
        if has_cake:
            result["active"] = True
    return result


def get_audit_log_entries(limit=200):
    """Denetim gunlugunden (audit.log) son kayitlari en yeniden en eskiye
    dogru sirali olarak doner."""
    result = []
    path = "/var/log/stratum-panel/audit.log"
    if not os.path.exists(path):
        return result
    try:
        proc = subprocess.run(["tail", "-n", str(limit), path], capture_output=True, text=True)
        lines = proc.stdout.splitlines()
        for line in reversed(lines):
            try:
                entry = json.loads(line)
                result.append(entry)
            except Exception:
                continue
    except Exception:
        pass
    return result


def get_backup_list():
    """/var/backups/stratum-panel dizinindeki yedekleri, en yeniden en
    eskiye siralanmis olarak doner."""
    result = []
    path = "/var/backups/stratum-panel"
    if not os.path.isdir(path):
        return result
    for fname in os.listdir(path):
        if not fname.endswith(".tar.gz"):
            continue
        full = os.path.join(path, fname)
        try:
            stat = os.stat(full)
            result.append({
                "filename": fname,
                "size_mb": round(stat.st_size / (1024 * 1024), 1),
                "mtime": stat.st_mtime,
                "created_at": subprocess.run(["date", "-d", f"@{int(stat.st_mtime)}", "+%Y-%m-%d %H:%M:%S"], capture_output=True, text=True).stdout.strip(),
            })
        except Exception:
            continue
    result.sort(key=lambda x: x["mtime"], reverse=True)
    return result


def get_hostname():
    result = subprocess.run(["hostnamectl", "--static"], capture_output=True, text=True)
    return result.stdout.strip()


def get_timezone():
    result = subprocess.run(["timedatectl", "show", "--property=Timezone", "--value"], capture_output=True, text=True)
    return result.stdout.strip()


def get_available_timezones():
    result = subprocess.run(["timedatectl", "list-timezones"], capture_output=True, text=True)
    return result.stdout.strip().splitlines()


def get_cert_info():
    """Panel HTTPS sertifikasinin temel bilgilerini (subject, issuer,
    gecerlilik tarihleri, kendinden-imzali mi) doner."""
    result = {"subject": "", "issuer": "", "not_before": "", "not_after": "", "is_self_signed": True, "fingerprint": ""}
    cert_path = "/etc/stratum-panel/tls/panel.crt"
    if not os.path.exists(cert_path):
        return result
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256"],
            capture_output=True, text=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("subject="):
                result["subject"] = line.replace("subject=", "").strip()
            elif line.startswith("issuer="):
                result["issuer"] = line.replace("issuer=", "").strip()
            elif line.startswith("notBefore="):
                result["not_before"] = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                result["not_after"] = line.replace("notAfter=", "").strip()
            elif "Fingerprint" in line:
                result["fingerprint"] = line.split("=", 1)[1].strip() if "=" in line else ""
        result["is_self_signed"] = (result["subject"] == result["issuer"])
    except Exception:
        pass
    return result


def get_ca_info():
    """Dahili CA'nin (varsa) temel bilgilerini doner."""
    result = {"exists": False, "subject": "", "not_before": "", "not_after": "", "fingerprint": ""}
    ca_path = "/etc/stratum-panel/ca/ca.crt"
    if not os.path.exists(ca_path):
        return result
    result["exists"] = True
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", ca_path, "-noout", "-subject", "-dates", "-fingerprint", "-sha256"],
            capture_output=True, text=True,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("subject="):
                result["subject"] = line.replace("subject=", "").strip()
            elif line.startswith("notBefore="):
                result["not_before"] = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                result["not_after"] = line.replace("notAfter=", "").strip()
            elif "Fingerprint" in line:
                result["fingerprint"] = line.split("=", 1)[1].strip() if "=" in line else ""
    except Exception:
        pass
    return result


COUNTRY_NAMES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AS": "American Samoa",
    "AD": "Andorra", "AO": "Angola", "AI": "Anguilla", "AQ": "Antarctica",
    "AG": "Antigua and Barbuda", "AR": "Argentina", "AM": "Armenia", "AW": "Aruba",
    "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BS": "Bahamas",
    "BH": "Bahrain", "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus",
    "BE": "Belgium", "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda",
    "BT": "Bhutan", "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana",
    "BR": "Brazil", "BN": "Brunei", "BG": "Bulgaria", "BF": "Burkina Faso",
    "BI": "Burundi", "KH": "Cambodia", "CM": "Cameroon", "CA": "Canada",
    "CV": "Cape Verde", "KY": "Cayman Islands", "CF": "Central African Republic",
    "TD": "Chad", "CL": "Chile", "CN": "China", "CO": "Colombia",
    "KM": "Comoros", "CG": "Congo", "CD": "Congo (DRC)", "CR": "Costa Rica",
    "CI": "Cote d'Ivoire", "HR": "Croatia", "CU": "Cuba", "CY": "Cyprus",
    "CZ": "Czech Republic", "DK": "Denmark", "DJ": "Djibouti", "DM": "Dominica",
    "DO": "Dominican Republic", "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador",
    "GQ": "Equatorial Guinea", "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia",
    "FJ": "Fiji", "FI": "Finland", "FR": "France", "GA": "Gabon",
    "GM": "Gambia", "GE": "Georgia", "DE": "Germany", "GH": "Ghana",
    "GI": "Gibraltar", "GR": "Greece", "GL": "Greenland", "GD": "Grenada",
    "GU": "Guam", "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau",
    "GY": "Guyana", "HT": "Haiti", "HN": "Honduras", "HK": "Hong Kong",
    "HU": "Hungary", "IS": "Iceland", "IN": "India", "ID": "Indonesia",
    "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JM": "Jamaica", "JP": "Japan", "JO": "Jordan",
    "KZ": "Kazakhstan", "KE": "Kenya", "KI": "Kiribati", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "KG": "Kyrgyzstan", "LA": "Laos",
    "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", "LR": "Liberia",
    "LY": "Libya", "LI": "Liechtenstein", "LT": "Lithuania", "LU": "Luxembourg",
    "MO": "Macao", "MK": "North Macedonia", "MG": "Madagascar", "MW": "Malawi",
    "MY": "Malaysia", "MV": "Maldives", "ML": "Mali", "MT": "Malta",
    "MH": "Marshall Islands", "MR": "Mauritania", "MU": "Mauritius", "MX": "Mexico",
    "FM": "Micronesia", "MD": "Moldova", "MC": "Monaco", "MN": "Mongolia",
    "ME": "Montenegro", "MA": "Morocco", "MZ": "Mozambique", "MM": "Myanmar",
    "NA": "Namibia", "NR": "Nauru", "NP": "Nepal", "NL": "Netherlands",
    "NZ": "New Zealand", "NI": "Nicaragua", "NE": "Niger", "NG": "Nigeria",
    "NO": "Norway", "OM": "Oman", "PK": "Pakistan", "PW": "Palau",
    "PS": "Palestine", "PA": "Panama", "PG": "Papua New Guinea", "PY": "Paraguay",
    "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal",
    "PR": "Puerto Rico", "QA": "Qatar", "RO": "Romania", "RU": "Russia",
    "RW": "Rwanda", "KN": "Saint Kitts and Nevis", "LC": "Saint Lucia",
    "VC": "Saint Vincent and the Grenadines", "WS": "Samoa", "SM": "San Marino",
    "ST": "Sao Tome and Principe", "SA": "Saudi Arabia", "SN": "Senegal",
    "RS": "Serbia", "SC": "Seychelles", "SL": "Sierra Leone", "SG": "Singapore",
    "SK": "Slovakia", "SI": "Slovenia", "SB": "Solomon Islands", "SO": "Somalia",
    "ZA": "South Africa", "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka",
    "SD": "Sudan", "SR": "Suriname", "SZ": "Eswatini", "SE": "Sweden",
    "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan",
    "TZ": "Tanzania", "TH": "Thailand", "TL": "Timor-Leste", "TG": "Togo",
    "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey",
    "TM": "Turkmenistan", "TV": "Tuvalu", "UG": "Uganda", "UA": "Ukraine",
    "AE": "United Arab Emirates", "GB": "United Kingdom", "US": "United States",
    "UY": "Uruguay", "UZ": "Uzbekistan", "VU": "Vanuatu", "VA": "Vatican City",
    "VE": "Venezuela", "VN": "Vietnam", "YE": "Yemen", "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


def get_geoblock_status():
    """Su an engellenen ulkeleri (kod + isim) ve nftables setinin gercek
    boyutunu doner."""
    result = {"blocked": [], "block_count": 0}
    path = "/etc/geoip-block/countries.conf"
    if os.path.exists(path):
        with open(path) as f:
            codes = [line.strip().upper() for line in f if line.strip()]
        for code in sorted(codes):
            result["blocked"].append({"code": code, "name": COUNTRY_NAMES.get(code, code)})
    try:
        proc = subprocess.run(["nft", "-j", "list", "set", "ip", "fw", "alias_geoblock"], capture_output=True, text=True)
        data = json.loads(proc.stdout)
        for item in data.get("nftables", []):
            if "set" in item:
                result["block_count"] = len(item["set"].get("elem", []))
    except Exception:
        pass
    return result


def get_threat_ip_status():
    """threat-ip-update.log'dan son calistirma ozetini ve nftables
    setinin gercek boyutunu doner."""
    result = {"last_run": None, "block_count": 0, "next_run": None}
    log_path = "/var/log/stratum-panel/threat-ip-update.log"
    if os.path.exists(log_path):
        proc = subprocess.run(["tail", "-n", "10", log_path], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            if "Run at:" in line:
                result["last_run"] = line.split("Run at:", 1)[0].strip()
    try:
        proc = subprocess.run(["nft", "-j", "list", "set", "ip", "fw", "alias_threat_ips"], capture_output=True, text=True)
        data = json.loads(proc.stdout)
        for item in data.get("nftables", []):
            if "set" in item:
                result["block_count"] = len(item["set"].get("elem", []))
    except Exception:
        pass
    try:
        proc = subprocess.run(["systemctl", "list-timers", "threat-ip-update.timer", "--no-pager"], capture_output=True, text=True, timeout=5)
        for line in proc.stdout.splitlines():
            if "threat-ip-update.timer" in line and "NEXT" not in line:
                parts = line.split()
                if len(parts) >= 4:
                    result["next_run"] = " ".join(parts[0:4])
    except Exception:
        pass
    return result


def get_module_backup_list():
    """stratum-module-backup'tan modul listesini (etiket + paylasilan
    dosya notu ile) okur."""
    try:
        proc = subprocess.run(["/usr/local/sbin/stratum-module-backup", "list"], capture_output=True, text=True, timeout=10)
        data = json.loads(proc.stdout)
        return [{"key": k, "label": v["label"], "shared_note": v.get("shared_note")} for k, v in data.items()]
    except Exception:
        return []


def get_wireguard_status():
    """WireGuard sunucusunun genel durumunu (calisiyor mu, genel anahtar,
    port, kac client kayitli) doner."""
    result = {"running": False, "public_key": "", "listen_port": 51820, "peer_count": 0, "vpn_subnet": "10.66.66.0/24"}
    result["running"] = subprocess.run(["systemctl", "is-active", "wg-quick@wg0"], capture_output=True, text=True).stdout.strip() == "active"
    pubkey_path = "/etc/wireguard/server_public.key"
    if os.path.exists(pubkey_path):
        with open(pubkey_path) as f:
            result["public_key"] = f.read().strip()
    peers_path = "/etc/wireguard/peers.json"
    if os.path.exists(peers_path):
        with open(peers_path) as f:
            result["peer_count"] = len(json.load(f))
    return result


def get_wireguard_peers():
    """wireguard-peer-manage'in JSON ciktisini panelin kullanacagi formata
    cevirir (son handshake'i okunabilir hale getirir)."""
    result = []
    try:
        proc = subprocess.run(["/usr/local/sbin/wireguard-peer-manage", "list"], capture_output=True, text=True, timeout=10)
        peers = json.loads(proc.stdout)
    except Exception:
        return result

    import datetime
    for p in peers:
        hs_epoch = int(p.get("last_handshake", "0") or "0")
        if hs_epoch == 0:
            last_handshake = "Never connected"
        else:
            last_handshake = datetime.datetime.fromtimestamp(hs_epoch).strftime("%Y-%m-%d %H:%M:%S")
        result.append({
            "name": p["name"],
            "ip": p["ip"],
            "created_at": p["created_at"],
            "last_handshake": last_handshake,
            "connected": hs_epoch > 0 and (datetime.datetime.now().timestamp() - hs_epoch) < 180,
            "rx": _human_bytes(p.get("rx_bytes", "0")),
            "tx": _human_bytes(p.get("tx_bytes", "0")),
        })
    return result


def get_dashboard_multiwan_summary():
    """Dashboard widget'i icin WAN'larin ozet saglik durumunu doner."""
    result = {"wans": []}
    path = "/var/log/stratum-panel/wan-status.json"
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                for w in data:
                    result["wans"].append({
                        "name": w.get("name", "?"),
                        "status": str(w.get("status", "unknown")).lower(),
                        "ip": w.get("ip", "n/a"),
                    })
        except Exception:
            pass
    return result


def get_dashboard_vpn_summary():
    """Dashboard widget'i icin WireGuard VPN ozetini doner."""
    status = get_wireguard_status()
    peers = get_wireguard_peers()
    connected = sum(1 for p in peers if p.get("connected"))
    return {
        "running": status["running"],
        "peer_count": status["peer_count"],
        "connected_count": connected,
    }


def get_dashboard_geoblock_summary():
    """Dashboard widget'i icin IP & Country Blocking ozetini doner."""
    geo = get_geoblock_status()
    threat = get_threat_ip_status()
    return {
        "countries_blocked": len(geo["blocked"]),
        "geo_ip_ranges": geo["block_count"],
        "threat_ip_ranges": threat["block_count"],
    }


def get_dashboard_backup_summary():
    """Dashboard widget'i icin son yedek ozetini doner."""
    backups = get_backup_list()
    if not backups:
        return {"has_backup": False}
    latest = backups[0]
    return {
        "has_backup": True,
        "last_backup_at": latest["created_at"],
        "size_mb": latest["size_mb"],
        "total_count": len(backups),
    }


def get_dashboard_qos_summary():
    """Dashboard widget'i icin Traffic Shaping ozetini doner."""
    active = get_qos_active_status()
    networks = get_qos_networks_with_shares()
    return {
        "active": active.get("active", False),
        "network_count": len(networks),
    }


DASHBOARD_WIDGET_DEFS = [
    {"key": "interfaces", "label": "Network Interfaces"},
    {"key": "temperature", "label": "Temperature"},
    {"key": "services", "label": "Service Status"},
    {"key": "dns", "label": "DNS Resolver"},
    {"key": "threats", "label": "Threat Protection"},
    {"key": "webfilter", "label": "Web Filter"},
    {"key": "traffic", "label": "Traffic Graph"},
    {"key": "multiwan", "label": "Multi-WAN Health"},
    {"key": "vpn", "label": "WireGuard VPN"},
    {"key": "geoblock", "label": "IP & Country Blocking"},
    {"key": "backup", "label": "Backup Status"},
    {"key": "qos", "label": "Traffic Shaping"},
]

DASHBOARD_WIDGETS_CONFIG_PATH = "/etc/stratum-panel/dashboard_widgets.json"
DEFAULT_ENABLED_WIDGETS = [w["key"] for w in DASHBOARD_WIDGET_DEFS]


def get_dashboard_widgets_config():
    """Panelde hangi dashboard widget'larinin aktif oldugunu doner.
    Config dosyasi yoksa TUM widget'lar varsayilan olarak aktiftir."""
    if os.path.exists(DASHBOARD_WIDGETS_CONFIG_PATH):
        try:
            with open(DASHBOARD_WIDGETS_CONFIG_PATH) as f:
                data = json.load(f)
            enabled = data.get("enabled", DEFAULT_ENABLED_WIDGETS)
            valid_keys = {w["key"] for w in DASHBOARD_WIDGET_DEFS}
            return [k for k in enabled if k in valid_keys]
        except Exception:
            pass
    return list(DEFAULT_ENABLED_WIDGETS)


def save_dashboard_widgets_config(enabled_keys):
    os.makedirs(os.path.dirname(DASHBOARD_WIDGETS_CONFIG_PATH), exist_ok=True)
    tmp = DASHBOARD_WIDGETS_CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"enabled": enabled_keys}, f, indent=2)
    os.replace(tmp, DASHBOARD_WIDGETS_CONFIG_PATH)
