"""
Captive Portal - nftables whitelist enforcement helpers.
Adds/removes authenticated clients' IP/MAC to/from nftables sets so that
future redirect rules can allow them through.
"""
import subprocess

NFT_BIN = "/usr/sbin/nft"
TABLE = "ip fw"
SET_IP = "captive_portal_whitelist_ip"
SET_MAC = "captive_portal_whitelist_mac"


def _run(args):
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=8)
        return proc.returncode == 0, proc.stdout, proc.stderr
    except Exception as e:
        return False, "", str(e)


def add_ip(ip: str):
    return _run([NFT_BIN, "add", "element", "ip", "fw", SET_IP, "{", ip, "}"])


def remove_ip(ip: str):
    return _run([NFT_BIN, "delete", "element", "ip", "fw", SET_IP, "{", ip, "}"])


def add_mac(mac: str):
    return _run([NFT_BIN, "add", "element", "ip", "fw", SET_MAC, "{", mac, "}"])


def remove_mac(mac: str):
    return _run([NFT_BIN, "delete", "element", "ip", "fw", SET_MAC, "{", mac, "}"])


def list_whitelisted_ips():
    ok, out, err = _run([NFT_BIN, "-j", "list", "set", "ip", "fw", SET_IP])
    if not ok:
        return []
    import json
    try:
        data = json.loads(out)
        for item in data.get("nftables", []):
            s = item.get("set")
            if s and s.get("name") == SET_IP:
                elems = s.get("elem", [])
                result = []
                for e in elems:
                    if isinstance(e, str):
                        result.append(e)
                    elif isinstance(e, dict) and "val" in e:
                        result.append(e["val"])
                return result
    except Exception:
        pass
    return []


def list_whitelisted_macs():
    ok, out, err = _run([NFT_BIN, "-j", "list", "set", "ip", "fw", SET_MAC])
    if not ok:
        return []
    import json
    try:
        data = json.loads(out)
        for item in data.get("nftables", []):
            s = item.get("set")
            if s and s.get("name") == SET_MAC:
                elems = s.get("elem", [])
                result = []
                for e in elems:
                    if isinstance(e, str):
                        result.append(e)
                    elif isinstance(e, dict) and "val" in e:
                        result.append(e["val"])
                return result
    except Exception:
        pass
    return []
