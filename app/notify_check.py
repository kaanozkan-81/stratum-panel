import json
import os
import sys

sys.path.insert(0, "/opt/stratum-panel/app")

import notifications
from system_info import get_crowdsec_decisions

WAN_STATUS_FILE = "/var/log/stratum-panel/wan-status.json"
STATE_PATH = "/var/lib/stratum-panel/notify_state.json"


def get_wan_status_raw():
    if os.path.exists(WAN_STATUS_FILE):
        try:
            with open(WAN_STATUS_FILE) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def load_state():
    if os.path.isfile(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {"wan_status": {}, "crowdsec_ids": []}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)


def check_wan(config, state):
    wans = get_wan_status_raw()
    prev = state.get("wan_status", {})
    current = {}
    for w in wans:
        iface = w.get("name")
        status = str(w.get("status", "")).lower()
        if not iface:
            continue
        current[iface] = status
        prev_status = prev.get(iface)
        if prev_status is not None and prev_status != status:
            if status == "down" and config.get("notify_wan_down", True):
                notifications.send_email(
                    f"[Stratum Gateway] WAN DOWN: {iface}",
                    f"Interface {iface} changed from '{prev_status}' to '{status}'.\n"
                    f"IP: {w.get('ip', 'n/a')}  RTT: {w.get('avg_rtt_ms', 'n/a')}ms  Loss: {w.get('packet_loss', 'n/a')}%",
                )
            elif prev_status == "down" and status == "up" and config.get("notify_wan_up", True):
                notifications.send_email(
                    f"[Stratum Gateway] WAN RECOVERED: {iface}",
                    f"Interface {iface} changed from '{prev_status}' to '{status}'.\n"
                    f"IP: {w.get('ip', 'n/a')}  RTT: {w.get('avg_rtt_ms', 'n/a')}ms  Loss: {w.get('packet_loss', 'n/a')}%",
                )
    state["wan_status"] = current


def check_crowdsec(config, state, is_first_run):
    if not config.get("notify_crowdsec_ban", True):
        return
    try:
        decisions = get_crowdsec_decisions()
    except Exception:
        return
    prev_ids = set(state.get("crowdsec_ids", []))
    current_ids = []
    new_items = []
    for d in decisions:
        did = str(d.get("id", ""))
        if not did:
            continue
        current_ids.append(did)
        if did not in prev_ids:
            new_items.append(d)

    # ONEMLI: ilk calistirmada (state dosyasi henuz yoksa) mevcut ban'lari
    # "yeni" olarak BILDIRME - sadece sessizce state'e kaydet. Aksi halde
    # sistem ilk kez calistiginda (ya da state dosyasi silinirse) o an
    # aktif olan TUM ban'lar yanlislikla "yeni ban" olarak bildirilir.
    if new_items and not is_first_run:
        lines = []
        for d in new_items[:20]:
            lines.append(f"- {d.get('ip', 'unknown')} | scenario: {d.get('scenario', 'n/a')} | duration: {d.get('duration', 'n/a')} | type: {d.get('type', 'n/a')}")
        body = "New CrowdSec ban(s) detected:\n\n" + "\n".join(lines)
        notifications.send_email(f"[Stratum Gateway] {len(new_items)} New CrowdSec Ban(s)", body)

    state["crowdsec_ids"] = current_ids[-500:]


def main():
    config = notifications.get_config()
    if not config.get("email_enabled"):
        return
    is_first_run = not os.path.isfile(STATE_PATH)
    state = load_state()
    check_wan(config, state)
    check_crowdsec(config, state, is_first_run)
    save_state(state)


if __name__ == "__main__":
    main()
