"""
Stratum Gateway - Web Panel
FastAPI backend, oturum bazlı (tek admin) kimlik doğrulama.
"""
import ipaddress
import json
import re
import safe_apply
import update_manager
import asyncio
import pty
import fcntl
import struct
import termios
import signal
import os
import secrets
import subprocess
from pathlib import Path

import radius_auth
import notifications
import captive_portal_manage

import bcrypt
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from system_info import get_interfaces, get_services, get_dns_stats, get_threat_stats, get_webfilter_stats, get_system_stats, get_traffic_stats, get_interface_details, get_physical_nic_details, get_lan_ifaces_with_subnets, get_webfilter_policies, ALL_WEBFILTER_CATEGORIES, get_live_chain_text, get_ip_blocklist, get_mac_blocklist, get_custom_rules, get_objects, get_dhcp_leases, get_dhcp_reservations, get_dhcp_subnets, get_dnsbl_feeds, get_last_rpz_update_log, get_last_bulk_import_log, get_feed_catalog, get_temperature_stats, get_rpz_update_summary, get_vlans_by_parent, get_vlan_parent_candidates, get_crowdsec_decisions, get_crowdsec_stats, get_suricata_alerts, get_suricata_stats, get_suricata_monitored_ifaces, get_suricata_suppressed, get_snmp_config, get_snmp_v3_users, get_netflow_summary, get_netflow_top, get_qos_wan_bandwidth, get_qos_networks_with_shares, get_qos_active_status, get_audit_log_entries, get_backup_list, get_hostname, get_timezone, get_available_timezones, get_cert_info, get_ca_info, get_geoblock_status, COUNTRY_NAMES, get_threat_ip_status, get_module_backup_list, get_wireguard_status, get_wireguard_peers, get_dashboard_multiwan_summary, get_dashboard_vpn_summary, get_dashboard_geoblock_summary, get_dashboard_backup_summary, get_dashboard_qos_summary, get_dashboard_widgets_config, save_dashboard_widgets_config, DASHBOARD_WIDGET_DEFS

BASE_DIR = Path(__file__).resolve().parent
CRED_FILE = Path("/etc/stratum-panel/credentials.json")
SECRET_FILE = Path("/etc/stratum-panel/session-secret.key")

if not SECRET_FILE.exists():
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_FILE.write_text(secrets.token_hex(32))
    os.chmod(SECRET_FILE, 0o600)
SESSION_SECRET = SECRET_FILE.read_text().strip()

app = FastAPI(title="Stratum Gateway Panel")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, session_cookie="stratum_session", https_only=True, max_age=3600 * 8)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

AUDIT_LOG_FILE = Path("/var/log/stratum-panel/audit.log")
AUDIT_SKIP_PATHS = {"/login", "/logout"}
# ONEMLI: dosya yukleme (multipart/form-data, buyuk binary icerik)
# iceren route'lar burada AYRICA muaf tutulur. Denetim middleware'inin
# "body'yi oku + yeniden oynat (replay)" mekanizmasi, KUCUK metin
# formlarinda sorunsuz calisir, ama COK BUYUK/binary multipart
# yuklemelerde (orn. 6.5MB'lik bir yedek dosyasi) icerigi BOZABILIYOR -
# canli ortamda dogrulanmis, gercek bir hataydi (Restore islemi hep
# "gecersiz dosya" hatasi veriyordu, aslinda dosyanin kendisi
# tamamen SAGLAMDI). Bu route'larin ZATEN dosya icerigini loglamasi
# MANTIKLI OLMADIGI icin (sadece ISIM/anahtar bilgisi degerli olurdu),
# TAMAMEN muaf tutmak en guvenli ve basit cozum.
AUDIT_SKIP_PREFIXES = ("/backup/restore", "/backup/module/", "/captive-portal/upload-template")
AUDIT_REDACT_KEYS = {"password", "current_password", "new_password", "new_password_confirm",
                      "authpass", "privpass", "pppoe_pass"}


def _should_skip_audit(path):
    if path in AUDIT_SKIP_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in AUDIT_SKIP_PREFIXES)


def audit_log(username, path, form_data):
    """Panelde yapilan HER degisiklik (POST istegi) icin, KIM/NE/NE ZAMAN
    yaptigini kaydeder. Sifre gibi hassas alanlar loglanmadan once
    REDACTED ile degistirilir - asla duz metin sifre diske yazilmaz."""
    try:
        AUDIT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        safe_data = {}
        for k, v in form_data.items():
            if any(sens in k.lower() for sens in ("pass", "secret", "privpass")):
                safe_data[k] = "[REDACTED]"
            else:
                safe_data[k] = v
        import datetime
        entry = {
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": username or "unknown",
            "path": path,
            "data": safe_data,
        }
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    is_auditable_post = request.method == "POST" and not _should_skip_audit(request.url.path)
    form_snapshot = None
    if is_auditable_post:
        # ONEMLI: request body'sini OKUDUKTAN SONRA, ASGI 'receive' callable'ini
        # AYNI byte'lari "replay" edecek sekilde manuel yeniden ayarliyoruz.
        # Aksi halde Starlette'in middleware mekanizmasinda body akisi
        # TUKETILMIS oluyor ve asagi akistaki route handler'in KENDI
        # Form(...) bagimliligi HICBIR VERI BULAMIYOR (canli ortamda
        # dogrulanmis, gercek bir hataydi - Web Filter kaydetme calismiyordu).
        body = await request.body()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive

        try:
            form = await request.form()
            form_snapshot = dict(form)
        except Exception:
            form_snapshot = None

        async def receive_again():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_again

    response = await call_next(request)

    if is_auditable_post and form_snapshot is not None:
        username = request.session.get("username")
        audit_log(username, request.url.path, form_snapshot)

    return response


def load_credentials():
    """Kayitli TUM kullanicilarin listesini doner (cok-kullanicili format).
    Eski tek-kullanicili format ile karsilasilirsa otomatik gocurulur."""
    if not CRED_FILE.exists():
        return None
    with open(CRED_FILE) as f:
        data = json.load(f)
    if "users" not in data and "username" in data:
        # eski format - otomatik goc
        data = {"users": [{"username": data["username"], "password_hash": data["password_hash"], "created_at": None}]}
        save_credentials(data)
    return data


def save_credentials(data):
    CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CRED_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CRED_FILE, 0o600)


def find_user(creds, username):
    for u in creds.get("users", []):
        if u["username"] == username:
            return u
    return None


def require_login(request: Request):
    if not request.session.get("logged_in"):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return True


def require_login_api(request: Request):
    if not request.session.get("logged_in"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Oturum gerekli")
    return True


@app.exception_handler(HTTPException)
async def auth_redirect_handler(request: Request, exc: HTTPException):
    if exc.status_code == status.HTTP_303_SEE_OTHER and "Location" in exc.headers:
        return RedirectResponse(url=exc.headers["Location"], status_code=303)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if request.session.get("logged_in"):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    creds = load_credentials()
    if not creds:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Sistem henüz kurulmamış. Sunucuda 'sudo stratum-panel-set-password' çalıştırın."},
            status_code=500,
        )

    user = find_user(creds, username)
    valid = user is not None and bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8"))
    if not valid:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Kullanıcı adı veya şifre hatalı."},
            status_code=401,
        )

    request.session["logged_in"] = True
    request.session["username"] = username
    return RedirectResponse(url="/", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "username": request.session.get("username", "admin"),
            "enabled_widgets": get_dashboard_widgets_config(),
            "all_widgets": DASHBOARD_WIDGET_DEFS,
        },
    )


@app.get("/api/status")
async def api_status(_=Depends(require_login_api)):
    return JSONResponse({
        "interfaces": get_interfaces(),
        "services": get_services(),
        "dns": get_dns_stats(),
        "threats": get_threat_stats(),
        "webfilter": get_webfilter_stats(),
        "system": get_system_stats(),
        "traffic": get_traffic_stats(),
        "temperature": get_temperature_stats(),
        "multiwan": get_dashboard_multiwan_summary(),
        "vpn": get_dashboard_vpn_summary(),
        "geoblock": get_dashboard_geoblock_summary(),
        "backup": get_dashboard_backup_summary(),
        "qos": get_dashboard_qos_summary(),
    })


@app.get("/api/dashboard-widgets")
async def api_get_dashboard_widgets(_=Depends(require_login_api)):
    return JSONResponse({
        "enabled": get_dashboard_widgets_config(),
        "all": DASHBOARD_WIDGET_DEFS,
    })


@app.post("/api/dashboard-widgets")
async def api_save_dashboard_widgets(request: Request, _=Depends(require_login)):
    body = await request.json()
    enabled = body.get("enabled", [])
    valid_keys = {w["key"] for w in DASHBOARD_WIDGET_DEFS}
    enabled = [w for w in enabled if w in valid_keys]
    save_dashboard_widgets_config(enabled)
    return JSONResponse({"success": True})


def read_portforward_rules():
    rules = []
    path = "/etc/nftables/portforward-rules.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) == 9:
                    rules.append({
                        "proto": parts[0], "ext_port": parts[1],
                        "internal_ip": parts[2], "internal_port": parts[3],
                        "allowed_source": parts[4], "enabled": parts[5] == "yes",
                        "description": parts[6], "wan_iface": parts[7], "local_iface": parts[8],
                    })
                elif len(parts) == 8:
                    rules.append({
                        "proto": parts[0], "ext_port": parts[1],
                        "internal_ip": parts[2], "internal_port": parts[3],
                        "allowed_source": parts[4], "enabled": parts[5] == "yes",
                        "description": parts[6], "wan_iface": parts[7], "local_iface": "any",
                    })
                elif len(parts) == 7:
                    rules.append({
                        "proto": parts[0], "ext_port": parts[1],
                        "internal_ip": parts[2], "internal_port": parts[3],
                        "allowed_source": parts[4], "enabled": parts[5] == "yes",
                        "description": parts[6], "wan_iface": "any", "local_iface": "any",
                    })
                elif len(parts) == 6:
                    rules.append({
                        "proto": parts[0], "ext_port": parts[1],
                        "internal_ip": parts[2], "internal_port": parts[3],
                        "allowed_source": parts[4], "enabled": parts[5] == "yes",
                        "description": "", "wan_iface": "any", "local_iface": "any",
                    })
    return rules


def read_nat1to1_rules():
    rules = []
    path = "/etc/nftables/nat1to1-rules.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) == 6:
                    rules.append({
                        "public_ip": parts[0], "internal_ip": parts[1],
                        "allowed_source": parts[2], "enabled": parts[3] == "yes",
                        "description": parts[4], "wan_iface": parts[5],
                    })
                elif len(parts) == 5:
                    rules.append({
                        "public_ip": parts[0], "internal_ip": parts[1],
                        "allowed_source": parts[2], "enabled": parts[3] == "yes",
                        "description": parts[4], "wan_iface": "any",
                    })
                elif len(parts) == 4:
                    rules.append({
                        "public_ip": parts[0], "internal_ip": parts[1],
                        "allowed_source": parts[2], "enabled": parts[3] == "yes",
                        "description": "", "wan_iface": "any",
                    })
    return rules


def get_wan_iface_names():
    return [i["name"] for i in get_interface_details() if i.get("vlan_id") is None]


def validate_ip_in_iface_subnet(ip_str, iface_name):
    """local_iface 'any' ise kisitlama yok. Aksi halde IP'nin secilen VLAN'in
    alt agina gercekten dahil olup olmadigini dogrular."""
    if iface_name in ("any", "", None):
        return True, None
    ifaces = {i["name"]: i["cidr"] for i in get_lan_ifaces_with_subnets()}
    cidr = ifaces.get(iface_name)
    if not cidr:
        return False, f"Unknown interface: {iface_name}"
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        addr = ipaddress.ip_address(ip_str)
        if addr not in network:
            return False, f'"{ip_str}" is not within {iface_name}\'s subnet ({cidr}). Choose a different interface or correct the IP address.'
        return True, None
    except ValueError:
        return False, f'"{ip_str}" is not a valid IP address.'


@app.get("/nat", response_class=HTMLResponse)
async def nat_page(request: Request, _=Depends(require_login)):
    all_objects = get_objects()
    return templates.TemplateResponse(
        request, "nat_portforward.html",
        {
            "username": request.session.get("username", "admin"),
            "portforward_rules": read_portforward_rules(),
            "wan_ifaces": get_wan_iface_names(),
            "lan_ifaces": get_lan_ifaces_with_subnets(),
            "address_objects": [o for o in all_objects if o["type"] == "address"],
            "port_objects": [o for o in all_objects if o["type"] == "port"],
            "error": None,
        }
    )


@app.get("/nat/1to1", response_class=HTMLResponse)
async def nat_1to1_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "nat_1to1.html",
        {
            "username": request.session.get("username", "admin"),
            "nat1to1_rules": read_nat1to1_rules(),
            "wan_ifaces": get_wan_iface_names(),
        }
    )


@app.post("/nat/portforward/add")
async def nat_pf_add(request: Request, proto: str = Form(...), ext_port: str = Form(...),
                      internal_ip: str = Form(...), internal_port: str = Form(...),
                      local_iface: str = Form("any"),
                      source: str = Form("any"), description: str = Form(""),
                      wan_iface: str = Form("any"), _=Depends(require_login)):
    valid, error = validate_ip_in_iface_subnet(internal_ip, local_iface)
    if not valid:
        return templates.TemplateResponse(
            request, "nat_portforward.html",
            {
                "username": request.session.get("username", "admin"),
                "portforward_rules": read_portforward_rules(),
                "wan_ifaces": get_wan_iface_names(),
                "lan_ifaces": get_lan_ifaces_with_subnets(),
                "error": error,
            },
            status_code=400,
        )
    subprocess.run(["/usr/local/sbin/fw-alias", "portforward", "add", proto, ext_port, internal_ip, internal_port, source, description, wan_iface, local_iface])
    return RedirectResponse(url="/nat", status_code=303)


@app.post("/nat/portforward/delete")
async def nat_pf_delete(request: Request, proto: str = Form(...), ext_port: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "portforward", "del", proto, ext_port])
    return RedirectResponse(url="/nat", status_code=303)


@app.post("/nat/portforward/toggle")
async def nat_pf_toggle(request: Request, proto: str = Form(...), ext_port: str = Form(...),
                         action: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "portforward", action, proto, ext_port])
    return RedirectResponse(url="/nat", status_code=303)


@app.post("/nat/nat1to1/add")
async def nat_11_add(request: Request, public_ip: str = Form(...), internal_ip: str = Form(...),
                      source: str = Form("any"), description: str = Form(""),
                      wan_iface: str = Form("any"), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "nat1to1", "add", public_ip, internal_ip, source, description, wan_iface])
    return RedirectResponse(url="/nat/1to1", status_code=303)


@app.post("/nat/nat1to1/delete")
async def nat_11_delete(request: Request, public_ip: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "nat1to1", "del", public_ip])
    return RedirectResponse(url="/nat/1to1", status_code=303)


@app.post("/nat/nat1to1/toggle")
async def nat_11_toggle(request: Request, public_ip: str = Form(...), action: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "nat1to1", action, public_ip])
    return RedirectResponse(url="/nat/1to1", status_code=303)


@app.get("/interfaces", response_class=HTMLResponse)
async def interfaces_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "interfaces.html",
        {
            "username": request.session.get("username", "admin"),
            "interfaces": get_interface_details(),
            "pending_change": request.query_params.get("pending_change"),
            "pending_iface": request.query_params.get("pending_iface"),
            "nics": get_physical_nic_details(),
            "error": request.query_params.get("nic_error", "").replace("+", " ") or None,
            "reboot_needed": None,
            "nic_applied": request.query_params.get("nic_applied"),
            "vlan_parent_candidates": get_vlan_parent_candidates(),
            "vlans_by_parent": get_vlans_by_parent(),
        }
    )


RPZ_TIMER_FILE = "/etc/systemd/system/rpz-update.timer"
RPZ_FREQUENCIES = {
    "hourly": "*-*-* *:00:00",
    "daily": "*-*-* 04:00:00",
    "weekly": "Sun 04:00",
}


def get_current_rpz_frequency():
    if os.path.exists(RPZ_TIMER_FILE):
        with open(RPZ_TIMER_FILE) as f:
            for line in f:
                if line.strip().startswith("OnCalendar="):
                    value = line.strip().split("=", 1)[1]
                    for freq, cal in RPZ_FREQUENCIES.items():
                        if cal == value:
                            return freq
                    return "custom"
    return "weekly"


@app.get("/webfilter", response_class=HTMLResponse)
async def webfilter_page(request: Request, _=Depends(require_login)):
    policies = get_webfilter_policies()
    policy_cidrs = {p["cidr"] for p in policies}
    available_networks = [n for n in get_lan_ifaces_with_subnets() if n["cidr"] not in policy_cidrs]
    return templates.TemplateResponse(
        request, "webfilter.html",
        {
            "username": request.session.get("username", "admin"),
            "policies": policies,
            "all_categories": ALL_WEBFILTER_CATEGORIES,
            "available_networks": available_networks,
            "rpz_summary": get_rpz_update_summary(),
            "rpz_frequency": get_current_rpz_frequency(),
            "update_started": request.query_params.get("update_started"),
        }
    )


@app.post("/webfilter/update-now")
async def webfilter_update_now(request: Request, _=Depends(require_login)):
    subprocess.Popen(["systemctl", "start", "rpz-update.service"])
    return JSONResponse({"started": True})


@app.get("/webfilter/update-status")
async def webfilter_update_status(request: Request, _=Depends(require_login)):
    active = subprocess.run(["systemctl", "is-active", "rpz-update.service"], capture_output=True, text=True).stdout.strip()
    running = active in ("active", "activating")
    result = {"running": running}
    if not running:
        result["summary"] = get_rpz_update_summary()
    return JSONResponse(result)


@app.post("/webfilter/frequency")
async def webfilter_set_frequency(request: Request, frequency: str = Form(...), _=Depends(require_login)):
    if frequency not in RPZ_FREQUENCIES:
        return RedirectResponse(url="/webfilter", status_code=303)

    with open(RPZ_TIMER_FILE) as f:
        content = f.read()
    new_content = re.sub(r'OnCalendar=.*', "OnCalendar=" + RPZ_FREQUENCIES[frequency], content)
    with open(RPZ_TIMER_FILE, "w") as f:
        f.write(new_content)

    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "restart", "rpz-update.timer"])

    return RedirectResponse(url="/webfilter", status_code=303)


@app.post("/webfilter/set")
async def webfilter_set(request: Request, cidr: str = Form(...), _=Depends(require_login)):
    form = await request.form()
    selected = form.getlist("categories")
    if selected:
        subprocess.run(["/usr/local/sbin/webfilter-policy", "set", cidr, *selected])
    else:
        subprocess.run(["/usr/local/sbin/webfilter-policy", "clear", cidr])
    return RedirectResponse(url="/webfilter", status_code=303)


@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, _=Depends(require_login)):
    all_objects = get_objects()
    return templates.TemplateResponse(
        request, "rules.html",
        {
            "username": request.session.get("username", "admin"),
            "forward_chain": get_live_chain_text("forward"),
            "input_chain": get_live_chain_text("input"),
            "ip_blocklist": get_ip_blocklist(),
            "mac_blocklist": get_mac_blocklist(),
            "custom_rules": get_custom_rules(),
            "lan_ifaces": get_lan_ifaces_with_subnets(),
            "portforward_rules": read_portforward_rules(),
            "nat1to1_rules": read_nat1to1_rules(),
            "port_objects": [o for o in all_objects if o["type"] == "port"],
        }
    )


@app.post("/rules/blocklist/add")
async def rules_blocklist_add(request: Request, ip: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "blocklist", "add", ip])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/blocklist/delete")
async def rules_blocklist_delete(request: Request, ip: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "blocklist", "del", ip])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/mac/add")
async def rules_mac_add(request: Request, mac: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "mac", "add", mac])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/mac/delete")
async def rules_mac_delete(request: Request, mac: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "mac", "del", mac])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/custom/add")
async def rules_custom_add(request: Request, interface: str = Form("any"), action: str = Form(...),
                            protocol: str = Form("any"), source: str = Form("any"), src_port: str = Form("any"),
                            destination: str = Form("any"), dst_port: str = Form("any"),
                            description: str = Form(""), log: str = Form("no"), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-rule", "add", interface, action, protocol, source, src_port, destination, dst_port, description, log])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/custom/delete")
async def rules_custom_delete(request: Request, rule_id: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-rule", "del", rule_id])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/custom/toggle")
async def rules_custom_toggle(request: Request, rule_id: str = Form(...), action: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-rule", action, rule_id])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/custom/move")
async def rules_custom_move(request: Request, rule_id: str = Form(...), direction: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-rule", "move", rule_id, direction])
    return RedirectResponse(url="/rules", status_code=303)


@app.post("/rules/custom/edit")
async def rules_custom_edit(request: Request, rule_id: str = Form(...), interface: str = Form("any"),
                             action: str = Form(...), protocol: str = Form("any"), source: str = Form("any"),
                             src_port: str = Form("any"), destination: str = Form("any"), dst_port: str = Form("any"),
                             description: str = Form(""), log: str = Form("no"), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-rule", "edit", rule_id, interface, action, protocol, source, src_port, destination, dst_port, description, log])
    return RedirectResponse(url="/rules", status_code=303)


@app.get("/objects", response_class=HTMLResponse)
async def objects_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "objects.html",
        {
            "username": request.session.get("username", "admin"),
            "objects": get_objects(),
        }
    )


@app.post("/objects/create")
async def objects_create(request: Request, name: str = Form(...), otype: str = Form(...),
                          description: str = Form(""), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-object", "create", name, otype, description])
    return RedirectResponse(url="/objects", status_code=303)


@app.post("/objects/add")
async def objects_add(request: Request, name: str = Form(...), value: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-object", "add", name, value])
    return RedirectResponse(url="/objects", status_code=303)


@app.post("/objects/remove")
async def objects_remove(request: Request, name: str = Form(...), value: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-object", "remove", name, str(value)])
    return RedirectResponse(url="/objects", status_code=303)


@app.post("/objects/delete")
async def objects_delete(request: Request, name: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-object", "delete", name])
    return RedirectResponse(url="/objects", status_code=303)


VLAN_NETWORK_DIR = "/etc/systemd/network"


def get_vlan_network_file(vlan_name):
    for prefix in ("40", "20"):
        path = f"{VLAN_NETWORK_DIR}/{prefix}-{vlan_name}.network"
        if os.path.exists(path):
            return path
    return None


@app.get("/interfaces/edit/{iface_name}", response_class=HTMLResponse)
async def interface_edit_page(request: Request, iface_name: str, _=Depends(require_login)):

    path = get_vlan_network_file(iface_name)
    if not path:
        return RedirectResponse(url="/interfaces", status_code=303)
    with open(path) as f:
        content = f.read()
    match = re.search(r'^Address=(.+)$', content, re.MULTILINE)
    current_cidr = match.group(1) if match else ""
    return templates.TemplateResponse(
        request, "interface_edit.html",
        {
            "username": request.session.get("username", "admin"),
            "iface_name": iface_name,
            "current_cidr": current_cidr,
            "error": None,
        }
    )


@app.post("/interfaces/edit/{iface_name}")
async def interface_edit_apply(request: Request, iface_name: str, new_cidr: str = Form(...), new_iface_name: str = Form(""), _=Depends(require_login)):
    old_iface = iface_name
    new_iface = new_iface_name.strip() if new_iface_name.strip() else old_iface

    # İsim değişikliği varsa lan-mode-apply scriptini çalıştır
    if new_iface != old_iface:
        result = subprocess.run(
            ["/usr/local/sbin/lan-mode-apply", old_iface, new_iface],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return templates.TemplateResponse(
                request, "interface_edit.html",
                {
                    "username": request.session.get("username", "admin"),
                    "iface_name": old_iface,
                    "current_cidr": new_cidr,
                    "error": result.stderr.strip() or result.stdout.strip() or "Interface rename failed.",
                },
                status_code=400,
            )

    # Yeni isimle .network dosyasını bul
    path = get_vlan_network_file(new_iface)
    if not path:
        return RedirectResponse(url="/interfaces", status_code=303)

    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', new_cidr):
        return templates.TemplateResponse(
            request, "interface_edit.html",
            {
                "username": request.session.get("username", "admin"),
                "iface_name": new_iface,
                "current_cidr": new_cidr,
                "error": "Invalid CIDR format (expected e.g. 10.10.20.1/24)",
            },
            status_code=400,
        )

    change_id = safe_apply.stage_change([path], reload_cmd=["networkctl", "reload"])

    with open(path) as f:
        old_content = f.read()
    new_content = re.sub(r'^Address=.+$', f'Address={new_cidr}', old_content, flags=re.MULTILINE)
    with open(path, "w") as f:
        f.write(new_content)

    subprocess.run(["networkctl", "reload"])
    safe_apply.launch_revert_watcher(change_id, delay_seconds=90)

    return RedirectResponse(url=f"/interfaces?pending_change={change_id}&pending_iface={new_iface}", status_code=303)


@app.post("/interfaces/confirm/{change_id}")
async def interface_confirm(request: Request, change_id: str, _=Depends(require_login)):
    ok = safe_apply.confirm_change(change_id)
    return JSONResponse({"confirmed": ok})


@app.get("/dhcp", response_class=HTMLResponse)
async def dhcp_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "dhcp.html",
        {
            "username": request.session.get("username", "admin"),
            "leases": get_dhcp_leases(),
            "reservations": get_dhcp_reservations(),
            "dhcp_subnets": get_dhcp_subnets(),
            "error": None,
        }
    )


@app.post("/dhcp/reservation/add")
async def dhcp_reservation_add(request: Request, vlan_id: str = Form(...), mac: str = Form(...),
                                ip: str = Form(...), hostname: str = Form(""), _=Depends(require_login)):
    args = ["/usr/local/sbin/dhcp-reserve", "add", vlan_id, mac, ip]
    if hostname:
        args.append(hostname)
    result = subprocess.run(args, capture_output=True, text=True)
    error = result.stderr.strip() if result.returncode != 0 else None
    return templates.TemplateResponse(
        request, "dhcp.html",
        {
            "username": request.session.get("username", "admin"),
            "leases": get_dhcp_leases(),
            "reservations": get_dhcp_reservations(),
            "dhcp_subnets": get_dhcp_subnets(),
            "error": error,
        },
        status_code=400 if error else 200,
    ) if error else RedirectResponse(url="/dhcp", status_code=303)


@app.post("/dhcp/reservation/delete")
async def dhcp_reservation_delete(request: Request, mac: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/dhcp-reserve", "del", mac])
    return RedirectResponse(url="/dhcp", status_code=303)


@app.post("/dhcp/reservation/from_lease")
async def dhcp_reservation_from_lease(request: Request, vlan_id: str = Form(...), mac: str = Form(...),
                                       ip: str = Form(...), hostname: str = Form(""), _=Depends(require_login)):
    args = ["/usr/local/sbin/dhcp-reserve", "add", vlan_id, mac, ip]
    if hostname:
        args.append(hostname)
    subprocess.run(args)
    return RedirectResponse(url="/dhcp", status_code=303)


@app.post("/dhcp/pool/edit")
async def dhcp_pool_edit(request: Request, vlan_id: str = Form(...), start_ip: str = Form(...),
                          end_ip: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/dhcp-pool-set", vlan_id, start_ip, end_ip],
        capture_output=True, text=True,
    )
    error = result.stderr.strip() if result.returncode != 0 else None
    if error:
        return templates.TemplateResponse(
            request, "dhcp.html",
            {
                "username": request.session.get("username", "admin"),
                "leases": get_dhcp_leases(),
                "reservations": get_dhcp_reservations(),
                "dhcp_subnets": get_dhcp_subnets(),
                "error": error,
            },
            status_code=400,
        )
    return RedirectResponse(url="/dhcp", status_code=303)


@app.get("/blocklist", response_class=HTMLResponse)
async def blocklist_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "blocklist.html",
        {
            "username": request.session.get("username", "admin"),
            "ip_blocklist": get_ip_blocklist(),
            "mac_blocklist": get_mac_blocklist(),
            "forward_chain": get_live_chain_text("forward"),
            "input_chain": get_live_chain_text("input"),
        }
    )


@app.post("/blocklist/ip/add")
async def blocklist_ip_add(request: Request, ip: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "blocklist", "add", ip])
    return RedirectResponse(url="/blocklist", status_code=303)


@app.post("/blocklist/ip/delete")
async def blocklist_ip_delete(request: Request, ip: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "blocklist", "del", ip])
    return RedirectResponse(url="/blocklist", status_code=303)


@app.post("/blocklist/mac/add")
async def blocklist_mac_add(request: Request, mac: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "mac", "add", mac])
    return RedirectResponse(url="/blocklist", status_code=303)


@app.post("/blocklist/mac/delete")
async def blocklist_mac_delete(request: Request, mac: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/fw-alias", "mac", "del", mac])
    return RedirectResponse(url="/blocklist", status_code=303)


@app.get("/dns", response_class=HTMLResponse)
async def dns_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "dns.html",
        {
            "username": request.session.get("username", "admin"),
            "dns_stats": get_dns_stats(),
            "feeds": get_dnsbl_feeds(),
            "lan_ifaces": get_lan_ifaces_with_subnets(),
            "update_log": get_last_rpz_update_log(),
            "error": None,
        }
    )


@app.post("/dns/feed/set_scope")
async def dns_feed_set_scope(request: Request, feed_id: str = Form(...), scope_type: str = Form(...),
                              targets: list = Form([]), _=Depends(require_login)):
    scope_arg = "all" if scope_type == "all" else ",".join(targets) if targets else "all"
    result = subprocess.run(
        ["/usr/local/sbin/dnsbl-feed", "set-scope", feed_id, scope_arg],
        capture_output=True, text=True,
    )
    error = result.stderr.strip() if result.returncode != 0 else None
    if error:
        return templates.TemplateResponse(
            request, "dns.html",
            {
                "username": request.session.get("username", "admin"),
                "dns_stats": get_dns_stats(),
                "feeds": get_dnsbl_feeds(),
                "lan_ifaces": get_lan_ifaces_with_subnets(),
                "update_log": get_last_rpz_update_log(),
                "error": error,
            },
            status_code=400,
        )
    return RedirectResponse(url="/dns", status_code=303)


@app.get("/dns/catalog", response_class=HTMLResponse)
async def dns_catalog_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "dns_catalog.html",
        {
            "username": request.session.get("username", "admin"),
            "catalog": get_feed_catalog(),
        }
    )


@app.post("/dns/catalog/add_one")
async def dns_catalog_add_one(request: Request, name: str = Form(...), feed_url: str = Form(...),
                               format: str = Form(...), website: str = Form(""), group: str = Form("Catalog"),
                               _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/dnsbl-feed", "add", name, group, feed_url, format, website])
    run_rpz_update_and_log()
    return RedirectResponse(url="/dns/catalog", status_code=303)


@app.post("/dns/catalog/add_group")
async def dns_catalog_add_group(request: Request, group_name: str = Form(...), _=Depends(require_login)):
    catalog = get_feed_catalog()
    bulk_lines = []
    for group in catalog:
        if group["name"] == group_name:
            for feed in group["feeds"]:
                if not feed["already_added"]:
                    bulk_lines.append(f'{feed["name"]}|{group_name}|{feed["url"]}|{feed["format"]}|{feed.get("website", "")}')
    if bulk_lines:
        subprocess.run(
            ["/usr/local/sbin/dnsbl-feed", "bulk-add"],
            input="\n".join(bulk_lines), capture_output=True, text=True,
        )
        run_rpz_update_and_log()
    return RedirectResponse(url="/dns/catalog", status_code=303)


@app.post("/dns/feed/edit")
async def dns_feed_edit(request: Request, feed_id: str = Form(...), name: str = Form(...), group: str = Form(...),
                         feed_url: str = Form(...), format: str = Form(...), website: str = Form(""), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/dnsbl-feed", "edit", feed_id, name, group, feed_url, format, website],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        run_rpz_update_and_log()
    return RedirectResponse(url="/dns", status_code=303)


def run_rpz_update_and_log():
    result = subprocess.run(["/usr/local/sbin/rpz-update"], capture_output=True, text=True)
    log_dir = "/var/log/stratum-panel"
    os.makedirs(log_dir, exist_ok=True)
    with open(f"{log_dir}/rpz-update.log", "w") as f:
        f.write(f"Run at: {subprocess.run(['date'], capture_output=True, text=True).stdout.strip()}\n")
        f.write(f"Exit code: {result.returncode}\n\n")
        f.write(result.stdout)
        f.write(result.stderr)
    return result.returncode


@app.post("/dns/feed/add")
async def dns_feed_add(request: Request, name: str = Form(...), group: str = Form(...),
                        feed_url: str = Form(...), format: str = Form(...),
                        website: str = Form(""), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/dnsbl-feed", "add", name, group, feed_url, format, website],
        capture_output=True, text=True,
    )
    error = result.stderr.strip() if result.returncode != 0 else None
    if not error:
        run_rpz_update_and_log()
    if error:
        return templates.TemplateResponse(
            request, "dns.html",
            {
                "username": request.session.get("username", "admin"),
                "dns_stats": get_dns_stats(),
                "feeds": get_dnsbl_feeds(),
                "error": error,
            },
            status_code=400,
        )
    return RedirectResponse(url="/dns", status_code=303)


@app.post("/dns/feed/toggle")
async def dns_feed_toggle(request: Request, feed_id: str = Form(...), action: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/dnsbl-feed", action, feed_id])
    return RedirectResponse(url="/dns", status_code=303)


@app.post("/dns/feed/delete")
async def dns_feed_delete(request: Request, feed_id: str = Form(...), _=Depends(require_login)):
    subprocess.run(["/usr/local/sbin/dnsbl-feed", "delete", feed_id])
    return RedirectResponse(url="/dns", status_code=303)


@app.post("/dns/feed/update")
async def dns_feed_update(request: Request, _=Depends(require_login)):
    run_rpz_update_and_log()
    return RedirectResponse(url="/dns", status_code=303)


@app.post("/dns/feed/bulk_add")
async def dns_feed_bulk_add(request: Request, bulk_text: str = Form(""), _=Depends(require_login)):
    log_dir = "/var/log/stratum-panel"
    os.makedirs(log_dir, exist_ok=True)

    if not bulk_text.strip():
        with open(f"{log_dir}/bulk-import.log", "w") as f:
            f.write("Nothing was submitted - the text box was empty. Paste at least one line in the format:\nname|group|feed_url|format|website(optional)")
        return RedirectResponse(url="/dns", status_code=303)

    result = subprocess.run(
        ["/usr/local/sbin/dnsbl-feed", "bulk-add"],
        input=bulk_text, capture_output=True, text=True,
    )
    with open(f"{log_dir}/bulk-import.log", "w") as f:
        f.write(f"Exit code: {result.returncode}\n\n")
        f.write(result.stdout)
        f.write(result.stderr)
    run_rpz_update_and_log()
    return RedirectResponse(url="/dns", status_code=303)


@app.post("/interfaces/vlan/create")
async def interfaces_vlan_create(request: Request, vlan_id: str = Form(...), parent_iface: str = Form(...),
                                  role_name: str = Form(""),
                                  gateway_cidr: str = Form(""), dhcp_start: str = Form(""),
                                  dhcp_end: str = Form(""), isolated: str = Form("no"), _=Depends(require_login)):
    parent_role = None
    for cand in get_vlan_parent_candidates():
        if cand["name"] == parent_iface:
            parent_role = cand["role_type"]
            break

    if parent_role == "wan":
        result = subprocess.run(
            ["/usr/local/sbin/wan-vlan-create", vlan_id, parent_iface],
            capture_output=True, text=True,
        )
    else:
        isolated_arg = "yes" if isolated == "yes" else "no"
        result = subprocess.run(
            ["/usr/local/sbin/vlan-create", vlan_id, parent_iface, role_name, gateway_cidr, dhcp_start, dhcp_end, isolated_arg],
            capture_output=True, text=True,
        )
    error = result.stderr.strip() if result.returncode != 0 else None
    if error:
        return templates.TemplateResponse(
            request, "interfaces.html",
            {
                "username": request.session.get("username", "admin"),
                "interfaces": get_interface_details(),
                "pending_change": None,
                "pending_iface": None,
                "nics": get_physical_nic_details(),
                "vlan_parent_candidates": get_vlan_parent_candidates(),
                "vlans_by_parent": get_vlans_by_parent(),
                "error": error,
            },
            status_code=400,
        )
    return RedirectResponse(url="/interfaces", status_code=303)


@app.post("/interfaces/vlan/delete")
async def interfaces_vlan_delete(request: Request, vlan_id: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/vlan-delete", vlan_id],
        capture_output=True, text=True,
    )
    error = result.stderr.strip() if result.returncode != 0 else None
    if error:
        return templates.TemplateResponse(
            request, "interfaces.html",
            {
                "username": request.session.get("username", "admin"),
                "interfaces": get_interface_details(),
                "pending_change": None,
                "pending_iface": None,
                "nics": get_physical_nic_details(),
                "vlan_parent_candidates": get_vlan_parent_candidates(),
                "vlans_by_parent": get_vlans_by_parent(),
                "error": error,
            },
            status_code=400,
        )
    return RedirectResponse(url="/interfaces", status_code=303)


@app.post("/interfaces/nic/reassign")
async def interfaces_nic_reassign(request: Request, _=Depends(require_login)):
    # ONEMLI: donanimdan BAGIMSIZ olmasi icin, gecerli MAC listesi HER
    # CAGRIDA canli sistemden (get_physical_nic_details) DINAMIK olarak
    # okunur - sabit/hard-coded bir liste KULLANILMAZ. Boylece bu kod,
    # HANGI DONANIMA kurulursa kurulsun dogru calisir (canli ortamda
    # dogrulanmis, gercek bir tasarim hatasiydi - sabit liste SADECE
    # tek bir cihazin kendi NIC'lerine gore yazilmisti).
    known_macs = {nic["mac"].lower() for nic in get_physical_nic_details() if nic.get("mac") and nic["mac"] != "?"}
    form = await request.form()
    args = []
    for key, value in form.items():
        if key.startswith("role_"):
            mac = key.replace("role_", "")
            if mac.lower() in known_macs:
                args.append(f"{mac}={value}")
    # ONEMLI: timeout EKLENIR - nic-configure'in ICINDEKI bir adim
    # (orn. WAN icin DHCP client'in IP almaya calismasi, ya da
    # systemctl restart) beklenenden UZUN surerse, panel SONSUZA KADAR
    # BEKLEMEZ, bir HATA ile GERI DONER (canli ortamda dogrulanmis,
    # gercek bir sorundu - WAN atamasi panelde "sonsuz donguye"
    # giriyormus gibi GORUNUYORDU).
    try:
        result = subprocess.run(
            ["/usr/local/sbin/nic-configure"] + args,
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return RedirectResponse(url="/interfaces?nic_error=Operation+timed+out+after+30+seconds", status_code=303)
    if result.returncode != 0:
        combined = (result.stderr.strip() + " " + result.stdout.strip()).strip()
        error = combined.replace(" ", "+").replace(chr(10), "+")
        return RedirectResponse(url=f"/interfaces?nic_error={error}", status_code=303)
    return RedirectResponse(url="/interfaces?nic_applied=1", status_code=303)


def get_wan_security_config(iface_name):
    result = {"block_private": "no", "block_bogons": "no"}
    path = "/etc/nftables/wan-security.conf"
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 3 and parts[0] == iface_name:
                    result["block_private"] = parts[1]
                    result["block_bogons"] = parts[2]
    return result


def get_wan_current_config(iface_name):
    network_file = f"/etc/systemd/network/20-{iface_name}.network"
    result = {"mode": "dhcp", "ip": "", "prefix": "24", "gateway": ""}
    if os.path.exists(f"/etc/ppp/peers/{iface_name}"):
        result["mode"] = "pppoe"
        return result
    if os.path.exists(network_file):
        with open(network_file) as f:
            content = f.read()
        if "DHCP=yes" not in content and "Address=" in content:
            result["mode"] = "static"
            for line in content.splitlines():
                if line.startswith("Address="):
                    addr_cidr = line.replace("Address=", "").strip()
                    if "/" in addr_cidr:
                        result["ip"], result["prefix"] = addr_cidr.split("/", 1)
                elif line.startswith("Gateway="):
                    result["gateway"] = line.replace("Gateway=", "").strip()
    return result


@app.get("/interfaces/wan-config/{iface_name}", response_class=HTMLResponse)
async def interfaces_wan_config_page(request: Request, iface_name: str, _=Depends(require_login)):
    cfg = get_wan_current_config(iface_name)
    sec = get_wan_security_config(iface_name)
    return templates.TemplateResponse(
        request, "wan_config.html",
        {
            "username": request.session.get("username", "admin"),
            "iface_name": iface_name,
            "current_mode": cfg["mode"],
            "current_ip": cfg["ip"],
            "current_prefix": cfg["prefix"],
            "current_gateway": cfg["gateway"],
            "block_private": sec["block_private"] == "yes",
            "block_bogons": sec["block_bogons"] == "yes",
            "error": None,
        }
    )


@app.post("/interfaces/wan-config/{iface_name}")
async def interfaces_wan_config_apply(request: Request, iface_name: str, mode: str = Form(...),
                                       pppoe_user: str = Form(""), pppoe_pass: str = Form(""),
                                       static_ip: str = Form(""), static_prefix: str = Form(""),
                                       static_gateway: str = Form(""),
                                       new_iface_name: str = Form(""),
                                       block_private: str = Form("no"), block_bogons: str = Form("no"),
                                       _=Depends(require_login)):
    old_iface = iface_name
    new_iface = new_iface_name.strip() if new_iface_name.strip() else old_iface

    def render_error(msg):
        return templates.TemplateResponse(
            request, "wan_config.html",
            {
                "username": request.session.get("username", "admin"),
                "iface_name": old_iface,
                "current_mode": mode,
                "current_ip": static_ip,
                "current_prefix": static_prefix,
                "current_gateway": static_gateway,
                "error": msg,
            },
            status_code=400,
        )

    if mode == "dhcp":
        args = ["/usr/local/sbin/wan-mode-apply", old_iface, new_iface, "dhcp"]
    elif mode == "pppoe":
        if not pppoe_user or not pppoe_pass:
            return render_error("PPPoE username and password are required.")
        args = ["/usr/local/sbin/wan-mode-apply", old_iface, new_iface, "pppoe", pppoe_user, pppoe_pass]
    elif mode == "static":
        if not static_ip or not static_prefix or not static_gateway:
            return render_error("IP address, subnet, and gateway are all required for static configuration.")
        args = ["/usr/local/sbin/wan-mode-apply", old_iface, new_iface, "static", static_ip, static_prefix, static_gateway]
    else:
        return RedirectResponse(url="/interfaces", status_code=303)

    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        return render_error(result.stderr.strip() or result.stdout.strip())

    sec_result = subprocess.run(
        ["/usr/local/sbin/wan-security-set", new_iface, block_private, block_bogons],
        capture_output=True, text=True,
    )
    if sec_result.returncode != 0:
        return render_error(sec_result.stderr.strip() or sec_result.stdout.strip())

    return RedirectResponse(url="/interfaces?nic_applied=1", status_code=303)


def get_opt_current_config(iface_name):
    result = {"gateway_ip": "", "prefix": "24", "dhcp_start": "", "dhcp_end": "", "display_name": ""}
    try:
        with open("/etc/kea/kea-dhcp4.conf") as f:
            kea_data = json.load(f)
        for s in kea_data["Dhcp4"]["subnet4"]:
            if s.get("interface") == iface_name:
                for opt in s.get("option-data", []):
                    if opt.get("name") == "routers":
                        result["gateway_ip"] = opt.get("data", "")
                if "/" in s.get("subnet", ""):
                    result["prefix"] = s["subnet"].split("/")[1]
                pools = s.get("pools", [])
                if pools and " - " in pools[0].get("pool", ""):
                    result["dhcp_start"], result["dhcp_end"] = pools[0]["pool"].split(" - ")
    except Exception:
        pass

    result["description"] = ""
    opt_names_file = "/etc/nftables/opt-names.conf"
    if os.path.exists(opt_names_file):
        with open(opt_names_file) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 2 and parts[0] == iface_name:
                    result["display_name"] = parts[1]
                    result["description"] = parts[2] if len(parts) > 2 else ""
    return result


@app.get("/interfaces/opt-config/{iface_name}", response_class=HTMLResponse)
async def interfaces_opt_config_page(request: Request, iface_name: str, _=Depends(require_login)):
    cfg = get_opt_current_config(iface_name)
    return templates.TemplateResponse(
        request, "opt_config.html",
        {
            "username": request.session.get("username", "admin"),
            "iface_name": iface_name,
            "gateway_ip": cfg["gateway_ip"],
            "prefix": cfg["prefix"],
            "dhcp_start": cfg["dhcp_start"],
            "dhcp_end": cfg["dhcp_end"],
            "display_name": cfg["display_name"],
            "description": cfg["description"],
            "error": None,
        }
    )


@app.post("/interfaces/opt-config/{iface_name}")
async def interfaces_opt_config_apply(request: Request, iface_name: str,
                                       new_name: str = Form(""),
                                       gateway_ip: str = Form(""), prefix: str = Form("24"),
                                       dhcp_start: str = Form(""), dhcp_end: str = Form(""),
                                       display_name: str = Form(""), description: str = Form(""),
                                       _=Depends(require_login)):
    # ONEMLI: bu alanlar FastAPI seviyesinde ZORUNLU (Form(...)) DEGIL -
    # boyle olsaydi eksik bir alan durumunda FastAPI, bizim KENDI hata
    # sayfamiza (asagidaki templates.TemplateResponse) HIC ULASMADAN,
    # kullaniciya CIPLAK/teknik bir JSON hatasi gosterirdi. Kontrolu
    # BURADA, kendi kodumuzda yapip DUZGUN bir hata banner'i gosteriyoruz.
    missing = []
    if not new_name.strip():
        missing.append("Interface Name")
    if not gateway_ip.strip():
        missing.append("Gateway IP")
    if not dhcp_start.strip():
        missing.append("DHCP Start")
    if not dhcp_end.strip():
        missing.append("DHCP End")
    if not display_name.strip():
        missing.append("Display Name")

    if missing:
        return templates.TemplateResponse(
            request, "opt_config.html",
            {
                "username": request.session.get("username", "admin"),
                "iface_name": iface_name,
                "gateway_ip": gateway_ip,
                "prefix": prefix,
                "dhcp_start": dhcp_start,
                "dhcp_end": dhcp_end,
                "display_name": display_name,
                "description": description,
                "error": "Please fill in the following required fields: " + ", ".join(missing),
            },
            status_code=400,
        )

    gateway_cidr = f"{gateway_ip}/{prefix}"
    result = subprocess.run(
        ["/usr/local/sbin/opt-configure", iface_name, new_name, gateway_cidr, dhcp_start, dhcp_end, display_name, description],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return templates.TemplateResponse(
            request, "opt_config.html",
            {
                "username": request.session.get("username", "admin"),
                "iface_name": iface_name,
                "gateway_ip": gateway_ip,
                "prefix": prefix,
                "dhcp_start": dhcp_start,
                "dhcp_end": dhcp_end,
                "display_name": display_name,
                "description": description,
                "error": result.stderr.strip() or result.stdout.strip(),
            },
            status_code=400,
        )
    return RedirectResponse(url="/interfaces?nic_applied=1", status_code=303)


@app.post("/interfaces/opt/delete")
async def interfaces_opt_delete(request: Request, iface_name: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/opt-delete", iface_name], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or result.stdout.strip()).replace(" ", "+")
        return RedirectResponse(url=f"/interfaces?nic_error={error}", status_code=303)
    return RedirectResponse(url="/interfaces?nic_applied=1", status_code=303)

def get_wan_status():
    """wan-monitor.sh tarafından üretilen JSON dosyasını okur."""
    result = []
    path = "/var/log/stratum-panel/wan-status.json"
    if os.path.exists(path):
        try:
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, list):
                result = data
        except Exception:
            pass

    # Failover config'ten tier/enabled bilgisini al ve eşle
    conf_path = "/etc/nftables/wan-failover.conf"
    config = {}
    if os.path.exists(conf_path):
        with open(conf_path) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) == 4:
                    config[parts[0]] = {"tier": parts[1], "metric": parts[2], "enabled": parts[3]}
    for w in result:
        if w["name"] in config:
            w["tier"] = config[w["name"]]["tier"]
            w["enabled"] = config[w["name"]]["enabled"]
        else:
            w.setdefault("tier", "1")
            w.setdefault("enabled", "yes")
    return result


WAN_STATUS_FILE = "/var/log/stratum-panel/wan-status.json"
WAN_MONITOR_LOG = "/var/log/stratum-panel/wan-monitor.log"
WAN_FAILOVER_CONF = "/etc/nftables/wan-failover.conf"


def get_multiwan_status():
    if os.path.exists(WAN_STATUS_FILE):
        try:
            with open(WAN_STATUS_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def get_wan_monitor_log_tail(n=40):
    if os.path.exists(WAN_MONITOR_LOG):
        result = subprocess.run(["tail", "-n", str(n), WAN_MONITOR_LOG], capture_output=True, text=True)
        return result.stdout
    return ""


WAN_MODE_CONF = "/etc/nftables/wan-mode.conf"


def get_wan_mode():
    if os.path.exists(WAN_MODE_CONF):
        with open(WAN_MODE_CONF) as f:
            mode = f.read().strip()
            if mode == "balance":
                return "balance"
    return "failover"


@app.get("/multi-wan", response_class=HTMLResponse)
async def multi_wan_page(request: Request, _=Depends(require_login)):
    wans = get_multiwan_status()
    logs = get_wan_monitor_log_tail()
    return templates.TemplateResponse(
        request, "multi_wan.html",
        {
            "username": request.session.get("username", "admin"),
            "wans": wans,
            "logs": logs,
            "wan_mode": get_wan_mode(),
            "saved": request.query_params.get("saved"),
        }
    )


@app.post("/multi-wan/save")
async def multi_wan_save(request: Request, _=Depends(require_login)):
    form = await request.form()
    wans = get_multiwan_status()

    mode = form.get("wan_mode", "failover")
    if mode not in ("failover", "balance"):
        mode = "failover"
    with open(WAN_MODE_CONF, "w") as f:
        f.write(mode + "\n")

    lines = []
    for w in wans:
        name = w["name"]
        tier = form.get(f"tier_{name}", w.get("tier", "1"))
        enabled = "yes" if form.get(f"enabled_{name}") == "yes" else "no"
        weight = form.get(f"weight_{name}", "1").strip() or "1"
        metric = str(100 * int(tier))
        lines.append(f"{name}|{tier}|{metric}|{enabled}|{weight}")

    with open(WAN_FAILOVER_CONF, "w") as f:
        f.write(chr(10).join(lines) + chr(10))

    subprocess.run(["/usr/local/sbin/wan-monitor.sh"], capture_output=True)

    return RedirectResponse(url="/multi-wan?saved=1", status_code=303)


from system_info import SERVICES


def get_services_detail():
    result = []
    for svc in SERVICES:
        active = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True).stdout.strip()
        enabled = subprocess.run(["systemctl", "is-enabled", svc], capture_output=True, text=True).stdout.strip()
        result.append({"name": svc, "active": active, "enabled": enabled})
    return result


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "services.html",
        {
            "username": request.session.get("username", "admin"),
            "services": get_services_detail(),
            "error": request.query_params.get("error"),
        }
    )


@app.post("/services/{action}")
async def services_action(request: Request, action: str, service: str = Form(...), _=Depends(require_login)):
    if service not in SERVICES:
        return RedirectResponse(url="/services?error=Gecersiz+servis", status_code=303)
    if action not in ("start", "stop", "restart"):
        return RedirectResponse(url="/services?error=Gecersiz+islem", status_code=303)

    result = subprocess.run(["systemctl", action, service], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/services?error={error}", status_code=303)

    return RedirectResponse(url="/services", status_code=303)


@app.get("/services/status/{service}")
async def services_status(service: str, _=Depends(require_login)):
    if service not in SERVICES:
        return JSONResponse({"error": "invalid service"}, status_code=400)
    active = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True).stdout.strip()
    return JSONResponse({"active": active})


@app.get("/crowdsec", response_class=HTMLResponse)
async def crowdsec_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "crowdsec.html",
        {
            "username": request.session.get("username", "admin"),
            "decisions": get_crowdsec_decisions(),
            "stats": get_crowdsec_stats(),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/crowdsec/unban")
async def crowdsec_unban(request: Request, decision_id: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/bin/cscli", "decisions", "delete", "--id", decision_id],
                             capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/crowdsec?error={error}", status_code=303)
    return RedirectResponse(url="/crowdsec", status_code=303)


@app.post("/crowdsec/ban")
async def crowdsec_ban(request: Request, ip: str = Form(...), duration: str = Form(...),
                        reason: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/bin/cscli", "decisions", "add", "--ip", ip, "--duration", duration, "--reason", reason, "--type", "ban"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/crowdsec?error={error}", status_code=303)
    return RedirectResponse(url="/crowdsec", status_code=303)


@app.get("/ids", response_class=HTMLResponse)
async def ids_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "ids.html",
        {
            "username": request.session.get("username", "admin"),
            "stats": get_suricata_stats(),
            "alerts": get_suricata_alerts(limit=100),
            "all_ifaces": get_vlan_parent_candidates(),
            "monitored_ifaces": get_suricata_monitored_ifaces(),
            "suppressed": get_suricata_suppressed(),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/ids/suppress")
async def ids_suppress_add(request: Request, sig_id: str = Form(...), src_ip: str = Form(""), _=Depends(require_login)):
    args = ["/usr/local/sbin/suricata-suppress", "add", sig_id]
    if src_ip.strip():
        args.append(src_ip.strip())
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/ids?error={error}", status_code=303)
    return RedirectResponse(url="/ids", status_code=303)


@app.post("/ids/unsuppress")
async def ids_suppress_remove(request: Request, sig_id: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/suricata-suppress", "remove", sig_id], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/ids?error={error}", status_code=303)
    return RedirectResponse(url="/ids", status_code=303)


@app.post("/ids/interfaces")
async def ids_set_interfaces(request: Request, _=Depends(require_login)):
    form = await request.form()
    ifaces = form.getlist("ifaces")
    if not ifaces:
        return RedirectResponse(url="/ids?error=En+az+bir+arayuz+secilmeli", status_code=303)
    result = subprocess.run(
        ["/usr/local/sbin/suricata-iface-set", ",".join(ifaces)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        error = (result.stderr.strip() or "Islem basarisiz").replace(" ", "+")
        return RedirectResponse(url=f"/ids?error={error}", status_code=303)
    return RedirectResponse(url="/ids", status_code=303)


@app.get("/snmp", response_class=HTMLResponse)
async def snmp_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "snmp.html",
        {
            "username": request.session.get("username", "admin"),
            "cfg": get_snmp_config(),
            "v3_users": get_snmp_v3_users(),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
            "saved": request.query_params.get("saved"),
        }
    )


@app.post("/snmp/settings")
async def snmp_save_settings(request: Request, location: str = Form(""), contact: str = Form(""), _=Depends(require_login)):
    path = "/etc/snmp/snmpd.conf"
    with open(path) as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        if line.strip().startswith("sysLocation"):
            new_lines.append(f"sysLocation    {location}\n")
        elif line.strip().startswith("sysContact"):
            new_lines.append(f"sysContact     {contact}\n")
        else:
            new_lines.append(line)
    with open(path, "w") as f:
        f.writelines(new_lines)
    subprocess.run(["systemctl", "restart", "snmpd"])
    return RedirectResponse(url="/snmp?saved=1", status_code=303)


@app.post("/snmp/adduser")
async def snmp_add_user(request: Request, username: str = Form(...), authpass: str = Form(...),
                         privpass: str = Form(...), _=Depends(require_login)):
    if len(authpass) < 8 or len(privpass) < 8:
        return RedirectResponse(url="/snmp?error=Passphrases+must+be+at+least+8+characters", status_code=303)

    subprocess.run(["systemctl", "stop", "snmpd"])
    result = subprocess.run(
        ["net-snmp-create-v3-user", "-A", authpass, "-a", "SHA", "-X", privpass, "-x", "AES", username],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        subprocess.run(["systemctl", "start", "snmpd"])
        error = (result.stderr.strip() or result.stdout.strip() or "Failed to create user").replace(" ", "+")
        return RedirectResponse(url=f"/snmp?error={error}", status_code=303)

    # ONEMLI: net-snmp-create-v3-user OTOMATIK olarak snmpd.conf'a
    # "rwuser <username>" satiri ekliyor - bu KISITLAMASIZ (view sinirlamasi
    # olmadan) OKUMA+YAZMA yetkisi anlamina gelir! Bunu kaldirip, YERINE
    # SADECE bizim eklemek istedigimiz kisitli "rouser ... -V systemonly"
    # satirini koyuyoruz - aksi halde panelden "salt-okunur, sadece sistem
    # bilgisi" niyetiyle eklenen bir kullanici, gercekte tam yetkili
    # kalirdi (gercek, ciddi bir guvenlik farkiydi).
    with open("/etc/snmp/snmpd.conf") as f:
        conf_lines = f.readlines()
    conf_lines = [l for l in conf_lines if not (l.strip().startswith("rwuser") and username in l.split())]
    conf_lines.append(f"rouser {username} authPriv -V systemonly\n")
    with open("/etc/snmp/snmpd.conf", "w") as f:
        f.writelines(conf_lines)

    subprocess.run(["systemctl", "start", "snmpd"])
    return RedirectResponse(url="/snmp?saved=1", status_code=303)


@app.post("/snmp/deleteuser")
async def snmp_delete_user(request: Request, username: str = Form(...), _=Depends(require_login)):
    with open("/etc/snmp/snmpd.conf") as f:
        lines = f.readlines()
    new_lines = [l for l in lines if not (l.strip().startswith("rouser") and username in l.split())]
    with open("/etc/snmp/snmpd.conf", "w") as f:
        f.writelines(new_lines)

    subprocess.run(["systemctl", "stop", "snmpd"])
    with open("/var/lib/snmp/snmpd.conf") as f:
        lines = f.readlines()
    new_lines = [l for l in lines if not (l.strip().startswith("usmUser") and f'"{username}"' in l)]
    with open("/var/lib/snmp/snmpd.conf", "w") as f:
        f.writelines(new_lines)
    subprocess.run(["systemctl", "start", "snmpd"])

    return RedirectResponse(url="/snmp?saved=1", status_code=303)


@app.get("/netflow", response_class=HTMLResponse)
async def netflow_page(request: Request, _=Depends(require_login)):
    time_range = request.query_params.get("range", "24h")
    if time_range not in ("1h", "24h", "7d"):
        time_range = "24h"
    return templates.TemplateResponse(
        request, "netflow.html",
        {
            "username": request.session.get("username", "admin"),
            "summary": get_netflow_summary(time_range),
            "top_ips": get_netflow_top("ip", time_range),
            "top_ports": get_netflow_top("port", time_range),
            "time_range": time_range,
        }
    )


@app.get("/qos", response_class=HTMLResponse)
async def qos_page(request: Request, _=Depends(require_login)):
    wan_candidates = [w for w in get_vlan_parent_candidates() if w["role_type"] == "wan"]
    wan_bw = get_qos_wan_bandwidth()
    return templates.TemplateResponse(
        request, "qos.html",
        {
            "username": request.session.get("username", "admin"),
            "wan_candidates": wan_candidates,
            "wan_bw": wan_bw,
            "networks": get_qos_networks_with_shares(),
            "status": get_qos_active_status(),
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/qos/apply")
async def qos_apply_settings(request: Request, _=Depends(require_login)):
    form = await request.form()

    wan_lines = []
    for w in get_vlan_parent_candidates():
        if w["role_type"] != "wan":
            continue
        name = w["name"]
        up_mbit = form.get(f"up_{name}", "").strip()
        down_mbit = form.get(f"down_{name}", "").strip()
        if not up_mbit or not down_mbit:
            continue
        try:
            up_kbit = int(float(up_mbit) * 1000)
            down_kbit = int(float(down_mbit) * 1000)
        except ValueError:
            return RedirectResponse(url="/qos?error=Invalid+bandwidth+value", status_code=303)
        wan_lines.append(f"{name}|{up_kbit}|{down_kbit}")

    if not wan_lines:
        return RedirectResponse(url="/qos?error=At+least+one+WAN+bandwidth+is+required", status_code=303)

    with open("/etc/qos/wan-bandwidth.conf", "w") as f:
        f.write("\n".join(wan_lines) + "\n")

    share_lines = []
    for net in get_lan_ifaces_with_subnets():
        name = net["name"]
        up_mbit = form.get(f"up_{name}", "").strip()
        down_mbit = form.get(f"down_{name}", "").strip()
        if not up_mbit or not down_mbit:
            return RedirectResponse(url="/qos?error=Missing+bandwidth+for+" + name, status_code=303)
        try:
            up_kbit = int(float(up_mbit) * 1000)
            down_kbit = int(float(down_mbit) * 1000)
        except ValueError:
            return RedirectResponse(url="/qos?error=Invalid+bandwidth+value", status_code=303)
        share_lines.append(f"{name}|{up_kbit}|{down_kbit}")

    with open("/etc/qos/shares.conf", "w") as f:
        f.write("\n".join(share_lines) + "\n")

    result = subprocess.run(["/usr/local/sbin/qos-generate"], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "qos-generate failed").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/qos?error={error}", status_code=303)

    return RedirectResponse(url="/qos?saved=1", status_code=303)


@app.post("/qos/disable")
async def qos_disable(request: Request, _=Depends(require_login)):
    for w in get_vlan_parent_candidates():
        if w["role_type"] == "wan":
            subprocess.run(["tc", "qdisc", "del", "dev", w["name"], "root"], capture_output=True)
            subprocess.run(["tc", "qdisc", "del", "dev", w["name"], "ingress"], capture_output=True)
            subprocess.run(["ip", "link", "del", f"ifb-{w['name']}"], capture_output=True)
    for net in get_lan_ifaces_with_subnets():
        name = net["name"]
        subprocess.run(["tc", "qdisc", "del", "dev", name, "root"], capture_output=True)
        subprocess.run(["tc", "qdisc", "del", "dev", name, "ingress"], capture_output=True)
        subprocess.run(["ip", "link", "del", f"ifb-net-{name}"], capture_output=True)
    return RedirectResponse(url="/qos?saved=1", status_code=303)


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, _=Depends(require_login)):
    creds = load_credentials() or {"users": []}
    return templates.TemplateResponse(
        request, "users.html",
        {
            "username": request.session.get("username", "admin"),
            "users": creds.get("users", []),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
            "saved": request.query_params.get("saved"),
        }
    )


@app.post("/users/add")
async def users_add(request: Request, new_username: str = Form(...), new_password: str = Form(...),
                     new_password_confirm: str = Form(...), _=Depends(require_login)):
    new_username = new_username.strip()
    if not re.match(r'^[a-zA-Z0-9_.-]{3,32}$', new_username):
        return RedirectResponse(url="/users?error=Username+must+be+3-32+chars+(letters,+numbers,+.+_+-)", status_code=303)
    if new_password != new_password_confirm:
        return RedirectResponse(url="/users?error=Passwords+do+not+match", status_code=303)
    if len(new_password) < 8:
        return RedirectResponse(url="/users?error=Password+must+be+at+least+8+characters", status_code=303)

    creds = load_credentials() or {"users": []}
    if find_user(creds, new_username):
        return RedirectResponse(url="/users?error=That+username+already+exists", status_code=303)

    import datetime
    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    creds["users"].append({
        "username": new_username,
        "password_hash": hashed.decode("utf-8"),
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_credentials(creds)

    return RedirectResponse(url="/users?saved=1", status_code=303)


@app.post("/users/delete")
async def users_delete(request: Request, username: str = Form(...), _=Depends(require_login)):
    creds = load_credentials() or {"users": []}
    if len(creds.get("users", [])) <= 1:
        return RedirectResponse(url="/users?error=Cannot+delete+the+last+remaining+user", status_code=303)
    if username == request.session.get("username"):
        return RedirectResponse(url="/users?error=You+cannot+delete+your+own+currently+logged-in+account", status_code=303)

    creds["users"] = [u for u in creds["users"] if u["username"] != username]
    save_credentials(creds)

    return RedirectResponse(url="/users?saved=1", status_code=303)


@app.post("/users/reset-password")
async def users_reset_password(request: Request, target_username: str = Form(...),
                                 new_password: str = Form(...), new_password_confirm: str = Form(...),
                                 _=Depends(require_login)):
    if new_password != new_password_confirm:
        return RedirectResponse(url="/users?error=Passwords+do+not+match", status_code=303)
    if len(new_password) < 8:
        return RedirectResponse(url="/users?error=Password+must+be+at+least+8+characters", status_code=303)

    creds = load_credentials() or {"users": []}
    target = find_user(creds, target_username)
    if not target:
        return RedirectResponse(url="/users?error=User+not+found", status_code=303)

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    target["password_hash"] = hashed.decode("utf-8")
    save_credentials(creds)

    return RedirectResponse(url="/users?saved=1", status_code=303)


@app.post("/users/change-password")
async def users_change_password(request: Request, current_password: str = Form(...),
                                  new_password: str = Form(...), new_password_confirm: str = Form(...),
                                  _=Depends(require_login)):
    creds = load_credentials() or {"users": []}
    me = find_user(creds, request.session.get("username", ""))
    if not me or not bcrypt.checkpw(current_password.encode("utf-8"), me["password_hash"].encode("utf-8")):
        return RedirectResponse(url="/users?error=Current+password+is+incorrect", status_code=303)
    if new_password != new_password_confirm:
        return RedirectResponse(url="/users?error=New+passwords+do+not+match", status_code=303)
    if len(new_password) < 8:
        return RedirectResponse(url="/users?error=Password+must+be+at+least+8+characters", status_code=303)

    hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
    me["password_hash"] = hashed.decode("utf-8")
    save_credentials(creds)

    return RedirectResponse(url="/users?saved=1", status_code=303)


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "logs.html",
        {
            "username": request.session.get("username", "admin"),
            "entries": get_audit_log_entries(200),
        }
    )


BACKUP_DIR = "/var/backups/stratum-panel"


@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "backup.html",
        {
            "username": request.session.get("username", "admin"),
            "backups": get_backup_list(),
            "modules": get_module_backup_list(),
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.get("/backup/module/{module_key}/download")
async def backup_module_download(request: Request, module_key: str, _=Depends(require_login)):
    if not re.match(r'^[a-z_]+$', module_key):
        raise HTTPException(status_code=400, detail="Invalid module")
    tmp_path = f"/tmp/module-backup-{module_key}-{secrets.token_hex(6)}.tar.gz"
    result = subprocess.run(
        ["/usr/local/sbin/stratum-module-backup", "backup", module_key, tmp_path],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0 or not os.path.isfile(tmp_path):
        raise HTTPException(status_code=400, detail=result.stderr.strip() or "Backup failed")
    return FileResponse(tmp_path, filename=f"stratum-{module_key}-backup.tar.gz", media_type="application/gzip", background=None)


@app.post("/backup/restore")
async def backup_restore(request: Request, file: UploadFile = File(...), confirm_text: str = Form(...), _=Depends(require_login)):
    if confirm_text.strip() != "RESTORE":
        return RedirectResponse(url="/backup?error=Confirmation+text+did+not+match", status_code=303)

    tmp_path = f"/tmp/restore-upload-{secrets.token_hex(6)}.tar.gz"
    with open(tmp_path, "wb") as f:
        f.write(await file.read())

    # ONEMLI: restore islemi SONUNDA "systemctl restart stratum-panel"
    # calistirir. Eger bu restore SURECI, panel PROCESSININ kendi
    # subprocess.Popen() ile baslattigi bir COCUK surec olarak kalirsa
    # (yani stratum-panel.service'in AYNI systemd cgroup'unun icinde),
    # "systemctl restart stratum-panel" komutunun KENDISI, systemd'nin
    # bu SERVISE AIT TUM surecleri (COCUKLAR DAHIL) sonlandirmasina
    # sebep olabilir - bu da restore script'inin KENDI KENDINI
    # OLDURUP, "tamamlandi" satirina hic ULASAMAMASINA yol acar (canli
    # ortamda dogrulanmis, gercek bir hataydi - restore "yeniden
    # baslatiliyor" adiminda SESSIZCE kesiliyordu). Cozum: "systemd-run"
    # ile TAMAMEN BAGIMSIZ, KENDI systemd birimine sahip bir surec
    # baslatmak - bu, stratum-panel.service'in restart/stop
    # yasam donguisunden ETKILENMEZ.
    subprocess.Popen([
        "systemd-run", "--unit=stratum-restore-run",
        "--description=Stratum Gateway Restore",
        "bash", "-c", f"sleep 2 && /usr/local/sbin/stratum-restore {tmp_path} && rm -f {tmp_path}"
    ])

    return RedirectResponse(url="/backup/restore-progress", status_code=303)


@app.get("/backup/restore-progress", response_class=HTMLResponse)
async def backup_restore_progress(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "restore_progress.html",
        {"username": request.session.get("username", "admin")}
    )


@app.get("/api/health")
async def api_health():
    # ONEMLI: bu endpoint KASITLI olarak require_login KULLANMIYOR -
    # restore sirasinda oturum/session state bile GECICI OLARAK
    # tutarsiz olabilir (panel yeniden baslatiliyor), bu yuzden
    # ilerleme sayfasinin "panel geri geldi mi?" kontrolu icin
    # kimlik dogrulama GEREKTIRMEYEN, sadece "ayakta miyim" diyen
    # en basit health-check.
    return JSONResponse({"status": "ok"})


@app.get("/api/restore-status")
async def api_restore_status():
    # ONEMLI: bu da kimlik dogrulama GEREKTIRMEZ (ayni sebepten -
    # restore sirasinda oturum durumu tutarsiz olabilir). Panelin
    # sadece "ayakta olup olmadigini" degil, restore'un GERCEKTEN
    # basarili mi yoksa reddedilip HICBIR SEY DEGISMEDEN mi bittigini
    # ayirt etmek icin gereklidir.
    status_path = "/var/log/stratum-panel/restore-status.json"
    if not os.path.exists(status_path):
        return JSONResponse({"success": None, "message": "No restore has been run yet."})
    try:
        with open(status_path) as f:
            data = json.load(f)
        return JSONResponse(data)
    except Exception:
        return JSONResponse({"success": None, "message": "Could not read restore status."})


@app.post("/backup/module/{module_key}/restore")
async def backup_module_restore(request: Request, module_key: str, file: UploadFile = File(...), _=Depends(require_login)):
    if not re.match(r'^[a-z_]+$', module_key):
        raise HTTPException(status_code=400, detail="Invalid module")
    tmp_path = f"/tmp/module-restore-{module_key}-{secrets.token_hex(6)}.tar.gz"
    try:
        with open(tmp_path, "wb") as f:
            f.write(await file.read())
        result = subprocess.run(
            ["/usr/local/sbin/stratum-module-backup", "restore", module_key, tmp_path],
            capture_output=True, text=True, timeout=120,
        )
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    if result.returncode != 0:
        error = (result.stderr.strip() or "Restore failed").replace(" ", "+")[:250]
        return RedirectResponse(url=f"/backup?error={error}", status_code=303)
    return RedirectResponse(url="/backup?saved=1", status_code=303)


@app.post("/backup/create")
async def backup_create(request: Request, _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/stratum-backup"], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Backup failed").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/backup?error={error}", status_code=303)
    return RedirectResponse(url="/backup?saved=1", status_code=303)


@app.get("/backup/download/{filename}")
async def backup_download(request: Request, filename: str, _=Depends(require_login)):
    # ONEMLI: path traversal koruması - sadece dosya adi deseni (../ veya
    # / icermeyen, .tar.gz ile biten) kabul edilir, ayrica dosyanin
    # GERCEKTEN backup dizininde olup olmadigi da ayrica dogrulanir.
    if not re.match(r'^[a-zA-Z0-9_.-]+\.tar\.gz$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename")
    full_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(full_path) or os.path.dirname(os.path.abspath(full_path)) != os.path.abspath(BACKUP_DIR):
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(full_path, filename=filename, media_type="application/gzip")


@app.post("/backup/delete")
async def backup_delete(request: Request, filename: str = Form(...), _=Depends(require_login)):
    # ONEMLI: ayni path traversal korumasi burada da uygulanir - sadece
    # gecerli desen VE gercekten backup dizininde olan dosyalar silinebilir.
    if not re.match(r'^[a-zA-Z0-9_.-]+\.tar\.gz$', filename):
        return RedirectResponse(url="/backup?error=Invalid+filename", status_code=303)
    full_path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(full_path) or os.path.dirname(os.path.abspath(full_path)) != os.path.abspath(BACKUP_DIR):
        return RedirectResponse(url="/backup?error=Backup+not+found", status_code=303)

    packages_file = full_path.replace(".tar.gz", "-packages.txt")
    os.remove(full_path)
    if os.path.isfile(packages_file):
        os.remove(packages_file)

    return RedirectResponse(url="/backup?saved=1", status_code=303)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "settings.html",
        {
            "username": request.session.get("username", "admin"),
            "hostname": get_hostname(),
            "timezone": get_timezone(),
            "timezones": get_available_timezones(),
            "cert": get_cert_info(),
            "ca": get_ca_info(),
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
            "radius_servers": radius_auth.get_servers(),
            "notif_config": notifications.get_config(),
        }
    )


@app.post("/settings/hostname")
async def settings_hostname(request: Request, hostname: str = Form(...), _=Depends(require_login)):
    hostname = hostname.strip()
    if not re.match(r'^[a-zA-Z0-9-]{1,63}$', hostname):
        return RedirectResponse(url="/settings?error=Invalid+hostname", status_code=303)
    result = subprocess.run(["hostnamectl", "set-hostname", hostname], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to set hostname").replace(" ", "+")[:150]
        return RedirectResponse(url=f"/settings?error={error}", status_code=303)
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.post("/settings/timezone")
async def settings_timezone(request: Request, timezone: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["timedatectl", "set-timezone", timezone], capture_output=True, text=True)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to set timezone").replace(" ", "+")[:150]
        return RedirectResponse(url=f"/settings?error={error}", status_code=303)
    return RedirectResponse(url="/settings?saved=1", status_code=303)


def _restart_panel_delayed():
    subprocess.Popen(["bash", "-c", "sleep 1.5 && systemctl restart stratum-panel"])

def _system_power_delayed(action: str):
    cmd = "reboot" if action == "reboot" else "poweroff"
    subprocess.Popen(["bash", "-c", f"sleep 2 && systemctl {cmd}"])


@app.post("/settings/power/{action}")
async def settings_power_action(request: Request, action: str, confirm_text: str = Form(...), _=Depends(require_login)):
    if action not in ("reboot", "halt"):
        return RedirectResponse(url="/settings?error=Gecersiz+islem", status_code=303)

    expected = "REBOOT" if action == "reboot" else "HALT"
    if confirm_text.strip() != expected:
        return RedirectResponse(url="/settings?error=Onay+metni+eslesmedi", status_code=303)

    _system_power_delayed(action)
    return RedirectResponse(url=f"/settings?saved=1&info={action}", status_code=303)


@app.post("/settings/factory-reset")
async def settings_factory_reset(request: Request, confirm_text: str = Form(...), _=Depends(require_login)):
    if confirm_text.strip() != "FACTORY RESET":
        return RedirectResponse(url="/settings?error=Onay+metni+eslesmedi", status_code=303)

    # ONEMLI: stratum-factory-reset script'inin KENDISI "systemctl reboot"
    # cagirir - bu, settings_power_action'daki "reboot" ile AYNI desen
    # (basit gecikmeli Popen), CUNKU factory-reset de panel'in KENDI
    # restart'ini BEKLEMIYOR, TUM sistemi reboot ediyor - restore'daki
    # deadlock riski BURADA GECERLI DEGIL.
    subprocess.Popen(["bash", "-c", "sleep 2 && /usr/local/sbin/stratum-factory-reset"])
    return RedirectResponse(url="/settings/factory-reset/progress", status_code=303)


@app.get("/settings/factory-reset/progress", response_class=HTMLResponse)
async def settings_factory_reset_progress(request: Request):
    # ONEMLI: burada require_login KULLANILMIYOR - factory reset,
    # session-secret.key dosyasini da SILIYOR, bu yuzden bu sayfaya
    # YONLENDIRILDIGI ANDA kullanicinin ESKI session'i ZATEN GECERSIZ
    # olmus olabilir. Sayfa kimlik dogrulama gerektirmeden goruntulenir,
    # zaten HICBIR hassas veri ICERMIYOR.
    return templates.TemplateResponse(
        request, "factory_reset_progress.html", {}
    )


@app.post("/settings/ca/create")
async def settings_ca_create(request: Request, cn: str = Form(...), o: str = Form(...), ou: str = Form(...),
                               c: str = Form(...), st: str = Form(...), l: str = Form(...),
                               days: str = Form("3650"), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/stratum-ca-manage", "create-ca", cn, o, ou, c, st, l, days],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to create CA").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/settings?error={error}", status_code=303)
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.get("/settings/ca/download")
async def settings_ca_download(request: Request, _=Depends(require_login)):
    ca_path = "/etc/stratum-panel/ca/ca.crt"
    if not os.path.isfile(ca_path):
        raise HTTPException(status_code=404, detail="CA certificate not found")
    return FileResponse(ca_path, filename="stratum-gateway-ca.crt", media_type="application/x-x509-ca-cert")


@app.post("/settings/cert/sign-with-ca")
async def settings_cert_sign(request: Request, cn: str = Form(...), days: str = Form("825"), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/stratum-ca-manage", "sign-panel-cert", cn, days],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to sign certificate").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/settings?error={error}", status_code=303)
    _restart_panel_delayed()
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.post("/settings/cert/self-signed")
async def settings_cert_self_signed(request: Request, cn: str = Form(...), o: str = Form(...), ou: str = Form(...),
                                      c: str = Form(...), st: str = Form(...), l: str = Form(...),
                                      days: str = Form("825"), _=Depends(require_login)):
    result = subprocess.run(
        ["/usr/local/sbin/stratum-ca-manage", "self-signed-panel-cert", cn, o, ou, c, st, l, days],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to create certificate").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/settings?error={error}", status_code=303)
    _restart_panel_delayed()
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.get("/geoblock", response_class=HTMLResponse)
async def geoblock_page(request: Request, _=Depends(require_login)):
    status = get_geoblock_status()
    blocked_codes = {b["code"] for b in status["blocked"]}
    all_countries = sorted(
        [{"code": c, "name": n} for c, n in COUNTRY_NAMES.items() if c not in blocked_codes],
        key=lambda x: x["name"],
    )
    return templates.TemplateResponse(
        request, "geoblock.html",
        {
            "username": request.session.get("username", "admin"),
            "status": status,
            "all_countries": all_countries,
            "threat_ip": get_threat_ip_status(),
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/geoblock/threat-ip-update")
async def geoblock_threat_ip_update(request: Request, _=Depends(require_login)):
    subprocess.Popen(["systemctl", "start", "threat-ip-update.service"])
    return JSONResponse({"started": True})


@app.get("/geoblock/threat-ip-status")
async def geoblock_threat_ip_status(request: Request, _=Depends(require_login)):
    active = subprocess.run(["systemctl", "is-active", "threat-ip-update.service"], capture_output=True, text=True).stdout.strip()
    running = active in ("active", "activating")
    result = {"running": running}
    if not running:
        result["status"] = get_threat_ip_status()
    return JSONResponse(result)


@app.post("/geoblock/add")
async def geoblock_add(request: Request, country_code: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/geoip-block", "add", country_code], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to add country").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/geoblock?error={error}", status_code=303)
    return RedirectResponse(url="/geoblock?saved=1", status_code=303)


@app.post("/geoblock/remove")
async def geoblock_remove(request: Request, country_code: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/geoip-block", "remove", country_code], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to remove country").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/geoblock?error={error}", status_code=303)
    return RedirectResponse(url="/geoblock?saved=1", status_code=303)


@app.get("/vpn", response_class=HTMLResponse)
async def vpn_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "vpn.html",
        {
            "username": request.session.get("username", "admin"),
            "status": get_wireguard_status(),
            "peers": get_wireguard_peers(),
            "new_config": request.session.pop("wg_new_config", None) if request.session.get("wg_new_config") else None,
            "new_config_name": request.session.pop("wg_new_config_name", None) if request.session.get("wg_new_config_name") else None,
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/vpn/add")
async def vpn_add(request: Request, name: str = Form(...), _=Depends(require_login)):
    name = name.strip()
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', name):
        return RedirectResponse(url="/vpn?error=Invalid+name+(letters,+numbers,+-+_+only)", status_code=303)
    result = subprocess.run(["/usr/local/sbin/wireguard-peer-manage", "add", name], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to add client").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/vpn?error={error}", status_code=303)
    request.session["wg_new_config"] = result.stdout
    request.session["wg_new_config_name"] = name
    return RedirectResponse(url="/vpn", status_code=303)


@app.post("/vpn/remove")
async def vpn_remove(request: Request, name: str = Form(...), _=Depends(require_login)):
    result = subprocess.run(["/usr/local/sbin/wireguard-peer-manage", "remove", name], capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        error = (result.stderr.strip() or "Failed to remove client").replace(" ", "+")[:200]
        return RedirectResponse(url=f"/vpn?error={error}", status_code=303)
    return RedirectResponse(url="/vpn?saved=1", status_code=303)


@app.get("/vpn/config/{name}")
async def vpn_download_config(request: Request, name: str, _=Depends(require_login)):
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', name):
        raise HTTPException(status_code=400, detail="Invalid name")
    result = subprocess.run(["/usr/local/sbin/wireguard-peer-manage", "get-config", name], capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        raise HTTPException(status_code=404, detail="Client not found")
    return Response(content=result.stdout, media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={name}.conf"})


@app.get("/vpn/qr/{name}")
async def vpn_qr_code(request: Request, name: str, _=Depends(require_login)):
    if not re.match(r'^[a-zA-Z0-9_-]{1,32}$', name):
        raise HTTPException(status_code=400, detail="Invalid name")
    result = subprocess.run(["/usr/local/sbin/wireguard-peer-manage", "get-config", name], capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        raise HTTPException(status_code=404, detail="Client not found")
    qr = subprocess.run(["qrencode", "-t", "PNG", "-o", "-"], input=result.stdout.encode(), capture_output=True, timeout=15)
    return Response(content=qr.stdout, media_type="image/png")




@app.post("/settings/notifications/save")
async def notifications_save(request: Request,
                               email_enabled: str = Form("false"),
                               smtp_host: str = Form(""),
                               smtp_port: str = Form("587"),
                               smtp_username: str = Form(""),
                               smtp_password: str = Form(""),
                               smtp_use_tls: str = Form("false"),
                               from_address: str = Form(""),
                               to_address: str = Form(""),
                               notify_wan_down: str = Form("false"),
                               notify_wan_up: str = Form("false"),
                               notify_crowdsec_ban: str = Form("false"),
                               _=Depends(require_login)):
    existing = notifications.get_config()
    new_password = smtp_password if smtp_password else existing.get("smtp_password", "")
    config = {
        "email_enabled": email_enabled == "true",
        "smtp_host": smtp_host.strip(),
        "smtp_port": int(smtp_port) if smtp_port.strip().isdigit() else 587,
        "smtp_username": smtp_username.strip(),
        "smtp_password": new_password,
        "smtp_use_tls": smtp_use_tls == "true",
        "from_address": from_address.strip(),
        "to_address": to_address.strip(),
        "notify_wan_down": notify_wan_down == "true",
        "notify_wan_up": notify_wan_up == "true",
        "notify_crowdsec_ban": notify_crowdsec_ban == "true",
    }
    notifications.save_config(config)
    return RedirectResponse(url="/settings?saved=notifications#notifications", status_code=303)


@app.post("/settings/notifications/test")
async def notifications_test(request: Request, _=Depends(require_login)):
    success, message = notifications.send_email(
        "[Stratum Gateway] Test Notification",
        "This is a test email from your Stratum Gateway panel. If you received this, SMTP settings are working correctly.",
    )
    if success:
        return RedirectResponse(url="/settings?saved=test_email_sent#notifications", status_code=303)
    else:
        return RedirectResponse(url=f"/settings?error={message.replace(' ', '+')}#notifications", status_code=303)


@app.get("/settings/radius", response_class=HTMLResponse)
async def radius_settings_page(request: Request, _=Depends(require_login)):
    servers = radius_auth.get_servers()
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "radius_servers": servers,
        "active_tab": "radius",
    })


@app.post("/settings/radius/add")
async def radius_add_server(request: Request,
                             name: str = Form(...),
                             host: str = Form(...),
                             secret: str = Form(...),
                             auth_port: str = Form("1812"),
                             acct_port: str = Form("1813"),
                             nas_identifier: str = Form("stratum-gateway"),
                             timeout: str = Form("5"),
                             _=Depends(require_login)):
    try:
        radius_auth.add_server(name=name, host=host, secret=secret,
                                auth_port=auth_port, acct_port=acct_port,
                                nas_identifier=nas_identifier, timeout=timeout, enabled=True)
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/settings?error={error}#radius", status_code=303)
    return RedirectResponse(url="/settings?saved=1#radius", status_code=303)


@app.post("/settings/radius/delete")
async def radius_delete_server(request: Request, server_id: str = Form(...), _=Depends(require_login)):
    try:
        radius_auth.delete_server(server_id)
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/settings?error={error}#radius", status_code=303)
    return RedirectResponse(url="/settings?saved=1#radius", status_code=303)


@app.post("/settings/radius/toggle")
async def radius_toggle_server(request: Request, server_id: str = Form(...), enabled: str = Form(...), _=Depends(require_login)):
    try:
        radius_auth.update_server(server_id, enabled=(enabled == "true"))
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/settings?error={error}#radius", status_code=303)
    return RedirectResponse(url="/settings?saved=1#radius", status_code=303)


@app.post("/settings/radius/test")
async def radius_test_server(request: Request,
                              host: str = Form(...),
                              secret: str = Form(...),
                              auth_port: str = Form("1812"),
                              timeout: str = Form("5"),
                              _=Depends(require_login)):
    ok, message = radius_auth.test_connection(host=host, secret=secret, auth_port=auth_port, timeout=timeout)
    return JSONResponse({"success": ok, "message": message})


@app.get("/captive-portal", response_class=HTMLResponse)
async def captive_portal_page(request: Request, _=Depends(require_login)):
    config = captive_portal_manage.get_config()
    interfaces = get_lan_ifaces_with_subnets()
    radius_servers = radius_auth.get_servers()
    return templates.TemplateResponse(request, "captive_portal.html", {
        "cp_config": config,
        "cp_interfaces": interfaces,
        "radius_servers": radius_servers,
        "username": request.session.get("username", "admin"),
    })


@app.get("/captive-portal/preview")
async def captive_portal_preview(custom: str = "0", _=Depends(require_login)):
    if custom == "1":
        template_path = Path("/etc/stratum-panel/captive_portal/templates/custom/index.html")
    else:
        template_path = Path("/etc/stratum-panel/captive_portal/templates/default/index.html")
    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    return FileResponse(template_path, media_type="text/html")



@app.get("/portal")
async def portal_page(request: Request):
    config = captive_portal_manage.get_config()
    if config.get("use_custom_portal_page") and config.get("custom_portal_page_path"):
        template_path = Path(config["custom_portal_page_path"])
    else:
        template_path = Path("/etc/stratum-panel/captive_portal/templates/default/index.html")

    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Portal page not found")

    html = template_path.read_text()
    error = request.query_params.get("error")
    if error:
        error_html = '<div style="color:#e5484d; font-size:13px; margin-top:10px; text-align:center;">' + error + '</div></form>'
        html = html.replace("<​/form>", error_html)
    return HTMLResponse(content=html)


@app.post("/portal/auth")
async def portal_auth(request: Request, username: str = Form(...), password: str = Form(...)):
    config = captive_portal_manage.get_config()
    server_id = config.get("radius_server_id") or None

    ok, message, attrs = radius_auth.authenticate(username, password, server_id=server_id)

    if not ok:
        from urllib.parse import quote
        return RedirectResponse(url=f"/portal?error={quote(message)}", status_code=303)

    redirect_url = config.get("redirect_url") or "https://www.google.com"
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie(key="stratum_portal_session", value=username, max_age=config.get("session_timeout_minutes", 60) * 60)
    return response

@app.post("/captive-portal/upload-template")
async def captive_portal_upload_template(template_file: UploadFile = File(...), _=Depends(require_login)):
    if not template_file.filename.lower().endswith((".html", ".htm")):
        return RedirectResponse(url="/captive-portal?error=Only+HTML+files+are+allowed", status_code=303)
    content_bytes = await template_file.read()
    max_size = 2 * 1024 * 1024
    if len(content_bytes) > max_size:
        return RedirectResponse(url="/captive-portal?error=File+too+large+(max+2MB)", status_code=303)
    try:
        captive_portal_manage.save_custom_template(content_bytes)
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/captive-portal?error={error}", status_code=303)
    return RedirectResponse(url="/captive-portal?saved=1", status_code=303)


@app.post("/captive-portal/remove-template")
async def captive_portal_remove_template(_=Depends(require_login)):
    try:
        captive_portal_manage.remove_custom_template()
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/captive-portal?error={error}", status_code=303)
    return RedirectResponse(url="/captive-portal?saved=1", status_code=303)


def _int_or(value, default):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


@app.post("/captive-portal/save")
async def captive_portal_save(request: Request,
                               enabled: str = Form("false"),
                               interfaces: list[str] = Form([]),
                               radius_server_id: str = Form(""),

                               max_concurrent_connections: str = Form("4"),
                               idle_timeout_minutes: str = Form("15"),
                               hard_timeout_minutes: str = Form("0"),
                               traffic_quota_mb: str = Form("0"),
                               max_devices_per_user: str = Form("1"),
                               concurrent_login_policy: str = Form("multiple"),

                               mac_filtering_disabled: str = Form("false"),
                               passthrough_mac_auto_add: str = Form("false"),

                               bandwidth_limit_enabled: str = Form("false"),
                               default_download_kbit: str = Form("0"),
                               default_upload_kbit: str = Form("0"),

                               pre_auth_redirect_url: str = Form(""),
                               post_auth_redirect_url: str = Form(""),
                               blocked_mac_redirect_url: str = Form(""),

                               portal_title: str = Form("Welcome"),
                               portal_message: str = Form(""),
                               logo_url: str = Form(""),
                               terms_text: str = Form(""),
                               use_custom_portal_page: str = Form("false"),
                               logout_popup_enabled: str = Form("false"),

                               auth_method: str = Form("radius"),
                               nas_identifier: str = Form(""),
                               reauthenticate_users: str = Form("false"),
                               radius_mac_secret: str = Form(""),
                               mac_auth_fallback_login: str = Form("true"),
                               use_radius_session_timeout: str = Form("false"),
                               use_radius_traffic_quota: str = Form("false"),
                               use_radius_bandwidth: str = Form("false"),
                               mac_address_format: str = Form("default"),

                               radius_accounting_enabled: str = Form("false"),
                               radius_accounting_server_id: str = Form(""),
                               accounting_update_mode: str = Form("none"),
                               accounting_invert_octets: str = Form("false"),
                               accounting_include_idle_time: str = Form("false"),

                               _=Depends(require_login)):
    try:
        captive_portal_manage.save_config({
            "enabled": enabled == "true",
            "interfaces": interfaces,
            "radius_server_id": radius_server_id,

            "max_concurrent_connections": _int_or(max_concurrent_connections, 4),
            "idle_timeout_minutes": _int_or(idle_timeout_minutes, 15),
            "hard_timeout_minutes": _int_or(hard_timeout_minutes, 0),
            "traffic_quota_mb": _int_or(traffic_quota_mb, 0),
            "max_devices_per_user": _int_or(max_devices_per_user, 1),
            "concurrent_login_policy": concurrent_login_policy,

            "mac_filtering_disabled": mac_filtering_disabled == "true",
            "passthrough_mac_auto_add": passthrough_mac_auto_add == "true",

            "bandwidth_limit_enabled": bandwidth_limit_enabled == "true",
            "default_download_kbit": _int_or(default_download_kbit, 0),
            "default_upload_kbit": _int_or(default_upload_kbit, 0),

            "pre_auth_redirect_url": pre_auth_redirect_url,
            "post_auth_redirect_url": post_auth_redirect_url,
            "blocked_mac_redirect_url": blocked_mac_redirect_url,

            "portal_title": portal_title,
            "portal_message": portal_message,
            "logo_url": logo_url,
            "terms_text": terms_text,
            "use_custom_portal_page": use_custom_portal_page == "true",
            "logout_popup_enabled": logout_popup_enabled == "true",

            "auth_method": auth_method,
            "nas_identifier": nas_identifier,
            "reauthenticate_users": reauthenticate_users == "true",
            "radius_mac_secret": radius_mac_secret,
            "mac_auth_fallback_login": mac_auth_fallback_login == "true",
            "use_radius_session_timeout": use_radius_session_timeout == "true",
            "use_radius_traffic_quota": use_radius_traffic_quota == "true",
            "use_radius_bandwidth": use_radius_bandwidth == "true",
            "mac_address_format": mac_address_format,

            "radius_accounting_enabled": radius_accounting_enabled == "true",
            "radius_accounting_server_id": radius_accounting_server_id,
            "accounting_update_mode": accounting_update_mode,
            "accounting_invert_octets": accounting_invert_octets == "true",
            "accounting_include_idle_time": accounting_include_idle_time == "true",
        })
    except Exception as e:
        error = str(e).replace(" ", "+")[:150]
        return RedirectResponse(url=f"/captive-portal?error={error}", status_code=303)
    return RedirectResponse(url="/captive-portal?saved=1", status_code=303)


@app.get("/update", response_class=HTMLResponse)
async def update_page(request: Request, _=Depends(require_login)):
    config = update_manager.get_update_config()
    return templates.TemplateResponse(
        request, "update.html",
        {
            "username": request.session.get("username", "admin"),
            "current_version": update_manager.get_current_version(),
            "manifest_url": config.get("manifest_url", ""),
            "saved": request.query_params.get("saved"),
            "error": request.query_params.get("error", "").replace("+", " ") or None,
        }
    )


@app.post("/update/configure")
async def update_configure(request: Request, manifest_url: str = Form(""), _=Depends(require_login)):
    try:
        update_manager.save_update_config(manifest_url)
    except ValueError as e:
        return RedirectResponse(url=f"/update?error={str(e).replace(' ', '+')}", status_code=303)
    return RedirectResponse(url="/update?saved=1", status_code=303)


@app.get("/update/check")
async def update_check(request: Request, _=Depends(require_login)):
    result = update_manager.check_for_updates()
    return JSONResponse(result)


@app.post("/update/apply")
async def update_apply(request: Request, _=Depends(require_login)):
    # ONEMLI: guncel manifest bilgisini (package_url, sha256, latest_version)
    # TEKRAR CEKIYORUZ - kullanicinin sayfayi actigi ANDAN BERI manifest
    # DEGISMIS OLABILIR, eski/onbellek bir bilgiyle GUNCELLEME YAPMAMAK icin.
    check_result = update_manager.check_for_updates()
    if not check_result.get("success") or not check_result.get("update_available"):
        return RedirectResponse(url="/update?error=No+update+available+or+check+failed", status_code=303)

    package_url = check_result.get("package_url", "")
    sha256 = check_result.get("sha256", "")
    new_version = check_result.get("latest_version", "")

    if not package_url:
        return RedirectResponse(url="/update?error=Manifest+missing+package_url", status_code=303)

    # ONEMLI: systemd-run ile TAMAMEN BAGIMSIZ bir birim olarak baslatiyoruz.
    # NEDEN: bu script, KENDI SONUNDA "systemctl restart stratum-panel"
    # cagirir - eger BU script panel'in KENDI subprocess.Popen() cocugu
    # olarak KALIRSA (yani stratum-panel.service'in AYNI cgroup'unun
    # icinde), panel'i restart etmek KENDI KENDINI OLDURMESINE ve
    # islemin YARIDA KESILMESINE sebep olabilir (canli ortamda
    # dogrulanmis, gercek bir hataydi - bkz. Backup Restore).
    subprocess.Popen([
        "systemd-run", "--unit=stratum-apply-update-run",
        "--description=Stratum Gateway Update",
        "/usr/local/sbin/stratum-apply-update", package_url, sha256, new_version
    ])

    return RedirectResponse(url="/update/progress", status_code=303)


@app.get("/update/progress", response_class=HTMLResponse)
async def update_progress_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "update_progress.html",
        {"username": request.session.get("username", "admin")}
    )


@app.get("/api/update-status")
async def api_update_status():
    # ONEMLI: bu da /api/health ve /api/restore-status gibi KIMLIK
    # DOGRULAMA GEREKTIRMEZ - guncelleme sirasinda panel YENIDEN
    # BASLADIGINDA oturum durumu GECICI OLARAK tutarsiz olabilir.
    status_path = "/var/log/stratum-panel/update-status.json"
    if not os.path.exists(status_path):
        return JSONResponse({"success": None, "message": "No update has been run yet."})
    try:
        with open(status_path) as f:
            data = json.load(f)
        return JSONResponse(data)
    except Exception:
        return JSONResponse({"success": None, "message": "Could not read update status."})


@app.get("/terminal", response_class=HTMLResponse)
async def terminal_page(request: Request, _=Depends(require_login)):
    return templates.TemplateResponse(
        request, "terminal.html",
        {"username": request.session.get("username", "admin")}
    )


@app.websocket("/terminal/ws")
async def terminal_ws(websocket: WebSocket):
    if not websocket.session.get("logged_in"):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        ["/bin/bash"],
        preexec_fn=os.setsid,
        stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
        env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(slave_fd)

    loop = asyncio.get_event_loop()
    closed = False

    def reader():
        try:
            data = os.read(master_fd, 4096)
        except OSError:
            data = b""
        if data:
            asyncio.run_coroutine_threadsafe(websocket.send_bytes(data), loop)
        else:
            asyncio.run_coroutine_threadsafe(websocket.close(), loop)

    loop.add_reader(master_fd, reader)

    try:
        while True:
            msg = await websocket.receive()
            if "text" in msg and msg["text"] is not None:
                payload = json.loads(msg["text"])
                if payload.get("type") == "input":
                    os.write(master_fd, payload["data"].encode())
                elif payload.get("type") == "resize":
                    rows = int(payload.get("rows", 24))
                    cols = int(payload.get("cols", 80))
                    winsize = struct.pack("HHHH", rows, cols, 0, 0)
                    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
            elif "bytes" in msg and msg["bytes"] is not None:
                os.write(master_fd, msg["bytes"])
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        closed = True
        try:
            loop.remove_reader(master_fd)
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(master_fd)
        except Exception:
            pass
