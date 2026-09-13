"""
Stratum Gateway - Captive Portal configuration manager.
Yapilandirma /etc/stratum-panel/captive_portal/config.json dosyasinda tutulur.
"""
import json
from pathlib import Path

CONFIG_PATH = Path("/etc/stratum-panel/captive_portal/config.json")

CUSTOM_TEMPLATE_DIR = Path("/etc/stratum-panel/captive_portal/templates/custom")
DEFAULT_TEMPLATE_PATH = Path("/etc/stratum-panel/captive_portal/templates/default/index.html")
CUSTOM_TEMPLATE_FILENAME = "index.html"


def save_custom_template(file_bytes: bytes) -> str:
    """Save uploaded custom portal HTML. Returns the saved file path as string."""
    CUSTOM_TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    target = CUSTOM_TEMPLATE_DIR / CUSTOM_TEMPLATE_FILENAME
    with open(target, "wb") as f:
        f.write(file_bytes)
    config = get_config()
    config["custom_portal_page_path"] = str(target)
    config["use_custom_portal_page"] = True
    save_config(config)
    return str(target)


def remove_custom_template():
    target = CUSTOM_TEMPLATE_DIR / CUSTOM_TEMPLATE_FILENAME
    if target.exists():
        target.unlink()
    config = get_config()
    config["custom_portal_page_path"] = ""
    config["use_custom_portal_page"] = False
    save_config(config)

DEFAULT_CONFIG = {
    "enabled": False,
    "interfaces": [],
    "radius_server_id": "",

    # Session / connection limits
    "max_concurrent_connections": 4,
    "idle_timeout_minutes": 15,
    "hard_timeout_minutes": 0,
    "traffic_quota_mb": 0,
    "max_devices_per_user": 1,
    "concurrent_login_policy": "multiple",  # disabled | multiple | last_login | first_login

    # MAC handling
    "mac_filtering_disabled": False,
    "passthrough_mac_auto_add": False,

    # Bandwidth
    "bandwidth_limit_enabled": False,
    "default_download_kbit": 0,
    "default_upload_kbit": 0,

    # Redirects
    "pre_auth_redirect_url": "",
    "post_auth_redirect_url": "",
    "blocked_mac_redirect_url": "",

    # Portal page customization
    "portal_title": "Welcome",
    "portal_message": "Please log in to access the internet.",
    "logo_url": "",
    "terms_text": "",
    "use_custom_portal_page": False,
    "custom_portal_page_path": "",
    "custom_auth_error_page_path": "",
    "custom_logout_page_path": "",
    "logout_popup_enabled": False,

    # Authentication
    "auth_method": "radius",  # radius | none | radius_mac
    "nas_identifier": "",
    "reauthenticate_users": False,
    "radius_mac_secret": "",
    "mac_auth_fallback_login": True,
    "use_radius_session_timeout": False,
    "use_radius_traffic_quota": False,
    "use_radius_bandwidth": False,
    "mac_address_format": "default",  # default | single_dash | ietf | cisco | unformatted

    # Accounting
    "radius_accounting_enabled": False,
    "radius_accounting_server_id": "",
    "accounting_update_mode": "none",  # none | interim | stopstart | stopstart_freeradius
    "accounting_invert_octets": False,
    "accounting_include_idle_time": False,
}


def get_config():
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(new_data: dict):
    current = get_config()
    current.update(new_data)
    tmp_path = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        json.dump(current, f, indent=2)
    tmp_path.replace(CONFIG_PATH)
    return current
