import json
import os
import smtplib
from email.mime.text import MIMEText

CONFIG_PATH = "/etc/stratum-panel/notifications/config.json"

DEFAULT_CONFIG = {
    "email_enabled": False,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_username": "",
    "smtp_password": "",
    "smtp_use_tls": True,
    "from_address": "",
    "to_address": "",
    "notify_wan_down": True,
    "notify_wan_up": True,
    "notify_crowdsec_ban": True,
}


def get_config():
    if not os.path.isfile(CONFIG_PATH):
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_CONFIG)


def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp_path = CONFIG_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(config, f, indent=2)
    os.replace(tmp_path, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def send_email(subject, body):
    """Sends an email using the configured SMTP settings. Returns (success, message)."""
    config = get_config()

    if not config.get("email_enabled"):
        return False, "Email notifications are disabled."

    host = config.get("smtp_host", "")
    port = int(config.get("smtp_port", 587))
    username = config.get("smtp_username", "")
    password = config.get("smtp_password", "")
    use_tls = config.get("smtp_use_tls", True)
    from_addr = config.get("from_address", "")
    to_addr = config.get("to_address", "")

    if not host or not from_addr or not to_addr:
        return False, "SMTP host, from address, or to address is not configured."

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            if use_tls:
                server.starttls()
        if username and password:
            server.login(username, password)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        return True, "Email sent successfully."
    except Exception as e:
        return False, str(e)
