"""
safe_apply.py - Riskli config degisiklikleri icin "uygula, onaylanmazsa geri al"
mekanizmasi. SSH'ta kullandigimiz 60 saniyelik rollback deseninin panel icin
web-tabanli esdegeri.

Kullanim akisi:
  1. change_id = stage_change([dosya1, dosya2], reload_cmd=[...])   # ESKI hali yedekler
  2. (cagiran) yeni icerigi dosyalara yazar
  3. (cagiran) reload/apply islemini calistirir
  4. launch_revert_watcher(change_id, delay_seconds=90)             # geri sayimi baslatir
  5. Kullanici onaylarsa: confirm_change(change_id)
  6. Onaylanmazsa: watcher otomatik olarak dosyalari eski haline dondurur
"""
import os
import json
import subprocess
import secrets

PENDING_DIR = "/var/lib/stratum-panel/pending-changes"


def stage_change(files: list, reload_cmd: list = None) -> str:
    """ONEMLI: bu fonksiyon cagirildiginda dosyalar HALA ESKI icerigiyle olmali.
    Yeni icerigi bu fonksiyondan SONRA yazin."""
    change_id = secrets.token_hex(8)
    change_dir = f"{PENDING_DIR}/{change_id}"
    os.makedirs(change_dir, exist_ok=True)

    meta = {"files": [], "reload_cmd": reload_cmd}
    for i, path in enumerate(files):
        backup_path = f"{change_dir}/backup_{i}"
        content = ""
        if os.path.exists(path):
            with open(path) as f:
                content = f.read()
        with open(backup_path, "w") as f:
            f.write(content)
        meta["files"].append({"original": path, "backup": backup_path})

    with open(f"{change_dir}/meta.json", "w") as f:
        json.dump(meta, f)

    return change_id


def launch_revert_watcher(change_id: str, delay_seconds: int = 90):
    subprocess.Popen(
        ["/usr/local/sbin/safe-apply-revert-watcher", change_id, str(delay_seconds)],
        start_new_session=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def confirm_change(change_id: str) -> bool:
    change_dir = f"{PENDING_DIR}/{change_id}"
    if not os.path.isdir(change_dir):
        return False
    with open(f"{change_dir}/confirmed", "w") as f:
        f.write("1")
    return True


def get_change_status(change_id: str) -> str:
    change_dir = f"{PENDING_DIR}/{change_id}"
    if not os.path.isdir(change_dir):
        return "unknown"
    if os.path.exists(f"{change_dir}/confirmed"):
        return "confirmed"
    return "pending"
