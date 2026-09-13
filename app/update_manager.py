"""
Stratum Gateway - Update Manager
Checks a remote HTTP manifest for new versions and (later) applies updates.
"""
import json
import os
import urllib.request
import urllib.error
import tempfile
import tarfile
import hashlib
import shutil
import datetime

VERSION_FILE = "/etc/stratum-panel/version.json"
UPDATE_CONFIG_FILE = "/etc/stratum-panel/update_config.json"

DEFAULT_UPDATE_CONFIG = {
    "manifest_url": ""
}


def get_current_version():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE) as f:
                data = json.load(f)
            return data.get("version", "unknown")
        except Exception:
            return "unknown"
    return "unknown"


def get_update_config():
    if os.path.exists(UPDATE_CONFIG_FILE):
        try:
            with open(UPDATE_CONFIG_FILE) as f:
                return {**DEFAULT_UPDATE_CONFIG, **json.load(f)}
        except Exception:
            pass
    return dict(DEFAULT_UPDATE_CONFIG)


def save_update_config(manifest_url: str):
    manifest_url = manifest_url.strip()
    if manifest_url and not manifest_url.lower().startswith("https://"):
        raise ValueError("Update server URL must use HTTPS for security.")
    os.makedirs(os.path.dirname(UPDATE_CONFIG_FILE), exist_ok=True)
    with open(UPDATE_CONFIG_FILE, "w") as f:
        json.dump({"manifest_url": manifest_url}, f, indent=2)


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def check_for_updates():
    """
    Fetches the manifest.json from the configured update server and compares
    versions. Does NOT modify any files. Returns a dict describing the result.
    """
    config = get_update_config()
    manifest_url = config.get("manifest_url", "").strip()
    current_version = get_current_version()

    if not manifest_url:
        return {
            "success": False,
            "error": "Update server URL not configured.",
            "current_version": current_version,
        }

    # ONEMLI: HTTPS ZORUNLU. Duz HTTP uzerinden bir "guncelleme mevcut"
    # mesaji AGDA BIRI TARAFINDAN sahte olarak enjekte edilebilir - bu da
    # kotu amacli bir paketin "resmi guncelleme" gibi sunulmasina yol
    # acabilir. localhost/127.0.0.1 test amacli bile olsa istisna
    # yapilmiyor - test sunuculari da HTTPS uzerinden calistirilmali.
    if not manifest_url.lower().startswith("https://"):
        return {
            "success": False,
            "error": "Update server URL must use HTTPS for security.",
            "current_version": current_version,
        }

    try:
        req = urllib.request.Request(manifest_url, headers={"User-Agent": "stratum-panel-update-check"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            manifest = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        return {"success": False, "error": f"Could not reach update server: {e}", "current_version": current_version}
    except Exception as e:
        return {"success": False, "error": f"Invalid manifest: {e}", "current_version": current_version}

    latest_version = manifest.get("latest_version", "unknown")
    update_available = _version_tuple(latest_version) > _version_tuple(current_version)

    return {
        "success": True,
        "current_version": current_version,
        "latest_version": latest_version,
        "update_available": update_available,
        "changelog": manifest.get("changelog", ""),
        "package_url": manifest.get("package_url", ""),
        "sha256": manifest.get("sha256", ""),
        "released_at": manifest.get("released_at", ""),
    }


def apply_update(package_url: str, expected_sha256: str, new_version: str) -> dict:
    """
    Guncelleme paketini indirir, SHA256 ile dogrular, MEVCUT app/
    dizininin yedegini alir, ve yeni surumu UYGULAR. Panel'i KENDISI
    YENIDEN BASLATMAZ - cagiran taraf (main.py route'u), bunu BAGIMSIZ
    bir surec olarak (systemd-run/gecikmeli Popen ile) tetiklemelidir -
    aksi halde "kendi ayagina basma" (self-inflicted deadlock) riski
    olusur (canli ortamda daha once dogrulanmis, gercek bir hataydi).
    """
    APP_DIR = "/opt/stratum-panel/app"

    if not package_url.lower().startswith("https://"):
        return {"success": False, "error": "Package URL must use HTTPS for security."}

    tmp_dir = tempfile.mkdtemp(prefix="stratum-update-")
    try:
        package_path = os.path.join(tmp_dir, "package.tar.gz")

        # 1) Indir
        try:
            req = urllib.request.Request(package_url, headers={"User-Agent": "stratum-panel-updater"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(package_path, "wb") as f:
                    shutil.copyfileobj(resp, f)
        except Exception as e:
            return {"success": False, "error": f"Download failed: {e}"}

        # 2) SHA256 dogrula (ONEMLI: manifest'te bos birakilmissa DOGRULAMA
        # ATLANMAZ - bos sha256, GUVENLIK ACISINDAN kabul edilemez, bu
        # yuzden BOS OLMASI DA hata sayilir).
        if not expected_sha256:
            return {"success": False, "error": "Manifest does not provide a SHA256 checksum - refusing to apply for security."}

        sha256_hash = hashlib.sha256()
        with open(package_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
        actual_sha256 = sha256_hash.hexdigest()
        if actual_sha256.lower() != expected_sha256.lower():
            return {"success": False, "error": "SHA256 mismatch - package may be corrupted or tampered with."}

        # 3) Cikart
        extract_dir = os.path.join(tmp_dir, "extracted")
        try:
            with tarfile.open(package_path, "r:gz") as tar:
                tar.extractall(extract_dir)
        except Exception as e:
            return {"success": False, "error": f"Extraction failed: {e}"}

        new_app_dir = os.path.join(extract_dir, "app")
        if not os.path.isdir(new_app_dir):
            return {"success": False, "error": "Invalid package structure - 'app/' directory not found."}

        # 4) Mevcut app/ dizininin yedegini al
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = f"/opt/stratum-panel/app-backup-{timestamp}"
        try:
            shutil.copytree(APP_DIR, backup_path)
        except Exception as e:
            return {"success": False, "error": f"Backup failed, aborting for safety: {e}"}

        # 5) Yeni dosyalari MEVCUT app/ uzerine uygula
        try:
            for item in os.listdir(new_app_dir):
                src = os.path.join(new_app_dir, item)
                dst = os.path.join(APP_DIR, item)
                if os.path.isdir(src):
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
        except Exception as e:
            # Basarisiz oldu - yedekten GERI AL
            shutil.rmtree(APP_DIR, ignore_errors=True)
            shutil.copytree(backup_path, APP_DIR)
            return {"success": False, "error": f"Apply failed, rolled back to previous version: {e}"}

        # 6) Ek CLI araclarini (varsa, orn. yeni bir /usr/local/sbin araci) kopyala
        tools_dir = os.path.join(extract_dir, "tools")
        if os.path.isdir(tools_dir):
            for item in os.listdir(tools_dir):
                src = os.path.join(tools_dir, item)
                dst = os.path.join("/usr/local/sbin", item)
                shutil.copy2(src, dst)
                os.chmod(dst, 0o755)

        # 7) Surum bilgisini guncelle
        os.makedirs(os.path.dirname(VERSION_FILE), exist_ok=True)
        with open(VERSION_FILE, "w") as f:
            json.dump({"version": new_version}, f)

        return {"success": True, "new_version": new_version, "backup_path": backup_path}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
