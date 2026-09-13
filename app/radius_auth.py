"""
Stratum Gateway - RADIUS Authentication Module
Handles communication with remote RADIUS server(s) for captive portal auth.
"""
import json
import os

CONFIG_PATH = "/etc/stratum-panel/radius/servers.json"

RADIUS_DICT = """
ATTRIBUTE   User-Name           1   string
ATTRIBUTE   User-Password       2   string
ATTRIBUTE   NAS-IP-Address      4   ipaddr
ATTRIBUTE   NAS-Port            5   integer
ATTRIBUTE   Session-Timeout     27  integer
ATTRIBUTE   Idle-Timeout        28  integer
ATTRIBUTE   Called-Station-Id   30  string
ATTRIBUTE   Calling-Station-Id  31  string
ATTRIBUTE   NAS-Identifier      32  string
ATTRIBUTE   Acct-Status-Type    40  integer
ATTRIBUTE   Acct-Session-Id     44  string

VALUE   Acct-Status-Type    Start           1
VALUE   Acct-Status-Type    Stop            2
VALUE   Acct-Status-Type    Interim-Update  3
"""

_dict_path_cache = None


def _get_dict_path():
    global _dict_path_cache
    if _dict_path_cache and os.path.isfile(_dict_path_cache):
        return _dict_path_cache
    path = "/etc/stratum-panel/radius/dictionary.stratum"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(RADIUS_DICT)
    _dict_path_cache = path
    return path


def get_servers():
    """Return list of configured RADIUS servers."""
    if not os.path.isfile(CONFIG_PATH):
        return []
    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)
        return data.get("servers", [])
    except (json.JSONDecodeError, OSError):
        return []


def save_servers(servers):
    """Persist the list of RADIUS servers to disk."""
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp_path = CONFIG_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump({"servers": servers}, f, indent=2)
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, CONFIG_PATH)


def add_server(name, host, secret, auth_port=1812, acct_port=1813,
                nas_identifier="stratum-gateway", timeout=5, enabled=True):
    servers = get_servers()
    new_id = (max([s.get("id", 0) for s in servers], default=0) + 1)
    servers.append({
        "id": new_id,
        "name": name,
        "host": host,
        "secret": secret,
        "auth_port": int(auth_port),
        "acct_port": int(acct_port),
        "nas_identifier": nas_identifier,
        "timeout": int(timeout),
        "enabled": bool(enabled),
    })
    save_servers(servers)
    return new_id


def delete_server(server_id):
    servers = get_servers()
    servers = [s for s in servers if s.get("id") != int(server_id)]
    save_servers(servers)


def update_server(server_id, **kwargs):
    servers = get_servers()
    for s in servers:
        if s.get("id") == int(server_id):
            s.update(kwargs)
    save_servers(servers)


def test_connection(host, secret, auth_port=1812, timeout=5):
    """
    Sends a throwaway Access-Request to verify the server is reachable
    and responds (Accept, Reject, or any valid RADIUS reply all count as
    a successful connectivity test).
    """
    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    import pyrad.packet

    try:
        client = Client(server=host, authport=int(auth_port),
                         secret=secret.encode("utf-8") if isinstance(secret, str) else secret,
                         dict=Dictionary(_get_dict_path()))
        client.timeout = int(timeout)

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                       User_Name="stratum-connectivity-test")
        req["User-Password"] = req.PwCrypt("stratum-test-probe")

        reply = client.SendPacket(req)
        if reply.code == pyrad.packet.AccessAccept:
            return True, "Server reachable (Access-Accept received)."
        elif reply.code == pyrad.packet.AccessReject:
            return True, "Server reachable (Access-Reject received - this is expected for a dummy test user)."
        else:
            return True, f"Server reachable (response code: {reply.code})."
    except Exception as e:
        return False, f"Connection failed: {e}"


def authenticate(username, password, server_id=None):
    """
    Authenticates a user against a configured remote RADIUS server.
    If server_id is given, uses that specific server; otherwise uses the
    first enabled server found in config.
    Returns (success: bool, message: str, reply_attrs: dict)
    """
    from pyrad.client import Client
    from pyrad.dictionary import Dictionary
    import pyrad.packet

    servers = get_servers()
    server = None

    if server_id:
        for s in servers:
            if str(s.get("id")) == str(server_id) and s.get("enabled"):
                server = s
                break

    if not server:
        for s in servers:
            if s.get("enabled"):
                server = s
                break

    if not server:
        return False, "No enabled RADIUS server configured", {}

    try:
        client = Client(
            server=server["host"],
            authport=int(server.get("auth_port", 1812)),
            secret=server["secret"].encode("utf-8") if isinstance(server["secret"], str) else server["secret"],
            dict=Dictionary(_get_dict_path()),
        )
        client.timeout = int(server.get("timeout", 5))

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name=username)
        req["User-Password"] = req.PwCrypt(password)
        if server.get("nas_identifier"):
            req["NAS-Identifier"] = server["nas_identifier"]

        reply = client.SendPacket(req)

        if reply.code == pyrad.packet.AccessAccept:
            attrs = {}
            try:
                if "Session-Timeout" in reply:
                    attrs["session_timeout"] = int(reply["Session-Timeout"][0])
                if "Idle-Timeout" in reply:
                    attrs["idle_timeout"] = int(reply["Idle-Timeout"][0])
            except Exception:
                pass
            return True, "Access granted", attrs
        else:
            return False, "Invalid username or password", {}

    except Exception as e:
        return False, f"RADIUS server error: {e}", {}
