#!/usr/bin/env python3
import os
import sys
import json
import socket
import threading
import subprocess
import datetime
import shutil
import re

SOCKET_PATH = "/tmp/config-updater.sock"
RNS_CONFIG_FILE = "/mnt/rns/.reticulum/config"
WPA_SUPPLICANT_CONF = "/etc/wpa_supplicant.conf"
INTERFACES_FILE = "/etc/network/interfaces"

# ----------------------
# Logging
# ----------------------
def log(msg):
    now = datetime.datetime.now().isoformat()
    print(f"[{now}] {msg}")
    sys.stdout.flush()

# ----------------------
# Normalize None
# ----------------------
def normalize_none(val):
    return val if val not in ("", None, "None") else None

# ----------------------
# Update RNS interfaces preserving indentation
# ----------------------
def apply_rns_interfaces(payload):
    TYPE_MAP = {
        "autointerface": "AutoInterface",
        "tcp_server": "TCPServerInterface",
        "tcp_client": "TCPClientInterface",
        "rnode": "RNodeInterface",
    }

    INTERFACE_KEY_MAP = {
        "autointerface": {},
        "tcp_server": {
            "bind_host": "listen_ip",
            "port": "listen_port",
            # "name" intentionally handled separately
        },
        "tcp_client": {
            "host": "target_host",
            "port": "target_port",
            "selected_interface_mode": "selected_interface_mode",
            "configured_bitrate": "configured_bitrate",
            # "name" intentionally handled separately
        },
        "rnode": {
            "serial": "port",
            "frequency": "frequency",
            "tx_power": "txpower",
            "spread_factor": "spreadingfactor",
            "coding_rate": "codingrate",
            "bandwidth": "bandwidth",
        },
    }

    # Read the original config
    with open(RNS_CONFIG_FILE, "r") as f:
        lines = f.readlines()

    out = []
    in_interfaces = False

    for line in lines:
        stripped = line.strip()

        # Start of [interfaces] section
        if stripped == "[interfaces]":
            out.append(line.rstrip("\n"))
            out.append("")  # spacing
            in_interfaces = True

            # Rebuild all interfaces from payload
            for iface in payload:
                iface_type = iface["type"]
                iface_name = iface["name"]
                settings = iface.get("settings", {})

                out.append(f"  [[{iface_name}]]")
                out.append(f"    type = {TYPE_MAP[iface_type]}")
                out.append(f"    enabled = Yes")

                key_map = INTERFACE_KEY_MAP.get(iface_type, {})
                for payload_key, cfg_key in key_map.items():
                    if payload_key in settings and settings[payload_key] is not None:
                        val = settings[payload_key]

                        # Convert bandwidth kHz  Hz
                        if payload_key == "bandwidth":
                            try:
                                val = int(float(val) * 1000)
                            except Exception:
                                val = 0

                        out.append(f"    {cfg_key} = {val}")

                # Always append the human-readable name at the end
                out.append(f"    name = {iface_name}")

                out.append("")  # spacing between interfaces

            continue

        if in_interfaces:
            # Skip everything in the old interfaces block
            if stripped.startswith("[") and not stripped.startswith("[["):
                in_interfaces = False
                out.append(line.rstrip("\n"))
            else:
                continue
        else:
            # Preserve all other sections untouched
            out.append(line.rstrip("\n"))

    # Write the new config back
    with open(RNS_CONFIG_FILE, "w") as f:
        f.write("\n".join(out) + "\n")

    log(f"RNS config written to {RNS_CONFIG_FILE}")

    # Restart rnsd and nomadnet
    subprocess.run(["/etc/init.d/S62nomadnet", "stop"], check=False)
    subprocess.run(["/etc/init.d/S61rnsd", "stop"], check=False)
    subprocess.run(["/etc/init.d/S61rnsd", "start"], check=False)
    subprocess.run(["/etc/init.d/S62nomadnet", "start"], check=False)
    log("RNS daemon and nomadnet restarted")

# -----------------------------
# Ethernet / WiFi updates
# -----------------------------
def update_interface(interface, config):
    if not os.path.exists(INTERFACES_FILE):
        raise FileNotFoundError(f"{INTERFACES_FILE} missing")
    with open(INTERFACES_FILE) as f:
        lines = f.readlines()
    new_lines = []
    in_iface = False
    iface_found = False
    written = {"address": False, "netmask": False, "gateway": False, "broadcast": False}

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"iface {interface}"):
            in_iface = True
            iface_found = True
            written = {k: False for k in written}
            new_lines.append(f"iface {interface} inet {config['ip_config']}")
            continue

        if in_iface:
            if stripped.startswith("iface ") or stripped.startswith("auto "):
                if config['ip_config'] != "dhcp":
                    for field, key in [("ip","address"),("netmask","netmask"),
                                       ("gateway","gateway"),("broadcast","broadcast")]:
                        val = normalize_none(config.get(field))
                        if val and not written[field]:
                            new_lines.append(f"    {key} {val}")
                            written[field] = True
                in_iface = False
                new_lines.append(line.rstrip())
                continue
            for field, key in [("ip","address"),("netmask","netmask"),
                               ("gateway","gateway"),("broadcast","broadcast")]:
                if stripped.startswith(key):
                    val = normalize_none(config.get(field))
                    if val:
                        new_lines.append(f"    {key} {val}")
                        written[field] = True
                    break
            else:
                new_lines.append(line.rstrip())
            continue

        new_lines.append(line.rstrip())

    if not iface_found:
        new_lines.append(f"\nauto {interface}")
        new_lines.append(f"iface {interface} inet {config['ip_config']}")
        if config['ip_config'] != "dhcp":
            for field, key in [("ip","address"),("netmask","netmask"),
                               ("gateway","gateway"),("broadcast","broadcast")]:
                val = normalize_none(config.get(field))
                if val:
                    new_lines.append(f"    {key} {val}")

    with open(INTERFACES_FILE, "w") as f:
        f.write("\n".join(new_lines) + "\n")
    log(f"Updated {interface} in {INTERFACES_FILE}")

def update_resolv_conf(dns1=None, dns2=None, filename="/etc/resolv.conf"):
    try:
        existing = []
        if os.path.exists(filename):
            with open(filename) as f:
                existing = f.read().splitlines()
        search_lines = [l for l in existing if l.lstrip().startswith("search")]
        dns_values = [v for v in (dns1,dns2) if v]
        final = search_lines + [f"nameserver {v}" for v in dns_values]
        with open(filename,"w") as f:
            for l in final:
                f.write(l+"\n")
        log(f"Updated {filename} with DNS")
    except Exception as e:
        log(f"Failed to update {filename}: {e}")

def update_wpa_supplicant(ssid, password, filename=WPA_SUPPLICANT_CONF):
    if not ssid or not password:
        raise ValueError("SSID and password required")
    lines = []
    if os.path.exists(filename):
        with open(filename) as f:
            for l in f:
                stripped = l.strip()
                if stripped.startswith(("network={","ssid=","psk=","}")):
                    continue
                lines.append(l.rstrip())
    lines += ["","network={",f'    ssid="{ssid}"',f'    psk="{password}"',"}"]
    with open(filename,"w") as f:
        f.write("\n".join(lines)+"\n")
    log(f"Wrote WPA supplicant config to {filename}")

def restart_interface(interface):
    try:
        subprocess.run(["ifdown", interface], check=False)
        subprocess.run(["ifup", interface], check=True)
        log(f"Restarted interface {interface}")
    except Exception as e:
        log(f"Failed to restart {interface}: {e}")

# -----------------------------
# Ethernet / WiFi apply
# -----------------------------
def handle_eth_apply(config):
    update_interface("eth0", config)
    if config['ip_config'] != "dhcp":
        update_resolv_conf(config.get("dns1"), config.get("dns2"))
    restart_interface("eth0")
    return {"status":"ok","message":"eth0 configured"}

def handle_wlan_apply(config):
    update_wpa_supplicant(config.get("ssid"), config.get("password"))
    update_interface("wlan0", config)
    if config.get("ip_config") != "dhcp":
        update_resolv_conf(config.get("dns1"), config.get("dns2"))
    restart_interface("wlan0")
    return {"status":"ok","message":"wlan0 configured"}

# -----------------------------
# Client thread for UNIX socket
# -----------------------------
def client_thread(conn):
    try:
        data = conn.recv(65536).decode("utf-8")
        payload = json.loads(data)
        log(f"Received payload: {json.dumps(payload)}")
        action = payload.get("action")
        if action == "apply_rns":
            iface_payload = payload.get("config", [])
            apply_rns_interfaces(iface_payload)
            reply = {"status":"ok","message":"RNS interfaces updated"}
        elif action == "apply_eth":
            reply = handle_eth_apply(payload.get("config",{}))
        elif action == "apply_wlan":
            reply = handle_wlan_apply(payload.get("config",{}))
        else:
            reply = {"status":"error","message":"unknown action"}
        conn.sendall(json.dumps(reply).encode("utf-8"))
    except Exception as e:
        log(f"Error handling client: {e}")
        conn.sendall(json.dumps({"status":"error","message":str(e)}).encode("utf-8"))
    finally:
        conn.close()

# -----------------------------
# Main daemon
# -----------------------------
def main():
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCKET_PATH)
    try:
        import pwd, grp
        os.chown(SOCKET_PATH, pwd.getpwnam("www-data").pw_uid, grp.getgrnam("www-data").gr_gid)
    except Exception:
        log("Failed to chown socket to www-data, continuing")
    sock.listen(5)
    log(f"Listening on {SOCKET_PATH}")
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=client_thread, args=(conn,)).start()

if __name__ == "__main__":
    main()
