#!/usr/bin/env python3
import os
import sys
import urllib.parse
import subprocess
import secrets

# ================= CONFIG =================

ALLOWED_FILES = [
    "/mnt/rns/.reticulum/config",
    "/mnt/rns/.nomadnetwork/config",
    "/mnt/rns/rnode.yaml"
]

AUTH_USER = "root"   # <-- system user to authenticate against
AUTH_HELPER = "/usr/bin/cgi-auth"
SESSION_DIR = "/tmp/editor-sessions"
RESTART_SCRIPT = "/usr/sbin/restart-rns"

# ==========================================

os.makedirs(SESSION_DIR, exist_ok=True)

def respond(status, body, headers=None):
    print(f"Status: {status}")
    if headers:
        for k, v in headers.items():
            print(f"{k}: {v}")
    print("Content-Type: text/plain\n")
    print(body)
    sys.exit(0)

def parse_cookies():
    cookies = {}
    raw = os.environ.get("HTTP_COOKIE", "")
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k] = v
    return cookies

def valid_session():
    cookies = parse_cookies()
    sid = cookies.get("EDITORSESSID")
    if not sid:
        return False
    return os.path.exists(os.path.join(SESSION_DIR, sid))

def authenticate(password):
    try:
        p = subprocess.Popen(
            [AUTH_HELPER, AUTH_USER],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        p.stdin.write((password + "\n").encode())
        p.stdin.close()
        return p.wait() == 0
    except:
        return False

def create_session():
    sid = secrets.token_hex(16)
    open(os.path.join(SESSION_DIR, sid), "w").close()
    return sid

# ============ REQUEST PARSING ==============

method = os.environ.get("REQUEST_METHOD", "GET")
query = urllib.parse.parse_qs(os.environ.get("QUERY_STRING", ""))
path = query.get("path", [None])[0]
restart = query.get("restart", ["0"])[0] == "1"
action = query.get("action", [None])[0]

# ============ AUTH HANDLING =================

if action == "login" and method == "POST":
    length = int(os.environ.get("CONTENT_LENGTH", 0))
    password = sys.stdin.read(length).strip()

    if authenticate(password):
        sid = create_session()
        respond(
            "200 OK",
            "OK",
            headers={
                "Set-Cookie": f"EDITORSESSID={sid}; HttpOnly; SameSite=Strict"
            }
        )
    else:
        respond("403 Forbidden", "Authentication failed")

if not valid_session():
    respond("401 Unauthorized", "Not authenticated")

# ============ FILE VALIDATION ===============

if path not in ALLOWED_FILES:
    respond("403 Forbidden", "File not allowed")

# ============ FILE OPERATIONS ===============

if method == "GET":
    try:
        with open(path, "r") as f:
            respond("200 OK", f.read())
    except Exception as e:
        respond("404 Not Found", str(e))

elif method == "POST":
    try:
        length = int(os.environ.get("CONTENT_LENGTH", 0))
        content = sys.stdin.read(length)

        # Backup
        if os.path.exists(path):
            with open(path, "r") as f:
                open(path + ".bak", "w").write(f.read())

        with open(path, "w") as f:
            f.write(content)

        msg = "Config Saved."

        if restart:
            subprocess.run([RESTART_SCRIPT], check=True)
            msg += " RNS restarted."

        respond("200 OK", msg)

    except Exception as e:
        respond("500 Internal Server Error", str(e))

else:
    respond("405 Method Not Allowed", "Invalid method")
