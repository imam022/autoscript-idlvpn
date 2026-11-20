#!/usr/bin/env python3
import base64
import datetime
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

CONF_PATH = "/etc/idlvpn/agent.conf"
PORT = 8448

def load_token():
    if os.path.exists(CONF_PATH):
        with open(CONF_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("TOKEN="):
                    return line.strip().split("=", 1)[1]
    return ""

def get_domain():
    for p in ["/etc/xray/domain", "/etc/v2ray/domain", "/root/domain"]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                d = f.read().strip()
                if d:
                    return d
    try:
        return subprocess.check_output(["curl", "-s", "ifconfig.me"], timeout=5).decode().strip()
    except Exception:
        return "localhost"

def get_metrics():
    ram_str = "-"
    try:
        out = subprocess.check_output(["free", "-m"]).decode().splitlines()
        for line in out:
            if line.startswith("Mem:"):
                parts = line.split()
                ram_str = f"{parts[2]}/{parts[1]}MB"
                break
    except Exception:
        pass

    cpu_str = "-"
    try:
        load1 = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        cpu_str = f"{round((load1 / cores) * 100, 1)}%"
    except Exception:
        pass

    uptime_str = "-"
    try:
        uptime_str = subprocess.check_output(["uptime", "-p"]).decode().replace("up ", "").strip()
    except Exception:
        pass

    ssh_cnt = 0
    try:
        with open("/etc/passwd", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[0] != "nobody":
                    uid = int(parts[2])
                    if uid >= 1000:
                        ssh_cnt += 1
    except Exception:
        pass

    def count_db(path):
        if not os.path.exists(path):
            return 0
        c = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("### "):
                    c += 1
        return c

    return {
        "status": "online",
        "ram": ram_str,
        "cpu": cpu_str,
        "uptime": uptime_str,
        "ssh": ssh_cnt,
        "vmess": count_db("/etc/vmess/.vmess.db"),
        "vless": count_db("/etc/vless/.vless.db"),
        "trojan": count_db("/etc/trojan/.trojan.db")
    }

def inject_xray_inbound(tag_keyword, client_entry):
    cfg_path = "/etc/xray/config.json"
    if not os.path.exists(cfg_path):
        return False
    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    modified = False
    for inb in cfg.get("inbounds", []):
        tag = str(inb.get("tag", "")).lower()
        proto = str(inb.get("protocol", "")).lower()
        if tag_keyword in tag or proto == tag_keyword:
            settings = inb.setdefault("settings", {})
            clients = settings.setdefault("clients", [])
            clients.append(client_entry)
            modified = True

    if modified:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        subprocess.run(["systemctl", "restart", "xray"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return modified

def create_account(data):
    proto = str(data.get("protocol", "")).lower().strip()
    user = re.sub(r"[^a-zA-Z0-9_-]", "", str(data.get("username", "")).strip())
    password = str(data.get("password", "")).strip()
    days = int(data.get("days", 30))
    quota = int(data.get("quota", 500))
    iplimit = int(data.get("iplimit", 2))

    if not user:
        return {"status": "error", "message": "Username tidak valid"}

    domain = get_domain()
    now = datetime.date.today()
    exp_date = now + datetime.timedelta(days=days)
    exp_iso = exp_date.strftime("%Y-%m-%d")
    exp_human = exp_date.strftime("%d %b, %Y")
    created_human = now.strftime("%d %b, %Y")

    if proto == "ssh":
        if not password:
            return {"status": "error", "message": "Password SSH wajib diisi"}
        subprocess.run(["userdel", "-f", user], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        res = subprocess.run(
            ["useradd", "-e", exp_iso, "-s", "/bin/false", "-M", user],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if res.returncode != 0:
            return {"status": "error", "message": res.stderr.decode().strip() or "Gagal useradd"}
        p = subprocess.Popen(["passwd", user], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(input=f"{password}\n{password}\n".encode())

        os.makedirs("/etc/xray/ssh", exist_ok=True)
        with open(f"/etc/xray/ssh/{user}", "w", encoding="utf-8") as f:
            f.write(str(iplimit))

        formatted = (
            f"━━━ IDLVPN SSH ACCOUNT ━━━\n"
            f"Host / IP   : {domain}\n"
            f"Username    : {user}\n"
            f"Password    : {password}\n"
            f"Limit IP    : {iplimit} IP\n"
            f"━━━ PORTS & SPEC ━━━\n"
            f"• OpenSSH   : 22\n"
            f"• Dropbear  : 109, 143\n"
            f"• WS TLS    : 443, 8443\n"
            f"• WS Non-TLS: 80, 8080\n"
            f"• UDP Custom: 1-65535\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Masa Aktif  : {days} Hari\n"
            f"Dibuat Pada : {created_human}\n"
            f"Berakhir    : {exp_human}\n"
            f"Powered by IDLVPN Premium"
        )
        return {
            "status": "success",
            "formatted_text": formatted,
            "primary_link": f"{domain}:443@{user}:{password}"
        }

    uid = str(uuid.uuid4())

    if proto == "vmess":
        os.makedirs("/etc/vmess", exist_ok=True)
        if quota > 0:
            with open(f"/etc/vmess/{user}", "w", encoding="utf-8") as f:
                f.write(str(quota * 1024 * 1024 * 1024))
        with open("/etc/vmess/.vmess.db", "a", encoding="utf-8") as f:
            f.write(f"### {user} {exp_iso} {uid} {quota} {iplimit}\n")

        inject_xray_inbound("vmess", {"id": uid, "alterId": 0, "email": user})

        def make_vmess(ps, port, net, path_or_svc, tls_val):
            payload = {
                "v": "2",
                "ps": ps,
                "add": domain,
                "port": str(port),
                "id": uid,
                "aid": "0",
                "net": net,
                "path": path_or_svc,
                "type": "none",
                "host": domain,
                "tls": tls_val
            }
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            return "vmess://" + base64.b64encode(raw).decode("utf-8")

        link_tls = make_vmess(f"{user}-TLS", 443, "ws", "/vmess", "tls")
        link_ntls = make_vmess(f"{user}-NTLS", 80, "ws", "/vmess", "none")
        link_grpc = make_vmess(f"{user}-gRPC", 443, "grpc", "vmess-grpc", "tls")

        formatted = (
            f"━━━ IDLVPN XRAY VMESS ACCOUNT ━━━\n"
            f"Remarks     : {user}\n"
            f"Domain      : {domain}\n"
            f"User Quota  : {quota} GB\n"
            f"Limit IP    : {iplimit} IP\n"
            f"UUID        : {uid}\n"
            f"━━━ PORTS & NETWORK SPEC ━━━\n"
            f"• Port TLS      : 443, 8443, 2087, 2096\n"
            f"• Port Non-TLS  : 80, 8080, 8880, 2082\n"
            f"• AlterID / Sec : 0 / auto\n"
            f"• Network / Path: ws (/vmess) | gRPC (vmess-grpc)\n"
            f"━━━ CONFIG & VMESS LINKS ━━━\n"
            f"Link WS TLS :\n{link_tls}\n\n"
            f"Link WS Non-TLS :\n{link_ntls}\n\n"
            f"Link gRPC :\n{link_grpc}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Masa Aktif  : {days} Hari\n"
            f"Dibuat Pada : {created_human}\n"
            f"Berakhir    : {exp_human}\n"
            f"Powered by IDLVPN Premium"
        )
        return {"status": "success", "formatted_text": formatted, "primary_link": link_tls}

    if proto == "vless":
        os.makedirs("/etc/vless", exist_ok=True)
        if quota > 0:
            with open(f"/etc/vless/{user}", "w", encoding="utf-8") as f:
                f.write(str(quota * 1024 * 1024 * 1024))
        with open("/etc/vless/.vless.db", "a", encoding="utf-8") as f:
            f.write(f"### {user} {exp_iso} {uid} {quota} {iplimit}\n")

        inject_xray_inbound("vless", {"id": uid, "email": user})

        link_tls = f"vless://{uid}@{domain}:443?path=%2Fvless&security=tls&encryption=none&host={domain}&type=ws&sni={domain}#{user}-TLS"
        link_ntls = f"vless://{uid}@{domain}:80?path=%2Fvless&security=none&encryption=none&host={domain}&type=ws#{user}-NTLS"
        link_grpc = f"vless://{uid}@{domain}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni={domain}#{user}-gRPC"

        formatted = (
            f"━━━ IDLVPN XRAY VLESS ACCOUNT ━━━\n"
            f"Remarks     : {user}\n"
            f"Domain      : {domain}\n"
            f"User Quota  : {quota} GB\n"
            f"Limit IP    : {iplimit} IP\n"
            f"UUID        : {uid}\n"
            f"━━━ PORTS & NETWORK SPEC ━━━\n"
            f"• Port TLS      : 443, 8443, 2087, 2096\n"
            f"• Port Non-TLS  : 80, 8080, 8880, 2082\n"
            f"• Network / Path: ws (/vless) | gRPC (vless-grpc)\n"
            f"━━━ CONFIG & VLESS LINKS ━━━\n"
            f"Link WS TLS :\n{link_tls}\n\n"
            f"Link WS Non-TLS :\n{link_ntls}\n\n"
            f"Link gRPC :\n{link_grpc}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Masa Aktif  : {days} Hari\n"
            f"Dibuat Pada : {created_human}\n"
            f"Berakhir    : {exp_human}\n"
            f"Powered by IDLVPN Premium"
        )
        return {"status": "success", "formatted_text": formatted, "primary_link": link_tls}

    if proto == "trojan":
        os.makedirs("/etc/trojan", exist_ok=True)
        if quota > 0:
            with open(f"/etc/trojan/{user}", "w", encoding="utf-8") as f:
                f.write(str(quota * 1024 * 1024 * 1024))
        with open("/etc/trojan/.trojan.db", "a", encoding="utf-8") as f:
            f.write(f"### {user} {exp_iso} {uid} {quota} {iplimit}\n")

        inject_xray_inbound("trojan", {"password": uid, "email": user})

        link_tls = f"trojan://{uid}@{domain}:443?path=%2Ftrojan-ws&security=tls&host={domain}&type=ws&sni={domain}#{user}-TLS"
        link_grpc = f"trojan://{uid}@{domain}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni={domain}#{user}-gRPC"

        formatted = (
            f"━━━ IDLVPN XRAY TROJAN ACCOUNT ━━━\n"
            f"Remarks     : {user}\n"
            f"Domain      : {domain}\n"
            f"User Quota  : {quota} GB\n"
            f"Limit IP    : {iplimit} IP\n"
            f"Key / Pass  : {uid}\n"
            f"━━━ PORTS & NETWORK SPEC ━━━\n"
            f"• Port TLS      : 443, 8443, 2087, 2096\n"
            f"• Network / Path: ws (/trojan-ws) | gRPC (trojan-grpc)\n"
            f"━━━ CONFIG & TROJAN LINKS ━━━\n"
            f"Link WS TLS :\n{link_tls}\n\n"
            f"Link gRPC :\n{link_grpc}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Masa Aktif  : {days} Hari\n"
            f"Dibuat Pada : {created_human}\n"
            f"Berakhir    : {exp_human}\n"
            f"Powered by IDLVPN Premium"
        )
        return {"status": "success", "formatted_text": formatted, "primary_link": link_tls}

    return {"status": "error", "message": "Protokol tidak dikenali"}

def build_backup_zip():
    buf = io.BytesIO()
    targets = [
        "/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
        "/etc/crontab", "/etc/xray", "/etc/vmess", "/etc/vless",
        "/etc/trojan", "/etc/shadowsocks"
    ]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in targets:
            if not os.path.exists(item):
                continue
            if os.path.isfile(item):
                zf.write(item, arcname=os.path.basename(item))
            elif os.path.isdir(item):
                base_name = os.path.basename(item)
                for root, _, files in os.walk(item):
                    for fn in files:
                        full_p = os.path.join(root, fn)
                        rel_p = os.path.join(base_name, os.path.relpath(full_p, item))
                        zf.write(full_p, arcname=rel_p)
    return buf.getvalue()

def restore_from_zip(raw_bytes):
    tmp_dir = tempfile.mkdtemp(prefix="idlvpn_rstr_")
    try:
        zip_path = os.path.join(tmp_dir, "backup.zip")
        with open(zip_path, "wb") as f:
            f.write(raw_bytes)
        if not zipfile.is_zipfile(zip_path):
            return False, "File yang diunggah bukan backup.zip valid"

        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_dir)

        for fname in ["passwd", "group", "shadow", "gshadow", "crontab"]:
            src = os.path.join(extract_dir, fname)
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join("/etc", fname))

        for dname in ["xray", "vmess", "vless", "trojan", "shadowsocks"]:
            src_d = os.path.join(extract_dir, dname)
            dst_d = os.path.join("/etc", dname)
            if os.path.isdir(src_d):
                shutil.copytree(src_d, dst_d, dirs_exist_ok=True)

        subprocess.run(["systemctl", "restart", "xray", "ssh", "dropbear", "cron"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, "Database akun berhasil di-restore & layanan di-restart!"
    except Exception as e:
        return False, f"Gagal ekstrak/restore: {str(e)}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self):
        expected = load_token()
        provided = self.headers.get("X-Auth-Token", "").strip()
        if not expected or provided != expected:
            self._send_json(401, {"status": "error", "message": "Token VPS tidak valid"})
            return False
        return True

    def do_GET(self):
        if not self._check_auth():
            return
        if self.path == "/api/status":
            self._send_json(200, get_metrics())
        elif self.path == "/api/backup":
            data = build_backup_zip()
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="backup.zip"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self._send_json(404, {"status": "error", "message": "Endpoint tidak ditemukan"})

    def do_POST(self):
        if not self._check_auth():
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b""

        if self.path == "/api/create":
            try:
                payload = json.loads(raw.decode("utf-8"))
                res = create_account(payload)
                self._send_json(200 if res.get("status") == "success" else 400, res)
            except Exception as e:
                self._send_json(400, {"status": "error", "message": str(e)})
        elif self.path == "/api/restore":
            ok, msg = restore_from_zip(raw)
            self._send_json(200 if ok else 400, {"status": "success" if ok else "error", "message": msg})
        else:
            self._send_json(404, {"status": "error", "message": "Endpoint tidak ditemukan"})

if __name__ == "__main__":
    server = ThreadedHTTPServer(("0.0.0.0", PORT), AgentHandler)
    server.serve_forever()
