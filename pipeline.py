#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🚀 ULTRA VPN SERVER v3.1 (GitHub Edition, без Telegram-бота)
- Адаптирован под запуск на сервере / GitHub Actions
- Все секреты берутся из переменных окружения
- Есть режим --generate-only (для крона)
"""

import json
import re
import os
import sys
import socket
import threading
import time
import requests
import base64
import random
import string
import hashlib
import shutil
import logging
import argparse
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from logging.handlers import RotatingFileHandler

# ==================== КОНФИГ ====================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
JSON_CONFIGS_DIR = os.path.join(BASE_DIR, "jsonconfigs")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")

for d in (DATA_DIR, LOG_DIR, OUTPUT_DIR, JSON_CONFIGS_DIR, BACKUP_DIR):
    os.makedirs(d, exist_ok=True)

SUBSCRIPTION_FILE = os.path.join(BASE_DIR, "url.txt")
SUBSCRIPTIONS_FILE = os.path.join(DATA_DIR, "subscriptions.json")

YOOMONEY_SECRET = os.environ.get(
    "YOOMONEY_SECRET",
    "1D63696E8DF74727C2EA8DEA91E23FF4D1837A1FE67B90FA1F9072BCBB46621C",
)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "!QAZ@WSX!@#!")
SERVER_DOMAIN = os.environ.get("SERVER_DOMAIN", "https://test.zetafiles.netcraze.pro")
PORT = int(os.environ.get("PORT", "8084"))
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", str(60 * 60)))

# ==================== ЛОГИРОВАНИЕ ====================

logger = logging.getLogger("UltraVPN")
logger.setLevel(logging.DEBUG)

file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "ultravpn.log"),
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
))
logger.addHandler(file_handler)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
))
logger.addHandler(console_handler)

# ==================== ГЛОБАЛЬНЫЕ ====================

CONFIGS = []
LAST_UPDATE = None

HEADERS = {
    "profile-title": "UltraVPN Obhod",
    "subscription-userinfo": "upload=0; download=0; total=0; expire=2524597200",
    "profile-update-interval": "1",
    "support-url": "https://t.me/infozevpn_bot",
    "profile-web-page-url": "https://t.me/UltraInfo_News",
    "sub-info": "UltraVPN - Free configs for everyone! Auto-update every hour",
}

TRAFFIC_UPDATE_COST_BYTES = 1024 * 1024 * 1024  # 1 ГБ

COUNTRIES = {
    "DE": {"flag": "🇩🇪", "name": "Германия"},
    "FR": {"flag": "🇫🇷", "name": "Франция"},
    "US": {"flag": "🇺🇸", "name": "США"},
    "GB": {"flag": "🇬🇧", "name": "Великобритания"},
    "NL": {"flag": "🇳🇱", "name": "Нидерланды"},
    "PL": {"flag": "🇵🇱", "name": "Польша"},
    "FI": {"flag": "🇫🇮", "name": "Финляндия"},
    "SE": {"flag": "🇸🇪", "name": "Швеция"},
    "JP": {"flag": "🇯🇵", "name": "Япония"},
    "TR": {"flag": "🇹🇷", "name": "Турция"},
    "EE": {"flag": "🇪🇪", "name": "Эстония"},
    "LT": {"flag": "🇱🇹", "name": "Литва"},
    "CH": {"flag": "🇨🇭", "name": "Швейцария"},
    "RU": {"flag": "🇷🇺", "name": "Россия"},
    "CZ": {"flag": "🇨🇿", "name": "Чехия"},
}


def get_server_url():
    return SERVER_DOMAIN


# ==================== HAPP ENCRYPT ====================

def get_happ_encrypted_link(raw_url: str) -> str:
    try:
        api_url = "https://crypto.happ.su/api-v2.php"
        headers = {"Content-Type": "application/json"}
        payload = {"url": raw_url}
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            try:
                result = response.json()
                link = result.get("encrypted_link")
                if link:
                    return link.strip("'\" \n\r")
            except Exception:
                pass
        return raw_url.strip("'\" \n\r")
    except Exception:
        return raw_url.strip("'\" \n\r")


# ==================== BACKUP ====================

def backup_files():
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if os.path.exists(SUBSCRIPTIONS_FILE):
            shutil.copy(SUBSCRIPTIONS_FILE, os.path.join(BACKUP_DIR, f"subscriptions_{timestamp}.json"))
        files = sorted(os.listdir(BACKUP_DIR))
        if len(files) > 20:
            for f in files[:-20]:
                os.remove(os.path.join(BACKUP_DIR, f))
    except Exception as e:
        logger.error(f"Backup error: {e}")


# ==================== SUBSCRIPTIONS ====================

class SubscriptionManager:
    def __init__(self, file_path=SUBSCRIPTIONS_FILE):
        self.file_path = file_path
        self.subscriptions = {}
        self.load()

    def load(self):
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r", encoding="utf-8") as f:
                    self.subscriptions = json.load(f)
            except Exception:
                self.subscriptions = {}

    def save(self):
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(self.subscriptions, f, indent=2, ensure_ascii=False)
        backup_files()

    def generate_code(self, length=16):
        chars = string.ascii_uppercase + string.digits
        chars = "".join(c for c in chars if c not in "O0I1")
        while True:
            code = "".join(random.choice(chars) for _ in range(length))
            if code not in self.subscriptions:
                return code

    def create_subscription(self, user_id=None, user_name=None, days=30, config_count=100, description=""):
        code = self.generate_code()
        sub = {
            "code": code,
            "user_id": user_id,
            "user_name": user_name or f"User_{code}",
            "description": description or f"Подписка для {user_name or code}",
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=days)).isoformat(),
            "is_active": True,
            "config_count": config_count,
            "configs": [],
            "usage": {"upload": 0, "download": 0},
            "devices": [],
            "device_names": {},
            "last_notify": "",
        }
        self.subscriptions[code] = sub
        self.save()
        return code, sub

    def create_or_extend_subscription(self, user_id, user_name, days, config_count=100, description=""):
        user_id = str(user_id) if user_id is not None else None
        code, existing = self.get_subscription_by_user_id(user_id) if user_id else (None, None)
        if existing:
            current = datetime.fromisoformat(existing["expires_at"])
            new_exp = (datetime.now() + timedelta(days=days)) if current < datetime.now() else (current + timedelta(days=days))
            existing["expires_at"] = new_exp.isoformat()
            existing["is_active"] = True
            existing["config_count"] = config_count
            existing["description"] = f"{existing.get('description', '')} | +{days}д. ({description})"
            existing["user_name"] = user_name or existing.get("user_name", f"User_{code}")
            self.save()
            return existing["code"], existing
        return self.create_subscription(user_id, user_name, days, config_count, description)

    def get_subscription(self, code):
        if not code:
            return None
        return self.subscriptions.get(code.upper().strip())

    def get_subscription_by_user_id(self, user_id):
        user_id = str(user_id)
        for code, sub in self.subscriptions.items():
            if str(sub.get("user_id")) == user_id:
                return code, sub
        return None, None

    def delete_subscription(self, code):
        if not code:
            return False
        code = code.upper().strip()
        if code in self.subscriptions:
            del self.subscriptions[code]
            self.save()
            return True
        return False

    def get_all_codes(self):
        return list(self.subscriptions.keys())

    def extend_subscription(self, code, days=30):
        sub = self.get_subscription(code)
        if sub:
            current = datetime.fromisoformat(sub["expires_at"])
            new_exp = (datetime.now() + timedelta(days=days)) if current < datetime.now() else (current + timedelta(days=days))
            sub["expires_at"] = new_exp.isoformat()
            sub["is_active"] = True
            self.save()
            return True
        return False


sub_manager = SubscriptionManager()


# ==================== CONFIG GENERATION ====================

def get_all_configs():
    all_configs = []

    if os.path.exists(JSON_CONFIGS_DIR):
        for filename in os.listdir(JSON_CONFIGS_DIR):
            if filename.endswith(".json"):
                try:
                    with open(os.path.join(JSON_CONFIGS_DIR, filename), "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    if "outbounds" in cfg and len(cfg.get("outbounds", [])) > 0:
                        if "remarks" not in cfg:
                            cfg["remarks"] = f"📦 {filename.replace('.json', '')}"
                        all_configs.append(cfg)
                except Exception as e:
                    logger.error(f"Error reading {filename}: {e}")

    urls = load_urls()
    if urls:
        all_content = []
        for url in urls:
            content = fetch_subscription(url)
            if content:
                all_content.append(content)
        if all_content:
            full_text = "\n".join(all_content)
            raw_links = [line.strip() for line in full_text.split("\n") if "vless://" in line]
            servers = []
            for link in raw_links:
                parsed = parse_vless(link)
                if parsed:
                    servers.append(parsed)
            unique = {}
            for s in servers:
                key = (s["uuid"], s["address"], s["port"])
                if key not in unique:
                    unique[key] = s
            servers = list(unique.values())
            grouped = group_by_ip_port(servers)
            for idx, s in enumerate(grouped):
                cfg = generate_json(s, idx)
                if cfg:
                    all_configs.append(cfg)
    return all_configs


def load_urls():
    if not os.path.exists(SUBSCRIPTION_FILE):
        return []
    with open(SUBSCRIPTION_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def fetch_subscription(url):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        content = r.text.strip()
        try:
            if re.match(r"^[A-Za-z0-9+/=]+$", content):
                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                if "vless://" in decoded:
                    content = decoded
        except Exception:
            pass
        if "vless://" not in content:
            try:
                data = json.loads(content)
                if "outbounds" in data:
                    return extract_vless_from_json(data)
            except Exception:
                pass
        return content
    except Exception:
        return None


def extract_vless_from_json(data):
    links = []

    def traverse(obj):
        if isinstance(obj, dict):
            if obj.get("protocol") == "vless":
                settings = obj.get("settings", {})
                for vn in settings.get("vnext", []):
                    address = vn.get("address", "")
                    port = vn.get("port", 443)
                    for user in vn.get("users", []):
                        uuid = user.get("id", "")
                        encryption = user.get("encryption", "none")
                        flow = user.get("flow", "")
                        stream = obj.get("streamSettings", {})
                        reality = stream.get("realitySettings", {})
                        sni = reality.get("serverName", "")
                        fp = reality.get("fingerprint", "chrome")
                        pbk = reality.get("publicKey", "")
                        sid = reality.get("shortId", "")
                        network = stream.get("network", "tcp")
                        service = stream.get("grpcSettings", {}).get("serviceName", "")
                        path = stream.get("xhttpSettings", {}).get("path", "/")
                        links.append(
                            f"vless://{uuid}@{address}:{port}?encryption={encryption}"
                            f"&flow={flow}&security=reality&sni={sni}&fp={fp}&pbk={pbk}"
                            f"&sid={sid}&type={network}&serviceName={service}&path={path}"
                        )
            for v in obj.values():
                traverse(v)
        elif isinstance(obj, list):
            for item in obj:
                traverse(item)

    traverse(data)
    return "\n".join(links)


def parse_vless(link):
    if not link or not link.startswith("vless://"):
        return None
    link = link.strip()
    if "#" in link:
        link, tag = link.split("#", 1)
    else:
        tag = ""
    try:
        parsed = urlparse(link)
        netloc = parsed.netloc
        if "@" not in netloc:
            return None
        uuid, address_port = netloc.split("@", 1)
        if ":" not in address_port:
            return None
        address, port = address_port.split(":", 1)
        if not address or not port or not port.isdigit():
            return None
        params = {}
        if parsed.query:
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0] if v else ""
        return {"uuid": uuid, "address": address, "port": int(port), "tag": tag, "params": params}
    except Exception:
        return None


def get_country_name(code):
    if code in COUNTRIES:
        return f"{COUNTRIES[code]['flag']} {COUNTRIES[code]['name']}"
    return code


def group_by_ip_port(servers):
    groups = defaultdict(list)
    for s in servers:
        if s:
            groups[(s["address"], s["port"])].append(s)
    result = []
    for (address, port), lst in groups.items():
        base = lst[0].copy()
        fps, uuids, snis, pbks, sids = [], [], [], [], []
        for s in lst:
            if s["params"].get("fp"):
                fps.append(s["params"]["fp"])
            if s["uuid"]:
                uuids.append(s["uuid"])
            if s["params"].get("sni"):
                snis.append(s["params"]["sni"])
            if s["params"].get("pbk"):
                pbks.append(s["params"]["pbk"])
            if s["params"].get("sid"):
                sids.append(s["params"]["sid"])
        base["fingerprints"] = list(set(fps)) if fps else ["chrome"]
        base["all_uuids"] = list(set(uuids))
        base["all_snis"] = list(set(snis))
        base["all_pbks"] = list(set(pbks))
        base["all_sids"] = list(set(sids))
        base["country_code"] = "DE"
        result.append(base)
    return result


def generate_json(server, server_index=0):
    address = server["address"]
    port = server["port"]
    country_code = "DE"
    uuid_list = server.get("all_uuids", [server["uuid"]])
    uuid = uuid_list[server_index % len(uuid_list)] if uuid_list else server["uuid"]
    fp = server.get("fingerprints", ["chrome"])[0]
    sni_list = server.get("all_snis", [])
    sni = sni_list[0] if sni_list else server["params"].get("sni", "")
    pbk_list = server.get("all_pbks", [])
    pbk = pbk_list[0] if pbk_list else server["params"].get("pbk", "")
    sid_list = server.get("all_sids", [])
    sid = sid_list[0] if sid_list else server["params"].get("sid", "")
    network = server["params"].get("type", "tcp")
    flow = server["params"].get("flow", "")
    encryption = server["params"].get("encryption", "none")
    service_name = server["params"].get("serviceName", "")
    path = server["params"].get("path", "/")

    stream = {
        "network": network,
        "security": "reality",
        "realitySettings": {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
        },
    }
    if network == "grpc":
        stream["grpcSettings"] = {"serviceName": service_name or "grpc"}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": path or "/"}

    outbound = {
        "tag": f"{country_code}-{address}-{server_index}",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": address,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": encryption,
                    "flow": flow if flow else "",
                    "level": 8,
                }],
            }]
        },
        "streamSettings": stream,
    }

    country_name = get_country_name(country_code)

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}, "tag": "socks-in"},
            {"port": 10809, "protocol": "http", "settings": {}, "tag": "http-in"},
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
            {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:category-ru", "domain:ru", "domain:su"], "outboundTag": "direct"},
                {"type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": outbound["tag"]},
            ],
        },
        "remarks": country_name,
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def generate_user_subscription_json(code):
    sub = sub_manager.get_subscription(code)
    if not sub or not sub.get("is_active", False):
        return None
    expires_at = datetime.fromisoformat(sub["expires_at"])
    if expires_at < datetime.now():
        return generate_expired_subscription(code)
    all_configs = get_all_configs()
    if not all_configs:
        return generate_expired_subscription(code)
    return all_configs[: sub.get("config_count", 100)]


def generate_expired_subscription(code):
    sub = sub_manager.get_subscription(code)
    if not sub:
        return None
    free = []
    for i in (1, 2):
        free.append({
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}, "tag": "socks-in"},
                {"port": 10809, "protocol": "http", "settings": {}, "tag": "http-in"},
            ],
            "outbounds": [{"tag": f"free-server-{i}", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": f"free-server-{i}"},
                ],
            },
            "remarks": f"🔓 Бесплатный сервер #{i}",
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "is_free": True,
        })
    return free


def update_configs():
    global CONFIGS, LAST_UPDATE
    logger.info("Updating configs...")
    all_configs = get_all_configs()
    if all_configs:
        CONFIGS = all_configs
        LAST_UPDATE = datetime.now()
        logger.info(f"Loaded {len(CONFIGS)} configs")
        for code in sub_manager.get_all_codes():
            user_configs = generate_user_subscription_json(code)
            if user_configs:
                with open(os.path.join(OUTPUT_DIR, f"sub_{code}.json"), "w", encoding="utf-8") as f:
                    json.dump(user_configs, f, indent=2, ensure_ascii=False)
        logger.info(f"Updated {len(sub_manager.get_all_codes())} personal subscriptions")
    else:
        logger.error("No configs!")


def add_hidden_traffic(user_id):
    try:
        code, sub = sub_manager.get_subscription_by_user_id(user_id)
        if sub:
            usage = sub.get("usage", {"upload": 0, "download": 0})
            usage["download"] += TRAFFIC_UPDATE_COST_BYTES
            sub["usage"] = usage
            sub_manager.save()
            return True
    except Exception:
        pass
    return False


def auto_update_loop():
    while True:
        update_configs()
        logger.info(f"Next update in {UPDATE_INTERVAL // 60} min")
        time.sleep(UPDATE_INTERVAL)


# ==================== HTTP HANDLER ====================

class ConfigHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug(fmt % args)

    def do_GET(self):
        try:
            path = self.path.split("?")[0]

            if path.startswith("/r/"):
                self.handle_redirect(path)
                return
            if path in ("/webapp", "/webapp/", "/docs", "/docs.html", "/webapp/docs", "/webapp/docs.html"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(self.get_webapp_html().encode("utf-8"))
                return
            if path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(self.get_main_html().encode("utf-8"))
                return
            if path.startswith("/admin"):
                if path == "/admin/logout":
                    self.handle_admin_logout()
                    return
                self.handle_admin(path)
                return
            if path.startswith("/sub/"):
                self.handle_subscription(path)
                return
            if path == "/subscriptions":
                self.handle_subscriptions_list()
                return
            if path == "/configs/sub.json":
                self.handle_configs()
                return
            if path == "/subscription":
                self.handle_subscription_list()
                return
            if path.startswith("/api/subscription/"):
                self.handle_api_subscription_get(path)
                return

            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"GET Error: {e}")

    def do_POST(self):
        try:
            path = self.path.split("?")[0]
            length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(length).decode("utf-8")
            params = parse_qs(post_data)

            if path == "/yoomoney_webhook":
                self.handle_yoomoney_webhook(params)
                return
            if path == "/api/trial":
                self.handle_trial_api(post_data)
                return
            if path == "/api/reset_devices":
                self.handle_reset_devices(post_data)
                return
            if path == "/api/subscription/create":
                self.handle_api_subscription_create(post_data)
                return
            if path.startswith("/admin/"):
                self.handle_admin_post(path, params)
                return
            if path == "/admin":
                self.handle_admin_login(params)
                return
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"POST Error: {e}")

    # ========== REDIRECT ==========

    def handle_redirect(self, path):
        try:
            parts = path.split("/")
            code = parts[2] if len(parts) > 2 else ""
            if not code or not sub_manager.get_subscription(code):
                self.send_response(404)
                self.end_headers()
                return
            raw = f"{get_server_url()}/sub/{code}"
            enc = get_happ_encrypted_link(raw)
            html = f"""<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url={enc}"><title>Redirect</title></head><body><a href="{enc}">Открыть в HAPP</a></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        except Exception as e:
            logger.error(f"Redirect error: {e}")
            self.send_response(500)
            self.end_headers()

    # ========== YOOMONEY ==========

    def handle_yoomoney_webhook(self, params):
        def g(k):
            return params.get(k, [""])[0]

        notification_type = g("notification_type")
        operation_id = g("operation_id")
        amount = g("amount")
        currency = g("currency")
        datetime_str = g("datetime")
        sender = g("sender")
        codepro = g("codepro")
        label = g("label")
        sha1_hash = g("sha1_hash")

        signature_source = (
            f"{notification_type}&{operation_id}&{amount}&{currency}&"
            f"{datetime_str}&{sender}&{codepro}&{YOOMONEY_SECRET}&{label}"
        )
        signature = hashlib.sha1(signature_source.encode("utf-8")).hexdigest()

        if signature != sha1_hash:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid signature")
            return

        if not label.startswith("yoomoney_"):
            self.send_response(400)
            self.end_headers()
            return

        parts = label.split("_")
        tariff = parts[1]
        user_id = parts[2]

        if tariff == "1":
            days, price, name = 30, 210, "1 месяц"
        elif tariff == "2":
            days, price, name = 60, 399, "2 месяца"
        else:
            days, price, name = 90, 570, "3 месяца"

        code, _ = sub_manager.create_or_extend_subscription(
            user_id=int(user_id),
            user_name=f"User_{user_id}",
            days=days,
            config_count=100,
            description=f"Оплачено {price}₽ за {name}",
        )
        logger.info(f"[YooMoney] Payment OK tariff={tariff} user={user_id} code={code}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    # ========== TRIAL ==========

    def handle_trial_api(self, post_data):
        try:
            data = json.loads(post_data)
            user_id = data.get("user_id")
            user_name = data.get("user_name", f"User_{user_id}")
            if not user_id:
                self._json(400, {"status": "error", "message": "user_id required"})
                return
            user_id_str = str(user_id)

            _, existing = sub_manager.get_subscription_by_user_id(user_id_str)
            if existing:
                exp = datetime.fromisoformat(existing["expires_at"])
                if exp > datetime.now():
                    self._json(400, {"status": "error", "message": "У вас уже есть активная подписка"})
                    return

            code, _ = sub_manager.create_or_extend_subscription(
                user_id=int(user_id), user_name=user_name, days=1,
                config_count=100, description="Тестовый период 24 часа",
            )
            raw = f"{get_server_url()}/sub/{code}"
            enc = get_happ_encrypted_link(raw)
            self._json(200, {"status": "success", "code": code, "encrypted_link": enc, "raw_link": raw})
        except Exception as e:
            logger.error(f"Trial error: {e}")
            self._json(500, {"status": "error", "message": str(e)})

    def handle_reset_devices(self, post_data):
        try:
            data = json.loads(post_data)
            user_id = data.get("user_id")
            if not user_id:
                self._json(400, {"status": "error", "message": "user_id required"})
                return
            code, sub = sub_manager.get_subscription_by_user_id(user_id)
            if not sub:
                self._json(404, {"status": "error", "message": "not found"})
                return
            old = len(sub.get("devices", []))
            sub["devices"] = []
            sub["device_names"] = {}
            sub_manager.save()
            self._json(200, {"status": "success", "message": f"Reset {old} devices"})
        except Exception as e:
            logger.error(f"Reset devices error: {e}")
            self._json(500, {"status": "error", "message": str(e)})

    def handle_api_subscription_create(self, post_data):
        try:
            data = json.loads(post_data)
            user_id = data.get("user_id")
            if not user_id:
                self._json(400, {"status": "error", "message": "user_id required"})
                return
            user_name = data.get("user_name", f"User_{user_id}")
            days = data.get("days", 30)
            count = data.get("config_count", 100)
            code, _ = sub_manager.create_or_extend_subscription(
                user_id=int(user_id), user_name=user_name, days=days,
                config_count=count, description=data.get("description", f"Подписка для {user_name}"),
            )
            raw = f"{get_server_url()}/sub/{code}"
            enc = get_happ_encrypted_link(raw)
            self._json(200, {"status": "success", "code": code, "encrypted_link": enc, "raw_link": raw})
        except Exception as e:
            logger.error(f"API create error: {e}")
            self._json(500, {"status": "error", "message": str(e)})

    def handle_api_subscription_get(self, path):
        try:
            user_id = path.split("/")[-1]
            code, sub = sub_manager.get_subscription_by_user_id(user_id)
            if sub:
                self._json(200, {"subscription": {
                    "code": code,
                    "user_id": sub.get("user_id"),
                    "user_name": sub.get("user_name"),
                    "expires_at": sub.get("expires_at"),
                    "is_active": sub.get("is_active", False),
                    "config_count": sub.get("config_count", 0),
                    "description": sub.get("description", ""),
                    "devices": sub.get("devices", []),
                    "device_names": sub.get("device_names", {}),
                    "usage": sub.get("usage", {"upload": 0, "download": 0}),
                }})
            else:
                self._json(200, {"subscription": None})
        except Exception as e:
            logger.error(f"API get error: {e}")
            self._json(500, {"status": "error", "message": str(e)})

    def _json(self, code, obj):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    # ========== SUBSCRIPTION ==========

    def get_device_id(self):
        ua = self.headers.get("User-Agent", "unknown")
        name = self.get_device_name(ua)
        stable = re.sub(r"[0-9]+", "", ua)
        return hashlib.md5(stable.encode()).hexdigest()[:12], name, ua

    def get_device_name(self, ua):
        u = ua.lower()
        if "android" in u:
            return "Android"
        if "iphone" in u or "ipad" in u:
            return "iPhone/iOS"
        if "windows" in u:
            return "Windows 64-bit" if "x64" in u else "Windows"
        if "macintosh" in u or "mac os" in u:
            return "Mac"
        if "linux" in u:
            return "Linux"
        if "chrome" in u:
            return "Chrome Browser"
        if "firefox" in u:
            return "Firefox Browser"
        return "Неизвестное устройство"

    def handle_subscription(self, path):
        parts = path.split("/")
        code = parts[2] if len(parts) > 2 else ""
        if not code:
            self.send_response(400)
            self.end_headers()
            return
        sub = sub_manager.get_subscription(code)
        user_configs = generate_user_subscription_json(code)
        if user_configs is None or not sub:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Invalid or expired code")
            return

        user_id = sub.get("user_id")
        if user_id:
            add_hidden_traffic(user_id)

        ua = self.headers.get("User-Agent", "").lower()
        is_browser = any(k in ua for k in ("mozilla", "chrome", "safari", "edge", "opera", "firefox", "brave", "vivaldi"))

        if not is_browser:
            device_id, device_name, ua_full = self.get_device_id()
            devices = sub.get("devices", [])
            names = sub.get("device_names", {})
            if device_id not in devices:
                if len(devices) >= 10:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"Max devices")
                    return
                devices.append(device_id)
                names[device_id] = {"device_name": device_name, "user_agent": ua_full[:100], "first_seen": datetime.now().isoformat(), "last_seen": datetime.now().isoformat()}
                sub["devices"] = devices
                sub["device_names"] = names
                sub_manager.save()
            else:
                if device_id in names:
                    names[device_id]["last_seen"] = datetime.now().isoformat()
                    sub["device_names"] = names
                    sub_manager.save()

        if is_browser:
            expires = datetime.fromisoformat(sub["expires_at"])
            is_active = sub.get("is_active", False) and expires > datetime.now()
            raw = f"{get_server_url()}/sub/{code}"
            enc = get_happ_encrypted_link(raw)
            html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>UltraVPN {code}</title></head><body style="font-family:sans-serif;background:#0a0a0f;color:#fff;padding:40px;text-align:center;"><h1>🚀 UltraVPN</h1><p>Статус: {'🟢 Активна' if is_active else '🔴 Истекла'}</p><p>Код: <b>{code}</b></p><p>До: {expires.strftime('%Y-%m-%d %H:%M')}</p><p>Ссылка HAPP:</p><code style="word-break:break-all;">{enc}</code></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
            return

        user_file = os.path.join(OUTPUT_DIR, f"sub_{code}.json")
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user_configs, f, indent=2, ensure_ascii=False)
        with open(user_file, "r", encoding="utf-8") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        for k, v in HEADERS.items():
            self.send_header(k, v)
        ui = sub.get("usage", {})
        expire_ts = int(datetime.fromisoformat(sub["expires_at"]).timestamp())
        self.send_header("subscription-userinfo",
                         f"upload={ui.get('upload',0)}; download={ui.get('download',0)}; total=0; expire={expire_ts}")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    # ========== STATIC PAGES ==========

    def get_main_html(self):
        codes = sub_manager.get_all_codes()
        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>UltraVPN</title></head>
<body style="font-family:sans-serif;background:#0a0a0f;color:#fff;text-align:center;padding:60px;">
<h1 style="font-size:48px;background:linear-gradient(135deg,#00ffc8,#00d4ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">🚀 UltraVPN</h1>
<p>Конфигов: <b>{len(CONFIGS)}</b> | Подписок: <b>{len(codes)}</b></p>
<a href="/admin" style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#00ffc8,#00d4ff);color:#0a0a0f;border-radius:12px;text-decoration:none;font-weight:700;margin-top:20px;">🔐 Админ-панель</a>
</body></html>"""

    def get_webapp_html(self):
        return """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Документы</title></head>
<body style="font-family:sans-serif;background:#0a0a0f;color:#fff;padding:40px;">
<h1>📋 Документы UltraVPN</h1>
<p>Политика конфиденциальности, соглашение, отказ от ответственности.</p>
</body></html>"""

    # ========== ADMIN ==========

    def handle_admin(self, path):
        cookie = self.headers.get("Cookie", "")
        if "admin_auth=1" not in cookie:
            if path in ("/admin", "/admin/"):
                html = """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin</title></head>
<body style="font-family:sans-serif;background:#0a0a0f;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;">
<form method="POST" action="/admin" style="background:rgba(255,255,255,0.05);padding:40px;border-radius:24px;">
<h1>🔐 Админ</h1><input type="password" name="password" placeholder="Пароль" required style="width:100%;padding:14px;margin:16px 0;background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);border-radius:12px;color:#fff;">
<button type="submit" style="width:100%;padding:14px;background:linear-gradient(135deg,#00ffc8,#00d4ff);border:none;border-radius:12px;font-weight:700;cursor:pointer;">Войти</button>
</form></body></html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))
                return
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.end_headers()
            return

        codes = sub_manager.get_all_codes()
        active = len([c for c in codes if sub_manager.get_subscription(c) and sub_manager.get_subscription(c).get("is_active")])
        rows = ""
        for code in codes:
            sub = sub_manager.get_subscription(code)
            if not sub:
                continue
            exp = datetime.fromisoformat(sub["expires_at"])
            is_act = sub.get("is_active", False) and exp > datetime.now()
            rows += f"<tr><td>{code}</td><td>{sub.get('user_name','')}</td><td>{sub.get('user_id','—')}</td><td>{exp.strftime('%Y-%m-%d %H:%M')}</td><td>{'✅' if is_act else '⛔'}</td><td>{len(sub.get('devices',[]))}/10</td></tr>"
        html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin</title></head>
<body style="font-family:sans-serif;background:#0a0a0f;color:#fff;padding:40px;">
<h1>🔐 Админ-панель</h1>
<p>Всего: {len(codes)} | Активных: {active} | Конфигов: {len(CONFIGS)}</p>
<form method="POST" action="/admin/create" style="margin:20px 0;display:flex;gap:10px;flex-wrap:wrap;">
<input name="user_name" placeholder="Имя" required style="padding:10px;border-radius:8px;border:1px solid #333;background:#111;color:#fff;">
<input name="user_id" placeholder="Telegram ID" style="padding:10px;border-radius:8px;border:1px solid #333;background:#111;color:#fff;">
<input name="days" type="number" value="30" required style="padding:10px;border-radius:8px;border:1px solid #333;background:#111;color:#fff;width:80px;">
<input name="config_count" type="number" value="100" required style="padding:10px;border-radius:8px;border:1px solid #333;background:#111;color:#fff;width:80px;">
<button type="submit" style="padding:10px 20px;background:linear-gradient(135deg,#00ffc8,#00d4ff);border:none;border-radius:8px;font-weight:700;cursor:pointer;">Создать</button>
</form>
<table style="width:100%;border-collapse:collapse;margin-top:20px;">
<tr style="border-bottom:1px solid #333;"><th>Код</th><th>Имя</th><th>TG ID</th><th>До</th><th>Активна</th><th>Устройства</th></tr>
{rows}
</table>
<p style="margin-top:30px;"><a href="/admin/logout" style="color:#ff6b6b;">🚪 Выйти</a></p>
</body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def handle_admin_login(self, params):
        password = params.get("password", [""])[0]
        if password == ADMIN_PASSWORD:
            self.send_response(302)
            self.send_header("Set-Cookie", "admin_auth=1; path=/")
            self.send_header("Location", "/admin")
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.end_headers()

    def handle_admin_logout(self):
        self.send_response(302)
        self.send_header("Set-Cookie", "admin_auth=; path=/; Max-Age=0")
        self.send_header("Location", "/admin")
        self.end_headers()

    def handle_admin_post(self, path, params):
        cookie = self.headers.get("Cookie", "")
        if "admin_auth=1" not in cookie:
            self.send_response(302)
            self.send_header("Location", "/admin")
            self.end_headers()
            return

        if "/create" in path:
            user_name = params.get("user_name", ["User"])[0]
            days = int(params.get("days", ["30"])[0])
            count = int(params.get("config_count", ["100"])[0])
            desc = params.get("description", [""])[0]
            user_id = params.get("user_id", [None])[0]
            sub_manager.create_or_extend_subscription(
                user_id=user_id if user_id and user_id != "None" else None,
                user_name=user_name, days=days, config_count=count, description=desc,
            )
        elif "/extend" in path:
            code = params.get("code", [""])[0].upper().strip()
            days = int(params.get("days", ["30"])[0])
            if code:
                sub_manager.extend_subscription(code, days)
        elif "/delete" in path:
            code = params.get("code", [""])[0].upper().strip()
            if code:
                sub_manager.delete_subscription(code)
        elif "/refresh" in path:
            update_configs()
        elif "/reset_devices" in path:
            code = params.get("code", [""])[0].upper().strip()
            if code:
                sub = sub_manager.get_subscription(code)
                if sub:
                    sub["devices"] = []
                    sub["device_names"] = {}
                    sub_manager.save()

        self.send_response(302)
        self.send_header("Location", "/admin")
        self.end_headers()

    # ========== OTHER HANDLERS ==========

    def handle_configs(self):
        fake = [
            {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "tag": "socks-in"},
                    {"port": 10809, "protocol": "http", "settings": {}, "tag": "http-in"},
                ],
                "outbounds": [{"tag": "no-happy", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": "no-happy"}]},
                "remarks": "🚫 Нет Халявы!",
            },
            {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "userLevel": 8}, "tag": "socks-in"},
                    {"port": 10809, "protocol": "http", "settings": {}, "tag": "http-in"},
                ],
                "outbounds": [{"tag": "no-sub", "protocol": "freedom"}],
                "routing": {"rules": [{"type": "field", "inboundTag": ["socks-in", "http-in"], "outboundTag": "no-sub"}]},
                "remarks": "📝 Попросите Сделать Подписку",
            },
        ]
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(fake, indent=2, ensure_ascii=False).encode("utf-8"))

    def handle_subscriptions_list(self):
        out = []
        for code in sub_manager.get_all_codes():
            sub = sub_manager.get_subscription(code)
            if sub:
                exp = datetime.fromisoformat(sub["expires_at"])
                out.append({
                    "code": code,
                    "user_name": sub.get("user_name"),
                    "user_id": sub.get("user_id"),
                    "description": sub.get("description", ""),
                    "created_at": sub.get("created_at"),
                    "expires_at": sub.get("expires_at"),
                    "is_active": sub.get("is_active", False) and exp > datetime.now(),
                    "config_count": sub.get("config_count", 0),
                    "devices": sub.get("devices", []),
                })
        self._json(200, {"total": len(out), "subscriptions": out})

    def handle_subscription_list(self):
        ua = self.headers.get("User-Agent", "").lower()
        is_browser = any(k in ua for k in ("mozilla", "chrome", "safari", "edge", "opera", "firefox"))
        if is_browser:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body style='font-family:sans-serif;background:#0a0a0f;color:#fff;padding:40px;'><h1>UltraVPN</h1></body></html>")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        for k, v in HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b"# UltraVPN Subscription\n")


# ==================== SERVER ====================

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_server():
    local_ip = get_local_ip()
    logger.info(f"Server starting on 0.0.0.0:{PORT}")
    httpd = HTTPServer(("0.0.0.0", PORT), ConfigHandler)
    logger.info(f"Local: http://{local_ip}:{PORT}")
    logger.info(f"Public: {SERVER_DOMAIN}")
    httpd.serve_forever()


# ==================== ENTRYPOINTS ====================

def cli_generate():
    update_configs()
    logger.info("Generation done.")


def cli_serve():
    update_configs()
    threading.Thread(target=auto_update_loop, daemon=True).start()
    run_server()


def main():
    parser = argparse.ArgumentParser(description="UltraVPN Server")
    parser.add_argument("--generate-only", action="store_true", help="Только сгенерировать конфиги и выйти")
    parser.add_argument("--serve", action="store_true", help="Запустить HTTP-сервер (по умолчанию)")
    args = parser.parse_args()

    if args.generate_only:
        cli_generate()
    else:
        cli_serve()


if __name__ == "__main__":
    main()
