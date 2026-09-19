#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import base64
import gzip
import urllib.parse
import urllib.request
import ssl
import sys
from datetime import datetime

# Построчный вывод логов — чтобы видеть прогресс в реальном времени на GitHub Actions
sys.stdout.reconfigure(line_buffering=True)

# Автоопределение путей под окружение GitHub Actions
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_FILE = os.path.join(BASE_DIR, "url.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
FINAL_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sub_1212.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# --- Гео-словари (регулярки по границам слов, чтобы "RU" не ловило "BRUSSELS" и т.п.) ---
RU_WORDS = ["RU", "RUS", "RUSSIA", "РОССИЯ", "РОССИИ", "YANDEX", "ЯНДЕКС"]
RU_FLAGS = ["🇷🇺"]

FOREIGN_WORDS = [
    "EU", "EUROPE", "ЕВРОПА",
    "DE", "GERMANY", "ГЕРМАНИЯ",
    "FR", "FRANCE", "ФРАНЦИЯ",
    "US", "USA", "США",
    "NL", "NETHERLANDS", "НИДЕРЛАНДЫ",
    "GB", "UK", "BRITAIN", "АНГЛИЯ",
    "PL", "POLAND", "ПОЛЬША",
    "FI", "FINLAND", "ФИНЛЯНДИЯ",
    "SE", "SWEDEN", "ШВЕЦИЯ",
    "TR", "TURKEY", "ТУРЦИЯ",
    "JP", "JAPAN", "ЯПОНИЯ",
    "KR", "KOREA", "КОРЕЯ",
    "SG", "SINGAPORE", "СИНГАПУР",
    "HK", "HONGKONG", "ГОНКОНГ",
    "CA", "CANADA", "КАНАДА",
    "AU", "AUSTRALIA", "АВСТРАЛИЯ",
]
FOREIGN_FLAGS = ["🇪🇺", "🇩🇪", "🇫🇷", "🇺🇸", "🇳🇱", "🇬🇧", "🇵🇱", "🇫🇮", "🇸🇪",
                 "🇹🇷", "🇯🇵", "🇰🇷", "🇸🇬", "🇭🇰", "🇨🇦", "🇦🇺"]


def _has_word(text_upper: str, words) -> bool:
    """Проверяет вхождение слов как отдельных токенов (по границам слов)."""
    for w in words:
        if re.search(rf"(?<![A-Z0-9]){re.escape(w)}(?![A-Z0-9])", text_upper):
            return True
    return False


class VPNAggregator:
    def __init__(self):
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self.outbounds = []

    # ---------------------------------------------------------------- utils
    def decode_base64(self, text: str) -> str:
        try:
            c = ''.join(text.split())
            # Корректный паддинг: добавляет 0..3 '=' в зависимости от остатка
            c += '=' * (-len(c) % 4)
            return base64.b64decode(c).decode('utf-8', errors='ignore')
        except Exception:
            return text

    # ---------------------------------------------------------------- loader
    def load_and_download(self):
        if not os.path.exists(URL_FILE):
            print(f"⚠️ Файл источников не найден по пути {URL_FILE}. Создаю пустой...")
            with open(URL_FILE, "w", encoding="utf-8") as f:
                f.write("# Вставьте ваши ссылки ниже\n")
            return

        with open(URL_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        print(f"📥 Загружено источников из url.txt: {len(urls)}")

        for url in urls:
            try:
                print(f"🛰 Скачивание провайдера: {url}")
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                                      "Chrome/122.0.0.0 Safari/537.36",
                        # Просим сервер отдавать без сжатия, чтобы не ловить бинарь
                        "Accept-Encoding": "identity",
                    },
                )
                with urllib.request.urlopen(req, timeout=20, context=self.ssl_ctx) as r:
                    raw = r.read()
                    enc = (r.headers.get("Content-Encoding") or "").lower()
                    if "gzip" in enc:
                        try:
                            raw = gzip.decompress(raw)
                        except Exception:
                            pass
                    content = raw.decode('utf-8', errors='ignore').strip()

                # Если это не плейн-текст со ссылками — пробуем base64
                if not content.startswith(('vless://', 'vmess://', 'trojan://', 'ss://')):
                    content = self.decode_base64(content)

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ob = self.parse_uri(line)
                    if ob:
                        self.outbounds.append(ob)

            except Exception as e:
                print(f"⚠️ Ошибка сети при скачивании ссылки: {e}")

    # ---------------------------------------------------------------- parser
    def parse_uri(self, uri: str):
        if not uri.startswith("vless://"):
            return None
        try:
            # Отрезаем схему
            rest = uri[len("vless://"):]

            # Fragment (tag) — всё после первого '#'
            if "#" in rest:
                rest, fragment = rest.split("#", 1)
                tag = urllib.parse.unquote(fragment)
            else:
                tag = ""

            # Query — всё после первого '?'
            if "?" in rest:
                rest, query = rest.split("?", 1)
                params = dict(urllib.parse.parse_qsl(query))
            else:
                params = {}

            # Осталось: uuid@host:port
            if "@" not in rest:
                return None
            user_info, host_port = rest.rsplit("@", 1)

            # Парсим host:port, учитывая IPv6 в [ ]
            if host_port.startswith("["):
                m = re.match(r"^\[(.+)\]:(\d+)$", host_port)
                if not m:
                    return None
                address, port = m.group(1), int(m.group(2))
            else:
                if ":" not in host_port:
                    return None
                address, port_str = host_port.rsplit(":", 1)
                if not port_str.isdigit():
                    return None
                port = int(port_str)

            if not user_info or not address:
                return None

            # --- streamSettings ---
            network = params.get("type", "raw")
            security = params.get("security", "none")

            stream = {
                "network": network,
                "security": security,
            }

            # TCP/raw + headerType=http иногда требует явного указания
            if network in ("tcp", "raw") and params.get("headerType") == "http":
                stream["tcpSettings"] = {
                    "header": {
                        "type": "http",
                        "request": {
                            "path": [params.get("path", "/")],
                            "headers": {"Host": [params.get("host", address)]},
                        },
                    }
                }

            # WebSocket
            if network == "ws":
                stream["wsSettings"] = {
                    "path": params.get("path", "/"),
                    "headers": {"Host": params.get("host", address)},
                }

            # gRPC
            if network == "grpc":
                stream["grpcSettings"] = {
                    "serviceName": params.get("serviceName", ""),
                    "multiMode": params.get("mode", "") == "multi",
                }

            # XHTTP / HTTPUpgrade (новые типы Xray)
            if network == "xhttp":
                stream["xhttpSettings"] = {
                    "path": params.get("path", "/"),
                    "host": params.get("host", address),
                    "mode": params.get("mode", "auto"),
                }
            if network == "httpupgrade":
                stream["httpupgradeSettings"] = {
                    "path": params.get("path", "/"),
                    "host": params.get("host", address),
                }

            # TLS / Reality
            if security == "tls":
                stream["tlsSettings"] = {
                    "serverName": params.get("sni", address),
                    "allowInsecure": params.get("allowInsecure", "0") == "1",
                    "fingerprint": params.get("fp", "chrome"),
                    "alpn": [a for a in params.get("alpn", "").split(",") if a] or None,
                }
                # Убираем None-поля
                stream["tlsSettings"] = {k: v for k, v in stream["tlsSettings"].items() if v is not None}

            if security == "reality":
                stream["realitySettings"] = {
                    "serverName": params.get("sni", address),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk") or params.get("publicKey", ""),
                    "shortId": params.get("sid", ""),
                    "spiderX": params.get("spx", ""),
                }

            # --- user ---
            user = {
                "id": user_info,
                "encryption": "none",
                "level": 8,
            }
            if params.get("flow"):
                user["flow"] = params["flow"]

            return {
                "protocol": "vless",
                "tag": tag or f"VLESS-[{address}]",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [user],
                    }]
                },
                "streamSettings": stream,
            }
        except Exception as e:
            print(f"❌ Ошибка разбора строки VLESS: {e}")
            return None

    # ---------------------------------------------------------------- filter
    def process_and_filter(self):
        print("🔧 Запуск гео-фильтрации (оставляем только RU, удаляем EU/мусор)...")
        filtered_obs = []
        seen_addresses = set()

        for ob in self.outbounds:
            try:
                old_tag = ob.get("tag", "")
                # ВАЖНО: vnext — это список
                address = ob["settings"]["vnext"][0]["address"]
            except (KeyError, IndexError, TypeError):
                continue

            tag_upper = old_tag.upper()

            is_russian = _has_word(tag_upper, RU_WORDS) or any(f in old_tag for f in RU_FLAGS)
            is_foreign = _has_word(tag_upper, FOREIGN_WORDS) or any(f in old_tag for f in FOREIGN_FLAGS)

            # Отсекаем зарубежные и всё, где RU не подтверждён явно
            if is_foreign or not is_russian:
                continue

            # Дедупликация по хосту
            if address in seen_addresses:
                continue
            seen_addresses.add(address)

            base_name = "🇷🇺 YandexTCP Тест"
            new_remarks = f"{base_name} Безлимит" if "безлимит" in old_tag.lower() else base_name

            if _has_word(tag_upper, ["LTE", "ЛТЕ"]):
                new_remarks += " (Долгий пинг)"

            ob["tag"] = f"{new_remarks} [{address}]"
            ob["remarks"] = new_remarks
            filtered_obs.append(ob)

        print(f"🗑 Фильтр завершён. Чистых RU серверов в базе: {len(filtered_obs)}")
        self.outbounds = filtered_obs

    # ---------------------------------------------------------------- saver
    def save_final_config(self):
        selected_obs = self.outbounds[:3000]
        tags = [o["tag"] for o in selected_obs]

        # Служебные outbounds
        selected_obs.append({
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
            "tag": "direct",
        })
        selected_obs.append({
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
            "tag": "block",
        })

        final_json = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                    },
                    "tag": "socks-in",
                },
                {
                    "port": 10809,
                    "protocol": "http",
                    "settings": {},
                    "tag": "http-in",
                },
            ],
            "outbounds": selected_obs,
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "balancers": [{
                    "tag": "Auto_Balancer",
                    "selector": tags,
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "baselines": ["200ms", "500ms"],
                            "expected": 2,
                            "maxRTT": "1500ms",
                            "tolerance": 0,
                        },
                    },
                }] if tags else [],
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "domain": ["geosite:category-ru", "domain:ru", "domain:su"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "direct"},
                ] + ([{"type": "field", "balancerTag": "Auto_Balancer", "network": "tcp,udp"}] if tags else []),
            },
            "burstObservatory": {
                "pingConfig": {
                    "destination": "http://gstatic.com",
                    "interval": "2m",
                    "sampling": 3,
                    "timeout": "3s",
                },
                "subjectSelector": tags,
            },
        }

        with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_json, f, indent=2, ensure_ascii=False)
        print(f"🎉 Итоговый конфиг записан: {FINAL_OUTPUT_FILE} "
              f"(серверов: {len(tags)}, обновлён: {datetime.now():%Y-%m-%d %H:%M:%S})")


if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_and_filter()
    aggregator.save_final_config()
