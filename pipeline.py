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

sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_FILE = os.path.join(BASE_DIR, "url.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
FINAL_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sub_1212.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# --- БЕЛЫЙ СПИСОК: только Россия ---
RU_WORDS = [
    "RU", "RUS", "RUSSIA", "РОССИЯ", "РОССИИ", "РОССИЙСКИЙ",
    "YANDEX", "ЯНДЕКС", "Германия", "Germany",
]
RU_FLAGS = ["🇷🇺"] ["🇩🇪"]

# UUID-регулярка
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _has_word(text_upper: str, words) -> bool:
    for w in words:
        if re.search(rf"(?<![A-Z0-9]){re.escape(w)}(?![A-Z0-9])", text_upper):
            return True
    return False


def _is_valid_uuid(value: str) -> bool:
    if not value:
        return False
    return bool(UUID_RE.match(value.strip()))


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
            urls = [s for s in (line.strip() for line in f) if s and not s.startswith("#")]

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

                if not content.startswith(('vless://', 'vmess://', 'trojan://', 'ss://')):
                    content = self.decode_base64(content)

                lines = content.splitlines()
                parsed_before = len(self.outbounds)
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ob = self.parse_uri(line)
                    if ob:
                        self.outbounds.append(ob)
                parsed_now = len(self.outbounds) - parsed_before
                print(f"   └─ строк: {len(lines)}, распарсено VLESS: {parsed_now}")

            except Exception as e:
                print(f"⚠️ Ошибка сети при скачивании ссылки {url}: {e}")

        print(f"📦 Всего распарсено до фильтра: {len(self.outbounds)}")

    # ---------------------------------------------------------------- parser
    def parse_uri(self, uri: str):
        if not uri.startswith("vless://"):
            return None
        try:
            rest = uri[len("vless://"):]

            if "#" in rest:
                rest, fragment = rest.split("#", 1)
                tag = urllib.parse.unquote(fragment)
            else:
                tag = ""

            if "?" in rest:
                rest, query = rest.split("?", 1)
                params = dict(urllib.parse.parse_qsl(query))
            else:
                params = {}

            if "@" not in rest:
                return None
            user_info, host_port = rest.rsplit("@", 1)

            user_info = (user_info or "").strip()
            if not user_info or not _is_valid_uuid(user_info):
                return None

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

            if not address or address in ("0.0.0.0", "127.0.0.1", "localhost"):
                return None
            if not (0 < port < 65536):
                return None

            network = params.get("type", "raw")
            security = params.get("security", "none")

            stream = {"network": network, "security": security}

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

            if network == "ws":
                stream["wsSettings"] = {
                    "path": params.get("path", "/"),
                    "headers": {"Host": params.get("host", address)},
                }

            if network == "grpc":
                stream["grpcSettings"] = {
                    "serviceName": params.get("serviceName", ""),
                    "multiMode": params.get("mode", "") == "multi",
                }

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

            if security == "tls":
                tls_settings = {
                    "serverName": params.get("sni", address),
                    "allowInsecure": params.get("allowInsecure", "0") == "1",
                    "fingerprint": params.get("fp") or "chrome",
                    "alpn": [a for a in params.get("alpn", "").split(",") if a] or None,
                }
                stream["tlsSettings"] = {k: v for k, v in tls_settings.items() if v is not None}

            if security == "reality":
                pbk = params.get("pbk") or params.get("publicKey", "")
                if not pbk:
                    return None
                stream["realitySettings"] = {
                    "serverName": params.get("sni", address),
                    "fingerprint": params.get("fp") or "chrome",
                    "publicKey": pbk,
                    "shortId": params.get("sid", ""),
                    "spiderX": params.get("spx", ""),
                }

            user = {
                "id": user_info,
                "encryption": "none",
                "level": 8,
            }
            if params.get("flow"):
                user["flow"] = params["flow"]

            return {
                "protocol": "vless",
                "tag": tag or f"VLESS-[{address}:{port}]",
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
        """
        Оставляем ТОЛЬКО ноды с явным RU-гео:
        слово RU/RUS/RUSSIA/РОССИЯ/ЯНДЕКС или флаг 🇷🇺.
        Всё остальное (DE, FR, EE, FI, NL, LV, любые другие и без гео) — под снос.
        """
        print("🔧 Фильтрация: оставляем только 🇷🇺 RU, всё остальное — под снос...")
        total_before = len(self.outbounds)
        filtered_obs = []
        seen_keys = set()

        for ob in self.outbounds:
            try:
                old_tag = ob.get("tag", "") or ""
                vnext = ob["settings"]["vnext"][0]
                address = vnext["address"]
                port = vnext["port"]
                users = vnext.get("users", [])
            except (KeyError, IndexError, TypeError):
                continue

            if address in ("0.0.0.0", "127.0.0.1"):
                continue

            if not users:
                continue
            user_id = (users[0].get("id") or "").strip()
            if not _is_valid_uuid(user_id):
                continue

            tag_upper = old_tag.upper()

            # --- Главное условие: явный RU ---
            has_ru = _has_word(tag_upper, RU_WORDS) or any(f in old_tag for f in RU_FLAGS)
            if not has_ru:
                continue

            key = (address, port)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Признак безлимита
            ob["_is_unlimited"] = "безлимит" in old_tag.lower()

            # Чистим дубли флагов и собираем новый тег
            orig = old_tag.strip()
            orig_clean = re.sub(r"^[\U0001F1E6-\U0001F1FF\s]+", "", orig).strip() or f"RU [{address}]"
            new_remarks = f"🇷🇺 {orig_clean}"

            if ob["_is_unlimited"]:
                new_remarks += " [Безлимит]"

            if _has_word(tag_upper, ["LTE", "4G", "ЛТЕ"]):
                new_remarks += " (Долгий пинг)"

            ob["tag"] = f"{new_remarks} [{address}:{port}]"
            filtered_obs.append(ob)

        print(f"🗑 Фильтр завершён. Было: {total_before}, стало: {len(filtered_obs)} "
              f"(отсеяно: {total_before - len(filtered_obs)})")
        self.outbounds = filtered_obs

    # ---------------------------------------------------------------- генератор конфига
    def build_single_config(self, nodes_list, config_name):
        tags = [o["tag"] for o in nodes_list]

        outbounds = list(nodes_list)
        outbounds.append({
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIP"},
            "tag": "direct",
        })
        outbounds.append({
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}},
            "tag": "block",
        })

        return {
            "remarks": config_name,
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
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
            "outbounds": outbounds,
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "balancers": [
                    {
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
                    }
                ] if tags else [],
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                    {"type": "field", "balancerTag": "Auto_Balancer", "network": "tcp,udp"},
                ],
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

    # ---------------------------------------------------------------- saver
    def save_final_config(self):
        CHUNK_SIZE = 75

        all_nodes = self.outbounds
        final_array = []

        chunk_index = 1
        for i in range(0, len(all_nodes), CHUNK_SIZE):
            chunk = all_nodes[i:i + CHUNK_SIZE]
            config_name = f"🇷🇺 RU Конфиг - Часть {chunk_index} ({len(chunk)} серв.)"
            single_config = self.build_single_config(chunk, config_name)
            final_array.append(single_config)
            chunk_index += 1

        with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_array, f, indent=2, ensure_ascii=False)

        print(f"🎉 Итоговый файл успешно обновлен: {FINAL_OUTPUT_FILE}\n"
              f"   - Всего серверов обработано: {len(all_nodes)}\n"
              f"   - Создано раздельных конфигов: {len(final_array)} (нарезка по {CHUNK_SIZE} шт.)\n"
              f"   - Дата генерации: {datetime.now():%Y-%m-%d %H:%M:%S}")


if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_and_filter()
    aggregator.save_final_config()
