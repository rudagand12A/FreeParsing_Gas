#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import base64
import gzip
import uuid
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
FINAL_LINKS_FILE = os.path.join(OUTPUT_DIR, "sub_1212.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Гео-словари ---
RU_WORDS = ["RU", "RUS", "RUSSIA", "РОССИЯ", "РОССИИ", "YANDEX", "ЯНДЕКС"]
RU_FLAGS = ["🇷🇺"]

ALLOWED_WORDS = [
    "DE", "GERMANY", "ГЕРМАНИЯ", "ГЕРМАНИИ", "DEUTSCHLAND",
    "FI", "FINLAND", "ФИНЛЯНДИЯ", "ФИНЛЯНДИИ", "HELSINKI", "ХЕЛЬСИНКИ",
    "EU", "EUROPE", "ЕВРОПА", "ЕВРОПЫ", "EUROPEAN",
    "NL", "NETHERLANDS", "НИДЕРЛАНДЫ", "НИДЕРЛАНДОВ", "HOLLAND", "AMSTERDAM", "АМСТЕРДАМ",
    "FR", "FRANCE", "ФРАНЦИЯ", "ФРАНЦИИ", "PARIS", "ПАРИЖ",
    "EE", "ESTONIA", "ЭСТОНИЯ", "ЭСТОНИИ", "TALLINN", "ТАЛЛИН",
    "GB", "UK", "BRITAIN", "АНГЛИЯ", "АНГЛИИ", "LONDON", "ЛОНДОН", "UNITED KINGDOM",
    "SE", "SWEDEN", "ШВЕЦИЯ", "ШВЕЦИИ", "STOCKHOLM", "СТОКГОЛЬМ",
    "PL", "POLAND", "ПОЛЬША", "ПОЛЬШИ", "POLSKA", "WARSAW", "ВАРШАВА",
    "LT", "LITHUANIA", "ЛИТВА", "ЛИТВЫ", "VILNIUS", "ВИЛЬНЮС",
    "LV", "LATVIA", "ЛАТВИЯ", "ЛАТВИИ", "RIGA", "РИГА",
    "US", "USA", "UNITED STATES", "США", "AMERICA", "АМЕРИКА", "NEW YORK", "НЬЮ-ЙОРК",
    "CZ", "CZECH", "CZECHIA", "ЧЕХИЯ", "ЧЕХИИ", "PRAGUE", "ПРАГА",
    "IT", "ITALY", "ИТАЛИЯ", "ИТАЛИИ", "ROME", "РИМ", "MILAN", "МИЛАН",
    "ES", "SPAIN", "ИСПАНИЯ", "ИСПАНИИ", "MADRID", "МАДРИД", "BARCELONA", "БАРСЕЛОНА",
    "NO", "NORWAY", "НОРВЕГИЯ", "НОРВЕГИИ", "OSLO", "ОСЛО",
]
ALLOWED_FLAGS = [
    "🇩🇪", "🇫🇮", "🇪🇺", "🇳🇱", "🇫🇷", "🇪🇪", "🇬🇧", "🇸🇪",
    "🇵🇱", "🇱🇹", "🇱🇻", "🇺🇸", "🇨🇿", "🇮🇹", "🇪🇸", "🇳🇴",
]

FOREIGN_WORDS = [
    "TR", "TURKEY", "ТУРЦИЯ",
    "JP", "JAPAN", "ЯПОНИЯ",
    "KR", "KOREA", "КОРЕЯ",
    "SG", "SINGAPORE", "СИНГАПУР",
    "HK", "HONGKONG", "ГОНКОНГ",
    "CA", "CANADA", "КАНАДА",
    "AU", "AUSTRALIA", "АВСТРАЛИЯ",
    "CN", "CHINA", "КИТАЙ",
    "IN", "INDIA", "ИНДИЯ",
    "BR", "BRAZIL", "БРАЗИЛИЯ",
]
FOREIGN_FLAGS = ["🇹🇷", "🇯🇵", "🇰🇷", "🇸🇬", "🇭🇰", "🇨🇦", "🇦🇺", "🇨🇳", "🇮🇳", "🇧🇷"]


def _has_word(text_upper: str, words) -> bool:
    for w in words:
        if re.search(rf"(?<![A-Z0-9]){re.escape(w)}(?![A-Z0-9])", text_upper):
            return True
    return False


def is_valid_uuid(value: str) -> bool:
    """Проверка, что строка — валидный UUID (обязательно для VLESS)."""
    if not value:
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


class VPNAggregator:
    def __init__(self):
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self.outbounds = []
        self.skipped_invalid = 0

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
            print(f"⚠️ Файл источников не найден: {URL_FILE}. Создаю пустой...")
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

                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    ob = self.parse_uri(line)
                    if ob:
                        self.outbounds.append(ob)

            except Exception as e:
                print(f"⚠️ Ошибка сети при скачивании {url}: {e}")

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
                self.skipped_invalid += 1
                return None
            user_info, host_port = rest.rsplit("@", 1)

            # === ЖЁСТКАЯ ВАЛИДАЦИЯ ===
            # 1. UUID обязателен (иначе панель требует password)
            if not is_valid_uuid(user_info):
                self.skipped_invalid += 1
                return None

            # 2. Фейковые и пустые ID
            if user_info.lower() in ("dummy", "none", "null", "00000000-0000-0000-0000-000000000000"):
                self.skipped_invalid += 1
                return None

            if host_port.startswith("["):
                m = re.match(r"^\[(.+)\]:(\d+)$", host_port)
                if not m:
                    self.skipped_invalid += 1
                    return None
                address, port = m.group(1), int(m.group(2))
            else:
                if ":" not in host_port:
                    self.skipped_invalid += 1
                    return None
                address, port_str = host_port.rsplit(":", 1)
                if not port_str.isdigit():
                    self.skipped_invalid += 1
                    return None
                port = int(port_str)

            # 3. Пустые/фейковые адреса
            if not address or address in ("0.0.0.0", "127.0.0.1", "localhost"):
                self.skipped_invalid += 1
                return None

            # 4. Порт в допустимом диапазоне
            if not (1 <= port <= 65535):
                self.skipped_invalid += 1
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
                    "fingerprint": params.get("fp", "chrome"),
                    "alpn": [a for a in params.get("alpn", "").split(",") if a] or None,
                }
                if "pinnedPeerCertSha256" in params:
                    tls_settings["pinnedPeerCertSha256"] = params["pinnedPeerCertSha256"]
                stream["tlsSettings"] = {k: v for k, v in tls_settings.items() if v is not None}

            if security == "reality":
                # Reality ОБЯЗАТЕЛЬНО требует pbk — иначе конфиг нерабочий
                pbk = params.get("pbk") or params.get("publicKey", "")
                if not pbk:
                    self.skipped_invalid += 1
                    return None
                stream["realitySettings"] = {
                    "serverName": params.get("sni", address),
                    "fingerprint": params.get("fp", "chrome"),
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
            print(f"❌ Ошибка разбора VLESS: {e}")
            self.skipped_invalid += 1
            return None

    # ---------------------------------------------------------------- filter
    def process_and_filter(self):
        print("🔧 Запуск гео-фильтрации...")
        filtered_obs = []
        seen_addresses = set()

        for ob in self.outbounds:
            try:
                old_tag = ob.get("tag", "")
                address = ob["settings"]["vnext"][0]["address"]
                user_id = ob["settings"]["vnext"][0]["users"][0]["id"]
            except (KeyError, IndexError, TypeError):
                continue

            # Повторная проверка UUID (на всякий)
            if not is_valid_uuid(user_id):
                continue

            if address in ("0.0.0.0", "127.0.0.1"):
                continue

            tag_upper = old_tag.upper()
            is_russian = _has_word(tag_upper, RU_WORDS) or any(f in old_tag for f in RU_FLAGS)
            is_allowed = _has_word(tag_upper, ALLOWED_WORDS) or any(f in old_tag for f in ALLOWED_FLAGS)
            is_foreign = _has_word(tag_upper, FOREIGN_WORDS) or any(f in old_tag for f in FOREIGN_FLAGS)

            if is_foreign:
                continue
            if not (is_russian or is_allowed):
                continue
            if address in seen_addresses:
                continue
            seen_addresses.add(address)

            ob["tag"] = f"🌍 Yandex/Max [{address}]"
            filtered_obs.append(ob)

        print(f"🔍 Фильтр завершён. Валидных серверов: {len(filtered_obs)} "
              f"(отброшено невалидных: {self.skipped_invalid})")
        self.outbounds = filtered_obs

    # ---------------------------------------------------------------- saver
    def _build_link(self, ob) -> str:
        settings = ob["settings"]["vnext"][0]
        address = settings["address"]
        port = settings["port"]
        user = settings["users"][0]
        user_id = user["id"]
        stream = ob.get("streamSettings", {})
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")

        params = {}
        if security == "tls":
            tls = stream.get("tlsSettings", {})
            if tls.get("serverName"): params["sni"] = tls["serverName"]
            if tls.get("fingerprint"): params["fp"] = tls["fingerprint"]
            if tls.get("alpn"): params["alpn"] = ",".join(tls["alpn"])
        elif security == "reality":
            reality = stream.get("realitySettings", {})
            if reality.get("serverName"): params["sni"] = reality["serverName"]
            if reality.get("fingerprint"): params["fp"] = reality["fingerprint"]
            if reality.get("publicKey"): params["pbk"] = reality["publicKey"]
            if reality.get("shortId"): params["sid"] = reality["shortId"]
            if reality.get("spiderX"): params["spx"] = reality["spiderX"]

        if network == "ws":
            ws = stream.get("wsSettings", {})
            if ws.get("path"): params["path"] = ws["path"]
            if ws.get("headers", {}).get("Host"): params["host"] = ws["headers"]["Host"]
        elif network == "grpc":
            grpc = stream.get("grpcSettings", {})
            if grpc.get("serviceName"): params["serviceName"] = grpc["serviceName"]
            if grpc.get("multiMode"): params["mode"] = "multi"
        elif network == "xhttp":
            xhttp = stream.get("xhttpSettings", {})
            if xhttp.get("path"): params["path"] = xhttp["path"]
            if xhttp.get("host"): params["host"] = xhttp["host"]
            if xhttp.get("mode"): params["mode"] = xhttp["mode"]
        elif network == "httpupgrade":
            hu = stream.get("httpupgradeSettings", {})
            if hu.get("path"): params["path"] = hu["path"]
            if hu.get("host"): params["host"] = hu["host"]

        params["type"] = network
        params["security"] = security
        if user.get("flow"):
            params["flow"] = user["flow"]

        query = urllib.parse.urlencode(params)
        tag = urllib.parse.quote(ob.get("tag", address))
        return f"vless://{user_id}@{address}:{port}?{query}#{tag}"

    def save_final_config(self):
        selected_obs = self.outbounds[:100000]

        # === 1) TXT-подписка (base64) ===
        links = []
        for ob in selected_obs:
            try:
                links.append(self._build_link(ob))
            except Exception as e:
                print(f"⚠️ Ошибка формирования ссылки: {e}")

        b64_subscription = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
        with open(FINAL_LINKS_FILE, "w", encoding="utf-8") as f:
            f.write(b64_subscription)
        print(f"🎉 Подписка сохранена: {FINAL_LINKS_FILE} (серверов: {len(links)})")

        # === 2) JSON БЕЗ inbounds, но с явным outbounds ===
        # Это формат, который не содержит ни одного inbound с ожиданием password.
        # Если панель всё ещё требует password — значит она читает не тот файл.
        final_json = {
            "remarks": "🇷🇺 Yandex/Max",
            "outbounds": selected_obs + [
                {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
                {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                ],
            },
        }

        def strip_remarks(obj):
            if isinstance(obj, dict):
                obj.pop("remarks", None)
                for v in obj.values():
                    strip_remarks(v)
            elif isinstance(obj, list):
                for item in obj:
                    strip_remarks(item)

        strip_remarks(final_json)
        final_json = {"remarks": "🇷🇺 Yandex/Max", **final_json}

        with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_json, f, indent=2, ensure_ascii=False)

        with open(FINAL_OUTPUT_FILE, "r", encoding="utf-8") as f:
            count = f.read().count('"remarks"')
        print(f"🔍 Проверка: строк 'remarks' в JSON = {count}")
        print(f"🎉 Итоговый конфиг сохранён: {FINAL_OUTPUT_FILE} "
              f"(серверов: {len(links)}, "
              f"отброшено невалидных: {self.skipped_invalid}, "
              f"дата: {datetime.now():%Y-%m-%d %H:%M:%S})")


if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_and_filter()
    aggregator.save_final_config()
