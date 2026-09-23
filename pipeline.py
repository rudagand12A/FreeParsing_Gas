#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pipeline.py — единый скрипт: скачивание + парсинг + гео-фильтр + зачистка мусора + сохранение.
Гарантирует уникальные tag'и (иначе Xray падает с "existing tag found").
"""

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

# Разрешённые транспорты (актуальные для Xray)
ALLOWED_NETWORKS = {"raw", "ws", "grpc", "xhttp", "httpupgrade", "tcp"}
# Запрещённые (удалены из Xray)
FORBIDDEN_NETWORKS = {"http"}


def _has_word(text_upper: str, words) -> bool:
    for w in words:
        if re.search(rf"(?<![A-Z0-9]){re.escape(w)}(?![A-Z0-9])", text_upper):
            return True
    return False


def is_valid_uuid(value: str) -> bool:
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
        self.skipped = {
            "invalid": 0,
            "old_http": 0,
            "foreign": 0,
            "dup": 0,
        }

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

        print(f"📥 Источников в url.txt: {len(urls)}")

        for url in urls:
            try:
                print(f"🛰 Скачивание: {url}")
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
                print(f"⚠️ Ошибка сети {url}: {e}")

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
                self.skipped["invalid"] += 1
                return None
            user_info, host_port = rest.rsplit("@", 1)

            # === ВАЛИДАЦИЯ ===
            if not is_valid_uuid(user_info):
                self.skipped["invalid"] += 1
                return None

            if user_info.lower() in ("dummy", "none", "null",
                                     "00000000-0000-0000-0000-000000000000"):
                self.skipped["invalid"] += 1
                return None

            if host_port.startswith("["):
                m = re.match(r"^\[(.+)\]:(\d+)$", host_port)
                if not m:
                    self.skipped["invalid"] += 1
                    return None
                address, port = m.group(1), int(m.group(2))
            else:
                if ":" not in host_port:
                    self.skipped["invalid"] += 1
                    return None
                address, port_str = host_port.rsplit(":", 1)
                if not port_str.isdigit():
                    self.skipped["invalid"] += 1
                    return None
                port = int(port_str)

            if not address or address in ("0.0.0.0", "127.0.0.1", "localhost"):
                self.skipped["invalid"] += 1
                return None

            if not (1 <= port <= 65535):
                self.skipped["invalid"] += 1
                return None

            network = params.get("type", "raw")
            security = params.get("security", "none")

            # === ЗАЧИСТКА СТАРОГО HTTP (удалён из Xray) ===
            if network in FORBIDDEN_NETWORKS:
                self.skipped["old_http"] += 1
                return None

            if network in ("tcp", "raw"):
                if params.get("headerType") == "http":
                    self.skipped["old_http"] += 1
                    return None

            if network not in ALLOWED_NETWORKS:
                self.skipped["invalid"] += 1
                return None

            stream = {"network": network, "security": security}

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
                pbk = params.get("pbk") or params.get("publicKey", "")
                if not pbk:
                    self.skipped["invalid"] += 1
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
            self.skipped["invalid"] += 1
            return None

    # ---------------------------------------------------------------- filter
    def process_and_filter(self):
        print("🔧 Гео-фильтрация + зачистка мусора...")
        filtered = []
        seen = set()         # дедупликация по address:port:uuid
        used_tags = set()    # гарантия уникальности tag

        for ob in self.outbounds:
            try:
                old_tag = ob.get("tag", "")
                address = ob["settings"]["vnext"][0]["address"]
                port = ob["settings"]["vnext"][0]["port"]
                user_id = ob["settings"]["vnext"][0]["users"][0]["id"]
            except (KeyError, IndexError, TypeError):
                continue

            if not is_valid_uuid(user_id):
                self.skipped["invalid"] += 1
                continue

            if address in ("0.0.0.0", "127.0.0.1"):
                continue

            # Повторная проверка транспорта
            stream = ob.get("streamSettings", {})
            network = stream.get("network", "tcp")
            if network in FORBIDDEN_NETWORKS:
                self.skipped["old_http"] += 1
                continue
            if network in ("tcp", "raw"):
                header = stream.get("tcpSettings", {}).get("header", {})
                if header.get("type") == "http":
                    self.skipped["old_http"] += 1
                    continue
            if network not in ALLOWED_NETWORKS:
                self.skipped["invalid"] += 1
                continue

            if stream.get("security") == "reality":
                if not stream.get("realitySettings", {}).get("publicKey"):
                    self.skipped["invalid"] += 1
                    continue

            # Гео-фильтр
            tag_upper = old_tag.upper()
            is_ru = _has_word(tag_upper, RU_WORDS) or any(f in old_tag for f in RU_FLAGS)
            is_allowed = _has_word(tag_upper, ALLOWED_WORDS) or any(f in old_tag for f in ALLOWED_FLAGS)
            is_foreign = _has_word(tag_upper, FOREIGN_WORDS) or any(f in old_tag for f in FOREIGN_FLAGS)

            if is_foreign:
                self.skipped["foreign"] += 1
                continue
            if not (is_ru or is_allowed):
                continue

            # Дедупликация
            key = f"{address}:{port}:{user_id}"
            if key in seen:
                self.skipped["dup"] += 1
                continue
            seen.add(key)

            # === УНИКАЛЬНЫЙ TAG: address + port + короткий UUID ===
            short_id = user_id.split("-")[0]
            new_tag = f"🌍 Yandex/Max [{address}:{port} #{short_id}]"

            base_tag = new_tag
            suffix = 2
            while new_tag in used_tags:
                new_tag = f"{base_tag} ({suffix})"
                suffix += 1
            used_tags.add(new_tag)

            ob["tag"] = new_tag
            filtered.append(ob)

        print(f"🔍 Валидных узлов: {len(filtered)}")
        print(f"   Отброшено: invalid={self.skipped['invalid']}, "
              f"old_http={self.skipped['old_http']}, "
              f"foreign={self.skipped['foreign']}, "
              f"dup={self.skipped['dup']}")
        self.outbounds = filtered

    # ---------------------------------------------------------------- saver
    def _build_link(self, ob) -> str:
        vnext = ob["settings"]["vnext"][0]
        address = vnext["address"]
        port = vnext["port"]
        user_id = vnext["users"][0]["id"]
        user = vnext["users"][0]
        stream = ob.get("streamSettings", {})
        network = stream.get("network", "tcp")
        security = stream.get("security", "none")

        params = {"type": network, "security": security}

        if security == "tls":
            tls = stream.get("tlsSettings", {})
            if tls.get("serverName"): params["sni"] = tls["serverName"]
            if tls.get("fingerprint"): params["fp"] = tls["fingerprint"]
            if tls.get("alpn"): params["alpn"] = ",".join(tls["alpn"])
        elif security == "reality":
            r = stream.get("realitySettings", {})
            if r.get("serverName"): params["sni"] = r["serverName"]
            if r.get("fingerprint"): params["fp"] = r["fingerprint"]
            if r.get("publicKey"): params["pbk"] = r["publicKey"]
            if r.get("shortId"): params["sid"] = r["shortId"]
            if r.get("spiderX"): params["spx"] = r["spiderX"]

        if network == "ws":
            ws = stream.get("wsSettings", {})
            if ws.get("path"): params["path"] = ws["path"]
            if ws.get("headers", {}).get("Host"): params["host"] = ws["headers"]["Host"]
        elif network == "grpc":
            g = stream.get("grpcSettings", {})
            if g.get("serviceName"): params["serviceName"] = g["serviceName"]
            if g.get("multiMode"): params["mode"] = "multi"
        elif network == "xhttp":
            x = stream.get("xhttpSettings", {})
            if x.get("path"): params["path"] = x["path"]
            if x.get("host"): params["host"] = x["host"]
            if x.get("mode"): params["mode"] = x["mode"]
        elif network == "httpupgrade":
            h = stream.get("httpupgradeSettings", {})
            if h.get("path"): params["path"] = h["path"]
            if h.get("host"): params["host"] = h["host"]

        if user.get("flow"):
            params["flow"] = user["flow"]

        q = urllib.parse.urlencode(params)
        tag = urllib.parse.quote(ob.get("tag", address))
        return f"vless://{user_id}@{address}:{port}?{q}#{tag}"

    def save_final_config(self):
        selected = self.outbounds[:100000]

        # 1) TXT-подписка (base64)
        links = []
        for ob in selected:
            try:
                links.append(self._build_link(ob))
            except Exception as e:
                print(f"⚠️ Ошибка формирования ссылки: {e}")

        b64 = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
        with open(FINAL_LINKS_FILE, "w", encoding="utf-8") as f:
            f.write(b64)
        print(f"🎉 Подписка сохранена: {FINAL_LINKS_FILE} (ссылок: {len(links)})")

        # 2) JSON без inbounds (клиентский конфиг)
        final_json = {
            "remarks": "🇷🇺 Yandex/Max",
            "outbounds": selected + [
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

        # Убираем вложенные remarks
        def strip_remarks(obj):
            if isinstance(obj, dict):
                obj.pop("remarks", None)
                for v in obj.values():
                    strip_remarks(v)
            elif isinstance(obj, list):
                for item in obj:
                    strip_remarks(item)

        strip_remarks(final_json["outbounds"])

        # === ФИНАЛЬНАЯ ГАРАНТИЯ УНИКАЛЬНОСТИ TAG'ОВ ===
        seen_tags = set()
        for ob in final_json["outbounds"]:
            t = ob.get("tag")
            if t is None:
                continue
            base = t
            suffix = 2
            while t in seen_tags:
                t = f"{base} ({suffix})"
                suffix += 1
            ob["tag"] = t
            seen_tags.add(t)

        with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_json, f, indent=2, ensure_ascii=False)

        print(f"🎉 JSON сохранён: {FINAL_OUTPUT_FILE} (узлов: {len(links)})")
        print(f"🕒 Время: {datetime.now():%Y-%m-%d %H:%M:%S}")


if __name__ == "__main__":
    agg = VPNAggregator()
    agg.load_and_download()
    agg.process_and_filter()
    agg.save_final_config()
