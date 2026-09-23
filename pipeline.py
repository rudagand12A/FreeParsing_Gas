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
FINAL_LINKS_FILE = os.path.join(OUTPUT_DIR, "sub_1212.txt")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# --- Гео-словари (регулярки по границам слов, чтобы "RU" не ловило "BRUSSELS" и т.п.) ---
RU_WORDS = ["RU", "RUS", "RUSSIA", "РОССИЯ", "РОССИИ", "YANDEX", "ЯНДЕКС"]
RU_FLAGS = ["🇷🇺"]

# Страны, которые ТОЖЕ оставляем (плюс к RU)
ALLOWED_WORDS = [
    # Германия
    "DE", "GERMANY", "ГЕРМАНИЯ", "ГЕРМАНИИ", "DEUTSCHLAND",
    # Финляндия
    "FI", "FINLAND", "ФИНЛЯНДИЯ", "ФИНЛЯНДИИ", "HELSINKI", "ХЕЛЬСИНКИ",
    # Европа
    "EU", "EUROPE", "ЕВРОПА", "ЕВРОПЫ", "EUROPEAN",
    # Нидерланды
    "NL", "NETHERLANDS", "НИДЕРЛАНДЫ", "НИДЕРЛАНДОВ", "HOLLAND", "AMSTERDAM", "АМСТЕРДАМ",
    # Франция
    "FR", "FRANCE", "ФРАНЦИЯ", "ФРАНЦИИ", "PARIS", "ПАРИЖ",
    # Эстония
    "EE", "ESTONIA", "ЭСТОНИЯ", "ЭСТОНИИ", "TALLINN", "ТАЛЛИН",
    # Великобритания
    "GB", "UK", "BRITAIN", "АНГЛИЯ", "АНГЛИИ", "LONDON", "ЛОНДОН", "UNITED KINGDOM",
    # Швеция
    "SE", "SWEDEN", "ШВЕЦИЯ", "ШВЕЦИИ", "STOCKHOLM", "СТОКГОЛЬМ",
    # Польша
    "PL", "POLAND", "ПОЛЬША", "ПОЛЬШИ", "POLSKA", "WARSAW", "ВАРШАВА",
    # Литва
    "LT", "LITHUANIA", "ЛИТВА", "ЛИТВЫ", "VILNIUS", "ВИЛЬНЮС",
    # Латвия
    "LV", "LATVIA", "ЛАТВИЯ", "ЛАТВИИ", "RIGA", "РИГА",
    # США
    "US", "USA", "UNITED STATES", "США", "AMERICA", "АМЕРИКА", "NEW YORK", "НЬЮ-ЙОРК",
    # Чехия
    "CZ", "CZECH", "CZECHIA", "ЧЕХИЯ", "ЧЕХИИ", "PRAGUE", "ПРАГА",
    # Италия
    "IT", "ITALY", "ИТАЛИЯ", "ИТАЛИИ", "ROME", "РИМ", "MILAN", "МИЛАН",
    # Испания
    "ES", "SPAIN", "ИСПАНИЯ", "ИСПАНИИ", "MADRID", "МАДРИД", "BARCELONA", "БАРСЕЛОНА",
    # Норвегия
    "NO", "NORWAY", "НОРВЕГИЯ", "НОРВЕГИИ", "OSLO", "ОСЛО",
]
ALLOWED_FLAGS = [
    "🇩🇪", "🇫🇮", "🇪🇺", "🇳🇱", "🇫🇷", "🇪🇪", "🇬🇧", "🇸🇪",
    "🇵🇱", "🇱🇹", "🇱🇻", "🇺🇸", "🇨🇿", "🇮🇹", "🇪🇸", "🇳🇴",
]

# Страны, которые ВСЕ РАВНО отсекаем
FOREIGN_WORDS = [
    "US", "USA", "США", "AMERICA", "АМЕРИКА",
    "PL", "POLAND", "ПОЛЬША",
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
FOREIGN_FLAGS = ["🇺🇸", "🇵🇱", "🇹🇷", "🇯🇵", "🇰🇷", "🇸🇬", "🇭🇰", "🇨🇦", "🇦🇺", "🇨🇳", "🇮🇳", "🇧🇷"]


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
                print(f"⚠️ Ошибка сети при скачивании ссылки {url}: {e}")

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

            # Фильтр пустых и фейковых адресов
            if address in ("0.0.0.0", "127.0.0.1", "localhost") or user_info.lower() == "dummy":
                return None

            network = params.get("type", "raw")
            security = params.get("security", "none")

            stream = {
                "network": network,
                "security": security,
            }

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
                # Поддержка современного пиннинга сертификатов вместо allowInsecure
                if "pinnedPeerCertSha256" in params:
                    tls_settings["pinnedPeerCertSha256"] = params["pinnedPeerCertSha256"]

                stream["tlsSettings"] = {k: v for k, v in tls_settings.items() if v is not None}

            if security == "reality":
                stream["realitySettings"] = {
                    "serverName": params.get("sni", address),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk") or params.get("publicKey", ""),
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
            print(f"❌ Ошибка разбора строки VLESS: {e}")
            return None

    # ---------------------------------------------------------------- filter
    def process_and_filter(self):
        print("🔧 Запуск гео-фильтрации (RU + DE + FI + EU + NL + FR + EE + GB + SE)...")
        filtered_obs = []
        seen_addresses = set()

        for ob in self.outbounds:
            try:
                old_tag = ob.get("tag", "")
                address = ob["settings"]["vnext"][0]["address"]
            except (KeyError, IndexError, TypeError):
                continue

            # Дополнительная проверка на мёртвый хост
            if address in ("0.0.0.0", "127.0.0.1"):
                continue

            tag_upper = old_tag.upper()
            is_russian = _has_word(tag_upper, RU_WORDS) or any(f in old_tag for f in RU_FLAGS)
            is_allowed = _has_word(tag_upper, ALLOWED_WORDS) or any(f in old_tag for f in ALLOWED_FLAGS)
            is_foreign = _has_word(tag_upper, FOREIGN_WORDS) or any(f in old_tag for f in FOREIGN_FLAGS)

            # Отсекаем всё, что в чёрном списке
            if is_foreign:
                continue

            # Оставляем только RU или разрешённые страны
            if not (is_russian or is_allowed):
                continue

            # Дедупликация по IP / Хосту
            if address in seen_addresses:
                continue
            seen_addresses.add(address)

            # Единый tag. remarks НЕ добавляем — он будет один на верхнем уровне конфига
            ob["tag"] = f"🌍 Yandex/Max [{address}]"
            filtered_obs.append(ob)

        print(f"🔍 Фильтр завершён. Найдено серверов (RU+разрешённые): {len(filtered_obs)}")
        self.outbounds = filtered_obs

    # ---------------------------------------------------------------- saver
    def _build_link(self, ob) -> str:
        """Собирает обратно VLESS-ссылку из распарсенного объекта."""
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
        # Увеличили лимит до 100 тысяч, чтобы ничего не резалось
        selected_obs = self.outbounds[:100000]

        # Собираем ссылки
        links = []
        for ob in selected_obs:
            try:
                links.append(self._build_link(ob))
            except Exception as e:
                print(f"⚠️ Ошибка при формировании ссылки: {e}")
                continue

        # 1) Сохраняем txt-подписку (base64 от списка ссылок) — это универсальный формат
        b64_subscription = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
        with open(FINAL_LINKS_FILE, "w", encoding="utf-8") as f:
            f.write(b64_subscription)
        print(f"🎉 Подписка сохранена: {FINAL_LINKS_FILE} (серверов: {len(links)})")

        # 2) Сохраняем JSON — но НЕ полный конфиг Xray, а совместимый с клиентами
        #    (список outbounds БЕЗ inbounds, чтобы не было ошибки empty "password")
        final_json = {
            "remarks": "🇷🇺 Yandex/Max",
            "outbounds": selected_obs + [
                {
                    "protocol": "freedom",
                    "settings": {"domainStrategy": "UseIP"},
                    "tag": "direct",
                },
                {
                    "protocol": "blackhole",
                    "settings": {"response": {"type": "http"}},
                    "tag": "block",
                },
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                ],
            },
        }

        # === ЖЁСТКАЯ ЗАЧИСТКА: удаляем ВСЕ ключи "remarks" рекурсивно ===
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

        # Контроль: считаем сколько раз встречается "remarks" в файле
        with open(FINAL_OUTPUT_FILE, "r", encoding="utf-8") as f:
            count = f.read().count('"remarks"')
        print(f"🔍 Проверка: строк 'remarks' в JSON = {count}")
        print(f"🎉 Итоговый конфиг успешно сохранён: {FINAL_OUTPUT_FILE} "
              f"(Всего рабочих серверов: {len(links)}, "
              f"дата обновления: {datetime.now():%Y-%m-%d %H:%M:%S})")


if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_and_filter()
    aggregator.save_final_config()
