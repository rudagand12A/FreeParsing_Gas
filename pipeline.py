#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import base64
import urllib.parse
import urllib.request
import ssl
import sys
from datetime import datetime

# Форсируем построчный вывод логов, чтобы видеть ошибки в реальном времени на GitHub
sys.stdout.reconfigure(line_buffering=True)

# Автоматическое определение путей под архитектуру виртуальной машины GitHub
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_FILE = os.path.join(BASE_DIR, "url.txt")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
FINAL_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sub_1212.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

class VPNAggregator:
    def __init__(self):
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE
        self.outbounds = []

    def decode_base64(self, text):
        try:
            c = ''.join(text.split())
            pad = 4 - (len(c) % 4)
            if pad != 4 and pad != 0:
                c += '=' * pad
            return base64.b64decode(c).decode('utf-8', errors='ignore')
        except:
            return text

    def load_and_download(self):
        if not os.path.exists(URL_FILE):
            print(f"⚠️ Файл источников не найден по пути {URL_FILE}. Создаю пустой...")
            with open(URL_FILE, "w") as f:
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
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )
                with urllib.request.urlopen(req, timeout=15, context=self.ssl_ctx) as r:
                    content = r.read().decode('utf-8', errors='ignore').strip()
                
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

    def parse_uri(self, uri):
        if not uri.startswith("vless://"):
            return None
        try:
            # Отрезаем протокол vless://
            rest = uri[len("vless://"):]

            # Отделяем fragment (tag) — всё после первого '#'
            if "#" in rest:
                rest, fragment = rest.split("#", 1)
                tag = urllib.parse.unquote(fragment)
            else:
                tag = ""

            # Отделяем query параметры — всё после первого '?'
            if "?" in rest:
                rest, query = rest.split("?", 1)
                params = dict(urllib.parse.parse_qsl(query))
            else:
                params = {}

            # rest теперь имеет вид: uuid@host:port
            if "@" not in rest:
                return None
            user_info, host_port = rest.rsplit("@", 1)

            # Разбираем хост и порт (с учетом IPv6 в квадратных скобках [])
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

            stream = {
                "network": params.get("type", "raw"),
                "security": params.get("security", "none")
            }

            if stream["security"] == "reality":
                stream["realitySettings"] = {
                    "publicKey": params.get("pbk") or params.get("publicKey", ""),
                    "shortId": params.get("sid", ""),
                    "serverName": params.get("sni", address),
                    "fingerprint": params.get("fp", "chrome")
                }

            return {
                "protocol": "vless",
                "tag": tag or f"VLESS-[{address}]",
                "settings": {
                    "vnext": [{
                        "address": address,
                        "port": port,
                        "users": [{
                            "id": user_info,
                            "encryption": "none",
                            "level": 8
                        }]
                    }]
                },
                "streamSettings": stream
            }
        except Exception as e:
            print(f"❌ Ошибка разбора строки VLESS: {e}")
            return None

    def process_and_filter(self):
        print("🔧 Запуск гео-фильтрации (удаление EU и мусора)...")
        filtered_obs = []
        seen_ips = set()

        for ob in self.outbounds:
            old_tag = ob.get("tag", "")
            address = ob['settings']['vnext']['address']

            # Проверка флагов и названий локаций
            is_russian = any(w in old_tag.upper() for w in ["🇷🇺", "RU", "РОССИЯ", "RUSSIA", "YANDEX", "ЯНДЕКС"])
            is_foreign = any(w in old_tag.upper() for w in ["🇪🇺", "EU", "ЕВРОПА", "EUROPE", "DE", "ГЕРМАНИЯ", "FR", "ФРАНЦИЯ", "US", "США", "NL", "НИДЕРЛАНДЫ"])
            
            # Фильтр: если это EU или локация неизвестна (нет RU флагов) — отсекаем
            if is_foreign or not is_russian:
                continue

            # Исключаем дубликаты серверов с одинаковыми IP/хостами
            if address in seen_ips:
                continue
            seen_ips.add(address)

            base_name = "🇷🇺 YandexTCP Тест"
            new_remarks = f"{base_name} Безлимит" if "безлимит" in old_tag.lower() else base_name
            
            if any(w in old_tag.upper() for w in ["LTE", "ЛТЕ"]):
                new_remarks += " (Долгий пинг)"

            ob["tag"] = f"{new_remarks} [{address}]"
            ob["remarks"] = new_remarks
            filtered_obs.append(ob)

        print(f"🗑 Удалено неизвестных и EU конфигов. Чистых RU серверов в базе: {len(filtered_obs)}")
        self.outbounds = filtered_obs

    def save_final_config(self):
        # Загружаем срез тарифа на 3000 серверов
        selected_obs = self.outbounds[:3000]
        tags = [o["tag"] for o in selected_obs]

        selected_obs.append({"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"})
        selected_obs.append({"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"})

        final_json = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}, "tag": "socks-in"},
                {"port": 10809, "protocol": "http", "settings": {}, "tag": "http-in"}
            ],
            "outbounds": selected_obs,
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "balancers": [{
                    "tag": "Auto_Balancer",
                    "selector": tags,
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {"baselines": ["200ms", "500ms"], "expected": 2, "maxRTT": "1500ms", "tolerance": 0}
                    }
                }],
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"},
                    {"type": "field", "domain": ["geosite:category-ru", "domain:ru", "domain:su"], "outboundTag": "direct"},
                    {"type": "field", "ip": ["geoip:private", "geoip:ru"], "outboundTag": "direct"},
                    {"type": "field", "balancerTag": "Auto_Balancer", "network": "tcp,udp"}
                ]
            },
            "burstObservatory": {
                "pingConfig": {"destination": "http://gstatic.com", "interval": "2m", "sampling": 3, "timeout": "3s"},
                "subjectSelector": tags
            },
            "remarks": "🇸🇴 YandexTCP Тест",
            "last_update": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        with open(FINAL_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(final_json, f, indent=2, ensure_ascii=False)
        print(f"🎉 Топовый файл успешно создан и записан: {FINAL_OUTPUT_FILE}")

if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_and_filter()
    aggregator.save_final_config()
