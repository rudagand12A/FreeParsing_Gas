#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import base64
import urllib.parse
import urllib.request
import ssl
from datetime import datetime

URL_FILE = "url.txt"
OUTPUT_DIR = "output"
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
            print(f"⚠️ Файл {URL_FILE} не найден.")
            return

        with open(URL_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        print(f"📥 Загрузка ссылок из url.txt: {len(urls)}")
        
        for url in urls:
            try:
                print(f"🛰 Скачивание источника: {url}")
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15, context=self.ssl_ctx) as r:
                    content = r.read().decode('utf-8').strip()
                
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
                print(f"❌ Ошибка при обработке URL: {e}")

    def parse_uri(self, uri):
        try:
            if uri.startswith("vless://"):
                url = uri.replace("vless://", "")
                tag = ""
                if "#" in url: url, tag = url.split("#", 1)
                tag = urllib.parse.unquote(tag)
                
                params = {}
                if "?" in url: url, ps = url.split("?", 1) params = dict(urllib.parse.parse_qsl(ps))
                if "@" not in url: return None
                
                uuid, hp = url.split("@", 1)
                if ":" not in hp: return None
                address, port = hp.split(":", 1)
                port = int(re.sub(r'[\/?#].*$', '', port))

                stream = {"network": params.get("type", "raw"), "security": params.get("security", "none")}
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
                    "settings": {"vnext": [{"address": address, "port": port, "users": [{"id": uuid, "encryption": "none", "level": 8}]}]},
                    "streamSettings": stream
                }
        except:
            pass
        return None

    def process_tags(self):
        print("🔧 Модификация тегов (добавление флага и меток)...")
        for ob in self.outbounds:
            old_tag = ob.get("tag", "")
            base_name = "🇷🇺 LTE(пинг долгий)"
            
            # Проверка на безлимит и LTE
            new_remarks = f"{base_name} Безлимит" if "безлимит" in old_tag.lower() else base_name
            if any(w in old_tag.upper() for w in ["LTE", "ЛТЕ"]):
                new_remarks += " (Долгий пинг)"

            ob["tag"] = f"{new_remarks} [{ob['settings']['vnext'][0]['address']}]"
            ob["remarks"] = new_remarks

    def save_final_config(self):
        # Ограничение тарифа в 3000 конфигов
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
        print(f"🎉 Конфиг sub_1212.json успешно обновлен в папке output/. Добавлено серверов: {len(tags)}")

if __name__ == "__main__":
    aggregator = VPNAggregator()
    aggregator.load_and_download()
    aggregator.process_tags()
    aggregator.save_final_config()
