#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cleaner.py — чистильщик готового конфига sub_1212.json
Удаляет узлы, которые валят Xray-core:
  - network: http / tcp с headerType=http (удалено из Xray)
  - невалидные UUID
  - Reality без publicKey
  - пустые/фейковые адреса
  - дубликаты по address:port
"""

import os
import json
import re
import base64
import uuid
import sys
import urllib.parse
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INPUT_FILE = os.path.join(BASE_DIR, "output", "sub_1212.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "output", "sub_1212_clean.json")
OUTPUT_LINKS = os.path.join(BASE_DIR, "output", "sub_1212_clean.txt")

# Транспорты, которые РАЗРЕШЕНЫ в текущем Xray
ALLOWED_NETWORKS = {"raw", "ws", "grpc", "xhttp", "httpupgrade", "tcp"}

# Запрещённые значения network (удалены из Xray)
FORBIDDEN_NETWORKS = {"http"}


def is_valid_uuid(value: str) -> bool:
    if not value:
        return False
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def is_valid_outbound(ob: dict) -> tuple[bool, str]:
    """Возвращает (валиден, причина_отказа)."""
    if not isinstance(ob, dict):
        return False, "not a dict"

    protocol = ob.get("protocol", "")
    tag = ob.get("tag", "")

    # Служебные outbounds — пропускаем как есть
    if protocol in ("freedom", "blackhole"):
        return True, ""

    if protocol != "vless":
        return False, f"unsupported protocol: {protocol}"

    try:
        vnext = ob["settings"]["vnext"][0]
        address = vnext["address"]
        port = vnext["port"]
        user = vnext["users"][0]
        user_id = user["id"]
    except (KeyError, IndexError, TypeError) as e:
        return False, f"broken settings: {e}"

    # 1. UUID
    if not is_valid_uuid(user_id):
        return False, f"invalid uuid: {user_id}"

    # 2. Адрес
    if not address or address in ("0.0.0.0", "127.0.0.1", "localhost"):
        return False, f"bad address: {address}"

    # 3. Порт
    if not isinstance(port, int) or not (1 <= port <= 65535):
        return False, f"bad port: {port}"

    stream = ob.get("streamSettings", {})
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    # 4. Запрещённые транспорты (старый HTTP)
    if network in FORBIDDEN_NETWORKS:
        return False, f"forbidden network: {network}"

    # 5. tcp/raw с headerType=http — тоже удалённый транспорт
    if network in ("tcp", "raw"):
        tcp_settings = stream.get("tcpSettings", {})
        header = tcp_settings.get("header", {})
        if header.get("type") == "http":
            return False, "old http-over-tcp transport"

    # 6. Неизвестный транспорт
    if network not in ALLOWED_NETWORKS:
        return False, f"unknown network: {network}"

    # 7. Reality без publicKey
    if security == "reality":
        reality = stream.get("realitySettings", {})
        if not reality.get("publicKey"):
            return False, "reality without publicKey"

    # 8. ws/xhttp/httpupgrade без пути — допустимо, но проверим
    if network == "ws":
        ws = stream.get("wsSettings", {})
        if not ws.get("path"):
            return False, "ws without path"

    return True, ""


def clean_config():
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Файл не найден: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    outbounds = data.get("outbounds", [])
    print(f"📥 Загружено outbounds: {len(outbounds)}")

    clean_outbounds = []
    removed = []
    seen_keys = set()

    for ob in outbounds:
        ok, reason = is_valid_outbound(ob)

        if not ok:
            removed.append((ob.get("tag", "?"), reason))
            continue

        # Дедупликация по address:port:uuid
        try:
            vnext = ob["settings"]["vnext"][0]
            key = f"{vnext['address']}:{vnext['port']}:{vnext['users'][0]['id']}"
        except (KeyError, IndexError, TypeError):
            key = None

        if key and key in seen_keys:
            removed.append((ob.get("tag", "?"), "duplicate"))
            continue
        if key:
            seen_keys.add(key)

        clean_outbounds.append(ob)

    print(f"\n🗑 Удалено узлов: {len(removed)}")
    for tag, reason in removed[:50]:  # показываем первые 50
        print(f"   - {tag}  →  {reason}")
    if len(removed) > 50:
        print(f"   ... и ещё {len(removed) - 50}")

    # Собираем финальный JSON
    data["outbounds"] = clean_outbounds

    # Убираем лишние remarks внутри (оставляем только верхний)
    def strip_remarks(obj):
        if isinstance(obj, dict):
            for k in list(obj.keys()):
                if k == "remarks" and obj is not data:
                    obj.pop(k, None)
                else:
                    strip_remarks(obj[k])
        elif isinstance(obj, list):
            for item in obj:
                strip_remarks(item)

    # Оставляем только верхнеуровневый remarks
    top_remarks = data.get("remarks", "🇷🇺 Yandex/Max")
    for ob in data["outbounds"]:
        ob.pop("remarks", None)
    data = {"remarks": top_remarks, **{k: v for k, v in data.items() if k != "remarks"}}

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Очищенный JSON: {OUTPUT_FILE}")
    print(f"   Осталось валидных узлов: {len(clean_outbounds)}")

    # Генерируем txt-подписку
    links = []
    for ob in clean_outbounds:
        if ob.get("protocol") != "vless":
            continue
        try:
            vnext = ob["settings"]["vnext"][0]
            address = vnext["address"]
            port = vnext["port"]
            user_id = vnext["users"][0]["id"]
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

            tag = urllib.parse.quote(ob.get("tag", address))
            q = urllib.parse.urlencode(params)
            links.append(f"vless://{user_id}@{address}:{port}?{q}#{tag}")
        except Exception as e:
            print(f"⚠️ Ошибка формирования ссылки: {e}")

    b64 = base64.b64encode("\n".join(links).encode("utf-8")).decode("utf-8")
    with open(OUTPUT_LINKS, "w", encoding="utf-8") as f:
        f.write(b64)
    print(f"✅ Подписка: {OUTPUT_LINKS} (ссылок: {len(links)})")
    print(f"🕒 Время: {datetime.now():%Y-%m-%d %H:%M:%S}")


if __name__ == "__main__":
    clean_config()
