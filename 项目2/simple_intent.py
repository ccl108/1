#!/usr/bin/env python3
"""Simple-Intent —— 基于 LLM 的简易意图驱动 SDN 访问控制系统（单文件版）。

一个文件包含全部角色：
    python simple_intent.py app         # 启动 Web 控制台（默认，可在 Windows 直接跑）
    python simple_intent.py controller  # 启动 Ryu 控制器（Linux / WSL，需 ryu）
    python simple_intent.py lab         # 启动 Mininet 实验网络（Linux / WSL，需 mininet）
    python simple_intent.py selftest    # 内置自检：意图解析 + 流表生成

未检测到 Ryu 控制器时，Web 端自动进入「仿真演示」模式，无需 Mininet 也能完整演示。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent


# ==========================================================================
# 配置
# ==========================================================================

def _load_dotenv() -> None:
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

TOPOLOGY = json.loads((ROOT / "topology.json").read_text(encoding="utf-8"))
SWITCH = TOPOLOGY["switch"]
HOSTS = TOPOLOGY["hosts"]
HOST_BY_NAME = {h["name"]: h for h in HOSTS}
HOST_BY_IP = {h["ip"]: h for h in HOSTS}

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "30"))

CONTROLLER_URL = os.getenv("CONTROLLER_URL", "http://127.0.0.1:8080").rstrip("/")
NET_URL = os.getenv("NET_URL", "http://127.0.0.1:8081").rstrip("/")
MODE = os.getenv("MODE", "auto").lower()
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "3"))
DB_PATH = Path(os.getenv("DB_PATH", str(ROOT / "logs.db")))


# ==========================================================================
# 意图模型：校验 + 生成流表
# ==========================================================================

ACTIONS = ("deny", "allow", "isolate", "unisolate")
PROTOCOLS = ("any", "tcp", "udp", "icmp")
PROTO_NUM = {"icmp": 1, "tcp": 6, "udp": 17}
PRIORITY_DENY = 200
PRIORITY_ISOLATE = 250


def resolve_host(token: str | None) -> dict | None:
    """把主机名 / IP / 中文别名解析成拓扑中的主机。"""
    if not token:
        return None
    key = str(token).strip().lower()
    for host in HOSTS:
        names = [host["name"], host["ip"], *host.get("alias", [])]
        if any(key == str(n).strip().lower() for n in names):
            return host
    return None


def _host_desc(host: dict) -> str:
    return f"{host['name']}({host['ip']})"


def _match(src: dict | None, dst: dict | None, protocol: str, port: int | None) -> dict[str, Any]:
    match: dict[str, Any] = {"eth_type": 0x0800}
    if src:
        match["ipv4_src"] = src["ip"]
    if dst:
        match["ipv4_dst"] = dst["ip"]
    if protocol in PROTO_NUM:
        match["ip_proto"] = PROTO_NUM[protocol]
        if port and protocol in ("tcp", "udp"):
            match[f"{protocol}_dst"] = port
    return match


def validate(intent: dict) -> str | None:
    """返回错误信息，None 表示合法。"""
    action = intent.get("action")
    if action not in ACTIONS:
        return f"不支持的动作：{action!r}，仅支持 {', '.join(ACTIONS)}"

    protocol = intent.get("protocol") or "any"
    if protocol not in PROTOCOLS:
        return f"不支持的协议：{protocol!r}"

    port = intent.get("port")
    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return f"端口必须是整数：{port!r}"
        if not 0 < port < 65536:
            return f"端口超出范围：{port}"
        if protocol not in ("tcp", "udp"):
            return "指定端口时必须同时指定 tcp 或 udp 协议"

    src = resolve_host(intent.get("src"))
    dst = resolve_host(intent.get("dst"))
    if intent.get("src") and not src:
        return f"拓扑中不存在主机：{intent.get('src')}"
    if intent.get("dst") and not dst:
        return f"拓扑中不存在主机：{intent.get('dst')}"

    if action == "isolate":
        if not (src or dst):
            return "隔离指令需要指定一台主机"
        if src and dst and src["name"] != dst["name"]:
            return "隔离指令只能指定一台主机"
    elif action in ("deny", "allow"):
        if not src or not dst:
            return f"{'阻断' if action == 'deny' else '放行'}指令需要同时指定源主机和目的主机"
        if src["name"] == dst["name"]:
            return "源主机和目的主机不能相同"
    else:  # unisolate
        if not (src or dst):
            return "解除隔离需要指定一台主机"
    return None


def build(intent: dict) -> dict:
    """生成待下发（flows）与待删除（deletes）的流表。"""
    action = intent["action"]
    protocol = (intent.get("protocol") or "any").lower()
    port = intent.get("port")
    port = int(port) if port is not None else None
    src = resolve_host(intent.get("src"))
    dst = resolve_host(intent.get("dst"))
    dpid = SWITCH["dpid"]

    if action == "deny":
        flows = [
            {"dpid": dpid, "priority": PRIORITY_DENY,
             "match": _match(src, dst, protocol, port), "actions": []},
            {"dpid": dpid, "priority": PRIORITY_DENY,
             "match": _match(dst, src, protocol, port), "actions": []},
        ]
        proto_txt = "全部 IP" if protocol == "any" else protocol.upper()
        if port:
            proto_txt += f"/{port}"
        return {
            "flows": flows,
            "deletes": [],
            "summary": f"阻断 {_host_desc(src)} <-> {_host_desc(dst)} 的 {proto_txt} 流量（双向）",
        }

    if action == "allow":
        deletes = [
            {"dpid": dpid, "priority": PRIORITY_DENY, "strict": True,
             "match": _match(src, dst, protocol, port)},
            {"dpid": dpid, "priority": PRIORITY_DENY, "strict": True,
             "match": _match(dst, src, protocol, port)},
        ]
        return {
            "flows": [],
            "deletes": deletes,
            "summary": f"放行 {_host_desc(src)} <-> {_host_desc(dst)} 的流量（删除对应阻断规则）",
        }

    host = src or dst
    keep_left = {
        "dpid": dpid,
        "priority": PRIORITY_ISOLATE,
        "strict": True,
        "match": _match(host, None, "any", None),
    }
    keep_right = {
        "dpid": dpid,
        "priority": PRIORITY_ISOLATE,
        "strict": True,
        "match": _match(None, host, "any", None),
    }

    if action == "unisolate":
        return {
            "flows": [],
            "deletes": [keep_left, keep_right],
            "summary": f"解除 {_host_desc(host)} 的隔离",
        }

    # isolate：对进出该主机的所有 IP 流量各下发一条丢弃规则
    flows = [
        {"dpid": dpid, "priority": PRIORITY_ISOLATE, "match": keep_left["match"], "actions": []},
        {"dpid": dpid, "priority": PRIORITY_ISOLATE, "match": keep_right["match"], "actions": []},
    ]
    return {
        "flows": flows,
        "deletes": [],
        "summary": f"隔离 {_host_desc(host)}：丢弃其进出全部 IP 流量",
    }


def host_states(flows: list[dict]) -> dict[str, dict]:
    """根据已生效流表推导每台主机状态，供拓扑图展示。"""
    states = {h["name"]: {"state": "normal", "notes": []} for h in HOSTS}
    for flow in flows:
        if flow.get("actions"):
            continue
        match = flow.get("match", {})
        if int(match.get("eth_type", 0x0800)) != 0x0800:
            continue
        src = HOST_BY_IP.get(str(match.get("ipv4_src")))
        dst = HOST_BY_IP.get(str(match.get("ipv4_dst")))
        if src and not dst:
            states[src["name"]]["state"] = "isolated"
            states[src["name"]]["notes"].append("出方向被丢弃")
        elif dst and not src:
            states[dst["name"]]["state"] = "isolated"
            states[dst["name"]]["notes"].append("入方向被丢弃")
        for host, other in ((src, dst), (dst, src)):
            if host and other and states[host["name"]]["state"] == "normal":
                states[host["name"]]["state"] = "restricted"
                states[host["name"]]["notes"].append(f"与 {other['name']} 的流量被阻断")
    return states


# ==========================================================================
# 自然语言 -> 意图（LLM 提示词工程 + 规则兜底）
# ==========================================================================

_SYSTEM_PROMPT = """你是一个 SDN 控制器里的“意图翻译器”。
你的任务：把用户的中文（或英文）网络管理指令，翻译成一个严格的 JSON 意图对象。

当前网络中只有一台 OpenFlow 交换机 s1，下面挂着这些主机：
{hosts}

可选动作 action：
- "deny"       阻断源主机到目的主机的流量
- "allow"      放行（撤销对应的阻断规则）
- "isolate"    隔离某台主机，丢弃它进出的全部 IP 流量
- "unisolate"  解除某台主机的隔离

字段规则：
- src：源主机，只能填上面列出的主机名（如 h1）；隔离/解除隔离时可留空
- dst：目的主机，只能填上面列出的主机名；隔离/解除隔离时为 null
- protocol：只能是 "any" / "tcp" / "udp" / "icmp"，没提到就填 "any"
- port：目的端口（整数），没提到就填 null；提到端口时必须同时给 tcp 或 udp
- reason：一句话说明你的理解

要求：
1. 只输出 JSON 对象，不要输出解释、Markdown 或代码块。
2. 主机只能用主机名表示，不要输出 IP。
3. 若无法理解，输出 {{"error": "原因"}}。

示例：
用户：禁止主机A访问服务器B
输出：{{"action": "deny", "src": "h1", "dst": "h2", "protocol": "any", "port": null, "reason": "阻断 h1 到 h2 的全部流量"}}

用户：隔离主机C
输出：{{"action": "isolate", "src": "h3", "dst": null, "protocol": "any", "port": null, "reason": "隔离 h3"}}

用户：放行主机A访问服务器B
输出：{{"action": "allow", "src": "h1", "dst": "h2", "protocol": "any", "port": null, "reason": "放行 h1 到 h2 的流量"}}

用户：禁止主机A访问主机B的80端口
输出：{{"action": "deny", "src": "h1", "dst": "h2", "protocol": "tcp", "port": 80, "reason": "阻断 h1 到 h2 的 TCP 80 端口"}}

用户：解除主机C的隔离
输出：{{"action": "unisolate", "src": "h3", "dst": null, "protocol": "any", "port": null, "reason": "解除 h3 的隔离"}}
"""

_ALIAS_NORMAL = {
    "block": "deny", "drop": "deny", "forbid": "deny", "prohibit": "deny",
    "permit": "allow", "recover": "allow", "restore": "allow",
    "隔离": "isolate", "隔离主机": "isolate",
    "解除隔离": "unisolate", "恢复": "unisolate",
}


def host_table() -> str:
    lines = []
    for host in HOSTS:
        alias = "、".join(host.get("alias", []))
        lines.append(f"- {host['name']}：IP {host['ip']}，交换机端口 {host['port']}，别名：{alias}")
    return "\n".join(lines)


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
        text = re.sub(r"\s*```$", "", text).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("模型没有返回 JSON 对象")
    return json.loads(text[start : end + 1])


def normalize(intent: dict) -> dict:
    action = str(intent.get("action", "")).strip().lower()
    action = _ALIAS_NORMAL.get(action, action)
    protocol = str(intent.get("protocol") or "any").strip().lower()
    if protocol not in ("tcp", "udp", "icmp"):
        protocol = "any"
    port = intent.get("port")
    try:
        port = int(port) if port not in (None, "", 0) else None
    except (TypeError, ValueError):
        port = None
    src = intent.get("src")
    dst = intent.get("dst")
    return {
        "action": action,
        "src": str(src).strip() if src else None,
        "dst": str(dst).strip() if dst else None,
        "protocol": protocol,
        "port": port,
        "reason": intent.get("reason") or "",
    }


def parse_with_llm(text: str) -> tuple[dict | None, str | None]:
    """返回 (意图, 错误)。"""
    if not LLM_API_KEY:
        return None, "未配置 LLM_API_KEY"
    import requests

    payload: dict[str, Any] = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT.format(hosts=host_table())},
            {"role": "user", "content": text},
        ],
        "temperature": 0,
    }
    headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
    url = f"{LLM_BASE_URL}/chat/completions"
    try:
        resp = requests.post(
            url,
            headers=headers,
            json={**payload, "response_format": {"type": "json_object"}},
            timeout=LLM_TIMEOUT,
        )
        if resp.status_code == 400:  # 部分服务不支持 response_format
            resp = requests.post(url, headers=headers, json=payload, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
    except Exception as exc:  # 网络 / 鉴权 / 响应格式问题
        return None, f"LLM 调用失败：{exc}"

    try:
        intent = normalize(_extract_json(content))
    except (ValueError, json.JSONDecodeError) as exc:
        return None, f"LLM 输出无法解析：{exc}"
    if intent.get("error") and not intent.get("action"):
        return None, f"LLM 无法理解该指令：{intent['error']}"
    return intent, None


def _ascii_pattern(word: str) -> str:
    return r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])"


def find_hosts(text: str) -> list[dict]:
    """按出现顺序找出文本中提到的主机（去重）。"""
    lower = text.lower()
    hits: list[tuple[int, int, dict]] = []
    for host in HOSTS:
        for name in [host["name"], host["ip"], *host.get("alias", [])]:
            name = str(name)
            pattern = _ascii_pattern(name.lower()) if name.isascii() else re.escape(name)
            for m in re.finditer(pattern, lower, flags=re.IGNORECASE):
                hits.append((m.start(), m.end() - m.start(), host))
    hits.sort(key=lambda x: (x[0], -x[1]))
    seen: set[str] = set()
    ordered: list[dict] = []
    for _, _, host in hits:
        if host["name"] not in seen:
            seen.add(host["name"])
            ordered.append(host)
    return ordered


def _guess_protocol(text: str) -> tuple[str, int | None]:
    lower = text.lower()
    protocol = "any"
    if "icmp" in lower or "ping" in lower:
        protocol = "icmp"
    elif "udp" in lower:
        protocol = "udp"
    elif "tcp" in lower:
        protocol = "tcp"
    port = None
    m = re.search(r"(?:端口|port)\s*[:：]?\s*(\d+)", lower) or re.search(r"(\d+)\s*(?:端口|port)", lower)
    if m:
        port = int(m.group(1))
        if protocol == "any":
            protocol = "tcp"
    return protocol, port


def parse_with_rules(text: str) -> tuple[dict | None, str | None]:
    lower = text.lower()
    hosts = find_hosts(text)
    protocol, port = _guess_protocol(text)

    def make(action: str, src: dict | None, dst: dict | None, reason: str) -> dict:
        return normalize(
            {
                "action": action,
                "src": src["name"] if src else None,
                "dst": dst["name"] if dst else None,
                "protocol": protocol,
                "port": port,
                "reason": reason,
            }
        )

    if re.search(r"(解除|取消|恢复).{0,6}隔离", text) or "恢复主机" in text:
        if not hosts:
            return None, "没有识别到主机名"
        return make("unisolate", hosts[0], None, f"解除 {hosts[0]['name']} 的隔离"), None

    if "隔离" in text:
        if not hosts:
            return None, "没有识别到主机名"
        return make("isolate", hosts[0], None, f"隔离 {hosts[0]['name']}"), None

    deny_words = ("禁止", "阻止", "阻断", "拦截", "不允许", "不准", "屏蔽", "禁止访问")
    allow_words = ("允许", "放行", "恢复", "解除阻断", "开启")
    if any(w in text for w in deny_words):
        if len(hosts) < 2:
            return None, "阻断指令需要两台主机"
        return make("deny", hosts[0], hosts[1], f"阻断 {hosts[0]['name']} 到 {hosts[1]['name']} 的流量"), None
    if any(w in lower for w in allow_words):
        if len(hosts) < 2:
            return None, "放行指令需要两台主机"
        return make("allow", hosts[0], hosts[1], f"放行 {hosts[0]['name']} 到 {hosts[1]['name']} 的流量"), None

    return None, "无法从指令中识别出动作（阻断 / 放行 / 隔离）"


def parse_intent(text: str) -> dict:
    """统一入口，返回 {intent, source, error, fallback_reason}。"""
    text = (text or "").strip()
    if not text:
        return {"intent": None, "source": None, "error": "指令不能为空", "fallback_reason": None}

    intent, llm_error = parse_with_llm(text)
    if intent:
        return {"intent": intent, "source": "llm", "error": None, "fallback_reason": None}

    intent, rule_error = parse_with_rules(text)
    if intent:
        return {"intent": intent, "source": "rule", "error": None, "fallback_reason": llm_error}
    return {"intent": None, "source": None, "error": rule_error, "fallback_reason": llm_error}


# ==========================================================================
# 日志
# ==========================================================================

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    text TEXT NOT NULL,
    source TEXT,
    intent TEXT,
    flows TEXT,
    deletes TEXT,
    result TEXT,
    ok INTEGER NOT NULL DEFAULT 0,
    mode TEXT
);
"""


class LogStore:
    def __init__(self, path: Path | str = DB_PATH) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def add(self, text, source, intent, flows, deletes, result, ok, mode) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO logs (ts, text, source, intent, flows, deletes, result, ok, mode)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    text,
                    source,
                    json.dumps(intent, ensure_ascii=False),
                    json.dumps(flows, ensure_ascii=False),
                    json.dumps(deletes, ensure_ascii=False),
                    result,
                    1 if ok else 0,
                    mode,
                ),
            )
            return int(cur.lastrowid)

    def list(self, limit: int = 50) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, log_id: int) -> dict | None:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT * FROM logs WHERE id = ?", (log_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def clear(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM logs")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data["intent"] = json.loads(data["intent"]) if data.get("intent") else None
        for key in ("flows", "deletes"):
            data[key] = json.loads(data[key]) if data.get(key) else []
        data["ok"] = bool(data["ok"])
        return data


# ==========================================================================
# 后端：真实（Ryu REST + Mininet 服务）/ 仿真
# ==========================================================================

class MockBackend:
    """没有 Mininet 时的内存仿真：真实解析、真实流表结构、模拟 Ping 结果。"""

    mode = "mock"

    def __init__(self) -> None:
        self._flows: list[dict] = []
        self._lock = threading.Lock()
        self._seq = 0

    def add(self, flows: list[dict]) -> list[dict]:
        results = []
        with self._lock:
            for flow in flows:
                self._seq += 1
                item = json.loads(json.dumps(flow))
                item["id"] = self._seq
                item["installed_at"] = time.strftime("%H:%M:%S")
                key = (flow["priority"], json.dumps(flow["match"], sort_keys=True))
                self._flows = [
                    f for f in self._flows
                    if (f["priority"], json.dumps(f["match"], sort_keys=True)) != key
                ]
                self._flows.append(item)
                results.append({"ok": True})
        return results

    def delete(self, rules: list[dict]) -> list[dict]:
        results = []
        with self._lock:
            for rule in rules:
                before = len(self._flows)
                self._flows = [
                    f for f in self._flows
                    if not (f["priority"] == rule["priority"] and f["match"] == rule["match"])
                ]
                results.append({"ok": True, "deleted": before - len(self._flows)})
        return results

    def flows(self) -> list[dict]:
        with self._lock:
            return list(self._flows)

    def clear(self) -> int:
        with self._lock:
            count = len(self._flows)
            self._flows = []
        return count

    def _blocked(self, src_ip: str, dst_ip: str) -> list[str]:
        hits = []
        with self._lock:
            flows = list(self._flows)
        for flow in flows:
            if flow.get("actions"):
                continue
            match = flow["match"]
            if match.get("ip_proto") not in (None, 1):  # ICMP ping
                continue
            if match.get("ipv4_src") and match["ipv4_src"] != src_ip:
                continue
            if match.get("ipv4_dst") and match["ipv4_dst"] != dst_ip:
                continue
            hits.append(f"优先级 {flow['priority']} 的丢弃规则")
        return hits

    def ping(self, src: str, dst: str) -> dict:
        hits = self._blocked(HOST_BY_NAME[src]["ip"], HOST_BY_NAME[dst]["ip"])
        if hits:
            return {"ok": False, "loss": 100.0, "rtt": None, "blocked": True,
                    "message": "ICMP 被流表丢弃（" + "，".join(hits) + "）"}
        return {"ok": True, "loss": 0.0, "rtt": round(random.uniform(0.08, 0.35), 2),
                "blocked": False, "message": "连通"}

    def topology(self) -> dict:
        ports = [{"port_no": h["port"], "name": f"{SWITCH['name']}-eth{h['port']}",
                  "hw_addr": f"02:00:00:00:00:{h['port']:02x}", "live": True} for h in HOSTS]
        net_hosts = [{"name": h["name"], "ip": h["ip"],
                      "mac": f"02:00:00:00:00:{h['port']:02x}"} for h in HOSTS]
        return {
            "controller": {"switches": [{"dpid": SWITCH["dpid"], "ports": ports, "mac_table": {}}]},
            "net": {"hosts": net_hosts},
        }


class RealBackend:
    """真实后端：流表交给 Ryu 控制器，Ping 交给 Mininet 内的网络服务。"""

    mode = "real"

    def __init__(self) -> None:
        self._requests = __import__("requests")

    def add(self, flows: list[dict]) -> list[dict]:
        resp = self._requests.post(
            f"{CONTROLLER_URL}/intent/flow/add", json={"flows": flows}, timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("ok"):
            return payload.get("results") or [{"ok": False, "error": payload.get("error", "下发失败")}]
        return payload.get("results") or [{"ok": True}]

    def delete(self, rules: list[dict]) -> list[dict]:
        resp = self._requests.post(
            f"{CONTROLLER_URL}/intent/flow/delete", json={"rules": rules}, timeout=HTTP_TIMEOUT
        )
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("ok"):
            return payload.get("results") or [{"ok": False, "error": payload.get("error", "删除失败")}]
        return payload.get("results") or [{"ok": True}]

    def flows(self) -> list[dict]:
        resp = self._requests.get(f"{CONTROLLER_URL}/intent/flows/{SWITCH['dpid']}", timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if not payload.get("ok"):
            raise RuntimeError(payload.get("error", "读取流表失败"))
        return payload.get("flows", [])

    def clear(self) -> int:
        resp = self._requests.post(
            f"{CONTROLLER_URL}/intent/flow/clear",
            json={"dpid": SWITCH["dpid"], "match": {"eth_type": 0x0800}},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return int(resp.json().get("deleted", 0))

    def ping(self, src: str, dst: str) -> dict:
        resp = self._requests.get(
            f"{NET_URL}/ping", params={"src": src, "dst": dst}, timeout=max(HTTP_TIMEOUT, 10)
        )
        resp.raise_for_status()
        return resp.json()

    def topology(self) -> dict:
        data: dict = {"controller": {}, "net": {}}
        try:
            data["controller"] = self._requests.get(
                f"{CONTROLLER_URL}/intent/topology", timeout=HTTP_TIMEOUT
            ).json()
        except Exception:
            data["controller"] = {}
        try:
            data["net"] = self._requests.get(f"{NET_URL}/status", timeout=HTTP_TIMEOUT).json()
        except Exception:
            data["net"] = {}
        return data


def controller_ready() -> bool:
    try:
        import requests

        return requests.get(f"{CONTROLLER_URL}/intent/health", timeout=0.6).ok
    except Exception:
        return False


def build_backend():
    if MODE in ("mock", "sim", "仿真"):
        return MockBackend()
    if MODE == "real":
        return RealBackend()
    return RealBackend() if controller_ready() else MockBackend()


# ==========================================================================
# Web 控制台
# ==========================================================================

PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simple-Intent · 意图驱动 SDN 访问控制</title>
<style>
:root{--bg:#0b1220;--panel:#111b2e;--line:#22304a;--text:#e6edf7;--muted:#8fa2bf;--accent:#4ea1ff;--ok:#3ddc97;--warn:#ffc857;--bad:#ff6b6b;--mono:ui-monospace,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 560px at 12% -8%,#16304f 0%,transparent 62%),var(--bg);color:var(--text);font:14px/1.6 "Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;min-height:100vh}
.shell{max-width:1320px;margin:0 auto;padding:22px 22px 40px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#4ea1ff,#7b61ff);display:grid;place-items:center;font-weight:700;letter-spacing:1px;color:#fff}
h1{margin:0;font-size:19px;letter-spacing:.4px}
.sub{margin:0;color:var(--muted);font-size:12px}
.meta{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.badge{padding:5px 10px;border-radius:999px;font-size:12px;border:1px solid var(--line);background:#0e1a2c;color:var(--muted)}
.badge.on{color:var(--ok);border-color:#1f6f57;background:#0e2a22}
.badge.real{color:var(--accent);border-color:#23548c;background:#0d2138}
.btn{cursor:pointer;border-radius:9px;border:1px solid var(--line);background:#16233a;color:var(--text);padding:7px 14px;font-size:13px;transition:.15s}
.btn:hover{border-color:#3a5a86;background:#1b2c47}
.btn:disabled{opacity:.55;cursor:not-allowed}
.btn.primary{background:linear-gradient(135deg,#2f7fe0,#5b64ff);border-color:#4b7fd0;font-weight:600}
.btn.primary:hover{filter:brightness(1.08)}
.btn.ghost{background:transparent}
.btn.small{padding:3px 9px;font-size:12px}
main{display:grid;grid-template-columns:1.12fr .88fr;gap:16px;align-items:start}
.col{display:flex;flex-direction:column;gap:16px}
.card{background:linear-gradient(180deg,rgba(23,35,56,.92),rgba(15,23,42,.94));border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 10px 30px rgba(0,0,0,.25)}
.card h2{margin:0 0 12px;font-size:14px;display:flex;align-items:center;gap:8px;color:#cfe0f7;font-weight:600;justify-content:space-between}
.card h2 small{color:var(--muted);font-weight:400;font-size:12px;margin-left:auto}
.card h2 .tools{display:flex;gap:8px;align-items:center;margin-left:auto}
textarea{width:100%;background:#0a1524;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:11px 12px;font:14px/1.6 inherit;resize:vertical;outline:none}
textarea:focus{border-color:#3d6ba3;box-shadow:0 0 0 3px rgba(78,161,255,.12)}
.chips{display:flex;flex-wrap:wrap;gap:7px;margin:10px 0 0}
.chipx{cursor:pointer;padding:4px 10px;border-radius:999px;border:1px solid var(--line);background:#0e1a2c;font-size:12px;color:#a9bdd8}
.chipx:hover{border-color:#3a5a86;color:#dbe9ff}
.row{display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap}
.hint{color:var(--muted);font-size:12px}
.result{margin-top:12px;border-radius:10px;border:1px solid var(--line);background:#0a1524;padding:12px}
.result.ok{border-color:#1f6f57}
.result.bad{border-color:#7a2b34}
.result h3{margin:0;font-size:13px}
pre{margin:8px 0 0;background:#07101c;border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font:12px/1.55 var(--mono);color:#a8c6e8;max-height:230px}
svg#topo{width:100%;height:auto;display:block}
.legend{display:flex;gap:14px;color:var(--muted);font-size:12px;margin-top:4px;flex-wrap:wrap}
.legend i{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:12px}
.matrix td,.matrix th{text-align:center}
.matrix td.ok{color:var(--ok)}
.matrix td.bad{color:var(--bad)}
.matrix td.self{color:#3a4a63}
.k{display:inline-block;padding:1px 7px;border-radius:6px;background:#0d2138;border:1px solid #23548c;color:#8ec2ff;font:11px var(--mono);margin:2px 3px 0 0}
.drop{color:var(--bad);font-weight:600}
.fwd{color:var(--ok)}
.scroll{max-height:300px;overflow:auto}
.muted{color:var(--muted)}
.toast{position:fixed;right:22px;bottom:22px;background:#132238;border:1px solid var(--line);padding:10px 16px;border-radius:10px;font-size:13px;opacity:0;transform:translateY(8px);transition:.25s;pointer-events:none;z-index:9}
.toast.show{opacity:1;transform:none}
.toast.bad{border-color:#7a2b34;color:#ffb3b3}
@media(max-width:980px){main{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="shell">
  <header>
    <div class="brand">
      <div class="logo">SI</div>
      <div>
        <h1>Simple-Intent</h1>
        <p class="sub">基于 LLM 的简易意图驱动 SDN 访问控制系统 · Ryu + Mininet</p>
      </div>
    </div>
    <div class="meta">
      <span id="mode" class="badge">检测中…</span>
      <span id="llm" class="badge">LLM …</span>
      <button id="refresh" class="btn ghost">刷新状态</button>
    </div>
  </header>

  <main>
    <div class="col">
      <section class="card">
        <h2>意图输入 <small>自然语言 → 意图 → OpenFlow 流表</small></h2>
        <textarea id="text" rows="3" placeholder="例如：禁止主机A访问服务器B / 隔离主机C / 放行主机A访问服务器B"></textarea>
        <div class="chips" id="chips"></div>
        <div class="row">
          <button id="run" class="btn primary">执行意图</button>
          <span id="hint" class="hint">回车快速执行，Shift+回车换行</span>
        </div>
        <div id="result" class="result" style="display:none"></div>
      </section>

      <section class="card">
        <h2>连通性检测 <small id="pinghint"></small></h2>
        <div class="row" style="margin-top:0">
          <button id="pingall" class="btn">全部检测（Ping）</button>
          <span class="hint">绿色=可达，红色=被流表阻断</span>
        </div>
        <div id="matrix" class="muted" style="margin-top:10px">尚未检测</div>
      </section>

      <section class="card">
        <h2>已下发流表
          <span class="tools"><small id="flow-sub"></small><button id="reset" class="btn small ghost">清空规则</button></span>
        </h2>
        <div id="flows" class="muted">加载中…</div>
      </section>
    </div>

    <div class="col">
      <section class="card">
        <h2>网络拓扑 <small id="topo-sub"></small></h2>
        <svg id="topo" viewBox="0 0 560 390"></svg>
        <div class="legend">
          <span><i style="background:#3ddc97"></i>正常</span>
          <span><i style="background:#ffc857"></i>受限（存在阻断规则）</span>
          <span><i style="background:#ff6b6b"></i>隔离</span>
          <span class="muted">点击被隔离主机可解除隔离</span>
        </div>
      </section>

      <section class="card">
        <h2>操作日志 <span class="tools"><small id="log-sub"></small><button id="clearlogs" class="btn small ghost">清空日志</button></span></h2>
        <div id="logs" class="muted">加载中…</div>
      </section>
    </div>
  </main>
</div>
<div id="toast" class="toast"></div>

<script>
const $ = (id) => document.getElementById(id);
const state = { hosts: [], flows: [], logs: [], mode: "mock" };
const COLORS = { normal: "#3ddc97", restricted: "#ffc857", isolated: "#ff6b6b" };
const NS = "http://www.w3.org/2000/svg";
const EXAMPLES = ["禁止主机A访问服务器B", "隔离主机C", "禁止主机A访问主机B的80端口", "放行主机A访问服务器B", "解除主机C的隔离"];

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(msg, ok) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast show" + (ok === false ? " bad" : "");
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.className = "toast"; }, 2800);
}

async function api(path, opts) {
  opts = opts || {};
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    const msg = (data && (data.error || data.detail)) || ("HTTP " + res.status);
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return data || {};
}

function mk(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  return el;
}

async function loadStatus() {
  const s = await api("/api/status");
  state.mode = s.mode;
  const m = $("mode");
  m.textContent = s.mode === "real" ? "真实网络 · Ryu + Mininet" : "仿真演示 · Mock 网络";
  m.className = "badge " + (s.mode === "real" ? "real" : "on");
  const l = $("llm");
  l.textContent = s.llm_configured ? ("LLM · " + s.llm_model) : "LLM · 未配置（规则解析）";
  l.className = "badge " + (s.llm_configured ? "on" : "");
}

function renderTopo(data) {
  state.hosts = data.hosts || [];
  const svg = $("topo");
  svg.innerHTML = "";
  const W = 560, H = 390, cx = W / 2, cy = 196;
  const hosts = state.hosts, n = hosts.length || 1;
  const pos = hosts.map((h, i) => {
    const a = -Math.PI / 2 + i * 2 * Math.PI / n;
    return { x: cx + Math.cos(a) * 196, y: cy + Math.sin(a) * 120, h: h };
  });

  pos.forEach((p) => {
    const c = COLORS[p.h.state] || COLORS.normal;
    svg.appendChild(mk("line", {
      x1: p.x, y1: p.y, x2: cx, y2: cy, stroke: c,
      "stroke-width": 2,
      "stroke-opacity": p.h.state === "normal" ? 0.5 : 0.95,
      "stroke-dasharray": p.h.state === "isolated" ? "7 5" : (p.h.live ? "0" : "4 4")
    }));
  });

  const swG = mk("g", {});
  swG.appendChild(mk("rect", { x: cx - 60, y: cy - 29, width: 120, height: 58, rx: 12, fill: "#122a45", stroke: "#3d6ba3", "stroke-width": 2 }));
  const l1 = mk("text", { x: cx, y: cy - 3, "text-anchor": "middle", fill: "#dbe9ff", "font-size": 14, "font-weight": 600 });
  l1.textContent = (data.switch && data.switch.name) || "s1";
  const l2 = mk("text", { x: cx, y: cy + 15, "text-anchor": "middle", fill: "#7d95b6", "font-size": 10.5 });
  l2.textContent = "OpenFlow 1.3 · " + (data.flow_count || 0) + " 条流表";
  swG.appendChild(l1); swG.appendChild(l2);
  svg.appendChild(swG);

  pos.forEach((p) => {
    const h = p.h, c = COLORS[h.state] || COLORS.normal;
    const g = mk("g", { transform: "translate(" + p.x.toFixed(1) + "," + p.y.toFixed(1) + ")", style: "cursor:pointer" });
    g.appendChild(mk("circle", {
      r: 30,
      fill: h.state === "normal" ? "rgba(61,220,151,.10)" : (h.state === "isolated" ? "rgba(255,107,107,.16)" : "rgba(255,200,87,.13)"),
      stroke: c, "stroke-width": 2
    }));
    const name = mk("text", { y: 5, "text-anchor": "middle", fill: "#e6edf7", "font-size": 14, "font-weight": 600 });
    name.textContent = h.name;
    g.appendChild(name);
    const ip = mk("text", { y: 49, "text-anchor": "middle", fill: "#7d95b6", "font-size": 10.5, "font-family": "ui-monospace,monospace" });
    ip.textContent = h.ip;
    g.appendChild(ip);
    if (h.state !== "normal") {
      const tag = mk("text", { y: (p.y > cy ? 66 : -44), "text-anchor": "middle", fill: c, "font-size": 11 });
      tag.textContent = h.state === "isolated" ? "隔离" : "受限";
      g.appendChild(tag);
    }
    if (!h.live) {
      const tag = mk("text", { x: 34, y: -20, fill: "#ff6b6b", "font-size": 10 });
      tag.textContent = "链路断开";
      g.appendChild(tag);
    }
    g.addEventListener("click", () => {
      if (h.state === "isolated") runText("解除主机" + h.name + "的隔离");
      else toast(h.name + " · " + h.ip + " · " + ((h.notes && h.notes[0]) || "状态正常"));
    });
    svg.appendChild(g);
  });

  $("topo-sub").textContent = state.hosts.filter((h) => h.state === "isolated").length + " 台隔离 · "
    + state.hosts.filter((h) => h.state === "restricted").length + " 台受限";
}

function fmtVal(k, v) {
  if (k === "eth_type") return (v === 2048 || v === "2048") ? "IPv4" : v;
  if (k === "ip_proto") return { 1: "ICMP", 6: "TCP", 17: "UDP" }[v] || v;
  return v;
}

function renderFlows(data) {
  state.flows = data.flows || [];
  $("flow-sub").textContent = state.flows.length + " 条";
  const box = $("flows");
  if (!state.flows.length) {
    box.className = "muted";
    box.innerHTML = "当前没有自定义流表，交换机处于默认转发（学习交换）模式。";
    return;
  }
  box.className = "";
  let html = "<div class='scroll'><table><thead><tr><th>优先级</th><th>匹配条件</th><th>动作</th></tr></thead><tbody>";
  state.flows.forEach((f) => {
    const m = f.match || {};
    const chips = Object.keys(m).map((k) => "<span class='k'>" + k + ": " + esc(fmtVal(k, m[k])) + "</span>").join("");
    const act = (f.actions && f.actions.length)
      ? "<span class='fwd'>OUTPUT → 端口 " + f.actions.map((a) => a.port).join(",") + "</span>"
      : "<span class='drop'>DROP 丢弃</span>";
    html += "<tr><td>" + f.priority + "</td><td>" + chips + "</td><td>" + act + "</td></tr>";
  });
  box.innerHTML = html + "</tbody></table></div>";
}

function srcBadge(l) {
  if (!l.source) return "<span class='muted'>—</span>";
  return "<span class='k'>" + (l.source === "llm" ? "LLM" : "规则") + "</span>";
}

function renderLogs(data) {
  state.logs = data.logs || [];
  $("log-sub").textContent = state.logs.length + " 条";
  const box = $("logs");
  if (!state.logs.length) {
    box.className = "muted";
    box.innerHTML = "还没有操作记录。";
    return;
  }
  box.className = "";
  let html = "<div class='scroll'><table><thead><tr><th>时间</th><th>指令 / 结果</th><th>来源</th><th></th></tr></thead><tbody>";
  state.logs.forEach((l) => {
    const canUndo = l.ok && ((l.flows && l.flows.length) || (l.deletes && l.deletes.length));
    html += "<tr><td class='muted' style='white-space:nowrap'>" + esc((l.ts || "").slice(11)) + "</td>"
      + "<td><div" + (l.ok ? "" : " style='color:#ffb3b3'") + ">" + esc(l.text) + "</div>"
      + "<div class='muted' style='font-size:11.5px'>" + esc(l.result) + "</div></td>"
      + "<td>" + srcBadge(l) + "</td>"
      + "<td>" + (canUndo ? "<button class='btn small' data-undo='" + l.id + "'>撤销</button>" : "") + "</td></tr>";
  });
  box.innerHTML = html + "</tbody></table></div>";
  box.querySelectorAll("[data-undo]").forEach((b) => {
    b.onclick = () => undo(+b.getAttribute("data-undo"));
  });
}

function renderMatrix(results, names) {
  names = names || state.hosts.map((h) => h.name);
  let html = "<table class='matrix'><thead><tr><th>源 \\ 目的</th>" + names.map((n) => "<th>" + n + "</th>").join("") + "</tr></thead><tbody>";
  names.forEach((src) => {
    html += "<tr><th>" + src + "</th>";
    names.forEach((dst) => {
      if (src === dst) { html += "<td class='self'>—</td>"; return; }
      const find = (results || []).find((x) => x.src === src && x.dst === dst);
      if (!find) { html += "<td class='self'>?</td>"; return; }
      if (find.ok) {
        html += "<td class='ok'>✓ " + (find.rtt == null ? "" : find.rtt) + "ms</td>";
      } else {
        html += "<td class='bad' title='" + esc(find.message || "") + "'>✗ 阻断</td>";
      }
    });
    html += "</tr>";
  });
  $("matrix").className = "";
  $("matrix").innerHTML = html + "</tbody></table>";
}

async function loadTopo() {
  const d = await api("/api/topology");
  renderTopo(d);
}

async function loadFlows() {
  renderFlows(await api("/api/flows"));
}

async function loadLogs() {
  renderLogs(await api("/api/logs?limit=60"));
}

async function refreshAll() {
  await Promise.all([loadTopo(), loadFlows(), loadLogs()]);
}

async function runText(text) {
  text = (text || "").trim();
  if (!text) { toast("请先输入意图", false); return; }
  $("text").value = text;
  const btn = $("run");
  btn.disabled = true;
  $("hint").textContent = "解析并下发中…";
  const box = $("result");
  box.style.display = "block";
  box.className = "result";
  box.innerHTML = "<h3 class='muted'>正在解析意图…</h3>";
  try {
    const r = await api("/api/intent", { method: "POST", body: JSON.stringify({ text: text }) });
    box.className = "result " + (r.ok ? "ok" : "bad");
    const head = (r.ok ? "✅ " : "❌ ") + (r.summary || r.error || "");
    box.innerHTML = "<h3>" + esc(head) + "</h3>"
      + "<div class='hint' style='margin-top:4px'>意图来源：" + (r.source === "llm" ? "LLM" : "规则兜底")
      + " · 下发 " + (r.exec ? r.exec.added : 0) + " 条 · 删除 " + (r.exec ? r.exec.deleted : 0) + " 条"
      + (r.fallback_reason ? " · LLM 不可用： " + esc(r.fallback_reason) : "") + "</div>"
      + "<pre>" + esc(JSON.stringify({ intent: r.intent, flows: r.flows, deletes: r.deletes }, null, 2)) + "</pre>";
    toast(r.ok ? "意图已执行" : (r.error || "执行失败"), r.ok);
  } catch (e) {
    box.className = "result bad";
    box.innerHTML = "<h3>❌ " + esc(e.message) + "</h3>";
    toast(e.message, false);
  } finally {
    btn.disabled = false;
    $("hint").textContent = "回车快速执行，Shift+回车换行";
    await refreshAll();
  }
}

async function pingAll() {
  const btn = $("pingall");
  btn.disabled = true;
  $("pinghint").textContent = "检测中…";
  try {
    const r = await api("/api/ping-all", { method: "POST" });
    renderMatrix(r.results, r.hosts);
    $("pinghint").textContent = (r.mode === "real" ? "真实网络" : "仿真") + " · " + new Date().toLocaleTimeString();
  } catch (e) {
    $("pinghint").textContent = "失败";
    toast(e.message, false);
  } finally {
    btn.disabled = false;
  }
}

async function undo(id) {
  try {
    const r = await api("/api/logs/" + id + "/undo", { method: "POST" });
    toast(r.ok ? "已撤销 #" + id : (r.error || "撤销失败"), r.ok);
  } catch (e) {
    toast(e.message, false);
  }
  await refreshAll();
  pingAll();
}

async function resetRules() {
  if (!confirm("确定清空所有 ACL 流表（保留学习交换）？")) return;
  try {
    const r = await api("/api/reset", { method: "POST" });
    toast(r.removed < 0 ? "已提交清空指令" : "已清除 " + r.removed + " 条流表");
  } catch (e) {
    toast(e.message, false);
  }
  await refreshAll();
  pingAll();
}

async function clearLogs() {
  if (!confirm("确定清空操作日志？")) return;
  await api("/api/logs", { method: "DELETE" });
  toast("日志已清空");
  await loadLogs();
}

function initChips() {
  const box = $("chips");
  EXAMPLES.forEach((t) => {
    const el = document.createElement("span");
    el.className = "chipx";
    el.textContent = t;
    el.onclick = () => runText(t);
    box.appendChild(el);
  });
}

function bind() {
  $("run").onclick = () => runText($("text").value);
  $("text").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey) { e.preventDefault(); runText($("text").value); }
  });
  $("pingall").onclick = pingAll;
  $("reset").onclick = resetRules;
  $("clearlogs").onclick = clearLogs;
  $("refresh").onclick = async () => { await loadStatus(); await refreshAll(); toast("状态已刷新"); };
}

async function boot() {
  initChips();
  bind();
  try {
    await loadStatus();
    await refreshAll();
    await pingAll();
  } catch (e) {
    toast(e.message, false);
  }
}

boot();
</script>
</body>
</html>
"""


def create_app():
    """创建 FastAPI 应用（延迟导入，保证 ryu-manager 导入本文件时不受影响）。"""
    from fastapi import Body, FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="Simple-Intent", version="1.0.0")
    store = LogStore()

    backend_holder: dict[str, Any] = {"backend": None}
    lock = threading.Lock()

    def backend(refresh: bool = False):
        with lock:
            current = backend_holder["backend"]
            if current is None or refresh:
                candidate = build_backend()
                if current is None or type(candidate) is not type(current):
                    backend_holder["backend"] = candidate
            return backend_holder["backend"]

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE

    @app.get("/api/status")
    def status():
        b = backend(refresh=True)
        return {
            "mode": b.mode,
            "llm_configured": bool(LLM_API_KEY),
            "llm_model": LLM_MODEL if LLM_API_KEY else None,
            "switch": SWITCH,
            "hosts": HOSTS,
            "controller_url": CONTROLLER_URL,
            "net_url": NET_URL,
        }

    @app.post("/api/intent")
    def run_intent(payload: dict = Body(...)):
        b = backend()
        text = str(payload.get("text") or "").strip()
        parsed = parse_intent(text)
        if not parsed["intent"]:
            store.add(text, None, None, [], [], parsed["error"] or "解析失败", False, b.mode)
            return JSONResponse(
                status_code=400,
                content={
                    "ok": False,
                    "error": parsed["error"],
                    "fallback_reason": parsed.get("fallback_reason"),
                    "mode": b.mode,
                },
            )

        intent = parsed["intent"]
        error = validate(intent)
        if error:
            store.add(text, parsed["source"], intent, [], [], error, False, b.mode)
            return JSONResponse(
                status_code=400,
                content={"ok": False, "error": error, "intent": intent, "mode": b.mode},
            )

        plan = build(intent)
        added, deleted, errors = [], [], []

        if plan["flows"]:
            try:
                results = b.add(plan["flows"])
            except Exception as exc:
                results = [{"ok": False, "error": str(exc)}]
            for flow, result in zip(plan["flows"], results):
                if result.get("ok"):
                    added.append(flow)
                else:
                    errors.append(result.get("error", "下发失败"))

        if plan["deletes"]:
            try:
                results = b.delete(plan["deletes"])
            except Exception as exc:
                results = [{"ok": False, "error": str(exc)}]
            for rule, result in zip(plan["deletes"], results):
                if result.get("ok"):
                    deleted.append(rule)
                else:
                    errors.append(result.get("error", "删除失败"))

        ok = not errors
        message = plan["summary"] if ok else "；".join(errors)
        log_id = store.add(text, parsed["source"], intent, added, deleted, message, ok, b.mode)

        return {
            "ok": ok,
            "error": None if ok else message,
            "source": parsed["source"],
            "fallback_reason": parsed.get("fallback_reason"),
            "intent": intent,
            "summary": plan["summary"],
            "flows": plan["flows"],
            "deletes": plan["deletes"],
            "exec": {"added": len(added), "deleted": len(deleted), "errors": errors},
            "log_id": log_id,
            "mode": b.mode,
        }

    @app.get("/api/flows")
    def list_flows():
        b = backend()
        try:
            flows = b.flows()
        except Exception as exc:
            return JSONResponse(status_code=502, content={"ok": False, "error": f"读取流表失败：{exc}"})
        flows = [f for f in flows if int(f.get("priority", 0)) > 0]
        return {"ok": True, "count": len(flows), "flows": flows, "mode": b.mode}

    @app.get("/api/topology")
    def topology():
        b = backend()
        try:
            flows = b.flows()
        except Exception:
            flows = []
        states = host_states(flows)
        raw = b.topology()

        port_live: dict[int, bool] = {}
        switches = (raw.get("controller") or {}).get("switches") or []
        for switch in switches:
            for port in switch.get("ports", []):
                port_live[int(port["port_no"])] = bool(port.get("live", True))

        net_hosts = {h["name"]: h for h in ((raw.get("net") or {}).get("hosts") or [])}
        hosts = []
        for host in HOSTS:
            st = states[host["name"]]
            hosts.append(
                {
                    "name": host["name"],
                    "ip": host["ip"],
                    "port": host["port"],
                    "alias": host.get("alias", []),
                    "mac": net_hosts.get(host["name"], {}).get("mac", ""),
                    "state": st["state"],
                    "notes": st["notes"],
                    "live": port_live.get(host["port"], True),
                }
            )

        return {
            "ok": True,
            "mode": b.mode,
            "switch": {**SWITCH, "online": bool(switches) or b.mode == "mock"},
            "hosts": hosts,
            "flow_count": len(flows),
        }

    @app.post("/api/ping")
    def ping(payload: dict = Body(...)):
        b = backend()
        src = str(payload.get("src") or "")
        dst = str(payload.get("dst") or "")
        if src not in HOST_BY_NAME or dst not in HOST_BY_NAME:
            raise HTTPException(status_code=400, detail="主机不存在")
        try:
            result = b.ping(src, dst)
        except Exception as exc:
            return JSONResponse(status_code=502, content={"ok": False, "error": str(exc)})
        return {**result, "src": src, "dst": dst}

    @app.post("/api/ping-all")
    def ping_all():
        b = backend()
        names = [h["name"] for h in HOSTS]
        results = []
        for src in names:
            for dst in names:
                if src == dst:
                    continue
                try:
                    result = b.ping(src, dst)
                except Exception as exc:
                    result = {"ok": False, "error": str(exc)}
                results.append({"src": src, "dst": dst, **result})
        return {"ok": True, "results": results, "hosts": names, "mode": b.mode}

    @app.get("/api/logs")
    def logs(limit: int = 50):
        return {"ok": True, "logs": store.list(limit)}

    @app.delete("/api/logs")
    def clear_logs():
        store.clear()
        return {"ok": True}

    @app.post("/api/logs/{log_id}/undo")
    def undo(log_id: int):
        entry = store.get(log_id)
        if not entry:
            raise HTTPException(status_code=404, detail="日志不存在")
        b = backend()

        deletes = [
            {"dpid": f["dpid"], "priority": f["priority"], "strict": True, "match": f["match"]}
            for f in entry["flows"]
        ]
        restores = [
            {"dpid": r["dpid"], "priority": r["priority"], "match": r["match"], "actions": []}
            for r in entry["deletes"]
        ]
        errors = []
        try:
            if deletes:
                b.delete(deletes)
            if restores:
                b.add(restores)
        except Exception as exc:
            errors.append(str(exc))

        ok = not errors
        store.add(f"撤销操作 #{log_id}", entry["source"], entry["intent"], restores, deletes,
                  "已撤销" if ok else "；".join(errors), ok, b.mode)
        return {"ok": ok, "error": None if ok else "；".join(errors)}

    @app.post("/api/reset")
    def reset():
        b = backend()
        try:
            removed = b.clear()
        except Exception as exc:
            return JSONResponse(status_code=502, content={"ok": False, "error": f"清空失败：{exc}"})
        store.add("清空全部规则", "ui", None, [], [], f"已清除 {removed} 条流表", True, b.mode)
        return {"ok": True, "removed": removed}

    return app


# ==========================================================================
# 角色一：Ryu 控制器（ryu-manager simple_intent.py）
# ==========================================================================

try:  # 只有装了 ryu 的 Linux / WSL 环境才会定义控制器类
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route
    from ryu.base import app_manager as ryu_app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                        MAIN_DISPATCHER, set_ev_cls)
    from ryu.lib.packet import ethernet, packet
    from ryu.ofproto import ofproto_v1_3
    from webob import Response

    HAS_RYU = True
except Exception:  # pragma: no cover - Windows 上通常没有 ryu
    HAS_RYU = False


if HAS_RYU:

    def _json_response(payload: dict, status: int = 200):
        return Response(
            status=status,
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )

    def _ofp_match(parser, match: dict):
        kwargs = {}
        for key, value in match.items():
            if key in ("ipv4_src", "ipv4_dst"):
                kwargs[key] = str(value)
            else:
                kwargs[key] = int(value)
        try:
            return parser.OFPMatch(**kwargs)
        except Exception:  # 个别 Ryu 版本要求 IPv4Address 对象
            import ipaddress

            for key in ("ipv4_src", "ipv4_dst"):
                if key in kwargs:
                    kwargs[key] = ipaddress.ip_address(kwargs[key])
            return parser.OFPMatch(**kwargs)

    def _flow_to_json(flow) -> dict:
        match = {}
        for key, value in flow.match.items():
            if key in ("ipv4_src", "ipv4_dst"):
                match[key] = str(value)
            elif isinstance(value, int):
                match[key] = value
            else:
                try:
                    match[key] = int(value)
                except (TypeError, ValueError):
                    match[key] = str(value)
        actions = []
        for inst in getattr(flow, "instructions", []):
            for action in getattr(inst, "actions", []):
                if getattr(action, "type", None) == 0:
                    actions.append({"type": "OUTPUT", "port": getattr(action, "port", None)})
        return {
            "priority": flow.priority,
            "match": match,
            "actions": actions,
            "packet_count": getattr(flow, "packet_count", 0),
        }

    class IntentRest(ControllerBase):
        def __init__(self, req, link, data, **config):
            super().__init__(req, link, data, **config)
            self.app = data["controller_app"]

        @route("simple_intent", "/intent/health", methods=["GET"])
        def health(self, req, **kwargs):
            return _json_response({"ok": True, "switches": list(self.app.datapaths.keys())})

        @route("simple_intent", "/intent/flow/add", methods=["POST"])
        def add_flows(self, req, **kwargs):
            try:
                body = json.loads(req.body.decode("utf-8"))
            except Exception as exc:
                return _json_response({"ok": False, "error": f"请求体不是合法 JSON：{exc}"}, 400)

            flows = body.get("flows") or ([body] if body.get("match") else [])
            results = []
            for flow in flows:
                dpid = int(flow.get("dpid", SWITCH["dpid"]))
                dp = self.app.datapaths.get(dpid)
                if not dp:
                    results.append({"ok": False, "error": f"交换机 {dpid} 未连接控制器"})
                    continue
                try:
                    ofp = dp.ofproto
                    parser = dp.ofproto_parser
                    match = _ofp_match(parser, flow.get("match", {}))
                    actions = [
                        parser.OFPActionOutput(int(a["port"]))
                        for a in (flow.get("actions") or [])
                        if a.get("type") == "OUTPUT"
                    ]
                    mod = parser.OFPFlowMod(
                        datapath=dp,
                        match=match,
                        priority=int(flow.get("priority", PRIORITY_DENY)),
                        command=ofp.OFPFC_ADD,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                        actions=actions,
                    )
                    dp.send_msg(mod)
                    results.append({"ok": True})
                except Exception as exc:
                    results.append({"ok": False, "error": str(exc)})
            ok = all(r["ok"] for r in results) if results else False
            return _json_response({"ok": ok, "results": results})

        @route("simple_intent", "/intent/flow/delete", methods=["POST"])
        def delete_flows(self, req, **kwargs):
            try:
                body = json.loads(req.body.decode("utf-8"))
            except Exception as exc:
                return _json_response({"ok": False, "error": f"请求体不是合法 JSON：{exc}"}, 400)

            rules = body.get("rules") or []
            results = []
            for rule in rules:
                dpid = int(rule.get("dpid", SWITCH["dpid"]))
                dp = self.app.datapaths.get(dpid)
                if not dp:
                    results.append({"ok": False, "error": f"交换机 {dpid} 未连接控制器"})
                    continue
                try:
                    ofp = dp.ofproto
                    parser = dp.ofproto_parser
                    strict = bool(rule.get("strict", True))
                    mod = parser.OFPFlowMod(
                        datapath=dp,
                        match=_ofp_match(parser, rule.get("match", {})),
                        priority=int(rule.get("priority", PRIORITY_DENY)) if strict else 0,
                        command=ofp.OFPFC_DELETE_STRICT if strict else ofp.OFPFC_DELETE,
                        out_port=ofp.OFPP_ANY,
                        out_group=ofp.OFPG_ANY,
                    )
                    dp.send_msg(mod)
                    results.append({"ok": True})
                except Exception as exc:
                    results.append({"ok": False, "error": str(exc)})
            ok = all(r["ok"] for r in results) if results else False
            return _json_response({"ok": ok, "results": results})

        @route("simple_intent", "/intent/flow/clear", methods=["POST"])
        def clear_flows(self, req, **kwargs):
            try:
                body = json.loads(req.body.decode("utf-8"))
            except Exception:
                body = {}
            dpid = int(body.get("dpid", SWITCH["dpid"]))
            dp = self.app.datapaths.get(dpid)
            if not dp:
                return _json_response({"ok": False, "error": f"交换机 {dpid} 未连接控制器"}, 404)
            try:
                ofp = dp.ofproto
                parser = dp.ofproto_parser
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    match=_ofp_match(parser, body.get("match") or {"eth_type": 0x0800}),
                    priority=0,
                    command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY,
                    out_group=ofp.OFPG_ANY,
                )
                dp.send_msg(mod)
            except Exception as exc:
                return _json_response({"ok": False, "error": str(exc)}, 500)
            return _json_response({"ok": True, "deleted": -1})

        @route("simple_intent", "/intent/flows/{dpid}", methods=["GET"])
        def list_flows(self, req, dpid, **kwargs):
            dp = self.app.datapaths.get(int(dpid))
            if not dp:
                return _json_response({"ok": False, "error": f"交换机 {dpid} 未连接控制器"}, 404)
            flows = self.app.request_flows(dp)
            return _json_response({"ok": True, "flows": flows})

        @route("simple_intent", "/intent/topology", methods=["GET"])
        def topology(self, req, **kwargs):
            switches = []
            for dpid, dp in self.app.datapaths.items():
                ports = []
                for port in sorted(dp.ports.values(), key=lambda p: p.port_no):
                    if port.port_no > 0xFF00:
                        continue
                    ports.append(
                        {
                            "port_no": port.port_no,
                            "name": port.name,
                            "hw_addr": str(port.hw_addr),
                            "live": not (port.state & 1),
                        }
                    )
                switches.append(
                    {
                        "dpid": dpid,
                        "ports": ports,
                        "mac_table": dict(self.app.mac_to_port.get(dpid, {})),
                    }
                )
            return _json_response({"ok": True, "switches": switches})

    class SimpleIntentController(ryu_app_manager.RyuApp):
        """学习交换 + 供 Web 端调用的 REST 接口。"""

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
        _CONTEXTS = {"wsgi": WSGIApplication}

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.mac_to_port: dict[int, dict[str, int]] = {}
            self.datapaths: dict[int, Any] = {}
            self._waiters: dict[int, threading.Event] = {}
            self._flow_cache: dict[int, list[dict]] = {}
            kwargs["wsgi"].register(IntentRest, {"controller_app": self})

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            dp = ev.msg.datapath
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            self.datapaths[dp.id] = dp
            self.mac_to_port.setdefault(dp.id, {})
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self.add_flow(dp, 0, match, actions)

        @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
        def port_status_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            port = msg.desc
            self.logger.info("端口状态变化 %s:%s state=%s", dp.id, port.port_no, port.state)

        @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
        def state_change_handler(self, ev):
            dp = ev.datapath
            if ev.state == MAIN_DISPATCHER:
                self.datapaths[dp.id] = dp
            elif ev.state == DEAD_DISPATCHER:
                self.datapaths.pop(dp.id, None)

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in_handler(self, ev):
            msg = ev.msg
            dp = msg.datapath
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            dpid = dp.id
            in_port = msg.match["in_port"]

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            if eth is None:
                return
            dst, src = eth.dst, eth.src
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofp.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(dp, 10, match, actions)
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=data
            )
            dp.send_msg(out)

        def add_flow(self, dp, priority, match, actions):
            ofp = dp.ofproto
            parser = dp.ofproto_parser
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=priority, match=match,
                instructions=inst, command=ofp.OFPFC_ADD,
            )
            dp.send_msg(mod)

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            dpid = ev.msg.datapath.id
            self._flow_cache[dpid] = [_flow_to_json(f) for f in ev.msg.body]
            waiter = self._waiters.get(dpid)
            if waiter:
                waiter.set()

        def request_flows(self, dp, timeout: float = 2.0) -> list[dict]:
            waiter = threading.Event()
            self._waiters[dp.id] = waiter
            dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            waiter.wait(timeout)
            self._waiters.pop(dp.id, None)
            return self._flow_cache.get(dp.id, [])


# ==========================================================================
# 角色二：Mininet 实验网络（Python 内起 HTTP 服务，提供 ping / 拓扑）
# ==========================================================================

def run_lab(net_port: int = 8081, controller_addr: str = "127.0.0.1:6653", with_cli: bool = True):
    try:
        from mininet.cli import CLI
        from mininet.log import info, setLogLevel
        from mininet.net import Mininet
        from mininet.node import OVSKernelSwitch, RemoteController
        from mininet.topo import Topo
    except ImportError as exc:
        print(f"[!] 需要先安装 mininet：{exc}")
        print("    sudo apt install mininet   # 或 pip install mininet")
        return 1

    setLogLevel("info")
    host_ip, controller_port = controller_addr.split(":")
    controller_port = int(controller_port)

    class StarTopo(Topo):
        def build(self):
            switch = self.addSwitch(
                SWITCH["name"],
                dpid=f"{SWITCH['dpid']:016x}",
                protocols="OpenFlow13",
            )
            for host in HOSTS:
                node = self.addHost(host["name"], ip=f"{host['ip']}/24")
                self.addLink(node, switch, port2=host["port"])

    net = Mininet(
        topo=StarTopo(),
        switch=OVSKernelSwitch,
        controller=None,
        ipBase=TOPOLOGY.get("subnet", "10.0.0.0/24"),
        build=False,
    )
    net.addController("c0", controller=RemoteController, ip=host_ip, port=controller_port)
    net.build()
    net.start()

    def find(name: str):
        return net.get(name)

    class NetHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, payload: dict, code: int = 200):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/status":
                self._send({
                    "ok": True,
                    "hosts": [{"name": h.name, "ip": h.IP(), "mac": h.MAC()} for h in net.hosts],
                    "links": [{"src": h["name"], "dst": SWITCH["name"]} for h in HOSTS],
                })
                return
            if parsed.path == "/ping":
                query = parse_qs(parsed.query)
                src, dst = query.get("src", [""])[0], query.get("dst", [""])[0]
                if src not in HOST_BY_NAME or dst not in HOST_BY_NAME:
                    self._send({"ok": False, "error": "主机不存在"}, 400)
                    return
                try:
                    s, d = find(src), find(dst)
                    out = s.cmd(f"ping -c 3 -W 1 {d.IP()}")
                    loss_m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
                    loss = float(loss_m.group(1)) if loss_m else 100.0
                    rtt_m = re.search(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/", out)
                    rtt = round(float(rtt_m.group(2)), 3) if rtt_m else None
                    ok = loss == 0
                    self._send({
                        "ok": ok,
                        "loss": loss,
                        "rtt": rtt,
                        "blocked": not ok,
                        "message": "连通" if ok else "ICMP 无法到达（可能被流表丢弃）",
                    })
                except Exception as exc:
                    self._send({"ok": False, "error": str(exc)}, 500)
                return
            self._send({"ok": False, "error": "not found"}, 404)

    server = ThreadingHTTPServer(("0.0.0.0", net_port), NetHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    info(f"\n*** Mininet 已启动，网络服务 http://127.0.0.1:{net_port}\n")
    info(f"*** 拓扑：{SWITCH['name']} + {', '.join(h['name'] for h in HOSTS)}\n")
    info("*** 在另一个终端运行： python simple_intent.py app\n")

    try:
        if with_cli:
            CLI(net)
    finally:
        server.shutdown()
        net.stop()
    return 0


# ==========================================================================
# 角色三：自检
# ==========================================================================

def selftest() -> int:
    cases = [
        "禁止主机A访问服务器B",
        "隔离主机C",
        "放行主机A访问服务器B",
        "解除主机C的隔离",
        "禁止主机A访问主机B的80端口",
        "把主机D隔离掉",
        "允许主机B访问主机A",
    ]
    failed = 0
    print("=" * 78)
    print(" Simple-Intent 自检（规则解析 + 流表生成）")
    print("=" * 78)
    for text in cases:
        parsed = parse_intent(text)
        print(f"\n▶ 指令：{text}")
        if not parsed["intent"]:
            print(f"  ✗ 解析失败：{parsed['error']}")
            failed += 1
            continue
        error = validate(parsed["intent"])
        if error:
            print(f"  ✗ 校验失败：{error}")
            failed += 1
            continue
        plan = build(parsed["intent"])
        print(f"  意图：{json.dumps(parsed['intent'], ensure_ascii=False)}")
        print(f"  结果：{plan['summary']}")
        for flow in plan["flows"]:
            print(f"  + 下发：{json.dumps(flow, ensure_ascii=False)}")
        for rule in plan["deletes"]:
            print(f"  - 删除：{json.dumps(rule, ensure_ascii=False)}")

    backend = MockBackend()
    plan = build(validate_or_intent("禁止主机A访问服务器B"))
    backend.add(plan["flows"])
    ping_blocked = backend.ping("h1", "h2")
    ping_free = backend.ping("h1", "h3")
    print("\n" + "-" * 78)
    print(f"仿真验证：h1→h2 {ping_blocked['message']}（ok={ping_blocked['ok']}）")
    print(f"仿真验证：h1→h3 {ping_free['message']}（ok={ping_free['ok']}）")
    if ping_blocked["ok"] or not ping_free["ok"]:
        failed += 1
    print(f"\n自检结果：{'全部通过' if not failed else str(failed) + ' 项失败'}")
    return 0 if not failed else 1


def validate_or_intent(text: str) -> dict:
    parsed = parse_intent(text)
    assert parsed["intent"], parsed["error"]
    assert not validate(parsed["intent"]), validate(parsed["intent"])
    return parsed["intent"]


# ==========================================================================
# 入口
# ==========================================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Simple-Intent 意图驱动 SDN 访问控制系统")
    parser.add_argument("role", nargs="?", default="app",
                        choices=["app", "controller", "lab", "selftest"],
                        help="app=Web 控制台；controller=Ryu 控制器；lab=Mininet 网络；selftest=自检")
    parser.add_argument("--host", default="127.0.0.1", help="Web 监听地址")
    parser.add_argument("--port", type=int, default=8000, help="Web 端口")
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--net-port", type=int, default=8081, help="Mininet 网络服务端口")
    parser.add_argument("--controller", default="127.0.0.1:6653", help="Ryu 控制器地址 ip:port")
    parser.add_argument("--no-cli", action="store_true", help="lab 模式不进入 mininet CLI")
    args = parser.parse_args(argv)

    if args.role == "app":
        import uvicorn

        app = create_app()
        if not args.no_open:
            threading.Timer(1.2, lambda: webbrowser.open(f"http://{args.host}:{args.port}")).start()
        print(f"[*] Simple-Intent 控制台： http://{args.host}:{args.port}")
        print(f"[*] 模式：{MODE}（auto 时会自动探测 {CONTROLLER_URL}）")
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        return 0

    if args.role == "controller":
        if not HAS_RYU:
            print("[!] 未安装 ryu：pip install ryu（Linux / WSL 环境）")
            return 1
        exe = shutil.which("ryu-manager")
        cmd = [exe] if exe else [sys.executable, "-m", "ryu.cmd.manager"]
        cmd += ["--observe-links", __file__]
        print("[*] 启动 Ryu 控制器：", " ".join(cmd))
        return subprocess.call(cmd)

    if args.role == "lab":
        return run_lab(args.net_port, args.controller, not args.no_cli)

    return selftest()


if __name__ == "__main__":
    raise SystemExit(main())
