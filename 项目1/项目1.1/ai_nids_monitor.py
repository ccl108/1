from __future__ import annotations

import csv
import json
import random
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, jsonify, redirect, render_template_string, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# 创建 Flask 应用，并通过内嵌 HTML 提供登录页和监控页面。
app = Flask(__name__)

# 系统默认配置；运行时可通过页面的“应用建议阈值”修改。
CONFIG = {
    'port': 5000,
    'refresh_interval': 2000,
    'ddos_threshold': 500,
    'port_scan_threshold': 50,
    'syn_flood_threshold': 100,
    'udp_flood_threshold': 200,
}
CONFIG_FILE = Path("nids_config.json")

# 启动时读取上次保存的配置。单个配置项读取失败时仍使用默认值。
if CONFIG_FILE.exists():
    try:
        saved_config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        for key in CONFIG:
            if key in saved_config:
                CONFIG[key] = int(saved_config[key])
    except (OSError, ValueError, TypeError):
        pass

# 账号保存在独立文件中，避免和数值配置混在一起。
USERS_FILE = Path("nids_users.json")
SECRET_FILE = Path(".nids_secret")
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"


def _save_users(users):
    USERS_FILE.write_text(
        json.dumps({"users": users}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _load_users():
    """读取账号文件；首次运行或文件损坏时创建默认管理员账号。"""
    if USERS_FILE.exists():
        try:
            payload = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            users = payload.get("users")
            if (isinstance(users, list) and users
                    and all(isinstance(item.get("username"), str)
                            and isinstance(item.get("password_hash"), str)
                            for item in users)):
                return users
        except (OSError, ValueError, TypeError):
            pass
    users = [{
        "username": DEFAULT_USERNAME,
        "password_hash": generate_password_hash(DEFAULT_PASSWORD),
    }]
    _save_users(users)
    print(f"[AI-NIDS] 已创建默认账号: {DEFAULT_USERNAME} / {DEFAULT_PASSWORD}")
    print("[AI-NIDS] 如需新增账号，请编辑 nids_users.json（密码需为加盐哈希）")
    return users


USERS = _load_users()


def _load_secret_key():
    """持久化 Flask 会话密钥，重启后已登录的会话仍然有效。"""
    try:
        if SECRET_FILE.exists():
            value = SECRET_FILE.read_text(encoding="utf-8").strip()
            if value:
                return value
        value = secrets.token_hex(32)
        SECRET_FILE.write_text(value, encoding="utf-8")
        return value
    except OSError:
        return secrets.token_hex(32)


app.secret_key = _load_secret_key()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

traffic_data = {
    # traffic_data 保存当前页面需要展示的实时统计信息。
    'qps': 200,
    'connections': 80,
    'alert': None,
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'packet_count': 0,
    'unique_ports': set(),
    'src_ips': set(),
    'src_ip_counts': {},
    'syn_packets': 0,
    'udp_packets': 0,
    'dns_packets': 0,
}

alert_history = []
traffic_history = []

# 保存最近一段时间的统计数据，供 CSV 导出使用。
OUTPUT_CSV = Path("traffic_data.csv")
# 抓包线程和 Flask 请求线程会同时访问共享状态，统一使用该锁保护。
STATE_LOCK = threading.Lock()
CAPTURE_STATE = {
    'mode': 'idle',
    'running': False,
    'interface': None,
    'error': None,
}
CAPTURE_THREAD = None
CAPTURE_SNIFFER = None
CAPTURE_STOP_EVENT = threading.Event()
CAPTURE_TIMES = deque()
CAPTURE_SYN_TIMES = deque()
CAPTURE_UDP_TIMES = deque()
CAPTURE_PORT_TIMES = deque()
# 端口扫描、SYN 洪水和 UDP 洪水均在最近 10 秒内进行统计。
PORT_SCAN_WINDOW_SECONDS = 10

# 建议阈值基于最近的指标采样点计算，因此需要先积累一定样本。
METRIC_SAMPLES = deque(maxlen=90)
SUGGESTION_MIN_SAMPLES = 10


def _record_src_ip(ip, count=1):
    """累计每个来源 IP 的包数，并限制条目数量，避免字典无限增长。

    调用方必须已经持有 STATE_LOCK。
    """
    counts = traffic_data['src_ip_counts']
    counts[ip] = counts.get(ip, 0) + count
    overflow = len(counts) - 300
    if overflow > 0:
        for old_ip, _ in sorted(counts.items(), key=lambda item: item[1])[:overflow]:
            counts.pop(old_ip, None)


def _percentile(values, ratio):
    """返回给定分位的数值，用于估算建议阈值。"""
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1,
                       int(round((len(ordered) - 1) * ratio))))
    return ordered[index]


def _quantize(value, minimum, step):
    """把建议值取整到便于阅读的刻度，并保证不低于最小值。"""
    return max(minimum, int(step * round(value / step)))


def build_suggestions():
    """根据最近采样计算建议阈值，不直接修改正在生效的阈值。"""
    with STATE_LOCK:
        samples = list(METRIC_SAMPLES)
    current = {
        'ddos_threshold': CONFIG['ddos_threshold'],
        'port_scan_threshold': CONFIG['port_scan_threshold'],
        'syn_flood_threshold': CONFIG['syn_flood_threshold'],
        'udp_flood_threshold': CONFIG['udp_flood_threshold'],
    }
    sample_count = len(samples)
    window_seconds = sample_count * max(1, CONFIG['refresh_interval'] // 1000)
    if sample_count < SUGGESTION_MIN_SAMPLES:
        return {
            'ready': False,
            'sample_count': sample_count,
            'min_samples': SUGGESTION_MIN_SAMPLES,
            'window_seconds': window_seconds,
            'window_seconds_unit': '秒',
            'current': current,
            'suggested': current,
            'basis': '采样数据不足，暂不给出建议值',
        }
    suggested = {
        'ddos_threshold': _quantize(
            _percentile([item['qps'] for item in samples], 0.95) * 1.2, 50, 10),
        'port_scan_threshold': _quantize(
            _percentile([item['port_count'] for item in samples], 0.95) * 1.2, 20, 5),
        'syn_flood_threshold': _quantize(
            _percentile([item['syn_packets'] for item in samples], 0.95) * 1.2, 20, 5),
        'udp_flood_threshold': _quantize(
            _percentile([item['udp_packets'] for item in samples], 0.95) * 1.2, 20, 5),
    }
    return {
        'ready': True,
        'sample_count': sample_count,
        'min_samples': SUGGESTION_MIN_SAMPLES,
        'window_seconds': window_seconds,
        'window_seconds_unit': '秒',
        'current': current,
        'suggested': suggested,
        'basis': f'基于最近 {sample_count} 个采样点（约 {window_seconds} 秒）的 95 分位 × 1.2 估算',
    }


class AnomalyDetector:
    """根据可配置阈值判断当前流量是否存在常见异常。"""

    def __init__(self, ddos_threshold=500, port_scan_threshold=50,
                 syn_flood_threshold=100, udp_flood_threshold=200):
        self.ddos_threshold = ddos_threshold
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.udp_flood_threshold = udp_flood_threshold

    def check_ddos(self, packet_count_per_second):
        # QPS 使用最近 1 秒内捕获的数据包数量计算。
        if packet_count_per_second > self.ddos_threshold:
            return True, f"检测到疑似 DDoS 攻击 (QPS: {packet_count_per_second})"
        return False, ""

    def check_port_scan(self, unique_ports_accessed):
        # 端口数量来自最近 10 秒内出现的 TCP/UDP 目的端口集合。
        if len(unique_ports_accessed) > self.port_scan_threshold:
            return True, f"检测到疑似端口扫描行为 (访问端口数: {len(unique_ports_accessed)})"
        return False, ""

    def check_syn_flood(self, syn_count):
        if syn_count > self.syn_flood_threshold:
            return True, f"检测到疑似 TCP SYN 洪水攻击 (SYN包: {syn_count})"
        return False, ""

    def check_udp_flood(self, udp_count):
        if udp_count > self.udp_flood_threshold:
            return True, f"检测到疑似 UDP 洪水攻击 (UDP包: {udp_count})"
        return False, ""


detector = AnomalyDetector(
    ddos_threshold=CONFIG['ddos_threshold'],
    port_scan_threshold=CONFIG['port_scan_threshold'],
    syn_flood_threshold=CONFIG['syn_flood_threshold'],
    udp_flood_threshold=CONFIG['udp_flood_threshold']
)


def update_traffic_data():
    """生成一组模拟流量数据，用于未接入真实网卡时演示界面。"""
    global traffic_data

    qps = random.randint(100, 800)
    connections = random.randint(50, 200)
    syn_count = random.randint(0, 150)
    udp_count = random.randint(0, 250)
    dns_count = random.randint(0, 50)

    # 模拟模式直接更新统计字段；真实抓包模式由 process_packet 更新。
    with STATE_LOCK:
        traffic_data['qps'] = qps
        traffic_data['connections'] = connections
        traffic_data['packet_count'] += random.randint(10, 50)
        traffic_data['unique_ports'].add(random.randint(1, 65535))
        traffic_data['unique_ports'].add(random.randint(1, 65535))
        # 每次模拟都随机产生几个来源 IP，便于演示 IP 明细面板。
        for _ in range(random.randint(2, 5)):
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            traffic_data['src_ips'].add(ip)
            _record_src_ip(ip, random.randint(1, 20))
        traffic_data['syn_packets'] = syn_count
        traffic_data['udp_packets'] = udp_count
        traffic_data['dns_packets'] = dns_count
        traffic_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 对模拟数据执行与真实抓包相同的检测规则，保证两种模式展示一致。
    alerts = []
    is_ddos, ddos_msg = detector.check_ddos(qps)
    is_scan, scan_msg = detector.check_port_scan(traffic_data['unique_ports'])
    is_syn_flood, syn_msg = detector.check_syn_flood(syn_count)
    is_udp_flood, udp_msg = detector.check_udp_flood(udp_count)

    if is_ddos:
        alerts.append(ddos_msg)
    if is_scan:
        alerts.append(scan_msg)
    if is_syn_flood:
        alerts.append(syn_msg)
    if is_udp_flood:
        alerts.append(udp_msg)

    with STATE_LOCK:
        if alerts:
            traffic_data['alert'] = " ⚠️ ".join(alerts)
        else:
            traffic_data['alert'] = None

        if alerts:
            alert_entry = {
                'time': traffic_data['timestamp'],
                'message': traffic_data['alert']
            }
            alert_history.insert(0, alert_entry)
            if len(alert_history) > 50:
                alert_history.pop()

        # 模拟模式没有 10 秒端口窗口，用随机窗口值近似，供建议阈值采样。
        METRIC_SAMPLES.append({
            'qps': qps,
            'port_count': random.randint(10, 90),
            'syn_packets': syn_count,
            'udp_packets': udp_count,
        })

        history_entry = {
            'time': traffic_data['timestamp'],
            'qps': qps,
            'connections': connections,
            'packet_count': traffic_data['packet_count'],
            'port_count': len(traffic_data['unique_ports']),
            'src_ip_count': len(traffic_data['src_ips']),
            'alert': traffic_data['alert']
        }
        traffic_history.append(history_entry)
        if len(traffic_history) > 60:
            traffic_history.pop(0)


def process_packet(packet):
    """只记录数据包元信息，不保留数据包载荷。"""
    global traffic_data
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.dns import DNS
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        with STATE_LOCK:
            if CAPTURE_STATE['mode'] != 'capture' or not CAPTURE_STATE['running']:
                return
            # 使用单调时钟计算时间窗口，避免系统时间调整影响统计结果。
            now = time.monotonic()
            # 清理窗口外的数据，使 QPS 和洪水检测只反映最近一段时间。
            CAPTURE_TIMES.append(now)
            while CAPTURE_TIMES and CAPTURE_TIMES[0] < now - 1:
                CAPTURE_TIMES.popleft()
            while CAPTURE_SYN_TIMES and CAPTURE_SYN_TIMES[0] < now - PORT_SCAN_WINDOW_SECONDS:
                CAPTURE_SYN_TIMES.popleft()
            while CAPTURE_UDP_TIMES and CAPTURE_UDP_TIMES[0] < now - PORT_SCAN_WINDOW_SECONDS:
                CAPTURE_UDP_TIMES.popleft()
            while CAPTURE_PORT_TIMES and CAPTURE_PORT_TIMES[0][0] < now - PORT_SCAN_WINDOW_SECONDS:
                CAPTURE_PORT_TIMES.popleft()
            # 仅提取协议、地址和端口等元数据，不读取业务内容。
            traffic_data['packet_count'] += 1
            traffic_data['src_ips'].add(ip.src)
            _record_src_ip(ip.src)
            if packet.haslayer(TCP):
                port = int(packet[TCP].dport)
                traffic_data['unique_ports'].add(port)
                if packet[TCP].flags & 0x02:
                    CAPTURE_SYN_TIMES.append(now)
                    CAPTURE_PORT_TIMES.append((now, port))
            if packet.haslayer(UDP):
                port = int(packet[UDP].dport)
                traffic_data['unique_ports'].add(port)
                CAPTURE_UDP_TIMES.append(now)
            if packet.haslayer(DNS):
                traffic_data['dns_packets'] += 1
            traffic_data['connections'] = len(traffic_data['src_ips'])
            traffic_data['qps'] = len(CAPTURE_TIMES)
            # 页面展示最近 10 秒窗口内的 SYN / UDP 包数，与检测口径保持一致。
            traffic_data['syn_packets'] = len(CAPTURE_SYN_TIMES)
            traffic_data['udp_packets'] = len(CAPTURE_UDP_TIMES)
            # 每个数据包到达时重新计算检测结果，确保页面能及时显示告警。
            checks = [
                detector.check_ddos(traffic_data['qps']),
                detector.check_port_scan({port for _, port in CAPTURE_PORT_TIMES}),
                detector.check_syn_flood(len(CAPTURE_SYN_TIMES)),
                detector.check_udp_flood(len(CAPTURE_UDP_TIMES)),
            ]
            messages = [message for matched, message in checks if matched]
            traffic_data['alert'] = " ⚠️ ".join(messages) if messages else None
            traffic_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if messages:
                alert_history.insert(0, {'time': traffic_data['timestamp'],
                                         'message': traffic_data['alert']})
                del alert_history[50:]
    except (AttributeError, TypeError, ValueError):
        return


def capture_worker(interface):
    """在后台线程中运行 Scapy 捕获器，避免阻塞 Flask 主线程。"""
    global CAPTURE_SNIFFER
    try:
        from scapy.all import AsyncSniffer
        from scapy.error import Scapy_Exception

        # store=False 可避免持续保存原始数据包，降低内存占用并减少敏感数据留存。
        sniffer = AsyncSniffer(
            iface=interface or None,
            prn=process_packet,
            store=False,
        )
        with STATE_LOCK:
            CAPTURE_SNIFFER = sniffer
        sniffer.start()
        # 主线程调用 stop_capture 时设置事件，后台线程随后停止抓包。
        CAPTURE_STOP_EVENT.wait()
        if sniffer.running:
            sniffer.stop(join=True)
    except ImportError:
        with STATE_LOCK:
            CAPTURE_STATE['error'] = '未安装 scapy。请运行: python -m pip install -r requirements.txt'
    except (OSError, RuntimeError, Scapy_Exception) as exc:
        message = str(exc)
        if 'winpcap is not installed' in message.lower():
            message = 'Windows 未安装 Npcap/WinPcap。请安装 Npcap 并启用 WinPcap-compatible mode'
        with STATE_LOCK:
            CAPTURE_STATE['error'] = f'网卡捕获失败: {message}'
    finally:
        with STATE_LOCK:
            CAPTURE_SNIFFER = None
            CAPTURE_STATE['running'] = False


def start_capture(interface=None):
    """清理旧状态并启动新的网卡捕获线程。"""
    global CAPTURE_THREAD
    stop_capture()
    with STATE_LOCK:
        CAPTURE_STATE.update({'mode': 'capture', 'running': True,
                              'interface': interface, 'error': None})
        CAPTURE_STOP_EVENT.clear()
        traffic_data['alert'] = None
        CAPTURE_TIMES.clear()
        CAPTURE_SYN_TIMES.clear()
        CAPTURE_UDP_TIMES.clear()
        CAPTURE_PORT_TIMES.clear()
        METRIC_SAMPLES.clear()
        alert_history.clear()
    CAPTURE_THREAD = threading.Thread(target=capture_worker, args=(interface,), daemon=True)
    CAPTURE_THREAD.start()


def stop_capture():
    """停止抓包器和后台线程，并将系统恢复到空闲状态。"""
    global CAPTURE_SNIFFER, CAPTURE_THREAD
    with STATE_LOCK:
        CAPTURE_STATE['mode'] = 'idle'
        CAPTURE_STATE['running'] = False
        traffic_data['alert'] = None
        CAPTURE_STOP_EVENT.set()
        sniffer = CAPTURE_SNIFFER
        capture_thread = CAPTURE_THREAD
    if sniffer is not None and sniffer.running:
        sniffer.stop(join=True)
    if (capture_thread is not None
            and capture_thread is not threading.current_thread()
            and capture_thread.is_alive()):
        capture_thread.join(timeout=2)


def save_traffic_data():
    """将内存中的历史统计记录覆盖写入 CSV 文件。"""
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "QPS", "Connections", "PacketCount", "PortCount", "SrcIPCount", "Alert"])
        for entry in traffic_history:
            writer.writerow([
                entry['time'],
                entry['qps'],
                entry['connections'],
                entry['packet_count'],
                entry['port_count'],
                entry['src_ip_count'],
                entry['alert'] if entry['alert'] else "Normal"
            ])


def login_required(view):
    """保护页面和接口；未登录的 API 请求返回 401。"""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'username' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'status': 'error', 'message': '未登录或会话已过期'}), 401
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def _safe_next(target):
    """只允许站内相对路径，避免开放重定向。"""
    if not target or not target.startswith('/') or target.startswith('//'):
        return None
    return target


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI-NIDS · 校园网加密流量入侵检测</title>
    <style>
        :root {
            --bg: #060a12;
            --panel: rgba(16, 24, 39, 0.82);
            --panel-soft: rgba(22, 32, 51, 0.68);
            --line: rgba(120, 170, 255, 0.14);
            --text: #e8f0ff;
            --muted: #7f8da6;
            --prefix: #38d6c4;
            --accent: #5b8dff;
            --danger: #ff5f73;
            --ok: #3ee0a0;
            --radius: 16px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh;
            color: var(--text);
            font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
            background:
                radial-gradient(1100px 620px at 6% -12%, rgba(56, 214, 196, 0.13), transparent 60%),
                radial-gradient(960px 520px at 96% -6%, rgba(91, 141, 255, 0.16), transparent 55%),
                var(--bg);
            background-attachment: fixed;
        }
        .topbar {
            position: sticky;
            top: 0;
            z-index: 20;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            flex-wrap: wrap;
            padding: 16px 28px;
            border-bottom: 1px solid var(--line);
            background: rgba(7, 11, 20, 0.78);
            backdrop-filter: blur(16px);
        }
        .brand { display: flex; align-items: center; gap: 13px; }
        .brand-mark {
            width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center;
            font-weight: 800; font-size: 20px; color: #04130f;
            background: linear-gradient(135deg, var(--prefix), var(--accent));
            box-shadow: 0 8px 24px rgba(56, 214, 196, 0.26);
        }
        .brand h1 { font-size: 18px; letter-spacing: 0.4px; font-weight: 650; }
        .brand .sub { font-size: 10px; color: var(--muted); letter-spacing: 2.2px; margin-top: 2px; }
        .topbar-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
        .live-pill {
            display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px;
            border-radius: 999px; border: 1px solid var(--line);
            background: rgba(255, 255, 255, 0.04); font-size: 12px; color: #b7c4d8;
        }
        .live-dot {
            width: 8px; height: 8px; border-radius: 50%; background: #5f6c84;
            box-shadow: 0 0 0 3px rgba(95, 108, 132, 0.16);
        }
        .live-pill.running .live-dot {
            background: var(--ok); box-shadow: 0 0 0 3px rgba(62, 224, 160, 0.16);
            animation: pulse 1.6s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.55; transform: scale(0.9); }
        }
        .clock { font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }
        .user-chip { display: flex; align-items: center; gap: 10px; font-size: 12px; color: #c3cfe3; }
        .user-chip .avatar {
            width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center;
            background: rgba(91, 141, 255, 0.18); border: 1px solid rgba(91, 141, 255, 0.32);
            color: #b9ccff; font-weight: 700; text-transform: uppercase; font-size: 12px;
        }
        .logout {
            color: #93a2ba; text-decoration: none; font-size: 12px;
            padding: 6px 10px; border-radius: 8px; border: 1px solid var(--line);
            transition: 0.18s;
        }
        .logout:hover { color: #fff; border-color: rgba(255, 95, 115, 0.45); background: rgba(255, 95, 115, 0.08); }

        .layout {
            max-width: 1420px;
            margin: 0 auto;
            padding: 22px 28px 52px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .status-banner {
            display: flex; align-items: center; gap: 12px;
            padding: 13px 18px; border-radius: 14px;
            border: 1px solid rgba(62, 224, 160, 0.26);
            background: linear-gradient(90deg, rgba(62, 224, 160, 0.12), rgba(62, 224, 160, 0.03));
            color: #9af2cd; font-size: 13px;
        }
        .status-banner.danger {
            border-color: rgba(255, 95, 115, 0.36);
            background: linear-gradient(90deg, rgba(255, 95, 115, 0.15), rgba(255, 95, 115, 0.04));
            color: #ffbac4;
        }
        .status-icon {
            width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center;
            background: rgba(62, 224, 160, 0.16); font-size: 14px; flex: none;
        }
        .status-banner.danger .status-icon { background: rgba(255, 95, 115, 0.18); }

        .kpi-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }
        .kpi {
            position: relative; overflow: hidden; padding: 16px 18px;
            border-radius: var(--radius); border: 1px solid var(--line);
            background: linear-gradient(158deg, var(--panel-soft), rgba(10, 15, 26, 0.78));
            transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
        }
        .kpi::before {
            content: ""; position: absolute; top: 0; left: 0; width: 100%; height: 2px;
            background: linear-gradient(90deg, var(--prefix), rgba(91, 141, 255, 0.35), transparent 75%);
        }
        .kpi:hover {
            transform: translateY(-2px);
            border-color: rgba(56, 214, 196, 0.34);
            box-shadow: 0 16px 34px rgba(0, 0, 0, 0.32);
        }
        .kpi-label {
            display: flex; align-items: center; justify-content: space-between; gap: 8px;
            font-size: 12px; color: var(--muted); letter-spacing: 0.3px;
        }
        .kpi-label .hint { font-size: 10px; color: #5c6a82; }
        .kpi.clickable { cursor: pointer; }
        .kpi.clickable .hint { color: var(--prefix); }
        .kpi-value {
            margin-top: 8px; font-size: 32px; font-weight: 700; line-height: 1.15;
            font-variant-numeric: tabular-nums; letter-spacing: 0.3px;
        }
        .kpi-value .unit { font-size: 12px; font-weight: 500; color: var(--muted); margin-left: 6px; }
        .kpi-foot { margin-top: 6px; font-size: 11px; color: #5f6c84; }

        .panel {
            padding: 20px 22px; border-radius: 18px; border: 1px solid var(--line);
            background: var(--panel); backdrop-filter: blur(10px);
        }
        .panel-head {
            display: flex; align-items: center; justify-content: space-between;
            gap: 12px; flex-wrap: wrap; margin-bottom: 16px;
        }
        .panel-title { display: flex; align-items: center; gap: 9px; font-size: 15px; font-weight: 650; }
        .panel-title::before {
            content: ""; width: 4px; height: 16px; border-radius: 2px;
            background: linear-gradient(180deg, var(--prefix), var(--accent));
        }
        .panel-sub { font-size: 12px; color: var(--muted); }

        .chart-wrap { position: relative; height: 320px; }
        canvas { width: 100% !important; height: 100% !important; }
        .chart-fallback {
            display: grid; place-items: center; height: 100%;
            color: var(--muted); font-size: 13px; border: 1px dashed var(--line); border-radius: 12px;
        }

        .controls-grid { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr); gap: 22px; }
        .field { display: flex; flex-direction: column; gap: 6px; }
        .field label { font-size: 12px; color: var(--muted); }
        select {
            width: 100%; padding: 10px 12px; color: var(--text); font-size: 13px;
            background: #131c2d; border: 1px solid rgba(120, 170, 255, 0.22); border-radius: 10px;
            outline: none; transition: border-color 0.18s;
        }
        select:focus { border-color: rgba(56, 214, 196, 0.55); }
        .actions { display: grid; grid-template-columns: repeat(auto-fit, minmax(132px, 1fr)); gap: 10px; }
        .btn {
            padding: 11px 14px; border-radius: 10px; font-size: 13px; font-weight: 650;
            color: #dfe8f7; cursor: pointer; transition: 0.18s;
            background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.09);
        }
        .btn:hover { background: rgba(255, 255, 255, 0.09); border-color: rgba(120, 170, 255, 0.3); }
        .btn:disabled { opacity: 0.5; cursor: wait; }
        .btn.primary {
            color: #04130f; border-color: transparent;
            background: linear-gradient(135deg, #38d6c4, #5b8dff);
            box-shadow: 0 10px 24px rgba(56, 214, 196, 0.2);
        }
        .btn.primary:hover { filter: brightness(1.06); }
        .btn.danger { color: #ff9aa7; background: rgba(255, 95, 115, 0.1); border-color: rgba(255, 95, 115, 0.36); }
        .btn.danger:hover { background: rgba(255, 95, 115, 0.18); }
        .control-message {
            min-height: 34px; margin-top: 14px; padding: 9px 12px; border-radius: 10px;
            font-size: 12px; line-height: 1.5; color: #95a5bd;
            background: rgba(255, 255, 255, 0.03); border: 1px solid var(--line);
        }
        .control-message.error { color: #ffb3bd; border-color: rgba(255, 95, 115, 0.3); background: rgba(255, 95, 115, 0.08); }
        .control-message.success { color: #96f0cc; border-color: rgba(62, 224, 160, 0.3); background: rgba(62, 224, 160, 0.08); }

        .suggest-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .suggest-table th {
            padding: 7px 8px; text-align: left; font-size: 11px; font-weight: 600;
            color: var(--muted); letter-spacing: 0.4px; border-bottom: 1px solid var(--line);
        }
        .suggest-table td {
            padding: 10px 8px; border-bottom: 1px solid rgba(120, 170, 255, 0.07);
            color: #d3deee; font-variant-numeric: tabular-nums;
        }
        .suggest-table tr:last-child td { border-bottom: none; }
        .rule-unit { font-size: 11px; color: var(--muted); }
        .chip {
            display: inline-block; padding: 3px 9px; border-radius: 999px;
            background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .chip.suggested {
            color: #7ff0d9; background: rgba(56, 214, 196, 0.1);
            border-color: rgba(56, 214, 196, 0.3);
        }
        .suggest-footer {
            display: flex; align-items: center; justify-content: space-between;
            gap: 12px; flex-wrap: wrap; margin-top: 14px;
        }
        .suggest-info { font-size: 11px; color: var(--muted); line-height: 1.6; flex: 1 1 180px; }

        .alerts-list { display: flex; flex-direction: column; gap: 9px; max-height: 330px; overflow: auto; }
        .alert-item {
            display: flex; gap: 14px; padding: 12px 14px; border-radius: 12px;
            background: rgba(255, 95, 115, 0.07);
            border: 1px solid rgba(255, 95, 115, 0.18);
            border-left: 3px solid var(--danger);
        }
        .alert-time { flex: none; font-size: 11px; color: var(--muted); font-variant-numeric: tabular-nums; padding-top: 1px; }
        .alert-message { font-size: 13px; line-height: 1.55; color: #ffc7ce; }
        .empty {
            display: grid; place-items: center; min-height: 90px; padding: 22px;
            border: 1px dashed rgba(120, 170, 255, 0.18); border-radius: 12px;
            color: #6d7c94; font-size: 13px;
        }

        .modal {
            position: fixed; inset: 0; z-index: 60; display: none;
            align-items: center; justify-content: center; padding: 24px;
            background: rgba(3, 6, 12, 0.72); backdrop-filter: blur(6px);
        }
        .modal.open { display: flex; }
        .modal-card {
            width: min(660px, 100%); max-height: 82vh; display: flex; flex-direction: column;
            border-radius: 18px; border: 1px solid rgba(120, 170, 255, 0.22);
            background: #0c1322; box-shadow: 0 32px 90px rgba(0, 0, 0, 0.6);
        }
        .modal-head {
            display: flex; align-items: center; justify-content: space-between;
            padding: 17px 22px; border-bottom: 1px solid var(--line);
        }
        .modal-head h2 { font-size: 15px; font-weight: 650; }
        .modal-head .modal-sub { font-size: 11px; color: var(--muted); margin-top: 3px; }
        .icon-btn {
            width: 32px; height: 32px; border-radius: 9px; cursor: pointer;
            color: #a9b7cd; font-size: 18px; line-height: 1;
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--line);
        }
        .icon-btn:hover { background: rgba(255, 255, 255, 0.1); color: #fff; }
        .modal-body { padding: 18px 22px 22px; overflow: auto; }
        .ip-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .ip-table th {
            text-align: left; padding: 7px 8px; font-size: 11px; color: var(--muted);
            border-bottom: 1px solid var(--line); font-weight: 600;
        }
        .ip-table td { padding: 9px 8px; border-bottom: 1px solid rgba(120, 170, 255, 0.06); }
        .ip-table td.mono { font-family: Consolas, "Courier New", monospace; font-size: 12px; color: #c9dcff; }
        .ip-table td.count { text-align: right; font-variant-numeric: tabular-nums; }
        .bar-cell { width: 34%; }
        .ip-bar { height: 6px; border-radius: 3px; background: rgba(120, 170, 255, 0.1); overflow: hidden; }
        .ip-bar > span {
            display: block; height: 100%; border-radius: 3px;
            background: linear-gradient(90deg, var(--prefix), var(--accent));
        }
        .modal-empty { padding: 26px; text-align: center; color: #6d7c94; font-size: 13px; }

        @media (max-width: 1080px) {
            .kpi-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            .controls-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 760px) {
            .topbar { padding: 14px 18px; }
            .layout { padding: 18px 18px 40px; }
            .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .kpi-value { font-size: 27px; }
            .brand h1 { font-size: 16px; }
            .brand .sub { display: none; }
        }
        @media (max-width: 460px) {
            .kpi-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <header class="topbar">
        <div class="brand">
            <div class="brand-mark">N</div>
            <div>
                <h1>AI-NIDS 校园网流量监控</h1>
                <div class="sub">Encrypted Traffic Intrusion Detection</div>
            </div>
        </div>
        <div class="topbar-right">
            <div class="live-pill" id="livePill">
                <span class="live-dot"></span><span id="liveText">未运行</span>
            </div>
            <div class="clock">最后更新 <span id="updateTime">--</span></div>
            <div class="user-chip">
                <span class="avatar">{{ username|e }}</span>
                <span>{{ username|e }}</span>
                <a class="logout" href="/logout">退出</a>
            </div>
        </div>
    </header>

    <main class="layout">
        <div class="status-banner" id="statusBanner">
            <span class="status-icon" id="statusIcon">✓</span>
            <span id="statusText">当前网络状态正常，未检测到异常流量</span>
        </div>

        <section class="kpi-grid">
            <div class="kpi">
                <div class="kpi-label">QPS<span class="hint">每秒请求数</span></div>
                <div class="kpi-value" id="qps">--<span class="unit">次/秒</span></div>
                <div class="kpi-foot">最近 1 秒窗口</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">活跃连接<span class="hint">按来源 IP 统计</span></div>
                <div class="kpi-value" id="connections">--<span class="unit">个</span></div>
                <div class="kpi-foot">观测到的源 IP 数量</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">累计数据包<span class="hint">进程运行期间</span></div>
                <div class="kpi-value" id="packetCount">--<span class="unit">包</span></div>
                <div class="kpi-foot">仅统计元数据，不保存载荷</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">访问端口<span class="hint">累计去重</span></div>
                <div class="kpi-value" id="portCount">--<span class="unit">个</span></div>
                <div class="kpi-foot">TCP / UDP 目的端口</div>
            </div>
            <div class="kpi clickable" id="srcIpCard" title="点击查看来源 IP 明细">
                <div class="kpi-label">来源 IP<span class="hint">查看明细 ›</span></div>
                <div class="kpi-value" id="srcIpCount">--<span class="unit">个</span></div>
                <div class="kpi-foot">按捕获包数排序</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">TCP SYN 包<span class="hint">10 秒窗口</span></div>
                <div class="kpi-value" id="synPackets">--<span class="unit">包</span></div>
                <div class="kpi-foot">仅统计 SYN 标志位</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">UDP 包<span class="hint">10 秒窗口</span></div>
                <div class="kpi-value" id="udpPackets">--<span class="unit">包</span></div>
                <div class="kpi-foot">含 DNS 查询流量</div>
            </div>
            <div class="kpi">
                <div class="kpi-label">DNS 包<span class="hint">累计</span></div>
                <div class="kpi-value" id="dnsPackets">--<span class="unit">包</span></div>
                <div class="kpi-foot">仅统计 DNS 层出现次数</div>
            </div>
        </section>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">QPS 实时趋势</div>
                <div class="panel-sub">横轴：时间（时:分:秒）　纵轴：QPS（次/秒）　仅保留最近 30 个点</div>
            </div>
            <div class="chart-wrap">
                <canvas id="qpsChart"></canvas>
            </div>
        </section>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">检测控制与建议阈值</div>
                <div class="panel-sub">建议值随采样自动更新，应用后立即生效并写入 nids_config.json</div>
            </div>
            <div class="controls-grid">
                <div>
                    <div class="field">
                        <label for="interfaceSelect">捕获网卡</label>
                        <select id="interfaceSelect">
                            <option value="">系统默认网卡（由 Scapy 自动选择）</option>
                        </select>
                    </div>
                    <div class="actions" style="margin-top: 14px;">
                        <button class="btn primary" id="startCapture">开始网卡捕获</button>
                        <button class="btn" id="startSimulation">开始模拟流量</button>
                        <button class="btn danger" id="stopCapture">停止</button>
                    </div>
                    <div class="control-message" id="controlMessage">正在加载网卡与配置...</div>
                </div>
                <div>
                    <table class="suggest-table">
                        <thead>
                            <tr>
                                <th>检测规则</th>
                                <th>当前阈值</th>
                                <th>建议阈值</th>
                                <th>单位</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>疑似 DDoS</td>
                                <td><span class="chip" id="curDdos">--</span></td>
                                <td><span class="chip suggested" id="sugDdos">--</span></td>
                                <td class="rule-unit">次/秒</td>
                            </tr>
                            <tr>
                                <td>疑似端口扫描</td>
                                <td><span class="chip" id="curPort">--</span></td>
                                <td><span class="chip suggested" id="sugPort">--</span></td>
                                <td class="rule-unit">个端口 / 10 秒</td>
                            </tr>
                            <tr>
                                <td>疑似 TCP SYN 洪水</td>
                                <td><span class="chip" id="curSyn">--</span></td>
                                <td><span class="chip suggested" id="sugSyn">--</span></td>
                                <td class="rule-unit">个 SYN 包 / 10 秒</td>
                            </tr>
                            <tr>
                                <td>疑似 UDP 洪水</td>
                                <td><span class="chip" id="curUdp">--</span></td>
                                <td><span class="chip suggested" id="sugUdp">--</span></td>
                                <td class="rule-unit">个 UDP 包 / 10 秒</td>
                            </tr>
                        </tbody>
                    </table>
                    <div class="suggest-footer">
                        <div class="suggest-info" id="suggestInfo">正在采集最近流量采样...</div>
                        <button class="btn primary" id="applySuggestions" disabled>应用建议阈值</button>
                    </div>
                </div>
            </div>
        </section>

        <section class="panel">
            <div class="panel-head">
                <div class="panel-title">安全警报日志</div>
                <div class="panel-sub">展示最近 20 条触发记录</div>
            </div>
            <div class="alerts-list" id="alertsContainer">
                <div class="empty">系统运行正常，暂无安全警报...</div>
            </div>
        </section>
    </main>

    <div class="modal" id="ipModal" aria-hidden="true">
        <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="ipModalTitle">
            <div class="modal-head">
                <div>
                    <h2 id="ipModalTitle">来源 IP 明细</h2>
                    <div class="modal-sub">按捕获包数量排序，最多显示 50 个来源 IP</div>
                </div>
                <button class="icon-btn" id="closeIpModal" aria-label="关闭">×</button>
            </div>
            <div class="modal-body" id="ipModalBody">
                <div class="modal-empty">正在加载来源 IP 数据...</div>
            </div>
        </div>
    </div>

    <script>
        const state = { chart: null, suggestions: null };
        const numberFormat = new Intl.NumberFormat('zh-CN');
        const modeLabels = { idle: '空闲', simulation: '模拟流量', capture: '网卡捕获' };

        function el(id) { return document.getElementById(id); }

        function escapeHtml(value) {
            return String(value).replace(/[&<>"']/g, ch => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[ch]));
        }

        async function request(url, options) {
            const response = await fetch(url, options);
            if (response.status === 401) {
                window.location.href = '/login';
                throw new Error('登录已过期，正在跳转登录页');
            }
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(data.message || `请求失败 (${response.status})`);
            }
            return data;
        }

        function setControlMessage(text, kind) {
            const node = el('controlMessage');
            node.textContent = text;
            node.className = 'control-message' + (kind ? ' ' + kind : '');
        }

        function initChart() {
            drawChart();
            window.addEventListener('resize', drawChart);
        }

        const chartState = { labels: [], values: [] };

        function niceStep(raw) {
            // 把刻度间隔取整为 1/2/5/10 的整数倍，保证 Y 轴标签可读。
            const safe = Math.max(1, raw || 1);
            const exponent = Math.floor(Math.log10(safe));
            const base = Math.pow(10, exponent);
            const normalized = safe / base;
            const factor = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
            return factor * base;
        }

        function drawChart() {
            const canvas = el('qpsChart');
            if (!canvas) return;
            const wrap = canvas.parentElement;
            const width = wrap.clientWidth;
            const height = wrap.clientHeight;
            if (!width || !height) return;
            const ratio = window.devicePixelRatio || 1;
            if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
                canvas.width = Math.round(width * ratio);
                canvas.height = Math.round(height * ratio);
            }
            const ctx = canvas.getContext('2d');
            if (!ctx) return;
            ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
            ctx.clearRect(0, 0, width, height);

            const padding = { top: 18, right: 20, bottom: 42, left: 68 };
            const plotWidth = width - padding.left - padding.right;
            const plotHeight = height - padding.top - padding.bottom;
            if (plotWidth < 20 || plotHeight < 20) return;

            const values = chartState.values;
            const labels = chartState.labels;
            const peak = values.length ? Math.max(...values) : 0;
            const step = niceStep(Math.max(1, peak) / 4);
            const yMax = Math.max(step * 4, Math.ceil(peak / step) * step, 10);
            const axisColor = '#7f8da6';
            const gridColor = 'rgba(120, 170, 255, 0.09)';

            // 横向网格线与 Y 轴刻度值
            ctx.font = '10px "Segoe UI", "Microsoft YaHei", sans-serif';
            ctx.textBaseline = 'middle';
            for (let i = 0; i <= 4; i++) {
                const y = padding.top + plotHeight - (plotHeight * i) / 4;
                ctx.strokeStyle = gridColor;
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(padding.left, y);
                ctx.lineTo(padding.left + plotWidth, y);
                ctx.stroke();
                ctx.fillStyle = axisColor;
                ctx.textAlign = 'right';
                ctx.fillText(numberFormat.format(Math.round((yMax * i) / 4)), padding.left - 10, y);
            }

            // 坐标轴标题与单位
            ctx.fillStyle = axisColor;
            ctx.textAlign = 'center';
            ctx.font = '11px "Segoe UI", "Microsoft YaHei", sans-serif';
            ctx.fillText('时间（时:分:秒）', padding.left + plotWidth / 2, height - 8);
            ctx.save();
            ctx.translate(14, padding.top + plotHeight / 2);
            ctx.rotate(-Math.PI / 2);
            ctx.fillText('QPS（次/秒）', 0, 0);
            ctx.restore();

            if (!values.length) {
                ctx.fillStyle = '#6d7c94';
                ctx.font = '13px "Segoe UI", "Microsoft YaHei", sans-serif';
                ctx.fillText('暂无数据，点击“开始模拟流量”后显示趋势', padding.left + plotWidth / 2, padding.top + plotHeight / 2);
                return;
            }

            const pointX = index => values.length === 1
                ? padding.left + plotWidth / 2
                : padding.left + (plotWidth * index) / (values.length - 1);
            const pointY = value => padding.top + plotHeight - (Math.min(value, yMax) / yMax) * plotHeight;

            // 折线下方的渐变填充
            const fill = ctx.createLinearGradient(0, padding.top, 0, padding.top + plotHeight);
            fill.addColorStop(0, 'rgba(56, 214, 196, 0.26)');
            fill.addColorStop(1, 'rgba(56, 214, 196, 0.02)');
            ctx.beginPath();
            ctx.moveTo(pointX(0), pointY(values[0]));
            values.forEach((value, index) => ctx.lineTo(pointX(index), pointY(value)));
            ctx.lineTo(pointX(values.length - 1), padding.top + plotHeight);
            ctx.lineTo(pointX(0), padding.top + plotHeight);
            ctx.closePath();
            ctx.fillStyle = fill;
            ctx.fill();

            // 折线本身
            ctx.beginPath();
            values.forEach((value, index) => {
                const x = pointX(index);
                const y = pointY(value);
                if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            ctx.strokeStyle = '#38d6c4';
            ctx.lineWidth = 2;
            ctx.lineJoin = 'round';
            ctx.stroke();

            // 数据点
            ctx.fillStyle = '#38d6c4';
            values.forEach((value, index) => {
                ctx.beginPath();
                ctx.arc(pointX(index), pointY(value), index === values.length - 1 ? 3.5 : 2.5, 0, Math.PI * 2);
                ctx.fill();
            });

            // X 轴时间标签
            ctx.fillStyle = axisColor;
            ctx.font = '10px "Segoe UI", "Microsoft YaHei", sans-serif';
            ctx.textAlign = 'center';
            const tickCount = Math.min(6, labels.length);
            const tickIndexes = new Set();
            for (let i = 0; i < tickCount; i++) {
                tickIndexes.add(Math.round(((labels.length - 1) * i) / Math.max(1, tickCount - 1)));
            }
            tickIndexes.forEach(index => {
                ctx.fillText(labels[index], pointX(index), padding.top + plotHeight + 16);
            });
        }

        function renderMetrics(data) {
            el('qps').innerHTML = `${numberFormat.format(data.qps)}<span class="unit">次/秒</span>`;
            el('connections').innerHTML = `${numberFormat.format(data.connections)}<span class="unit">个</span>`;
            el('packetCount').innerHTML = `${numberFormat.format(data.packet_count)}<span class="unit">包</span>`;
            el('portCount').innerHTML = `${numberFormat.format(data.port_count)}<span class="unit">个</span>`;
            el('srcIpCount').innerHTML = `${numberFormat.format(data.src_ip_count)}<span class="unit">个</span>`;
            el('synPackets').innerHTML = `${numberFormat.format(data.syn_packets)}<span class="unit">包</span>`;
            el('udpPackets').innerHTML = `${numberFormat.format(data.udp_packets)}<span class="unit">包</span>`;
            el('dnsPackets').innerHTML = `${numberFormat.format(data.dns_packets)}<span class="unit">包</span>`;
            el('updateTime').textContent = data.timestamp || '--';

            const pill = el('livePill');
            pill.classList.toggle('running', Boolean(data.running));
            const mode = modeLabels[data.mode] || data.mode || '空闲';
            let liveText = data.running ? `${mode} · 运行中` : `${mode} · 已停止`;
            if (data.error) liveText = '运行异常';
            el('liveText').textContent = liveText;

            const banner = el('statusBanner');
            if (data.alert) {
                banner.classList.add('danger');
                el('statusIcon').textContent = '!';
                el('statusText').textContent = '检测到异常流量：' + data.alert;
            } else {
                banner.classList.remove('danger');
                el('statusIcon').textContent = '✓';
                el('statusText').textContent = '当前网络状态正常，未检测到异常流量';
            }

            if (data.error) {
                setControlMessage(`模式：${mode} | 状态：${data.running ? '运行中' : '已停止'} | ${data.error}`, 'error');
            } else {
                setControlMessage(`模式：${mode} | 状态：${data.running ? '运行中' : '已停止'} | 网卡：${data.interface || '系统默认网卡'}`, 'success');
            }
        }

        function renderChart(data) {
            const timeLabel = (data.timestamp || '').split(' ')[1] || '--:--:--';
            chartState.labels.push(timeLabel);
            chartState.values.push(data.qps);
            if (chartState.labels.length > 30) {
                chartState.labels.shift();
                chartState.values.shift();
            }
            drawChart();
        }

        function renderAlerts(alerts) {
            const container = el('alertsContainer');
            if (!alerts.length) {
                container.innerHTML = '<div class="empty">系统运行正常，暂无安全警报...</div>';
                return;
            }
            container.innerHTML = alerts.map(alert => `
                <div class="alert-item">
                    <div class="alert-time">${escapeHtml(alert.time)}</div>
                    <div class="alert-message">${escapeHtml(alert.message)}</div>
                </div>
            `).join('');
        }

        async function updateDashboard() {
            try {
                const [data, alerts] = await Promise.all([
                    request('/api/traffic'),
                    request('/api/alerts')
                ]);
                renderMetrics(data);
                renderChart(data);
                renderAlerts(alerts);
            } catch (error) {
                setControlMessage('数据获取失败：' + error.message, 'error');
            }
        }

        async function runControl(action) {
            setBusy(true);
            try {
                await request('/api/control', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        action,
                        interface: el('interfaceSelect').value
                    })
                });
                await updateDashboard();
            } catch (error) {
                setControlMessage(error.message, 'error');
            } finally {
                setBusy(false);
            }
        }

        function setBusy(busy) {
            ['startCapture', 'startSimulation', 'stopCapture'].forEach(id => {
                el(id).disabled = busy;
            });
        }

        function setCurrentThresholds(config) {
            el('curDdos').textContent = numberFormat.format(config.ddos_threshold);
            el('curPort').textContent = numberFormat.format(config.port_scan_threshold);
            el('curSyn').textContent = numberFormat.format(config.syn_flood_threshold);
            el('curUdp').textContent = numberFormat.format(config.udp_flood_threshold);
        }

        async function loadControls() {
            try {
                const config = await request('/api/config');
                setCurrentThresholds(config);
            } catch (error) {
                setControlMessage('配置加载失败：' + error.message, 'error');
                return;
            }
            try {
                const interfaces = await request('/api/interfaces');
                const select = el('interfaceSelect');
                const items = interfaces.interfaces || [];
                const defaultInterface = items.find(item => item.id === interfaces.default);
                if (defaultInterface) {
                    select.options[0].textContent = `系统默认网卡（${defaultInterface.label}）`;
                }
                for (const item of items) {
                    const option = document.createElement('option');
                    option.value = item.id;
                    option.textContent = item.label;
                    option.title = [
                        item.description && `描述: ${item.description}`,
                        item.ip && `IP: ${item.ip}`,
                        item.mac && `MAC: ${item.mac}`
                    ].filter(Boolean).join(' | ');
                    select.appendChild(option);
                }
                if (!items.length) {
                    select.options[0].textContent = '未发现可用网卡（将使用系统默认）';
                }
            } catch (error) {
                el('interfaceSelect').options[0].textContent = '网卡列表不可用（' + error.message + '）';
            }
        }

        async function loadSuggestions() {
            try {
                const data = await request('/api/suggestions');
                state.suggestions = data;
                el('sugDdos').textContent = data.ready ? numberFormat.format(data.suggested.ddos_threshold) : '--';
                el('sugPort').textContent = data.ready ? numberFormat.format(data.suggested.port_scan_threshold) : '--';
                el('sugSyn').textContent = data.ready ? numberFormat.format(data.suggested.syn_flood_threshold) : '--';
                el('sugUdp').textContent = data.ready ? numberFormat.format(data.suggested.udp_flood_threshold) : '--';
                el('applySuggestions').disabled = !data.ready;
                el('suggestInfo').textContent = data.ready
                    ? `${data.basis}。点击应用后立即生效。`
                    : `正在积累采样：${data.sample_count}/${data.min_samples}。开始运行后约 ${Math.max(1, Math.ceil((data.min_samples - data.sample_count) * 2))} 秒后可给出建议。`;
            } catch (error) {
                el('suggestInfo').textContent = '建议阈值获取失败：' + error.message;
            }
        }

        async function applySuggestions() {
            const suggestions = state.suggestions;
            if (!suggestions || !suggestions.ready) {
                setControlMessage('采样数据不足，暂时无法应用建议阈值', 'error');
                return;
            }
            el('applySuggestions').disabled = true;
            try {
                const response = await request('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(suggestions.suggested)
                });
                setCurrentThresholds(response.config);
                setControlMessage('已应用建议阈值，新的检测规则立即生效', 'success');
                await loadSuggestions();
            } catch (error) {
                setControlMessage('应用建议阈值失败：' + error.message, 'error');
                el('applySuggestions').disabled = false;
            }
        }

        function openIpModal() {
            const modal = el('ipModal');
            modal.classList.add('open');
            modal.setAttribute('aria-hidden', 'false');
            el('ipModalBody').innerHTML = '<div class="modal-empty">正在加载来源 IP 数据...</div>';
            loadSourceIps();
        }

        function closeIpModal() {
            const modal = el('ipModal');
            modal.classList.remove('open');
            modal.setAttribute('aria-hidden', 'true');
        }

        async function loadSourceIps() {
            try {
                const data = await request('/api/source_ips');
                if (!data.ips.length) {
                    el('ipModalBody').innerHTML = '<div class="modal-empty">当前还没有捕获到来源 IP，请先开始采集。</div>';
                    return;
                }
                const rows = data.ips.map((item, index) => `
                    <tr>
                        <td class="rule-unit">${index + 1}</td>
                        <td class="mono">${escapeHtml(item.ip)}</td>
                        <td class="count">${numberFormat.format(item.packets)} 包</td>
                        <td class="count">${item.percent}%</td>
                        <td class="bar-cell">
                            <div class="ip-bar"><span style="width: ${Math.min(100, item.percent)}%"></span></div>
                        </td>
                    </tr>
                `).join('');
                el('ipModalBody').innerHTML = `
                    <div style="margin-bottom: 12px; font-size: 12px; color: #7f8da6;">
                        共 ${numberFormat.format(data.unique)} 个来源 IP，累计 ${numberFormat.format(data.total)} 个包；
                        当前展示前 ${data.ips.length} 个。
                    </div>
                    <table class="ip-table">
                        <thead>
                            <tr><th>#</th><th>来源 IP</th><th style="text-align: right;">捕获包数</th><th style="text-align: right;">占比</th><th>占比条</th></tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                `;
            } catch (error) {
                el('ipModalBody').innerHTML = `<div class="modal-empty">来源 IP 获取失败：${escapeHtml(error.message)}</div>`;
            }
        }

        el('startCapture').onclick = () => runControl('start_capture');
        el('startSimulation').onclick = () => runControl('start_simulation');
        el('stopCapture').onclick = () => runControl('stop');
        el('applySuggestions').onclick = applySuggestions;
        el('srcIpCard').onclick = openIpModal;
        el('srcIpCard').onkeydown = event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openIpModal();
            }
        };
        el('closeIpModal').onclick = closeIpModal;
        el('ipModal').onclick = event => {
            if (event.target === el('ipModal')) closeIpModal();
        };
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape') closeIpModal();
        });

        initChart();
        loadControls();
        loadSuggestions();
        updateDashboard();
        setInterval(updateDashboard, 2000);
        setInterval(loadSuggestions, 10000);
    </script>
</body>
</html>
"""


LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>登录 · AI-NIDS 校园网流量监控</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh; display: grid; place-items: center; padding: 24px;
            color: #e8f0ff; font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
            background:
                radial-gradient(900px 520px at 10% 0%, rgba(56, 214, 196, 0.14), transparent 60%),
                radial-gradient(800px 480px at 95% 100%, rgba(91, 141, 255, 0.18), transparent 55%),
                #060a12;
        }
        .wrap { width: min(390px, 100%); }
        .brand { display: flex; align-items: center; gap: 13px; justify-content: center; margin-bottom: 26px; }
        .brand-mark {
            width: 46px; height: 46px; border-radius: 13px; display: grid; place-items: center;
            font-weight: 800; font-size: 21px; color: #04130f;
            background: linear-gradient(135deg, #38d6c4, #5b8dff);
            box-shadow: 0 10px 26px rgba(56, 214, 196, 0.28);
        }
        .brand h1 { font-size: 19px; font-weight: 650; letter-spacing: 0.4px; }
        .brand .sub { font-size: 10px; color: #7f8da6; letter-spacing: 2px; margin-top: 3px; }
        .card {
            padding: 26px 24px; border-radius: 20px; border: 1px solid rgba(120, 170, 255, 0.16);
            background: rgba(15, 23, 38, 0.86); backdrop-filter: blur(14px);
            box-shadow: 0 28px 70px rgba(0, 0, 0, 0.45);
        }
        .card h2 { font-size: 17px; font-weight: 650; margin-bottom: 6px; }
        .card .hint { font-size: 12px; color: #7f8da6; margin-bottom: 20px; }
        .error {
            margin-bottom: 16px; padding: 10px 12px; border-radius: 10px; font-size: 12px;
            color: #ffb3bd; background: rgba(255, 95, 115, 0.1);
            border: 1px solid rgba(255, 95, 115, 0.32);
        }
        .field { margin-bottom: 14px; }
        .field label { display: block; font-size: 12px; color: #9aa9c0; margin-bottom: 7px; }
        .field input {
            width: 100%; padding: 11px 13px; font-size: 14px; color: #e8f0ff;
            background: #101a2b; border: 1px solid rgba(120, 170, 255, 0.2);
            border-radius: 10px; outline: none; transition: 0.18s;
        }
        .field input:focus { border-color: rgba(56, 214, 196, 0.55); box-shadow: 0 0 0 3px rgba(56, 214, 196, 0.1); }
        .submit {
            width: 100%; margin-top: 6px; padding: 12px; border: none; border-radius: 10px;
            font-size: 14px; font-weight: 700; color: #04130f; cursor: pointer;
            background: linear-gradient(135deg, #38d6c4, #5b8dff);
            box-shadow: 0 12px 26px rgba(56, 214, 196, 0.22);
            transition: filter 0.18s;
        }
        .submit:hover { filter: brightness(1.06); }
        .foot { margin-top: 18px; text-align: center; font-size: 11px; color: #5f6c84; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="brand">
            <div class="brand-mark">N</div>
            <div>
                <h1>AI-NIDS 校园网流量监控</h1>
                <div class="sub">Encrypted Traffic Intrusion Detection</div>
            </div>
        </div>
        <div class="card">
            <h2>登录监控中心</h2>
            <p class="hint">请输入账号信息，登录后即可查看实时流量与告警。</p>
            {% if error %}<div class="error">{{ error|e }}</div>{% endif %}
            <form method="post" action="/login" autocomplete="off">
                <div class="field">
                    <label for="username">用户名</label>
                    <input id="username" name="username" required autofocus placeholder="请输入用户名">
                </div>
                <div class="field">
                    <label for="password">密码</label>
                    <input id="password" name="password" type="password" required placeholder="请输入密码">
                </div>
                <input type="hidden" name="next" value="{{ next_url|e }}">
                <button class="submit" type="submit">登录</button>
            </form>
            <p class="foot">首次运行时自动创建默认账号，账号与密码见服务启动日志。</p>
        </div>
    </div>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    """用户名密码登录；成功后将身份写入会话。"""
    next_url = _safe_next(request.values.get('next')) or ""
    if request.method == "POST":
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        user = next((item for item in USERS if item['username'] == username), None)
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['username'] = username
            return redirect(next_url or url_for('dashboard'))
        return render_template_string(
            LOGIN_TEMPLATE,
            error='用户名或密码错误，请重试',
            next_url=next_url,
        )
    return render_template_string(LOGIN_TEMPLATE, error=None, next_url=next_url)


@app.route("/logout")
def logout():
    """清空会话并回到登录页。"""
    session.clear()
    return redirect(url_for('login'))


@app.route("/")
@login_required
def dashboard():
    """返回监控仪表盘页面。"""
    return render_template_string(HTML_TEMPLATE, username=session.get('username', ''))


@app.route("/api/traffic")
@login_required
def get_traffic_data():
    # 模拟模式没有独立线程，因此在前端轮询时生成下一组数据。
    if CAPTURE_STATE['mode'] == 'simulation' and CAPTURE_STATE['running']:
        update_traffic_data()
    elif CAPTURE_STATE['mode'] == 'capture' and CAPTURE_STATE['running']:
        # 抓包模式的采样跟随页面轮询节奏，供建议阈值计算使用。
        with STATE_LOCK:
            METRIC_SAMPLES.append({
                'qps': len(CAPTURE_TIMES),
                'port_count': len({port for _, port in CAPTURE_PORT_TIMES}),
                'syn_packets': len(CAPTURE_SYN_TIMES),
                'udp_packets': len(CAPTURE_UDP_TIMES),
            })
    with STATE_LOCK:
        return jsonify({
            'qps': traffic_data['qps'],
            'connections': traffic_data['connections'],
            'alert': traffic_data['alert'],
            'timestamp': traffic_data['timestamp'],
            'packet_count': traffic_data['packet_count'],
            'port_count': len(traffic_data['unique_ports']),
            'src_ip_count': len(traffic_data['src_ips']),
            'syn_packets': traffic_data['syn_packets'],
            'udp_packets': traffic_data['udp_packets'],
            'dns_packets': traffic_data['dns_packets'],
            'mode': CAPTURE_STATE['mode'],
            'running': CAPTURE_STATE['running'],
            'interface': CAPTURE_STATE['interface'],
            'error': CAPTURE_STATE['error'],
        })


@app.route("/api/alerts")
@login_required
def get_alerts():
    # 只返回最近 20 条，避免前端一次加载过多历史记录。
    return jsonify(alert_history[:20])


@app.route("/api/source_ips")
@login_required
def get_source_ips():
    """返回按包数排序的来源 IP 明细，用于页面弹窗展示。"""
    with STATE_LOCK:
        items = sorted(traffic_data['src_ip_counts'].items(),
                       key=lambda item: item[1], reverse=True)
        total = sum(count for _, count in items)
        unique = len(items)
    top_items = items[:50]
    return jsonify({
        'total': total,
        'unique': unique,
        'ips': [{
            'ip': ip,
            'packets': count,
            'percent': round(count / total * 100, 1) if total else 0,
        } for ip, count in top_items],
    })


@app.route("/api/suggestions")
@login_required
def get_suggestions():
    """返回基于近期采样计算的建议阈值，不直接修改生效阈值。"""
    return jsonify(build_suggestions())


@app.route("/api/config", methods=['GET', 'POST'])
@login_required
def config():
    """读取或更新检测阈值，并将更新后的配置持久化到 JSON 文件。"""
    global CONFIG, detector
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        try:
            for key in ('ddos_threshold', 'port_scan_threshold',
                        'syn_flood_threshold', 'udp_flood_threshold'):
                if key in data:
                    value = int(data[key])
                    if value < 1:
                        raise ValueError
                    CONFIG[key] = value
            CONFIG_FILE.write_text(
                json.dumps(CONFIG, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError):
            return jsonify({
                'status': 'error',
                'message': '阈值必须是大于 0 的整数，且配置文件必须可写',
            }), 400

        # 更新配置后重建检测器，使新阈值立即对后续数据生效。
        detector = AnomalyDetector(
            ddos_threshold=CONFIG['ddos_threshold'],
            port_scan_threshold=CONFIG['port_scan_threshold'],
            syn_flood_threshold=CONFIG['syn_flood_threshold'],
            udp_flood_threshold=CONFIG['udp_flood_threshold']
        )
        return jsonify({'status': 'success', 'config': CONFIG})
    return jsonify(CONFIG)


@app.route("/api/save")
@login_required
def save_data():
    """提供手动导出当前统计数据的接口。"""
    save_traffic_data()
    return jsonify({'status': 'success', 'message': '数据已保存到 traffic_data.csv'})


@app.route("/api/interfaces")
@login_required
def interfaces():
    """枚举 Scapy 可用网卡，并返回页面显示所需的网卡信息。"""
    try:
        from scapy.all import conf, get_if_list
        interface_items = []
        for interface_id in get_if_list():
            details = conf.ifaces.get(interface_id)
            name = str(getattr(details, 'name', '') or interface_id)
            description = str(getattr(details, 'description', '') or '')
            ip = str(getattr(details, 'ip', '') or '')
            mac = str(getattr(details, 'mac', '') or '')
            display_name = description or name
            if ip:
                display_name = f'{display_name} ({ip})'
            interface_items.append({
                'id': interface_id,
                'name': name,
                'description': description,
                'ip': ip,
                'mac': mac,
                'label': display_name,
            })
        default_interface = str(conf.iface)
        return jsonify({
            'interfaces': interface_items,
            'default': default_interface,
        })
    except ImportError:
        return jsonify({'interfaces': [], 'error': '未安装 scapy'}), 503


@app.route("/api/control", methods=["POST"])
@login_required
def control():
    """根据前端动作切换模拟、真实抓包和停止状态。"""
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if action == 'start_simulation':
        stop_capture()
        with STATE_LOCK:
            METRIC_SAMPLES.clear()
            CAPTURE_STATE.update({'mode': 'simulation', 'running': True, 'error': None})
    elif action == 'start_capture':
        start_capture(data.get('interface'))
    elif action == 'stop':
        stop_capture()
        with STATE_LOCK:
            CAPTURE_STATE['running'] = False
    else:
        return jsonify({'status': 'error', 'message': 'action 必须是 start_simulation、start_capture 或 stop'}), 400
    return jsonify({'status': 'success', 'state': CAPTURE_STATE})


def run_app():
    # Keep startup output compatible with the default GBK console on Windows.
    print("AI-NIDS 监控系统启动成功")
    print(f"访问地址: http://localhost:{CONFIG['port']}")
    print(f"刷新间隔: {CONFIG['refresh_interval']}ms")
    print(f"数据保存文件: {OUTPUT_CSV}")
    print("=" * 50)
    app.run(debug=False, port=CONFIG['port'], host='0.0.0.0')


if __name__ == "__main__":
    run_app()
