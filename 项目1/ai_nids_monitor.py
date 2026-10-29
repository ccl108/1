from __future__ import annotations

import random
import csv
import json
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, jsonify, request

# 创建 Flask 应用，并通过内嵌 HTML 提供监控页面。
app = Flask(__name__)

# 系统默认配置；运行时可通过页面上的“保存阈值”修改。
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

traffic_data = {
    # traffic_data 保存当前页面需要展示的实时统计信息。
    'qps': 200,
    'connections': 80,
    'alert': None,
    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    'packet_count': 0,
    'unique_ports': set(),
    'src_ips': set(),
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
        traffic_data['src_ips'].add(f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}")
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
            if packet.haslayer(TCP):
                port = int(packet[TCP].dport)
                traffic_data['unique_ports'].add(port)
                if packet[TCP].flags & 0x02:
                    CAPTURE_SYN_TIMES.append(now)
                    CAPTURE_PORT_TIMES.append((now, port))
                    traffic_data['syn_packets'] += 1
            if packet.haslayer(UDP):
                port = int(packet[UDP].dport)
                traffic_data['unique_ports'].add(port)
                CAPTURE_UDP_TIMES.append(now)
                traffic_data['udp_packets'] += 1
            if packet.haslayer(DNS):
                traffic_data['dns_packets'] += 1
            traffic_data['connections'] = len(traffic_data['src_ips'])
            traffic_data['qps'] = len(CAPTURE_TIMES)
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


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI-NIDS 校园网流量监控中心</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%); color: white; min-height: 100vh; }
        .header { background: rgba(255,255,255,0.05); padding: 20px; text-align: center; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .update-time { font-size: 12px; color: #888; }
        .refresh-indicator { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: #4CAF50; animation: blink 1s infinite; margin-left: 8px; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 20px; max-width: 1400px; margin: 0 auto; }
        .card { background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.1); transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); }
        .card-title { font-size: 14px; color: #888; margin-bottom: 10px; }
        .card-value { font-size: 32px; font-weight: bold; }
        .card-value.alert { color: #ff4d4d; }
        .card-value.normal { color: #4CAF50; }
        
        .chart-container { grid-column: 1 / -1; background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,255,255,0.1); }
        .chart-title { font-size: 16px; margin-bottom: 15px; }
        canvas { width: 100% !important; height: 300px !important; }
        
        .alerts-section { grid-column: 1 / -1; }
        .alert-item { background: rgba(255,77,77,0.1); border-left: 4px solid #ff4d4d; padding: 12px 15px; margin-bottom: 8px; border-radius: 4px; }
        .alert-time { font-size: 12px; color: #888; margin-bottom: 4px; }
        .alert-message { font-size: 14px; }
        .no-alert { color: #4CAF50; text-align: center; padding: 20px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .controls { grid-column: 1 / -1; }
        .control-row { display: flex; flex-wrap: wrap; gap: 10px; align-items: end; }
        .control-group { flex: 1 1 180px; }
        .control-group label { display: block; color: #aaa; font-size: 12px; margin-bottom: 5px; }
        select, input, button { width: 100%; padding: 9px; color: white; background: #29294a; border: 1px solid #505078; border-radius: 5px; }
        button { cursor: pointer; }
        button:hover { background: #3b3b68; }
        #controlMessage { color: #aaa; margin-top: 10px; min-height: 18px; }
        
        @media (max-width: 768px) {
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AI-NIDS 校园网加密流量入侵检测系统</h1>
        <p class="update-time">最后更新: <span id="updateTime">--</span> <span class="refresh-indicator"></span></p>
    </div>

    <div class="dashboard">
        <div class="card controls">
            <div class="card-title">控制与检测阈值</div>
            <div class="control-row">
                <div class="control-group">
                    <label for="interfaceSelect">捕获网卡</label>
                    <select id="interfaceSelect"><option value="">系统默认网卡（由 Scapy 自动选择）</option></select>
                </div>
                <div class="control-group"><label for="ddosThreshold">DDoS QPS阈值</label><input id="ddosThreshold" type="number" min="1"></div>
                <div class="control-group"><label for="portThreshold">10秒端口数阈值</label><input id="portThreshold" type="number" min="1"></div>
                <div class="control-group"><label for="synThreshold">10秒 SYN阈值</label><input id="synThreshold" type="number" min="1"></div>
                <div class="control-group"><label for="udpThreshold">10秒 UDP阈值</label><input id="udpThreshold" type="number" min="1"></div>
            </div>
            <div class="control-row">
                <button id="startCapture">开始网卡捕获</button>
                <button id="startSimulation">开始模拟流量</button>
                <button id="stopCapture">停止</button>
                <button id="saveConfig">保存阈值</button>
            </div>
            <div id="controlMessage"></div>
        </div>
        <div class="card">
            <div class="card-title">QPS (每秒请求数)</div>
            <div class="card-value" id="qps">--</div>
        </div>
        <div class="card">
            <div class="card-title">活跃连接数</div>
            <div class="card-value" id="connections">--</div>
        </div>
        <div class="card">
            <div class="card-title">数据包计数</div>
            <div class="card-value" id="packetCount">--</div>
        </div>
        <div class="card">
            <div class="card-title">访问端口数</div>
            <div class="card-value" id="portCount">--</div>
        </div>
        <div class="card">
            <div class="card-title">来源IP数</div>
            <div class="card-value" id="srcIpCount">--</div>
        </div>
        <div class="card">
            <div class="card-title">安全状态</div>
            <div class="card-value" id="status">--</div>
        </div>

        <div class="stats-grid">
            <div class="card">
                <div class="card-title">TCP SYN包</div>
                <div class="card-value" id="synPackets">--</div>
            </div>
            <div class="card">
                <div class="card-title">UDP包</div>
                <div class="card-value" id="udpPackets">--</div>
            </div>
            <div class="card">
                <div class="card-title">DNS查询</div>
                <div class="card-value" id="dnsPackets">--</div>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-title">📊 QPS 实时趋势图</div>
            <canvas id="qpsChart"></canvas>
        </div>

        <div class="alerts-section">
            <div class="chart-title">🔔 安全警报日志</div>
            <div id="alertsContainer">
                <p class="no-alert">系统运行正常，暂无安全警报...</p>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        let qpsChart;
        
        // 初始化 QPS 折线图；后续数据由 updateDashboard 追加。
        function initChart() {
            const ctx = document.getElementById('qpsChart').getContext('2d');
            qpsChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'QPS',
                        data: [],
                        borderColor: '#4CAF50',
                        backgroundColor: 'rgba(76, 175, 80, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { display: false },
                        y: { 
                            beginAtZero: true,
                            grid: { color: 'rgba(255,255,255,0.1)' },
                            ticks: { color: '#888' }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        function updateDashboard() {
            // 定时获取实时指标，并同步更新卡片、状态和趋势图。
            fetch('/api/traffic')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('qps').textContent = data.qps;
                    document.getElementById('connections').textContent = data.connections;
                    document.getElementById('packetCount').textContent = data.packet_count;
                    document.getElementById('portCount').textContent = data.port_count;
                    document.getElementById('srcIpCount').textContent = data.src_ip_count;
                    document.getElementById('synPackets').textContent = data.syn_packets;
                    document.getElementById('udpPackets').textContent = data.udp_packets;
                    document.getElementById('dnsPackets').textContent = data.dns_packets;
                    document.getElementById('updateTime').textContent = data.timestamp;
                    document.getElementById('controlMessage').textContent =
                        `模式: ${data.mode} | 状态: ${data.running ? '运行中' : '已停止'} | 网卡: ${data.interface || '系统默认网卡'}${data.error ? ' | ' + data.error : ''}`;
                    
                    const statusEl = document.getElementById('status');
                    if (data.alert) {
                        statusEl.textContent = '⚠️ 异常';
                        statusEl.className = 'card-value alert';
                    } else {
                        statusEl.textContent = '✓ 正常';
                        statusEl.className = 'card-value normal';
                    }
                    
                    // 只保留最近 30 个点，避免页面运行时间过长导致图表无限增长。
                    if (qpsChart) {
                        qpsChart.data.labels.push(data.timestamp.split(' ')[1]);
                        qpsChart.data.datasets[0].data.push(data.qps);
                        if (qpsChart.data.labels.length > 30) {
                            qpsChart.data.labels.shift();
                            qpsChart.data.datasets[0].data.shift();
                        }
                        qpsChart.update();
                    }
                })
                .catch(error => console.error('获取数据失败:', error));

            // 告警列表单独请求，避免指标更新失败时影响告警展示。
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('alertsContainer');
                    if (data.length > 0) {
                        container.innerHTML = data.map(alert => `
                            <div class="alert-item">
                                <div class="alert-time">${alert.time}</div>
                                <div class="alert-message">${alert.message}</div>
                            </div>
                        `).join('');
                    } else {
                        container.innerHTML = '<p class="no-alert">系统运行正常，暂无安全警报...</p>';
                    }
                })
                .catch(error => console.error('获取警报失败:', error));
        }

        async function postControl(action) {
            // 统一处理开始模拟、开始抓包和停止操作。
            const response = await fetch('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({action, interface: document.getElementById('interfaceSelect').value})
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.message || '操作失败');
            updateDashboard();
        }

        async function loadControls() {
            // 并行加载网卡列表和检测阈值，减少控制面板首次打开的等待时间。
            const [interfacesResponse, configResponse] = await Promise.all([
                fetch('/api/interfaces'), fetch('/api/config')
            ]);
            const interfaces = await interfacesResponse.json();
            const config = await configResponse.json();
            const select = document.getElementById('interfaceSelect');
            const defaultInterface = (interfaces.interfaces || [])
                .find(item => item.id === interfaces.default);
            if (defaultInterface) {
                select.options[0].textContent =
                    `系统默认网卡（${defaultInterface.label}）`;
            }
            for (const item of interfaces.interfaces || []) {
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
            if (!interfaces.interfaces || interfaces.interfaces.length === 0) {
                select.options[0].textContent = '未发现可用网卡（将使用系统默认）';
            }
            document.getElementById('ddosThreshold').value = config.ddos_threshold;
            document.getElementById('portThreshold').value = config.port_scan_threshold;
            document.getElementById('synThreshold').value = config.syn_flood_threshold;
            document.getElementById('udpThreshold').value = config.udp_flood_threshold;
        }

        document.getElementById('startCapture').onclick = () => postControl('start_capture').catch(error => {
            document.getElementById('controlMessage').textContent = error.message;
        });
        document.getElementById('startSimulation').onclick = () => postControl('start_simulation').catch(error => {
            document.getElementById('controlMessage').textContent = error.message;
        });
        document.getElementById('stopCapture').onclick = () => postControl('stop').catch(error => {
            document.getElementById('controlMessage').textContent = error.message;
        });
        document.getElementById('saveConfig').onclick = async () => {
            const values = ['ddosThreshold', 'portThreshold', 'synThreshold', 'udpThreshold']
                .map(id => Number(document.getElementById(id).value));
            if (values.some(value => !Number.isInteger(value) || value < 1)) {
                document.getElementById('controlMessage').textContent = '阈值必须是大于 0 的整数';
                return;
            }
            await fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    ddos_threshold: values[0],
                    port_scan_threshold: values[1],
                    syn_flood_threshold: values[2],
                    udp_flood_threshold: values[3]
                })
            });
            document.getElementById('controlMessage').textContent = '阈值已保存';
        };

        initChart();
        loadControls().catch(error => {
            document.getElementById('controlMessage').textContent = '控制面板加载失败: ' + error.message;
        });
        setInterval(updateDashboard, 2000);
        updateDashboard();
    </script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    """返回监控仪表盘页面。"""
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/traffic")
def get_traffic_data():
    # 模拟模式没有独立线程，因此在前端轮询时生成下一组数据。
    if CAPTURE_STATE['mode'] == 'simulation' and CAPTURE_STATE['running']:
        update_traffic_data()
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
def get_alerts():
    # 只返回最近 20 条，避免前端一次加载过多历史记录。
    return jsonify(alert_history[:20])


@app.route("/api/config", methods=['GET', 'POST'])
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
def save_data():
    """提供手动导出当前统计数据的接口。"""
    save_traffic_data()
    return jsonify({'status': 'success', 'message': '数据已保存到 traffic_data.csv'})


@app.route("/api/interfaces")
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
def control():
    """根据前端动作切换模拟、真实抓包和停止状态。"""
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if action == 'start_simulation':
        stop_capture()
        with STATE_LOCK:
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
