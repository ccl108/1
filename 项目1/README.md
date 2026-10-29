# AI-NIDS 校园网流量监控系统

这是一个基于 Flask 和 Scapy 的网络入侵检测演示项目。系统支持两种数据来源：

- **模拟模式**：生成随机流量，用于验证监控页面和告警流程。
- **实时抓包模式**：通过 Scapy 读取数据包的 IP、协议、端口和 DNS 等元数据，不保存数据包载荷。

## 1. Windows 虚拟环境

在项目根目录执行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python ai_nids_monitor.py
```

也可以不激活环境，直接使用：

```powershell
.\.venv\Scripts\python.exe ai_nids_monitor.py
```

启动后访问 <http://localhost:5000>。

实时抓包还需要 Windows 安装 Npcap，并启用 **WinPcap-compatible mode**。如果只使用模拟模式，不需要抓包驱动。

## 2. 当前实现的量化结果

以下结果来自对当前源码的静态核查，不是基于带标签数据集的模型评测：

| 项目 | 当前结果 | 说明 |
|---|---:|---|
| 检测规则数量 | 4 类 | DDoS、端口扫描、TCP SYN 洪水、UDP 洪水 |
| 检测器输入特征数量 | 4 个 | QPS、10 秒端口数、10 秒 SYN 包数、10 秒 UDP 包数 |
| 实时统计数值特征 | 8 个 | QPS、连接数、累计包数、端口数、源 IP 数、SYN 包数、UDP 包数、DNS 包数 |
| 数据包元数据类型 | 6 类 | IP 存在性、源 IP、TCP/UDP 协议、目的端口、TCP SYN 标志、DNS 层 |
| CSV 数值字段 | 5 个 | QPS、Connections、PacketCount、PortCount、SrcIPCount |
| 监控接口 | 7 个 | 页面、流量、告警、配置、保存、网卡、控制 |
| 告警历史上限 | 50 条 | 页面接口最多返回最近 20 条 |
| 图表数据点上限 | 30 个 | 前端仅保留最近 30 个 QPS 点 |
| 导出历史记录上限 | 60 条 | 内存中的 `traffic_history` 超过后先进先出 |

### 默认阈值与时间窗口

| 规则 | 默认阈值 | 统计窗口 | 触发条件 |
|---|---:|---:|---|
| 疑似 DDoS | 500 | 最近 1 秒 | QPS > 500 |
| 疑似端口扫描 | 50 个端口 | 最近 10 秒 | 目的端口数 > 50 |
| 疑似 TCP SYN 洪水 | 100 个 SYN 包 | 最近 10 秒 | SYN 包数 > 100 |
| 疑似 UDP 洪水 | 200 个 UDP 包 | 最近 10 秒 | UDP 包数 > 200 |

阈值可在页面中修改，并持久化到 `nids_config.json`。

## 3. 识别准确率说明

当前项目**没有实现可计算准确率的离线评估流程**，原因是源码中没有提供：

1. 带有正常/攻击标签的数据集；
2. 预测结果与真实标签的逐样本对齐；
3. TP、TN、FP、FN 或混淆矩阵统计；
4. 训练集、测试集或交叉验证划分。

因此，当前版本不能诚实地给出“识别准确率 xx%”。模拟模式只用于演示界面和规则触发，随机生成的数据也不能作为准确率依据。若要得到准确率，需要先采集并标注数据，再按以下指标评估：

```text
Accuracy  = (TP + TN) / (TP + TN + FP + FN)
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
```

在没有真实标签前，当前最可靠的量化结论是：系统包含 **4 类可配置阈值检测规则**，覆盖 **4 个直接判定特征**，并展示 **8 个实时数值统计特征**。

## 4. 数据与隐私边界

实时抓包只读取包的元数据，不保留原始 payload；抓包器使用 `store=False`。导出的 `traffic_data.csv` 保存时间、统计值和告警文本，不保存原始数据包内容。

## 5. 已知限制

- 规则是阈值判断，不是经过训练和验证的机器学习分类器。
- `connections` 实际上按观测到的源 IP 数量统计，不等同于 TCP 连接数。
- `packet_count`、端口集合和源 IP 集合在进程运行期间累计；窗口化的主要检测量是 QPS、SYN、UDP 和端口扫描计数。
- Windows 实时抓包依赖管理员权限、Npcap 和正确的网卡选择。
