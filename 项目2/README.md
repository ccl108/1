# Simple-Intent · 基于 LLM 的简易意图驱动 SDN 访问控制系统

用户输入一句自然语言（如「禁止主机A访问服务器B」「隔离主机C」），系统用 LLM 把它翻译成结构化意图，
再生成 OpenFlow 1.3 流表，通过 Ryu 控制器下发到 Mininet 虚拟交换机；控制台同时提供拓扑可视化、
连通性检测和操作日志。

**单文件交付：`simple_intent.py`**（后端 + 意图解析 + 规则生成 + 前端页面 + Ryu 控制器 + Mininet 网络，一个文件四种角色）。

## 文件

```
simple_intent.py      # 全部代码（Web / Ryu 控制器 / Mininet 实验网 / 自检）
topology.json         # 拓扑配置：s1 + h1~h4（IP、交换机端口、中文别名）
requirements.txt      # Web 端依赖
.env.example          # LLM 与模式配置示例
ui.png                # 运行效果截图
.venv/                # 已配置好的虚拟环境（依赖已安装）
```

## 快速开始（Windows，仿真模式，开箱即用）

项目里已带配置好的 `.venv`，直接运行即可：

```powershell
.\.venv\Scripts\python.exe simple_intent.py app
```

浏览器打开 <http://127.0.0.1:8000>，默认「仿真演示 · Mock 网络」：意图解析、流表、拓扑、Ping 结果全部真实逻辑，
只是流表存在内存中、Ping 由规则推导，适合演示与答辩。

自检（不需要启动服务）：

```powershell
.\.venv\Scripts\python.exe simple_intent.py selftest
```

如需重建虚拟环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

> 当前机器 pip 走 HTTPS 时存在自签证书拦截，安装失败可加
> `--trusted-host pypi.org --trusted-host files.pythonhosted.org`。

## 接入 LLM

复制 `.env.example` 为 `.env`，填 `LLM_API_KEY`（默认走 DeepSeek，兼容任意 OpenAI 接口）。
未配置或调用失败时自动退回**规则解析**，页面会标注「意图来源：规则兜底」，不影响功能。

## 真实网络（Linux / WSL，需要 Mininet + Ryu）

```bash
sudo apt install mininet python3-pip
pip install ryu requests fastapi uvicorn

# 终端 1：Ryu 控制器（REST 监听 8080）
python simple_intent.py controller

# 终端 2：Mininet 实验网络（REST 监听 8081）
sudo python3 simple_intent.py lab

# 终端 3：Web 控制台（auto 模式会自动识别到控制器，切为「真实网络」）
python simple_intent.py app
```

拓扑：`s1`（OpenFlow 1.3）下挂 `h1~h4`，IP `10.0.0.1~4`，交换机端口 1~4。
Web 端 Ping 由 Mininet 进程内的 HTTP 服务执行真实 `ping -c 3`。

## 支持的意图

| 指令示例 | 解析结果 | 流表动作 |
| --- | --- | --- |
| 禁止主机A访问服务器B | deny h1 h2 | 优先级 200，双向 DROP |
| 禁止主机A访问主机B的80端口 | deny h1 h2 tcp:80 | 匹配 `ip_proto=6, tcp_dst=80` |
| 隔离主机C | isolate h3 | 优先级 250，进/出方向各一条 DROP |
| 放行主机A访问服务器B | allow h1 h2 | 删除对应双向阻断规则 |
| 解除主机C的隔离 | unisolate h3 | 删除两条隔离规则 |

主机名支持 `h1` / `10.0.0.1` / `主机A` / `服务器B` 等别名（见 `topology.json`）。

## 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/intent` | `{"text": "..."}` → 解析 + 下发流表 + 写日志 |
| GET | `/api/flows` | 当前生效流表 |
| GET | `/api/topology` | 主机状态（正常 / 受限 / 隔离）、端口状态 |
| POST | `/api/ping-all` | 全量连通性检测 |
| GET/DELETE | `/api/logs` | 操作日志 / 清空 |
| POST | `/api/logs/{id}/undo` | 撤销某条操作（删除其流表、恢复其删除的规则） |
| POST | `/api/reset` | 清空全部 ACL 流表 |

Ryu 控制器侧：`POST /intent/flow/add`、`POST /intent/flow/delete`、`POST /intent/flow/clear`、
`GET /intent/flows/{dpid}`、`GET /intent/topology`、`GET /intent/health`。
Mininet 侧：`GET /status`、`GET /ping?src=h1&dst=h2`。

## 已验证

- `python simple_intent.py selftest`：7 条中英文指令解析、流表生成、仿真 Ping 全部通过。
- 页面实测：禁止 h1↔h2 后连通矩阵双向变红，h3 隔离后与所有主机不通，h4 正常；
  流表 4 条（2 条阻断 + 2 条隔离），日志与撤销可用。
- 放行操作实测删除了双向规则（4 → 2 条），再阻断恢复 4 条。
