# ipv6-watchdog

**零第三方依赖（纯 Python 3 标准库）、面向 IPv6 `/64` 代理节点的高 SLA 防阻断检测与零停机自动轮换看门狗。**

面向拥有 **IPv6 `/64` 子网 + Cloudflare DNS（纯 AAAA，TTL 60s）** 的代理节点（Xray / sing-box / Hysteria 等）：平时每 90 秒由**中国大陆三网（电信 / 联通 / 移动）探针正向实测入站 TCP 端口**，同时兼顾「整 IP 封禁」与「仅封 443 端口」；确认阻断后 **~20 秒内**自动切换到全新随机 `/64` 地址并更新 Cloudflare DNS，**代理内核全程 0 重启、旧连接 120 秒平滑排空**。

---

## 核心特性

1. **直线极速决策树（无冗余探测，低误判 + 高 SLA）**
   - **主检测**：调用 [Globalping Public API](https://globalping.io/) 精准点名 **中国电信 (`AS4134`) + 中国联通 (`AS4837`) + 中国移动** 共 3 个大陆探针，正向 TCP 握手实测 `[当前IPv6]:443`。
   - **≥ 2 网同时断才动作**：默认阈值 `FAIL_CARRIER_THRESHOLD=2`，免疫单家运营商晚高峰跨网抖动。
   - **本地自愈优先（绝不把程序崩溃误判成被墙）**：发现异常先查本机网卡 IPv6、`systemd` 服务、可选 `nftables` / Xray 入站用户数与本机 TCP 握手；本地异常只修本地，绝不乱换 IP。
2. **「现拉全新随机接班 IPv6」当对照组（彻底不怕固定对照被无差别封禁）**
   - 不依赖固定的 `::2` 当对照组！
   - 本地健康时，现场在 `/64` 内生成一个从未用过的随机 `[接班IPv6]`，绑上网卡预热 2 秒 NDP，立即用大陆三网探针实测 `[接班IPv6]:443`：
     - **接班通**：一石二鸟——既证明不是整段 `/64` 连坐/机房故障/Globalping 抽风，又提前完成了新 IPv6 的 NDP 预热和国内三网 443 验通；
     - **接班也不通**：说明整段 `/64` 或线路/探针整体异常，立即删掉临时地址、不动 DNS 并告警。
3. **10 秒快复测 + 零重启平滑切换**
   - 接班验通后等待 `10s`（可配）对旧 IPv6 做最后一次复测：恢复了就删临时地址；依然 ≥2 网断则当场调 Cloudflare API 切换 `AAAA` 记录（TTL 60s），旧 IPv6 保留 `120s` 让存量连接优雅排空后再清理。
   - 代理内核只需监听 `[::]:443`（配合 `nftables` 屏蔽外部 IPv4 443），**换 IP 全程无需改代理配置、无需重启内核**。
4. **自动降级兜底 & 防 `/64` 连坐安全锁**
   - 若 Globalping API 临时维护或限流（HTTP 429），自动无缝降级为**本机反向三网 9 端点（电信/联通/移动各 3 个固定基础设施 IPv6）对照检测**；
   - 内置 **30 分钟冷却期** + **24 小时最多切换 3 次上限**，防止极端情况下高频换 IP 触发整段 `/64` 连坐封禁。
5. **零依赖、超省额度、近乎零流量**
   - 纯 Python 3.8+ 标准库，无任何 `pip` 包依赖，不常驻后台（由 `systemd timer` 按周期拉起即退，常驻内存 `0 MB`）；
   - 支持 Telegram Bot 与通用 JSON Webhook 告警。

---

## 决策流程一览

```text
每 90 秒巡检：Globalping 精准三网（电信 1 + 联通 1 + 移动 1，仅耗 3 额度）正向 TCP 测 [当前v6]:443
  ├── ≥ 2 网通 ──▶ HEALTHY，直接结束（1 步同时验证：机器活 + 代理活 + IPv6 未封 + 443 未封）
  └── ≥ 2 网断 ──▶ 进入极速排障（全程 ~20 秒）：
        1. 本地自愈检查（网卡 IPv6 / systemd 服务 / 本机 TCP 握手 / 可选 nftables & Xray 用户数）
             └─ 本机异常 ──▶ 自动修复本地服务/网卡，绝不换 IP
        2. 本地正常 ──▶ 现场生成 1 个全新随机 [接班v6] 绑网卡预热 2s NDP，大陆三网测 [接班v6]:443
             ├─ 接班也不通 ──▶ 整段 /64 或国际线路/探针整体异常 ──▶ 清理临时地址、不动 DNS、发告警
             └─ 接班 ≥ 2 网通 ──▶ 接班人已就位，进入第 3 步
        3. 等 10 秒，复测 [当前v6]:443
             ├─ 恢复（≥ 2 网通）──▶ 瞬时抖动 ──▶ 清理临时地址、不动 DNS
             └─ 依然 ≥ 2 网断 ──▶ 实锤阻断！检查冷却/24h 上限 ──▶ 改 CF AAAA 指向 [接班v6]（TTL 60s）
                                  ──▶ 旧 v6 保留 120s 平滑排空后删除（代理 0 重启）
```

---

## Globalping 免费额度与服务器流量消耗

- **免费额度**：未登录即可免费使用 **`250` 次探针测试 / 小时**（按探针数扣费）；免费注册 Globalping（GitHub 登录）领 Token 可翻倍至 **`500` 次 / 小时**。
- **服务器流量**：TCP 握手探测仅收发 3 个 SYN/ACK 包即断（不触发 TLS 握手与回落抓网页），单次巡检总计仅 **`~3 KB`**。

| 巡检间隔 (`--interval`) | 每次探针数 | 每小时额度消耗 | 占免费 250 额度 | 预估月流量消耗 |
| :---: | :---: | :---: | :---: | :---: |
| **`90s`（默认推荐）** | 3（电信+联通+移动） | `120 / 250` | **48%**（留 130 给复核/切换） | `~86 MB / 月` |
| **`60s`** | 3（电信+联通+移动） | `180 / 250` | **72%**（留 70 给复核/切换） | `~130 MB / 月` |
| **`120s`** | 3（电信+联通+移动） | `90 / 250` | **36%** | `~65 MB / 月` |

---

## 前置准备

1. **确认 VPS 拥有可用 IPv6 `/64`**（能绑定额外 IPv6 地址并正常收发）：
   ```bash
   # 临时测试绑定第二个地址（替换成你的 /64 前缀）
   ip -6 addr add 2001:db8:abcd:1234::100/64 dev eth0 preferred_lft 0
   sleep 2
   curl -6 --interface 2001:db8:abcd:1234::100 -sS --max-time 6 https://api64.ipify.org; echo
   ip -6 addr del 2001:db8:abcd:1234::100/64 dev eth0
   ```
2. **代理服务端监听 `[::]:443`**（通配 IPv6，这样换 IP 时无需改配置或重启内核；建议配合 `--drop-v4-port` 用 `nftables` 屏蔽外部 IPv4 443）。
3. **Cloudflare API Token**：在 Cloudflare 控制台创建一个仅具备目标域名 `Zone -> DNS -> Edit` 最小权限的 API Token。

---

## 一键安装、升级与卸载

### 1. 交互式一键安装（自动识别网卡、`/64` 前缀、Cloudflare Zone 与 AAAA 记录）
```bash
curl -fsSL https://raw.githubusercontent.com/ashvvvvv/ipv6-watchdog/main/install.sh | sudo bash
```

### 2. 非交互式全参数一键安装（适合自动化部署）
```bash
curl -fsSL https://raw.githubusercontent.com/ashvvvvv/ipv6-watchdog/main/install.sh \
  | sudo bash -s -- \
  --cf-token "YOUR_CLOUDFLARE_TOKEN" \
  --domain "edge.example.com" \
  --port 443 \
  --interval 90s \
  --services "xray.service" \
  --drop-v4-port
```

可选附加参数：
- `--gp-token <token>`：传入 Globalping 免费 Token（额度翻倍至 500/小时）
- `--tg-token <bot_token> --tg-chat-id <chat_id>`：开启 Telegram 实时告警
- `--webhook-url <url>`：开启自定义 JSON Webhook 告警
- `--recheck-delay 10`：复测等待秒数（默认 `10`）
- `--fail-carriers 2`：触发阻断判定的最少失联运营商数（默认 `2`）

### 3. 一键升级（仅更新 `watchdog.py`，完整保留 `config.env` 与 `state.json`）
```bash
curl -fsSL https://raw.githubusercontent.com/ashvvvvv/ipv6-watchdog/main/install.sh | sudo bash -s -- --upgrade
```

### 4. 一键卸载
```bash
curl -fsSL https://raw.githubusercontent.com/ashvvvvv/ipv6-watchdog/main/install.sh | sudo bash -s -- --uninstall
```

---

## 日常运维命令

```bash
# 查看当前活跃 IPv6、最近巡检摘要、历史切换记录及 Globalping 剩余额度
/opt/ipv6-watchdog/watchdog.py --status

# 手动立即执行一次完整检测
/opt/ipv6-watchdog/watchdog.py --check

# 演练模式（仅打印决策，不改动网卡/DNS/服务）
/opt/ipv6-watchdog/watchdog.py --check --dry-run

# 手动立即轮换到一个全新验通的随机 IPv6
/opt/ipv6-watchdog/watchdog.py --force-switch

# 仅执行本地服务/网卡/防火墙自愈检查
/opt/ipv6-watchdog/watchdog.py --self-heal

# 查看定时巡检日志与定时器状态
journalctl -u ipv6-watchdog -n 30 --no-pager
systemctl list-timers ipv6-watchdog.timer
```

---

## 配置文件参考

配置文件位于 `/opt/ipv6-watchdog/config.env`（权限 `0600`），完整模板见 [config.env.example](config.env.example)。

若你使用 Xray + 外置面板伴生壳（如 `mini-agent-shell`），还可在 `config.env` 中追加以下 3 行，开启「入站用户意外归零自动重同步」保护：

```ini
XRAY_API_ADDR=127.0.0.1:10085
XRAY_INBOUND_TAGS=vless-101-in,vless-102-in
XRAY_SIDECAR_SERVICE=mini-agent-shell.service
```

---

## 本地测试

```bash
python3 -m unittest discover -v
bash -n install.sh
```

## License

[MIT](LICENSE)
