# IP 端口测速器

[![Release](https://github.com/mackolzjj/ip-port-tester/actions/workflows/release.yml/badge.svg)](https://github.com/mackolzjj/ip-port-tester/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/mackolzjj/ip-port-tester)](https://github.com/mackolzjj/ip-port-tester/releases)
[![License](https://img.shields.io/github/license/mackolzjj/ip-port-tester)](LICENSE)

对一批 `IP:端口` 做**纯 TCP 握手**探测，筛出真正连得上、延迟低、抖动小的节点，按耗时排序导出可直接贴回配置的列表。

不 TLS 握手、不发 HTTP 请求、不解析任何应用层协议——它衡量的是网络层可达性，所以结果和你后面跑什么协议无关。

![深色界面](https://cdn.jsdelivr.net/gh/mackolzjj/ip-port-tester@main/docs/screenshot-dark.jpg)

<details>
<summary>浅色主题</summary>

![浅色界面](https://cdn.jsdelivr.net/gh/mackolzjj/ip-port-tester@main/docs/screenshot-light.jpg)

</details>

## 特性

- **纯 TCP 探测**：连上即关，不占对端资源，也不受协议差异影响
- **多次采样**：最快值、均值、中位数、**抖动（max−min）**、成功率，一眼分出「快而稳」和「快但飘」
- **环境自检**：对样本 IP 连一个必不通的「对照端口」，若它也连通，说明本机代理/TUN 在替目标回 SYN，整轮结果标记为不可信
- **假阳性标记**：公网 IP 握手 < 10ms 单独标「可疑」
- **与上次对比**：新增 / 丢失 / 保持，逐行显示延迟变化 ±ms
- **失败自动重试**：首轮失败的节点用 次数×2、超时×1.5 再跑一遍，抖动弹回来的会被捞回
- **批量输入**：`IP:端口#地区#延迟`、纯 IP、IP 段 `192.168.1.1-20`、CIDR `10.0.0.0/28`
- **多端口**：一个 IP 自动展开成多个端口（`443,8443,8000-8010`）
- **导出**：`ip_speed.txt`（可用节点，按延迟升序）+ `ip_speed_detail.csv`（全量明细）
- **深浅主题**、CSV 回导继续测、局域网口令认证

## 运行

### 方式一：直接用 exe（Windows）

从 [Releases](../../releases) 下载 `IPPortTester.exe`，双击即可。

- `一键测速.bat` —— 仅本机访问（`127.0.0.1:8765`），不需要口令
- `局域网访问.bat` —— 局域网可访问（`0.0.0.0:8765`），首次自动生成 `token.txt` 作为登录口令

### 方式二：Python

只需要 Python 3.9+，无第三方依赖：

```bash
python ip_tester.py                 # 起网页界面，默认 http://127.0.0.1:8765
python ip_tester.py --host 0.0.0.0  # 局域网可访问（自动启用口令认证）
python ip_tester.py --cli ip.txt    # 命令行模式，直接出文件
```

命令行参数：

| 参数 | 说明 |
|---|---|
| `--host` | 监听地址，默认 `127.0.0.1`；`0.0.0.0` 表示局域网（自动生成口令） |
| `--port` | HTTP 端口，默认 8765 |
| `--cli FILE` | 命令行模式，测完导出 |
| `--workers` | 并发连接数，默认 32 |
| `--timeout` | 单次连接超时（秒），默认 2.0 |
| `--repeat` | 每节点采样次数，默认 3 |
| `--force-port` | 强制端口，覆盖输入行里的端口 |
| `--ports` | 端口集合，每个 IP 展开多个端口，如 `443,8443,8000-8010` |
| `--no-retry` | 关闭失败节点自动重试 |
| `--history N` | 保留最近 N 份带时间戳的历史副本（0=只留最新） |
| `--idle-exit` | 秒：这么久没有请求就退出（0=不退出） |

## 部署到服务器

放到 VPS / 内网服务器上常驻，完整说明见 **[docs/DEPLOY.md](docs/DEPLOY.md)**。

**Docker（最省事）**

```bash
git clone https://github.com/mackolzjj/ip-port-tester.git
cd ip-port-tester
cp .env.example .env          # 改掉里面的 IPTESTER_TOKEN
mkdir -p output
docker compose up -d --build
```

浏览器打开 `http://服务器IP:8765`，用户名随意，口令填 `.env` 里那个。

**systemd（不用 Docker）**

```bash
python3 ip_tester.py --host 0.0.0.0 --port 8765 --keep-alive --no-browser
```

要点：必须加 `--keep-alive`，否则最后一个页面关掉服务会自己退出。`deploy/iptester.service` 是现成的单元文件。

## 输入格式

```
1.2.3.4:443#HK#120         IP:端口#地区#原始延迟（后两段可省略）
5.6.7.8                   纯 IP，默认端口 443
9.10.11.12:8443           指定端口
192.168.1.1-20#LAN        IP 段
10.0.0.0/28               CIDR（自动跳过网络地址与广播）
```

端口集合与 IP 段会做笛卡尔积；单行最多展开 4096 个地址，整份列表上限 8192 个节点。

## 输出

```
output/
  ip_speed.txt                 可用节点，按握手耗时升序，可直接贴回配置
  ip_speed_detail.csv          全量明细（含失败原因、抖动、趋势、是否重试）
```

CSV 列：

```
node,host,port,region,ref_ms,connect_ms,avg_ms,jitter_ms,p50_ms,
tries,ok_count,success_rate,status,error,delta_ms,trend,retried,suspect,ok
```

`trend` 为 `new`（上次不通这次通）/ `lost`（上次通这次不通）/ `kept`（两次都通）。

## 关于「可疑」

工具会在开始前做一次环境自检：拿 3 个样本 IP，连一个几乎不可能开放的端口（默认 45123）。

- 都连不上 → 结果可信
- **有任何一个连上了** → 说明本机代理的 TUN / 增强模式在本地替目标回了 SYN，此时所有「端口开放」都是假的

出现这种提示时，先关掉代理的 TUN 模式再测，否则整轮数据没有意义。

## 界面源码

`ip_tester.py` 里的 `INDEX_HTML` 是内嵌的界面（单文件部署）。`ui.html` 是可编辑的源文件，改完需要重新注入：

```python
from pathlib import Path
html = Path("ui.html").read_text(encoding="utf-8")
src = Path("ip_tester.py").read_text(encoding="utf-8")
start = src.index('INDEX_HTML = r"""')
end = src.index('"""', start + len('INDEX_HTML = r"""'))
Path("ip_tester.py").write_text(
    src[:start] + 'INDEX_HTML = r"""' + html + '"""' + src[end + 3:], encoding="utf-8")
```

## 打包成单文件 exe

```bash
pip install pyinstaller
python -m PyInstaller --onefile --noconsole --name IPPortTester \
  --distpath dist --workpath build_tmp --specpath build_tmp --noconfirm --clean ip_tester.py
```

首次启动慢 1–2 秒（onefile 要解包），部分杀软可能误报，加白名单即可。

## 安全

- 仅监听 `127.0.0.1` 时不启用认证
- 监听 `0.0.0.0` 时自动生成 16 位口令，存于同目录 `token.txt`（也可用环境变量 `IPTESTER_TOKEN` 覆盖）
- 校验 `Origin` 与 `Host` 一致，拒绝其它网站的跨站请求（防 CSRF / DNS rebinding）

## 发版

推送 `v*` 开头的标签即可，GitHub Actions 会自动打包并发布：

```bash
git tag v4.2 && git push origin v4.2
```

CI 流程（`.github/workflows/release.yml`）：

1. `windows-latest` + Python 3.12 + PyInstaller 打包单文件 exe
2. **冒烟测试**：启动 exe → 请求 `/api/version` → 失败则整轮中止
3. 生成 `CHECKSUM.txt`（大小 + SHA256）
4. 上传 workflow artifact，并在标签触发时发布到 Release

也可以在 Actions 页面手动 `workflow_dispatch` 只构建、不发布。

## License

MIT
