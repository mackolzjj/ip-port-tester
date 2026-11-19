#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 端口测速器 v4 —— 单文件，仅依赖 Python 标准库。

做什么：对一批 IP:端口 做纯 TCP 连接（不 TLS、不发 HTTP、不解析应用层），
        多次采样后给出「是否可达 / 握手耗时 / 成功率」，并按耗时排序导出可用的那批。

用法：
  python ip_tester_v4.py                  # 起网页界面（默认 http://127.0.0.1:8765）
  python ip_tester_v4.py --host 0.0.0.0   # 局域网可访问（建议同时设 IPTESTER_TOKEN）
  python ip_tester_v4.py --cli ip.txt     # 命令行模式，测完直接出文件

输入格式（后两段可省略，也支持纯 IP / 域名）：
  IP:端口#地区#原始延迟
  1.2.3.4:443#HK#120

输出（默认 ./output）：
  ip_speed.txt          可用节点，按握手耗时升序，可直接贴回配置
  ip_speed_detail.csv   全量明细（含失败原因与上次对比）

环境自检：对样本 IP 连一个几乎不可能开放的「对照端口」。
  若对照端口也连得上，说明本机代理 / TUN 在网络层替目标回了 SYN，
  此时的「端口开放」全是假阳性，整轮结果会被标记为不可信。
"""
from __future__ import annotations

import argparse
import base64
import csv
import hmac
import ipaddress
import json
import re
import socket
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

APP_TAG = "ip-port-tester"
IDLE_EXIT = 0            # >0：这么多秒没有请求就退出（兜底）
BYE_GRACE = 3.0          # 收到「页面关闭」通知后的宽限期：期间有新请求=刷新，取消退出
_LAST_REQ = [time.time()]
_BYE_AT = [0.0]          # >0 表示已收到 bye
_WS_CLIENTS = [0]        # 当前连着几个页面
_WS_GONE_AT = [0.0]      # 最后一个页面断开的时间
_WS_LOCK = threading.Lock()
VERSION = "4.3"
def _app_dir() -> Path:
    """冻结成 exe 后 __file__ 指向临时解包目录，必须用 exe 所在目录，
    否则输出文件和缓存会被写进 %TEMP% 并在退出时消失。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


HERE = _app_dir()
CACHE_FILE = HERE / "last_result.json"
UPLOAD_FILE = HERE / "uploaded_ip.txt"
DEFAULT_OUT = HERE / "output"
TOKEN_FILE = HERE / "token.txt"
AUTH_TOKEN = __import__("os").environ.get("IPTESTER_TOKEN", "").strip()

HISTORY_KEEP = 0        # CLI 模式下保留多少份历史副本
NO_RETRY = False        # CLI --no-retry
SUSPECT_MS = 10          # 公网 IP 握手快于此值 ≈ 本地假应答
DEFAULT_PORT = 443

DEFAULTS = {"workers": 32, "timeout": 2.0, "repeat": 3, "port_override": "",
            "control_port": 45123, "ports": "", "history": 0, "retry": 1}
LIMITS = {"workers": (1, 256), "repeat": (1, 10), "timeout": (0.2, 30.0)}
LINE_RE = re.compile(r"^\s*(\S+?):(\d+)\s*(?:#(.*))?\s*$")


@dataclass
class Node:
    raw: str
    host: str
    port: int
    region: str = ""
    ref_ms: int | None = None


# ────────────────────────────── 解析 ──────────────────────────────
def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", host))


MAX_EXPAND_PER_LINE = 4096      # 单行最多展开多少个地址
MAX_NODES = 8192                # 整份列表上限，防止手滑写 /8


def expand_host_spec(spec: str) -> list[str]:
    """支持 CIDR 与末位区间：10.0.0.0/28、192.168.1.1-20、192.168.1.1-192.168.1.20"""
    spec = spec.strip()
    if not spec:
        return []
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return []
        if net.num_addresses > MAX_EXPAND_PER_LINE:
            return []
        hosts = list(net.hosts()) or [net.network_address]
        return [str(h) for h in hosts[:MAX_EXPAND_PER_LINE]]
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})", spec)
    if not m:
        return []
    start, end = m.group(1), m.group(2)
    try:
        a = int(ipaddress.ip_address(start))
        if "." in end:
            b = int(ipaddress.ip_address(end))
        else:
            b = int(ipaddress.ip_address(start.rsplit(".", 1)[0] + "." + end))
    except ValueError:
        return []
    if b < a or b - a + 1 > MAX_EXPAND_PER_LINE:
        return []
    return [str(ipaddress.ip_address(i)) for i in range(a, b + 1)]


def parse_nodes(text: str, port_override="", default_port: int = DEFAULT_PORT) -> list[Node]:
    override = int(port_override) if str(port_override).strip().isdigit() else None
    nodes: list[Node] = []
    seen: set[tuple[str, int]] = set()
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith(("#", "//", ";")):
            continue
        m = LINE_RE.match(s)
        if m:
            host, tail = m.group(1), (m.group(3) or "")
            port = override or int(m.group(2))
            raw = s
        else:
            head, _, tail = s.partition("#")
            host = head.strip()
            hosts_expanded = expand_host_spec(host) if ("/" in host or "-" in host) else []
            if hosts_expanded:
                for h in hosts_expanded:
                    if len(nodes) >= MAX_NODES:
                        break
                    key = (h, override or default_port)
                    if key in seen:
                        continue
                    seen.add(key)
                    port_e = override or default_port
                    raw_e = f"{h}:{port_e}" + (f"#{tail.strip()}" if tail.strip() else "")
                    parts_e = [p.strip() for p in tail.split("#")]
                    region_e = parts_e[0] if parts_e and parts_e[0] else ""
                    ref_e = next((int(p) for p in parts_e[1:] if p.isdigit()), None)
                    nodes.append(Node(raw=raw_e, host=h, port=port_e, region=region_e, ref_ms=ref_e))
                continue
            if not _valid_host(host):
                continue
            port = override or default_port
            raw = f"{host}:{port}" + (f"#{tail.strip()}" if tail.strip() else "")
        parts = [p.strip() for p in tail.split("#")]
        region = parts[0] if parts and parts[0] else ""
        ref = next((int(p) for p in parts[1:] if p.isdigit()), None)
        if len(nodes) >= MAX_NODES:
            break
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(Node(raw=raw, host=host, port=port, region=region, ref_ms=ref))
    return nodes


def parse_ports(spec: str) -> list[int]:
    """'443,8443 2053,8000-8010' → [443, 8443, 2053, 8000..8010]"""
    out: list[int] = []
    for chunk in re.split(r"[,\s]+", (spec or "").strip()):
        if not chunk:
            continue
        m = re.fullmatch(r"(\d{1,5})-(\d{1,5})", chunk)
        if m:
            lo, hi = sorted((int(m.group(1)), int(m.group(2))))
            out.extend(range(lo, min(hi, 65535) + 1))
        elif chunk.isdigit():
            out.append(int(chunk))
    seen, uniq = set(), []
    for p in out:
        if 0 < p < 65536 and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def expand_ports(nodes: list[Node], ports: list[int]) -> list[Node]:
    """同一批 IP 展开成多个端口；端口集合优先于行内端口。"""
    if not ports:
        return nodes
    out: list[Node] = []
    seen: set[tuple[str, int]] = set()
    for n in nodes:
        for port in ports:
            if (n.host, port) in seen:
                continue
            seen.add((n.host, port))
            tail = "#" + "#".join(filter(None, [n.region, str(n.ref_ms) if n.ref_ms is not None else ""]))
            out.append(Node(raw=f"{n.host}:{port}{tail}", host=n.host, port=port,
                            region=n.region, ref_ms=n.ref_ms))
            if len(out) >= MAX_NODES:      # 解析阶段限的是 IP 数，乘上端口集合还要再兜一次
                return out
    return out


# ────────────────────────────── 探测 ──────────────────────────────
def err_name(exc: BaseException) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "连接超时"
    if isinstance(exc, ConnectionRefusedError):
        return "端口拒绝"
    if isinstance(exc, socket.gaierror):
        return "域名解析失败"
    if isinstance(exc, OSError):
        return "网络不可达"
    return type(exc).__name__


def connect_once(host: str, port: int, timeout: float) -> int:
    t0 = time.perf_counter()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return round((time.perf_counter() - t0) * 1000)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def is_public_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return True


def check_environment(cfg: dict, nodes: list[Node]) -> dict:
    port = int(cfg.get("control_port") or 0)
    env = {"checked": False, "control_port": port, "samples": 0,
           "false_accept": 0, "trust": "skipped", "note": "未启用对照端口自检"}
    if not port or not nodes:
        return env
    hosts: list[str] = []
    for n in nodes:
        if n.host not in hosts:
            hosts.append(n.host)
    if len(hosts) > 3:
        hosts = [hosts[0], hosts[len(hosts) // 2], hosts[-1]]
    tmo = min(cfg["timeout"], 1.5)
    accepted = 0
    with ThreadPoolExecutor(max_workers=max(1, len(hosts))) as ex:
        for fut in [ex.submit(connect_once, h, port, tmo) for h in hosts]:
            try:
                fut.result()
                accepted += 1
            except Exception:  # noqa: BLE001
                pass
    env.update(checked=True, samples=len(hosts), false_accept=accepted)
    if accepted:
        env["trust"] = "proxy"
        env["note"] = (f"对照端口 {port}（正常应不可达）在 {len(hosts)} 个样本里有 {accepted} 个连上了，"
                       "说明本机代理/TUN 在替你回 SYN，本轮「端口开放」不可信。"
                       "请关闭 TUN / 增强 / 透明代理后重测。")
    else:
        env["trust"] = "ok"
        env["note"] = f"环境自检通过：对照端口 {port} 在 {len(hosts)} 个样本上均不可达，本轮结果可信。"
    return env


def probe(node: Node, cfg: dict, stop: threading.Event) -> dict:
    times: list[int] = []
    errors: list[str] = []
    for _ in range(max(1, int(cfg["repeat"]))):
        if stop.is_set():
            break
        try:
            times.append(connect_once(node.host, node.port, cfg["timeout"]))
        except Exception as exc:  # noqa: BLE001
            errors.append(err_name(exc))
    tries = len(times) + len(errors)
    ok_count = len(times)
    if ok_count and ok_count == tries:
        status = "open"
    elif ok_count:
        status = "flaky"
    else:
        status = "closed"
    best = min(times) if times else None
    worst = max(times) if times else None
    jitter = (worst - best) if times else None
    p50 = sorted(times)[len(times) // 2] if times else None
    return {
        "raw": node.raw, "host": node.host, "port": node.port,
        "region": node.region, "ref_ms": node.ref_ms,
        "connect_ms": best,
        "avg_ms": round(sum(times) / len(times)) if times else None,
        "jitter": jitter,
        "p50": p50,
        "tries": tries, "ok_count": ok_count,
        "success_rate": round(ok_count / tries * 100) if tries else 0,
        "status": status,
        "error": max(set(errors), key=errors.count) if errors else "",
        "ok": ok_count > 0,
        "metric": best if best is not None else 99999,
        "delta": None,
        "suspect": bool(best is not None and best < SUSPECT_MS and is_public_host(node.host)),
    }


def sort_key(r: dict):
    return (not r.get("ok"), -r.get("ok_count", 0), r.get("metric", 99999))


def normalize_cfg(raw: dict) -> dict:
    cfg = dict(DEFAULTS)
    if raw:
        cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
    for key, (lo, hi) in LIMITS.items():
        try:
            cfg[key] = max(lo, min(hi, type(DEFAULTS[key])(cfg[key])))
        except (TypeError, ValueError):
            cfg[key] = DEFAULTS[key]
    cfg["port_override"] = str(cfg["port_override"] or "").strip()
    cfg["ports"] = str(cfg.get("ports") or "").strip()
    try:
        cfg["retry"] = 1 if str(cfg.get("retry", 1)) in ("1", "True", "true", "on") else 0
    except (TypeError, ValueError):
        cfg["retry"] = 1
    try:
        cfg["history"] = max(0, min(200, int(cfg.get("history") or 0)))
    except (TypeError, ValueError):
        cfg["history"] = 0
    try:
        cfg["control_port"] = max(0, min(65535, int(cfg["control_port"] or 0)))
    except (TypeError, ValueError):
        cfg["control_port"] = DEFAULTS["control_port"]
    return cfg


# ────────────────────────────── 缓存与导出 ──────────────────────────────
def load_last() -> dict | None:
    try:
        d = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if d.get("app") == APP_TAG and isinstance(d.get("results"), list):
            return d
    except Exception:  # noqa: BLE001
        pass
    return None


def save_last(cfg: dict, results: list[dict], files: dict, env: dict) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = {"app": APP_TAG, "version": VERSION, "ts": ts, "cfg": cfg,
               "files": files, "results": results, "env": env,
               "duration": round(getattr(STATE, "duration", 0.0), 1)}
    try:
        tmp = CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp.replace(CACHE_FILE)
    except Exception:  # noqa: BLE001
        pass
    return ts


def attach_trend(rec: dict, prev: dict) -> dict:
    """和上次比：新可用 / 保持可用 / 新失效 / 仍失效。"""
    old = prev.get(rec["raw"])
    if rec["ok"]:
        rec["trend"] = "kept" if (old and old.get("ok")) else "new"
    else:
        rec["trend"] = "lost" if (old and old.get("ok")) else ""
    return rec


def attach_delta(rec: dict, prev: dict) -> dict:
    old = prev.get(rec["raw"])
    if old and rec["ok"] and old.get("ok") and rec["connect_ms"] is not None \
            and old.get("connect_ms") is not None:
        rec["delta"] = rec["connect_ms"] - old["connect_ms"]
    return rec


def prune_history(out: Path, keep: int):
    """只保留最近 keep 份带时间戳的副本，其余删除（keep=0 时全删）。"""
    for pattern in ("ip_speed_2*.txt", "ip_speed_detail_2*.csv"):
        files = sorted(out.glob(pattern))
        for f in files[:max(0, len(files) - keep)]:
            try:
                f.unlink()
            except OSError:
                pass


def export_results(cfg: dict, results: list[dict], outdir: Path | None = None) -> dict:
    out = Path(outdir or DEFAULT_OUT).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    ok_rows = sorted([r for r in results if r["ok"]], key=sort_key)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    keep = int(cfg.get("history") or 0)
    body = "\n".join(r["raw"] for r in ok_rows) + ("\n" if ok_rows else "")
    names = ["ip_speed.txt"] + ([f"ip_speed_{ts}.txt"] if keep else [])
    for name in names:
        (out / name).write_text(body, encoding="utf-8")
    fields = ["node", "host", "port", "region", "ref_ms", "connect_ms", "avg_ms",
              "jitter_ms", "p50_ms", "tries", "ok_count", "success_rate", "status",
              "error", "delta_ms", "trend", "retried", "suspect", "ok"]
    detail_names = ["ip_speed_detail.csv"] + ([f"ip_speed_detail_{ts}.csv"] if keep else [])
    for name in detail_names:
        with (out / name).open("w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(fields)
            for r in sorted(results, key=sort_key):
                w.writerow([r["raw"], r["host"], r["port"], r["region"],
                            r["ref_ms"] if r["ref_ms"] is not None else "",
                            r["connect_ms"] if r["connect_ms"] is not None else "",
                            r["avg_ms"] if r["avg_ms"] is not None else "",
                            r.get("jitter") if r.get("jitter") is not None else "",
                            r.get("p50") if r.get("p50") is not None else "",
                            r["tries"], r["ok_count"], r["success_rate"], r["status"],
                            r["error"], r.get("delta") if r.get("delta") is not None else "",
                            r.get("trend", ""), int(bool(r.get("retried"))),
                            int(bool(r.get("suspect"))), int(r["ok"])])
    if keep:
        prune_history(out, keep)
    return {"outdir": str(out), "txt": str(out / "ip_speed.txt"),
            "csv": str(out / "ip_speed_detail.csv"),
            "ok_count": len(ok_rows), "fail_count": len(results) - len(ok_rows)}


# ────────────────────────────── 状态 ──────────────────────────────
class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.running = False
        self.done = 0
        self.total = 0
        self.results: list[dict] = []
        self.message = "就绪"
        self.cfg = dict(DEFAULTS)
        self.files: dict = {}
        self.env: dict = {}
        self.started_at = 0.0
        self.finished_ts = ""
        self.duration = 0.0     # 结束后保留总耗时，页面刷新也看得到

    def reset(self, total: int, cfg: dict):
        with self.lock:
            self.running = True
            self.stop.clear()
            self.done, self.total = 0, total
            self.results = []
            self.files = {}
            self.message = "正在测试…"
            self.cfg = cfg
            self.started_at = time.time()
            self.duration = 0.0
            self.finished_ts = ""
            self.env = {"checked": False, "trust": "checking",
                        "note": "正在做环境自检…", "control_port": cfg.get("control_port", 0)}

    def snapshot(self) -> dict:
        with self.lock:
            return {"running": self.running, "done": self.done, "total": self.total,
                    "message": self.message,
                    "results": sorted(self.results, key=sort_key),
                    "files": self.files, "env": self.env,
                    "elapsed": round(time.time() - self.started_at, 1) if self.running else round(self.duration, 1),
                    "finished_ts": self.finished_ts, "cfg": self.cfg, "version": VERSION}


STATE = State()


def bootstrap():
    """启动时载入上次结果，页面一打开就有内容，不必先重测一遍。"""
    d = load_last()
    if not d or not d.get("results"):
        return
    with STATE.lock:
        STATE.results = d["results"]
        STATE.cfg = normalize_cfg(d.get("cfg") or {})
        STATE.files = d.get("files") or {}
        STATE.env = d.get("env") or {}
        STATE.total = STATE.done = len(d["results"])
        STATE.duration = float(d.get("duration") or 0)
        STATE.finished_ts = d.get("ts", "")
        STATE.message = f"已载入上次结果（{d.get('ts', '')}）· 共 {len(d['results'])} 个节点"


def run_job(text: str, cfg: dict):
    nodes = expand_ports(parse_nodes(text, cfg.get("port_override", "")),
                         parse_ports(cfg.get("ports", "")))
    if not nodes:
        with STATE.lock:
            STATE.running = False
            STATE.message = "没有解析到有效节点，检查格式：IP:端口#地区#延迟"
        return

    prev = {r["raw"]: r for r in (load_last() or {}).get("results", [])}
    STATE.reset(len(nodes), cfg)
    try:
        env = check_environment(cfg, nodes)
    except Exception as exc:  # noqa: BLE001
        env = {"checked": False, "trust": "unknown", "note": f"环境自检失败：{exc}",
               "control_port": 0, "samples": 0, "false_accept": 0}
    with STATE.lock:
        STATE.env = env

    executor = ThreadPoolExecutor(max_workers=cfg["workers"])
    futs = {executor.submit(probe, n, cfg, STATE.stop): n for n in nodes}
    try:
        for fut in as_completed(futs):
            if STATE.stop.is_set():
                break
            node = futs[fut]
            try:
                rec = attach_trend(attach_delta(fut.result(), prev), prev)
            except Exception as exc:  # noqa: BLE001
                rec = {"raw": node.raw, "host": node.host, "port": node.port,
                       "region": node.region, "ref_ms": node.ref_ms,
                       "connect_ms": None, "avg_ms": None, "tries": 0, "ok_count": 0,
                       "success_rate": 0, "status": "closed", "error": err_name(exc),
                       "ok": False, "metric": 99999, "delta": None, "suspect": False}
            with STATE.lock:
                STATE.results.append(rec)
                STATE.done += 1
                STATE.message = f"已测 {STATE.done}/{STATE.total} · {rec['raw']}"
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    # ── 失败节点自动重试一轮：抖动造成的假失效，靠更高的次数和更宽的超时捞回来
    if cfg.get("retry") and not STATE.stop.is_set():
        with STATE.lock:
            failed = [r for r in STATE.results if not r["ok"]]
            idx = {r["raw"]: i for i, r in enumerate(STATE.results)}
            if failed:
                STATE.total += len(failed)
                STATE.message = f"重试 {len(failed)} 个失败节点…"
        if failed:
            cfg2 = {**cfg, "repeat": min(10, int(cfg["repeat"]) * 2),
                    "timeout": min(30.0, float(cfg["timeout"]) * 1.5)}
            nodes2 = [n for n in nodes if n.raw in {r["raw"] for r in failed}]
            ex2 = ThreadPoolExecutor(max_workers=max(4, min(cfg["workers"], len(nodes2))))
            try:
                futs2 = {ex2.submit(probe, n, cfg2, STATE.stop): n for n in nodes2}
                for fut in as_completed(futs2):
                    if STATE.stop.is_set():
                        break
                    node = futs2[fut]
                    try:
                        rec2 = attach_trend(attach_delta(fut.result(), prev), prev)
                    except Exception:  # noqa: BLE001
                        continue
                    rec2["retried"] = True
                    with STATE.lock:
                        if rec2["ok"] and node.raw in idx:
                            STATE.results[idx[node.raw]] = rec2
                        elif node.raw in idx:
                            STATE.results[idx[node.raw]]["retried"] = True
                        STATE.done += 1
                        STATE.message = f"重试 {STATE.done}/{STATE.total} · {node.raw}"
            finally:
                ex2.shutdown(wait=False, cancel_futures=True)

    with STATE.lock:
        results = list(STATE.results)
        aborted = STATE.stop.is_set()
    files = export_results(cfg, results) if results else {}
    ts = save_last(cfg, results, files, env) if results else ""
    with STATE.lock:
        STATE.running = False
        STATE.duration = time.time() - STATE.started_at
        STATE.files = files
        STATE.finished_ts = ts
        ok = sum(1 for r in results if r["ok"])
        STATE.message = ("已停止 · " if aborted else "完成 · ") + f"可用 {ok} / 共 {len(results)}"


def retest_job(node: Node, cfg: dict):
    """单个节点复测：就地替换这一行，不动其它结果。"""
    with STATE.lock:
        STATE.running = True
        STATE.stop.clear()
        STATE.message = f"复测 {node.raw}…"
        STATE.started_at = time.time()
    try:
        rec = probe(node, cfg, STATE.stop)
    except Exception as exc:  # noqa: BLE001
        rec = {"raw": node.raw, "host": node.host, "port": node.port, "region": node.region,
               "ref_ms": node.ref_ms, "connect_ms": None, "avg_ms": None, "tries": 0,
               "ok_count": 0, "success_rate": 0, "status": "closed", "error": err_name(exc),
               "ok": False, "metric": 99999, "delta": None, "suspect": False}
    prev = {r["raw"]: r for r in (load_last() or {}).get("results", [])}
    rec = attach_delta(rec, prev)
    with STATE.lock:
        STATE.results = [r for r in STATE.results if r["raw"] != rec["raw"]] + [rec]
        STATE.done = STATE.total = len(STATE.results)
        STATE.running = False
        STATE.duration = time.time() - STATE.started_at
        STATE.message = f"复测完成 · {rec['raw']} · {rec['connect_ms'] or '—'} ms"
    files = export_results({**cfg, "history": 0}, list(STATE.results))
    save_last(cfg, list(STATE.results), files, STATE.env)
    with STATE.lock:
        STATE.files = files


# ────────────────────────────── HTTP ──────────────────────────────
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept_key(key: str) -> str:
    import hashlib
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def ws_read_frame(sock) -> tuple[int, bytes]:
    """读一帧：返回 (opcode, payload)。对端关闭返回 (-1, b"")。"""
    head = sock.recv(2)
    if len(head) < 2:
        return -1, b""
    opcode = head[0] & 0x0F
    masked = head[1] & 0x80
    ln = head[1] & 0x7F
    if ln == 126:
        ln = int.from_bytes(sock.recv(2), "big")
    elif ln == 127:
        ln = int.from_bytes(sock.recv(8), "big")
    mask = sock.recv(4) if masked else b""
    data = b""
    while len(data) < ln:
        chunk = sock.recv(min(ln - len(data), 8192))
        if not chunk:
            return -1, b""
        data += chunk
    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def ws_write(sock, opcode: int, payload: bytes = b""):
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + n.to_bytes(2, "big")
    else:
        head += bytes([127]) + n.to_bytes(8, "big")
    try:
        sock.sendall(head + payload)
    except OSError:
        pass


class Server(ThreadingHTTPServer):
    """Windows 上 allow_reuse_address=1 会允许两个进程绑同一端口（127.0.0.1 与 0.0.0.0 可以共存），
    表现就是「改了代码却测到老进程」。这里关掉，端口被占就直接报错退出。"""
    allow_reuse_address = False
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "IPPortTester/" + VERSION
    protocol_version = "HTTP/1.1"      # WebSocket 要求 1.1，且所有响应都带 Content-Length

    def log_message(self, fmt, *args):
        pass

    def _touch(self):
        _LAST_REQ[0] = time.time()

    def _send(self, code: int, body: bytes = b"", ctype="application/json; charset=utf-8",
              extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _auth_ok(self) -> bool:
        if not AUTH_TOKEN:
            return True
        head = self.headers.get("Authorization", "")
        if not head.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(head[6:]).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            return False
        _, _, pw = raw.partition(":")
        return hmac.compare_digest(pw, AUTH_TOKEN)

    def _need_auth(self):
        self._send(401, b"", "text/plain; charset=utf-8",
                   {"WWW-Authenticate": 'Basic realm="IP Port Tester"'})

    def _ws_serve(self):
        """极简 WebSocket：只用来感知「页面还在不在」。
        浏览器进程一死 / 标签页一关，TCP 立刻断，服务端当场知道。"""
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key or self.headers.get("Upgrade", "").lower() != "websocket":
            return self._send(400, b"bad websocket request", "text/plain; charset=utf-8")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept_key(key))
        self.end_headers()
        sock = self.connection
        with _WS_LOCK:
            _WS_CLIENTS[0] += 1
            _WS_GONE_AT[0] = 0.0
        try:
            sock.settimeout(None)
            while True:
                opcode, payload = ws_read_frame(sock)
                if opcode < 0 or opcode == 0x8:      # EOF / close
                    break
                if opcode == 0x9:                    # ping → pong
                    ws_write(sock, 0xA, payload)
        except OSError:
            pass
        finally:
            with _WS_LOCK:
                _WS_CLIENTS[0] = max(0, _WS_CLIENTS[0] - 1)
                if _WS_CLIENTS[0] == 0:
                    _WS_GONE_AT[0] = time.time()
            self.close_connection = True

    def _same_origin_ok(self) -> bool:
        """挡住别的网站偷偷 POST 到 127.0.0.1:8765（CSRF / DNS rebinding）。
        直接访问、curl、局域网访问都不带 Origin 或带同源 Origin，不受影响。"""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = (self.headers.get("Host") or "").lower()
        try:
            from urllib.parse import urlparse as _up
            return (_up(origin).netloc or "").lower() == host
        except Exception:  # noqa: BLE001
            return False

    def _body_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > 8 * 1024 * 1024:
                return {}
            return json.loads(self.rfile.read(n).decode("utf-8", "ignore") or "{}")
        except Exception:  # noqa: BLE001
            return {}

    def do_GET(self):  # noqa: N802
        self._touch()
        if not self._auth_ok():
            return self._need_auth()
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        if path == "/api/state":
            return self._json(STATE.snapshot())
        if path == "/api/download":
            name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
            if name not in ("ip_speed.txt", "ip_speed_detail.csv"):
                return self._json({"error": "不支持的文件名"}, 400)
            f = DEFAULT_OUT / name
            if not f.is_file():
                return self._json({"error": "还没有生成结果文件"}, 404)
            ctype = "text/plain; charset=utf-8" if name.endswith(".txt") else "text/csv; charset=utf-8"
            return self._send(200, f.read_bytes(), ctype,
                              {"Content-Disposition": f'attachment; filename="{name}"'})
        if path == "/ws":
            return self._ws_serve()
        if path == "/api/bye":
            if not STATE.running:
                _BYE_AT[0] = time.time()
            return self._json({"ok": True})
        if path == "/api/ping":
            return self._json({"ok": True, "running": STATE.running})
        if path == "/api/version":
            return self._json({"app": APP_TAG, "version": VERSION})
        return self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        self._touch()
        if not self._same_origin_ok():
            return self._json({"error": "跨站请求被拒绝"}, 403)
        if not self._auth_ok():
            return self._need_auth()
        path = urlparse(self.path).path
        if path == "/api/bye":          # sendBeacon 是 POST
            if not STATE.running:
                _BYE_AT[0] = time.time()
            return self._json({"ok": True})
        if path == "/api/start":
            if STATE.running:
                return self._json({"error": "已经在测，先停掉再开始"}, 409)
            body = self._body_json()
            text = str(body.get("text") or "")
            cfg = normalize_cfg(body.get("cfg") or {})
            nodes = expand_ports(parse_nodes(text, cfg["port_override"]),
                                 parse_ports(cfg.get("ports", "")))
            if not nodes:
                return self._json({"error": "没有解析到有效节点"}, 400)
            try:
                UPLOAD_FILE.write_text(text, encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
            threading.Thread(target=run_job, args=(text, cfg), daemon=True).start()
            return self._json({"ok": True, "nodes": len(nodes), "cfg": cfg})

        if path == "/api/retest":
            body = self._body_json()
            raw = str(body.get("raw") or "").strip()
            if not raw:
                return self._json({"error": "缺少节点"}, 400)
            if STATE.running:
                return self._json({"error": "正在测速中，稍后再复测"}, 409)
            cfg = normalize_cfg(body.get("cfg") or {})
            nodes = parse_nodes(raw, cfg["port_override"])
            if not nodes:
                return self._json({"error": "节点格式无法解析"}, 400)
            threading.Thread(target=retest_job, args=(nodes[0], cfg), daemon=True).start()
            return self._json({"ok": True, "nodes": 1})

        if path == "/api/stop":
            STATE.stop.set()
            return self._json({"ok": True})

        if path == "/api/upload":
            body = self._body_json()
            text = str(body.get("text") or "")
            nodes = parse_nodes(text)
            if not nodes:
                return self._json({"error": "文件里没有可用节点"}, 400)
            try:
                UPLOAD_FILE.write_text(text, encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
            return self._json({"ok": True, "nodes": len(nodes)})

        return self._send(404, b"not found", "text/plain; charset=utf-8")


# ────────────────────────────── 入口 ──────────────────────────────
def cli_main(path: str, workers: int, timeout: float, repeat: int,
             port: str = "", ports: str = "") -> int:
    cfg = normalize_cfg({"workers": workers, "timeout": timeout, "repeat": repeat,
                         "port_override": port, "ports": ports,
                         "history": HISTORY_KEEP, "retry": 0 if NO_RETRY else 1})
    text = Path(path).expanduser().read_text(encoding="utf-8-sig", errors="ignore")
    nodes = expand_ports(parse_nodes(text, cfg["port_override"]),
                         parse_ports(cfg.get("ports", "")))
    if not nodes:
        print("没有解析到有效节点")
        return 2
    print(f"开始测试 {len(nodes)} 个节点 · 并发 {cfg['workers']} · 每节点 {cfg['repeat']} 次")
    prev = {r["raw"]: r for r in (load_last() or {}).get("results", [])}
    stop = threading.Event()
    results = []
    with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
        futs = [ex.submit(probe, n, cfg, stop) for n in nodes]
        for i, fut in enumerate(as_completed(futs), 1):
            rec = attach_trend(attach_delta(fut.result(), prev), prev)
            results.append(rec)
            print(f"  {i}/{len(nodes)}  {rec['raw']:<30} {rec['connect_ms'] or '—'} ms")

    if cfg.get("retry") and any(not r["ok"] for r in results):
        dead = [n for n in nodes if any(r["raw"] == n.raw and not r["ok"] for r in results)]
        if dead:
            print(f"\n重试 {len(dead)} 个失败节点（次数×2、超时×1.5）…")
            cfg2 = {**cfg, "repeat": min(10, int(cfg["repeat"]) * 2),
                    "timeout": min(30.0, float(cfg["timeout"]) * 1.5)}
            idx = {r["raw"]: i for i, r in enumerate(results)}
            with ThreadPoolExecutor(max_workers=max(4, min(cfg["workers"], len(dead)))) as ex2:
                for fut in as_completed([ex2.submit(probe, n, cfg2, stop) for n in dead]):
                    try:
                        rec = attach_trend(attach_delta(fut.result(), prev), prev)
                    except Exception:  # noqa: BLE001
                        continue
                    rec["retried"] = True
                    if rec["ok"] and rec["raw"] in idx:
                        results[idx[rec["raw"]]] = rec
                        print(f"  抢救回: {rec['raw']}  {rec['connect_ms']} ms")
                    elif rec["raw"] in idx:
                        results[idx[rec["raw"]]]["retried"] = True
    files = export_results(cfg, results)
    save_last(cfg, results, files, {})     # CLI 也要写缓存，下次才有「与上次对比」
    ok = [r for r in results if r["ok"]]
    print(f"\n可用 {len(ok)} / 共 {len(results)}")
    print(f"  {files['txt']}\n  {files['csv']}")
    return 0


def resolve_token(need_auth: bool) -> tuple[str, str]:
    """决定这次运行的口令。

    优先级：环境变量 IPTESTER_TOKEN > token.txt > 新生成（仅局域网模式）。
    只监听本机时不做认证，避免每次自己用还要输密码。
    返回 (token, 说明)。
    """
    env = __import__("os").environ.get("IPTESTER_TOKEN", "").strip()
    if env:
        return env, "使用环境变量 IPTESTER_TOKEN"
    if not need_auth:
        return "", "仅监听本机，未启用认证"
    try:
        if TOKEN_FILE.is_file():
            saved = TOKEN_FILE.read_text(encoding="utf-8").strip()
            if saved:
                return saved, f"使用已有口令（{TOKEN_FILE.name}）"
    except OSError:
        pass
    import secrets
    token = secrets.token_urlsafe(12)
    try:
        TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
        note = f"已生成新口令并写入 {TOKEN_FILE.name}"
    except OSError as exc:
        note = f"已生成新口令（写入 {TOKEN_FILE.name} 失败：{exc}）"
    return token, note


def main() -> int:
    ap = argparse.ArgumentParser(description="IP 端口测速器 v4")
    ap.add_argument("--host", default=None,
                    help="监听地址，默认 127.0.0.1；用 0.0.0.0 供局域网访问（会自动启用口令）")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--cli", metavar="FILE", help="命令行模式：直接测这个文件")
    ap.add_argument("--workers", type=int, default=DEFAULTS["workers"])
    ap.add_argument("--timeout", type=float, default=DEFAULTS["timeout"])
    ap.add_argument("--repeat", type=int, default=DEFAULTS["repeat"])
    ap.add_argument("--force-port", dest="port_override", default="",
                    help="强制端口：覆盖输入行里的端口（默认 443）")
    ap.add_argument("--no-retry", action="store_true", help="关闭失败节点自动重试")
    ap.add_argument("--history", type=int, default=0,
                    help="保留最近 N 份带时间戳的历史副本（0=只留最新一份）")
    ap.add_argument("--ports", dest="ports", default="",
                    help="端口集合：每个 IP 展开成多个端口，如 443,8443,8000-8010")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--keep-alive", action="store_true",
                    help="常驻模式：不管有没有人开着页面都不退出（部署到服务器时用）")
    ap.add_argument("--idle-exit", type=int, default=None,
                    help="秒：这么久没有请求就自动退出（默认：本机模式 60，服务模式 0=不退出）")
    ap.add_argument("--version", action="version", version=f"ip_tester {VERSION}")
    args = ap.parse_args()

    global HISTORY_KEEP, NO_RETRY, AUTH_TOKEN
    HISTORY_KEEP = max(0, args.history)
    NO_RETRY = bool(args.no_retry)

    env_host = __import__("os").environ.get("IPTESTER_HOST", "").strip()
    host = args.host or env_host or ("0.0.0.0" if AUTH_TOKEN else "127.0.0.1")
    args.host = host
    lan = host not in ("127.0.0.1", "localhost", "::1")
    AUTH_TOKEN, token_note = resolve_token(lan)

    if args.cli:
        return cli_main(args.cli, args.workers, args.timeout, args.repeat,
                        args.port_override, args.ports)

    bootstrap()
    try:
        httpd = Server((args.host, args.port), Handler)
    except OSError as exc:
        msg = (f"端口 {args.port} 已被占用。\n\n"
               "多半是上一次的程序还在跑。\n"
               "请在任务管理器结束「一键测速IP.exe」，或稍后重试。\n\n"
               f"（{exc}）")
        print("\n[错误] " + msg)
        try:  # exe 是 --noconsole，控制台输出看不到，弹个框更实在
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, msg, "一键测速IP · 启动失败", 0x10)
        except Exception:  # noqa: BLE001
            pass
        return 3
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}/"
    print(f"IP 端口测速器 v{VERSION}")
    print(f"  地址: {url}")
    print(f"  认证: {'Basic（用户名任意，口令见下）' if AUTH_TOKEN else '关闭（仅本机）'}")
    if AUTH_TOKEN:
        print(f"  口令: {AUTH_TOKEN}   ← {token_note}")
        print(f"  访问: http://<本机IP>:{args.port}/  浏览器会弹登录框，用户名随便填")
    print(f"  输出: {DEFAULT_OUT}")
    print("  Ctrl+C 退出")
    global IDLE_EXIT
    if args.keep_alive:
        args.idle_exit = 0
    if args.idle_exit is None:
        # 本机模式给个兜底：浏览器被强杀时页面来不及发消息，只能靠超时退出；
        # 服务模式（有口令）不退，避免把常驻服务关掉。
        args.idle_exit = 0 if AUTH_TOKEN else 60
    IDLE_EXIT = max(0, args.idle_exit)

    def _watch():
        while True:
            time.sleep(1)
            if STATE.running:            # 测试进行中不退出
                _LAST_REQ[0] = time.time()
                _BYE_AT[0] = 0.0
                continue
            now = time.time()
            with _WS_LOCK:
                clients = _WS_CLIENTS[0]
                gone_at = _WS_GONE_AT[0]
            if IDLE_EXIT > 0 and clients == 0 and gone_at and now - gone_at >= 2.5:
                print("\n页面已断开（WebSocket 关闭），退出")
                __import__("os")._exit(0)
            if _BYE_AT[0] and now - _BYE_AT[0] >= BYE_GRACE and _LAST_REQ[0] <= _BYE_AT[0]:
                print("\n页面已关闭，退出")
                __import__("os")._exit(0)
            if IDLE_EXIT and now - _LAST_REQ[0] > IDLE_EXIT:
                print(f"\n空闲 {IDLE_EXIT}s，自动退出")
                __import__("os")._exit(0)

    threading.Thread(target=_watch, daemon=True).start()

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已退出")
    finally:
        httpd.server_close()
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP 端口测速器</title>
<style>
  :root{
    --bg:#0b0e14; --panel:#12161f; --panel2:#171c27; --line:#232a38;
    --txt:#e7ebf3; --dim:#8b93a7; --accent:#5b8cff; --ok:#34d399; --warn:#fbbf24; --bad:#f87171;
  }
  :root[data-theme="light"]{
    --bg:#f5f7fb; --panel:#ffffff; --panel2:#eef2f8; --line:#dde3ec;
    --txt:#18202e; --dim:#5b6676; --accent:#2563eb;
    --ok:#0b8a4b; --warn:#a16207; --bad:#c62828;
  }
  :root[data-theme="light"] .toast{background:#fff;border-color:var(--line);color:var(--txt)}
  :root[data-theme="light"] tbody tr:hover{background:rgba(0,0,0,.03)}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font:14px/1.55 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif}
  .wrap{max-width:1180px;margin:0 auto;padding:22px 18px 60px}
  header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
  h1{font-size:19px;margin:0;font-weight:650;letter-spacing:.2px}
  .tag{font-size:11px;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:2px 9px}
  .spacer{flex:1}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px}
  .card h2{font-size:13px;margin:0 0 10px;color:var(--dim);font-weight:600;letter-spacing:.3px}
  textarea{width:100%;min-height:150px;resize:vertical;background:var(--panel2);color:var(--txt);
           border:1px solid var(--line);border-radius:10px;padding:12px;font:13px/1.6 ui-monospace,Consolas,monospace}
  .drop{border:1px dashed var(--line);border-radius:10px;padding:10px;color:var(--dim);font-size:12px;
        display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
  .drop.hot{border-color:var(--accent);color:var(--txt)}
  .row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
  label{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--dim)}
  input[type=number],input[type=text]{background:var(--panel2);color:var(--txt);border:1px solid var(--line);
        border-radius:8px;padding:7px 9px;width:110px;font-size:13px}
  button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:9px;
         padding:8px 14px;font-size:13px;cursor:pointer;transition:.15s}
  button:hover{border-color:#39445c}
  button.primary{background:var(--accent);border-color:var(--accent);color:#08101f;font-weight:650}
  button.danger{color:var(--bad);border-color:#41232a}
  button.factive{border-color:var(--accent);color:var(--accent)}
  button:disabled{opacity:.45;cursor:not-allowed}
  .bar{height:8px;background:var(--panel2);border-radius:999px;overflow:hidden;margin:10px 0 8px}
  .bar>i{display:block;height:100%;width:0;background:linear-gradient(90deg,#5b8cff,#34d399);transition:width .2s}
  .meta{display:flex;gap:16px;flex-wrap:wrap;font-size:12px;color:var(--dim)}
  .env{border-radius:10px;padding:10px 12px;font-size:12.5px;margin-top:10px;border:1px solid}
  .env.ok{background:rgba(52,211,153,.08);border-color:rgba(52,211,153,.35)}
  .env.proxy{background:rgba(248,113,113,.08);border-color:rgba(248,113,113,.4)}
  .env.checking,.env.skipped,.env.unknown{background:rgba(251,191,36,.08);border-color:rgba(251,191,36,.35)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
  th{color:var(--dim);font-weight:600;font-size:12px;position:sticky;top:0;background:var(--panel);z-index:2}
  tbody tr:hover{background:rgba(255,255,255,.025)}
  .pill{border-radius:999px;padding:1px 8px;font-size:11px;border:1px solid}
  .pill.open{color:var(--ok);border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.08)}
  .pill.flaky{color:var(--warn);border-color:rgba(251,191,36,.4);background:rgba(251,191,36,.08)}
  .pill.closed{color:var(--bad);border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.08)}
  .mono{font-family:ui-monospace,Consolas,monospace}
  .lat{display:flex;align-items:center;gap:8px}
  .lat>i{height:6px;border-radius:3px;background:var(--accent);display:block;min-width:3px}
  .tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  .tools input[type=text]{width:200px}
  .muted{color:var(--dim)}
  .tiny{font-size:11.5px;color:var(--dim)}
  .scroll{max-height:520px;overflow:auto;border-radius:10px;border:1px solid var(--line)}
  .toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);background:#1c2230;
         border:1px solid var(--line);border-radius:10px;padding:9px 16px;font-size:13px;opacity:0;
         transition:.2s;pointer-events:none}
  .toast.show{opacity:1}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>IP 端口测速器</h1>
    <span class="tag" id="ver">v4.0</span>
    <span class="tag">纯 TCP 握手 · 不 TLS · 不发 HTTP</span>
    <div class="spacer"></div>
    <button id="theme" title="切换深色/浅色" style="padding:5px 11px">🌙</button>
    <span class="tag mono" id="clock"></span>
  </header>

  <div class="card">
    <h2>输入</h2>
    <textarea id="input" spellcheck="false" placeholder="每行一个，格式：IP:端口#地区#原始延迟
1.2.3.4:443#HK#120
5.6.7.8:8443
9.10.11.12
192.168.1.1-20#LAN          ← IP 段
10.0.0.0/28                 ← CIDR"></textarea>
    <div class="drop" id="drop">
      <span>拖入 .txt 文件，或</span>
      <button id="pick">选择 TXT</button>
      <button id="pickCsv">导入 CSV</button>
      <input type="file" id="file" accept=".txt,.csv,text/plain" hidden>
      <input type="file" id="csvFile" accept=".csv,text/csv" hidden>
      <span class="tiny" id="fname"></span>
    </div>
  </div>

  <div class="card">
    <h2>参数</h2>
    <div class="row">
      <label>并发 <input type="number" id="workers" value="32" min="1" max="256"></label>
      <label>单次超时(秒) <input type="number" id="timeout" value="2" step="0.2" min="0.2" max="30"></label>
      <label>每节点次数 <input type="number" id="repeat" value="3" min="1" max="10"></label>
      <label>强制端口 <input type="text" id="port_override" placeholder="留空=用行内"></label>
      <label>端口集合 <input type="text" id="ports" placeholder="443,8443,2053" style="width:150px"></label>
      <label>保留历史 <input type="number" id="history" value="0" min="0" max="200" style="width:80px" title="0=只留最新一份，N=保留最近 N 份带时间戳的副本"></label>
      <label style="flex-direction:row;align-items:center;gap:6px;color:var(--txt)">
        <input type="checkbox" id="retry" checked style="width:15px;height:15px"> 失败自动重试
      </label>
      <label>对照端口 <input type="number" id="control_port" value="45123" min="0" max="65535"></label>
      <div class="spacer"></div>
      <button class="primary" id="start">开始测速</button>
      <button class="danger" id="stop" disabled>停止</button>
    </div>
  </div>

  <div class="card">
    <h2>进度</h2>
    <div class="bar"><i id="pbar"></i></div>
    <div class="meta">
      <span id="msg">就绪</span>
      <span>完成 <b id="done">0</b>/<b id="total">0</b></span>
      <span>耗时 <b id="elapsed">0s</b></span>
      <span>可用 <b id="okc" style="color:var(--ok)">0</b></span>
      <span>可疑 <b id="susc" style="color:var(--warn)">0</b></span>
      <span>新增 <b id="newc" style="color:var(--ok)">0</b></span>
      <span>丢失 <b id="lostc" style="color:var(--bad)">0</b></span>
    </div>
    <div class="env skipped" id="env">未开始</div>
  </div>

  <div class="card">
    <h2>结果</h2>
    <div class="tools">
      <button data-f="all" class="factive">全部</button>
      <button data-f="ok">可用</button>
      <button data-f="suspect">可疑</button>
      <button data-f="fail">失效</button>
      <button data-f="new">新可用</button>
      <button data-f="lost">新失效</button>
      <input type="text" id="q" placeholder="搜索 IP / 地区">
      <select id="sort" style="background:var(--panel2);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 9px;font-size:13px">
        <option value="metric">按延迟</option>
        <option value="jitter">按抖动</option>
        <option value="rate">按成功率</option>
      </select>
      <div class="spacer"></div>
      <button id="copy">复制可用列表</button>
      <button id="dl-txt">下载 txt</button>
      <button id="dl-csv">下载 csv</button>
    </div>
    <div class="scroll">
      <table>
        <thead><tr>
          <th>#</th><th>节点</th><th>地区</th><th>握手</th><th>抖动</th><th>成功率</th><th>状态</th><th>对比</th><th></th>
        </tr></thead>
        <tbody id="rows"><tr><td colspan="9" class="muted" style="padding:24px;text-align:center">还没有结果</td></tr></tbody>
      </table>
    </div>
    <div class="tiny" id="outfiles" style="margin-top:10px"></div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const $ = s => document.querySelector(s);
let state = {results: [], running: false};
let filter = 'all', query = '', sortBy = 'metric';
let timer = null;

const fmt = ms => (ms === null || ms === undefined) ? '—' : ms + ' ms';
const esc = s => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(t){
  const el = $('#toast'); el.textContent = t; el.classList.add('show');
  clearTimeout(el._t); el._t = setTimeout(() => el.classList.remove('show'), 1800);
}

function cfg(){
  return {
    workers: +$('#workers').value,
    timeout: +$('#timeout').value,
    repeat: +$('#repeat').value,
    port_override: $('#port_override').value.trim(),
    control_port: +$('#control_port').value,
    ports: $('#ports').value.trim(),
    history: +$('#history').value,
    retry: $('#retry').checked ? 1 : 0
  };
}

function jitterColor(r){
  if (!r.ok || r.jitter === null || r.jitter === undefined) return 'var(--dim)';
  const base = r.connect_ms || 1;
  const ratio = r.jitter / base;
  if (ratio > 1) return 'var(--bad)';
  if (ratio > 0.4) return 'var(--warn)';
  return '';
}

function render(){
  const sorter = sortBy === 'jitter'
    ? (a, b) => ((a.jitter === null || a.jitter === undefined) ? 1e9 : a.jitter) - ((b.jitter === null || b.jitter === undefined) ? 1e9 : b.jitter)
    : sortBy === 'rate'
      ? (a, b) => (b.success_rate - a.success_rate) || (a.metric - b.metric)
      : (a, b) => (a.metric - b.metric);
  const rs = state.results.filter(r => {
    if (filter === 'ok' && !r.ok) return false;
    if (filter === 'fail' && r.ok) return false;
    if (filter === 'suspect' && !r.suspect) return false;
    if (filter === 'new' && r.trend !== 'new') return false;
    if (filter === 'lost' && r.trend !== 'lost') return false;
    if (query && !(r.raw + ' ' + (r.region || '')).toLowerCase().includes(query.toLowerCase())) return false;
    return true;
  }).sort(sorter);
  $('#okc').textContent = state.results.filter(r => r.ok).length;
  $('#susc').textContent = state.results.filter(r => r.suspect).length;
  $('#newc').textContent = state.results.filter(r => r.trend === 'new').length;
  $('#lostc').textContent = state.results.filter(r => r.trend === 'lost').length;
  $('#done').textContent = state.done || 0;
  $('#total').textContent = state.total || 0;
  $('#pbar').style.width = state.total ? Math.round((state.done || 0) / state.total * 100) + '%' : '0';

  if (!rs.length){
    const msg = state.results.length ? '当前筛选无结果' : '还没有结果';
    $('#rows').innerHTML = '<tr><td colspan="9" class="muted" style="padding:24px;text-align:center">' + msg + '</td></tr>';
    return;
  }
  const max = Math.max.apply(null, rs.map(r => r.metric < 99999 ? r.metric : 0).concat([1]));
  $('#rows').innerHTML = rs.map((r, i) => {
    const pct = r.metric < 99999 ? Math.max(4, Math.round(r.metric / max * 100)) : 0;
    const cls = r.status === 'open' ? 'open' : r.status === 'flaky' ? 'flaky' : 'closed';
    const label = ({open:'可用', flaky:'不稳', closed:'失效'})[r.status] || r.status;
    let d = '<span class="muted">—</span>';
    if (r.delta !== null && r.delta !== undefined){
      const c = r.delta > 0 ? 'var(--bad)' : 'var(--ok)';
      d = '<span style="color:' + c + '">' + (r.delta > 0 ? '+' : '') + r.delta + ' ms</span>';
    }
    const sus = r.suspect ? '<span class="pill flaky" style="margin-left:6px">可疑</span>' : '';
    const trend = r.trend === 'new' ? '<span class="pill open" style="margin-left:6px">新增</span>'
      : r.trend === 'lost' ? '<span class="pill closed" style="margin-left:6px">丢失</span>' : '';
    const rt = r.retried ? '<span class="tiny" style="margin-left:6px;color:var(--dim)">重试过</span>' : '';
    const err = r.error ? '<span class="tiny" style="margin-left:6px">' + esc(r.error) + '</span>' : '';
    return '<tr>' +
      '<td class="muted">' + (i + 1) + '</td>' +
      '<td class="mono">' + esc(r.raw) + sus + '</td>' +
      '<td class="muted">' + esc(r.region || '—') + '</td>' +
      '<td><div class="lat"><i style="width:' + pct + '%;background:' + (r.ok ? 'var(--accent)' : 'var(--bad)') + '"></i>' + fmt(r.connect_ms) + '</div></td>' +
      '<td class="mono" style="color:' + jitterColor(r) + '">' + (r.jitter === null || r.jitter === undefined ? '—' : '±' + r.jitter + ' ms') + '</td>' +
      '<td class="mono">' + r.success_rate + '% <span class="muted">(' + r.ok_count + '/' + r.tries + ')</span></td>' +
      '<td><span class="pill ' + cls + '">' + label + '</span>' + sus + trend + rt + err + '</td>' +
      '<td>' + d + '</td>' +
      '<td><button data-retest="' + esc(r.raw) + '" style="padding:3px 9px;font-size:12px">复测</button></td>' +
    '</tr>';
  }).join('');
  document.querySelectorAll('[data-retest]').forEach(b => {
    b.onclick = () => retest(b.getAttribute('data-retest'));
  });
}

function renderEnv(env){
  if (!env || !env.trust) return;
  const el = $('#env');
  el.className = 'env ' + env.trust;
  const icon = env.trust === 'ok' ? '✅' : env.trust === 'proxy' ? '⚠️' : '⏳';
  el.textContent = icon + ' ' + (env.note || '');
}

function renderFiles(f){
  const el = $('#outfiles');
  if (!f || (!f.outdir && !f.ok_count)){ el.textContent = ''; return; }
  el.innerHTML = '输出目录 <span class="mono">' + esc(f.outdir || '') + '</span> · 可用 ' +
    f.ok_count + ' · 失效 ' + f.fail_count;
}

async function poll(){
  try{
    const r = await fetch('api/state', {cache:'no-store'});
    if (!r.ok) return;
    const s = await r.json();
    state = s;
    $('#msg').textContent = s.message || '';
    $('#elapsed').textContent = (s.elapsed || 0) + 's';
    $('#start').disabled = !!s.running;
    $('#stop').disabled = !s.running;
    renderEnv(s.env); renderFiles(s.files); render();
    if (!s.running && timer){ clearInterval(timer); timer = null; }
  }catch(e){}
}

async function start(){
  const text = $('#input').value.trim();
  if (!text){ toast('先粘贴 IP 列表，或拖入 txt'); return; }
  $('#start').disabled = true;
  const r = await fetch('api/start', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text: text, cfg: cfg()})
  });
  const j = await r.json().catch(function(){ return {}; });
  if (!r.ok || j.error){ toast(j.error || '启动失败'); $('#start').disabled = false; return; }
  state = {results: [], running: true, done: 0, total: j.nodes};
  render();
  if (!timer) timer = setInterval(poll, 400);
}

async function retest(raw){
  const r = await fetch('api/retest', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({raw: raw, cfg: cfg()})
  });
  const j = await r.json().catch(function(){ return {}; });
  if (!r.ok || j.error){ toast(j.error || '复测失败'); return; }
  if (!timer) timer = setInterval(poll, 400);
}

$('#start').onclick = start;
$('#stop').onclick = () => fetch('api/stop', {method:'POST'});
// 主题：跟随 localStorage，默认深色
(function initTheme(){
  const saved = localStorage.getItem('ipt-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  const btn = $('#theme');
  const sync = () => { btn.textContent = document.documentElement.dataset.theme === 'light' ? '☀️' : '🌙'; };
  btn.onclick = () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    localStorage.setItem('ipt-theme', next);
    sync();
  };
  sync();
})();

// 导入上次导出的 CSV：取第一列 node，填回输入框继续测
$('#pickCsv').onclick = () => $('#csvFile').click();
$('#csvFile').onchange = e => {
  const f = e.target.files[0]; if (!f) return;
  const rd = new FileReader();
  rd.onload = () => {
    const lines = String(rd.result).split(/\r?\n/);
    const out = [];
    for (const line of lines){
      if (!line.trim()) continue;
      const cell = (line.split(',')[0] || '').replace(/^"|"$/g, '').trim();
      if (!cell || /^node$/i.test(cell)) continue;   // 跳过表头
      out.push(cell);
    }
    $('#input').value = out.join('\n');
    $('#fname').textContent = f.name + '（' + out.length + ' 行）';
    toast('已导入 ' + out.length + ' 条节点');
  };
  rd.readAsText(f, 'utf-8');
};

$('#pick').onclick = () => $('#file').click();
$('#file').onchange = e => { const f = e.target.files[0]; if (f) readFile(f); };
$('#drop').ondragover = e => { e.preventDefault(); $('#drop').classList.add('hot'); };
$('#drop').ondragleave = () => $('#drop').classList.remove('hot');
$('#drop').ondrop = e => {
  e.preventDefault(); $('#drop').classList.remove('hot');
  const f = e.dataTransfer.files[0]; if (f) readFile(f);
};
function readFile(f){
  if (f.size > 2 * 1024 * 1024){ toast('文件超过 2 MB'); return; }
  const rd = new FileReader();
  rd.onload = () => { $('#input').value = rd.result; $('#fname').textContent = f.name; toast('已载入 ' + f.name); };
  rd.readAsText(f, 'utf-8');
}

document.querySelectorAll('.tools button[data-f]').forEach(b => {
  b.onclick = () => {
    filter = b.getAttribute('data-f');
    document.querySelectorAll('.tools button[data-f]').forEach(x => x.classList.remove('factive'));
    b.classList.add('factive'); render();
  };
});
$('#q').oninput = e => { query = e.target.value; render(); };
$('#sort').onchange = e => { sortBy = e.target.value; render(); };

$('#copy').onclick = async () => {
  const ok = state.results.filter(r => r.ok)
    .sort((a, b) => a.metric - b.metric).map(r => r.raw).join('\n');
  if (!ok){ toast('没有可用节点'); return; }
  try{ await navigator.clipboard.writeText(ok); toast('已复制 ' + ok.split('\n').length + ' 条'); }
  catch(e){ toast('剪贴板被拒绝，请用下载 txt'); }
};
$('#dl-txt').onclick = () => { location.href = 'api/download?name=ip_speed.txt'; };
$('#dl-csv').onclick = () => { location.href = 'api/download?name=ip_speed_detail.csv'; };

setInterval(() => {
  $('#clock').textContent = new Date().toLocaleTimeString('zh-CN', {hour12:false});
}, 1000);
poll();

// ── 存活探测 ───────────────────────────────────────────────
// 1) WebSocket：标签页关闭 / 浏览器被杀时 TCP 立刻断，服务端 2.5 秒后退出
window._ws = null;
(function keepWs(){
  try{
    const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    window._ws = new WebSocket(proto + location.host + '/ws');
    window._ws.onclose = () => { window._ws = null; setTimeout(keepWs, 3000); };  // 页面还开着才会走到这里
    window._ws.onerror = () => {};
  }catch(e){}
})();

// 2) 心跳：页面可见时每 8 秒打一次，让服务端知道窗口还在
setInterval(() => {
  if (document.hidden) return;
  fetch('api/ping', {cache:'no-store'}).catch(() => {});
}, 8000);

// 3) 关页面时顺手通知一次，让退出更快
window.addEventListener('pagehide', () => {
  try { navigator.sendBeacon('api/bye', '1'); } catch (e) {}
  try { if (window._ws) window._ws.close(); } catch (e) {}
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
