#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core.py — 代理池核心：抓取 / 测活 / 存储 / 淘汰

不依赖任何第三方库。数据库用 SQLite，测活交给同目录的 proxy-check.py。
"""

from __future__ import annotations

import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path

VERSION = "2.0.0"
HERE = Path(__file__).resolve().parent
CHECKER = HERE / "proxy-check.py"
DB_PATH = HERE / "data" / "pool.db"

# ─────────────────────────── 数据源 ───────────────────────────
SOURCES = {
    "proxifly":   ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt", "http"),
    "speedx":     ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http"),
    "speedx4":    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    "speedx5":    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
    "monosans":   ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http"),
    "monosans5":  ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5"),
    "vakhov":     ("https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt", "http"),
    "hideip":     ("https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt", "http"),
    "roosterkid": ("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", "http"),
    "proxyscrape_s5": ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=text", "socks5"),
    "proxyscrape_http": ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text", "http"),
    "proxyscrape_s4": ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks4&proxy_format=protocolipport&format=text", "socks4"),
    "proxifly_s5": ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "socks5"),
    "proxifly_http": ("https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "http"),
    "monosans_s4": ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
}

DEFAULT_SETTINGS = {
    "interval": 3600,          # 每轮间隔秒
    "limit": 2000,             # 每轮最多测多少
    "batch": 400,              # 每批交给 proxy-check 的数量
    "threads": 200,            # 并发
    "timeout": 6.0,            # 单代理超时
    "geo": 1,                  # 是否查 GeoIP
    "full": 0,                 # 是否全协议深检
    "require_https": 1,        # 是否要求支持 HTTPS
    "max_fail": 3,             # 连续失败几次淘汰
    "max_size": 5000,          # 池子容量上限
    "sources": ",".join(SOURCES.keys()),
    "enabled": 1,              # 定时任务是否启用
    "country_allow": "",       # 只保留这些国家（逗号分隔 ISO2），空=不限制
    "country_deny": "",        # 排除这些国家
    "isp_deny": "",            # 排除 ISP 含这些关键词的（逗号分隔）
    "min_ok_export": 0,        # 导出时要求最低成功次数
    "report_offline": 1,       # 反馈失败达到阈值时立即下线
    "webshare_key": "",        # Webshare API Key（免费套餐 10 个代理）
    "api_public": 0,           # /proxy 是否免 token（UI 仍然要 token）
    "feed_key": "",            # 机器对接专用只读密钥（放在路径里，不需要请求头）
    "feed_schemes": "http,https,socks5",   # feed 输出的协议（codex2api 只认 http/https/socks5）
    "feed_limit": 100,         # feed 单次最多返回条数（硬上限 100）
    "feed_https_only": 1,      # feed 只给验证过支持 HTTPS CONNECT 的
    "openai_probe": 1,         # 用 api.openai.com 真实性探测
    "openai_only_feed": 1,     # feed 只给 OpenAI 实测可用的
    "openai_workers": 40,      # 探测并发
    "openai_timeout": 10,      # 单代理探测超时秒
    "openai_probe_limit": 400, # 每轮最多探测多少个
    "direct_ingest": 1,        # 直接从高产出源用 OpenAI 目标入库（绕过 httpbin 误杀）
    "direct_sources": "proxyscrape_s5,monosans5,proxyscrape_http,hideip,monosans,roosterkid",
    "direct_limit": 1200,      # 直连入库每轮测多少候选
    "direct_workers": 80,
    "static_proxies": "",      # 固定代理（如自建 Clash 的 http://IP:7890），永久保留
}

MAX_RETURN = 100               # 任何对外接口单次最多返回的代理数

IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
SCHEME_PREFIX = re.compile(r"^(https?|socks4|socks5)://", re.I)

NAME2CODE = {
    "United States": "US", "United Kingdom": "GB", "Korea": "KR", "South Korea": "KR",
    "Russia": "RU", "Germany": "DE", "France": "FR", "Netherlands": "NL", "Japan": "JP",
    "China": "CN", "Hong Kong": "HK", "Taiwan": "TW", "Singapore": "SG", "India": "IN",
    "Indonesia": "ID", "Thailand": "TH", "Vietnam": "VN", "Brazil": "BR", "Romania": "RO",
    "Nepal": "NP", "Pakistan": "PK", "Bangladesh": "BD", "Turkey": "TR", "Iran": "IR",
    "Ukraine": "UA", "Poland": "PL", "Spain": "ES", "Italy": "IT", "Canada": "CA",
    "Australia": "AU", "Mexico": "MX", "Argentina": "AR", "South Africa": "ZA",
    "Zimbabwe": "ZW", "Egypt": "EG", "Nigeria": "NG", "Kenya": "KE", "Israel": "IL",
    "United Arab Emirates": "AE", "Saudi Arabia": "SA", "Kazakhstan": "KZ",
}


# ─────────────────────────── 小工具 ───────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def norm_cc(c: str) -> str:
    if not c:
        return ""
    c = c.strip()
    return c.upper() if len(c) <= 2 else NAME2CODE.get(c, c[:2].upper())


def is_public_ipv4(ip: str) -> bool:
    m = IPV4.match(ip)
    if not m:
        return False
    a, b, c, d = (int(x) for x in m.groups())
    if any(x > 255 for x in (a, b, c, d)):
        return False
    if a in (0, 10, 127):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    if a >= 224:
        return False
    return True


def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# ─────────────────────────── 数据库 ───────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    country TEXT DEFAULT '',
    isp TEXT DEFAULT '',
    hosting INTEGER,
    anonymity TEXT DEFAULT '',
    https_ok INTEGER DEFAULT 0,
    latency_ms INTEGER,
    ok_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0,
    consec_fail INTEGER DEFAULT 0,
    first_seen TEXT,
    last_ok TEXT,
    last_check TEXT,
    alive INTEGER DEFAULT 0,
    openai_ok INTEGER,
    openai_status TEXT DEFAULT '',
    openai_checked TEXT,
    source TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alive    ON proxies(alive);
CREATE INDEX IF NOT EXISTS idx_country  ON proxies(country);
CREATE INDEX IF NOT EXISTS idx_latency  ON proxies(latency_ms);
CREATE INDEX IF NOT EXISTS idx_hosting  ON proxies(hosting);

CREATE TABLE IF NOT EXISTS rounds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT,
    finished TEXT,
    fetched INTEGER DEFAULT 0,
    tested INTEGER DEFAULT 0,
    alive INTEGER DEFAULT 0,
    new_alive INTEGER DEFAULT 0,
    died INTEGER DEFAULT 0,
    pruned INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    status TEXT DEFAULT 'running',
    message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    scheme TEXT DEFAULT 'http',
    kind TEXT DEFAULT 'list',
    enabled INTEGER DEFAULT 1,
    last_fetch TEXT,
    last_count INTEGER DEFAULT 0,
    last_error TEXT DEFAULT '',
    total_fetched INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    level TEXT DEFAULT 'info',
    msg TEXT
);
"""

_db_lock = threading.Lock()


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db() -> None:
    with connect() as c:
        c.executescript(SCHEMA)
        # 老库升级：补认证列
        cols = {r["name"] for r in c.execute("PRAGMA table_info(proxies)").fetchall()}
        for col, ddl in (("username", "TEXT DEFAULT ''"), ("password", "TEXT DEFAULT ''"),
                         ("openai_ok", "INTEGER"), ("openai_status", "TEXT DEFAULT ''"),
                         ("openai_checked", "TEXT")):
            if col not in cols:
                c.execute(f"ALTER TABLE proxies ADD COLUMN {col} {ddl}")
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(k, v) VALUES (?, ?)", (k, str(v)))
        # 清理已从代码里移除的源
        keep = tuple(SOURCES.keys()) + ("webshare",)
        qmarks = ",".join("?" * len(keep))
        c.execute(f"DELETE FROM sources WHERE name NOT IN ({qmarks})", keep)
        # 初始化源表
        for name, (url, scheme) in SOURCES.items():
            c.execute("INSERT OR IGNORE INTO sources(name,url,scheme,kind) VALUES (?,?,?,?)",
                      (name, url, scheme, "list"))
        c.execute("INSERT OR IGNORE INTO sources(name,url,scheme,kind) VALUES (?,?,?,?)",
                  ("webshare", "https://proxy.webshare.io/api/v2/proxy/list/", "http", "api"))
        # 首次生成机器对接密钥
        row = c.execute("SELECT v FROM settings WHERE k='feed_key'").fetchone()
        if row and not (row["v"] or "").strip():
            import secrets as _secrets
            c.execute("UPDATE settings SET v=? WHERE k='feed_key'",
                      (_secrets.token_urlsafe(24),))


def get_sources(enabled_only: bool = False) -> list[dict]:
    with connect() as c:
        q = "SELECT * FROM sources"
        if enabled_only:
            q += " WHERE enabled=1"
        q += " ORDER BY kind DESC, name"
        return [dict(r) for r in c.execute(q).fetchall()]


def set_source(name: str, patch: dict) -> bool:
    allowed = {k: v for k, v in patch.items()
               if k in ("enabled", "url", "scheme", "kind")}
    if not allowed:
        return False
    sets = ", ".join(f"{k}=?" for k in allowed)
    with connect() as c:
        cur = c.execute(f"UPDATE sources SET {sets} WHERE name=?",
                        list(allowed.values()) + [name])
        return cur.rowcount > 0


def get_settings() -> dict:
    with connect() as c:
        rows = c.execute("SELECT k, v FROM settings").fetchall()
    out = dict(DEFAULT_SETTINGS)
    for r in rows:
        k, v = r["k"], r["v"]
        if k in ("sources",):
            out[k] = v
        elif k in ("timeout",):
            out[k] = float(v)
        else:
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = v
    return out


def set_settings(patch: dict) -> dict:
    with connect() as c:
        for k, v in patch.items():
            if k not in DEFAULT_SETTINGS:
                continue
            c.execute("INSERT INTO settings(k, v) VALUES (?, ?) "
                      "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
    return get_settings()


def add_log(level: str, msg: str) -> None:
    try:
        with connect() as c:
            c.execute("INSERT INTO logs(ts, level, msg) VALUES (?,?,?)",
                      (now_iso(), level, msg[:500]))
            c.execute("DELETE FROM logs WHERE id < (SELECT MAX(id)-800 FROM logs)")
    except sqlite3.Error:
        pass   # 日志写不进去不能影响主流程


def get_logs(limit: int = 200) -> list[dict]:
    with connect() as c:
        rows = c.execute("SELECT ts, level, msg FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────── 抓取 ───────────────────────────
def fetch_one(name: str, url: str, timeout: float = 25.0) -> tuple[str, list[str], str]:
    req = urllib.request.Request(url, headers={"User-Agent": f"proxy-pool/{VERSION}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return name, [l.strip() for l in raw.splitlines() if l.strip()], ""
    except Exception as e:
        return name, [], f"{type(e).__name__}: {e}"


def normalize(lines: list[str], default_scheme: str = "http") -> set[str]:
    """归一化成 scheme://[user:pass@]host:port，保留认证信息"""
    got: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        scheme = default_scheme
        m = SCHEME_PREFIX.match(line)
        if m:
            scheme = m.group(1).lower()
            line = line[m.end():]

        user = pwd = ""
        if "@" in line:
            cred, _, rest = line.rpartition("@")
            if ":" in cred:
                user, _, pwd = cred.partition(":")
            line = rest

        mm = LINE.search(line)
        if not mm:
            continue
        ip, port = mm.group(1), int(mm.group(2))
        if not (0 < port < 65536) or not is_public_ipv4(ip):
            continue
        if user:
            got.add(f"{scheme}://{user}:{pwd}@{ip}:{port}")
        else:
            got.add(f"{scheme}://{ip}:{port}")
    return got


def split_auth(url: str) -> tuple[str, str, str]:
    """把 scheme://user:pass@host:port 拆成 (scheme, user, pass, host:port)"""
    scheme, _, rest = url.partition("://")
    user = pwd = ""
    if "@" in rest:
        cred, _, rest = rest.rpartition("@")
        if ":" in cred:
            user, _, pwd = cred.partition(":")
    return scheme, user, pwd, rest


def fetch_webshare(api_key: str, timeout: float = 20.0) -> tuple[list[str], str]:
    """Webshare 官方 API：免费套餐给 10 个代理（数据中心），带 user:pass 认证"""
    if not api_key:
        return [], "未配置 Webshare API Key"
    url = "https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=100"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Token {api_key}",
        "User-Agent": f"proxy-pool/{VERSION}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"

    lines: list[str] = []
    for p in data.get("results", []):
        if not p.get("valid", True):
            continue
        host, port = p.get("proxy_address"), p.get("port")
        if not host or not port:
            continue
        u, pw = p.get("username") or "", p.get("password") or ""
        lines.append(f"http://{u}:{pw}@{host}:{port}" if u and pw else f"http://{host}:{port}")
    return lines, ""


def fetch_all(progress=None) -> tuple[set[str], dict[str, int], list[str]]:
    """按 sources 表抓取所有启用的源，返回 (去重代理, {源: 数量}, 错误)"""
    srcs = get_sources(enabled_only=True)
    allp: set[str] = set()
    stats: dict[str, int] = {}
    errors: list[str] = []
    st = get_settings()

    if not srcs:
        return allp, stats, ["没有启用的数据源"]

    def record(name: str, count: int, err: str) -> None:
        with connect() as c:
            c.execute(
                "UPDATE sources SET last_fetch=?, last_count=?, last_error=?, "
                "total_fetched=total_fetched+? WHERE name=?",
                (now_iso(), count, err[:300], count, name))

    # 普通列表源并发抓
    list_srcs = [x for x in srcs if x["kind"] != "api"]
    api_srcs = [x for x in srcs if x["kind"] == "api"]

    if list_srcs:
        with ThreadPoolExecutor(max_workers=min(8, len(list_srcs))) as ex:
            futs = {ex.submit(fetch_one, x["name"], x["url"], 25.0): x for x in list_srcs}
            for f in futs:
                src = futs[f]
                name, lines, err = f.result()
                if err:
                    errors.append(f"{name}: {err}")
                    record(name, 0, err)
                    if progress:
                        progress(f"源 {name} 失败: {err}")
                    continue
                got = normalize(lines, src["scheme"] or "http")
                stats[name] = len(got)
                allp |= got
                record(name, len(got), "")
                if progress:
                    progress(f"源 {name}: {len(got)} 个")

    # API 型源
    for src in api_srcs:
        if src["name"] == "webshare":
            lines, err = fetch_webshare(str(st.get("webshare_key") or ""))
            if err:
                errors.append(f"webshare: {err}")
                record("webshare", 0, err)
                if progress:
                    progress(f"源 webshare 失败: {err}")
                continue
            got = normalize(lines, "http")
            stats["webshare"] = len(got)
            allp |= got
            record("webshare", len(got), "")
            if progress:
                progress(f"源 webshare: {len(got)} 个（免费套餐）")

    return allp, stats, errors


# ─────────────────────────── 测活 ───────────────────────────
def run_checker(candidates: list[str], threads: int, timeout: float,
                full: bool, require_https: bool) -> list[dict]:
    if not candidates:
        return []
    cmd = [sys.executable, str(CHECKER), "--stdin",
           "-t", str(threads), "--timeout", str(timeout),
           "--json", "--quiet", "--no-color"]
    if full:
        cmd += ["--mode", "full"]
    if not require_https:
        cmd += ["--no-require-https"]
    payload = "\n".join(candidates) + "\n"
    try:
        p = subprocess.run(cmd, input=payload, capture_output=True, text=True,
                           timeout=max(180, timeout * 15))
        if not p.stdout.strip():
            return []
        return json.loads(p.stdout).get("results", [])
    except subprocess.TimeoutExpired:
        add_log("warn", f"测活进程超时（{len(candidates)} 个）")
        return []
    except json.JSONDecodeError:
        add_log("warn", "测活输出无法解析")
        return []


def batch_geo(hosts: list[str]) -> dict[str, dict]:
    """ip-api 批量查国家/ISP/是否机房。100 个一次，15 次/分钟。"""
    out: dict[str, dict] = {}
    for idx, part in enumerate(chunked(list(dict.fromkeys(hosts)), 100)):
        if idx:
            time.sleep(4.2)
        payload = json.dumps([{"query": h.split(":")[0]} for h in part]).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,countryCode,isp,hosting,proxy",
            data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read())
            for h, d in zip(part, data):
                if isinstance(d, dict) and d.get("status") == "success":
                    out[h] = {
                        "country": norm_cc(d.get("countryCode", "") or ""),
                        "isp": (d.get("isp") or "")[:60],
                        "hosting": 1 if d.get("hosting") else 0,
                    }
        except Exception as e:
            add_log("warn", f"GeoIP 失败: {type(e).__name__}: {e}")
    return out


# ─────────────────────────── 入库 / 淘汰 ───────────────────────────
def pick_candidates(limit: int) -> tuple[list[str], int]:
    """老池子占一半名额，新候选占一半"""
    with connect() as c:
        alive = [r["url"] for r in c.execute(
            "SELECT url FROM proxies WHERE alive=1 ORDER BY latency_ms ASC").fetchall()]
        known = {r["url"] for r in c.execute("SELECT url FROM proxies").fetchall()}
    return alive, len(known)


def select_batch(all_proxies: set[str], limit: int) -> tuple[list[str], int]:
    with connect() as c:
        alive = [r["url"] for r in c.execute(
            "SELECT url FROM proxies WHERE alive=1 "
            "AND COALESCE(source,'') NOT IN ('direct-openai','static') "
            "ORDER BY latency_ms ASC").fetchall()]
        known_hp = {f'{r["host"]}:{r["port"]}'
                    for r in c.execute("SELECT host, port FROM proxies").fetchall()}
    fresh = [p for p in all_proxies if split_auth(p)[3] not in known_hp]
    random.shuffle(fresh)
    if limit <= 0:
        return list(dict.fromkeys(alive + fresh)), len(fresh)
    half = max(1, limit // 2)
    picked = list(dict.fromkeys(alive[:half] + fresh[:max(0, limit - min(len(alive), half))]))
    return picked, len(fresh)


def apply_results(results: list[dict],
                  auth_map: dict[str, str] | None = None) -> tuple[int, int, list[str]]:
    """
    写入测活结果，返回 (新增存活, 新增死亡, 本轮新存活 host:port 列表)。
    auth_map: host:port -> 原始 url（可能带 user:pass），用来恢复认证信息。
    """
    new_alive = new_dead = 0
    newly: list[str] = []
    ts = now_iso()
    auth_map = auth_map or {}
    with connect() as c:
        for r in results:
            hp = (r.get("proxy") or "").split("://", 1)[-1]
            if "@" in hp:
                hp = hp.rpartition("@")[2]
            if not hp or ":" not in hp:
                continue
            host, _, port_s = hp.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            ptype = (r.get("ptype") or "").lower()
            if ptype not in ("http", "https", "socks4", "socks5"):
                ptype = "http"

            # 优先用原始候选里的 url（带认证）
            orig = auth_map.get(hp)
            if orig:
                oscheme, ouser, opwd, _ = split_auth(orig)
                ptype = oscheme or ptype
            else:
                ouser = opwd = ""

            row = c.execute("SELECT id, alive FROM proxies WHERE host=? AND port=?",
                            (host, port)).fetchone()
            ok = bool(r.get("alive")) and r.get("verdict") == "ok"
            lat = r.get("latency_ms")
            lat = lat if isinstance(lat, int) and lat >= 0 else None

            if row is None:
                url = orig if orig else f"{ptype}://{hp}"
                c.execute(
                    "INSERT OR IGNORE INTO proxies(url,host,port,scheme,username,password,"
                    "first_seen,last_check,last_ok,alive,latency_ms,ok_count,consec_fail,"
                    "https_ok,anonymity,source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (url, host, port, ptype, ouser, opwd, ts, ts, ts if ok else None,
                     1 if ok else 0, lat, 1 if ok else 0, 0 if ok else 1,
                     1 if r.get("https_ok") else 0, r.get("anonymity") or "", ""))
                if ok:
                    new_alive += 1
                    newly.append(hp)
                continue

            if ok:
                c.execute(
                    "UPDATE proxies SET alive=1, ok_count=ok_count+1, consec_fail=0, "
                    "last_ok=?, last_check=?, latency_ms=COALESCE(?, latency_ms), "
                    "https_ok=?, anonymity=? WHERE id=?",
                    (ts, ts, lat, 1 if r.get("https_ok") else 0,
                     r.get("anonymity") or "", row["id"]))
                if not row["alive"]:
                    new_alive += 1
                    newly.append(hp)
            else:
                c.execute(
                    "UPDATE proxies SET alive=0, fail_count=fail_count+1, "
                    "consec_fail=consec_fail+1, last_check=? WHERE id=?",
                    (ts, row["id"]))
                if row["alive"]:
                    new_dead += 1
    return new_alive, new_dead, newly


def enrich_geo(hosts: list[str]) -> int:
    if not hosts:
        return 0
    info = batch_geo(hosts)
    n = 0
    with connect() as c:
        for hp, g in info.items():
            host, _, port_s = hp.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            cur = c.execute("UPDATE proxies SET country=?, isp=?, hosting=? "
                            "WHERE host=? AND port=?", (g["country"], g["isp"], g["hosting"], host, port))
            n += cur.rowcount
    return n


OPENAI_PROBE_URL = "https://api.openai.com/v1/models"


def _curl_via_proxy(url: str, proxy: str, timeout: int) -> str:
    """用 curl 走代理请求，返回 HTTP 状态码字符串（000=失败）"""
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", str(timeout), "-x", proxy,
             "-o", "/dev/null", "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        return (r.stdout or "").strip() or "000"
    except Exception:
        return "000"


def probe_openai(limit: int = 0, progress=None) -> dict:
    """
    用真实目标 api.openai.com 探测代理是否可用。
    401/200 = 可用（401 只是没带 key），403 = 被 Cloudflare 封，000 = 不通。
    只探「活着但还没探过 / 探得很旧」的，避免每轮重复开销。
    """
    st = get_settings()
    if not int(st.get("openai_probe") or 0):
        return {"probed": 0, "ok": 0}
    workers = max(4, int(st.get("openai_workers") or 40))
    timeout = max(4, int(st.get("openai_timeout") or 10))
    cap = limit or int(st.get("openai_probe_limit") or 400)

    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id, url FROM proxies WHERE alive=1 "
            "AND scheme IN ('http','https','socks5') "
            "AND (openai_checked IS NULL OR openai_checked < ?) "
            "ORDER BY latency_ms ASC LIMIT ?",
            ((datetime.now(timezone.utc).astimezone()
              - timedelta(hours=6)).isoformat(timespec="seconds"), cap)
        ).fetchall()]

    if not rows:
        return {"probed": 0, "ok": 0}

    if progress:
        progress(f"OpenAI 探测 {len(rows)} 个…")

    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_curl_via_proxy, OPENAI_PROBE_URL, r["url"], timeout): r for r in rows}
        for f in futs:
            r = futs[f]
            results.append((r["id"], f.result()))

    ts = now_iso()
    ok = 0
    with connect() as c:
        for pid, code in results:
            good = 1 if code in ("401", "200") else 0
            ok += good
            c.execute("UPDATE proxies SET openai_ok=?, openai_status=?, openai_checked=? WHERE id=?",
                      (good, code, ts, pid))
            # 直连入库的代理一旦 OpenAI 不通就下线（它本来就不做 httpbin 检测）
            if not good:
                c.execute(
                    "UPDATE proxies SET alive=0, fail_count=fail_count+1, consec_fail=consec_fail+1 "
                    "WHERE id=? AND COALESCE(source,'')='direct-openai'", (pid,))
    if progress:
        progress(f"OpenAI 探测完成：{ok}/{len(rows)} 可用")
    return {"probed": len(rows), "ok": ok}


def _curl_code_latency(url: str, proxy: str, timeout: int) -> tuple[str, int]:
    try:
        r = subprocess.run(
            ["curl", "-s", "-m", str(timeout), "-x", proxy, "-o", "/dev/null",
             "-w", "%{http_code} %{time_total}", url],
            capture_output=True, text=True, timeout=timeout + 5)
        parts = (r.stdout or "").strip().split()
        code = parts[0] if parts else "000"
        lat = int(float(parts[1]) * 1000) if len(parts) > 1 else 0
        return code, lat
    except Exception:
        return "000", 0


def ingest_direct(progress=None) -> dict:
    """
    直连入库：跳过 httpbin 回显检测（对 socks5 误杀严重），
    直接拿高产出源的候选打 api.openai.com，401/200 就入库并标记 openai_ok=1。
    这是喂 codex2api 的主力路径。
    """
    st = get_settings()
    if not int(st.get("direct_ingest") or 0):
        return {"tested": 0, "added": 0}
    src_names = [x.strip() for x in str(st.get("direct_sources") or "").split(",") if x.strip()]
    limit = int(st.get("direct_limit") or 1200)
    workers = max(10, int(st.get("direct_workers") or 80))
    timeout = max(6, int(st.get("openai_timeout") or 10))

    # 抓这些源
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT * FROM sources WHERE enabled=1").fetchall()]
    want = [r for r in rows if r["name"] in src_names]
    if not want:
        return {"tested": 0, "added": 0}

    cands: set[str] = set()
    for src in want:
        if src["kind"] == "api":
            continue
        _, lines, err = fetch_one(src["name"], src["url"], 25.0)
        if err:
            continue
        cands |= normalize(lines, src["scheme"] or "http")
        if progress:
            progress(f"直连入库·源 {src['name']}: {len(cands)} 累计")

    # 排除已知 host:port
    with connect() as c:
        known = {f'{r["host"]}:{r["port"]}' for r in c.execute(
            "SELECT host, port FROM proxies").fetchall()}
    fresh = [u for u in cands if split_auth(u)[3] not in known]
    random.shuffle(fresh)
    fresh = fresh[:max(1, limit)]
    if not fresh:
        return {"tested": 0, "added": 0}
    if progress:
        progress(f"直连 OpenAI 测试 {len(fresh)} 个候选…")

    results: list[tuple[str, str, int]] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_curl_code_latency, OPENAI_PROBE_URL, u, timeout): u for u in fresh}
        for f in futs:
            u = futs[f]
            code, lat = f.result()
            results.append((u, code, lat))

    ts = now_iso()
    added = 0
    with connect() as c:
        for u, code, lat in results:
            if code not in ("401", "200"):
                continue
            scheme, user, pwd, hp = split_auth(u)
            host, _, port_s = hp.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            c.execute(
                "INSERT OR IGNORE INTO proxies(url,host,port,scheme,username,password,"
                "first_seen,last_check,last_ok,alive,latency_ms,ok_count,consec_fail,"
                "https_ok,anonymity,source,openai_ok,openai_status,openai_checked) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (u, host, port, scheme, user, pwd, ts, ts, ts, 1, lat, 1, 0,
                 1, "", "direct-openai", 1, code, ts))
            added += 1
    if progress:
        progress(f"直连入库完成：{added}/{len(fresh)} 可用")
    return {"tested": len(fresh), "added": added}


def sync_static(progress=None) -> int:
    """把 settings.static_proxies 里的固定代理写进池子（如 clash），永不淘汰"""
    st = get_settings()
    raw = str(st.get("static_proxies") or "").strip()
    if not raw:
        return 0
    items = [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]
    ts = now_iso()
    n = 0
    with connect() as c:
        for u in items:
            scheme, user, pwd, hp = split_auth(u)
            if ":" not in hp:
                continue
            host, _, port_s = hp.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                continue
            c.execute(
                "INSERT INTO proxies(url,host,port,scheme,username,password,first_seen,"
                "last_check,last_ok,alive,latency_ms,ok_count,consec_fail,https_ok,"
                "anonymity,source,openai_ok,openai_status,openai_checked) "
                "VALUES (?,?,?,?,?,?,?,?,?,1,0,1,0,1,'','static',1,'static',?) "
                "ON CONFLICT(url) DO UPDATE SET alive=1, openai_ok=1, source='static'",
                (u, host, port, scheme or "http", user, pwd, ts, ts, ts, ts))
            n += 1
    if progress:
        progress(f"固定代理同步 {n} 条")
    return n


def prune(max_fail: int, max_size: int) -> int:
    with connect() as c:
        cur = c.execute(
            "DELETE FROM proxies WHERE alive=0 AND "
            "((last_ok IS NULL AND consec_fail>=?) OR consec_fail>=?)",
            (max_fail, max_fail * 2))
        n = cur.rowcount
        total = c.execute("SELECT COUNT(*) n FROM proxies WHERE alive=1").fetchone()["n"]
        if max_size > 0 and total > max_size:
            over = total - max_size
            c.execute(
                "DELETE FROM proxies WHERE id IN ("
                " SELECT id FROM proxies WHERE alive=1 ORDER BY latency_ms DESC LIMIT ?)", (over,))
            n += over
    return n


# ─────────────────────────── 一轮 ───────────────────────────
_round_lock = threading.Lock()


def run_round(progress=None) -> dict:
    """完整跑一轮。progress(msg) 可选回调。"""
    if not _round_lock.acquire(blocking=False):
        return {"ok": False, "error": "已有一轮在跑"}

    def say(msg: str) -> None:
        add_log("info", msg)
        if progress:
            progress(msg)

    try:
        st = get_settings()
        started = now_iso()
        t0 = time.time()
        with connect() as c:
            rid = c.execute("INSERT INTO rounds(started, status) VALUES (?, 'running')",
                            (started,)).lastrowid

        # 1. 抓
        say("开始抓取…")
        allp, stats, errors = fetch_all(progress=say)
        say(f"去重后 {len(allp)} 个候选")
        if not allp:
            with connect() as c:
                c.execute("UPDATE rounds SET finished=?, status='failed', message=? WHERE id=?",
                          (now_iso(), "; ".join(errors)[:300], rid))
            return {"ok": False, "error": "没抓到代理", "details": errors}

        # 1.4 固定代理（clash 等）
        try:
            ns = sync_static(progress=say)
        except Exception as e:
            add_log("warn", f"固定代理同步失败: {type(e).__name__}: {e}")

        # 1.5 直连 OpenAI 入库（高产出源主力路径）
        try:
            di = ingest_direct(progress=say)
            if di.get("added"):
                say(f"直连入库新增 {di['added']} 个 OpenAI 可用")
        except Exception as e:
            add_log("warn", f"直连入库失败: {type(e).__name__}: {e}")

        # 2. 选
        picked, fresh_n = select_batch(allp, int(st["limit"]))
        say(f"本轮测活 {len(picked)} 个（新候选池 {fresh_n}）")

        # 3. 测
        tested = 0
        new_alive_total = 0
        died_total = 0
        newly_all: list[str] = []
        for i, part in enumerate(chunked(picked, max(50, int(st["batch"]))), 1):
            batch_auth = {}
            for u in part:
                _, _, _, hp = split_auth(u)
                batch_auth[hp] = u
            res = run_checker(part, int(st["threads"]), float(st["timeout"]),
                              bool(st["full"]), bool(st["require_https"]))
            na, nd, newly = apply_results(res, batch_auth)
            tested += len(part)
            new_alive_total += na
            died_total += nd
            newly_all.extend(newly)
            with connect() as c:
                alive_n = c.execute("SELECT COUNT(*) n FROM proxies WHERE alive=1").fetchone()["n"]
                c.execute("UPDATE rounds SET tested=?, new_alive=?, died=? WHERE id=?",
                          (tested, new_alive_total, died_total, rid))
            say(f"批次 {i}: {len(part)} 个 → 新增活 {na} 死 {nd} | 池内 {alive_n}")

        # 4. GeoIP（只查新存活的）
        if st["geo"] and newly_all:
            say(f"查 GeoIP {len(set(newly_all))} 个…")
            enrich_geo(list(dict.fromkeys(newly_all)))

        # 4.5 OpenAI 真实性探测（喂 codex2api 的关键）
        try:
            probe_openai(progress=say)
        except Exception as e:
            add_log("warn", f"OpenAI 探测失败: {type(e).__name__}: {e}")

        # 5. 淘汰
        pruned = prune(int(st["max_fail"]), int(st["max_size"]))
        if pruned:
            say(f"淘汰 {pruned} 个")

        dur = round(time.time() - t0, 1)
        with connect() as c:
            alive_n = c.execute("SELECT COUNT(*) n FROM proxies WHERE alive=1").fetchone()["n"]
            c.execute("UPDATE rounds SET finished=?, fetched=?, tested=?, alive=?, "
                      "pruned=?, duration=?, status='ok' WHERE id=?",
                      (now_iso(), len(allp), tested, alive_n, pruned, dur, rid))
        say(f"完成 {dur}s | 池内可用 {alive_n}")
        return {"ok": True, "fetched": len(allp), "tested": tested,
                "alive": alive_n, "new_alive": new_alive_total,
                "died": died_total, "pruned": pruned, "duration": dur, "round_id": rid}
    except Exception as e:
        add_log("error", f"轮次异常: {type(e).__name__}: {e}")
        try:
            with connect() as c:
                c.execute("UPDATE rounds SET finished=?, status='error', message=? WHERE id=?",
                          (now_iso(), str(e)[:300], rid))
        except Exception:
            pass
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        _round_lock.release()


# ─────────────────────────── 查询 ───────────────────────────
def _filter_sql(where: list, args: list, min_ok: int = 0) -> None:
    """把「白名单/黑名单/最低成功率」这类全局过滤条件拼进 where"""
    st = get_settings()

    allow = [c.strip().upper() for c in str(st.get("country_allow") or "").split(",") if c.strip()]
    if allow:
        where.append("country IN (%s)" % ",".join("?" * len(allow)))
        args.extend(allow)

    deny = [c.strip().upper() for c in str(st.get("country_deny") or "").split(",") if c.strip()]
    if deny:
        where.append("country NOT IN (%s)" % ",".join("?" * len(deny)))
        args.extend(deny)

    isp_deny = [k.strip() for k in str(st.get("isp_deny") or "").split(",") if k.strip()]
    for kw in isp_deny:
        where.append("COALESCE(isp,'') NOT LIKE ?")
        args.append(f"%{kw}%")

    need = max(int(min_ok or 0), int(st.get("min_ok_export") or 0))
    if need:
        where.append("ok_count>=?")
        args.append(need)


def query_proxies(country: str = "", scheme: str = "", ptype: str = "",
                  min_ok: int = 0, max_latency: int = 0, search: str = "",
                  sort: str = "latency", limit: int = 100, offset: int = 0,
                  schemes: list[str] | None = None,
                  https_only: bool = False,
                  openai_only: bool = False) -> tuple[list[dict], int]:
    where = ["alive=1"]
    args: list = []
    if country:
        where.append("country=?")
        args.append(country.upper())
    if scheme:
        where.append("scheme=?")
        args.append(scheme.lower())
    if schemes:
        where.append("scheme IN (%s)" % ",".join("?" * len(schemes)))
        args.extend([x.lower() for x in schemes])
    if https_only:
        where.append("https_ok=1")
    if openai_only:
        where.append("openai_ok=1")
    if ptype == "residential":
        where.append("hosting=0")
    elif ptype == "datacenter":
        where.append("hosting=1")
    _filter_sql(where, args, min_ok)
    if max_latency:
        where.append("latency_ms<=?")
        args.append(max_latency)
    if search:
        where.append("(url LIKE ? OR isp LIKE ?)")
        args += [f"%{search}%", f"%{search}%"]
    w = " AND ".join(where)
    order = {"latency": "latency_ms ASC", "ok": "ok_count DESC",
             "country": "country ASC", "recent": "last_ok DESC"}.get(sort, "latency_ms ASC")
    with connect() as c:
        total = c.execute(f"SELECT COUNT(*) n FROM proxies WHERE {w}", args).fetchone()["n"]
        rows = c.execute(f"SELECT * FROM proxies WHERE {w} ORDER BY {order} LIMIT ? OFFSET ?",
                         args + [limit, offset]).fetchall()
    return [dict(r) for r in rows], total


def report_feedback(url: str, ok: bool, note: str = "") -> dict:
    """
    外部软件反馈代理质量。
    ok=False 时累计连续失败，达到 max_fail 阈值立即下线（不用等下一轮）。
    ok=True  时加分并重置连续失败。
    注意：日志写入必须放在事务块外，否则 SQLite 会因嵌套连接报 database is locked。
    """
    st = get_settings()
    threshold = max(1, int(st.get("max_fail", 3)))
    ts = now_iso()
    hp = url.split("://", 1)[-1]
    took_offline = False

    with connect() as c:
        row = c.execute(
            "SELECT id, alive, consec_fail, ok_count FROM proxies WHERE url=?",
            (url,)).fetchone()
        if row is None:
            row = c.execute(
                "SELECT id, alive, consec_fail, ok_count FROM proxies "
                "WHERE host || ':' || port = ?", (hp,)).fetchone()
        if row is None:
            return {"ok": False, "error": "该代理不在池子里"}

        if ok:
            c.execute(
                "UPDATE proxies SET ok_count=ok_count+1, consec_fail=0, alive=1, "
                "last_ok=? WHERE id=?", (ts, row["id"]))
            return {"ok": True, "action": "marked_alive", "url": url,
                    "ok_count": int(row["ok_count"] or 0) + 1}

        new_cf = int(row["consec_fail"] or 0) + 1
        c.execute(
            "UPDATE proxies SET fail_count=fail_count+1, consec_fail=?, last_check=? "
            "WHERE id=?", (new_cf, ts, row["id"]))

        if st.get("report_offline") and new_cf >= threshold and row["alive"]:
            c.execute("UPDATE proxies SET alive=0 WHERE id=?", (row["id"],))
            took_offline = True

    if took_offline:
        add_log("info", f"反馈下线 {url}（连续失败 {new_cf}）")
        return {"ok": True, "action": "taken_offline", "url": url,
                "consec_fail": new_cf, "threshold": threshold}

    return {"ok": True, "action": "recorded", "url": url, "consec_fail": new_cf}


def feed_text(limit: int = 100, country: str = "", ptype: str = "",
              scheme: str = "", order: str = "latency") -> str:
    """
    给外部软件（codex2api 等）直接消费的纯文本列表。
    - 只输出目标软件支持的协议（默认 http/https/socks5，socks4 会被 codex2api 拒绝）
    - 单次硬上限 MAX_RETURN=100
    - 默认只给验证过 HTTPS CONNECT 的，避免对方拿去跑 https 全挂
    """
    st = get_settings()
    allow = [x.strip().lower() for x in str(st.get("feed_schemes") or "").split(",") if x.strip()]
    if not allow:
        allow = ["http", "https", "socks5"]
    n = max(1, min(int(limit or st.get("feed_limit") or MAX_RETURN), MAX_RETURN))
    use_openai = bool(st.get("openai_only_feed"))
    rows, _ = query_proxies(country=country, scheme=scheme, ptype=ptype,
                            schemes=allow, https_only=bool(st.get("feed_https_only")),
                            openai_only=use_openai,
                            sort=("latency" if order != "random" else "ok"),
                            limit=n, offset=0)
    if order == "random":
        random.shuffle(rows)
    return "\n".join(r["url"] for r in rows)


def stats() -> dict:
    with connect() as c:
        g = lambda q, *a: c.execute(q, a).fetchone()
        alive = g("SELECT COUNT(*) n FROM proxies WHERE alive=1")["n"]
        total = g("SELECT COUNT(*) n FROM proxies")["n"]
        resi = g("SELECT COUNT(*) n FROM proxies WHERE alive=1 AND hosting=0")["n"]
        dc = g("SELECT COUNT(*) n FROM proxies WHERE alive=1 AND hosting=1")["n"]
        avg = g("SELECT AVG(latency_ms) a FROM proxies WHERE alive=1 AND latency_ms IS NOT NULL")["a"] or 0
        https_ok = g("SELECT COUNT(*) n FROM proxies WHERE alive=1 AND https_ok=1")["n"]
        feed_ready = g("SELECT COUNT(*) n FROM proxies WHERE alive=1 AND https_ok=1 "
                       "AND scheme IN ('http','https','socks5')")["n"]
        openai_ok = g("SELECT COUNT(*) n FROM proxies WHERE alive=1 AND openai_ok=1")["n"]
        countries = [dict(r) for r in c.execute(
            "SELECT country, COUNT(*) n FROM proxies WHERE alive=1 AND country<>'' "
            "GROUP BY country ORDER BY n DESC LIMIT 40").fetchall()]
        schemes = [dict(r) for r in c.execute(
            "SELECT scheme, COUNT(*) n FROM proxies WHERE alive=1 GROUP BY scheme").fetchall()]
        last = g("SELECT * FROM rounds ORDER BY id DESC LIMIT 1")
        rounds = g("SELECT COUNT(*) n FROM rounds WHERE status='ok'")["n"]
    return {
        "alive": alive, "total": total, "residential": resi, "datacenter": dc,
        "https_ok": https_ok, "feed_ready": feed_ready, "openai_ok": openai_ok,
        "avg_latency": round(avg), "countries": countries, "schemes": schemes,
        "country_count": len(countries), "rounds": rounds,
        "last_round": dict(last) if last else None,
        "version": VERSION,
    }


def export_lines(fmt: str = "txt", country: str = "", scheme: str = "",
                 ptype: str = "", limit: int = 0, sort: str = "latency") -> str:
    rows, _ = query_proxies(country=country, scheme=scheme, ptype=ptype,
                            sort=sort, limit=limit or 100000, offset=0)
    if fmt == "txt":
        return "\n".join(r["url"] for r in rows)
    if fmt == "plain":
        return "\n".join(r["host"] + ":" + str(r["port"]) for r in rows)
    if fmt == "csv":
        head = "url,host,port,scheme,country,isp,hosting,latency_ms,ok_count,last_ok"
        body = [head] + [
            f'{r["url"]},{r["host"]},{r["port"]},{r["scheme"]},{r["country"]},'
            f'"{r["isp"]}",{"" if r["hosting"] is None else r["hosting"]},'
            f'{r["latency_ms"] or ""},{r["ok_count"]},{r["last_ok"] or ""}'
            for r in rows]
        return "\n".join(body)
    return json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=1)


def random_one(ptype: str = "", country: str = "", scheme: str = "") -> dict | None:
    rows, _ = query_proxies(country=country, scheme=scheme, ptype=ptype,
                            limit=50, sort="latency")
    if not rows:
        return None
    top = rows[: min(20, len(rows))]      # 只在最快的一批里随机，避免抽到最烂的
    return random.choice(top)


if __name__ == "__main__":
    init_db()
    print(json.dumps(stats(), ensure_ascii=False, indent=1))
