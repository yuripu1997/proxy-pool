#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server.py — 代理池服务：定时抓取 + 测活 + Web UI + 通用代理 API

    python3 server.py                              # http://127.0.0.1:8787（无鉴权，仅本机）
    python3 server.py --bind 0.0.0.0 --token KEY   # 开鉴权，UI 需要登录
    python3 server.py --token KEY --api-public     # UI 要登录，/proxy 对外开放

零第三方依赖，Python 3.8+。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import core

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"

STATE = {
    "token": "",
    "scheduler_on": True,
    "next_run_at": 0.0,
    "running": False,
    "last_result": None,
}
_state_lock = threading.Lock()

# 简易限流：每 IP 每分钟最多 N 次
RATE_LIMIT = 180
RATE_WINDOW = 60
_hits: dict[str, deque] = defaultdict(deque)
_login_fails: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()
LOGIN_MAX_FAIL = 8          # 每 IP 每分钟最多失败 8 次
LOGIN_WINDOW = 60


def login_blocked(ip: str) -> bool:
    now = time.time()
    with _hits_lock:
        q = _login_fails[ip]
        while q and now - q[0] > LOGIN_WINDOW:
            q.popleft()
        return len(q) >= LOGIN_MAX_FAIL


def login_fail(ip: str) -> None:
    with _hits_lock:
        _login_fails[ip].append(time.time())


def rate_ok(ip: str) -> bool:
    now = time.time()
    with _hits_lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        if len(_hits) > 5000:            # 防内存膨胀
            for k in list(_hits)[:1000]:
                if not _hits[k]:
                    _hits.pop(k, None)
        return True


# ─────────────────────────── 会话 ───────────────────────────
SESSION_TTL = 7 * 86400


def make_session(token: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = str(exp)
    sig = hmac.new(token.encode(), payload.encode(), hashlib.sha256).hexdigest()[:40]
    return f"{payload}.{sig}"


def check_session(cookie: str, token: str) -> bool:
    if not cookie or "." not in cookie or not token:
        return False
    payload, _, sig = cookie.rpartition(".")
    try:
        if int(payload) < time.time():
            return False
    except ValueError:
        return False
    want = hmac.new(token.encode(), payload.encode(), hashlib.sha256).hexdigest()[:40]
    return hmac.compare_digest(sig, want)


# ─────────────────────────── 调度器 ───────────────────────────
class Scheduler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="scheduler")
        self.wake = threading.Event()

    def run(self) -> None:
        while True:
            st = core.get_settings()
            interval = max(300, int(st["interval"]))
            with _state_lock:
                STATE["next_run_at"] = time.time() + interval
            self.wake.wait(timeout=interval)
            self.wake.clear()
            st = core.get_settings()
            if not st.get("enabled"):
                continue
            with _state_lock:
                if STATE["running"]:
                    continue
                STATE["running"] = True
            try:
                res = core.run_round()
                with _state_lock:
                    STATE["last_result"] = res
            finally:
                with _state_lock:
                    STATE["running"] = False


def trigger_round() -> dict:
    with _state_lock:
        if STATE["running"]:
            return {"ok": False, "error": "已有一轮在跑"}
        STATE["running"] = True
    try:
        res = core.run_round()
        with _state_lock:
            STATE["last_result"] = res
        return res
    finally:
        with _state_lock:
            STATE["running"] = False


def trigger_async() -> dict:
    with _state_lock:
        if STATE["running"]:
            return {"ok": False, "error": "已有一轮在跑"}
    threading.Thread(target=trigger_round, daemon=True).start()
    return {"ok": True, "message": "已在后台开始"}


# ─────────────────────────── HTTP ───────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ProxyPool · 登录</title>
<style>
:root{--bg:#0e1116;--panel:#161a22;--line:#252b36;--tx:#e6e9ef;--tx2:#8b94a7;--green:#3ddc84}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:var(--bg);color:var(--tx);font:14px/1.6 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif}
.box{width:340px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{font-size:17px;margin:0 0 4px}p{color:var(--tx2);font-size:12.5px;margin:0 0 20px}
input{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--line);background:#1c212b;
color:var(--tx);font:inherit;outline:none;margin-bottom:12px}input:focus{border-color:var(--green)}
button{width:100%;padding:11px;border:0;border-radius:9px;background:var(--green);color:#06170d;
font:inherit;font-weight:600;cursor:pointer}button:hover{filter:brightness(1.08)}
.err{color:#ff6b6b;font-size:12.5px;margin-bottom:10px;display:{{ERR_DISPLAY}}}
</style></head><body><div class="box">
<h1>ProxyPool</h1><p>请输入访问密钥</p>
{{ERR_MSG}}
<form method="POST" action="/login">
<input type="password" name="token" placeholder="访问密钥" autofocus autocomplete="current-password">
<button type="submit">进入</button></form></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ProxyPool"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---------- 基础 ----------
    def log_message(self, fmt, *args):
        pass

    def _client_ip(self) -> str:
        """取真实客户端 IP；IPv6 归并到 /64，防止攻击者在一个段内轮换地址绕过限流"""
        ip = (self.headers.get("X-Real-IP") or self.client_address[0] or "").strip()
        if not ip:
            return "unknown"
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                if addr.ipv4_mapped:
                    return str(addr.ipv4_mapped)
                return str(ipaddress.ip_network(f"{ip}/64", strict=False))
            return str(addr)
        except ValueError:
            return ip

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Token, Authorization")

    def _sec_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
        self._cors()
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

    def _text(self, s: str, code: int = 200, ctype: str = "text/plain; charset=utf-8") -> None:
        self._send(code, s.encode("utf-8"), ctype)

    def _cookie(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _authed(self, q: dict) -> bool:
        """三种方式任一通过：?token= / X-API-Token 头 / 登录 cookie"""
        token = STATE["token"]
        if not token:
            return True
        got = q.get("token", [""])[0] or self.headers.get("X-API-Token", "")
        if not got:
            auth = self.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                got = auth[7:]
        if got and hmac.compare_digest(got, token):
            return True
        return check_session(self._cookie("pp_session"), token)

    def _q(self) -> dict:
        return urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

    # ---------- 路由 ----------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not rate_ok(self._client_ip()):
            return self._json({"ok": False, "error": "请求过快，稍后再试"}, 429)

        parsed = urllib.parse.urlparse(self.path)
        path, q = parsed.path, self._q()

        # 公开
        if path == "/health":
            return self._json({"ok": True, "version": core.VERSION,
                               "running": STATE["running"], "ts": core.now_iso()})

        if path == "/login":
            return self._login_page()

        # 通用代理接口（可配置为免鉴权）
        if path in ("/proxy", "/proxy.txt", "/proxies", "/api/proxy"):
            st = core.get_settings()
            if not st.get("api_public") and not self._authed(q):
                return self._text("unauthorized", 401)
            return self._serve_proxy(q)

        # 机器对接专用 feed：密钥在路径里，不需要请求头（codex2api 这类只发 GET）
        if path.startswith("/feed/"):
            key = path[len("/feed/"):].strip("/")
            st = core.get_settings()
            want = (st.get("feed_key") or "").strip()
            token = STATE["token"]
            if not (key and ((want and hmac.compare_digest(key, want))
                             or (token and hmac.compare_digest(key, token)))):
                return self._text("unauthorized", 401)
            return self._serve_feed(q)

        if path == "/proxy/one":
            st = core.get_settings()
            if not st.get("api_public") and not self._authed(q):
                return self._text("unauthorized", 401)
            ptype = (q.get("type", [""])[0] or "").lower()
            row = core.random_one(ptype=ptype,
                                  country=q.get("country", [""])[0],
                                  scheme=q.get("scheme", [""])[0])
            if not row:
                return self._json({"ok": False, "error": "池子里没有可用代理"}, 404)
            fmt = q.get("format", ["url"])[0]
            if fmt == "json":
                return self._json(row)
            if fmt == "plain":
                return self._text(f'{row["host"]}:{row["port"]}')
            return self._text(row["url"])

        # 未登录访问 UI → 登录页
        if path == "/" or path == "/index.html":
            if not self._authed(q):
                return self._login_page()
            return self._serve_file(STATIC / "index.html")

        if path.startswith("/static/"):
            if not self._authed(q):
                return self._text("unauthorized", 401)
            rel = path[len("/static/"):]
            target = (STATIC / rel).resolve()
            if STATIC.resolve() not in target.parents and target != STATIC.resolve():
                return self._text("forbidden", 403)
            return self._serve_file(target)

        # 以下全部需要鉴权
        if not self._authed(q):
            return self._json({"ok": False, "error": "unauthorized"}, 401)

        if path == "/api/stats":
            st = core.stats()
            with _state_lock:
                st["running"] = STATE["running"]
                st["next_run_at"] = STATE["next_run_at"]
                st["scheduler_on"] = STATE["scheduler_on"]
                st["last_result"] = STATE["last_result"]
            st["settings"] = core.get_settings()
            return self._json(st)

        if path == "/api/proxies":
            limit = min(core.MAX_RETURN, int(q.get("limit", ["100"])[0] or 100))
            offset = max(0, int(q.get("offset", ["0"])[0] or 0))
            _t = (q.get("type", [""])[0] or "").lower()
            rows, total = core.query_proxies(
                country=q.get("country", [""])[0],
                scheme=q.get("scheme", [""])[0],
                ptype=("" if _t == "openai" else _t),
                openai_only=(_t == "openai"),
                min_ok=int(q.get("min_ok", ["0"])[0] or 0),
                max_latency=int(q.get("max_latency", ["0"])[0] or 0),
                search=q.get("q", [""])[0],
                sort=q.get("sort", ["latency"])[0],
                limit=limit, offset=offset)
            return self._json({"ok": True, "total": total, "limit": limit,
                               "offset": offset, "items": rows})

        if path == "/api/export":
            fmt = q.get("format", ["txt"])[0]
            _lim = int(q.get("limit", ["0"])[0] or 0)
            _lim = min(_lim, core.MAX_RETURN) if _lim else core.MAX_RETURN
            body = core.export_lines(
                fmt=fmt,
                country=q.get("country", [""])[0],
                scheme=q.get("scheme", [""])[0],
                ptype=(q.get("type", [""])[0] or "").lower(),
                limit=_lim)
            ctype = {"json": "application/json; charset=utf-8",
                     "csv": "text/csv; charset=utf-8"}.get(fmt, "text/plain; charset=utf-8")
            return self._text(body, ctype=ctype)

        if path == "/api/rounds":
            with core.connect() as c:
                rows = [dict(r) for r in c.execute(
                    "SELECT * FROM rounds ORDER BY id DESC LIMIT 50").fetchall()]
            return self._json({"ok": True, "items": rows})

        if path == "/api/logs":
            return self._json({"ok": True, "items": core.get_logs(int(q.get("limit", ["200"])[0] or 200))})

        if path == "/api/settings":
            return self._json({"ok": True, "settings": core.get_settings(),
                               "sources_available": list(core.SOURCES.keys())})

        if path == "/api/sources":
            return self._json({"ok": True, "items": core.get_sources()})

        return self._json({"ok": False, "error": "not found"}, 404)

    def do_POST(self):
        if not rate_ok(self._client_ip()):
            return self._json({"ok": False, "error": "请求过快"}, 429)

        parsed = urllib.parse.urlparse(self.path)
        path, q = parsed.path, self._q()

        # 登录表单（form 提交）
        if path == "/login":
            if login_blocked(self._client_ip()):
                return self._send(429, b"too many attempts, wait a minute",
                                  "text/plain; charset=utf-8")
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            form = urllib.parse.parse_qs(raw)
            given = (form.get("token", [""])[0] or "").strip()
            if STATE["token"] and hmac.compare_digest(given, STATE["token"]):
                cookie = make_session(STATE["token"])
                body = b"<html><meta http-equiv='refresh' content='0;url=/'></html>"
                return self._send(302, body, "text/html; charset=utf-8", {
                    "Set-Cookie": f"pp_session={cookie}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}",
                    "Location": "/",
                })
            login_fail(self._client_ip())
            return self._login_page(error="密钥不正确")

        if not self._authed(q):
            return self._json({"ok": False, "error": "unauthorized"}, 401)

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._json({"ok": False, "error": "bad json"}, 400)

        if path == "/api/run":
            return self._json(trigger_async())

        if path == "/api/settings":
            patch = {k: v for k, v in body.items() if k in core.DEFAULT_SETTINGS}
            st = core.set_settings(patch)
            if "interval" in patch:
                sched.wake.set()
            return self._json({"ok": True, "settings": st})

        if path == "/api/sources":
            name = (body.get("name") or "").strip()
            if not name:
                return self._json({"ok": False, "error": "缺少 name"}, 400)
            ok = core.set_source(name, body)
            return self._json({"ok": ok, "items": core.get_sources()})

        if path == "/api/report":
            url = (body.get("url") or "").strip()
            if not url:
                return self._json({"ok": False, "error": "缺少 url"}, 400)
            ok = bool(body.get("ok", True))
            note = str(body.get("note") or "")[:200]
            res = core.report_feedback(url, ok, note)
            return self._json(res, 200 if res.get("ok") else 404)

        if path == "/api/probe-openai":
            res = core.probe_openai(limit=int(body.get("limit", 0) or 0))
            return self._json({"ok": True, **res})

        if path == "/api/prune":
            n = core.prune(int(body.get("max_fail", 3)), int(body.get("max_size", 5000)))
            return self._json({"ok": True, "pruned": n})

        if path == "/api/logout":
            return self._send(200, b'{"ok":true}', extra={
                "Set-Cookie": "pp_session=; Path=/; Max-Age=0"})

        return self._json({"ok": False, "error": "not found"}, 404)

    # ---------- 具体实现 ----------
    def _login_page(self, error: str = ""):
        html = (LOGIN_HTML
                .replace("{{ERR_DISPLAY}}", "block" if error else "none")
                .replace("{{ERR_MSG}}", f'<div class="err">{error}</div>' if error else ""))
        return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_feed(self, q: dict) -> None:
        """给外部软件用的纯文本 feed：http/https/socks5、只给 HTTPS 可用、≤100 条"""
        limit = int(q.get("limit", ["0"])[0] or 0)
        body = core.feed_text(
            limit=limit or core.get_settings().get("feed_limit", core.MAX_RETURN),
            country=q.get("country", [""])[0],
            ptype=(q.get("type", [""])[0] or "").lower(),
            scheme=q.get("scheme", [""])[0],
            order=q.get("order", ["latency"])[0])
        return self._text(body)

    def _serve_proxy(self, q: dict) -> None:
        fmt = q.get("format", ["txt"])[0].lower()
        country = q.get("country", [""])[0]
        scheme = q.get("scheme", [""])[0]
        ptype = (q.get("type", [""])[0] or "").lower()
        limit = int(q.get("limit", ["0"])[0] or 0)
        limit = min(limit, core.MAX_RETURN) if limit else core.MAX_RETURN

        if fmt in ("plain", "host"):
            return self._text(core.export_lines("plain", country=country, scheme=scheme,
                                                ptype=ptype, limit=limit))
        if fmt == "json":
            rows, _ = core.query_proxies(country=country, scheme=scheme, ptype=ptype,
                                         limit=limit or 100, offset=0)
            return self._json(rows)
        if fmt == "csv":
            return self._text(core.export_lines("csv", country=country, scheme=scheme,
                                                ptype=ptype, limit=limit),
                              ctype="text/csv; charset=utf-8")
        return self._text(core.export_lines("txt", country=country, scheme=scheme,
                                            ptype=ptype, limit=limit))

    def _serve_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            return self._text("not found", 404)
        ctype = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(200, path.read_bytes(), ctype)


sched = Scheduler()


def main() -> int:
    ap = argparse.ArgumentParser(description="代理池服务：抓取 + 测活 + UI + API")
    ap.add_argument("--bind", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    ap.add_argument("--port", type=int, default=8787, help="端口（默认 8787）")
    ap.add_argument("--token", default="", help="访问密钥；设置后 UI 需要登录")
    ap.add_argument("--api-public", action="store_true", help="/proxy 免鉴权（UI 仍需登录）")
    ap.add_argument("--no-scheduler", action="store_true", help="不启动定时任务")
    ap.add_argument("--run-now", action="store_true", help="启动后立刻跑一轮")
    args = ap.parse_args()

    core.init_db()
    STATE["token"] = args.token or ""
    if args.api_public:
        core.set_settings({"api_public": 1})
    core.add_log("info", f"服务启动 {args.bind}:{args.port}")

    if not args.no_scheduler:
        sched.start()
    if args.run_now:
        threading.Thread(target=trigger_round, daemon=True).start()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    shown = "127.0.0.1" if args.bind in ("0.0.0.0", "::") else args.bind
    print(f"ProxyPool {core.VERSION}  →  http://{shown}:{args.port}")
    if args.token:
        print("鉴权已开启：UI 需登录，API 需带 ?token= 或 X-API-Token")
    else:
        print("未设置 --token：任何人都能访问，绑公网请务必加 --token")
    print("Ctrl-C 退出")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
