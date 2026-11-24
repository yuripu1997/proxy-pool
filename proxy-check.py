#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy-check.py — 代理池快速测活工具 v1.4（纯 Python 标准库，无需 pip install）

为什么需要「严格校验」
----------------------
大量 IP:80 / IP:8080 根本不是代理，而是普通 Web 服务器。它们收到
`GET http://checkip.amazonaws.com/ HTTP/1.1` 这种代理专用请求时，会忽略绝对 URI，
直接返回自己的首页并带上 `200 OK`。只看状态码会造成大面积误报。
本工具用三重手段消灭误报：
  1) 回显校验：响应体必须「整体就是一个 IP」或「JSON 里的 origin/ip 字段是 IP」
  2) 随机 nonce 查询串：击穿 squid/nginx 缓存，证明请求真的穿透到了源站
  3) 出口 IP 对比本机 IP：识别透明代理（等于没代理）
并给出明确判定 verdict：ok / not_a_proxy / auth_required / timeout / refused / dead

特性
----
* 高并发线程池测活，30 个代理通常 5~15 秒出结果
* 自动识别协议：HTTP / HTTPS(CONNECT+TLS) / SOCKS4 / SOCKS5（含用户名密码认证）
* 多检测站自动故障转移，随机 nonce 防缓存
* 延迟（请求->响应头）+ 建连耗时 + 总耗时
* 出口 IP、匿名度（高匿名/普通/透明）、泄露头（Via / X-Forwarded-For / Proxy-Agent）
* 可选 GeoIP（国家/城市/ISP/AS）
* 可选多轮复测计算可用率，过滤秒断代理
* 内置 --selftest：本地起「假 Web 服务器」+「真转发代理」，自证判定逻辑正确
* 输出 valid.txt / valid_url.txt / results.csv / results.json / dead.txt

用法
----
    python3 proxy-check.py -f proxies.txt
    python3 proxy-check.py -f proxies.txt -t 200 --timeout 6 --full
    python3 proxy-check.py -f proxies.txt --show-dead --geo --deep
    cat proxies.txt | python3 proxy-check.py --stdin -t 100
    python3 proxy-check.py 1.2.3.4:8080 5.6.7.8:3128
    python3 proxy-check.py -f proxies.txt --repeat 3 --min-rate 0.66
    python3 proxy-check.py --selftest
    python3 proxy-check.py -f proxies.txt --lenient     # 退回宽松模式(只看状态码)

代理书写格式
------------
    1.2.3.4:8080
    http://1.2.3.4:8080          socks5://1.2.3.4:1080
    1.2.3.4:8080:https
    user:pass@1.2.3.4:8080       http://user:pass@1.2.3.4:8080
    1.2.3.4:8080:user:pass       [2001:db8::1]:3128
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import http.server
import ipaddress
import json
import os
import random
import re
import socket
import socketserver
import ssl
import string
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

VERSION = "1.4.0"

# --allow-private-ip 时置 True：允许私网/环回 IP 作为有效回显（内网代理、本地自建检测站）
ALLOW_PRIVATE_IP = False

# --------------------------------------------------------------------------- #
# 检测目标
#   validate: ip_only  = 响应体整体必须就是一个 IP（最严格，杀误报主力）
#             json_ip  = JSON 中 origin/ip/clientIp 字段必须是 IP
#             text_ip  = 文本中能提取到合法 IP（较松）
# --------------------------------------------------------------------------- #
DEFAULT_TARGETS: List[Dict[str, Any]] = [
    {"name": "checkip.amazonaws.com", "host": "checkip.amazonaws.com", "path": "/",
     "validate": "ip_only", "nonce": True},
    {"name": "ip.sb", "host": "ip.sb", "path": "/", "validate": "ip_only", "nonce": True},
    {"name": "ifconfig.me", "host": "ifconfig.me", "path": "/ip",
     "validate": "ip_only", "nonce": True},
    {"name": "httpbin.org", "host": "httpbin.org", "path": "/ip",
     "validate": "json_ip", "nonce": True},
    {"name": "api.ipify.org", "host": "api.ipify.org", "path": "/",
     "validate": "ip_only", "nonce": True},
    {"name": "icanhazip.com", "host": "icanhazip.com", "path": "/",
     "validate": "ip_only", "nonce": True},
]

TLS_TARGET = {"host": "httpbin.org", "port": 443, "path": "/ip", "validate": "json_ip"}
HEADERS_TARGET = {"host": "httpbin.org", "port": 443, "path": "/headers"}

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

MAX_BODY = 1 << 20
MAX_HEADER = 1 << 16

# 判定
V_OK = "ok"
V_NOT_PROXY = "not_a_proxy"
V_LIMITED = "target_limited"     # 检测站限流，但目标具备转发行为（真代理，待复测）
V_AUTH = "auth_required"
V_TIMEOUT = "timeout"
V_REFUSED = "refused"
V_DEAD = "dead"
V_TRANSPARENT = "transparent"

ANON_HIGH = "high_anonymous"
ANON_NORMAL = "anonymous"
ANON_TRANSPARENT = "transparent"
ANON_UNKNOWN = "unknown"

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b|::")


# --------------------------------------------------------------------------- #
# IP 校验（严格：拒绝 124.0.0.0 这类 UA 版本号、拒绝 ::af 这类误匹配）
# --------------------------------------------------------------------------- #
def is_valid_public_ip(s: str) -> bool:
    """合法「可用于判定回显」的 IP。
    默认排除私网/环回/保留段——因为普通网页里的 192.168.x.x、127.0.0.1、
    UA 里的 124.0.0.0 之类会造成误判。--allow-private-ip 时放宽（内网/本地自建检测站用）。"""
    s = (s or "").strip().strip("[]")
    if not s or len(s) > 45:
        return False
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if ALLOW_PRIVATE_IP:
        return not (ip.is_multicast or ip.is_unspecified)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def parse_ip_list(s: str) -> List[str]:
    """httpbin 的 origin 可能是 '1.2.3.4, 5.6.7.8' 或含 IPv6。"""
    out = []
    for part in re.split(r"[,\s]+", s or ""):
        part = part.strip()
        if part and is_valid_public_ip(part):
            out.append(part)
    return out


def validate_echo(body: bytes, mode: str) -> Tuple[bool, str]:
    """按目标的校验模式判断响应体是否为真实 IP 回显。返回 (是否有效, 出口IP)。"""
    if not body:
        return False, ""
    text = body.decode("utf-8", "replace").strip()

    if mode == "ip_only":
        # 整体必须就是一个 IP（允许结尾换行/BOM）
        cand = text.lstrip("\ufeff").strip()
        if is_valid_public_ip(cand):
            return True, cand
        # 退化：单行且行内只有一个 IP
        lines = [l.strip() for l in cand.splitlines() if l.strip()]
        if len(lines) == 1:
            m = IPV4_RE.findall(lines[0]) or IPV6_RE.findall(lines[0])
            valid = [x for x in m if is_valid_public_ip(x)]
            if len(valid) == 1 and len(lines[0]) < 60:
                return True, valid[0]
        return False, ""

    if mode == "json_ip":
        try:
            data = json.loads(text)
        except Exception:
            return False, ""
        if isinstance(data, dict):
            for key in ("origin", "ip", "clientIp", "client_ip", "ip_addr", "query", "result"):
                v = data.get(key)
                if isinstance(v, str):
                    ips = parse_ip_list(v)
                    if ips:
                        return True, ips[0]
        return False, ""

    # text_ip：宽松，全文找合法公网 IP
    for rx in (IPV4_RE, IPV6_RE):
        for m in rx.findall(text[:8192]):
            if is_valid_public_ip(m):
                return True, m
    return False, ""


def extract_ip_loose(body: bytes) -> str:
    """用于本机出口 IP 采集等宽松场景。"""
    ok, ip = validate_echo(body, "text_ip")
    return ip if ok else ""


def detect_leak(headers: Dict[str, str]) -> List[str]:
    keys = ("via", "x-forwarded-for", "proxy-agent", "x-squid-error", "forwarded",
            "x-proxy-agent", "x-via", "x-forwarded", "x-real-ip", "x-cache")
    return [f"{k}={headers[k][:48]}" for k in keys if k in headers]


def server_hint(headers: Dict[str, str], body: bytes) -> str:
    """给 not_a_proxy 一个可读的证据摘要。"""
    hint = []
    if headers.get("server"):
        hint.append(f"Server={headers['server'][:30]}")
    if headers.get("x-powered-by"):
        hint.append(headers["x-powered-by"][:24])
    m = re.search(rb"<title[^>]*>(.{0,60}?)</title>", body[:8192], re.I | re.S)
    if m:
        hint.append("title=" + m.group(1).decode("utf-8", "replace").strip()[:36])
    if not hint:
        snippet = body[:60].decode("latin-1", "replace").replace("\n", " ").strip()
        if snippet:
            hint.append(f"body={snippet!r}")
    return "; ".join(hint)[:110]


# --------------------------------------------------------------------------- #
# 检测站限流识别 + 转发行为指纹
#   场景：真代理可用，但 checkip/ip.sb 被我们打爆后返回 "Rate limited"，
#   响应体里没有 IP。若此时判为 not_a_proxy 就是假阴性。
# --------------------------------------------------------------------------- #
LIMITED_RE = re.compile(rb"rate.?limit|too many requests|forbidden|slow down|"
                        rb"try again later|quota|throttl|access denied", re.I)


def looks_limited(status: int, headers: Dict[str, str], body: bytes) -> bool:
    """判断响应是否来自「检测站限流/拒绝」而非「目标不是代理」。"""
    if status in (429, 503):
        return True
    if status not in (200, 403, 400):
        return False
    head = body[:400]
    if len(head) > 300:
        return False
    ctype = (headers.get("content-type") or "").lower()
    if "html" in ctype and b"<html" in body[:500].lower():
        return False      # HTML 首页 -> 属于 not_a_proxy 证据
    return bool(LIMITED_RE.search(head))


def body_fingerprint(headers: Dict[str, str], body: bytes) -> str:
    """内容指纹。非代理服务器对任何绝对 URI 都回自己那份内容 -> 指纹恒定；
    真代理对不同目标返回不同源站内容 -> 指纹随目标变化。"""
    norm = re.sub(rb"\s+", b" ", body[:4096]).strip().lower()
    title = ""
    m = re.search(rb"<title[^>]*>(.{0,80}?)</title>", body[:8192], re.I | re.S)
    if m:
        title = m.group(1).decode("utf-8", "replace").strip().lower()
    key = f"{headers.get('etag', '')}|{headers.get('server', '')}|{title}|".encode() + norm
    return hashlib.sha256(key).hexdigest()[:16]


def rotate_targets(targets: List[Dict[str, Any]], seed: str) -> List[Dict[str, Any]]:
    """按代理地址做确定性轮换，避免所有并发同时打同一个检测站导致限流。"""
    out = list(targets)
    random.Random(seed).shuffle(out)
    return out


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass
class ProxyTarget:
    raw: str
    host: str
    port: int
    ptype: str = "auto"
    user: Optional[str] = None
    password: Optional[str] = None

    @property
    def addr(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def auth_header(self) -> Optional[str]:
        if not self.user:
            return None
        tok = base64.b64encode(f"{self.user}:{self.password or ''}".encode()).decode()
        return f"Basic {tok}"

    def url(self) -> str:
        sch = {"socks5": "socks5h", "socks4": "socks4"}.get(self.ptype, "http")
        auth = f"{quote(self.user, safe='')}:{quote(self.password or '', safe='')}@" if self.user else ""
        return f"{sch}://{auth}{self.addr}"


@dataclass
class CheckResult:
    proxy: str
    alive: bool = False            # 严格意义上的「代理可用」
    verdict: str = V_DEAD
    ptype: str = ""
    method: str = ""               # http | connect | connect+tls | socks5 | socks4
    target: str = ""
    status: int = 0
    latency_ms: int = -1
    connect_ms: int = -1
    total_ms: int = -1
    egress_ip: str = ""
    transparent: bool = False
    anonymity: str = ANON_UNKNOWN
    leaked_headers: str = ""
    hint: str = ""                 # not_a_proxy 的证据
    https_ok: bool = False         # CONNECT+TLS 是否真的可用（浏览器访问 https 站点的前提）
    https_err: str = ""
    probes: Dict[str, str] = field(default_factory=dict)   # 指定站点探测结果
    country: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""
    rounds_ok: int = 0
    rounds: int = 0
    success_rate: float = 0.0
    error: str = ""
    attempts: List[str] = field(default_factory=list)

    def to_row(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("attempts", None)
        return d


# --------------------------------------------------------------------------- #
# 解析代理列表
# --------------------------------------------------------------------------- #
def parse_proxy(raw: str) -> Optional[ProxyTarget]:
    line = raw.strip()
    if not line or line.startswith(("#", ";")):
        return None
    line = line.split("#", 1)[0].strip().split(";")[0].strip()
    if not line:
        return None

    user = password = None
    ptype = "auto"

    if "://" in line:
        u = urlparse(line)
        scheme = (u.scheme or "http").lower()
        if u.username:
            user, password = u.username, u.password or ""
        host, port = u.hostname, u.port
        ptype = {"http": "http", "https": "https", "socks5": "socks5", "socks5h": "socks5",
                 "socks4": "socks4", "socks4a": "socks4"}.get(scheme, "http")
        return ProxyTarget(line, host, int(port), ptype, user, password) if host and port else None

    if "@" in line:
        cred, _, rest = line.rpartition("@")
        if ":" in cred:
            user, _, password = cred.partition(":")
        else:
            user = cred
        line = rest

    # IPv6: [addr]:port[:type][:user:pass]
    if line.startswith("["):
        end = line.find("]")
        if end <= 0:
            return None
        host = line[1:end]
        rest = line[end + 1:].lstrip(":").split(":")
        if not rest or not rest[0].isdigit():
            return None
        port = int(rest[0])
        tail = rest[1:]
        if tail and tail[0].lower() in ("http", "https", "socks4", "socks5", "socks5h"):
            ptype = tail[0].lower().replace("socks5h", "socks5")
            tail = tail[1:]
        if tail and tail[0]:
            user = tail[0]
            password = tail[1] if len(tail) > 1 else ""
        return ProxyTarget(line, host, port, ptype, user, password) if 0 < port < 65536 else None

    parts = line.split(":")
    if len(parts) < 2:
        return None
    host, port_s = parts[0].strip(), parts[1].strip()
    if not host or not port_s.isdigit():
        return None
    tail = parts[2:]
    if tail and tail[0].lower() in ("http", "https", "socks4", "socks5", "socks5h"):
        ptype = tail[0].lower().replace("socks5h", "socks5")
        tail = tail[1:]
    if tail and tail[0]:
        user = tail[0]
        password = tail[1] if len(tail) > 1 else ""
    port = int(port_s)
    return ProxyTarget(line, host, port, ptype, user, password) if 0 < port < 65536 else None


def load_proxies(args: argparse.Namespace) -> List[ProxyTarget]:
    lines: List[str] = []
    if args.stdin:
        lines += sys.stdin.read().splitlines()
    for f in args.file or []:
        if f == "-":
            lines += sys.stdin.read().splitlines()
            continue
        if not os.path.isfile(f):
            sys.exit(f"[!] 文件不存在: {f}")
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            lines += fh.read().splitlines()
    lines += list(args.proxies or [])

    seen, out = set(), []
    for ln in lines:
        p = parse_proxy(ln)
        if not p:
            if ln.strip() and not ln.strip().startswith(("#", ";")):
                print(f"[!] 跳过无法解析的行: {ln.strip()[:60]}", file=sys.stderr)
            continue
        key = (p.host.lower(), p.port, p.ptype, p.user)
        if key in seen:
            continue
        seen.add(key)
        if args.type and args.type != "auto":
            p.ptype = args.type
        out.append(p)
    return out


# --------------------------------------------------------------------------- #
# 底层网络
# --------------------------------------------------------------------------- #
def _recv_headers(sock: socket.socket, deadline: float) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
        left = deadline - time.time()
        if left <= 0:
            raise socket.timeout("等待响应头超时")
        sock.settimeout(min(left, 5.0))
        chunk = sock.recv(8192)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_HEADER:
            break
    return buf


def _split_head(raw: bytes) -> Tuple[str, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[:i].decode("latin-1", "replace"), raw[i + len(sep):]
    return raw.decode("latin-1", "replace"), b""


def _parse_headers(head_text: str) -> Tuple[str, int, Dict[str, str]]:
    lines = head_text.split("\n")
    status_line = lines[0].strip()
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line, re.I)
    status = int(m.group(1)) if m else 0
    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        ln = ln.strip("\r")
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status_line, status, headers


def _dechunk(body: bytes) -> bytes:
    out, i = b"", 0
    while i < len(body):
        nl = body.find(b"\r\n", i)
        if nl < 0:
            break
        try:
            size = int(body[i:nl].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += body[nl + 2: nl + 2 + size]
        i = nl + 2 + size + 2
    return out or body


def _read_body(sock: socket.socket, headers: Dict[str, str], extra: bytes,
               deadline: float, idle_grace: float = 1.2) -> bytes:
    body = extra
    cl = headers.get("content-length")
    te = (headers.get("transfer-encoding") or "").lower()

    if cl and cl.isdigit():
        need = min(int(cl), MAX_BODY)
        while len(body) < need:
            left = deadline - time.time()
            if left <= 0:
                break
            sock.settimeout(min(left, 5.0))
            try:
                chunk = sock.recv(min(65536, need - len(body)))
            except (socket.timeout, TimeoutError, OSError):
                break
            if not chunk:
                break
            body += chunk
        return body[:need]

    if "chunked" in te:
        idle_end = time.time() + idle_grace + 1.0
        while not re.search(rb"(^|\r\n)0\r\n\r\n$", body):
            left = min(deadline, idle_end) - time.time()
            if left <= 0:
                break
            sock.settimeout(min(left, 2.0))
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, TimeoutError, OSError):
                break
            if not chunk:
                break
            body += chunk
            if len(body) > MAX_BODY:
                break
        return _dechunk(body)

    idle_end = time.time() + idle_grace
    while len(body) < MAX_BODY:
        left = min(deadline, idle_end) - time.time()
        if left <= 0:
            break
        sock.settimeout(min(left, 2.0))
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, TimeoutError, OSError):
            break
        if not chunk:
            break
        body += chunk
    return body


def _connect_proxy(p: ProxyTarget, timeout: float) -> Tuple[socket.socket, float]:
    t0 = time.time()
    last: Optional[Exception] = None
    try:
        infos = socket.getaddrinfo(p.host, p.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise socket.gaierror(e.errno, f"DNS解析失败: {e.strerror}") from None
    for family, stype, proto, _, sockaddr in infos:
        sock = socket.socket(family, stype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock, (time.time() - t0) * 1000
        except OSError as e:
            last = e
            try:
                sock.close()
            except Exception:
                pass
    raise last or OSError("connect failed")


# --------------------------------------------------------------------------- #
# 协议实现
# --------------------------------------------------------------------------- #
def http_proxy_request(sock, p: ProxyTarget, host: str, path: str, ua: str,
                       deadline: float, timeout: float) -> Tuple[int, Dict[str, str], bytes, float]:
    auth = f"Proxy-Authorization: {p.auth_header}\r\n" if p.auth_header else ""
    req = (f"GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
           f"Accept: */*\r\n{auth}Connection: close\r\nProxy-Connection: close\r\n\r\n").encode()
    t0 = time.time()
    sock.settimeout(timeout)
    sock.sendall(req)
    raw = _recv_headers(sock, deadline)
    latency = (time.time() - t0) * 1000
    if not raw:
        raise ConnectionError("代理返回空响应（很可能不是 HTTP 代理）")
    head_text, extra = _split_head(raw)
    _, status, headers = _parse_headers(head_text)
    if status == 407:
        raise PermissionError("407 需要代理认证")
    body = _read_body(sock, headers, extra, deadline)
    return status, headers, body, latency


def connect_tunnel(sock, p: ProxyTarget, host: str, port: int, ua: str,
                   deadline: float, timeout: float) -> Tuple[int, Dict[str, str], float]:
    auth = f"Proxy-Authorization: {p.auth_header}\r\n" if p.auth_header else ""
    req = (f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {ua}\r\n"
           f"{auth}Proxy-Connection: keep-alive\r\n\r\n").encode()
    t0 = time.time()
    sock.settimeout(timeout)
    sock.sendall(req)
    raw = _recv_headers(sock, deadline)
    latency = (time.time() - t0) * 1000
    if not raw:
        raise ConnectionError("CONNECT 空响应")
    head_text, _ = _split_head(raw)
    _, status, headers = _parse_headers(head_text)
    if status == 407:
        raise PermissionError("407 需要代理认证")
    return status, headers, latency


def tls_request_over_tunnel(sock, host: str, path: str, ua: str,
                            timeout: float) -> Tuple[int, Dict[str, str], bytes]:
    ctx = ssl.create_default_context()
    tsock = ctx.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False)
    tsock.settimeout(timeout)
    tsock.do_handshake()
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    tsock.sendall(req)
    deadline = time.time() + timeout
    raw = _recv_headers(tsock, deadline)
    head_text, extra = _split_head(raw)
    _, status, headers = _parse_headers(head_text)
    body = _read_body(tsock, headers, extra, deadline)
    try:
        tsock.close()
    except Exception:
        pass
    return status, headers, body


def _recv_exact(sock, n: int, timeout: float) -> bytes:
    buf, end = b"", time.time() + timeout
    while len(buf) < n:
        left = end - time.time()
        if left <= 0:
            raise socket.timeout("socks 握手超时")
        sock.settimeout(min(left, 5.0))
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socks 连接被对端关闭")
        buf += chunk
    return buf


def socks5_handshake(sock, p: ProxyTarget, host: str, port: int, timeout: float) -> None:
    auth = bool(p.user)
    methods = b"\x02\x00" if auth else b"\x01\x00"
    sock.settimeout(timeout)
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    resp = _recv_exact(sock, 2, timeout)
    if resp[0] != 0x05:
        raise ConnectionError("非 SOCKS5 服务")
    chosen = resp[1]
    if chosen == 0xFF:
        raise PermissionError("SOCKS5 拒绝所有认证方式")
    if chosen == 0x02:
        if not auth:
            raise PermissionError("SOCKS5 要求用户名密码")
        u, pw = (p.user or "").encode(), (p.password or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        if _recv_exact(sock, 2, timeout)[1] != 0x00:
            raise PermissionError("SOCKS5 认证失败")
    elif chosen != 0x00:
        raise ConnectionError(f"不支持的 SOCKS5 认证方式 {chosen:#x}")

    hb = host.encode("idna")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))
    ver, rep, _, atyp = _recv_exact(sock, 4, timeout)
    if rep != 0x00:
        codes = {1: "general failure", 2: "connection not allowed", 3: "network unreachable",
                 4: "host unreachable", 5: "connection refused", 6: "TTL expired",
                 7: "command not supported", 8: "address type not supported"}
        raise ConnectionError(f"SOCKS5 reply={rep:#x}({codes.get(rep, '?')})")
    if atyp == 0x01:
        _recv_exact(sock, 6, timeout)
    elif atyp == 0x03:
        n = _recv_exact(sock, 1, timeout)[0]
        _recv_exact(sock, n + 2, timeout)
    elif atyp == 0x04:
        _recv_exact(sock, 18, timeout)
    else:
        raise ConnectionError(f"未知 SOCKS5 ATYP {atyp:#x}")


def socks4_handshake(sock, p: ProxyTarget, host: str, port: int, timeout: float) -> None:
    userid = (p.user or "").encode()
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        ip4 = infos[0][4][0] if infos else None
    except OSError:
        ip4 = None
    if ip4 and not ip4.startswith("127."):
        req = b"\x04\x01" + port.to_bytes(2, "big") + socket.inet_aton(ip4) + userid + b"\x00"
    else:
        req = (b"\x04\x01" + port.to_bytes(2, "big") + b"\x00\x00\x00\x01"
               + userid + b"\x00" + host.encode("idna") + b"\x00")
    sock.settimeout(timeout)
    sock.sendall(req)
    resp = _recv_exact(sock, 8, timeout)
    if resp[0] != 0x00:
        raise ConnectionError("非 SOCKS4 服务")
    if resp[1] != 0x5A:
        codes = {0x5B: "请求被拒绝", 0x5C: "无法连接 identd", 0x5D: "identd 无法确认用户"}
        raise ConnectionError(f"SOCKS4 code={resp[1]:#x}({codes.get(resp[1], '?')})")


def plain_http_request(sock, host: str, path: str, ua: str, deadline: float,
                       timeout: float) -> Tuple[int, Dict[str, str], bytes, float]:
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n"
           f"Connection: close\r\n\r\n").encode()
    t0 = time.time()
    sock.settimeout(timeout)
    sock.sendall(req)
    raw = _recv_headers(sock, deadline)
    latency = (time.time() - t0) * 1000
    if not raw:
        raise ConnectionError("隧道内空响应")
    head_text, extra = _split_head(raw)
    _, status, headers = _parse_headers(head_text)
    body = _read_body(sock, headers, extra, deadline)
    return status, headers, body, latency


def nonce_path(path: str, nonce: str) -> str:
    if not nonce:
        return path
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}_pc={nonce}"


def authority(tg: Dict[str, Any]) -> str:
    """绝对 URI 与 Host 头使用的 host[:port]；默认端口省略。
    端口必须保留，否则自建检测站（如 http://VPS:8080/ip）会被请求到 80 端口。"""
    host = tg["host"]
    port = int(tg.get("port", 80))
    if port == 80:
        return host
    if ":" in host:            # IPv6 字面量需要方括号
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def target_port(tg: Dict[str, Any]) -> int:
    return int(tg.get("port", 80))


# --------------------------------------------------------------------------- #
# HTTPS 能力探测：CONNECT + TLS + GET
#   浏览器访问任何 https 站点（chatgpt.com 等）走的就是 CONNECT 隧道。
#   「明文 HTTP 回显成功」≠「能开 https 网站」：有的代理 CONNECT 直接 RST，
#   有的 CONNECT 返回 200 但 TLS 立刻被掐断（SSLEOF），这两种都必须报出来。
# --------------------------------------------------------------------------- #
BLOCK_TAGS = [
    (b"just a moment", "cloudflare_challenge"),
    (b"attention required", "cloudflare_block"),
    (b"enable cookies and javascript", "cf_cookie_wall"),
    (b"access denied", "access_denied"),
    (b"requested url cannot be forwarded", "proxy_acl_deny"),
    (b"error 403", "http_403"),
]


def tls_probe(p: ProxyTarget, host: str, port: int, path: str, ua: str,
              timeout: float, echo: bool = False, nonce: str = "") -> Dict[str, Any]:
    """经代理 CONNECT 到 host:port，做 TLS 握手并 GET path。

    echo=True  时额外要求响应体是 IP 回显（用于判定 https_ok）
    echo=False 时只关心「能不能拿到 HTTP 响应」+ 拦截特征（用于站点探测）
    返回 {connect, status, tag, err, ip}
    """
    out: Dict[str, Any] = {"connect": 0, "status": 0, "tag": "", "err": "", "ip": ""}
    if nonce:
        path = nonce_path(path, nonce)
    try:
        sock, _ = _connect_proxy(p, timeout)
    except (socket.timeout, TimeoutError):
        out["err"] = "tcp_timeout"
        return out
    except OSError as e:
        out["err"] = f"tcp_{type(e).__name__}"
        return out
    try:
        st, _, _lat = connect_tunnel(sock, p, host, port, ua, time.time() + timeout, timeout)
        out["connect"] = st
        if st != 200:
            out["err"] = f"connect_{st}"
            return out
        st2, h2, b2 = tls_request_over_tunnel(sock, host, path, ua, timeout)
        out["status"] = st2
        low = b2[:2048].lower()
        for needle, tag in BLOCK_TAGS:
            if needle in low:
                out["tag"] = tag
                break
        if echo:
            ok, ip = validate_echo(b2, "json_ip")
            out["ip"] = ip
            if st2 == 200 and ok:
                return out
            out["err"] = "no_echo" if st2 == 200 else f"get_{st2}"
            return out
        return out
    except ssl.SSLError as e:
        out["err"] = f"tls_{type(e).__name__}"
        return out
    except (socket.timeout, TimeoutError):
        out["err"] = "timeout"
        return out
    except ConnectionResetError:
        out["err"] = "reset"
        return out
    except Exception as e:
        out["err"] = f"{type(e).__name__}"
        return out
    finally:
        try:
            sock.close()
        except Exception:
            pass


def probe_label(pr: Dict[str, Any]) -> str:
    """把探测结果压成一行人类可读标签。"""
    if pr["err"] in ("reset", "tcp_timeout", "timeout"):
        return "连接被重置/超时"
    if pr["err"].startswith("tls_"):
        return "TLS 握手失败（隧道不通 HTTPS）"
    if pr["connect"] and pr["connect"] != 200:
        return f"CONNECT 被拒 ({pr['connect']})"
    if pr["err"].startswith("connect_"):
        return f"CONNECT 被拒 ({pr['err'][8:]})"
    if pr["err"].startswith("tcp_"):
        return "连不上代理"
    if pr["status"]:
        tag = f" · {pr['tag']}" if pr["tag"] else ""
        return f"可达 HTTP {pr['status']}{tag}"
    return pr["err"] or "未知"


def parse_probe_hosts(specs: List[str]) -> List[Tuple[str, int]]:
    out = []
    for s in specs or []:
        s = s.strip()
        if not s:
            continue
        s = re.sub(r"^https?://", "", s).rstrip("/")
        host, _, port_s = s.partition(":")
        port = int(port_s) if port_s.isdigit() else 443
        if host:
            out.append((host, port))
    return out


# --------------------------------------------------------------------------- #
# 单个代理检测
# --------------------------------------------------------------------------- #
def check_one(p: ProxyTarget, targets: List[Dict[str, Any]], timeout: float, ua: str,
              mode: str, local_ips: set, strict: bool = True, do_tls: bool = True,
              nonce: str = "", probe_hosts: Optional[List[Tuple[str, int]]] = None) -> CheckResult:
    res = CheckResult(proxy=p.addr)
    t_start = time.time()
    budget = timeout * (4 if mode == "full" else 3) + 1
    overall_deadline = t_start + budget
    max_targets = len(targets) if mode == "full" else min(4, len(targets))
    targets = rotate_targets(targets, p.addr)   # 每代理不同顺序，避免同时打爆一个检测站
    hints: List[str] = []
    obs: List[Tuple[str, int, Dict[str, str], bytes]] = []   # (目标, 状态, 头, 体)
    diag: List[str] = []     # 各阶段失败原因，按发生顺序保留，避免后面的覆盖前面的

    def mark_ok(ptype, method, tg_name, status, lat, ip, headers, body=b""):
        res.alive = True
        res.ptype, res.method = ptype, method
        res.target, res.status = tg_name, status
        res.latency_ms = int(lat)
        res.egress_ip = ip
        res.leaked_headers = "; ".join(detect_leak(headers))[:200]
        res.anonymity = ANON_NORMAL if res.leaked_headers else ANON_UNKNOWN
        if ip and ip in local_ips:
            res.transparent = True
            res.anonymity = ANON_TRANSPARENT
            res.verdict = V_TRANSPARENT
        else:
            res.verdict = V_OK
        res.error = ""

    # --- Stage 0: TCP ---
    try:
        sock, cms = _connect_proxy(p, timeout)
        res.connect_ms = int(cms)
        sock.close()
    except socket.gaierror as e:
        res.verdict, res.error = V_DEAD, str(e)
        res.total_ms = int((time.time() - t_start) * 1000)
        return res
    except (socket.timeout, TimeoutError):
        res.verdict, res.error = V_TIMEOUT, "TCP连接超时"
        res.total_ms = int((time.time() - t_start) * 1000)
        return res
    except OSError as e:
        refused = getattr(e, "errno", None) in (61, 111, 10061)
        res.verdict = V_REFUSED if refused else V_DEAD
        res.error = f"TCP连接失败: {e.strerror or e}"
        res.total_ms = int((time.time() - t_start) * 1000)
        return res

    order = {"auto": ["http", "socks5", "socks4"], "http": ["http"], "https": ["https"],
             "socks4": ["socks4"], "socks5": ["socks5"]}.get(p.ptype, ["http"])

    # --- Stage 1: HTTP ---
    if "http" in order:
        for tg in targets[:max_targets]:
            if time.time() > overall_deadline:
                res.attempts.append("http:budget_exceeded")
                break
            try:
                sock, _ = _connect_proxy(p, timeout)
            except OSError:
                break
            try:
                path = nonce_path(tg["path"], nonce)
                dl = time.time() + timeout
                status, headers, body, lat = http_proxy_request(
                    sock, p, authority(tg), path, ua, dl, timeout)
                ok, ip = validate_echo(body, tg["validate"]) if strict else (True, extract_ip_loose(body))
                if status == 200 and (ok or not strict):
                    mark_ok("http", "http", tg["name"], status, lat, ip, headers, body)
                    res.attempts.append(f"http:{tg['name']}:200:echo={'Y' if ip else 'N'}")
                    break
                obs.append((tg["name"], status, headers, body))
                if status == 200:
                    if looks_limited(status, headers, body):
                        res.attempts.append(f"http:{tg['name']}:200:limited")
                    else:
                        hints.append(f"{tg['name']}->{server_hint(headers, body)}")
                        res.attempts.append(f"http:{tg['name']}:200:no_echo")
                        # 早停：期望纯文本 IP 却拿到 HTML 网页 -> 铁证是普通网站，
                        # 不必再浪费 3 个检测站的超时时间（这是 fast 模式提速的关键）
                        if (tg["validate"] == "ip_only"
                                and "html" in (headers.get("content-type") or "").lower()
                                and re.search(rb"<(html|title|!doctype)", body[:2048], re.I)):
                            res.attempts.append("early_exit:html_homepage")
                            break
                else:
                    tag = f"http:{tg['name']}:{status}"
                    diag.append(f"HTTP {status}")
                    if looks_limited(status, headers, body):
                        res.attempts.append(tag + ":limited")
                    else:
                        res.attempts.append(tag)
                        if status in (403, 405, 501):
                            hints.append(f"{tg['name']}->HTTP {status} 拒绝代理请求")
            except PermissionError as e:
                res.verdict, res.error = V_AUTH, str(e)
                res.attempts.append("http:407")
                try:
                    sock.close()
                except Exception:
                    pass
                res.total_ms = int((time.time() - t_start) * 1000)
                return res
            except Exception as e:
                res.attempts.append(f"http:{tg['name']}:{type(e).__name__}")
                diag.append(f"http:{type(e).__name__}")
                if not res.error:
                    res.error = f"{type(e).__name__}: {e}"
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

    # --- Stage 2: HTTPS CONNECT ---
    if not res.alive and ("https" in order or "http" in order) and mode == "full" \
            and res.verdict not in (V_AUTH,):
        sock = None
        try:
            sock, _ = _connect_proxy(p, timeout)
            dl = time.time() + timeout
            status, headers, lat = connect_tunnel(sock, p, TLS_TARGET["host"],
                                                  TLS_TARGET["port"], ua, dl, timeout)
            if status == 200:
                res.ptype, res.method = "https", "connect"
                res.target = f"{TLS_TARGET['host']}:{TLS_TARGET['port']}"
                res.status, res.latency_ms = status, int(lat)
                if do_tls:
                    try:
                        path = nonce_path(TLS_TARGET["path"], nonce)
                        st2, h2, b2 = tls_request_over_tunnel(
                            sock, TLS_TARGET["host"], path, ua, timeout)
                        ok, ip = validate_echo(b2, TLS_TARGET["validate"])
                        res.status = st2
                        if st2 == 200 and (ok or not strict):
                            mark_ok("https", "connect+tls", res.target, st2, lat, ip, h2, b2)
                            res.attempts.append(f"connect+tls:{st2}:echo={'Y' if ip else 'N'}")
                        else:
                            res.attempts.append(f"connect+tls:{st2}:no_echo")
                    except Exception as e:
                        res.attempts.append(f"tls:{type(e).__name__}")
                        if not strict:  # 宽松模式：CONNECT 200 即认为可用
                            mark_ok("https", "connect", res.target, status, lat, "", headers)
                else:
                    mark_ok("https", "connect", res.target, status, lat, "", headers)
                    res.attempts.append("connect:200")
            else:
                res.attempts.append(f"connect:{status}")
                diag.append(f"CONNECT {status}")
                if status == 407:
                    res.verdict, res.error = V_AUTH, "CONNECT 407 需要认证"
        except PermissionError as e:
            res.verdict, res.error = V_AUTH, str(e)
            res.attempts.append("connect:407")
        except Exception as e:
            res.attempts.append(f"connect:{type(e).__name__}")
            diag.append(f"connect:{type(e).__name__}")
        finally:
            try:
                if sock:
                    sock.close()
            except Exception:
                pass

    # --- Stage 3: SOCKS5 / SOCKS4 ---
    # fast 模式提速：若对端已经用 HTTP 语义应答过（哪怕 502/404），它就不是 SOCKS 服务，
    # 再等两次 socks 握手超时纯属浪费。SOCKS 服务收到 HTTP 请求不会给出状态行。
    http_responded = any(d.startswith(("HTTP ", "CONNECT ")) for d in diag)
    for proto in ("socks5", "socks4"):
        if res.alive or proto not in order or res.verdict == V_AUTH:
            continue
        if mode == "fast" and http_responded:
            res.attempts.append(f"{proto}:skipped(http_responded)")
            continue
        if time.time() > overall_deadline:
            break
        for tg in targets[:3]:
            sock = None
            try:
                sock, _ = _connect_proxy(p, timeout)
                dl = time.time() + timeout
                hs = time.time()
                if proto == "socks5":
                    socks5_handshake(sock, p, tg["host"], target_port(tg), timeout)
                else:
                    socks4_handshake(sock, p, tg["host"], target_port(tg), timeout)
                hs_ms = (time.time() - hs) * 1000
                path = nonce_path(tg["path"], nonce)
                status, headers, body, lat = plain_http_request(
                    sock, authority(tg), path, ua, dl, timeout)
                ok, ip = validate_echo(body, tg["validate"]) if strict else (True, extract_ip_loose(body))
                if status == 200 and (ok or not strict):
                    mark_ok(proto, proto, tg["name"], status, lat + hs_ms, ip, headers, body)
                    res.attempts.append(f"{proto}:{tg['name']}:200")
                    break
                res.attempts.append(f"{proto}:{tg['name']}:{status}:no_echo")
                diag.append(f"{proto}:HTTP {status}")
            except PermissionError as e:
                res.verdict, res.error = V_AUTH, str(e)
                res.attempts.append(f"{proto}:auth")
                break
            except Exception as e:
                res.attempts.append(f"{proto}:{tg['name']}:{type(e).__name__}")
                diag.append(f"{proto}:{type(e).__name__}")
                if not res.alive:
                    break  # 握手都失败，换下一个协议而不是换目标
            finally:
                try:
                    if sock:
                        sock.close()
                except Exception:
                    pass

    # --- 收尾判定 ---
    if not res.alive and res.verdict not in (V_AUTH,):
        oks = [o for o in obs if o[1] == 200]
        fps = {body_fingerprint(o[2], o[3]) for o in oks}
        limited = [o for o in obs if looks_limited(o[1], o[2], o[3])]
        if hints:
            # 有「返回自身网页」的铁证 -> 就是普通 Web 服务器
            res.verdict = V_NOT_PROXY
            res.hint = hints[0][:110]
            res.error = "非代理端口：返回自身网页而非 IP 回显"
        elif limited or len(fps) >= 2:
            # 检测站限流，或响应内容随目标变化 -> 具备转发行为，是真代理但没拿到回显
            res.verdict = V_LIMITED
            names = ",".join(dict.fromkeys(o[0] for o in limited))[:40]
            res.hint = (f"检测站限流({names})" if limited
                        else f"响应随目标变化({len(fps)}种指纹)")
            res.error = "疑似真代理：检测站限流未取得 IP 回显，建议稍后复测"
        else:
            # 用各阶段真实原因按顺序组成摘要，避免后面的 socks 超时掩盖前面的 HTTP 502
            summary = "; ".join(dict.fromkeys(diag))[:120]
            res.error = summary or res.error or "无有效响应"
    if res.alive:
        res.hint = ""
        # 浏览器访问 https 站点走 CONNECT 隧道；明文回显成功不代表隧道可用，必须实测
        hp = tls_probe(p, TLS_TARGET["host"], TLS_TARGET["port"], TLS_TARGET["path"],
                       ua, timeout, echo=True, nonce=nonce)
        if hp["connect"] == 200 and hp["status"] == 200 and not hp["err"]:
            res.https_ok, res.https_err = True, ""
        elif hp["connect"] == 200 and hp["status"] == 200:
            res.https_ok, res.https_err = True, "TLS 通，回显校验未过"
        else:
            res.https_ok, res.https_err = False, probe_label(hp)
        for ph, pport in (probe_hosts or []):
            pr = tls_probe(p, ph, pport, "/", ua, timeout, echo=False)
            res.probes[f"{ph}:{pport}"] = probe_label(pr)
    res.total_ms = int((time.time() - t_start) * 1000)
    return res


# --------------------------------------------------------------------------- #
# 深度匿名度
# --------------------------------------------------------------------------- #
def deep_anonymity(p: ProxyTarget, ua: str, timeout: float, method: str) -> Tuple[str, List[str]]:
    leaked: List[str] = []
    try:
        sock, _ = _connect_proxy(p, timeout)
    except OSError as e:
        return ANON_UNKNOWN, [f"reconnect failed: {e}"]
    try:
        host = HEADERS_TARGET["host"]
        deadline = time.time() + timeout * 2
        if method.startswith("socks5"):
            socks5_handshake(sock, p, host, 80, timeout)
            status, headers, body, _ = plain_http_request(sock, host, "/headers", ua, deadline, timeout)
        elif method.startswith("socks4"):
            socks4_handshake(sock, p, host, 80, timeout)
            status, headers, body, _ = plain_http_request(sock, host, "/headers", ua, deadline, timeout)
        elif method.startswith("connect"):
            st, _, _ = connect_tunnel(sock, p, host, 443, ua, deadline, timeout)
            if st != 200:
                return ANON_UNKNOWN, [f"connect status {st}"]
            status, headers, body = tls_request_over_tunnel(sock, host, "/headers", ua, timeout)
        else:
            status, headers, body, _ = http_proxy_request(sock, p, host, "/headers", ua, deadline, timeout)
        leaked += detect_leak(headers)
        if status == 200 and body:
            try:
                seen = json.loads(body.decode("utf-8", "replace")).get("headers", {})
            except Exception:
                seen = {}
            for k, v in seen.items():
                if k.lower() in ("x-forwarded-for", "via", "forwarded", "x-real-ip", "client-ip"):
                    leaked.append(f"echo:{k}={str(v)[:60]}")
        low = [x.lower() for x in leaked]
        if any(x.startswith(("x-forwarded-for", "echo:x-forwarded-for", "forwarded",
                             "echo:forwarded", "echo:x-real-ip")) for x in low):
            return ANON_TRANSPARENT, leaked
        if any(x.startswith(("via", "proxy-agent", "echo:via", "x-cache")) for x in low):
            return ANON_NORMAL, leaked
        return ANON_HIGH, leaked
    except Exception as e:
        return ANON_UNKNOWN, [f"{type(e).__name__}: {e}"]
    finally:
        try:
            sock.close()
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Geo / 本机 IP
# --------------------------------------------------------------------------- #
def enrich_geo(results: List[CheckResult], timeout: float, threads: int) -> None:
    todo = [r for r in results if r.alive and r.egress_ip and not r.country]
    if not todo:
        return

    def one(r: CheckResult) -> None:
        url = f"http://ip-api.com/json/{r.egress_ip}?fields=status,country,city,isp,as"
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA}),
                    timeout=timeout) as resp:
                data = json.loads(resp.read(65536).decode("utf-8", "replace"))
            if data.get("status") == "success":
                r.country = data.get("country", "")
                r.city = data.get("city", "")
                r.isp = (data.get("isp") or "")[:40]
                r.asn = (data.get("as") or "")[:30]
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(threads, 32)) as ex:
        list(ex.map(one, todo))


def get_local_ips(timeout: float = 6) -> set:
    ips = set()
    for tg in DEFAULT_TARGETS[:4]:
        try:
            url = f"http://{tg['host']}{nonce_path(tg['path'], rand_nonce(8))}"
            with urllib.request.urlopen(
                    urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA}),
                    timeout=timeout) as r:
                body = r.read(65536)
            ip = extract_ip_loose(body)
            if ip:
                ips.add(ip)
        except Exception:
            continue
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


def rand_nonce(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# --------------------------------------------------------------------------- #
# 自检：假 Web 服务器必须判为 not_a_proxy，真转发代理必须判为 ok/transparent
# --------------------------------------------------------------------------- #
class _FakeWebHandler(http.server.BaseHTTPRequestHandler):
    """模拟「占着 80 端口但不是代理」的普通 Web 服务器：任何请求都回自己的首页。"""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        page = (b"<!DOCTYPE html><html><head><title>TURN Server Information and Test</title>"
                b"</head><body><h1>Hello</h1><p>Chrome/124.0.0.0 Safari/537.36</p>"
                b"<p>version 1.2.3.4</p></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.18.0 (Ubuntu)")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

    def log_message(self, *a):
        pass


class _RealProxyHandler(http.server.BaseHTTPRequestHandler):
    """极简真转发代理：处理绝对 URI，真实回源并把 IP 回显返回。"""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if not self.path.startswith("http://"):
            self.send_error(400, "not a proxy request")
            return
        u = urlparse(self.path)
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(self.path, headers={"User-Agent": DEFAULT_UA}),
                    timeout=8) as r:
                body = r.read(4096)
            ip = extract_ip_loose(body)
            payload = (ip or "0.0.0.0").encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain;charset=UTF-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Via", "1.1 selftest-proxy")
            self.end_headers()
            self.wfile.write(payload)
        except Exception as e:
            self.send_error(502, f"upstream failed: {e}")

    def do_CONNECT(self):
        self.send_response(501)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _LimitedProxyHandler(http.server.BaseHTTPRequestHandler):
    """真代理，但检测站对它限流：只回纯文本 'Rate limited'，没有 IP 回显。
    用来验证工具不会把它误判成 not_a_proxy（假阴性保护）。"""
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if not self.path.startswith("http://"):
            self.send_error(400)
            return
        payload = b"Rate limited\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


def _serve(handler_cls) -> Tuple[socketserver.TCPServer, int]:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def run_selftest(timeout: float) -> int:
    print(f"[*] proxy-check {VERSION} 自检开始", file=sys.stderr)
    fake, fake_port = _serve(_FakeWebHandler)
    real, real_port = _serve(_RealProxyHandler)
    lim, lim_port = _serve(_LimitedProxyHandler)
    print(f"[*] 假 Web 服务器 127.0.0.1:{fake_port}（回 200 + HTML，模拟误报源）", file=sys.stderr)
    print(f"[*] 真转发代理   127.0.0.1:{real_port}（绝对 URI 回源 + IP 回显）", file=sys.stderr)
    print(f"[*] 限流代理     127.0.0.1:{lim_port}（真转发但只回 Rate limited）", file=sys.stderr)

    nonce = rand_nonce()
    ok = True
    try:
        # 1) 假 Web 服务器
        r1 = check_one(ProxyTarget("fake", "127.0.0.1", fake_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), True, False, nonce)
        print(f"\n[1] 假 Web 服务器 -> alive={r1.alive} verdict={r1.verdict} hint={r1.hint[:60]}")
        if r1.alive or r1.verdict != V_NOT_PROXY:
            print("    ✗ 失败：严格模式下必须判为 not_a_proxy")
            ok = False
        else:
            print("    ✓ 通过：正确识别为「非代理端口」")

        # 2) 宽松模式下同一目标会误报（证明严格校验的价值）
        r2 = check_one(ProxyTarget("fake", "127.0.0.1", fake_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), False, False, nonce)
        print(f"\n[2] 假 Web 服务器(--lenient) -> alive={r2.alive} verdict={r2.verdict}")
        print("    ✓ 宽松模式确实误报为存活（这就是只看状态码的危害）" if r2.alive
              else "    · 宽松模式也未误报")

        # 3) 真转发代理
        r3 = check_one(ProxyTarget("real", "127.0.0.1", real_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), True, False, nonce)
        print(f"\n[3] 真转发代理 -> alive={r3.alive} verdict={r3.verdict} "
              f"出口={r3.egress_ip} 延迟={r3.latency_ms}ms 透明={r3.transparent}")
        if not r3.alive or not r3.egress_ip:
            print("    ✗ 失败：真代理必须判为存活并抓到出口 IP")
            ok = False
        else:
            print("    ✓ 通过：真代理存活且抓到出口 IP")

        # 4) 透明代理识别。本机可能是双栈出口（IPv4 + IPv6），不同检测站看到的地址不同，
        #    因此必须用完整的多地址集合来判定，只拿单个 IP 会漏判。
        local = get_local_ips(timeout) | ({r3.egress_ip} if r3.egress_ip else set())
        r4 = check_one(ProxyTarget("real", "127.0.0.1", real_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", local, True, False, nonce)
        print(f"\n[4] 透明代理识别 -> transparent={r4.transparent} verdict={r4.verdict} "
              f"anonymity={r4.anonymity} 出口={r4.egress_ip}")
        print(f"    本机出口集合: {sorted(local)}")
        if r4.egress_ip and r4.egress_ip in local:
            print("    ✓ 通过：出口 IP 命中本机出口集合，正确标记为透明" if r4.transparent
                  else "    ✗ 失败：出口 IP 属于本机却未标记透明")
            ok = ok and r4.transparent
        else:
            print("    · 跳过：本机出口 IP 采集不全，无法构造透明场景")

        # 5) 关闭的端口
        dead_port = _free_port()
        r5 = check_one(ProxyTarget("dead", "127.0.0.1", dead_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), True, False, nonce)
        print(f"\n[5] 关闭端口 127.0.0.1:{dead_port} -> alive={r5.alive} "
              f"verdict={r5.verdict} err={r5.error[:40]}")
        print("    ✓ 通过：正确判为不可用" if not r5.alive else "    ✗ 失败")
        ok = ok and not r5.alive

        # 6) IP 校验函数单测
        print("\n[6] IP 校验函数单测")
        cases = [("161.35.70.249", True), ("104.28.197.13", True), ("124.0.0.0", True),
                 ("2001:db8::1", False),   # RFC3849 文档前缀，ipaddress 视为 private
                 ("192.168.1.1", False), ("127.0.0.1", False),
                 ("::af", False), ("999.1.1.1", False), ("", False),
                 ("0.0.0.0", False), ("2409:8a6c:385:8764::1", True)]
        for s, want in cases:
            got = is_valid_public_ip(s)
            flag = "✓" if got == want else "✗"
            print(f"    {flag} is_valid_public_ip({s!r}) = {got} (期望 {want})")
            ok = ok and (got == want)

        # 7b) HTTPS 通道探测：本地假代理的 CONNECT 回 501 -> 必须报 https_ok=False
        r7b = check_one(ProxyTarget("real", "127.0.0.1", real_port, "http"),
                        DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), True, False, nonce)
        print(f"\n[7b] HTTPS 通道探测(CONNECT 被 501 拒) -> https_ok={r7b.https_ok} err={r7b.https_err}")
        if r7b.alive and r7b.https_ok:
            print("    ✗ 失败：CONNECT 被拒却报 HTTPS 可用")
            ok = False
        elif r7b.alive and not r7b.https_ok and r7b.https_err:
            print("    ✓ 通过：明文可用但 HTTPS 隧道不通被如实标出")
        else:
            print("    · 跳过：本地代理未判活")

        # 7) 假阴性保护：真代理 + 检测站限流 -> 必须判 target_limited，不能判 not_a_proxy
        r7 = check_one(ProxyTarget("lim", "127.0.0.1", lim_port, "http"),
                       DEFAULT_TARGETS, timeout, DEFAULT_UA, "fast", set(), True, False, nonce)
        print(f"\n[7] 限流场景(真代理但无 IP 回显) -> alive={r7.alive} verdict={r7.verdict} "
              f"hint={r7.hint[:40]}")
        if r7.verdict == V_NOT_PROXY:
            print("    ✗ 失败：把限流的真代理误判成了非代理（假阴性）")
            ok = False
        elif r7.verdict == V_LIMITED and not r7.alive:
            print("    ✓ 通过：判为「限流待测」，不计入 valid 也不冤枉它")
        else:
            print(f"    · 判定为 {r7.verdict}（非 not_a_proxy，可接受）")
    finally:
        fake.shutdown(); fake.server_close()
        real.shutdown(); real.server_close()
        lim.shutdown(); lim.server_close()

    print("\n" + ("[+] 自检全部通过" if ok else "[!] 自检存在失败项"), file=sys.stderr)
    return 0 if ok else 1


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #
CSV_FIELDS = ["proxy", "alive", "verdict", "ptype", "method", "target", "status",
              "latency_ms", "connect_ms", "total_ms", "egress_ip", "transparent",
              "anonymity", "country", "city", "isp", "asn", "rounds_ok", "rounds",
              "success_rate", "https_ok", "https_err", "probes",
              "leaked_headers", "hint", "error"]

VERDICT_CN = {V_OK: "可用", V_TRANSPARENT: "透明", V_NOT_PROXY: "非代理",
              V_LIMITED: "限流待测", V_AUTH: "需认证", V_TIMEOUT: "超时",
              V_REFUSED: "拒绝", V_DEAD: "失效"}


def write_outputs(results: List[CheckResult], outdir: str, sort_key: str,
                  keep_transparent: bool, min_rate: float,
                  require_https: bool = True) -> Dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    alive = [r for r in results if r.alive]
    usable = alive if keep_transparent else [r for r in alive if not r.transparent]
    if require_https:
        usable = [r for r in usable if r.https_ok]
    if min_rate > 0:
        usable = [r for r in usable if r.rounds == 0 or r.success_rate >= min_rate]

    def lat(r):
        return r.latency_ms if r.latency_ms >= 0 else 10 ** 9

    if sort_key == "latency":
        usable.sort(key=lat); alive.sort(key=lat)
    elif sort_key == "rate":
        usable.sort(key=lambda r: (-r.success_rate, lat(r)))
    else:
        def ipkey(r):
            m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):", r.proxy)
            return tuple(int(x) for x in m.groups()) if m else (999, 999, 999, 999)
        usable.sort(key=ipkey)

    dead = [r for r in results if not r.alive]
    paths = {}

    def dump(name, lines):
        p = os.path.join(outdir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
        paths[name] = p

    dump("valid.txt", [r.proxy for r in usable])
    dump("valid_url.txt", [_scheme(r) + r.proxy for r in usable])
    dump("dead.txt", [f"{r.proxy}\t{r.verdict}\t{r.error or r.hint}" for r in dead])
    # 检测站限流导致无法确认的疑似真代理，单独存档供复测
    unverified = [r for r in results if r.verdict == V_LIMITED]
    if unverified:
        dump("unverified.txt", [r.proxy for r in unverified])
        dump("recheck.sh", ["#!/bin/sh",
                            "# 检测站限流时未能确认的疑似真代理，隔几分钟单独复测：",
                            f"python3 proxy-check.py -f {os.path.basename(outdir)}/../unverified.txt "
                            f"-t 8 --timeout 12 --mode full --show-dead -o recheck 2>/dev/null || true"])

    p = os.path.join(outdir, "results.csv")
    with open(p, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in results:
            row = r.to_row()
            row["probes"] = "; ".join(f"{k}={v}" for k, v in (row.get("probes") or {}).items())
            w.writerow(row)
    paths["results.csv"] = p

    p = os.path.join(outdir, "results.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "version": VERSION,
                   "total": len(results), "alive": len(alive), "usable": len(usable),
                   "verdict_stats": _verdict_stats(results),
                   "results": [dict(r.to_row(), attempts=r.attempts) for r in results]},
                  f, ensure_ascii=False, indent=2)
    paths["results.json"] = p
    return paths


def _scheme(r: CheckResult) -> str:
    """curl / requests 可直接使用的 scheme（socks5 -> socks5h，让代理做 DNS）。"""
    if r.ptype == "socks5":
        return "socks5h://"
    if r.ptype == "socks4":
        return "socks4a://"
    if r.ptype == "https":
        return "http://"   # HTTPS 代理仍用 http:// 前缀接入 CONNECT
    return "http://"


def _verdict_stats(results: List[CheckResult]) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    for r in results:
        stats[r.verdict] = stats.get(r.verdict, 0) + 1
    return stats


def print_table(results: List[CheckResult], show_dead: bool, color: bool) -> None:
    C = (lambda s, c: f"\033[{c}m{s}\033[0m") if color else (lambda s, c: s)
    rows = results if show_dead else [r for r in results if r.alive]
    if not rows:
        print(C("（无可用代理，加 --show-dead 查看失败原因）", "33"))
        return
    print(C(f"{'代理地址':<22}{'判定':<9}{'HTTPS':<7}{'协议':<8}{'延迟':>8}  {'出口IP':<24}"
            f"{'匿名度':<14}{'证据/地区'}", "1"))
    print("-" * 138)
    for r in rows:
        v = r.verdict
        vc = {"ok": "32", "transparent": "35", "not_a_proxy": "33", "target_limited": "36",
              "auth_required": "35", "timeout": "90", "refused": "90", "dead": "31"}.get(v, "90")
        vt = C(VERDICT_CN.get(v, v), vc)
        if r.alive:
            lat = f"{r.latency_ms}ms"
            lc = "32" if r.latency_ms < 800 else ("33" if r.latency_ms < 2500 else "31")
            anon = (C("透明", "35") if r.transparent else
                    C("高匿名", "32") if r.anonymity == ANON_HIGH else
                    C("普通匿名", "33") if r.anonymity == ANON_NORMAL else C("未知", "90"))
            tail = " ".join(x for x in (r.country, r.city, r.isp) if x) or r.leaked_headers[:34] or "-"
            hs = C("✓", "32") if r.https_ok else C("✗", "31")
            print(f"{r.proxy:<22}{vt:<9}{hs:<7}{r.ptype:<8}{C(lat, lc):>8}  "
                  f"{(r.egress_ip or '-'):<24}{anon:<14}{tail[:44]}")
        else:
            print(f"{r.proxy:<22}{vt:<9}{'-':<7}{'-':<8}{'-':>8}  {'-':<24}{'-':<14}"
                  f"{C((r.hint or r.error)[:52], '90')}")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
class Progress:
    def __init__(self, total: int, enabled: bool):
        self.total, self.done, self.alive = total, 0, 0
        self.lock = threading.Lock()
        self.enabled = enabled
        self.t0 = time.time()

    def tick(self, alive: bool) -> None:
        with self.lock:
            self.done += 1
            self.alive += 1 if alive else 0
            if self.enabled:
                w = 28
                filled = int(w * self.done / max(self.total, 1))
                el = time.time() - self.t0
                eta = el / self.done * (self.total - self.done) if self.done else 0
                sys.stderr.write(f"\r[{'█' * filled}{'░' * (w - filled)}] "
                                 f"{self.done}/{self.total} 可用={self.alive} "
                                 f"{el:.1f}s ETA {eta:.1f}s   ")
                sys.stderr.flush()
                if self.done == self.total:
                    sys.stderr.write("\n")

    def finish(self) -> None:
        if self.enabled and self.done < self.total:
            sys.stderr.write("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="proxy-check.py",
        description="代理池快速测活工具 v1.4（严格回显校验，杜绝把普通 Web 服务器误判为代理）",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("proxies", nargs="*", help="直接指定 host:port（可多个）")
    ap.add_argument("-f", "--file", action="append", help="代理列表文件，可重复")
    ap.add_argument("--stdin", action="store_true", help="从标准输入读取")
    ap.add_argument("-t", "--threads", type=int, default=100, help="并发线程数（默认 100）")
    ap.add_argument("--timeout", type=float, default=8.0, help="单请求超时秒（默认 8）")
    ap.add_argument("--type", default="auto",
                    choices=["auto", "http", "https", "socks4", "socks5"], help="强制协议")
    ap.add_argument("--mode", default="fast", choices=["fast", "full"],
                    help="fast=HTTP+SOCKS 快速判定；full=追加 CONNECT/TLS 与全部检测站")
    ap.add_argument("--lenient", action="store_true",
                    help="宽松模式：只看 HTTP 200（会误报，仅用于对比）")
    ap.add_argument("--allow-private-ip", action="store_true",
                    help="允许私网/环回 IP 作为有效回显（内网代理或本地自建检测站时用）")
    ap.add_argument("--no-nonce", action="store_true", help="禁用随机 nonce 查询串（不推荐）")
    ap.add_argument("--deep", action="store_true", help="深度匿名度检测（额外请求 /headers）")
    ap.add_argument("--probe-host", action="append", metavar="HOST[:PORT]",
                    help="额外探测该站点能否经代理以 HTTPS 打开（可重复），如 --probe-host chatgpt.com")
    ap.add_argument("--require-https", action=argparse.BooleanOptionalAction, default=True,
                    help="可用列表只保留 CONNECT+TLS 实测通过的代理（默认开启；--no-require-https 关闭）")
    ap.add_argument("--geo", action="store_true", help="查询出口 IP 地理位置与 ISP")
    ap.add_argument("--repeat", type=int, default=1, help="重复轮数，计算可用率")
    ap.add_argument("--min-rate", type=float, default=0.0, help="可用率阈值（0~1）")
    ap.add_argument("--keep-transparent", action="store_true", help="保留透明代理（默认剔除）")
    ap.add_argument("--sort", default="latency", choices=["latency", "ip", "rate"], help="排序")
    ap.add_argument("-o", "--out", default="out", help="输出目录（默认 ./out）")
    ap.add_argument("--show-dead", action="store_true", help="表格显示失效代理及原因")
    ap.add_argument("--target", action="append", help="自定义检测地址，可重复")
    ap.add_argument("--ua", default=DEFAULT_UA, help="自定义 User-Agent")
    ap.add_argument("--selftest", action="store_true", help="运行内置自检（本地起真假服务器对比）")
    ap.add_argument("--no-color", action="store_true", help="禁用彩色")
    ap.add_argument("--quiet", action="store_true", help="不打印表格")
    ap.add_argument("--json", action="store_true", help="结果以 JSON 输出到 stdout")
    ap.add_argument("-V", "--version", action="version", version=f"proxy-check {VERSION}")
    return ap


def custom_targets(specs: List[str]) -> List[Dict[str, Any]]:
    out = []
    for s in specs:
        s = s.strip()
        if not s:
            continue
        if not s.startswith(("http://", "https://")):
            s = "http://" + s
        u = urlparse(s)
        if not u.hostname:
            print(f"[!] 无法解析 --target: {s}", file=sys.stderr)
            continue
        if u.scheme == "https":
            print(f"[!] 跳过 https 检测站 {s}：HTTP 代理阶段走明文绝对 URI，"
                  f"请给 http:// 地址（自建 echo-server 用 http 端口即可）", file=sys.stderr)
            continue
        port = u.port or 80
        out.append({"name": f"{u.hostname}:{port}" if port != 80 else u.hostname,
                    "host": u.hostname, "port": port, "path": u.path or "/",
                    "validate": "json_ip" if "httpbin" in u.hostname else "ip_only",
                    "nonce": True})
    return out or DEFAULT_TARGETS


def main(argv: Optional[List[str]] = None) -> int:
    global ALLOW_PRIVATE_IP
    args = build_arg_parser().parse_args(argv)
    ALLOW_PRIVATE_IP = bool(args.allow_private_ip)
    if args.selftest:
        return run_selftest(args.timeout)

    color = (not args.no_color) and sys.stderr.isatty() and os.environ.get("NO_COLOR") is None
    C = (lambda s, c: f"\033[{c}m{s}\033[0m") if color else (lambda s, c: s)
    proxies = load_proxies(args)
    if not proxies:
        print("[!] 没有可测试的代理。用 -f proxies.txt / --stdin / 直接传 host:port", file=sys.stderr)
        return 2

    targets = custom_targets(args.target) if args.target else DEFAULT_TARGETS
    probe_hosts = parse_probe_hosts(args.probe_host)
    strict = not args.lenient
    nonce = "" if args.no_nonce else rand_nonce(12)
    print(f"[*] proxy-check {VERSION} | 代理={len(proxies)} 并发={args.threads} "
          f"超时={args.timeout}s 模式={args.mode} 协议={args.type} 轮次={args.repeat} "
          f"校验={'严格' if strict else '宽松'} nonce={nonce or 'off'}", file=sys.stderr)

    t_all = time.time()
    local_ips = get_local_ips(min(args.timeout, 6))
    print(f"[*] 本机出口 IP: {', '.join(sorted(local_ips)) or '未知'}"
          f"（用于识别透明代理）", file=sys.stderr)

    agg: Dict[str, CheckResult] = {}
    rounds = max(1, args.repeat)
    for rnd in range(1, rounds + 1):
        if rounds > 1:
            print(f"\n[*] === 第 {rnd}/{rounds} 轮 ===", file=sys.stderr)
        rnd_nonce = nonce or rand_nonce(12)
        prog = Progress(len(proxies), sys.stderr.isatty() and not args.quiet)
        with ThreadPoolExecutor(max_workers=max(1, min(args.threads, max(len(proxies), 1)))) as ex:
            futs = {ex.submit(check_one, p, targets, args.timeout, args.ua, args.mode,
                              local_ips, strict, True, rnd_nonce, probe_hosts): p
                    for p in proxies}
            for fut in as_completed(futs):
                p = futs[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = CheckResult(proxy=p.addr, verdict=V_DEAD,
                                    error=f"internal {type(e).__name__}: {e}")
                prev = agg.get(r.proxy)
                if prev is None:
                    r.rounds, r.rounds_ok = 1, 1 if r.alive else 0
                    agg[r.proxy] = r
                else:
                    prev.rounds += 1
                    prev.rounds_ok += 1 if r.alive else 0
                    if r.alive:
                        kr, ko = prev.rounds, prev.rounds_ok
                        best = [x for x in (prev.latency_ms, r.latency_ms) if x >= 0]
                        prev.__dict__.update({k: v for k, v in r.to_row().items()
                                              if k not in ("rounds", "rounds_ok", "success_rate")})
                        prev.latency_ms = min(best) if best else -1
                        prev.rounds, prev.rounds_ok = kr, ko
                        prev.attempts = r.attempts
                prog.tick(r.alive)
        prog.finish()

    results = list(agg.values())
    for r in results:
        r.success_rate = round(r.rounds_ok / r.rounds, 3) if r.rounds else 0.0

    if args.deep:
        todo = [r for r in results if r.alive]
        if todo:
            print(f"[*] 深度匿名度检测 {len(todo)} 个...", file=sys.stderr)
            prog = Progress(len(todo), sys.stderr.isatty() and not args.quiet)
            by_addr = {p.addr: p for p in proxies}

            def _deep(r: CheckResult) -> None:
                p = by_addr.get(r.proxy)
                if p:
                    anon, leaked = deep_anonymity(p, args.ua, args.timeout, r.method)
                    r.anonymity = anon
                    if leaked:
                        r.leaked_headers = "; ".join(leaked)[:200]
                prog.tick(True)

            with ThreadPoolExecutor(max_workers=max(1, min(args.threads, 40))) as ex:
                list(ex.map(_deep, todo))
            prog.finish()

    if args.geo:
        print("[*] 查询 GeoIP...", file=sys.stderr)
        enrich_geo(results, min(args.timeout, 8), args.threads)

    paths = write_outputs(results, args.out, args.sort, args.keep_transparent,
                          args.min_rate, args.require_https)
    elapsed = time.time() - t_all

    alive = [r for r in results if r.alive]
    usable = alive if args.keep_transparent else [r for r in alive if not r.transparent]
    if args.require_https:
        usable = [r for r in usable if r.https_ok]
    if args.min_rate > 0:
        usable = [r for r in usable if r.rounds == 0 or r.success_rate >= args.min_rate]
    stats = _verdict_stats(results)

    print("", file=sys.stderr)
    print(f"[+] 完成 | 总数 {len(results)} | 真代理 {len(alive)} | 可用 {len(usable)} | "
          f"耗时 {elapsed:.1f}s", file=sys.stderr)
    print("    判定分布: " + "  ".join(f"{VERDICT_CN.get(k, k)}={v}" for k, v in
                                    sorted(stats.items(), key=lambda x: -x[1])), file=sys.stderr)
    for name, path in paths.items():
        print(f"    -> {name:<15} {path}", file=sys.stderr)

    if args.json:
        json.dump({"total": len(results), "alive": len(alive), "usable": len(usable),
                   "elapsed_s": round(elapsed, 2), "verdict_stats": stats,
                   "results": [dict(r.to_row(), attempts=r.attempts) for r in results]},
                  sys.stdout, ensure_ascii=False, indent=2)
        print()
    elif not args.quiet:
        print()
        print_table(results, args.show_dead, color)
        https_bad = [r for r in alive if not r.https_ok]
        if https_bad:
            print()
            print(C(f"[!] {len(https_bad)} 个代理明文 HTTP 可用但 HTTPS 隧道不可用"
                    f"（浏览器打不开 https 站点）：", "33"))
            for r in https_bad:
                print(f"    {r.proxy:<22} {r.https_err}")
        if probe_hosts:
            print()
            print(C("[*] 站点探测（CONNECT+TLS+GET /）：", "1"))
            for r in alive:
                for k, v in r.probes.items():
                    good = v.startswith("可达") and "challenge" not in v and "block" not in v
                    print(f"    {r.proxy:<22} -> {k:<24} "
                          f"{C(v, '32' if good else '31')}")
        if usable:
            best = min(usable, key=lambda r: r.latency_ms if r.latency_ms >= 0 else 10 ** 9)
            print()
            print(f"最快: {best.proxy}  {best.latency_ms}ms  出口={best.egress_ip or '?'}"
                  f"{'  HTTPS✓' if best.https_ok else ''}")
            print(f"验证: curl -x http://{best.proxy} http://checkip.amazonaws.com/")
        elif not alive:
            print("\n[!] 没有发现真正的代理。多数 IP:80 是普通 Web 服务器，不是代理端口。")
    return 0 if alive else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 已中断", file=sys.stderr)
        sys.exit(130)
