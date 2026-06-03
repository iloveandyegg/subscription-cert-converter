#!/usr/bin/env python3
"""Subscription Converter - replaces insecure/allowInsecure with certificate pins.

Usage: https://your-domain.example:8443/?url=<subscription_url>
"""
import base64
import hashlib
import asyncio
import http.client
import ipaddress
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs as parse_url_qs, urlencode, quote, unquote, urljoin

CERT_CACHE = {}
CACHE_LOCK = threading.Lock()
CERT_CACHE_TTL = 3600
MISSING = object()

MAX_URL_LENGTH = 4096
MAX_SUB_BYTES = 2 * 1024 * 1024
MAX_SUB_LINES = 1000
MAX_CERT_TARGETS = 256
MAX_REDIRECTS = 3
MAX_ACTIVE_REQUESTS = 16
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_REQUESTS = 30
FETCH_PORTS = {80, 443}
BLOCKED_CERT_PORTS = {
    0, 19, 25, 53, 110, 135, 137, 138, 139, 143, 161, 389, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 9200, 9300, 11211, 27017,
}

RATE_LIMIT = {}
RATE_LOCK = threading.Lock()
ACTIVE_REQUESTS = threading.BoundedSemaphore(MAX_ACTIVE_REQUESTS)


class SecurityError(Exception):
    pass


class FetchError(Exception):
    pass


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def normalize_host(host):
    if not host:
        raise SecurityError("missing host")
    host = host.strip().rstrip(".")
    if not host:
        raise SecurityError("missing host")
    return host.encode("idna").decode("ascii")


def validate_port(port, purpose):
    if port < 1 or port > 65535:
        raise SecurityError("invalid port")
    if purpose == "fetch" and port not in FETCH_PORTS:
        raise SecurityError("subscription URL port is not allowed")
    if purpose == "cert" and port in BLOCKED_CERT_PORTS:
        raise SecurityError("certificate probe port is not allowed")


def resolve_public_addresses(host, port, socket_type, purpose):
    host = normalize_host(host)
    validate_port(port, purpose)

    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None

    if literal is not None:
        if not literal.is_global:
            raise SecurityError("non-public IP is not allowed")
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        sockaddr = (str(literal), port, 0, 0) if family == socket.AF_INET6 else (str(literal), port)
        return [(family, sockaddr, str(literal))]

    try:
        infos = socket.getaddrinfo(host, port, type=socket_type)
    except socket.gaierror as e:
        raise SecurityError(f"DNS resolution failed: {e}") from e

    addresses = []
    seen = set()
    for family, socktype, _proto, _canonname, sockaddr in infos:
        if socktype != socket_type:
            continue
        ip = sockaddr[0]
        if not is_public_ip(ip):
            raise SecurityError(f"non-public resolved IP is not allowed: {ip}")
        key = (family, ip)
        if key in seen:
            continue
        seen.add(key)
        addresses.append((family, sockaddr, ip))

    if not addresses:
        raise SecurityError("no usable public address")
    return addresses


def create_public_tcp_connection(host, port, timeout, purpose):
    errors = []
    for family, sockaddr, ip in resolve_public_addresses(host, port, socket.SOCK_STREAM, purpose):
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            errors.append(f"{ip}: {e}")
            sock.close()
    raise OSError("; ".join(errors) or "connection failed")


def host_header(host, port, scheme):
    host = normalize_host(host)
    display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default_port = 443 if scheme == "https" else 80
    return display if port == default_port else f"{display}:{port}"


def response_path(parsed):
    path = parsed.path or "/"
    if parsed.params:
        path += ";" + parsed.params
    if parsed.query:
        path += "?" + parsed.query
    return path


def validate_fetch_url(url):
    if len(url) > MAX_URL_LENGTH:
        raise SecurityError("URL is too long")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SecurityError("only http/https subscription URLs are allowed")
    if parsed.username or parsed.password:
        raise SecurityError("userinfo in URL is not allowed")
    if not parsed.hostname:
        raise SecurityError("missing host")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as e:
        raise SecurityError("invalid port") from e
    validate_port(port, "fetch")
    resolve_public_addresses(parsed.hostname, port, socket.SOCK_STREAM, "fetch")
    return parsed, normalize_host(parsed.hostname), port


def fetch_once(url):
    parsed, host, port = validate_fetch_url(url)
    sock = create_public_tcp_connection(host, port, 10, "fetch")
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        request = (
            f"GET {response_path(parsed)} HTTP/1.1\r\n"
            f"Host: {host_header(host, port, parsed.scheme)}\r\n"
            "User-Agent: v2rayN/6.23\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        sock.sendall(request)
        resp = http.client.HTTPResponse(sock, method="GET")
        resp.begin()

        content_length = resp.getheader("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_SUB_BYTES:
                    raise FetchError("subscription response is too large")
            except ValueError as e:
                raise FetchError("invalid content length") from e

        body = resp.read(MAX_SUB_BYTES + 1)
        if len(body) > MAX_SUB_BYTES:
            raise FetchError("subscription response is too large")
        return resp.status, resp.headers, body
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_subscription(url):
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        status, headers, body = fetch_once(current)
        if status in {301, 302, 303, 307, 308}:
            location = headers.get("Location")
            if not location:
                raise FetchError("redirect without location")
            current = urljoin(current, location)
            continue
        if status < 200 or status >= 300:
            raise FetchError(f"subscription server returned HTTP {status}")
        charset = headers.get_content_charset() or "utf-8"
        return body.decode(charset, errors="replace")
    raise FetchError("too many redirects")


def check_rate_limit(client_ip):
    now = time.monotonic()
    with RATE_LOCK:
        hits = [t for t in RATE_LIMIT.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
        if len(hits) >= RATE_LIMIT_REQUESTS:
            RATE_LIMIT[client_ip] = hits
            return False
        hits.append(now)
        RATE_LIMIT[client_ip] = hits

        if len(RATE_LIMIT) > 10000:
            for ip, values in list(RATE_LIMIT.items()):
                RATE_LIMIT[ip] = [t for t in values if now - t < RATE_LIMIT_WINDOW]
                if not RATE_LIMIT[ip]:
                    RATE_LIMIT.pop(ip, None)
        return True


def get_cert_sha256(method, host, port, sni):
    cache_key = f"{method}:{host}:{port}:{sni}"
    now = time.monotonic()
    with CACHE_LOCK:
        cached = CERT_CACHE.get(cache_key)
        if cached and now - cached[0] < CERT_CACHE_TTL:
            return cached[1]

    sha256 = None
    for attempt in range(2):
        if method == "quic":
            sha256 = get_quic_cert_sha256(host, port, sni)
        else:
            sha256 = get_tcp_cert_sha256(host, port, sni)
        if sha256 or attempt == 1:
            break
        time.sleep(0.2)

    with CACHE_LOCK:
        CERT_CACHE[cache_key] = (time.monotonic(), sha256)
    return sha256


def get_tcp_cert_sha256(host, port, sni):
    try:
        normalize_host(host)
        validate_port(port, "cert")
    except SecurityError:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    sha256 = None
    try:
        with create_public_tcp_connection(host, port, 5, "cert") as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                sha256 = hashlib.sha256(cert_der).hexdigest()
    except Exception:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with create_public_tcp_connection(host, port, 5, "cert") as sock:
                with ctx2.wrap_socket(sock, server_hostname=sni) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    sha256 = hashlib.sha256(cert_der).hexdigest()
        except Exception:
            pass
    return sha256


async def get_quic_cert_sha256_async(host, port, sni):
    from aioquic.asyncio.client import connect
    from aioquic.quic.configuration import QuicConfiguration
    from cryptography.hazmat.primitives import serialization

    addresses = resolve_public_addresses(host, port, socket.SOCK_DGRAM, "cert")
    connect_host = addresses[0][2]
    configuration = QuicConfiguration(alpn_protocols=["h3"], is_client=True)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = sni or host

    async with connect(connect_host, port, configuration=configuration, wait_connected=True) as protocol:
        peer_cert = protocol._quic.tls._peer_certificate
        if peer_cert is None:
            return None
        cert_der = peer_cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_der).hexdigest()


def get_quic_cert_sha256(host, port, sni):
    try:
        return asyncio.run(asyncio.wait_for(get_quic_cert_sha256_async(host, port, sni), timeout=7))
    except Exception:
        return None


def parse_link(link):
    lower = link.lower()
    if lower.startswith("hysteria2://") or lower.startswith("hy2://"):
        return parse_hy2(link)
    if lower.startswith("trojan://"):
        return parse_trojan(link)
    if lower.startswith("vless://"):
        return parse_vless(link)
    return None


def split_parts(rest):
    name = ""
    if "#" in rest:
        rest, frag = rest.rsplit("#", 1)
        name = unquote(frag)
    qs = ""
    if "?" in rest:
        rest, qs = rest.split("?", 1)
    rest = rest.rstrip("/")
    return name, qs, rest


def split_user_host(main):
    at = main.rfind("@")
    if at == -1:
        raise ValueError("no @")
    user = main[:at]
    hp = main[at + 1:]
    colon = hp.rfind(":")
    if colon == -1:
        raise ValueError("no port")
    return user, hp[:colon], int(hp[colon + 1:])


def parse_link_qs(qs):
    params = {}
    if not qs:
        return params
    for pair in qs.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[unquote(k)] = unquote(v)
        else:
            params[unquote(pair)] = ""
    return params


def parse_hy2(link):
    rest = link
    if rest.lower().startswith("hy2://"):
        rest = "hysteria2://" + rest[6:]
    rest = rest.replace("hysteria2://", "", 1)
    name, qs, main = split_parts(rest)
    user, host, port = split_user_host(main)
    return {"type": "hy2", "user": unquote(user), "host": host, "port": port, "params": parse_link_qs(qs), "name": name}


def parse_trojan(link):
    rest = link.replace("trojan://", "", 1)
    name, qs, main = split_parts(rest)
    user, host, port = split_user_host(main)
    return {"type": "trojan", "user": unquote(user), "host": host, "port": port, "params": parse_link_qs(qs), "name": name}


def parse_vless(link):
    rest = link.replace("vless://", "", 1)
    name, qs, main = split_parts(rest)
    user, host, port = split_user_host(main)
    return {"type": "vless", "user": unquote(user), "host": host, "port": port, "params": parse_link_qs(qs), "name": name}


def cert_target(info):
    sni = info["params"].get("sni") or info["params"].get("peer") or info["host"]
    method = "quic" if info["type"] == "hy2" else "tcp"
    return method, info["host"], info["port"], sni


def convert_link(info, sha256=MISSING):
    if sha256 is MISSING:
        sha256 = get_cert_sha256(*cert_target(info))
    params = dict(info["params"])
    params.pop("insecure", None)
    params.pop("allowInsecure", None)
    params.pop("pinSHA256", None)
    params.pop("pcs", None)
    if sha256:
        if info["type"] == "hy2":
            params["pinSHA256"] = sha256
        else:
            params["pcs"] = sha256
    else:
        if info["params"].get("insecure"):
            params["insecure"] = info["params"]["insecure"]
        if info["params"].get("allowInsecure"):
            params["allowInsecure"] = info["params"]["allowInsecure"]
    qs = urlencode(params, quote_via=quote)
    if info["type"] == "hy2":
        link = f"hysteria2://{quote(info['user'], safe='')}@{info['host']}:{info['port']}?{qs}"
    elif info["type"] == "trojan":
        link = f"trojan://{quote(info['user'], safe='')}@{info['host']}:{info['port']}?{qs}"
    elif info["type"] == "vless":
        link = f"vless://{quote(info['user'], safe='')}@{info['host']}:{info['port']}?{qs}"
    else:
        return ""
    if info["name"]:
        link += f"#{quote(info['name'])}"
    return link


def convert_subscription(text):
    try:
        decoded = base64.b64decode(text.strip()).decode("utf-8")
        if "://" in decoded:
            text = decoded
    except Exception:
        pass
    lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
    if len(lines) > MAX_SUB_LINES:
        raise FetchError("subscription has too many lines")
    parsed = []
    targets = {}
    for line in lines:
        info = parse_link(line)
        parsed.append((line, info))
        if info:
            targets.setdefault(cert_target(info), None)
            if len(targets) > MAX_CERT_TARGETS:
                raise FetchError("subscription has too many certificate targets")

    if targets:
        workers = min(32, len(targets))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(get_cert_sha256, *target): target for target in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    targets[target] = future.result()
                except Exception:
                    targets[target] = None

    results = []
    for line, info in parsed:
        if info:
            try:
                results.append(convert_link(info, targets.get(cert_target(info))))
            except Exception:
                results.append(line)
        else:
            results.append(line)
    return "\n".join(results)


class Handler(BaseHTTPRequestHandler):
    def send_text(self, status, text, content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_GET(self):
        client_ip = self.client_address[0]
        if not check_rate_limit(client_ip):
            self.send_text(429, "Rate limit exceeded")
            return
        if not ACTIVE_REQUESTS.acquire(blocking=False):
            self.send_text(503, "Server is busy")
            return

        parsed = urlparse(self.path)
        try:
            qs = parse_url_qs(parsed.query)
            sub_url = qs.get("url", [None])[0]
            if not sub_url:
                self.send_text(200, "Usage: /?url=<subscription_url>")
                return

            text = fetch_subscription(sub_url)
            converted = convert_subscription(text)
            output = base64.b64encode(converted.encode("utf-8")).decode("ascii")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Profile-Update-Interval", "24")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(output.encode())
        except SecurityError as e:
            self.send_text(403, f"Request blocked: {e}")
        except Exception as e:
            self.send_text(502, f"Failed to convert subscription: {e}")
        finally:
            ACTIVE_REQUESTS.release()

    def log_message(self, format, *args):
        pass  # Silence BaseHTTPRequestHandler default output


def main():
    cert = os.environ.get("CONVERTER_CERT", "fullchain.pem")
    key = os.environ.get("CONVERTER_KEY", "privkey.pem")
    host = os.environ.get("CONVERTER_HOST", "0.0.0.0")
    port = int(os.environ.get("CONVERTER_PORT", "8443"))
    server = ThreadingHTTPServer((host, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(f"Listening on https://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
