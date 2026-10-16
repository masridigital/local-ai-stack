"""Local forward proxy. Clients CONNECT by name; only allowlisted FQDNs are dialed.

Entra login, Anthropic (only when the BAA switch is on), and the Azure OpenAI
host on the Presidio-gated path come from deploy/egress-destinations.yaml.
IP literals are refused. nftables is what limits off-host TCP to this process.
"""

from __future__ import annotations

import os
import select
import socket
import threading
from pathlib import Path

from stack.egress import host_allowed, load_destinations

PROXY_USER = "egress-proxy"
PROXY_BIND = "127.0.0.1"
PROXY_PORT = 8888
ALLOWED_PORTS = frozenset({80, 443})


def connect_allowed(host: str, port: int, raw: dict, env: dict[str, str]) -> bool:
    if port not in ALLOWED_PORTS:
        return False
    name = host.strip().lower().rstrip(".")
    if not name or ":" in name or "/" in name:
        return False
    try:
        socket.inet_aton(name)
        return False
    except OSError:
        pass
    return host_allowed(name, raw, env)


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        raise ValueError("ipv6 target")
    host, sep, port_text = target.rpartition(":")
    if not sep:
        return target, default_port
    return host, int(port_text)


def _absolute_host(target: str) -> tuple[str, int]:
    if "://" not in target:
        raise ValueError("relative target")
    rest = target.split("://", 1)[1]
    hostport = rest.split("/", 1)[0]
    return _split_host_port(hostport, 80)


class EgressProxy:
    def __init__(self, raw: dict, env: dict[str, str], connect=None, bind: str = PROXY_BIND, port: int = 0):
        self.raw = raw
        self.env = env
        self.connect = connect or (lambda host, port: socket.create_connection((host, port), timeout=10))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind, port))
        self.sock.listen(32)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                client, _addr = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            return

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, sep, rest = data.partition(b"\r\n\r\n")
            if not sep:
                _send_status(client, 400, "Bad Request")
                return
            line = head.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
            parts = line.split(" ")
            if len(parts) < 2:
                _send_status(client, 400, "Bad Request")
                return
            method, target = parts[0].upper(), parts[1]
            try:
                if method == "CONNECT":
                    host, port = _split_host_port(target, 443)
                else:
                    host, port = _absolute_host(target)
            except (ValueError, UnicodeError):
                _send_status(client, 400, "Bad Request")
                return
            if not connect_allowed(host, port, self.raw, self.env):
                _send_status(client, 403, "Forbidden")
                return
            upstream = self.connect(host, port)
            if method == "CONNECT":
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _relay(client, upstream)
                return
            upstream.sendall(head + b"\r\n\r\n" + rest)
            _relay(client, upstream)
        except Exception:
            try:
                _send_status(client, 502, "Bad Gateway")
            except OSError:
                return
        finally:
            for sock in (upstream, client):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    continue


def _send_status(client: socket.socket, status: int, reason: str) -> None:
    body = reason.encode("ascii")
    client.sendall(
        f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )


def _relay(left: socket.socket, right: socket.socket) -> None:
    left.setblocking(False)
    right.setblocking(False)
    pair = {left: right, right: left}
    open_socks = {left, right}
    while open_socks:
        readable, _, _ = select.select(list(open_socks), [], [], 30)
        if not readable:
            return
        for sock in readable:
            try:
                chunk = sock.recv(16384)
            except OSError:
                return
            if not chunk:
                open_socks.discard(sock)
                continue
            other = pair[sock]
            try:
                other.sendall(chunk)
            except OSError:
                return


def main() -> None:
    path = Path(os.environ.get("EGRESS_DESTINATIONS", "/etc/local-ai-stack/egress-destinations.yaml"))
    raw = load_destinations(path)
    env = dict(os.environ)
    proxy = EgressProxy(raw, env, bind=os.environ.get("EGRESS_PROXY_BIND", PROXY_BIND), port=int(os.environ.get("EGRESS_PROXY_PORT", str(PROXY_PORT))))
    proxy.serve_forever()


if __name__ == "__main__":
    main()
