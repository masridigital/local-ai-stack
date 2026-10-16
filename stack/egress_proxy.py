"""Local forward proxy. Each service has its own loopback port.

Open WebUI's port allows only Entra login names. LiteLLM's port allows
Anthropic when the BAA switch is on, and the Azure OpenAI host when that
name is a single US-region label. CONNECT to port 443 is the only method.
The dialed address is a resolved IP that is not loopback, link-local,
RFC1918, CGNAT, or ULA.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import threading
from pathlib import Path

from stack.egress import load_destinations, proxy_host_allowed

PROXY_USER = "egress-proxy"
PROXY_BIND = "127.0.0.1"
# (service user, port). nftables lets only that uid reach the port.
RUNTIME_LISTENERS = (
    ("openwebui", 8888),
    ("litellm", 8889),
)

_FORBIDDEN = tuple(
    ipaddress.ip_network(item)
    for item in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    )
)


def bind_address(host: str) -> str:
    if host.strip() != PROXY_BIND:
        raise SystemExit("egress proxy refuses a non-loopback bind")
    return PROXY_BIND


def forbidden_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return forbidden_ip(str(ip.ipv4_mapped))
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return True
    return any(ip in network for network in _FORBIDDEN)


def default_resolve(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return [info[4][0] for info in infos]


def vetted_ip(host: str, resolve) -> str | None:
    try:
        addresses = resolve(host)
    except OSError:
        return None
    for address in addresses:
        if not forbidden_ip(address):
            return address
    return None


def connect_allowed(host: str, port: int, raw: dict, env: dict[str, str], user: str) -> bool:
    if port != 443:
        return False
    name = host.strip().lower().rstrip(".")
    if not name or ":" in name or "/" in name or ".." in name:
        return False
    try:
        socket.inet_aton(name)
        return False
    except OSError:
        pass
    return proxy_host_allowed(name, user, raw, env)


def _split_host_port(target: str) -> tuple[str, int]:
    if target.startswith("["):
        raise ValueError("ipv6 target")
    host, sep, port_text = target.rpartition(":")
    if not sep:
        raise ValueError("port required")
    return host, int(port_text)


class EgressProxy:
    def __init__(
        self,
        raw: dict,
        env: dict[str, str],
        listeners=RUNTIME_LISTENERS,
        connect=None,
        resolve=None,
        bind: str = PROXY_BIND,
    ):
        self.raw = raw
        self.env = env
        self.connect = connect or (lambda host, port: socket.create_connection((host, port), timeout=10))
        self.resolve = resolve or default_resolve
        self.bind_host = bind_address(bind)
        self._stop = threading.Event()
        self.sockets: list[tuple[str, socket.socket]] = []
        for user, port in listeners:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.bind_host, port))
            if sock.getsockname()[0] != PROXY_BIND:
                raise SystemExit("egress proxy refuses a non-loopback bind")
            sock.listen(32)
            sock.settimeout(0.5)
            self.sockets.append((user, sock))

    def port_for(self, user: str) -> int:
        for name, sock in self.sockets:
            if name == user:
                return sock.getsockname()[1]
        raise KeyError(user)

    def serve_forever(self) -> None:
        watched = [sock for _user, sock in self.sockets]
        while not self._stop.is_set():
            readable, _, _ = select.select(watched, [], [], 0.5)
            for sock in readable:
                user = next(name for name, item in self.sockets if item is sock)
                try:
                    client, _addr = sock.accept()
                except OSError:
                    continue
                threading.Thread(target=self._handle, args=(client, user), daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        for _user, sock in self.sockets:
            try:
                sock.close()
            except OSError:
                continue

    def _handle(self, client: socket.socket, user: str) -> None:
        upstream = None
        try:
            client.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = client.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, sep, _rest = data.partition(b"\r\n\r\n")
            if not sep:
                _send_status(client, 400, "Bad Request")
                return
            line = head.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
            parts = line.split(" ")
            if len(parts) < 2:
                _send_status(client, 400, "Bad Request")
                return
            method, target = parts[0].upper(), parts[1]
            if method != "CONNECT":
                _send_status(client, 405, "Method Not Allowed")
                return
            try:
                host, port = _split_host_port(target)
            except (ValueError, UnicodeError):
                _send_status(client, 400, "Bad Request")
                return
            if not connect_allowed(host, port, self.raw, self.env, user):
                _send_status(client, 403, "Forbidden")
                return
            address = vetted_ip(host, self.resolve)
            if address is None:
                _send_status(client, 403, "Forbidden")
                return
            upstream = self.connect(address, port)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
    proxy = EgressProxy(raw, dict(os.environ), bind=os.environ.get("EGRESS_PROXY_BIND", PROXY_BIND))
    proxy.serve_forever()


if __name__ == "__main__":
    main()
