"""Local forward proxy. Each listener has its own loopback port.

Open WebUI's port allows only Entra login names. LiteLLM's port allows
Anthropic when the BAA switch is on, and the Azure OpenAI host when that
name is a single US-region label. Those two ports accept CONNECT to port 443
only. The apt port (root and _apt) allows the archive, security, and
Cloudsmith names, plus install-time package hosts while INSTALL_EGRESS=1.
Port 443 on that listener is CONNECT, which is the name the client will use
as SNI. Port 80 is absolute-form HTTP and the Host header must match. The
policy-gateway port allows only the configured StackJack and Composio names.

The dialed address is the first resolved address for which ip.is_global is
true, after unwrapping an IPv4-mapped address. Multicast is refused.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import threading
from pathlib import Path

from stack.egress import (
    APT_DESTINATIONS,
    MCP_DESTINATIONS,
    host_on_named_destination,
    load_destinations,
    proxy_host_allowed,
)

PROXY_USER = "egress-proxy"
PROXY_BIND = "127.0.0.1"
# (service user, port). nftables lets only that uid reach the port.
RUNTIME_LISTENERS = (
    ("openwebui", 8888),
    ("litellm", 8889),
)
APT_LISTENER = ("apt", 8890)
MCP_LISTENER = ("policy-gateway", 8891)
PROXY_LISTENERS = RUNTIME_LISTENERS + (APT_LISTENER, MCP_LISTENER)


def bind_address(host: str) -> str:
    if host.strip() != PROXY_BIND:
        raise SystemExit("egress proxy refuses a non-loopback bind")
    return PROXY_BIND


def forbidden_ip(address: str) -> bool:
    """True when the address is not a global unicast destination.

    IPv4-mapped addresses are unwrapped first. ip.is_global is false for
    loopback, link-local, RFC1918, CGNAT, ULA, and documentation ranges.
    Multicast reports is_global on this interpreter, so it is refused too.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return forbidden_ip(str(ip.ipv4_mapped))
    if ip.is_multicast:
        return True
    return not ip.is_global


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


def _dns_name(host: str) -> str | None:
    name = host.strip().lower().rstrip(".")
    if not name or ":" in name or "/" in name or ".." in name or "@" in name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        return name


def connect_allowed(host: str, port: int, raw: dict, env: dict[str, str], user: str) -> bool:
    if port != 443:
        return False
    name = _dns_name(host)
    if name is None:
        return False
    return proxy_host_allowed(name, user, raw, env)


def apt_target_allowed(method: str, host: str, port: int, raw: dict, env: dict[str, str]) -> bool:
    name = _dns_name(host)
    if name is None:
        return False
    if method == "CONNECT" and port == 443:
        return host_on_named_destination(name, 443, raw, env, APT_DESTINATIONS)
    if method in {"GET", "HEAD"} and port == 80:
        return host_on_named_destination(name, 80, raw, env, APT_DESTINATIONS)
    return False


def mcp_target_allowed(host: str, port: int, raw: dict, env: dict[str, str]) -> bool:
    if port != 443:
        return False
    name = _dns_name(host)
    if name is None:
        return False
    return host_on_named_destination(name, 443, raw, env, MCP_DESTINATIONS)


def _split_host_port(target: str) -> tuple[str, int]:
    if target.startswith("["):
        raise ValueError("ipv6 target")
    host, sep, port_text = target.rpartition(":")
    if not sep:
        raise ValueError("port required")
    return host, int(port_text)


def _header_value(head: bytes, name: str) -> str | None:
    prefix = name.lower().encode("ascii") + b":"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(prefix):
            return line.split(b":", 1)[1].decode("iso-8859-1").strip()
    return None


def _hostname_of(value: str) -> str:
    text = value.strip().lower().rstrip(".")
    if not text or text.startswith("[") or "@" in text or "/" in text:
        raise ValueError("host")
    if ":" in text:
        name, port_text = text.rsplit(":", 1)
        if not port_text.isdigit():
            raise ValueError("port")
        text = name.rstrip(".")
    if not text or ":" in text or ".." in text:
        raise ValueError("host")
    return text


def host_header_matches(head: bytes, host: str, *, required: bool) -> bool:
    """CONNECT may omit Host. Absolute-form HTTP must send a matching Host."""
    raw = _header_value(head, "host")
    if raw is None:
        return not required
    return _hostname_of(raw) == host.strip().lower().rstrip(".")


def absolute_http_target(target: str) -> tuple[str, int, str]:
    if not target.lower().startswith("http://"):
        raise ValueError("absolute")
    rest = target[7:]
    hostport, sep, path = rest.partition("/")
    path = "/" + path if sep else "/"
    if not hostport or "@" in hostport or "\r" in path or "\n" in path or " " in path:
        raise ValueError("absolute")
    if ":" in hostport:
        host, port = _split_host_port(hostport)
    else:
        host, port = hostport, 80
    return host, port, path


class EgressProxy:
    def __init__(
        self,
        raw: dict,
        env: dict[str, str],
        listeners=PROXY_LISTENERS,
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
            if user in {"openwebui", "litellm", "policy-gateway"}:
                upstream = self._connect_request(client, user, method, target, head)
                return
            if user == "apt":
                upstream = self._apt_request(client, method, target, head, rest)
                return
            _send_status(client, 405, "Method Not Allowed")
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

    def _connect_request(self, client: socket.socket, user: str, method: str, target: str, head: bytes):
        if method != "CONNECT":
            _send_status(client, 405, "Method Not Allowed")
            return None
        try:
            host, port = _split_host_port(target)
        except (ValueError, UnicodeError):
            _send_status(client, 400, "Bad Request")
            return None
        try:
            matched = host_header_matches(head, host, required=False)
        except ValueError:
            _send_status(client, 400, "Bad Request")
            return None
        if not matched:
            _send_status(client, 403, "Forbidden")
            return None
        if user == "policy-gateway":
            allowed = mcp_target_allowed(host, port, self.raw, self.env)
        else:
            allowed = connect_allowed(host, port, self.raw, self.env, user)
        if not allowed:
            _send_status(client, 403, "Forbidden")
            return None
        return self._tunnel(client, host, port)

    def _apt_request(self, client: socket.socket, method: str, target: str, head: bytes, rest: bytes):
        if method == "CONNECT":
            try:
                host, port = _split_host_port(target)
            except (ValueError, UnicodeError):
                _send_status(client, 400, "Bad Request")
                return None
            try:
                matched = host_header_matches(head, host, required=False)
            except ValueError:
                _send_status(client, 400, "Bad Request")
                return None
            if not matched or not apt_target_allowed(method, host, port, self.raw, self.env):
                _send_status(client, 403, "Forbidden")
                return None
            return self._tunnel(client, host, port)
        if method not in {"GET", "HEAD"}:
            _send_status(client, 405, "Method Not Allowed")
            return None
        try:
            host, port, path = absolute_http_target(target)
            matched = host_header_matches(head, host, required=True)
        except (ValueError, UnicodeError):
            _send_status(client, 400, "Bad Request")
            return None
        if not matched or not apt_target_allowed(method, host, port, self.raw, self.env):
            _send_status(client, 403, "Forbidden")
            return None
        length = _header_value(head, "content-length")
        if length not in {None, "0"}:
            _send_status(client, 400, "Bad Request")
            return None
        return self._forward_http(client, head, rest, method, path, host, port)

    def _tunnel(self, client: socket.socket, host: str, port: int):
        address = vetted_ip(host, self.resolve)
        if address is None:
            _send_status(client, 403, "Forbidden")
            return None
        upstream = self.connect(address, port)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _relay(client, upstream)
        except Exception:
            upstream.close()
            raise
        return upstream

    def _forward_http(
        self,
        client: socket.socket,
        head: bytes,
        rest: bytes,
        method: str,
        path: str,
        host: str,
        port: int,
    ):
        address = vetted_ip(host, self.resolve)
        if address is None:
            _send_status(client, 403, "Forbidden")
            return None
        lines = head.split(b"\r\n")
        origin = f"{method} {path} HTTP/1.1".encode("ascii")
        rewritten = b"\r\n".join([origin, *lines[1:]]) + b"\r\n\r\n" + rest
        upstream = self.connect(address, port)
        try:
            upstream.sendall(rewritten)
            _relay(client, upstream)
        except Exception:
            upstream.close()
            raise
        return upstream


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
