"""Report whether a path sits on a LUKS mapping.

install.sh --apply refuses to continue when the data directory is not on
crypto. --self-check exercises the walker without touching the host.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def parents_include_crypt(start: str, nodes: dict[str, tuple[str, str]]) -> bool:
    """nodes maps a device name to (type, parent name)."""
    name = start.removeprefix("/dev/").removeprefix("mapper/")
    seen: set[str] = set()
    while name and name not in seen:
        seen.add(name)
        dev_type, parent = nodes.get(name, ("", ""))
        if dev_type == "crypt":
            return True
        name = parent
    return False


def parse_lsblk(text: str) -> dict[str, tuple[str, str]]:
    nodes: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name, dev_type = parts[0], parts[1]
        parent = parts[2] if len(parts) > 2 else ""
        nodes[name] = (dev_type, parent)
    return nodes


def source_name(source: str) -> str:
    path = source.strip()
    if path.startswith("/dev/mapper/"):
        return path.removeprefix("/dev/mapper/")
    return Path(path).name


def live_nodes() -> dict[str, tuple[str, str]]:
    output = subprocess.check_output(["lsblk", "-rno", "NAME,TYPE,PKNAME"], text=True)
    return parse_lsblk(output)


def live_source(target: str) -> str:
    output = subprocess.check_output(["findmnt", "-n", "-o", "SOURCE", "--target", target], text=True)
    return output.strip()


def self_check() -> None:
    encrypted = {
        "sda": ("disk", ""),
        "sda2": ("part", "sda"),
        "dm-0": ("crypt", "sda2"),
        "ubuntu--vg-root": ("lvm", "dm-0"),
    }
    plain = {"vda": ("disk", ""), "vda1": ("part", "vda")}
    if not parents_include_crypt("ubuntu--vg-root", encrypted):
        raise SystemExit("luks walker missed a crypt parent")
    if parents_include_crypt("vda1", plain):
        raise SystemExit("luks walker treated a plain disk as crypt")
    parsed = parse_lsblk("sda disk\nsda2 part sda\ndm-0 crypt sda2\n")
    if not parents_include_crypt(source_name("/dev/mapper/dm-0"), parsed):
        raise SystemExit("luks walker missed a mapper source")
    print("luks self-check ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    if not args.target:
        raise SystemExit("usage: check_luks.py --self-check | --target PATH")
    try:
        source = live_source(args.target)
        nodes = live_nodes()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"cannot inspect LUKS for {args.target}: {exc}") from exc
    if not source or not parents_include_crypt(source_name(source), nodes):
        raise SystemExit(
            f"{args.target} is not on LUKS. Encrypt the Proxmox disk or set LUKS_DISK before apply."
        )
    print(f"luks ok {args.target}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc
