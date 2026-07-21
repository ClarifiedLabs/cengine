#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import os
import re
import subprocess


POOLS = {
    "automatic IPv4": os.environ.get("CENGINE_COMPAT_IPV4_AUTO_POOL", "10.192.0.0/12"),
    "fixture IPv4": os.environ.get("CENGINE_COMPAT_IPV4_FIXTURE_POOL", "10.208.0.0/12"),
    "automatic IPv6": os.environ.get("CENGINE_COMPAT_IPV6_AUTO_PREFIX", "fdcc::/16"),
    "fixture IPv6": os.environ.get("CENGINE_COMPAT_IPV6_FIXTURE_PREFIX", "fdcd::/16"),
}


def host_networks() -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    output = subprocess.run(
        ["/sbin/ifconfig"], check=True, text=True, stdout=subprocess.PIPE
    ).stdout
    interface = "unknown"
    networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for line in output.splitlines():
        match = re.match(r"^([^\s:]+):", line)
        if match:
            interface = match.group(1)
            continue
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "inet" and "netmask" in fields:
            if interface == "lo0":
                continue
            mask = fields[fields.index("netmask") + 1]
            prefix = bin(int(mask, 16)).count("1") if mask.startswith("0x") else mask
            networks.append((interface, ipaddress.ip_interface(f"{fields[1]}/{prefix}").network))
        elif len(fields) >= 4 and fields[0] == "inet6" and "prefixlen" in fields:
            if interface == "lo0" or fields[1].lower().startswith("fe80:"):
                continue
            address = fields[1].split("%", 1)[0]
            prefix = fields[fields.index("prefixlen") + 1]
            networks.append((interface, ipaddress.ip_interface(f"{address}/{prefix}").network))
    return networks


def specific_route(pool: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[str, str] | None:
    target = str(pool.network_address + 1)
    command = ["/sbin/route", "-n", "get"]
    if pool.version == 6:
        command.append("-inet6")
    result = subprocess.run(
        [*command, target], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    if result.returncode != 0:
        return None
    values = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    destination = values.get("destination", "")
    if not destination or destination == "default":
        return None
    return destination, values.get("interface", "unknown")


def main() -> None:
    selected = {name: ipaddress.ip_network(value, strict=True) for name, value in POOLS.items()}
    collisions = []
    for pool_name, pool in selected.items():
        for interface, network in host_networks():
            if pool.version == network.version and pool.overlaps(network):
                collisions.append(f"{pool_name} {pool} overlaps {interface} ({network})")
        route = specific_route(pool)
        if route is not None:
            collisions.append(
                f"{pool_name} {pool} is captured by {route[1]} (specific route {route[0]})"
            )
    if collisions:
        raise SystemExit(
            "compatibility network pool collision:\n  "
            + "\n  ".join(collisions)
            + "\nChoose non-overlapping CENGINE_COMPAT_*_POOL/PREFIX values."
        )
    print("compatibility network pools do not overlap active host interfaces or routes")


if __name__ == "__main__":
    main()
