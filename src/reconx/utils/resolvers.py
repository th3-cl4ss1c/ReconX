from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
import urllib.request
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Iterable

DEFAULT_RESOLVER_SOURCES = [
    "https://public-dns.info/nameservers.txt",
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt",
]


def _extract_ipv4(line: str) -> str | None:
    value = line.strip()
    if not value or value.startswith("#"):
        return None

    token = value.split()[0].strip()
    if token.count(":") == 1:
        host, _, port = token.partition(":")
        if port.isdigit():
            token = host
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return None
    return str(ip)


def normalize_resolvers(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in lines:
        ip = _extract_ipv4(str(raw))
        if not ip or ip in seen:
            continue
        seen.add(ip)
        result.append(ip)
    return result


def _download_lines(url: str, timeout: int = 25) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore").splitlines()


def collect_resolver_candidates(primary_source: str | None = None, max_candidates: int = 20000) -> list[str]:
    sources: list[str] = []
    if primary_source:
        sources.append(primary_source)
    for src in DEFAULT_RESOLVER_SOURCES:
        if src not in sources:
            sources.append(src)

    candidates: list[str] = []
    seen: set[str] = set()
    for src in sources:
        try:
            lines = _download_lines(src)
        except Exception:
            continue
        for line in lines:
            ip = _extract_ipv4(line)
            if not ip or ip in seen:
                continue
            seen.add(ip)
            candidates.append(ip)
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    random.shuffle(candidates)
    return candidates


def _build_query(domain: str, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(len(label).to_bytes(1, "big") + label.encode("ascii") for label in domain.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


def _query_once(resolver_ip: str, domain: str, timeout_sec: float = 1.3) -> tuple[int, int] | None:
    txid = random.randint(0, 65535)
    packet = _build_query(domain, txid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.sendto(packet, (resolver_ip, 53))
        data, _ = sock.recvfrom(1024)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if len(data) < 12:
        return None
    rxid, flags, _, answer_count, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rxid != txid:
        return None
    if (flags & 0x8000) == 0:
        return None
    rcode = flags & 0x000F
    return rcode, answer_count


def _probe_resolver(resolver_ip: str) -> bool:
    q1 = _query_once(resolver_ip, "example.com")
    if not q1:
        return False
    rcode1, answers1 = q1
    if rcode1 != 0 or answers1 <= 0:
        return False

    rand_label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(10))
    q2 = _query_once(resolver_ip, f"{rand_label}.example.com")
    if not q2:
        return False
    rcode2, answers2 = q2

    if rcode2 == 3:
        return True
    if rcode2 == 0 and answers2 == 0:
        return True
    if rcode2 == 2:  # SERVFAIL на NXDOMAIN-проверке тоже приемлем для рекурсоров в некоторых сетях
        return True
    return False


def validate_resolvers_fast(
    candidates: list[str],
    duration_sec: int,
    workers: int = 256,
    max_valid: int = 5000,
) -> list[str]:
    if not candidates or duration_sec <= 0:
        return []

    workers = max(32, min(512, workers))
    deadline = time.monotonic() + max(1, duration_sec)
    valid: set[str] = set()
    idx = 0
    futures: dict = {}

    def _submit(executor: ThreadPoolExecutor) -> bool:
        nonlocal idx
        if idx >= len(candidates):
            return False
        if time.monotonic() >= deadline:
            return False
        ip = candidates[idx]
        idx += 1
        futures[executor.submit(_probe_resolver, ip)] = ip
        return True

    with ThreadPoolExecutor(max_workers=workers) as executor:
        initial = min(len(candidates), workers * 4)
        for _ in range(initial):
            if not _submit(executor):
                break

        while futures and time.monotonic() < deadline:
            if len(valid) >= max_valid:
                break
            timeout = max(0.05, min(0.5, deadline - time.monotonic()))
            done, _ = wait(list(futures.keys()), timeout=timeout, return_when=FIRST_COMPLETED)
            if not done:
                continue
            for fut in done:
                ip = futures.pop(fut, None)
                if not ip:
                    continue
                try:
                    if fut.result():
                        valid.add(ip)
                except Exception:
                    pass
                _submit(executor)

    return sorted(valid)

