from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


def run_cmd(cmd: str, timeout: int) -> list[str]:
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, timeout=timeout, stderr=subprocess.DEVNULL)
        return [line.strip() for line in out.splitlines() if line.strip()]
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return []


def run_subfinder(domain: str) -> list[str]:
    return run_cmd(f"subfinder -d {domain} -silent", timeout=180)


def has_wildcard(domain: str, resolvers: str, shuffledns_bin: str | None, massdns_bin: str | None) -> bool:
    if not shuffledns_bin or not massdns_bin:
        return False
    test_labels = [f"zz{os.getpid()}", f"xx{os.getpid() + 1}"]
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        for lbl in test_labels:
            tmp.write(f"{lbl}.{domain}\n")
        tmp.flush()
        tmp_name = tmp.name
    try:
        meta = run_cmd(
            f"shuffledns -list {tmp_name} -r {resolvers} -silent -mode resolve -retries 1 -t 100",
            timeout=15,
        )
        return len(meta) >= 2
    finally:
        os.remove(tmp_name)


def shuffledns_bruteforce(domain: str, resolvers: str, wordlist: str) -> list[str]:
    return run_cmd(
        f"shuffledns -d {domain} -w {wordlist} -r {resolvers} -silent -mode bruteforce -retries 1 -t 10000",
        timeout=300,
    )


def resolve_with_shuffledns(candidates: set[str], wildcard: bool, resolvers: str, resolve_path: Path) -> list[str]:
    if not candidates:
        return []
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("\n".join(sorted(candidates)))
        tmp.flush()
        tmp_name = tmp.name
    try:
        resolved = run_cmd(
            f"shuffledns -list {tmp_name} -r {resolvers} -silent -mode resolve -retries 1 -t 200",
            timeout=300,
        )
        if resolved:
            final_list = resolved
        elif wildcard:
            final_list = sorted(candidates)
        else:
            final_list = sorted(candidates)
        resolve_path.write_text("\n".join(final_list) + ("\n" if final_list else ""), encoding="utf-8")
        return final_list
    finally:
        os.remove(tmp_name)
