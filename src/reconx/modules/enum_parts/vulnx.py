from __future__ import annotations

from collections import deque
import json
import math
import os
import re
import subprocess
import time
from pathlib import Path

from reconx.utils.process import raise_on_interrupt_returncode

from .providers import load_projectdiscovery_api_key

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RATE_LIMIT_MARKERS = ("rate limit", "too many requests", "429", "quota")
_AUTH_ERROR_MARKERS = ("invalid api key", "unauthorized", "forbidden")


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_float(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def _extract_cves_from_text(text: str) -> set[str]:
    return {match.group(0).upper() for match in _CVE_RE.finditer(text or "")}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_cves_from_smap(smap_path: Path) -> set[str]:
    if not smap_path.exists():
        return set()
    text = _read_text(smap_path)
    cves = _extract_cves_from_text(text)
    if not text.strip():
        return cves
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return cves

    hosts = data if isinstance(data, list) else [data]
    for host in hosts:
        if not isinstance(host, dict):
            continue
        vulns = host.get("vulns")
        if isinstance(vulns, list):
            for entry in vulns:
                if not entry:
                    continue
                cves.update(_extract_cves_from_text(str(entry)))
        ports = host.get("ports")
        if isinstance(ports, list):
            for port_obj in ports:
                if not isinstance(port_obj, dict):
                    continue
                port_vulns = port_obj.get("vulns")
                if isinstance(port_vulns, list):
                    for entry in port_vulns:
                        if not entry:
                            continue
                        cves.update(_extract_cves_from_text(str(entry)))
    return cves


def _collect_cves(raw_scan_dir: Path) -> tuple[list[str], dict[str, int]]:
    found: set[str] = set()
    by_source: dict[str, int] = {}

    smap_path = raw_scan_dir / "smap.json"
    smap_cves = _extract_cves_from_smap(smap_path)
    if smap_cves:
        found.update(smap_cves)
        by_source["smap.json"] = len(smap_cves)

    nuclei_net_path = raw_scan_dir / "nuclei-net.json"
    if nuclei_net_path.exists():
        nuclei_cves = _extract_cves_from_text(_read_text(nuclei_net_path))
        if nuclei_cves:
            found.update(nuclei_cves)
            by_source["nuclei-net.json"] = len(nuclei_cves)

    nmap_matches = sorted(path for path in raw_scan_dir.glob("nmap*") if path.is_file())
    for nmap_file in nmap_matches:
        nmap_cves = _extract_cves_from_text(_read_text(nmap_file))
        if nmap_cves:
            found.update(nmap_cves)
            by_source[nmap_file.name] = len(nmap_cves)

    return sorted(found), by_source


def _decode_vulnx_payload(stdout: str) -> list[dict]:
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(decoded, dict):
        return [decoded]
    if isinstance(decoded, list):
        return [entry for entry in decoded if isinstance(entry, dict)]
    return []


def _extract_cve_id(entry: dict) -> str | None:
    for key in ("cve_id", "doc_id", "id"):
        value = entry.get(key)
        if not value:
            continue
        match = _CVE_RE.search(str(value))
        if match:
            return match.group(0).upper()
    probe = json.dumps(entry, ensure_ascii=False)
    match = _CVE_RE.search(probe)
    if match:
        return match.group(0).upper()
    return None


def run_vulnx_scan(raw_scan_dir: Path, vulnx_bin: str | None) -> None:
    """
    Обогащает найденные CVE через vulnx и сохраняет результаты в raw/scan.
    """
    input_cves_path = raw_scan_dir / "vulnx-input-cves.txt"
    out_jsonl_path = raw_scan_dir / "vulnx.jsonl"
    missing_cves_path = raw_scan_dir / "vulnx-missing-cves.txt"
    summary_path = raw_scan_dir / "vulnx-summary.json"

    if not vulnx_bin:
        print("⚠️  vulnx не найден, пропускаю CVE enrichment")
        return

    cves, by_source = _collect_cves(raw_scan_dir)
    if not cves:
        input_cves_path.write_text("", encoding="utf-8")
        out_jsonl_path.write_text("", encoding="utf-8")
        missing_cves_path.write_text("", encoding="utf-8")
        summary = {
            "status": "no-cve",
            "input_cves": 0,
            "retrieved_cves": 0,
            "missing_cves": 0,
            "sources": by_source,
        }
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print("vulnx: 0 CVE (нет входных CVE)")
        return

    batch_size = _env_int("RECONX_VULNX_BATCH_SIZE", 50)
    delay_seconds = _env_float("RECONX_VULNX_BATCH_DELAY", 0.8)
    timeout_seconds = _env_int("RECONX_VULNX_TIMEOUT", 90)

    input_cves_path.write_text("\n".join(cves) + "\n", encoding="utf-8")
    out_jsonl_path.write_text("", encoding="utf-8")
    missing_cves_path.write_text("", encoding="utf-8")

    api_key = load_projectdiscovery_api_key()
    env = os.environ.copy()
    if api_key:
        # vulnx ожидает ключ именно в PDCP_API_KEY.
        env["PDCP_API_KEY"] = api_key
        env["PROJECTDISCOVERY_API_KEY"] = api_key
        print("🔐 ProjectDiscovery API key загружен (ENV/Bitwarden/provider-config).")
    else:
        print("⚠️  ProjectDiscovery API key не найден (ENV/Bitwarden/provider-config), продолжаю без ключа.")

    records_by_cve: dict[str, dict] = {}
    failed_batches = 0
    initial_batches = int(math.ceil(len(cves) / batch_size))
    pending = deque(cves[index : index + batch_size] for index in range(0, len(cves), batch_size))
    stopped_by_rate_limit = False
    stopped_on_batch_size = 0
    requests_attempted = 0
    requests_rate_limited = 0
    max_rate_limit_events = _env_int("RECONX_VULNX_MAX_RATE_EVENTS", 20)

    while pending:
        chunk = pending.popleft()
        requests_attempted += 1
        batch_no = requests_attempted
        batch_len = len(chunk)
        ids_arg = ",".join(chunk)
        cmd = [
            vulnx_bin,
            "--silent",
            "--disable-update-check",
            "--json",
            "--timeout",
            f"{timeout_seconds}s",
            "id",
            ids_arg,
        ]

        try:
            proc = subprocess.run(
                cmd,
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_seconds + 10,
                env=env,
            )
            raise_on_interrupt_returncode(proc.returncode)
        except subprocess.TimeoutExpired:
            failed_batches += 1
            print(f"⚠️  vulnx timeout на запросе #{batch_no} (batch={batch_len})")
            if delay_seconds > 0 and pending:
                time.sleep(delay_seconds)
            continue

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined = (stderr + "\n" + stdout).strip().lower()
        payload = _decode_vulnx_payload(stdout)
        if proc.returncode != 0 and not payload:
            failed_batches += 1
            if any(marker in combined for marker in _RATE_LIMIT_MARKERS):
                requests_rate_limited += 1
                if requests_rate_limited > max_rate_limit_events:
                    stopped_by_rate_limit = True
                    stopped_on_batch_size = batch_len
                    print(
                        f"⚠️  vulnx rate-limit повторился {requests_rate_limited} раз, "
                        f"останавливаю обработку (batch={batch_len})."
                    )
                    break
                if batch_len > 1:
                    split_size = max(1, batch_len // 2)
                    split_chunks = [chunk[idx : idx + split_size] for idx in range(0, batch_len, split_size)]
                    for subchunk in reversed(split_chunks):
                        pending.appendleft(subchunk)
                    print(
                        f"⚠️  vulnx rate-limit на запросе #{batch_no}; "
                        f"дроблю batch {batch_len} -> {split_size}."
                    )
                    time.sleep(max(delay_seconds, 1.0))
                    continue
                stopped_by_rate_limit = True
                stopped_on_batch_size = batch_len
                print("⚠️  vulnx rate-limit даже на batch=1, останавливаю дальнейшие запросы.")
                break
            if any(marker in combined for marker in _AUTH_ERROR_MARKERS):
                print(f"⚠️  vulnx auth-ошибка на запросе #{batch_no} (batch={batch_len}, код {proc.returncode})")
            else:
                print(f"⚠️  vulnx ошибка на запросе #{batch_no} (batch={batch_len}, код {proc.returncode})")
            if delay_seconds > 0 and pending:
                time.sleep(delay_seconds)
            continue

        for entry in payload:
            cve_id = _extract_cve_id(entry)
            if not cve_id:
                continue
            records_by_cve[cve_id] = entry

        if delay_seconds > 0 and pending:
            time.sleep(delay_seconds)

    sorted_cves = sorted(records_by_cve.keys())
    with out_jsonl_path.open("w", encoding="utf-8") as output_file:
        for cve_id in sorted_cves:
            output_file.write(json.dumps(records_by_cve[cve_id], ensure_ascii=False) + "\n")

    missing = sorted(set(cves) - set(sorted_cves))
    missing_cves_path.write_text("\n".join(missing) + ("\n" if missing else ""), encoding="utf-8")

    summary = {
        "status": "ok",
        "input_cves": len(cves),
        "retrieved_cves": len(sorted_cves),
        "missing_cves": len(missing),
        "batches_total_initial": initial_batches,
        "batches_failed": failed_batches,
        "requests_attempted": requests_attempted,
        "requests_rate_limited": requests_rate_limited,
        "stopped_by_rate_limit": stopped_by_rate_limit,
        "stopped_on_batch_size": stopped_on_batch_size,
        "rate_limit_events_max": max_rate_limit_events,
        "batch_size": batch_size,
        "delay_seconds": delay_seconds,
        "timeout_seconds": timeout_seconds,
        "api_key_loaded": bool(api_key),
        "sources": by_source,
        "output_jsonl": str(out_jsonl_path),
        "input_cves_file": str(input_cves_path),
        "missing_cves_file": str(missing_cves_path),
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(
        f"vulnx: input={len(cves)}, resolved={len(sorted_cves)}, missing={len(missing)}, "
        f"requests={requests_attempted}, failed={failed_batches}"
    )
