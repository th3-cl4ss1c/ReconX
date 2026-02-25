from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from reconx.utils.process import raise_on_interrupt_returncode


def run_httpx(
    targets: list[str],
    out_path: Path,
    alive_urls_path: Path,
    alive_urls_unic_path: Path | None = None,
    headers_path: Path | None = None,
) -> None:
    if not targets:
        out_path.write_text("", encoding="utf-8")
        alive_urls_path.write_text("", encoding="utf-8")
        if alive_urls_unic_path is not None:
            alive_urls_unic_path.write_text("", encoding="utf-8")
        if headers_path is not None:
            headers_path.write_text("", encoding="utf-8")
        return
    preferred = Path.home() / ".cache" / "reconx" / "bin" / "httpx"
    httpx_bin = str(preferred) if preferred.exists() else None
    if not httpx_bin:
        out_path.write_text("", encoding="utf-8")
        alive_urls_path.write_text("", encoding="utf-8")
        if alive_urls_unic_path is not None:
            alive_urls_unic_path.write_text("", encoding="utf-8")
        if headers_path is not None:
            headers_path.write_text("", encoding="utf-8")
        print("⚠️  httpx не найден (ожидаю ~/.cache/reconx/bin/httpx), пропускаю")
        return
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("\n".join(targets))
        tmp.flush()
        tmp_name = tmp.name
    httpx_cmd = [
        httpx_bin,
        "-silent",
        "-j",
        "-no-color",
        "-fr",
        "-retries",
        "1",
        "-timeout",
        "10",
        "-threads",
        "50",
        "-l",
        tmp_name,
    ]
    if headers_path is not None:
        httpx_cmd.append("-irh")
    try:
        proc = subprocess.run(
            httpx_cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
        raise_on_interrupt_returncode(proc.returncode)
        combined = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            out_path.write_text(combined, encoding="utf-8")
            alive_urls_path.write_text("", encoding="utf-8")
            if alive_urls_unic_path is not None:
                alive_urls_unic_path.write_text("", encoding="utf-8")
            if headers_path is not None:
                headers_path.write_text("", encoding="utf-8")
            first_line = combined.splitlines()[0] if combined else ""
            print(f"⚠️  httpx ошибка (код {proc.returncode}) {first_line}")
            return

        out_path.write_text(proc.stdout, encoding="utf-8")
        urls: list[str] = []
        techs: set[str] = set()
        by_content_length: dict[int | None, str] = {}
        urls_by_length: dict[int | None, list[str]] = {}
        header_groups: dict[tuple[tuple[str, str], ...], tuple[list[str], dict[str, str]]] = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url")
                if url:
                    urls.append(url)
                cl = data.get("content_length")
                cl_key: int | None = int(cl) if isinstance(cl, (int, float)) else None
                if url:
                    urls_by_length.setdefault(cl_key, []).append(url)
                    if cl_key not in by_content_length:
                        by_content_length[cl_key] = url
                tech_list = data.get("tech") or data.get("technologies") or data.get("techs")
                if isinstance(tech_list, list):
                    techs.update([str(t) for t in tech_list if t])
                if url and headers_path is not None:
                    raw = (
                        data.get("header")
                        or data.get("response_header")
                        or data.get("response_headers")
                        or data.get("raw_header")
                    )
                    if isinstance(raw, dict) and raw:
                        normalized = {k.lower().replace("-", "_"): str(v) for k, v in raw.items()}
                        sig = tuple(sorted(normalized.items()))
                        if sig not in header_groups:
                            header_groups[sig] = ([], normalized)
                        header_groups[sig][0].append(url)
                    elif isinstance(raw, str) and raw.strip():
                        normalized = {}
                        for part in raw.strip().split("\n"):
                            if ":" in part:
                                k, _, v = part.partition(":")
                                normalized[k.strip().lower().replace("-", "_")] = v.strip()
                        if normalized:
                            sig = tuple(sorted(normalized.items()))
                            if sig not in header_groups:
                                header_groups[sig] = ([], normalized)
                            header_groups[sig][0].append(url)
            except json.JSONDecodeError:
                continue
        header_chunks = []
        for urls_list, hdict in header_groups.values():
            urls_sorted = sorted(set(urls_list))
            header_chunks.append(
                "=== " + ", ".join(urls_sorted) + " ===\n" + "\n".join(f"{k}: {v}" for k, v in sorted(hdict.items()))
            )
        chunks: list[str] = []
        for cl_key in sorted(urls_by_length.keys(), key=lambda x: (x is None, x or 0)):
            urls_in_group = sorted(set(urls_by_length[cl_key]))
            label = str(cl_key) if cl_key is not None else "?"
            chunks.append(f"# {label}\n" + "\n".join(urls_in_group))
        alive_urls_path.write_text("\n\n".join(chunks) + ("\n" if chunks else ""), encoding="utf-8")
        if headers_path is not None:
            headers_path.write_text("\n\n".join(header_chunks) + ("\n" if header_chunks else ""), encoding="utf-8")
        tech_part = f" tech={', '.join(sorted(techs))}" if techs else ""
        if alive_urls_unic_path is not None:
            unic_urls = sorted(by_content_length.values())
            alive_urls_unic_path.write_text("\n".join(unic_urls) + ("\n" if unic_urls else ""), encoding="utf-8")
            msg = f"httpx: {len(urls)} -> alive-urls-unic: {len(unic_urls)}"
            if headers_path is not None and header_chunks:
                msg += f", headers: {len(header_chunks)} groups"
            print(f"{msg}{tech_part}")
        else:
            msg = f"httpx: {len(urls)}"
            if headers_path is not None and header_chunks:
                msg += f", headers: {len(header_chunks)} groups"
            print(f"{msg}{tech_part}")
    except KeyboardInterrupt:
        raise
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        alive_urls_path.write_text("", encoding="utf-8")
        if alive_urls_unic_path is not None:
            alive_urls_unic_path.write_text("", encoding="utf-8")
        if headers_path is not None:
            headers_path.write_text("", encoding="utf-8")
        print("⚠️  httpx timeout")
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def run_nuclei(targets: list[str], out_path: Path, profile: str, mode: str = "web") -> None:
    if not targets:
        out_path.write_text("", encoding="utf-8")
        return
    preferred = Path.home() / ".cache" / "reconx" / "bin" / "nuclei"
    nuclei_bin = str(preferred) if preferred.exists() else None
    if not nuclei_bin:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  nuclei не найден (ожидаю ~/.cache/reconx/bin/nuclei), пропускаю")
        return
    profiles_web = {
        "fast": {
            "severity": "medium,high,critical",
            "tags": "misconfig,exposure",
            "timeout": "10",
            "concurrency": "30",
        },
        "full": {
            "severity": "medium,high,critical",
            "tags": "cves,misconfig,exposure,default-login,technology",
            "timeout": "20",
            "concurrency": "80",
        },
    }
    profiles_net = {
        "fast": {
            "severity": "medium,high,critical",
            "tags": "network",
            "timeout": "15",
            "concurrency": "50",
        },
        "full": {
            "severity": "medium,high,critical",
            "tags": "network,cves,exposure,default-login,technology,misconfig",
            "timeout": "20",
            "concurrency": "80",
        },
    }
    cfg = (profiles_web if mode == "web" else profiles_net).get(profile, profiles_web["fast"])
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("\n".join(targets))
        tmp.flush()
        tmp_name = tmp.name
    try:
        proc = subprocess.run(
            [
                nuclei_bin,
                "-silent",
                "-j",
                "-severity",
                cfg["severity"],
                "-tags",
                cfg["tags"],
                "-timeout",
                cfg["timeout"],
                "-c",
                cfg["concurrency"],
                "-l",
                tmp_name,
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=600,
        )
        raise_on_interrupt_returncode(proc.returncode)
        combined = (proc.stdout or "") + (proc.stderr or "")
        out_path.write_text(combined, encoding="utf-8")
        findings = 0
        severities: dict[str, int] = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings += 1
                sev = str(data.get("info", {}).get("severity") or "").lower()
                if sev:
                    severities[sev] = severities.get(sev, 0) + 1
            except json.JSONDecodeError:
                continue
        prefix = f"nuclei-{mode}"
        if proc.returncode != 0:
            first_line = combined.splitlines()[0] if combined else ""
            print(f"⚠️  {prefix} ошибка (код {proc.returncode}) {first_line}")
        print(f"{prefix}: {findings} ({', '.join(f'{k}={v}' for k, v in sorted(severities.items()))})")
    except KeyboardInterrupt:
        raise
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  nuclei timeout")
    finally:
        Path(tmp_name).unlink(missing_ok=True)
