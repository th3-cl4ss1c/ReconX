from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Iterable


def count_cves(lines: Iterable[str]) -> int:
    pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    count = 0
    for line in lines:
        count += len(pattern.findall(line))
    return count


def unique_naabu_hosts(lines: list[str]) -> set[str]:
    hosts: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or ":" not in line:
            continue
        host_part = line.rsplit(":", 1)[0]
        hosts.add(host_part)
    return hosts


def parse_naabu_ports(lines: list[str]) -> set[int]:
    ports: set[int] = set()
    for line in lines:
        parts = line.split(":")
        if len(parts) < 2:
            continue
        port_part = parts[1].split()[0]
        try:
            port = int(port_part)
            if 0 < port < 65536:
                ports.add(port)
        except ValueError:
            continue
    return ports


def run_dnsx(hosts: list[str], resolvers: str, out_path: Path) -> list[str]:
    if not hosts:
        out_path.write_text("", encoding="utf-8")
        print("dnsx: 0 (нет хостов)")
        return []
    dnsx_bin = shutil.which("dnsx")
    if not dnsx_bin:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  dnsx не найден, пропускаю")
        return []

    def _run_dnsx(args: list[str]) -> tuple[list[str], str]:
        proc = subprocess.run(
            [dnsx_bin, *args],
            input="\n".join(hosts),
            text=True,
            capture_output=True,
            check=True,
            timeout=300,
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return lines, proc.stdout

    try:
        lines, stdout = _run_dnsx(["-silent", "-r", resolvers, "-retry", "3", "-j"])
        if not lines:
            print("dnsx: 0, пробую без -r (system resolvers)")
            lines, stdout = _run_dnsx(["-silent", "-retry", "2", "-j"])

        out_path.write_text(stdout, encoding="utf-8")
        print(f"dnsx: {len(lines)}")
        ips: set[str] = set()
        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            for key in ("a", "aaaa"):
                vals = obj.get(key) or []
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    s = str(v).strip()
                    if s:
                        ips.add(s)
        return sorted(ips)
    except KeyboardInterrupt:
        raise
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  dnsx timeout")
        return []
    except subprocess.CalledProcessError as error:
        out_path.write_text(error.stdout or "", encoding="utf-8")
        print(f"⚠️  dnsx ошибка (код {error.returncode})")
        return []


def run_smap_hosts(hosts: list[str], out_path: Path) -> tuple[list[str], set[int]]:
    smap_bin = shutil.which("smap")
    if not smap_bin:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  smap не найден, пропускаю dnsx IP scan")
        return [], set()
    unique_hosts = sorted(set(hosts))
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("\n".join(unique_hosts))
        tmp.flush()
        tmp_name = tmp.name
    try:
        proc = subprocess.run(
            [smap_bin, "-iL", tmp_name, "-oJ", "-"],
            text=True,
            capture_output=True,
            check=True,
            timeout=300,
        )
        out_path.write_text(proc.stdout, encoding="utf-8")
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        ports: set[int] = set()
        host_port_lines: set[str] = set()
        ports_count = 0
        try:
            data = json.loads(proc.stdout)
            if isinstance(data, list):
                for item in data:
                    ports_list = item.get("ports") or []
                    if isinstance(ports_list, list):
                        ports_count += len(ports_list)
                        for entry in ports_list:
                            try:
                                num = int(entry.get("port"))
                            except Exception:
                                continue
                            state = entry.get("state")
                            if state and state.lower() != "open":
                                continue
                            if 0 < num < 65536:
                                ports.add(num)
                                host = item.get("user_hostname") or item.get("ip") or item.get("host") or item.get("name")
                                if host:
                                    host_port_lines.add(f"{host}:{num}")
        except json.JSONDecodeError:
            pass
        hosts_set = {line.split(":", 1)[0] for line in host_port_lines}
        cve_hits = count_cves(lines)
        print(f"smap: hosts={len(hosts_set)}, ports={len(ports)}, units={ports_count}, cve={cve_hits}")
        return sorted(host_port_lines), ports
    except KeyboardInterrupt:
        raise
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  smap timeout (hosts)")
        return [], set()
    except subprocess.CalledProcessError as error:
        out_path.write_text(error.stdout or "", encoding="utf-8")
        print(f"⚠️  smap ошибка (код {error.returncode})")
        return [], set()
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def run_naabu_hosts(hosts: list[str], out_path: Path, aggressive: bool = False) -> tuple[list[str], set[int]]:
    naabu_bin = shutil.which("naabu")
    if not naabu_bin:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  naabu не найден, пропускаю")
        return [], set()
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("\n".join(hosts))
        tmp.flush()
        tmp_name = tmp.name
    try:
        if aggressive:
            cmd = [naabu_bin, "-list", tmp_name, "-p", "-", "-no-color", "-silent"]
        else:
            cmd = [naabu_bin, "-list", tmp_name, "-top-ports", "1000", "-no-color", "-silent"]
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=True,
            timeout=420,
        )
        out_path.write_text(proc.stdout, encoding="utf-8")
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        ports = parse_naabu_ports(lines)
        hosts_count = len(unique_naabu_hosts(lines))
        print(f"naabu: hosts={hosts_count}, lines={len(lines)}, ports={len(ports)}")
        return lines, ports
    except KeyboardInterrupt:
        raise
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        print("⚠️  naabu timeout (hosts)")
        return [], set()
    except subprocess.CalledProcessError as error:
        out_path.write_text(error.stdout or "", encoding="utf-8")
        print(f"⚠️  naabu ошибка (код {error.returncode})")
        return [], set()
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def run_nmap_hosts(hosts: list[str], ports: set[int], out_path: Path, aggression: int, debug: bool = False) -> None:
    nmap_bin = shutil.which("nmap")
    base_path = out_path.with_suffix("") if out_path.suffix else out_path
    txt_path = base_path.with_suffix(".txt")
    if not nmap_bin:
        txt_path.write_text("", encoding="utf-8")
        print("⚠️  nmap не найден, пропускаю")
        return
    if not ports or not hosts:
        txt_path.write_text("", encoding="utf-8")
        print("nmap: нет портов/хостов для сканирования")
        return
    ports_str = ",".join(str(p) for p in sorted(ports))

    ipv4_hosts: list[str] = []
    ipv6_hosts: list[str] = []
    for h in hosts:
        try:
            ip_obj = ipaddress.ip_address(h)
            if ip_obj.version == 6:
                ipv6_hosts.append(h)
            else:
                ipv4_hosts.append(h)
        except ValueError:
            ipv4_hosts.append(h)

    def run_group(group_hosts: list[str], use_ipv6: bool, suffix: str) -> None:
        if not group_hosts:
            return
        prefix = base_path.with_stem(base_path.stem + suffix)
        group_txt_path = prefix.with_suffix(".txt")
        log_path = prefix.with_suffix(".log")
        if debug:
            print(
                f"[debug] nmap start (hosts{' v6' if use_ipv6 else ''}): "
                f"list={len(group_hosts)}, ports={len(ports)}, prefix={prefix}"
            )
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("\n".join(group_hosts))
            tmp.flush()
            tmp_name = tmp.name
        flags = ["-6"] if use_ipv6 else []
        if aggression == 3:
            nmap_opts = [
                "-Pn",
                "-sS",
                "-A",
                "-T4",
                "--script",
                "vuln,discovery,safe",
                "--max-retries",
                "2",
                "--host-timeout",
                "180s",
            ]
            attempts = 2
        else:
            nmap_opts = [
                "-Pn",
                "-n",
                "-sS",
                "-sV",
                "--version-light",
                "-T3",
                "--open",
                "--max-retries",
                "2",
                "--host-timeout",
                "90s",
            ]
            attempts = 1

        def _as_text(data: str | bytes | None) -> str:
            if isinstance(data, (bytes, bytearray)):
                return data.decode("utf-8", errors="replace")
            return data or ""

        try:
            cmd = [
                nmap_bin,
                *flags,
                *nmap_opts,
                "-p",
                ports_str,
                "-iL",
                tmp_name,
                "-oA",
                str(prefix),
            ]

            combined = ""
            for attempt in range(1, attempts + 1):
                try:
                    attempt_start = time.monotonic()
                    if debug:
                        print(f"[debug] nmap attempt {attempt}/{attempts} (hosts{' v6' if use_ipv6 else ''})")
                        print(f"[debug] cmd: {' '.join(cmd)}")
                    proc = subprocess.run(
                        cmd,
                        text=True,
                        capture_output=True,
                        check=True,
                    )
                    combined = _as_text(proc.stdout) + _as_text(proc.stderr)
                    if debug:
                        elapsed = time.monotonic() - attempt_start
                        print(
                            f"[debug] nmap success (hosts{' v6' if use_ipv6 else ''}) "
                            f"attempt {attempt}/{attempts}, elapsed={elapsed:.1f}s, "
                            f"lines={len(combined.splitlines())}"
                        )
                    break
                except subprocess.TimeoutExpired as error:
                    elapsed = time.monotonic() - attempt_start
                    combined = _as_text(error.stdout) + _as_text(error.stderr)
                    log_path.write_text(combined, encoding="utf-8")
                    print(
                        f"⚠️  nmap timeout (hosts{' v6' if use_ipv6 else ''}) "
                        f"attempt {attempt}/{attempts}: list={len(group_hosts)}, "
                        f"ports_scanned={len(ports)}, elapsed={elapsed:.1f}s"
                    )
                    if attempt == attempts:
                        group_txt_path.write_text("", encoding="utf-8")
                        prefix.with_suffix(".xml").write_text("", encoding="utf-8")
                        prefix.with_suffix(".gnmap").write_text("", encoding="utf-8")
                        return
                    continue
        except KeyboardInterrupt:
            raise
        except subprocess.CalledProcessError as error:
            combined = _as_text(error.stdout) + _as_text(error.stderr)
            log_path.write_text(combined, encoding="utf-8")
        finally:
            Path(tmp_name).unlink(missing_ok=True)

        lines = [ln for ln in combined.splitlines() if ln.strip()]
        group_txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if log_path.exists():
            log_path.unlink(missing_ok=True)
        cve_hits = count_cves(lines)
        if aggression >= 3:
            print(
                f"nmap (hosts{' v6' if use_ipv6 else ''}): list={len(group_hosts)}, "
                f"ports_scanned={len(ports)}, cve={cve_hits}"
            )
        else:
            print(
                f"nmap (hosts{' v6' if use_ipv6 else ''}): list={len(group_hosts)}, "
                f"ports_scanned={len(ports)}"
            )

    run_group(ipv4_hosts, use_ipv6=False, suffix="")
    run_group(ipv6_hosts, use_ipv6=True, suffix="_v6")
