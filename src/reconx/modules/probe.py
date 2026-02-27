from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List, Set
import ipaddress

from reconx.modules.base import Module
from reconx.modules.enum_parts.providers import load_projectdiscovery_api_key
from reconx.modules.enum_parts.vulnx import run_vulnx_scan
from reconx.utils.targets import Target
from reconx.utils.process import raise_on_interrupt_returncode


class ProbeModule(Module):
    """Сканирование IP-целей с уровнями агрессии."""

    name = "probe"
    description = "Порт-сканирование IP (smap/naabu + nmap)."

    def __init__(
        self,
        workspace_root: Path,
        aggression: int = 1,
        nuclei_profile: str | None = None,
        single_mode: bool = False,
        debug: bool = False,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.aggression = aggression
        self.smap_bin = shutil.which("smap")
        self.naabu_bin = shutil.which("naabu")
        self.nmap_bin = shutil.which("nmap")
        self.vulnx_bin = shutil.which("vulnx")
        self.nuclei_profile = nuclei_profile
        self.single_mode = single_mode
        self.debug = debug

    def run(self, targets: Iterable[Target]) -> Path:
        for target in targets:
            if target.kind != "ip":
                continue
            self._process_ip(target)
        return self.workspace_root

    # --- internal ---

    def _process_ip(self, target: Target) -> None:
        ip = target.raw
        target_dir = self.workspace_root if self.single_mode else self._unique_target_dir(target.folder_name)
        if self.debug:
            print(f"[debug] probe start: ip={ip}, aggression={self.aggression}, target_dir={target_dir}")
        projectdiscovery_api_key = load_projectdiscovery_api_key()
        raw_scan = target_dir / "raw" / "scan"
        raw_web = target_dir / "raw" / "web"
        processed_dir = target_dir / "processed"
        raw_scan.mkdir(parents=True, exist_ok=True)
        raw_web.mkdir(parents=True, exist_ok=True)
        processed_dir.mkdir(parents=True, exist_ok=True)

        smap_path = raw_scan / "smap.json"
        naabu_path = raw_scan / "naabu.txt"
        nmap_path = raw_scan / "nmap"
        open_ports_path = processed_dir / "open-ports.txt"
        httpx_path = raw_web / "httpx.json"
        alive_urls_path = processed_dir / "alive-urls.txt"
        alive_path = processed_dir / "alive.txt"
        nuclei_web_path = raw_web / "nuclei-web.json"
        nuclei_net_path = raw_scan / "nuclei-net.json"

        cve_count = 0
        smap_ports: Set[int] = set()
        ports: Set[int] = set()

        # alive.txt (вход для httpx)
        alive_path.write_text(f"{ip}\n", encoding="utf-8")

        # Всегда запускаем smap сначала, чтобы получить хосты/порты и CVE
        smap_ports, cve_smap = self._run_smap(ip, smap_path)
        cve_count += cve_smap

        if self.aggression == 1:
            ports = smap_ports
        elif self.aggression == 2:
            naabu_ports = self._run_naabu(ip, naabu_path, top_ports=True)
            ports = smap_ports | naabu_ports
            if ports:
                cve_nmap = self._run_nmap(ip, ports, nmap_path, "-T3")
                cve_count += cve_nmap
        else:
            naabu_ports = self._run_naabu(ip, naabu_path, top_ports=False)
            ports = smap_ports | naabu_ports
            if ports:
                cve_nmap = self._run_nmap(ip, ports, nmap_path, "-T5")
                cve_count += cve_nmap

        # сохраняем открытые порты (ip:port)
        sorted_ports = sorted(ports)
        lines = [f"{ip}:{p}" for p in sorted_ports]
        open_ports_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if self.aggression == 3:
            print(f"cve: {cve_count}")

        run_vulnx_scan(raw_scan, self.vulnx_bin, projectdiscovery_api_key=projectdiscovery_api_key)

        # httpx: host:port (если есть open-ports), иначе alive.txt
        httpx_input = [ln.strip() for ln in open_ports_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not httpx_input:
            httpx_input = [ln.strip() for ln in alive_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        self._run_httpx(httpx_input, httpx_path, alive_urls_path)

        if self.nuclei_profile:
            web_input = [
                ln.strip() for ln in alive_urls_path.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            if web_input:
                self._run_nuclei(web_input, nuclei_web_path, self.nuclei_profile, mode="web")
            else:
                nuclei_web_path.write_text("", encoding="utf-8")
            net_input = [ln.strip() for ln in open_ports_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if net_input:
                self._run_nuclei(net_input, nuclei_net_path, self.nuclei_profile, mode="net")
            else:
                nuclei_net_path.write_text("", encoding="utf-8")

    def _unique_target_dir(self, folder_name: str) -> Path:
        # Переиспользуем существующую папку, не создаём суффиксы
        return self.workspace_root / folder_name

    def _run_cmd(self, cmd: str, timeout: int) -> List[str]:
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=timeout, stderr=subprocess.DEVNULL)
            return [line.strip() for line in out.splitlines() if line.strip()]
        except subprocess.CalledProcessError as error:
            raise_on_interrupt_returncode(error.returncode)
            return []
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _parse_ports(self, lines: Iterable[str]) -> Set[int]:
        ports: Set[int] = set()
        pattern = re.compile(r"(\d{1,5})/open")
        for line in lines:
            if "Ports:" not in line:
                continue
            _, _, rest = line.partition("Ports:")
            for entry in rest.split(","):
                match = pattern.search(entry)
                if not match:
                    continue
                num = int(match.group(1))
                if 0 < num < 65536:
                    ports.add(num)
        return ports

    def _parse_smap_json(self, lines: Iterable[str]) -> tuple[Set[int], int]:
        ports: Set[int] = set()
        ports_count = 0
        if not lines:
            return ports, ports_count
        text = "\n".join(lines)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ports, ports_count
        # Ожидаем структуру {"targets":[{"ports":[...]}]} или список хостов
        hosts = []
        if isinstance(data, dict) and "targets" in data:
            hosts = data.get("targets", [])
        elif isinstance(data, list):
            hosts = data
        else:
            hosts = [data]
        for host in hosts:
            entries = host.get("ports", []) if isinstance(host, dict) else []
            for entry in entries:
                try:
                    num = int(entry.get("port"))
                except Exception:
                    continue
                state = entry.get("state")
                if state and state.lower() != "open":
                    continue
                if 0 < num < 65536:
                    ports.add(num)
                    ports_count += 1
        return ports, ports_count

    def _run_smap(self, ip: str, out_path: Path) -> tuple[Set[int], int]:
        if not self.smap_bin:
            print("⚠️  smap не найден, пропускаю (aggression=1)")
            out_path.write_text("", encoding="utf-8")
            return set(), 0
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write(ip + "\n")
            tmp.flush()
            tmp_name = tmp.name
        try:
            cmd = f"{self.smap_bin} -iL {tmp_name} -oJ -"
            lines = self._run_cmd(cmd, timeout=180)
            # Сохраняем оригинальный вывод smap как есть
            out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            ports, ports_count = self._parse_smap_json(lines)
            if not ports:
                # фолбэк к Grepable, если JSON не распарсился
                ports = self._parse_ports(lines)
                ports_count = len(ports)
            cve_hits = self._count_cves(lines)
            host_count = self._count_hosts_smap(lines)
            print(f"smap: hosts={host_count}, ports={len(ports)}, units={ports_count}, cve={cve_hits}")
            return ports, cve_hits
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def _count_hosts_smap(self, lines: Iterable[str]) -> int:
        if not lines:
            return 0
        try:
            data = json.loads("\n".join(lines))
            if isinstance(data, list):
                return len(data)
            return 1
        except json.JSONDecodeError:
            return len(list(lines))

    def _run_naabu(self, ip: str, out_path: Path, top_ports: bool) -> Set[int]:
        if not self.naabu_bin:
            print("⚠️  naabu не найден, пропускаю")
            out_path.write_text("", encoding="utf-8")
            return set()
        mode = "-top-ports 1000" if top_ports else "-p -"
        cmd = f"{self.naabu_bin} -host {ip} {mode} -no-color -silent"
        lines = self._run_cmd(cmd, timeout=300 if top_ports else 420)
        out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        ports = self._parse_naabu_ports(lines)
        hosts_count = len(lines)
        print(f"naabu: hosts={hosts_count}, lines={len(lines)}, ports={len(ports)} ({'top1000' if top_ports else 'all'})")
        return ports

    def _run_nmap(self, ip: str, ports: Set[int], out_path: Path, speed_flag: str) -> int:
        base_path = out_path.with_suffix("") if out_path.suffix else out_path
        txt_path = out_path if out_path.suffix else out_path.with_suffix(".txt")
        if not self.nmap_bin:
            print("⚠️  nmap не найден, пропускаю")
            txt_path.write_text("", encoding="utf-8")
            return 0
        if not ports:
            txt_path.write_text("", encoding="utf-8")
            print("nmap: нет портов для сканирования")
            return 0
        ports_str = ",".join(str(p) for p in sorted(ports))
        flags = []
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 6:
                flags.append("-6")
        except ValueError:
            pass
        if speed_flag == "-T3":
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
            report_services = True
        else:
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
            report_services = False

        cmd = [self.nmap_bin] + flags + nmap_opts + ["-p", ports_str, ip]
        try:
            proc = subprocess.run(
                cmd + ["-oA", str(base_path)],
                text=True,
                capture_output=True,
                check=True,
            )
            combined = (proc.stdout or "") + (proc.stderr or "")
        except KeyboardInterrupt:
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
            raise
        except subprocess.TimeoutExpired:
            txt_path.write_text("", encoding="utf-8")
            base_path.with_suffix(".xml").write_text("", encoding="utf-8")
            base_path.with_suffix(".gnmap").write_text("", encoding="utf-8")
            print("⚠️  nmap timeout (ip)")
            return 0
        except subprocess.CalledProcessError as error:
            raise_on_interrupt_returncode(error.returncode)
            combined = (error.stdout or "") + (error.stderr or "")
        lines = [ln for ln in combined.splitlines() if ln.strip()]
        # Сохраняем текстовый вывод
        txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

        cve_hits = self._count_cves(lines)
        if report_services:
            services = []
            gnmap_path = base_path.with_suffix(".gnmap")
            try:
                txt = gnmap_path.read_text(encoding="utf-8")
                for ln in txt.splitlines():
                    if "Ports:" not in ln:
                        continue
                    _, _, rest = ln.partition("Ports:")
                    for entry in rest.split(","):
                        entry = entry.strip()
                        # формат: 80/open/tcp//http///
                        parts = entry.split("/")
                        if len(parts) >= 5 and parts[1] == "open":
                            port = parts[0]
                            svc = parts[4] or "unknown"
                            services.append(f"{port}/{svc}")
            except Exception:
                pass
            uniq_services = ", ".join(sorted(set(services))) if services else "none"
            print(f"nmap: services={uniq_services}")
            return 0
        else:
            print(f"nmap: lines={len(lines)}, cve={cve_hits}")
            return cve_hits

    def _count_cves(self, lines: Iterable[str]) -> int:
        pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        count = 0
        for line in lines:
            count += len(pattern.findall(line))
        return count

    def _run_httpx(self, targets: list[str], out_path: Path, alive_urls_path: Path) -> None:
        if not targets:
            out_path.write_text("", encoding="utf-8")
            alive_urls_path.write_text("", encoding="utf-8")
            return
        preferred = Path.home() / ".cache" / "reconx" / "bin" / "httpx"
        httpx_bin = str(preferred) if preferred.exists() else None
        if not httpx_bin:
            out_path.write_text("", encoding="utf-8")
            alive_urls_path.write_text("", encoding="utf-8")
            print("⚠️  httpx не найден (ожидаю ~/.cache/reconx/bin/httpx), пропускаю")
            return
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("\n".join(targets))
            tmp.flush()
            tmp_name = tmp.name
        try:
            proc = subprocess.run(
                [
                    httpx_bin,
                    "-silent",
                    "-j",
                    "-no-color",
                    "-retries",
                    "1",
                    "-timeout",
                    "10",
                    "-threads",
                    "50",
                    "-l",
                    tmp_name,
                ],
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
                first_line = combined.splitlines()[0] if combined else ""
                print(f"⚠️  httpx ошибка (код {proc.returncode}) {first_line}")
                return

            out_path.write_text(proc.stdout, encoding="utf-8")
            urls: list[str] = []
            techs: set[str] = set()
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url")
                    if url:
                        urls.append(url)
                    tech_list = data.get("tech") or data.get("technologies") or data.get("techs")
                    if isinstance(tech_list, list):
                        techs.update([str(t) for t in tech_list if t])
                except json.JSONDecodeError:
                    continue
            urls_sorted = sorted(set(urls))
            alive_urls_path.write_text("\n".join(urls_sorted) + ("\n" if urls_sorted else ""), encoding="utf-8")
            tech_part = f" tech={', '.join(sorted(techs))}" if techs else ""
            print(f"httpx: {len(urls_sorted)}{tech_part}")
        except KeyboardInterrupt:
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
            raise
        except subprocess.TimeoutExpired:
            out_path.write_text("", encoding="utf-8")
            alive_urls_path.write_text("", encoding="utf-8")
            print("⚠️  httpx timeout")
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def _run_nuclei(self, targets: list[str], out_path: Path, profile: str | None, mode: str = "web") -> None:
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
                "tags": "network,cves,exposure",
                "timeout": "20",
                "concurrency": "80",
            },
        }
        cfg = (profiles_web if mode == "web" else profiles_net).get(profile or "fast", profiles_web["fast"])
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
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
            raise
        except subprocess.TimeoutExpired:
            out_path.write_text("", encoding="utf-8")
            print("⚠️  nuclei timeout")
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def _parse_naabu_ports(self, lines: Iterable[str]) -> Set[int]:
        """
        Парсер вывода naabu (host:port[/state]).
        Поддерживает IPv4/IPv6, берём число после последнего ':'.
        """
        ports: Set[int] = set()
        for line in lines:
            line = line.strip()
            if not line or ":" not in line:
                continue
            last = line.rsplit(":", 1)[-1]
            port_str = last.split("/")[0].split()[0]
            try:
                port = int(port_str)
                if 0 < port < 65536:
                    ports.add(port)
            except ValueError:
                continue
        return ports
