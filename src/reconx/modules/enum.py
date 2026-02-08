from __future__ import annotations

import json
import ipaddress
import os
import shutil
import subprocess
import tempfile
import re
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from reconx.modules.base import Module
from reconx.utils.targets import Target
from reconx.utils.data import get_data_dir, WORDLIST_NAME


class EnumModule(Module):
    """Сбор субдоменов для доменных целей на базе subfinder + shuffledns."""

    name = "enum"
    description = "Сбор и резолв субдоменов для доменных целей."

    def __init__(
        self,
        workspace_root: Path,
        resolvers: str | None = None,
        wordlist: str | None = None,
        aggression: int = 1,
        nuclei_profile: str | None = None,
        single_mode: bool = False,
        debug: bool = False,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        data_dir = get_data_dir()
        self.resolvers = str(Path(resolvers) if resolvers else data_dir / "resolvers.txt")
        default_wordlist = data_dir / "wordlists" / WORDLIST_NAME
        self.wordlist = str(Path(wordlist) if wordlist else default_wordlist)
        self.shuffledns_bin = shutil.which("shuffledns")
        self.massdns_bin = shutil.which("massdns")
        self.aggression = aggression
        self.nuclei_profile = nuclei_profile
        self.single_mode = single_mode
        self.debug = debug

    def run(self, targets: Iterable[Target]) -> Path:
        for target in targets:
            if target.kind != "domain":
                continue
            self._process_domain(target)
        return self.workspace_root

    # --- внутренние методы ---

    def _process_domain(self, target: Target) -> None:
        domain = target.raw
        target_dir = self.workspace_root if self.single_mode else self.workspace_root / target.folder_name
        if self.debug:
            print(f"[debug] enum start: domain={domain}, aggression={self.aggression}, target_dir={target_dir}")
        raw_dir = target_dir / "raw" / "enum"
        raw_scan_dir = target_dir / "raw" / "scan"
        raw_web_dir = target_dir / "raw" / "web"
        raw_urls_dir = target_dir / "raw" / "urls"
        raw_humans_dir = target_dir / "raw" / "humans"
        raw_breach_dir = target_dir / "raw" / "breach"
        processed_dir = target_dir / "processed"
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw_scan_dir.mkdir(parents=True, exist_ok=True)
        raw_web_dir.mkdir(parents=True, exist_ok=True)
        raw_urls_dir.mkdir(parents=True, exist_ok=True)
        raw_humans_dir.mkdir(parents=True, exist_ok=True)
        raw_breach_dir.mkdir(parents=True, exist_ok=True)
        processed_dir.mkdir(parents=True, exist_ok=True)

        subfinder_path = raw_dir / "subfinder.txt"
        resolve_path = raw_dir / "resolved.txt"
        bruteforce_path = raw_dir / "bruteforce.txt"
        gau_path = raw_urls_dir / "gau.txt"
        gau_clean_path = raw_urls_dir / "gau-clean.txt"
        gau_core_path = raw_urls_dir / "gau-core.txt"
        gau_subs_path = raw_urls_dir / "gau-subs.txt"
        paramspider_path = raw_urls_dir / "paramspider.txt"
        hunter_path = raw_humans_dir / "hunter.json"
        snusbase_path = raw_breach_dir / "snusbase.json"
        dnsx_path = raw_scan_dir / "dnsx.json"
        smap_dnsx_path = raw_scan_dir / "smap.json"
        naabu_path = raw_scan_dir / "naabu.txt"
        nmap_path = raw_scan_dir / "nmap"
        alive_path = processed_dir / "alive.txt"
        open_ports_path = processed_dir / "open-ports.txt"
        httpx_path = raw_web_dir / "httpx.json"
        headers_path = raw_web_dir / "headers.txt"
        alive_urls_path = processed_dir / "alive-urls.txt"
        alive_urls_unic_path = processed_dir / "alive-urls-unic.txt"
        nuclei_web_path = raw_web_dir / "nuclei-web.json"
        nuclei_net_path = raw_scan_dir / "nuclei-net.json"

        # Запускаем snusbase, hunter.io и gau перед subfinder; paramspider формируем из gau
        self._run_snusbase(domain, snusbase_path)
        self._run_hunter(domain, hunter_path)
        self._run_gau(domain, gau_path, gau_clean_path, gau_core_path, gau_subs_path)
        self._derive_paramspider_from_gau(gau_path, paramspider_path)

        subfinder_lines = self._run_cmd(
            f"subfinder -d {domain} -silent",
            timeout=180,
            context=domain,
        )
        subfinder_path.write_text("\n".join(subfinder_lines) + ("\n" if subfinder_lines else ""), encoding="utf-8")
        print(f"subfinder: {len(subfinder_lines)}")

        passive = set(subfinder_lines)

        if not self.shuffledns_bin or not self.massdns_bin:
            print("⚠️  shuffledns/massdns не найдены, пропускаю bruteforce/resolve")
            combined = passive
            resolved = sorted(combined)
        else:
            wildcard = self._has_wildcard(domain)
            print(f"wildcard: {'yes' if wildcard else 'no'}")
            if wildcard:
                combined = passive
            else:
                brute = self._shuffledns_bruteforce(domain)
                bruteforce_path.write_text("\n".join(brute) + ("\n" if brute else ""), encoding="utf-8")
                print(f"shuffledns bruteforce: {len(brute)}")
                combined = passive | set(brute)

            resolved = self._resolve_with_shuffledns(combined, wildcard, resolve_path)
            print(f"resolved: {len(resolved)}")

        dnsx_input = resolved + [domain]
        dnsx_ips = self._run_dnsx(dnsx_input, dnsx_path)
        host_list = sorted(set(resolved + [domain] + dnsx_ips))
        alive_path.write_text("\n".join(host_list) + ("\n" if host_list else ""), encoding="utf-8")

        if host_list:
            smap_lines, smap_ports = self._run_smap_hosts(host_list, smap_dnsx_path)
            merged_ports = set(smap_ports)
            if self.aggression == 1:
                open_lines = sorted({ln.strip() for ln in smap_lines if ln.strip()})
                open_ports_path.write_text("\n".join(open_lines) + ("\n" if open_lines else ""), encoding="utf-8")
            else:
                naabu_lines, naabu_ports = self._run_naabu_hosts(host_list, naabu_path, aggressive=self.aggression == 3)
                merged_ports |= naabu_ports
                # если naabu пуст, сохраняем то, что дал smap
                if naabu_lines:
                    open_lines = sorted({ln.strip() for ln in naabu_lines if ln.strip()})
                else:
                    open_lines = sorted({ln.strip() for ln in smap_lines if ln.strip()})
                open_ports_path.write_text("\n".join(open_lines) + ("\n" if open_lines else ""), encoding="utf-8")
                if merged_ports:
                    self._run_nmap_hosts(host_list, merged_ports, nmap_path)

        (processed_dir / "subdomains.txt").write_text("\n".join(resolved) + ("\n" if resolved else ""), encoding="utf-8")

        # HTTPX stage: host:port из open-ports + домены из alive с портами 80/443 (чтобы в alive-urls были URL с доменами)
        httpx_input_lines = [ln.strip() for ln in open_ports_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not httpx_input_lines:
            httpx_input_lines = [ln.strip() for ln in alive_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        alive_hosts = [ln.strip() for ln in alive_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        seen = {ln for ln in httpx_input_lines}
        for host in alive_hosts:
            if not host:
                continue
            try:
                ipaddress.ip_address(host)
            except ValueError:
                for port in (80, 443):
                    entry = f"{host}:{port}"
                    if entry not in seen:
                        seen.add(entry)
                        httpx_input_lines.append(entry)
        httpx_input = httpx_input_lines
        self._run_httpx(httpx_input, httpx_path, alive_urls_path, alive_urls_unic_path, headers_path)

        # nuclei (optional) web + net
        # web: alive-urls-unic.txt (по одному URL на длину ответа — быстрее, меньше дублей) или alive-urls.txt
        if self.nuclei_profile:
            unic_path = processed_dir / "alive-urls-unic.txt"
            if unic_path.exists():
                web_input = [ln.strip() for ln in unic_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            else:
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

    def _run_cmd(self, cmd: str, timeout: int, context: str) -> list[str]:
        try:
            out = subprocess.check_output(cmd, shell=True, text=True, timeout=timeout, stderr=subprocess.DEVNULL)
            return [line.strip() for line in out.splitlines() if line.strip()]
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            return []

    def _has_wildcard(self, domain: str) -> bool:
        if not self.shuffledns_bin or not self.massdns_bin:
            return False
        test_labels = [f"zz{os.getpid()}", f"xx{os.getpid()+1}"]
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            for lbl in test_labels:
                tmp.write(f"{lbl}.{domain}\n")
            tmp.flush()
            tmp_name = tmp.name
        try:
            meta = self._run_cmd(
                f"shuffledns -list {tmp_name} -r {self.resolvers} -silent -mode resolve -retries 1 -t 100",
                timeout=15,
                context=domain,
            )
            return len(meta) >= 2
        finally:
            os.remove(tmp_name)

    def _run_hunter(self, domain: str, out_path: Path) -> None:
        """Запуск hunter.io API для поиска email адресов."""
        # Перезагружаем конфигурацию на случай, если она была изменена
        api_key = os.getenv("HUNTER_API_KEY")
        
        if not api_key:
            try:
                import yaml
                # Используем только стандартное место для совместимости с pipx
                config_file = Path.home() / ".config" / "reconx" / "provider-config.yaml"
                if config_file.exists():
                    try:
                        with open(config_file, "r", encoding="utf-8") as f:
                            config = yaml.safe_load(f) or {}
                            if "hunter_io" in config and config["hunter_io"]:
                                api_key = config["hunter_io"][0] if isinstance(config["hunter_io"], list) else config["hunter_io"]
                                os.environ["HUNTER_API_KEY"] = str(api_key)
                    except Exception:
                        pass
            except ImportError:
                # PyYAML не установлен
                pass
            except Exception:
                # Игнорируем другие ошибки
                pass
        
        if not api_key:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  HUNTER_API_KEY не установлен, пропускаю")
            return
        
        try:
            import requests
            use_requests = True
        except ImportError:
            use_requests = False
            import urllib.request
            import urllib.error

        try:
            import urllib.parse

            def build_url(offset: int | None = None, limit: int | None = None) -> str:
                params = {
                    "domain": domain,
                    "api_key": api_key,
                }
                if offset is not None:
                    params["offset"] = str(offset)
                if limit is not None:
                    params["limit"] = str(limit)
                return f"https://api.hunter.io/v2/domain-search?{urllib.parse.urlencode(params)}"

            def fetch_page(offset: int | None = None, limit: int | None = None) -> dict | None:
                url = build_url(offset, limit)
                retry_statuses = {429, 500, 502, 503, 504}
                attempts = 3
                for attempt in range(1, attempts + 1):
                    if use_requests:
                        response = requests.get(url, timeout=30)
                        if response.status_code == 200:
                            return response.json()
                        if response.status_code in retry_statuses and attempt < attempts:
                            time.sleep(2)
                            continue
                        suppress_log = False
                        error_preview = ""
                        try:
                            error_json = response.json()
                            error_preview = error_json
                            if response.status_code == 400:
                                errors = error_json.get("errors") if isinstance(error_json, dict) else None
                                if isinstance(errors, list) and any(
                                    isinstance(err, dict) and err.get("id") == "pagination_error" for err in errors
                                ):
                                    suppress_log = True
                        except Exception:
                            error_preview = (response.text or "")[:300]
                            if response.status_code == 400 and "pagination_error" in str(error_preview):
                                suppress_log = True
                        if not suppress_log:
                            print(f"⚠️  hunter.io HTTP ошибка {response.status_code}: {error_preview}")
                        return None
                    try:
                        req = urllib.request.Request(url)
                        with urllib.request.urlopen(req, timeout=30) as response:
                            return json.loads(response.read().decode("utf-8"))
                    except urllib.error.HTTPError as e:
                        if e.code in retry_statuses and attempt < attempts:
                            time.sleep(2)
                            continue
                        body = ""
                        try:
                            body = (e.read() or b"").decode("utf-8", errors="replace")
                        except Exception:
                            body = ""
                        error_preview = body[:300] if body else ""
                        suppress_log = e.code == 400 and "pagination_error" in error_preview
                        if not suppress_log:
                            print(f"⚠️  hunter.io HTTP ошибка {e.code}: {error_preview}")
                        return None
                    except Exception as e:
                        if attempt < attempts:
                            time.sleep(2)
                            continue
                        print(f"⚠️  hunter.io ошибка запроса: {e}")
                        return None
                return None

            def dedupe_emails(emails: list[dict]) -> list[dict]:
                seen: set[str] = set()
                unique: list[dict] = []
                for email in emails:
                    value = str(email.get("value") or "").strip().lower()
                    if not value or value in seen:
                        continue
                    seen.add(value)
                    unique.append(email)
                return unique

            limit = 100
            offset = 0
            all_emails: list[dict] = []
            base_data: dict | None = None
            meta: dict | None = None
            total_results: int | None = None
            page_limit: int | None = None
            page_count = 0
            max_pages = 20

            # Первая страница без pagination параметров (для планов с лимитом)
            data = fetch_page()
            if data is None:
                out_path.write_text("{}", encoding="utf-8")
                print("⚠️  hunter.io ошибка: нет данных")
                return

            base_data = data
            page_emails = []
            if isinstance(data, dict):
                page_emails = data.get("data", {}).get("emails") or []
                if not isinstance(page_emails, list):
                    page_emails = []
                if isinstance(data.get("meta"), dict):
                    meta = data.get("meta")
                    total_results = meta.get("results") if isinstance(meta.get("results"), int) else None
                    page_limit = meta.get("limit") if isinstance(meta.get("limit"), int) else None

            all_emails.extend(page_emails)

            # Если есть признаки, что можно пагинировать — пробуем, иначе остаёмся на первой странице
            if total_results is not None and page_limit is not None and total_results > page_limit:
                limit = page_limit if page_limit > 0 else limit
                offset = limit
                while True:
                    data = fetch_page(offset, limit)
                    if data is None:
                        break

                    page_emails = []
                    if isinstance(data, dict):
                        page_emails = data.get("data", {}).get("emails") or []
                        if not isinstance(page_emails, list):
                            page_emails = []

                    all_emails.extend(page_emails)

                    if not page_emails:
                        break

                    if total_results is not None and len(all_emails) >= total_results:
                        break

                    offset += limit
                    page_count += 1
                    if page_count >= max_pages:
                        break

            all_emails = dedupe_emails(all_emails)
            if base_data is None:
                out_path.write_text("{}", encoding="utf-8")
                print("⚠️  hunter.io ошибка")
                return

            base_data.setdefault("data", {})
            base_data["data"]["emails"] = all_emails
            if meta is None and isinstance(base_data.get("meta"), dict):
                meta = base_data.get("meta")
            if meta is None:
                meta = {}
            meta.setdefault("results", len(all_emails))
            meta["offset"] = 0
            meta["limit"] = len(all_emails)
            base_data["meta"] = meta

            # Сохраняем полный ответ в JSON
            out_path.write_text(json.dumps(base_data, indent=2, ensure_ascii=False), encoding="utf-8")

            email_count = len(all_emails)
            print(f"hunter.io: {email_count} email{'ов' if email_count != 1 else ''}")

        except KeyboardInterrupt:
            raise
        except Exception:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  hunter.io ошибка")

    def _run_snusbase(self, domain: str, out_path: Path) -> None:
        """Запуск Snusbase API для поиска утечек данных по домену."""
        api_key = os.getenv("SNUSBASE_API_KEY")

        if not api_key:
            try:
                import yaml
                config_file = Path.home() / ".config" / "reconx" / "provider-config.yaml"
                if config_file.exists():
                    try:
                        with open(config_file, "r", encoding="utf-8") as f:
                            config = yaml.safe_load(f) or {}
                            if "snusbase" in config and config["snusbase"]:
                                api_key = config["snusbase"][0] if isinstance(config["snusbase"], list) else config["snusbase"]
                                os.environ["SNUSBASE_API_KEY"] = str(api_key)
                    except Exception:
                        pass
            except ImportError:
                pass
            except Exception:
                pass

        if not api_key:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  SNUSBASE_API_KEY не установлен, пропускаю")
            return

        try:
            import requests
            use_requests = True
        except ImportError:
            use_requests = False
            import urllib.request
            import urllib.error

        try:
            url = "https://api.snusbase.com/data/search"
            headers = {
                "Content-Type": "application/json",
                "Auth": api_key
            }
            payload = {
                "terms": [domain],
                "types": ["_domain"]
            }

            if use_requests:
                import time
                max_retries = 3
                retry_delay = 2
                result = None
                
                for attempt in range(max_retries):
                    try:
                        response = requests.post(url, json=payload, headers=headers, timeout=45)
                        if response.status_code != 200:
                            if attempt < max_retries - 1:
                                time.sleep(retry_delay)
                                continue
                            out_path.write_text("{}", encoding="utf-8")
                            print("⚠️  snusbase HTTP ошибка")
                            return
                        result = response.json()
                        break
                    except requests.exceptions.Timeout:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase ошибка сети")
                        return
                    except requests.exceptions.ConnectionError:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase ошибка сети")
                        return
                    except requests.exceptions.RequestException:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase ошибка")
                        return
                
                if result is None:
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка")
                    return
            else:
                import time
                max_retries = 3
                retry_delay = 2
                result = None
                data = json.dumps(payload).encode("utf-8")

                for attempt in range(max_retries):
                    try:
                        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                        with urllib.request.urlopen(req, timeout=45) as response:
                            response_data = response.read()
                            response_text = response_data.decode("utf-8")
                            result = json.loads(response_text)
                            break
                    except urllib.error.HTTPError:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase HTTP ошибка")
                        return
                    except urllib.error.URLError:
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue
                        out_path.write_text("{}", encoding="utf-8")
                        print("⚠️  snusbase ошибка сети")
                        return
                
                if result is None:
                    out_path.write_text("{}", encoding="utf-8")
                    print("⚠️  snusbase ошибка")
                    return

            out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            total_size = result.get("size", 0)
            print(f"snusbase: {total_size}")

        except KeyboardInterrupt:
            raise
        except Exception:
            out_path.write_text("{}", encoding="utf-8")
            print("⚠️  snusbase ошибка")

    def _run_gau(
        self,
        domain: str,
        out_path: Path,
        gau_clean_path: Path | None = None,
        gau_core_path: Path | None = None,
        gau_subs_path: Path | None = None,
    ) -> None:
        """Запуск gau для сбора URL из архивов; gau-clean — отфильтрованный; gau-core — корень/www; gau-subs — поддомены."""
        preferred = Path.home() / ".cache" / "reconx" / "bin" / "gau"
        gau_bin = str(preferred) if preferred.exists() else None
        if not gau_bin:
            gau_bin = shutil.which("gau")
        if not gau_bin:
            out_path.write_text("", encoding="utf-8")
            for p in (gau_clean_path, gau_core_path, gau_subs_path):
                if p is not None:
                    p.write_text("", encoding="utf-8")
            print("⚠️  gau не найден, пропускаю")
            return
        # Только явная статика (картинки, шрифты, медиа); не исключаем xml/pdf, архивы (могут быть бэкапы)
        EXCLUDED_EXT = frozenset(
            {
                "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "bmp",
                "css", "js", "woff", "woff2", "ttf", "eot", "otf",
                "mp4", "mp3", "webm", "ogg", "wav", "avi",
            }
        )
        MAX_URL_LEN = 2048
        try:
            proc = subprocess.run(
                [gau_bin, "--subs", domain],
                text=True,
                capture_output=True,
                check=False,
                timeout=300,
            )
            urls = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            out_path.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
            print(f"gau: {len(urls)}")
            if gau_clean_path is not None and urls:
                seen: dict[tuple, str] = {}
                for raw in urls:
                    if len(raw) > MAX_URL_LEN:
                        continue
                    try:
                        parsed = urlparse(raw)
                        scheme = parsed.scheme or "https"
                        netloc = parsed.netloc or ""
                        path_raw = parsed.path or "/"
                        path_lower = path_raw.lower()
                        if "url(" in path_lower or "'" in path_raw or '"' in path_raw:
                            continue
                        ext = path_lower.rsplit(".", 1)[-1] if "." in path_lower.split("/")[-1] else ""
                        if ext in EXCLUDED_EXT:
                            continue
                        if ":" in netloc:
                            host_part, port_part = netloc.rsplit(":", 1)
                            if port_part == "80" and scheme == "http":
                                netloc = host_part
                            elif port_part == "443" and scheme == "https":
                                netloc = host_part
                        if netloc.lower().startswith("www."):
                            netloc = netloc[4:]
                        query = parsed.query
                        canonical = urlunparse((scheme, netloc, path_raw, "", query, ""))
                        signature = (scheme, netloc, path_raw, query)
                        if signature not in seen:
                            seen[signature] = canonical
                    except Exception:
                        continue
                clean = sorted(seen.values())
                gau_clean_path.parent.mkdir(parents=True, exist_ok=True)
                gau_clean_path.write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
                print(f"gau-clean: {len(clean)}({len(urls)})")
                domain_lower = domain.lower()
                core_list: list[str] = []
                subs_list: list[str] = []
                for (_scheme, netloc, _path, _query), canonical in seen.items():
                    if netloc.lower() == domain_lower:
                        core_list.append(canonical)
                    else:
                        subs_list.append(canonical)
                core_list.sort()
                subs_list.sort()
                if gau_core_path is not None:
                    gau_core_path.write_text("\n".join(core_list) + ("\n" if core_list else ""), encoding="utf-8")
                    print(f"gau-core: {len(core_list)}")
                if gau_subs_path is not None:
                    gau_subs_path.write_text("\n".join(subs_list) + ("\n" if subs_list else ""), encoding="utf-8")
                    print(f"gau-subs: {len(subs_list)}")
            elif gau_clean_path is not None:
                gau_clean_path.write_text("", encoding="utf-8")
                for p in (gau_core_path, gau_subs_path):
                    if p is not None:
                        p.write_text("", encoding="utf-8")
        except KeyboardInterrupt:
            raise
        except subprocess.TimeoutExpired:
            out_path.write_text("", encoding="utf-8")
            for p in (gau_clean_path, gau_core_path, gau_subs_path):
                if p is not None:
                    p.write_text("", encoding="utf-8")
            print("⚠️  gau timeout")
        except subprocess.CalledProcessError as error:
            out_path.write_text(error.stdout or "", encoding="utf-8")
            for p in (gau_clean_path, gau_core_path, gau_subs_path):
                if p is not None:
                    p.write_text("", encoding="utf-8")
            print(f"⚠️  gau ошибка (код {error.returncode})")
        except Exception as e:
            out_path.write_text("", encoding="utf-8")
            for p in (gau_clean_path, gau_core_path, gau_subs_path):
                if p is not None:
                    p.write_text("", encoding="utf-8")
            print(f"⚠️  gau ошибка: {e}")

    def _derive_paramspider_from_gau(self, gau_path: Path, paramspider_path: Path) -> None:
        """Формирует paramspider.txt из gau: только качественные URL с параметрами, в духе paramspider."""
        # Только явная статика (картинки, шрифты, медиа); не исключаем xml/pdf, архивы (могут быть бэкапы)
        EXCLUDED_EXT = frozenset(
            {
                "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "bmp",
                "css", "js", "woff", "woff2", "ttf", "eot", "otf",
                "mp4", "mp3", "webm", "ogg", "wav", "avi",
            }
        )
        # Параметры, обычно неинтересные для исследования (трекинг, аналитика)
        BORING_PARAMS = frozenset(
            {
                "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "utm_referrer",
                "fbclid", "gclid", "gclsrc", "ref", "_ga", "_gl", "_gac", "_gid",
                "mc_cid", "mc_eid", "_hsenc", "_hsmi", "hsCtaTracking",
                "msclkid", "dclid", "twclid", "li_fat_id",
                "_ref", "fb_action_ids", "fb_action_types", "fb_source",
                "campaign", "pk_campaign", "pk_kwd", "mc_eid", "mc_tc",
                "phoenix_error", "n_c", "nr_email_referer",
            }
        )
        MAX_URL_LEN = 2048

        def _is_boring_param(name: str) -> bool:
            n = name.lower()
            return n in BORING_PARAMS or n.startswith("utm_")

        if not gau_path.exists():
            paramspider_path.write_text("", encoding="utf-8")
            print("paramspider: 0 (gau.txt отсутствует)")
            return
        try:
            content = gau_path.read_text(encoding="utf-8")
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            seen: dict[tuple, str] = {}  # (scheme, netloc, path, param_names) -> canonical URL
            for raw in lines:
                if "?" not in raw or len(raw) > MAX_URL_LEN:
                    continue
                try:
                    parsed = urlparse(raw)
                    if not parsed.query:
                        continue
                    path_raw = parsed.path or "/"
                    path_lower = path_raw.lower()
                    # Отсекаем мусор из CSS/JS: url('...'), кавычки в path
                    if "url(" in path_lower or "'" in path_raw or '"' in path_raw:
                        continue
                    ext = path_lower.rsplit(".", 1)[-1] if "." in path_lower.split("/")[-1] else ""
                    if ext in EXCLUDED_EXT:
                        continue
                    params = parse_qs(parsed.query, keep_blank_values=False)
                    param_names = frozenset(k.lower() for k in params)
                    if not param_names:
                        continue
                    if all(_is_boring_param(p) for p in param_names):
                        continue
                    scheme = parsed.scheme or "https"
                    netloc = parsed.netloc or ""
                    # Нормализация порта по умолчанию для дедупа (не трогаем :8080 и т.п.)
                    if ":" in netloc:
                        host_part, port_part = netloc.rsplit(":", 1)
                        if port_part == "80" and scheme == "http":
                            netloc = host_part
                        elif port_part == "443" and scheme == "https":
                            netloc = host_part
                    # Схлопывание www / без www: для дедупа и вывода используем хост без префикса www.
                    if netloc.lower().startswith("www."):
                        netloc = netloc[4:]
                    # Канонический URL: схема + netloc + path + отсортированные параметры со значением FUZZ (дедуп по endpoint+params)
                    sorted_params = sorted(params.items(), key=lambda x: x[0].lower())
                    query_canon = urlencode(
                        [(k, "FUZZ") for k, _ in sorted_params],
                        doseq=False,
                    )
                    canonical = urlunparse((scheme, netloc, path_raw, "", query_canon, ""))
                    signature = (scheme, netloc, path_raw, param_names)
                    if signature not in seen:
                        seen[signature] = canonical
                except Exception:
                    continue
            result = sorted(seen.values())
            paramspider_path.parent.mkdir(parents=True, exist_ok=True)
            paramspider_path.write_text(
                "\n".join(result) + ("\n" if result else ""),
                encoding="utf-8",
            )
            with_params = sum(1 for l in lines if "?" in l)
            print(f"paramspider: {len(result)}({with_params})")
        except Exception as e:
            paramspider_path.write_text("", encoding="utf-8")
            print(f"⚠️  paramspider ошибка: {e}")

    def _run_dnsx(self, hosts: list[str], out_path: Path) -> list[str]:
        if not hosts:
            out_path.write_text("", encoding="utf-8")
            print("dnsx: 0 (нет хостов)")
            return []
        dnsx_bin = shutil.which("dnsx")
        if not dnsx_bin:
            out_path.write_text("", encoding="utf-8")
            print("⚠️  dnsx не найден, пропускаю")
            return []
        def run_dnsx(args: list[str]) -> tuple[list[str], str]:
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
            # первый проход с кастомными резолверами
            lines, stdout = run_dnsx(["-silent", "-r", self.resolvers, "-retry", "3", "-j"])
            # если пусто — делаем фолбэк на системные резолверы
            if not lines:
                print("dnsx: 0, пробую без -r (system resolvers)")
                lines, stdout = run_dnsx(["-silent", "-retry", "2", "-j"])

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
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
            raise
        except subprocess.TimeoutExpired:
            out_path.write_text("", encoding="utf-8")
            print("⚠️  dnsx timeout")
            return []
        except subprocess.CalledProcessError as error:
            out_path.write_text(error.stdout or "", encoding="utf-8")
            print(f"⚠️  dnsx ошибка (код {error.returncode})")
            return []

    def _run_smap_hosts(self, hosts: list[str], out_path: Path) -> tuple[list[str], set[int]]:
        smap_bin = shutil.which("smap")
        if not smap_bin:
            out_path.write_text("", encoding="utf-8")
            print("⚠️  smap не найден, пропускаю dnsx IP scan")
            return [], set()
        # Дедуплицируем хосты перед записью в файл для smap
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
                                    # предпочитаем user_hostname (исходный хост из нашего списка), иначе ip
                                    host = item.get("user_hostname") or item.get("ip") or item.get("host") or item.get("name")
                                    if host:
                                        host_port_lines.add(f"{host}:{num}")
            except json.JSONDecodeError:
                pass
            hosts_set = {line.split(":", 1)[0] for line in host_port_lines}
            cve_hits = self._count_cves(lines)
            print(f"smap: hosts={len(hosts_set)}, ports={len(ports)}, units={ports_count}, cve={cve_hits}")
            return sorted(host_port_lines), ports
        except KeyboardInterrupt:
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
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

    def _run_httpx(
        self,
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
            "-fr",  # follow redirects — заголовки и остальные поля от финального ответа
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
            by_content_length: dict[int | None, str] = {}  # одна ссылка на каждую уникальную длину ответа
            urls_by_length: dict[int | None, list[str]] = {}  # все URL по длине ответа (для alive-urls с комментариями)
            # Группировка заголовков по одинаковому набору: signature -> (urls[], normalized_headers_dict)
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
                    # Полный сбор заголовков из httpx (-irh): группировка по одинаковому набору заголовков
                    if url and headers_path is not None:
                        raw = (
                            data.get("header")
                            or data.get("response_header")
                            or data.get("response_headers")
                            or data.get("raw_header")
                        )
                        if isinstance(raw, dict) and raw:
                            # Нормализация ключей: Cache-Control -> cache_control
                            normalized = {
                                k.lower().replace("-", "_"): str(v) for k, v in raw.items()
                            }
                            sig = tuple(sorted(normalized.items()))
                            if sig not in header_groups:
                                header_groups[sig] = ([], normalized)
                            header_groups[sig][0].append(url)
                        elif isinstance(raw, str) and raw.strip():
                            # Сырая строка — одна группа на URL
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
            # headers.txt: группы с URL через запятую, заголовки в формате key: value (lowercase_underscore)
            header_chunks = []
            for urls_list, hdict in header_groups.values():
                urls_sorted = sorted(set(urls_list))
                header_chunks.append(
                    "=== " + ", ".join(urls_sorted) + " ===\n"
                    + "\n".join(f"{k}: {v}" for k, v in sorted(hdict.items()))
                )
            # alive-urls.txt: сортировка по длине ответа, комментарии # как разделители
            chunks: list[str] = []
            for cl_key in sorted(urls_by_length.keys(), key=lambda x: (x is None, x or 0)):
                urls_in_group = sorted(set(urls_by_length[cl_key]))
                label = str(cl_key) if cl_key is not None else "?"
                chunks.append(f"# {label}\n" + "\n".join(urls_in_group))
            alive_urls_path.write_text(
                "\n\n".join(chunks) + ("\n" if chunks else ""), encoding="utf-8"
            )
            if headers_path is not None:
                headers_path.write_text(
                    "\n\n".join(header_chunks) + ("\n" if header_chunks else ""), encoding="utf-8"
                )
            tech_part = f" tech={', '.join(sorted(techs))}" if techs else ""
            if alive_urls_unic_path is not None:
                unic_urls = sorted(by_content_length.values())
                alive_urls_unic_path.write_text(
                    "\n".join(unic_urls) + ("\n" if unic_urls else ""), encoding="utf-8"
                )
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
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
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

    def _run_nuclei(self, targets: list[str], out_path: Path, profile: str, mode: str = "web") -> None:
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

    def _run_naabu_hosts(self, hosts: list[str], out_path: Path, aggressive: bool = False) -> tuple[list[str], set[int]]:
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
            ports = self._parse_naabu_ports(lines)
            hosts_count = len(self._unique_naabu_hosts(lines))
            print(f"naabu: hosts={hosts_count}, lines={len(lines)}, ports={len(ports)}")
            return lines, ports
        except KeyboardInterrupt:
            # Пробрасываем KeyboardInterrupt наверх для корректной обработки
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

    def _run_nmap_hosts(self, hosts: list[str], ports: set[int], out_path: Path) -> None:
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
                # hostname — считаем как IPv4-запуск
                ipv4_hosts.append(h)

        def run_group(group_hosts: list[str], use_ipv6: bool, suffix: str) -> None:
            if not group_hosts:
                return
            prefix = base_path.with_stem(base_path.stem + suffix)
            txt_path = prefix.with_suffix(".txt")
            log_path = prefix.with_suffix(".log")
            if self.debug:
                print(
                    f"[debug] nmap start (hosts{' v6' if use_ipv6 else ''}): "
                    f"list={len(group_hosts)}, ports={len(ports)}, prefix={prefix}"
                )
            # готовим all.txt для этой группы
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
                tmp.write("\n".join(group_hosts))
                tmp.flush()
                tmp_name = tmp.name
            flags = ["-6"] if use_ipv6 else []
            if self.aggression == 3:
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
                attempts = 2  # одна повторная попытка при таймауте
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
                        if self.debug:
                            print(
                                f"[debug] nmap attempt {attempt}/{attempts} "
                                f"(hosts{' v6' if use_ipv6 else ''}) timeout={timeout}s"
                            )
                            print(f"[debug] cmd: {' '.join(cmd)}")
                        proc = subprocess.run(
                            cmd,
                            text=True,
                            capture_output=True,
                            check=True,
                        )
                        combined = _as_text(proc.stdout) + _as_text(proc.stderr)
                        if self.debug:
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
                        # сохраняем временный лог
                        log_path.write_text(combined, encoding="utf-8")
                        print(
                            f"⚠️  nmap timeout (hosts{' v6' if use_ipv6 else ''}) "
                            f"attempt {attempt}/{attempts}: list={len(group_hosts)}, "
                            f"ports_scanned={len(ports)}, elapsed={elapsed:.1f}s"
                        )
                        if attempt == attempts:
                            txt_path.write_text("", encoding="utf-8")
                            prefix.with_suffix(".xml").write_text("", encoding="utf-8")
                            prefix.with_suffix(".gnmap").write_text("", encoding="utf-8")
                            return
                        # повторная попытка
                        continue
            except KeyboardInterrupt:
                # Пробрасываем KeyboardInterrupt наверх для корректной обработки
                raise
            except subprocess.CalledProcessError as error:
                combined = _as_text(error.stdout) + _as_text(error.stderr)
                log_path.write_text(combined, encoding="utf-8")
            finally:
                Path(tmp_name).unlink(missing_ok=True)

            lines = [ln for ln in combined.splitlines() if ln.strip()]
            txt_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            if log_path.exists():
                log_path.unlink(missing_ok=True)
            cve_hits = self._count_cves(lines)
            if self.aggression >= 3:
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

    def _unique_naabu_hosts(self, lines: list[str]) -> set[str]:
        hosts: set[str] = set()
        for line in lines:
            line = line.strip()
            if not line or ":" not in line:
                continue
            host_part = line.rsplit(":", 1)[0]
            hosts.add(host_part)
        return hosts

    def _count_cves(self, lines: Iterable[str]) -> int:
        pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        count = 0
        for line in lines:
            count += len(pattern.findall(line))
        return count

    def _parse_naabu_ports(self, lines: list[str]) -> set[int]:
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

    def _shuffledns_bruteforce(self, domain: str) -> list[str]:
        return self._run_cmd(
            f"shuffledns -d {domain} -w {self.wordlist} -r {self.resolvers} -silent -mode bruteforce -retries 1 -t 10000",
            timeout=300,
            context=domain,
        )

    def _resolve_with_shuffledns(self, candidates: set[str], wildcard: bool, resolve_path: Path) -> list[str]:
        if not candidates:
            return []
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
            tmp.write("\n".join(sorted(candidates)))
            tmp.flush()
            tmp_name = tmp.name
        try:
            resolved = self._run_cmd(
                f"shuffledns -list {tmp_name} -r {self.resolvers} -silent -mode resolve -retries 1 -t 200",
                timeout=300,
                context="resolve",
            )
            final_list = resolved if resolved else (sorted(candidates) if not wildcard else sorted(candidates))
            resolve_path.write_text("\n".join(final_list) + ("\n" if final_list else ""), encoding="utf-8")
            return final_list
        finally:
            os.remove(tmp_name)

