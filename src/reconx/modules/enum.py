from __future__ import annotations

import ipaddress
import shutil
from pathlib import Path
from typing import Iterable

from reconx.modules.base import Module
from reconx.modules.enum_parts import (
    EnumPaths,
    derive_paramspider_from_gau,
    has_wildcard,
    resolve_with_shuffledns,
    run_dnsx,
    run_gau,
    run_hunter,
    run_httpx,
    run_naabu_hosts,
    run_nmap_hosts,
    run_nuclei,
    run_smap_hosts,
    run_snusbase,
    run_subfinder,
    run_vulnx_scan,
    shuffledns_bruteforce,
)
from reconx.modules.enum_parts.providers import load_projectdiscovery_api_key
from reconx.utils.data import WORDLIST_NAME, get_data_dir
from reconx.utils.targets import Target


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
        self.vulnx_bin = shutil.which("vulnx")
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

    def _process_domain(self, target: Target) -> None:
        domain = target.raw
        target_dir = self.workspace_root if self.single_mode else self.workspace_root / target.folder_name
        if self.debug:
            print(f"[debug] enum start: domain={domain}, aggression={self.aggression}, target_dir={target_dir}")
        paths = EnumPaths.create(target_dir)
        projectdiscovery_api_key = load_projectdiscovery_api_key()

        run_snusbase(domain, paths.snusbase_path)
        run_hunter(domain, paths.hunter_path)
        run_gau(domain, paths.gau_path, paths.gau_clean_path, paths.gau_core_path, paths.gau_subs_path)
        derive_paramspider_from_gau(paths.gau_path, paths.paramspider_path)

        subfinder_lines = run_subfinder(domain)
        paths.subfinder_path.write_text("\n".join(subfinder_lines) + ("\n" if subfinder_lines else ""), encoding="utf-8")
        print(f"subfinder: {len(subfinder_lines)}")

        passive = set(subfinder_lines)
        if not self.shuffledns_bin or not self.massdns_bin:
            print("⚠️  shuffledns/massdns не найдены, пропускаю bruteforce/resolve")
            combined = passive
            resolved = sorted(combined)
        else:
            wildcard = has_wildcard(domain, self.resolvers, self.shuffledns_bin, self.massdns_bin)
            print(f"wildcard: {'yes' if wildcard else 'no'}")
            if wildcard:
                combined = passive
            else:
                brute = shuffledns_bruteforce(domain, self.resolvers, self.wordlist)
                paths.bruteforce_path.write_text("\n".join(brute) + ("\n" if brute else ""), encoding="utf-8")
                print(f"shuffledns bruteforce: {len(brute)}")
                combined = passive | set(brute)

            resolved = resolve_with_shuffledns(combined, wildcard, self.resolvers, paths.resolve_path)
            print(f"resolved: {len(resolved)}")

        dnsx_input = resolved + [domain]
        dnsx_ips = run_dnsx(dnsx_input, self.resolvers, paths.dnsx_path)
        host_list = sorted(set(resolved + [domain] + dnsx_ips))
        paths.alive_path.write_text("\n".join(host_list) + ("\n" if host_list else ""), encoding="utf-8")

        if host_list:
            smap_lines, smap_ports = run_smap_hosts(host_list, paths.smap_dnsx_path)
            merged_ports = set(smap_ports)
            if self.aggression == 1:
                open_lines = sorted({ln.strip() for ln in smap_lines if ln.strip()})
                paths.open_ports_path.write_text("\n".join(open_lines) + ("\n" if open_lines else ""), encoding="utf-8")
            else:
                naabu_lines, naabu_ports = run_naabu_hosts(host_list, paths.naabu_path, aggressive=self.aggression == 3)
                merged_ports |= naabu_ports
                if naabu_lines:
                    open_lines = sorted({ln.strip() for ln in naabu_lines if ln.strip()})
                else:
                    open_lines = sorted({ln.strip() for ln in smap_lines if ln.strip()})
                paths.open_ports_path.write_text("\n".join(open_lines) + ("\n" if open_lines else ""), encoding="utf-8")
                if merged_ports:
                    run_nmap_hosts(host_list, merged_ports, paths.nmap_path, aggression=self.aggression, debug=self.debug)

        run_vulnx_scan(paths.raw_scan_dir, self.vulnx_bin, projectdiscovery_api_key=projectdiscovery_api_key)

        paths.subdomains_path.write_text("\n".join(resolved) + ("\n" if resolved else ""), encoding="utf-8")

        httpx_input = self._build_httpx_input(paths.open_ports_path, paths.alive_path)
        run_httpx(httpx_input, paths.httpx_path, paths.alive_urls_path, paths.alive_urls_unic_path, paths.headers_path)

        if self.nuclei_profile:
            if paths.alive_urls_unic_path.exists():
                web_input = [ln.strip() for ln in paths.alive_urls_unic_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            else:
                web_input = [
                    ln.strip()
                    for ln in paths.alive_urls_path.read_text(encoding="utf-8").splitlines()
                    if ln.strip() and not ln.strip().startswith("#")
                ]
            if web_input:
                run_nuclei(web_input, paths.nuclei_web_path, self.nuclei_profile, mode="web")
            else:
                paths.nuclei_web_path.write_text("", encoding="utf-8")

            net_input = [ln.strip() for ln in paths.open_ports_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if net_input:
                run_nuclei(net_input, paths.nuclei_net_path, self.nuclei_profile, mode="net")
            else:
                paths.nuclei_net_path.write_text("", encoding="utf-8")

    @staticmethod
    def _build_httpx_input(open_ports_path: Path, alive_path: Path) -> list[str]:
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
        return httpx_input_lines
