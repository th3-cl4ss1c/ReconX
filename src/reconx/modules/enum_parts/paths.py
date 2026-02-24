from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EnumPaths:
    raw_dir: Path
    raw_scan_dir: Path
    raw_web_dir: Path
    raw_urls_dir: Path
    raw_humans_dir: Path
    raw_breach_dir: Path
    processed_dir: Path
    subfinder_path: Path
    resolve_path: Path
    bruteforce_path: Path
    gau_path: Path
    gau_clean_path: Path
    gau_core_path: Path
    gau_subs_path: Path
    paramspider_path: Path
    hunter_path: Path
    snusbase_path: Path
    dnsx_path: Path
    smap_dnsx_path: Path
    naabu_path: Path
    nmap_path: Path
    alive_path: Path
    open_ports_path: Path
    httpx_path: Path
    headers_path: Path
    alive_urls_path: Path
    alive_urls_unic_path: Path
    nuclei_web_path: Path
    nuclei_net_path: Path
    subdomains_path: Path

    @classmethod
    def create(cls, target_dir: Path) -> "EnumPaths":
        raw_dir = target_dir / "raw" / "enum"
        raw_scan_dir = target_dir / "raw" / "scan"
        raw_web_dir = target_dir / "raw" / "web"
        raw_urls_dir = target_dir / "raw" / "urls"
        raw_humans_dir = target_dir / "raw" / "humans"
        raw_breach_dir = target_dir / "raw" / "breach"
        processed_dir = target_dir / "processed"

        for path in (
            raw_dir,
            raw_scan_dir,
            raw_web_dir,
            raw_urls_dir,
            raw_humans_dir,
            raw_breach_dir,
            processed_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

        return cls(
            raw_dir=raw_dir,
            raw_scan_dir=raw_scan_dir,
            raw_web_dir=raw_web_dir,
            raw_urls_dir=raw_urls_dir,
            raw_humans_dir=raw_humans_dir,
            raw_breach_dir=raw_breach_dir,
            processed_dir=processed_dir,
            subfinder_path=raw_dir / "subfinder.txt",
            resolve_path=raw_dir / "resolved.txt",
            bruteforce_path=raw_dir / "bruteforce.txt",
            gau_path=raw_urls_dir / "gau.txt",
            gau_clean_path=raw_urls_dir / "gau-clean.txt",
            gau_core_path=raw_urls_dir / "gau-core.txt",
            gau_subs_path=raw_urls_dir / "gau-subs.txt",
            paramspider_path=raw_urls_dir / "paramspider.txt",
            hunter_path=raw_humans_dir / "hunter.json",
            snusbase_path=raw_breach_dir / "snusbase.json",
            dnsx_path=raw_scan_dir / "dnsx.json",
            smap_dnsx_path=raw_scan_dir / "smap.json",
            naabu_path=raw_scan_dir / "naabu.txt",
            nmap_path=raw_scan_dir / "nmap",
            alive_path=processed_dir / "alive.txt",
            open_ports_path=processed_dir / "open-ports.txt",
            httpx_path=raw_web_dir / "httpx.json",
            headers_path=raw_web_dir / "headers.txt",
            alive_urls_path=processed_dir / "alive-urls.txt",
            alive_urls_unic_path=processed_dir / "alive-urls-unic.txt",
            nuclei_web_path=raw_web_dir / "nuclei-web.json",
            nuclei_net_path=raw_scan_dir / "nuclei-net.json",
            subdomains_path=processed_dir / "subdomains.txt",
        )
