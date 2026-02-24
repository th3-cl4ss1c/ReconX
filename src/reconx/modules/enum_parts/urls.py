from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def run_gau(
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

    EXCLUDED_EXT = frozenset(
        {
            "jpg",
            "jpeg",
            "png",
            "gif",
            "svg",
            "ico",
            "webp",
            "bmp",
            "css",
            "js",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "otf",
            "mp4",
            "mp3",
            "webm",
            "ogg",
            "wav",
            "avi",
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


def derive_paramspider_from_gau(gau_path: Path, paramspider_path: Path) -> None:
    """Формирует paramspider.txt из gau: только качественные URL с параметрами, в духе paramspider."""
    EXCLUDED_EXT = frozenset(
        {
            "jpg",
            "jpeg",
            "png",
            "gif",
            "svg",
            "ico",
            "webp",
            "bmp",
            "css",
            "js",
            "woff",
            "woff2",
            "ttf",
            "eot",
            "otf",
            "mp4",
            "mp3",
            "webm",
            "ogg",
            "wav",
            "avi",
        }
    )
    BORING_PARAMS = frozenset(
        {
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_content",
            "utm_term",
            "utm_referrer",
            "fbclid",
            "gclid",
            "gclsrc",
            "ref",
            "_ga",
            "_gl",
            "_gac",
            "_gid",
            "mc_cid",
            "mc_eid",
            "_hsenc",
            "_hsmi",
            "hsCtaTracking",
            "msclkid",
            "dclid",
            "twclid",
            "li_fat_id",
            "_ref",
            "fb_action_ids",
            "fb_action_types",
            "fb_source",
            "campaign",
            "pk_campaign",
            "pk_kwd",
            "mc_tc",
            "phoenix_error",
            "n_c",
            "nr_email_referer",
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
        seen: dict[tuple, str] = {}
        for raw in lines:
            if "?" not in raw or len(raw) > MAX_URL_LEN:
                continue
            try:
                parsed = urlparse(raw)
                if not parsed.query:
                    continue
                path_raw = parsed.path or "/"
                path_lower = path_raw.lower()
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
                if ":" in netloc:
                    host_part, port_part = netloc.rsplit(":", 1)
                    if port_part == "80" and scheme == "http":
                        netloc = host_part
                    elif port_part == "443" and scheme == "https":
                        netloc = host_part
                if netloc.lower().startswith("www."):
                    netloc = netloc[4:]
                sorted_params = sorted(params.items(), key=lambda x: x[0].lower())
                query_canon = urlencode([(k, "FUZZ") for k, _ in sorted_params], doseq=False)
                canonical = urlunparse((scheme, netloc, path_raw, "", query_canon, ""))
                signature = (scheme, netloc, path_raw, param_names)
                if signature not in seen:
                    seen[signature] = canonical
            except Exception:
                continue
        result = sorted(seen.values())
        paramspider_path.parent.mkdir(parents=True, exist_ok=True)
        paramspider_path.write_text("\n".join(result) + ("\n" if result else ""), encoding="utf-8")
        with_params = sum(1 for l in lines if "?" in l)
        print(f"paramspider: {len(result)}({with_params})")
    except Exception as e:
        paramspider_path.write_text("", encoding="utf-8")
        print(f"⚠️  paramspider ошибка: {e}")
