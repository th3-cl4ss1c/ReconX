"""Обеспечение наличия данных в RECONX_DATA_DIR (~/.local/share/reconx)."""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
WORDLIST_NAME = "subdomains-top1million-110000.txt"


def get_data_dir() -> Path:
    """Возвращает каталог данных (RECONX_DATA_DIR или ~/.local/share/reconx)."""
    import os

    env = os.getenv("RECONX_DATA_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return Path.home() / ".local" / "share" / "reconx"


def ensure_data_dir(data_dir: Path) -> None:
    """Создаёт каталог данных и wordlists при необходимости."""
    data_dir.mkdir(parents=True, exist_ok=True)
    wordlists_dir = data_dir / "wordlists"
    wordlists_dir.mkdir(parents=True, exist_ok=True)

    # resolvers.txt — из пакета, если файла нет
    resolvers_path = data_dir / "resolvers.txt"
    if not resolvers_path.exists():
        _copy_default_resolvers(resolvers_path)

    # wordlist — скачиваем при первом запуске
    wordlist_path = wordlists_dir / WORDLIST_NAME
    if not wordlist_path.exists():
        _download_wordlist(wordlist_path)


def _copy_default_resolvers(dest: Path) -> None:
    """Копирует resolvers из пакета в data dir."""
    try:
        from importlib import resources

        pkg = resources.files("reconx.data")
        src = pkg / "resolvers.txt"
        if src.exists():
            dest.write_bytes(src.read_bytes())
            return
    except Exception:
        pass
    # fallback: минимальный набор публичных DNS
    fallback = "8.8.8.8\n1.1.1.1\n8.26.56.26\n"
    dest.write_text(fallback, encoding="utf-8")


def _download_wordlist(dest: Path) -> None:
    """Скачивает wordlist из SecLists."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(WORDLIST_URL, headers={"User-Agent": "ReconX/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
    except Exception as e:
        print(f"⚠️  Не удалось скачать wordlist: {e}", file=sys.stderr)
        print(f"   Создайте вручную: {dest}", file=sys.stderr)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text("www\nmail\nlocalhost\n", encoding="utf-8")
