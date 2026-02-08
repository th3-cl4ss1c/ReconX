from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Tuple, List

SUPPORTED_PLATFORMS = {
    ("linux", "x86_64"): "linux-amd64",
    ("linux", "amd64"): "linux-amd64",
}


def _platform_tag() -> str | None:
    key = (sys.platform, platform.machine().lower())
    return SUPPORTED_PLATFORMS.get(key)


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IEXEC)


def _build_massdns(bin_path: Path) -> Path:
    """
    Сборка massdns из исходников, если нет готового релиза.
    Требует установленный toolchain (make, gcc).
    """
    src_url = "https://github.com/blechschmidt/massdns/archive/refs/heads/master.zip"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        zip_dest = tmpdir_path / "massdns.zip"
        _download(src_url, zip_dest)
        _extract_zip(zip_dest, tmpdir_path)
        # Находим распакованный каталог
        src_root = next((p for p in tmpdir_path.iterdir() if p.is_dir() and p.name.startswith("massdns")), None)
        if not src_root:
            raise RuntimeError("Не найден каталог massdns после распаковки")
        subprocess.run(["make"], cwd=src_root, check=True)
        built = src_root / "bin" / "massdns"
        if not built.exists():
            raise RuntimeError("Сборка massdns не создала bin/massdns")
        dest = bin_path / "massdns"
        shutil.copy2(built, dest)
        _make_executable(dest)
        return dest


def ensure_external_tools(bin_dir: Path | None = None) -> Tuple[Path, Dict[str, Path], Iterable[str], Iterable[str]]:
    """
    Гарантировать наличие бинарей: subfinder, shuffledns, massdns, smap, naabu,
    httpx, dnsx, nuclei, vulnx, katana, gau.
    Установка: go install (GOBIN=~/.cache/reconx/bin) + сборка massdns + pip install для Python инструментов.
    Возвращает: (bin_dir, mapping name->path, warnings, notes)
    """
    warnings: List[str] = []
    notes: List[str] = []
    tag = _platform_tag()
    if not tag:
        warnings.append("Автодогрузка поддерживает только linux x86_64. Установите инструменты вручную.")
        return Path("."), {}, warnings, notes

    bin_path = Path(bin_dir) if bin_dir else Path.home() / ".cache" / "reconx" / "bin"
    bin_path.mkdir(parents=True, exist_ok=True)
    certs_path = bin_path.parent / "certs"
    certs_path.mkdir(parents=True, exist_ok=True)

    go_bin = shutil.which("go")
    if not go_bin:
        warnings.append("go не найден в PATH. Установите golang для автодогрузки инструментов.")

    go_tools = [
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", {}),
        ("shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", {}),
        ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", {}),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", {}),
        ("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", {}),
        ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", {}),
        ("vulnx", "github.com/projectdiscovery/cvemap/cmd/vulnx@latest", {}),
        # ("openrisk", "github.com/projectdiscovery/openrisk@latest", {}),
        ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest", {"CGO_ENABLED": "1"}),
        ("smap", "github.com/s0md3v/smap/cmd/smap@latest", {}),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest", {}),
    ]

    def _go_install(name: str, module: str, env_extra: dict[str, str] | None = None) -> Path | None:
        if not go_bin:
            return None
        target = bin_path / name
        if target.exists():
            return target
        env = os.environ.copy()
        env["GOBIN"] = str(bin_path)
        # Используем прямой прокси для Go модулей, если есть проблемы с сетью
        if "GOPROXY" not in env:
            env["GOPROXY"] = "direct"
        if env_extra:
            env.update(env_extra)
        try:
            result = subprocess.run(
                [go_bin, "install", "-v", module],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Объединяем stderr в stdout для полного вывода
                text=True,
                env=env,
            )
            if result.stdout:
                # Логируем только важные сообщения, не весь вывод
                output_lines = result.stdout.strip().splitlines()
                important_lines = [line for line in output_lines if "error" in line.lower() or "warning" in line.lower()]
                if important_lines:
                    notes.append("\n".join(important_lines))
        except subprocess.CalledProcessError as error:
            # Получаем полный вывод (stdout + stderr)
            error_output = error.stdout if hasattr(error, 'stdout') and error.stdout else (error.stderr if hasattr(error, 'stderr') else "")
            error_msg = error_output.decode("utf-8") if isinstance(error_output, bytes) else error_output
            stderr_txt = error_msg.lower() if error_msg else ""
            
            if "pcap.h" in stderr_txt:
                warnings.append(f"{name}: отсутствует libpcap-dev (sudo apt install -y libpcap-dev)")
            elif "timeout" in stderr_txt or "dial tcp" in stderr_txt:
                warnings.append(f"{name}: проблема с сетью при установке (таймаут/сеть). Попробуйте установить вручную: go install {module}")
            else:
                # Берем последние строки вывода для диагностики
                if error_msg:
                    error_lines = error_msg.strip().splitlines()
                    error_preview = "\n".join(error_lines[-3:]) if len(error_lines) > 3 else error_msg[:300]
                else:
                    error_preview = "нет вывода"
                warnings.append(f"{name}: go install не удался (код {error.returncode})\n{error_preview}")
            return None
        if target.exists():
            _make_executable(target)
            return target
        fresh = shutil.which(name)
        return Path(fresh) if fresh else None

    found: Dict[str, Path] = {}

    # massdns (build) — кэшируем в bin_path
    massdns_cached = bin_path / "massdns"
    if massdns_cached.exists():
        found["massdns"] = massdns_cached
    else:
        existing_massdns = shutil.which("massdns")
        if existing_massdns:
            found["massdns"] = Path(existing_massdns)
        else:
            try:
                built = _build_massdns(bin_path)
                found["massdns"] = built
            except Exception as error:  # noqa: BLE001
                warnings.append(f"Не удалось собрать massdns: {error}")

    # go-based tools
    for name, module, env_extra in go_tools:
        path = _go_install(name, module, env_extra)
        if path:
            found[name] = path

    # nuclei templates (бесшумная автозагрузка)
    if "nuclei" in found:
        try:
            subprocess.run(
                [str(found["nuclei"]), "-silent", "-ut", "-ud", str(bin_path / "nuclei-templates")],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            warnings.append("nuclei templates: автодогрузка не удалась, запустите вручную nuclei -ut")

    expected = {"subfinder", "shuffledns", "massdns", "smap", "naabu", "httpx", "dnsx", "nuclei", "vulnx", "katana", "gau"}
    missing = expected - set(found.keys())
    if missing:
        warnings.append("Не найдены: " + ", ".join(sorted(missing)))

    # prepend bin_path to PATH so subprocess sees tools
    os.environ["PATH"] = str(bin_path) + os.pathsep + os.environ.get("PATH", "")
    os.environ["RECONX_CERTS"] = str(certs_path)

    return bin_path, found, warnings, notes

