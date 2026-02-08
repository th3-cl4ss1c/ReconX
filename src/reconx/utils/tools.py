from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Tuple, List

SUPPORTED_PLATFORMS = {
    ("linux", "x86_64"): ("linux", "amd64"),
    ("linux", "amd64"): ("linux", "amd64"),
    ("linux", "aarch64"): ("linux", "arm64"),
    ("linux", "arm64"): ("linux", "arm64"),
}

# (binary_name, "owner/repo") — бинарники загружаются с GitHub Releases
PREBUILT_TOOLS = [
    ("subfinder", "projectdiscovery/subfinder"),
    ("shuffledns", "projectdiscovery/shuffledns"),
    ("naabu", "projectdiscovery/naabu"),
    ("httpx", "projectdiscovery/httpx"),
    ("dnsx", "projectdiscovery/dnsx"),
    ("nuclei", "projectdiscovery/nuclei"),
    ("katana", "projectdiscovery/katana"),
    ("smap", "s0md3v/Smap"),
    ("gau", "lc/gau"),
    ("vulnx", "projectdiscovery/cvemap"),  # vulnx из cvemap repo
]


def _platform_tag() -> tuple[str, str] | None:
    """Возвращает (os, arch) для выбора ассета: linux/amd64, linux/arm64 и т.д."""
    key = (sys.platform, platform.machine().lower())
    return SUPPORTED_PLATFORMS.get(key)


def _download(url: str, dest: Path, timeout: int = 120) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as fh:
        fh.write(resp.read())


def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def _extract_tar(path: Path, dest_dir: Path) -> None:
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(dest_dir)


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IEXEC)


def _download_prebuilt(name: str, repo: str, bin_path: Path, platform_os: str, arch: str) -> Path | None:
    """
    Скачивает бинарь с GitHub Releases. Ищет ассет с linux_amd64 или linux_arm64.
    Возвращает Path до бинаря или None при ошибке.
    """
    target = bin_path / name
    if target.exists():
        return target
    # Преобразуем macOS -> darwin для некоторых репо (gau)
    asset_os = "darwin" if platform_os == "darwin" else platform_os
    asset_arch = "386" if arch == "386" else arch
    match_suffix = f"{asset_os}_{asset_arch}"
    # Доп. варианты: macOS_amd64, linux_amd64
    alt_suffix = f"{'macOS' if platform_os == 'darwin' else platform_os}_{asset_arch}"

    try:
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(api_url, headers={"Accept": "application/vnd.github.v3+json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return None

    assets = data.get("assets", [])
    tag = data.get("tag_name", "latest")
    download_url = None
    archive_ext = None

    for a in assets:
        aname = a.get("name", "")
        aname_lower = aname.lower()
        if "checksum" in aname_lower or ".sig" in aname_lower:
            continue
        if match_suffix in aname_lower or alt_suffix.lower() in aname_lower:
            download_url = a.get("browser_download_url")
            if download_url:
                if aname_lower.endswith(".zip"):
                    archive_ext = ".zip"
                elif ".tar.xz" in aname_lower:
                    archive_ext = ".tar.xz"
                elif ".tar.gz" in aname_lower or aname_lower.endswith(".tgz"):
                    archive_ext = ".tar.gz"
                else:
                    archive_ext = ".zip"
                break

    if not download_url:
        return None

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            arc_path = tmp / f"download{archive_ext}"
            _download(download_url, arc_path)

            if archive_ext == ".zip":
                _extract_zip(arc_path, tmp)
            else:
                _extract_tar(arc_path, tmp)

            # Ищем бинарь в распакованном содержимом
            binary = None
            for p in tmp.rglob("*"):
                if p.is_file() and p.name == name:
                    binary = p
                    break
            if not binary:
                # Может быть без расширения, ищем исполняемый файл с нужным именем
                for p in tmp.rglob(name):
                    if p.is_file():
                        binary = p
                        break
            if binary:
                shutil.copy2(binary, target)
                _make_executable(target)
                return target
    except Exception:
        pass
    return None


def _build_massdns(bin_path: Path) -> Path:
    """
    Сборка massdns из исходников (готовых релизов нет).
    Требует make, gcc. GIT_DISCOVERY_ACROSS_FILESYSTEM=1 избегает ошибки git в tmp.
    """
    src_url = "https://github.com/blechschmidt/massdns/archive/refs/heads/master.zip"
    env = os.environ.copy()
    env["GIT_DISCOVERY_ACROSS_FILESYSTEM"] = "1"
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        zip_dest = tmpdir_path / "massdns.zip"
        _download(src_url, zip_dest)
        _extract_zip(zip_dest, tmpdir_path)
        src_root = next((p for p in tmpdir_path.iterdir() if p.is_dir() and p.name.startswith("massdns")), None)
        if not src_root:
            raise RuntimeError("Не найден каталог massdns после распаковки")
        subprocess.run(["make"], cwd=src_root, check=True, env=env)
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
    Сначала скачивает готовые бинари с GitHub Releases (без Go).
    Если не найден — пробует go install. massdns собирается из исходников.
    Возвращает: (bin_dir, mapping name->path, warnings, notes)
    """
    warnings: List[str] = []
    notes: List[str] = []
    platform_tag = _platform_tag()
    if not platform_tag:
        warnings.append("Автодогрузка поддерживает только linux x86_64/arm64. Установите инструменты вручную.")
        return Path("."), {}, warnings, notes

    platform_os, arch = platform_tag
    bin_path = Path(bin_dir) if bin_dir else Path.home() / ".cache" / "reconx" / "bin"
    bin_path.mkdir(parents=True, exist_ok=True)
    certs_path = bin_path.parent / "certs"
    certs_path.mkdir(parents=True, exist_ok=True)

    go_bin = shutil.which("go")
    go_tools = [
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", {}),
        ("shuffledns", "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", {}),
        ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", {}),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", {}),
        ("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", {}),
        ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", {}),
        ("vulnx", "github.com/projectdiscovery/cvemap/cmd/vulnx@latest", {}),
        ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest", {"CGO_ENABLED": "1"}),
        ("smap", "github.com/s0md3v/smap/cmd/smap@latest", {}),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest", {}),
    ]
    go_tools_map = {name: (module, env) for name, module, env in go_tools}

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

    # 1) Готовые бинари с GitHub Releases (работает без Go)
    for name, repo in PREBUILT_TOOLS:
        if name in found:
            continue
        path = _download_prebuilt(name, repo, bin_path, platform_os, arch)
        if path:
            found[name] = path

    # 2) Go install для тех, кого не нашли в prebuilt
    for name in [n for n, _ in PREBUILT_TOOLS]:
        if name in found or not go_bin:
            continue
        entry = go_tools_map.get(name)
        if entry:
            module, env_extra = entry
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

