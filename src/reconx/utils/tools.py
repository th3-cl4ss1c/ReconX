from __future__ import annotations

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple

from reconx.utils.process import raise_on_interrupt_returncode

try:
    import fcntl
except Exception:  # pragma: no cover - fcntl всегда есть на Linux, это fallback.
    fcntl = None

SUPPORTED_PLATFORMS = {
    ("linux", "x86_64"): ("linux", "amd64"),
    ("linux", "amd64"): ("linux", "amd64"),
    ("linux", "aarch64"): ("linux", "arm64"),
    ("linux", "arm64"): ("linux", "arm64"),
}

# (binary_name, "owner/repo") — бинарники загружаются с GitHub Releases
PREBUILT_TOOLS = [
    # dnsvalidator ставится отдельно через vortexau/dnsvalidator (см. _install_dnsvalidator).
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

EXPECTED_TOOLS = {
    "dnsvalidator",
    "subfinder",
    "shuffledns",
    "massdns",
    "smap",
    "naabu",
    "httpx",
    "dnsx",
    "nuclei",
    "vulnx",
    "katana",
    "gau",
}


def _platform_tag() -> tuple[str, str] | None:
    """Возвращает (os, arch) для выбора ассета: linux/amd64, linux/arm64 и т.д."""
    key = (sys.platform, platform.machine().lower())
    return SUPPORTED_PLATFORMS.get(key)


@contextmanager
def _install_lock(lock_path: Path, wait_timeout_sec: int = 600) -> Iterator[None]:
    """
    Межпроцессный lock на установку тулов.
    Нужен, чтобы параллельные запуски reconx не портили кэш бинарей.
    """
    if fcntl is None:
        yield
        return

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, "a+", encoding="utf-8")
    start = time.monotonic()
    try:
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                elapsed = time.monotonic() - start
                if elapsed >= wait_timeout_sec:
                    raise TimeoutError(f"timeout ожидания lock: {lock_path}")
                time.sleep(0.2)
        yield
    finally:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        fh.close()


def _make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IEXEC)


def _atomic_install_binary(src: Path, target: Path) -> None:
    """
    Атомарная установка бинаря:
    копируем в tmp-файл в той же директории и только затем переименовываем.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_target = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    try:
        shutil.copy2(src, tmp_target)
        _make_executable(tmp_target)
        os.replace(tmp_target, target)
    finally:
        tmp_target.unlink(missing_ok=True)


def _download(url: str, dest: Path, timeout: int = 120, retries: int = 4, backoff_sec: float = 2.0) -> None:
    """
    Скачивание с retry + атомарной записью файла.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    retryable_statuses = {408, 425, 429, 500, 502, 503, 504}

    for attempt in range(1, retries + 1):
        tmp_dest = dest.with_name(f".{dest.name}.tmp.{os.getpid()}.{attempt}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ReconX/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp_dest, "wb") as fh:
                fh.write(resp.read())
            os.replace(tmp_dest, dest)
            return
        except urllib.error.HTTPError as error:
            last_error = error
            tmp_dest.unlink(missing_ok=True)
            if error.code in retryable_statuses and attempt < retries:
                time.sleep(backoff_sec * attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last_error = error
            tmp_dest.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(backoff_sec * attempt)
                continue
            break

    if last_error:
        raise last_error
    raise RuntimeError(f"download failed: {url}")


def _fetch_json(url: str, timeout: int = 15, retries: int = 4, backoff_sec: float = 1.5) -> dict:
    last_error: Exception | None = None
    retryable_statuses = {408, 425, 429, 500, 502, 503, 504}
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ReconX/1.0",
    }
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code in retryable_statuses and attempt < retries:
                time.sleep(backoff_sec * attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            last_error = error
            if attempt < retries:
                time.sleep(backoff_sec * attempt)
                continue
            break
    if last_error:
        raise last_error
    raise RuntimeError(f"fetch json failed: {url}")


def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest_dir)


def _extract_tar(path: Path, dest_dir: Path) -> None:
    with tarfile.open(path, "r:*") as tf:
        tf.extractall(dest_dir)


def _smoke_check_binary(name: str, path: Path, timeout: int = 5) -> bool:
    """
    Базовая проверка целостности/исполняемости бинаря.
    Если команда зависла на --help, считаем это pass (бинарь исполняется).
    """
    try:
        if not path.exists() or path.stat().st_size == 0:
            return False
    except OSError:
        return False

    if not os.access(path, os.X_OK):
        try:
            _make_executable(path)
        except Exception:
            return False

    args = [str(path), "-h"]
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        raise_on_interrupt_returncode(proc.returncode)
        # 127 обычно означает невозможность запуска (битый/несовместимый бинарь).
        return proc.returncode != 127
    except subprocess.TimeoutExpired:
        return True
    except OSError:
        return False
    except Exception:
        return False


def _download_prebuilt(name: str, repo: str, bin_path: Path, platform_os: str, arch: str) -> Path | None:
    """
    Скачивает бинарь с GitHub Releases. Ищет ассет с linux_amd64 или linux_arm64.
    Возвращает Path до бинаря или None при ошибке.
    """
    target = bin_path / name
    if target.exists():
        if _smoke_check_binary(name, target):
            return target
        target.unlink(missing_ok=True)

    asset_os = "darwin" if platform_os == "darwin" else platform_os
    asset_arch = "386" if arch == "386" else arch
    match_suffix = f"{asset_os}_{asset_arch}"
    alt_suffix = f"{'macOS' if platform_os == 'darwin' else platform_os}_{asset_arch}"

    try:
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        data = _fetch_json(api_url)
    except Exception:
        return None

    assets = data.get("assets", [])
    candidates: list[tuple[str, str]] = []
    for asset in assets:
        aname = asset.get("name", "")
        aname_lower = aname.lower()
        if "checksum" in aname_lower or ".sig" in aname_lower:
            continue
        if match_suffix in aname_lower or alt_suffix.lower() in aname_lower:
            download_url = asset.get("browser_download_url")
            if not download_url:
                continue
            if aname_lower.endswith(".zip"):
                archive_ext = ".zip"
            elif ".tar.xz" in aname_lower:
                archive_ext = ".tar.xz"
            elif ".tar.gz" in aname_lower or aname_lower.endswith(".tgz"):
                archive_ext = ".tar.gz"
            else:
                archive_ext = ".zip"
            candidates.append((download_url, archive_ext))

    if not candidates:
        return None

    for download_url, archive_ext in candidates:
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                arc_path = tmp / f"download{archive_ext}"
                _download(download_url, arc_path)

                if archive_ext == ".zip":
                    _extract_zip(arc_path, tmp)
                else:
                    _extract_tar(arc_path, tmp)

                binary = None
                for path_candidate in tmp.rglob("*"):
                    if path_candidate.is_file() and path_candidate.name == name:
                        binary = path_candidate
                        break
                if not binary:
                    for path_candidate in tmp.rglob(name):
                        if path_candidate.is_file():
                            binary = path_candidate
                            break
                if binary:
                    _atomic_install_binary(binary, target)
                    if _smoke_check_binary(name, target):
                        return target
                    target.unlink(missing_ok=True)
        except Exception:
            continue
    return None


def _build_massdns(bin_path: Path) -> Path:
    """
    Сборка massdns из исходников (готовых релизов нет).
    Требует make, gcc. Принудительно задаём MASSDNS_REVISION пустой строкой,
    чтобы make не пытался читать git-метаданные в zip-архиве.
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
        try:
            subprocess.run(
                ["make", "PROJECT_FLAGS=-DMASSDNS_REVISION=\\\"\\\""],
                cwd=src_root,
                check=True,
                env=env,
                timeout=600,
            )
        except subprocess.CalledProcessError as error:
            raise_on_interrupt_returncode(error.returncode)
            raise
        built = src_root / "bin" / "massdns"
        if not built.exists():
            raise RuntimeError("Сборка massdns не создала bin/massdns")
        dest = bin_path / "massdns"
        _atomic_install_binary(built, dest)
        if not _smoke_check_binary("massdns", dest):
            raise RuntimeError("Сборка massdns дала нерабочий бинарь")
        return dest


def _write_dnsvalidator_wrapper(target: Path, dnsvalidator_bin: Path) -> Path | None:
    """
    Создаёт wrapper `dnsvalidator`, который прозрачно проксирует вызов в dnsvalidator.
    """
    script = (
        "#!/bin/sh\n"
        f"exec \"{dnsvalidator_bin}\" \"$@\"\n"
    )
    try:
        target.write_text(script, encoding="utf-8")
        _make_executable(target)
    except Exception:
        target.unlink(missing_ok=True)
        return None
    return target


def _install_dnsvalidator(bin_path: Path, warnings: list[str] | None = None) -> Path | None:
    """
    Устанавливает dnsvalidator через vortexau/dnsvalidator:
    - если dnsvalidator уже есть в PATH, создаёт wrapper;
    - иначе поднимает локальный venv и ставит dnsvalidator из GitHub.
    """
    warnings = warnings if warnings is not None else []
    target = bin_path / "dnsvalidator"
    if target.exists() and _smoke_check_binary("dnsvalidator", target):
        return target
    target.unlink(missing_ok=True)

    existing = shutil.which("dnsvalidator")
    if existing:
        wrapped = _write_dnsvalidator_wrapper(target, Path(existing))
        if wrapped and _smoke_check_binary("dnsvalidator", wrapped):
            return wrapped
        target.unlink(missing_ok=True)

    venv_root = bin_path.parent / "venvs" / "dnsvalidator"
    venv_python = venv_root / "bin" / "python3"
    venv_dnsvalidator = venv_root / "bin" / "dnsvalidator"
    try:
        if not venv_python.exists():
            subprocess.run(
                [sys.executable, "-m", "venv", str(venv_root)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
            )

        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
        )
        subprocess.run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--upgrade",
                "https://github.com/vortexau/dnsvalidator/archive/refs/heads/master.zip",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        warnings.append("dnsvalidator: timeout установки dnsvalidator (vortexau/dnsvalidator)")
        return None
    except subprocess.CalledProcessError as error:
        raise_on_interrupt_returncode(error.returncode)
        warnings.append("dnsvalidator: не удалось установить dnsvalidator (vortexau/dnsvalidator)")
        return None
    except Exception:
        warnings.append("dnsvalidator: непредвиденная ошибка установки dnsvalidator")
        return None

    if not venv_dnsvalidator.exists():
        warnings.append("dnsvalidator: dnsvalidator установлен, но бинарь не найден")
        return None

    wrapped = _write_dnsvalidator_wrapper(target, venv_dnsvalidator)
    if wrapped and _smoke_check_binary("dnsvalidator", wrapped):
        return wrapped
    if wrapped:
        target.unlink(missing_ok=True)
    warnings.append("dnsvalidator: wrapper создан, но smoke-check не пройден")
    return None


def _download_vulnx_from_releases_page(bin_path: Path, platform_os: str, arch: str) -> Path | None:
    """
    Fallback для vulnx, если GitHub API недоступен (например, rate limit).
    Ищет download-ссылку на странице releases и ставит бинарь как обычно.
    """
    if platform_os != "linux":
        return None

    target = bin_path / "vulnx"
    if target.exists():
        if _smoke_check_binary("vulnx", target):
            return target
        target.unlink(missing_ok=True)

    releases_url = "https://github.com/projectdiscovery/cvemap/releases"
    try:
        req = urllib.request.Request(releases_url, headers={"User-Agent": "ReconX/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return None

    pattern = re.compile(
        rf'href="(/projectdiscovery/cvemap/releases/download/[^"]*/vulnx_[^"]*_{platform_os}_{arch}\.zip)"',
        re.IGNORECASE,
    )
    match = pattern.search(html)
    if not match:
        return None

    download_url = f"https://github.com{match.group(1)}"
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            arc_path = tmp / "vulnx.zip"
            _download(download_url, arc_path)
            _extract_zip(arc_path, tmp)

            binary = None
            for path_candidate in tmp.rglob("*"):
                if path_candidate.is_file() and path_candidate.name == "vulnx":
                    binary = path_candidate
                    break
            if not binary:
                return None

            _atomic_install_binary(binary, target)
            if _smoke_check_binary("vulnx", target):
                return target
            target.unlink(missing_ok=True)
    except Exception:
        return None
    return None


def ensure_external_tools(bin_dir: Path | None = None) -> Tuple[Path, Dict[str, Path], Iterable[str], Iterable[str]]:
    """
    Гарантировать наличие бинарей: dnsvalidator, subfinder, shuffledns, massdns,
    smap, naabu, httpx, dnsx, nuclei, vulnx, katana, gau.
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
    go_tools_map = {name: (module, env_extra) for name, module, env_extra in go_tools}

    def _go_install(name: str, module: str, env_extra: dict[str, str] | None = None) -> Path | None:
        if not go_bin:
            return None
        target = bin_path / name
        if target.exists():
            if _smoke_check_binary(name, target):
                return target
            target.unlink(missing_ok=True)

        env = os.environ.copy()
        env["GOBIN"] = str(bin_path)
        if "GOPROXY" not in env:
            env["GOPROXY"] = "https://proxy.golang.org,direct"
        if env_extra:
            env.update(env_extra)

        try:
            result = subprocess.run(
                [go_bin, "install", "-v", module],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                timeout=900,
            )
            if result.stdout:
                output_lines = result.stdout.strip().splitlines()
                important_lines = [line for line in output_lines if "error" in line.lower() or "warning" in line.lower()]
                if important_lines:
                    notes.append("\n".join(important_lines))
        except subprocess.TimeoutExpired:
            warnings.append(f"{name}: go install timeout. Попробуйте вручную: go install {module}")
            return None
        except subprocess.CalledProcessError as error:
            raise_on_interrupt_returncode(error.returncode)
            error_output = error.stdout if hasattr(error, "stdout") and error.stdout else ""
            error_msg = error_output.decode("utf-8") if isinstance(error_output, bytes) else error_output
            stderr_txt = error_msg.lower() if error_msg else ""

            if "pcap.h" in stderr_txt:
                warnings.append(f"{name}: отсутствует libpcap-dev (sudo apt install -y libpcap-dev)")
            elif "timeout" in stderr_txt or "dial tcp" in stderr_txt:
                warnings.append(f"{name}: проблема с сетью при установке. Попробуйте вручную: go install {module}")
            else:
                if error_msg:
                    error_lines = error_msg.strip().splitlines()
                    error_preview = "\n".join(error_lines[-3:]) if len(error_lines) > 3 else error_msg[:300]
                else:
                    error_preview = "нет вывода"
                warnings.append(f"{name}: go install не удался (код {error.returncode})\n{error_preview}")
            return None

        if target.exists() and _smoke_check_binary(name, target):
            return target
        target.unlink(missing_ok=True)
        return None

    found: Dict[str, Path] = {}

    lock_path = bin_path.parent / ".install.lock"
    try:
        with _install_lock(lock_path):
            dnsvalidator_cached = bin_path / "dnsvalidator"
            legacy_dns_validate = bin_path / "dns_validate"
            if not dnsvalidator_cached.exists() and legacy_dns_validate.exists():
                try:
                    os.replace(legacy_dns_validate, dnsvalidator_cached)
                except Exception:
                    pass
            if dnsvalidator_cached.exists() and _smoke_check_binary("dnsvalidator", dnsvalidator_cached):
                found["dnsvalidator"] = dnsvalidator_cached
            else:
                dnsvalidator_cached.unlink(missing_ok=True)
                installed_dnsvalidator = _install_dnsvalidator(bin_path, warnings=warnings)
                if installed_dnsvalidator and _smoke_check_binary("dnsvalidator", installed_dnsvalidator):
                    found["dnsvalidator"] = installed_dnsvalidator

            massdns_cached = bin_path / "massdns"
            if massdns_cached.exists() and _smoke_check_binary("massdns", massdns_cached):
                found["massdns"] = massdns_cached
            else:
                massdns_cached.unlink(missing_ok=True)
                existing_massdns = shutil.which("massdns")
                if existing_massdns and _smoke_check_binary("massdns", Path(existing_massdns)):
                    found["massdns"] = Path(existing_massdns)
                else:
                    try:
                        built = _build_massdns(bin_path)
                        found["massdns"] = built
                    except Exception as error:  # noqa: BLE001
                        if isinstance(error, subprocess.CalledProcessError):
                            raise_on_interrupt_returncode(error.returncode)
                        warnings.append(f"Не удалось собрать massdns: {error}")

            # 1) Готовые бинари с GitHub Releases (работает без Go)
            for name, repo in PREBUILT_TOOLS:
                if name in found:
                    continue
                path = _download_prebuilt(name, repo, bin_path, platform_os, arch)
                if path and _smoke_check_binary(name, path):
                    found[name] = path

            # 1b) Дополнительный fallback для vulnx без GitHub API.
            if "vulnx" not in found:
                vulnx_path = _download_vulnx_from_releases_page(bin_path, platform_os, arch)
                if vulnx_path and _smoke_check_binary("vulnx", vulnx_path):
                    found["vulnx"] = vulnx_path

            # 2) Go install для тех, кого не нашли в prebuilt
            for name in [n for n, _ in PREBUILT_TOOLS]:
                if name in found or not go_bin:
                    continue
                entry = go_tools_map.get(name)
                if entry:
                    module, env_extra = entry
                    path = _go_install(name, module, env_extra)
                    if path and _smoke_check_binary(name, path):
                        found[name] = path
    except TimeoutError as error:
        warnings.append(f"Установка инструментов занята другим процессом: {error}")

    missing = EXPECTED_TOOLS - set(found.keys())
    if missing:
        warnings.append("Не найдены: " + ", ".join(sorted(missing)))

    # prepend bin_path to PATH so subprocess sees tools
    os.environ["PATH"] = str(bin_path) + os.pathsep + os.environ.get("PATH", "")
    os.environ["RECONX_CERTS"] = str(certs_path)

    return bin_path, found, warnings, notes
