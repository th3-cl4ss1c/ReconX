from __future__ import annotations

import argparse
import sys
from pathlib import Path
import shutil
import os
import subprocess

from reconx import __version__
from reconx.modules.workspace import WorkspaceModule
from reconx.modules import EnumModule, ProbeModule
from reconx.utils.targets import Target, load_targets


def _default_data_dir() -> Path:
    """Возвращает каталог данных (по умолчанию ~/.local/share/reconx)."""
    env = os.getenv("RECONX_DATA_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".local" / "share" / "reconx"


def _ensure_data_dir_env() -> None:
    """Автоматически проставляет RECONX_DATA_DIR, если не задан явно."""
    if not os.getenv("RECONX_DATA_DIR"):
        try:
            os.environ["RECONX_DATA_DIR"] = str(_default_data_dir())
        except Exception:
            pass


from reconx.utils.tools import ensure_external_tools
from reconx.utils.data import ensure_data_dir, get_data_dir


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconx",
        description="ReconX: модульный CLI для подготовки и запуска разведки",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"reconx {__version__}",
        help="Показать версию",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Цель (домен или IP). Можно передать несколько.",
    )
    parser.add_argument(
        "-l",
        "--list",
        dest="list_path",
        help="Путь до файла со списком целей (домен или IP по строкам).",
    )
    parser.add_argument(
        "--list-id",
        dest="list_id",
        help="Пользовательский идентификатор для имени каталога со списком.",
    )
    parser.add_argument(
        "-a",
        "--aggression",
        dest="aggression",
        type=int,
        choices=[1, 2, 3],
        default=1,
        help="Уровень агрессии для IP-сканирования: 1=smap, 2=naabu top + nmap -A -T3, 3=naabu all + nmap -A -T5",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Подробный лог запуска (nmap команды, попытки, таймауты).",
    )

    return parser


def _restore_terminal() -> None:
    """Восстанавливает терминал в нормальное состояние."""
    if not sys.stdin.isatty():
        return
    
    # Пробуем восстановить через прямой доступ к терминалу через /dev/tty
    # Это более надежно, чем через stdin, так как работает напрямую с терминалом
    try:
        # Используем прямой доступ к /dev/tty для восстановления
        os.system('stty sane < /dev/tty 2>/dev/null')
    except Exception:
        # Если не получилось, пробуем обычный способ
        try:
            os.system('stty sane 2>/dev/null')
        except Exception:
            pass
    
    # Дополнительно: восстановление через termios для установки критических флагов
    try:
        import termios
        # Пробуем через /dev/tty напрямую
        try:
            with open('/dev/tty', 'r+b') as tty_fd:
                fd = tty_fd.fileno()
                attrs = termios.tcgetattr(fd)
                # Устанавливаем критически важные флаги для cooked mode
                attrs[3] = attrs[3] | termios.ICANON | termios.ECHO | termios.ISIG
                attrs[3] = attrs[3] | termios.ICRNL
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except (OSError, termios.error, FileNotFoundError):
            # Если не получилось через /dev/tty, пробуем через stdin
            try:
                fd = sys.stdin.fileno()
                if fd >= 0:
                    attrs = termios.tcgetattr(fd)
                    attrs[3] = attrs[3] | termios.ICANON | termios.ECHO | termios.ISIG
                    attrs[3] = attrs[3] | termios.ICRNL
                    termios.tcsetattr(fd, termios.TCSANOW, attrs)
            except (OSError, termios.error):
                pass
    except (ImportError, AttributeError):
        pass
    except Exception:
        pass
    
    # Принудительно сбрасываем буферы
    try:
        sys.stdin.flush()
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass


def _read_nonempty_lines(path: Path, skip_comments: bool = False) -> list[str]:
    if not path.exists():
        return []
    result: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if skip_comments and line.startswith("#"):
            continue
        result.append(line)
    return result


def _nuclei_profiles(mode: str) -> dict[str, dict[str, str]]:
    if mode == "web":
        return {
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
    return {
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


def _build_nuclei_cmd(nuclei_bin: str, input_file: Path, mode: str, profile: str) -> list[str]:
    cfg = _nuclei_profiles(mode).get(profile, _nuclei_profiles(mode)["fast"])
    return [
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
        str(input_file),
    ]


def _run_nuclei_command(cmd: list[str], out_path: Path, mode: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=900,
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
                import json

                data = json.loads(line)
                findings += 1
                sev = str(data.get("info", {}).get("severity") or "").lower()
                if sev:
                    severities[sev] = severities.get(sev, 0) + 1
            except Exception:
                continue
        prefix = f"nuclei-{mode}"
        if proc.returncode != 0:
            first_line = combined.splitlines()[0] if combined else ""
            print(f"⚠️  {prefix} ошибка (код {proc.returncode}) {first_line}")
        print(f"{prefix}: {findings} ({', '.join(f'{k}={v}' for k, v in sorted(severities.items()))})")
    except subprocess.TimeoutExpired:
        out_path.write_text("", encoding="utf-8")
        print(f"⚠️  nuclei-{mode} timeout")


def _ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    default_hint = "y/N" if default_no else "Y/n"
    answer = input(f"{prompt} [{default_hint}]: ").strip().lower()
    if not answer:
        return not default_no
    return answer in {"y", "yes", "д", "да"}


def _prompt_nuclei_after_run(completed_runs: list[tuple[Target, Path]]) -> None:
    if not completed_runs:
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return

    preferred = Path.home() / ".cache" / "reconx" / "bin" / "nuclei"
    nuclei_bin = str(preferred) if preferred.exists() else shutil.which("nuclei")
    if not nuclei_bin:
        print("ℹ️  nuclei не найден — пост-скан пропущен.")
        return

    tasks: list[dict[str, object]] = []
    for target, run_dir in completed_runs:
        processed_dir = run_dir / "processed"
        raw_web_dir = run_dir / "raw" / "web"
        raw_scan_dir = run_dir / "raw" / "scan"

        web_unic = processed_dir / "alive-urls-unic.txt"
        web_plain = processed_dir / "alive-urls.txt"
        web_input = web_unic if _read_nonempty_lines(web_unic) else web_plain
        web_lines = _read_nonempty_lines(web_input, skip_comments=True)
        if web_lines:
            tasks.append(
                {
                    "target": target.raw,
                    "mode": "web",
                    "input_path": web_input,
                    "count": len(web_lines),
                    "out_path": raw_web_dir / "nuclei-web.json",
                }
            )

        net_input = processed_dir / "open-ports.txt"
        net_lines = _read_nonempty_lines(net_input, skip_comments=True)
        if net_lines:
            tasks.append(
                {
                    "target": target.raw,
                    "mode": "net",
                    "input_path": net_input,
                    "count": len(net_lines),
                    "out_path": raw_scan_dir / "nuclei-net.json",
                }
            )

    if not tasks:
        print("ℹ️  Ресурсов для запуска nuclei не найдено.")
        return

    profile = "fast"
    selected = input("\n🧪 Nuclei профиль (fast/full, Enter=fast): ").strip().lower()
    if selected in {"fast", "full"}:
        profile = selected

    for task in tasks:
        target = str(task["target"])
        mode = str(task["mode"])
        input_path = Path(task["input_path"])
        out_path = Path(task["out_path"])
        count = int(task["count"])
        cmd = _build_nuclei_cmd(nuclei_bin, input_path, mode=mode, profile=profile)
        cmd_preview = " ".join(cmd)
        print(f"\n🔍 {target} [{mode}] ресурсов: {count}")
        print(f"   cmd: {cmd_preview}")
        print(f"   out: {out_path}")
        if _ask_yes_no("Запустить nuclei?", default_no=True):
            _run_nuclei_command(cmd, out_path, mode=mode)


def _run_init(args: argparse.Namespace) -> int:
    root_dir: Path | None = None
    completed_runs: list[tuple[Target, Path]] = []

    try:
        _ensure_data_dir_env()
        data_dir = get_data_dir()
        ensure_data_dir(data_dir)
        # Проверяем/догружаем внешние инструменты
        bin_dir, binaries, warnings, notes = ensure_external_tools()
        if warnings:
            for msg in warnings:
                print(f"⚠️  {msg}", file=sys.stderr)
        if notes:
            for msg in notes:
                print(f"ℹ️  {msg}")
        if binaries:
            print(f"\n🔧 Tools: " + ", ".join(sorted(binaries.keys())))
            print(f"📁 bin: {bin_dir}")

        targets: list[Target] = load_targets(
            list_path=args.list_path,
            inline_targets=args.targets,
        )

        if not targets:
            print("❌ Не указаны цели. Используйте позиционные аргументы или -l", file=sys.stderr)
            return 1

        output_root = Path(getattr(args, "output_root", _default_data_dir()))
        module = WorkspaceModule(output_root=output_root, list_id=args.list_id)
        root_dir = module.create_root(targets)

        aggression_label = {
            1: "invisible (smap: -iL ... -oJ -)",
            2: "balance (naabu: -top-ports 1000; nmap: -Pn -n -sS -sV --version-light -T3 --open --max-retries 2 --host-timeout 90s)",
            3: "for blood (naabu: -p -; nmap: -Pn -sS -A -T4 --script vuln,discovery,safe --max-retries 2 --host-timeout 180s)",
        }.get(args.aggression, str(args.aggression))
        print(f"🗂  Root: {root_dir}")
        print(f"💥 Aggression: {aggression_label}")

        # Обработка целей в порядке входного списка
        for target in targets:
            print("\n" + "-" * 50)
            if target.kind == "domain":
                try:
                    target_dir = module.create_target_layout(target)
                except FileExistsError as error:
                    print(f"❌ {error}", file=sys.stderr)
                    continue
                print(f"\n🌐 Домен: {target.raw} (enum)")
                print(f"📂 Run: {target_dir}")
                EnumModule(
                    target_dir,
                    aggression=args.aggression,
                    nuclei_profile=None,
                    single_mode=True,
                    debug=args.debug,
                ).run([target])
                completed_runs.append((target, target_dir))
            elif target.kind == "ip":
                try:
                    target_dir = module.create_target_layout(target)
                except FileExistsError as error:
                    print(f"❌ {error}", file=sys.stderr)
                    continue
                print(f"\n📡 IP: {target.raw} (scan)")
                print(f"📂 Run: {target_dir}")
                ProbeModule(
                    target_dir,
                    aggression=args.aggression,
                    nuclei_profile=None,
                    single_mode=True,
                    debug=args.debug,
                ).run([target])
                completed_runs.append((target, target_dir))

        _prompt_nuclei_after_run(completed_runs)

        print("\n✅ Готово")
        return 0

    except KeyboardInterrupt:
        # ВАЖНО: Восстанавливаем терминал ПЕРЕД выводом сообщения
        # Это позволяет readline правильно работать после восстановления
        _restore_terminal()
        # Принудительно выводим символ новой строки и сбрасываем буферы
        try:
            sys.stdout.write('\n')
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        print("⏹ Прервано пользователем (Ctrl+C)", file=sys.stderr)
        return 130
    except (FileNotFoundError, ValueError) as error:
        print(f"❌ {error}", file=sys.stderr)
        if root_dir and root_dir.exists():
            shutil.rmtree(root_dir, ignore_errors=True)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "debug", False):
        print("[debug] reconx start")
        print(f"[debug] argv: {argv}")
        print(f"[debug] cwd: {Path.cwd()}")
        print(f"[debug] output_root: {getattr(args, 'output_root', _default_data_dir())}")
        print(f"[debug] targets: {args.targets}")
        print(f"[debug] list_path: {args.list_path}")
        print(f"[debug] aggression: {args.aggression}")
    return _run_init(args)


if __name__ == "__main__":
    raise SystemExit(main())
