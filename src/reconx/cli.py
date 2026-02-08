from __future__ import annotations

import argparse
import sys
from pathlib import Path
import shutil
import os

# Загружаем конфигурацию провайдеров из provider-config.yaml ПЕРЕД импортом модулей
# Используем только стандартное место ~/.config/reconx/provider-config.yaml
# для совместимости с pipx и изолированными окружениями
try:
    import yaml
    config_file = Path.home() / ".config" / "reconx" / "provider-config.yaml"
    if config_file.exists():
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
                for key, env_var in (
                    ("hunter_io", "HUNTER_API_KEY"),
                    ("snusbase", "SNUSBASE_API_KEY"),
                    ("deepseek_api", "DEEPSEEK_API_KEY"),
                ):
                    val = config.get(key)
                    if val:
                        api_key = val[0] if isinstance(val, list) else val
                        os.environ[env_var] = str(api_key)
        except Exception:
            # Игнорируем ошибки чтения конфига
            pass
except ImportError:
    # PyYAML не установлен - конфиг не загружается
    pass
except Exception:
    # Игнорируем другие ошибки
    pass

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
        "-n",
        "--nuclei",
        dest="nuclei_profile",
        choices=["fast", "full"],
        help="Запуск nuclei (web+net). web: alive-urls.txt; net: open-ports.txt. fast (web): severity=medium,high,critical; tags=cves,misconfig,exposure; c=30; timeout=10. full (web): +technology; c=80; timeout=20. net fast: tags=network,default-login; net full: +cves,exposure; c=50/80.",
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


def _run_init(args: argparse.Namespace) -> int:
    root_dir: Path | None = None

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
                    nuclei_profile=args.nuclei_profile,
                    single_mode=True,
                    debug=args.debug,
                ).run([target])

                dnsx_path = target_dir / "raw" / "scan" / "dnsx.json"
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
                    nuclei_profile=args.nuclei_profile,
                    single_mode=True,
                    debug=args.debug,
                ).run([target])

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
        print(f"[debug] nuclei_profile: {args.nuclei_profile}")
    return _run_init(args)


if __name__ == "__main__":
    raise SystemExit(main())

