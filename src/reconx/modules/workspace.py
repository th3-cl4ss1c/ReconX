from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable
import re

from reconx.modules.base import Module
from reconx.utils.targets import Target, date_token


class WorkspaceModule(Module):
    """Создать каркас каталогов и файлов под цели разведки."""

    name = "workspace"
    description = "Генерация структуры хранения артефактов для целей."

    def __init__(
        self,
        output_root: str | Path = ".",
        list_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        self.output_root = Path(output_root)
        self.list_id = list_id
        self.now = now or datetime.now()
        self.root_dir: Path | None = None
        self._name_counts: dict[str, int] = {}
        self._single_mode: bool = True

    @property
    def is_single_mode(self) -> bool:
        return self._single_mode

    def run(self, targets: Iterable[Target]) -> Path:
        target_list = list(targets)
        if not target_list:
            raise ValueError("Не переданы цели для создания структуры.")

        root_dir = self.create_root(target_list)

        for target in target_list:
            self.create_target_layout(target)

        return root_dir

    def create_root(self, targets: Iterable[Target]) -> Path:
        target_list = list(targets)
        if not target_list:
            raise ValueError("Не переданы цели для создания структуры.")
        root_dir = self.output_root
        root_dir.mkdir(parents=True, exist_ok=True)
        self.root_dir = root_dir
        return root_dir

    def create_target_layout(self, target: Target) -> Path:
        if self.root_dir is None:
            raise ValueError("Root не создан. Вызовите create_root перед созданием целей.")
        domain_dir = self.root_dir / target.folder_name
        domain_dir.mkdir(parents=True, exist_ok=True)
        run_dir = domain_dir / self._next_run_dir_name(domain_dir)
        run_dir.mkdir(parents=True, exist_ok=False)

        layout = {
            run_dir / "scope" / "in-scope.txt": "# Добавьте цели в scope\n",
            run_dir / "scope" / "out-of-scope.txt": "# Исключения\n",
            run_dir / "raw" / "enum" / "subfinder.txt": "",
            run_dir / "raw" / "scan" / "smap.json": "",
            run_dir / "raw" / "web" / "httpx.json": "[]\n",
            run_dir / "raw" / "web" / "headers.txt": "",
            run_dir / "raw" / "urls" / "gau.txt": "",
            run_dir / "raw" / "urls" / "gau-clean.txt": "",
            run_dir / "raw" / "urls" / "gau-core.txt": "",
            run_dir / "raw" / "urls" / "gau-subs.txt": "",
            run_dir / "raw" / "urls" / "paramspider.txt": "",
            run_dir / "raw" / "breach" / "snusbase.json": "{}\n",
            run_dir / "raw" / "humans" / "README.md": "# Данные о людях\n",
            run_dir / "raw" / "humans" / "hunter.json": "{}\n",
            run_dir / "processed" / "subdomains.txt": "",
            run_dir / "processed" / "alive.txt": "",
            run_dir / "processed" / "alive-urls.txt": "",
            run_dir / "processed" / "alive-urls-unic.txt": "",
            run_dir / "processed" / "open-ports.txt": "",
            run_dir / "reports" / "README.md": "# Сюда складывайте отчёты, скрины, эксплойты\n",
            run_dir / "notes.md": self._notes_template(target),
        }

        for path, content in layout.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(content, encoding="utf-8")
        return run_dir

    def _notes_template(self, target: Target) -> str:
        created = self.now.isoformat(timespec="seconds")
        header = f"# Notes for {target.raw}\n\n"
        meta = f"- created: {created}\n"
        return header + meta

    def _next_run_dir_name(self, domain_dir: Path) -> str:
        pattern = re.compile(r"^(\d+)_\d{2}-\d{2}-\d{2}$")
        max_num = 0
        if domain_dir.exists():
            for entry in domain_dir.iterdir():
                if not entry.is_dir():
                    continue
                match = pattern.match(entry.name)
                if not match:
                    continue
                try:
                    num = int(match.group(1))
                except ValueError:
                    continue
                if num > max_num:
                    max_num = num
        next_num = max_num + 1
        return f"{next_num}_{date_token(self.now)}"

