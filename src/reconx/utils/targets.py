from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class Target:
    """Единичная цель (домен или IP)."""

    raw: str
    kind: str  # "domain" | "ip"
    slug: str
    folder_name: str


def _normalize(text: str) -> str:
    return text.strip()


def _safe_dir_name(value: str) -> str:
    """Обезопасить имя каталога для файловой системы."""
    cleaned = value.replace(":", "_").replace("/", "_").replace("\\", "_")
    return cleaned or "target"


def slugify(value: str) -> str:
    """Сделать короткий slug для корневого каталога."""
    lower = value.lower()
    safe = "".join(ch if ch.isalnum() else "_" for ch in lower)
    compact = "_".join(part for part in safe.split("_") if part)
    return compact or "target"


def parse_target_value(value: str) -> Target:
    raw = _normalize(value)
    if not raw:
        raise ValueError("Пустое значение цели.")

    try:
        ipaddress.ip_address(raw)
        kind = "ip"
    except ValueError:
        kind = "domain"

    return Target(
        raw=raw,
        kind=kind,
        slug=slugify(raw),
        folder_name=_safe_dir_name(raw),
    )


def deduplicate_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for val in values:
        normalized = _normalize(val)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def load_targets(list_path: str | None, inline_targets: Iterable[str]) -> List[Target]:
    candidates: List[str] = []

    if list_path:
        path = Path(list_path)
        if not path.exists():
            raise FileNotFoundError(f"Файл со списком целей не найден: {path}")
        with path.open("r", encoding="utf-8") as handle:
            candidates.extend(handle.readlines())

    candidates.extend(inline_targets)

    targets = [parse_target_value(item) for item in deduplicate_preserve_order(candidates)]
    return targets


def generate_list_id() -> str:
    return uuid.uuid4().hex[:8]


def date_token(now: datetime | None = None) -> str:
    """Вернуть токен даты вида DD-MM-YY."""
    current = now or datetime.now()
    return current.strftime("%d-%m-%y")



