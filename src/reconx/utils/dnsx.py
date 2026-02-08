from __future__ import annotations

import json
from pathlib import Path
from typing import Set


def extract_ips_from_dnsx_file(path: Path) -> Set[str]:
    """
    Извлечь A/AAAA из файла dnsx JSONL.
    """
    ips: Set[str] = set()
    if not path.exists():
        return ips
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for key in ("a", "aaaa"):
                    vals = obj.get(key) or []
                    if isinstance(vals, str):
                        vals = [vals]
                    for v in vals:
                        s = str(v).strip()
                        if s:
                            ips.add(s)
    except Exception:
        return ips
    return ips


