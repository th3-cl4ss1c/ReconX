from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from reconx.utils.targets import Target


class Module(ABC):
    """Базовый класс для модулей ReconX."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def run(self, targets: Iterable[Target]) -> Path:
        """Выполнить модуль и вернуть путь к результатам."""
        raise NotImplementedError



