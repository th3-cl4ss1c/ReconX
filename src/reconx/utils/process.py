from __future__ import annotations

import signal


def is_interrupt_returncode(returncode: int | None) -> bool:
    """
    Возвращает True, если код возврата соответствует завершению по Ctrl+C.
    """
    return returncode in {130, -signal.SIGINT}


def raise_on_interrupt_returncode(returncode: int | None) -> None:
    """
    Превращает сигнальный код возврата дочернего процесса в KeyboardInterrupt.
    """
    if is_interrupt_returncode(returncode):
        raise KeyboardInterrupt
