#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v pipx >/dev/null 2>&1; then
  echo "Ошибка: pipx не найден."
  echo "Установите pipx и повторите:"
  echo "  python3 -m pip install --user pipx"
  echo "  python3 -m pipx ensurepath"
  exit 1
fi

pipx install --force --editable .
echo "reconx установлен в editable-режиме через pipx (обновление/переустановка выполнены)."
