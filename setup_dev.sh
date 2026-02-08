#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
pipx install --editable .
echo "reconx установлен в editable-режиме. Изменения в коде применяются сразу."
