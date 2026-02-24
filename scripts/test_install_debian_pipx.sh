#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-reconx/debian-pipx:local}"
SPEC="${SPEC:-.}"
DOCKER_CONFIG_DIR="${DOCKER_CONFIG_DIR:-${TMPDIR:-/tmp}/reconx-docker-config}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "Ошибка: docker не найден"
  exit 1
fi

mkdir -p "${DOCKER_CONFIG_DIR}"

echo "[1/2] build ${IMAGE_TAG}"
DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" docker build -f "${REPO_ROOT}/Dockerfile.debian-pipx" -t "${IMAGE_TAG}" "${REPO_ROOT}"

echo "[2/2] test pipx install (${SPEC})"
DOCKER_CONFIG="${DOCKER_CONFIG_DIR}" docker run --rm \
  -v "${REPO_ROOT}:/workspace" \
  -w /workspace \
  -e SPEC="${SPEC}" \
  "${IMAGE_TAG}" \
  bash -lc "
    set -euo pipefail
    pipx install --force \"\${SPEC}\"
    reconx --version

    set +e
    OUTPUT=\$(reconx 2>&1)
    STATUS=\$?
    set -e

    echo \"\$OUTPUT\"
    if [ \"\$STATUS\" -ne 1 ]; then
      echo \"Ожидался код 1 от reconx без целей, получен \$STATUS\"
      exit 1
    fi

    if echo \"\$OUTPUT\" | grep -q 'Не найдены:'; then
      echo 'Ошибка: не все managed tools установились'
      exit 1
    fi

    echo 'OK: pipx install и bootstrap managed tools успешны'
  "
