# ReconX

Модульный CLI-инструмент для подготовки и запуска разведки с единообразной структурой артефактов. Создаёт стандартное дерево директорий для целей (доменов и IP), запускает subfinder, shuffledns, dnsx, smap, naabu, nmap, httpx, nuclei и связанные утилиты.

## Установка (pipx)

1. Установите `pipx` (один раз на систему):

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
```

После `ensurepath` откройте новый shell, чтобы `pipx`/`reconx` были в `PATH`.

2. Установите ReconX:

```bash
pipx install git+https://github.com/th3-cl4ss1c/ReconX.git
reconx --version
```

Запуск без установки (полезно для быстрой проверки):

```bash
pipx run --spec git+https://github.com/th3-cl4ss1c/ReconX.git reconx --help
```

Локальная установка из клонированного репозитория (обычное использование):

```bash
pipx install .
```

Для разработки (рекомендуется локальный editable, не удалённый `git+...`):

```bash
pipx install --force --editable .
```

Удалённый `git+...` удобен для пользовательской установки, но не для локальной разработки (изменения в рабочей директории не подхватываются сразу).

## Проверка установки в Docker (чистый Debian + pipx)

Требуется установленный Docker.
Это опциональный smoke-тест для CI/проверки окружения. Основной способ работы — установка напрямую через `pipx`.

```bash
bash scripts/test_install_debian_pipx.sh
```

По умолчанию тест ставит пакет из локального каталога (`SPEC=.`). Для проверки установки из GitHub:

```bash
SPEC='git+https://github.com/th3-cl4ss1c/ReconX.git' bash scripts/test_install_debian_pipx.sh
```

## Обновление и удаление

```bash
# Переустановить текущий источник пакета
pipx reinstall reconx

# Принудительно обновить из GitHub (поверх существующей установки)
pipx install --force git+https://github.com/th3-cl4ss1c/ReconX.git

# Удалить
pipx uninstall reconx
```

## Системные зависимости

ReconX автоматически скачивает нужные утилиты в `~/.cache/reconx/bin` при первом запуске.

- Автоуправляемые утилиты: `dnsvalidator` (wrapper для `vortexau/dnsvalidator`), `subfinder`, `shuffledns`, `massdns`, `dnsx`, `smap`, `naabu`, `httpx`, `nuclei`, `katana`, `gau`, `vulnx`.
- Системно рекомендуется: `nmap` (для уровней агрессии `2` и `3`) и `build-essential` (для fallback-сборки `massdns`, если готовый бинарь недоступен).

Пример для Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y nmap build-essential
```

## Использование

```bash
# Одиночная цель (домен или IP)
reconx example.com
reconx 1.2.3.4

# Список целей из файла
reconx -l targets.txt

# Уровень агрессии сканирования: 1|2|3
reconx example.com -a 1   # invisible (smap)
reconx example.com -a 2   # balance (naabu top + nmap -A -T3)
reconx example.com -a 3   # for blood (naabu all + nmap vuln)

# Идентификатор каталога для списка целей
reconx -l targets.txt --list-id custom01

# После завершения основного цикла CLI спросит, запускать ли nuclei
# и покажет команду для найденных ресурсов (web/net)

# Подробный лог (nmap, таймауты и т.д.)
reconx example.com --debug

# Обновить resolvers через dnsvalidator в течение 500 секунд
reconx -pr 500

# Обновить resolvers через dnsvalidator в 100 потоков
reconx -pr 500 -prt 100

# Обновить resolvers и сразу запустить enum/scan
reconx -pr 500 -prt 100 example.com
```

`-pr/--parse-resolve N` запускает `dnsvalidator` (из `vortexau/dnsvalidator`) на `N` секунд и сохраняет валидные резолверы в `~/.local/share/reconx/resolvers.txt` (или `RECONX_DATA_DIR/resolvers.txt`).
Базовый вызов: `dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o <path>`.
Число потоков по умолчанию: `20`, изменить можно через `-prt/--parse-resolve-threads`.
Источник кандидатов можно переопределить через `RECONX_DNSVALIDATOR_TARGETS_URL`.

## Конфигурация

Основной приоритет источников ключей:

1. `ENV` (`HUNTER_API_KEY`, `SNUSBASE_API_KEY`)
2. `Bitwarden CLI` (`bw`)
3. `provider-config.yaml` (опциональный fallback)

### Вариант 1: ENV (самый простой)

```bash
export HUNTER_API_KEY="..."
export SNUSBASE_API_KEY="..."
```

### Вариант 2: Bitwarden CLI (рекомендуется)

По умолчанию ReconX ищет items:
- `hunter` (поле `password`)
- `snusbase` (поле `password`)

Переопределить item/поле можно через ENV:

```bash
export RECONX_BW_HUNTER_ITEM="my/hunter-item"
export RECONX_BW_HUNTER_FIELD="password"      # или custom:FIELD
export RECONX_BW_SNUSBASE_ITEM="my/snus-item"
export RECONX_BW_SNUSBASE_FIELD="password"    # или custom:FIELD
```

Если `BW_SESSION` не задан, ReconX в интерактивном TTY предложит скрыто ввести готовый ключ `BW_SESSION` (Enter — пропустить).
Если вставка в скрытый prompt не сработала, ReconX автоматически предложит второй (видимый) prompt.
Если введённый `BW_SESSION` невалиден, ReconX предложит ввести другой ключ; для пропуска достаточно нажать Enter.

Подготовить ключ заранее:

```bash
bw login
export BW_SESSION="$(bw unlock --raw)"
```

Альтернатива для запуска только текущей команды (без глобального `export`):

```bash
RECONX_BW_SESSION="$(bw unlock --raw)" reconx example.com
```

### Вариант 3: `provider-config.yaml` (опционально)

```bash
mkdir -p ~/.config/reconx
cp provider-config.yaml.example ~/.config/reconx/provider-config.yaml
```

Пример `~/.config/reconx/provider-config.yaml`:

```yaml
hunter_io: [your_hunter_api_key]
snusbase: [your_snusbase_api_key]
# Опционально: явные ссылки на Bitwarden item/field
hunter_io_bw_item: hunter
hunter_io_bw_field: password
snusbase_bw_item: snusbase
snusbase_bw_field: password
```

## Данные

Каталог `~/.local/share/reconx/` (или `RECONX_DATA_DIR`):

- `resolvers.txt` — копируется из пакета при первом запуске
- `resolvers.txt` — можно обновить через `reconx -pr <seconds>` (dnsvalidator)
- `wordlists/` — wordlist для subdomain bruteforce (SecLists, скачивается автоматически)

## Лицензия

MIT — см. [LICENSE](LICENSE).
