# ReconX

Модульный CLI-инструмент для подготовки и запуска разведки с единообразной структурой артефактов. Создаёт стандартное дерево директорий для целей (доменов и IP), запускает subfinder, shuffledns, dnsx, smap, naabu, nmap, httpx, nuclei и связанные утилиты.

## Установка

Через pipx (рекомендуется — изолированное окружение):

```bash
# Из репозитория
pipx install git+https://github.com/th3-cl4ss1c/ReconX.git

# Локально из клонированного репозитория
pipx install .

# Editable-режим для разработки
pipx install --editable .
```

Обновление:

```bash
pipx reinstall reconx
```

Если установлено с GitHub — pipx подтянет последний коммит. Чтобы принудительно переустановить поверх существующей установки: `pipx install --force git+https://github.com/th3-cl4ss1c/ReconX.git`

Быстрый старт для разработки:

```bash
./setup_dev.sh
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

# Запуск nuclei после enum/scan
reconx example.com --nuclei fast
reconx example.com --nuclei full

# Подробный лог (nmap, таймауты и т.д.)
reconx example.com --debug
```

## Внешние инструменты

При первом запуске ReconX автоматически скачивает все нужные утилиты в `~/.cache/reconx/bin` (готовые бинари с GitHub Releases, без Go). Если загрузка не удалась — пробует `go install` как запасной вариант.

- **DNS/enum**: subfinder, shuffledns, massdns, dnsx
- **Сканирование**: smap, naabu, nmap
- **Web/URL**: httpx, gau, paramspider
- **Vuln**: nuclei
- **Провайдеры**: hunter.io, snusbase (API-ключи в конфиге)

## Конфигурация

API-ключи в `~/.config/reconx/provider-config.yaml`:

```yaml
hunter_io: [your_hunter_api_key]
snusbase: [your_snusbase_api_key]
deepseek_api: [your_deepseek_api_key]
```

Без конфига соответствующие провайдеры пропускаются.

## Данные

Каталог `~/.local/share/reconx/` (или `RECONX_DATA_DIR`):

- `resolvers.txt` — копируется из пакета при первом запуске
- `wordlists/` — wordlist для subdomain bruteforce (SecLists, скачивается автоматически)

## Лицензия

MIT — см. [LICENSE](LICENSE).
