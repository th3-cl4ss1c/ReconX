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

Локальная установка из клонированного репозитория:

```bash
pipx install .
```

Для разработки (editable-режим):

```bash
./setup_dev.sh
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

- Автоуправляемые утилиты: `subfinder`, `shuffledns`, `massdns`, `dnsx`, `smap`, `naabu`, `httpx`, `nuclei`, `katana`, `gau`, `vulnx`.
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

# Запуск nuclei после enum/scan
reconx example.com --nuclei fast
reconx example.com --nuclei full

# Подробный лог (nmap, таймауты и т.д.)
reconx example.com --debug
```

## Конфигурация

Скопируйте пример и заполните API-ключи:

```bash
mkdir -p ~/.config/reconx
cp provider-config.yaml.example ~/.config/reconx/provider-config.yaml
```

Файл `~/.config/reconx/provider-config.yaml`:

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
