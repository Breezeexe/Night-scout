# Night Scout

> Рекурсивная, scope-aware разведка поверхности атаки для авторизованных исследований безопасности.

[English version](README.md) · [Архитектура](docs/ARCHITECTURE_RU.md)

Night Scout координирует инструменты разведки вокруг постоянной модели
авторизованного target. Он обнаруживает assets, сохраняет происхождение каждого
факта, превращает новые observations в следующие задачи и показывает понятную
поверхность атаки вместо набора несвязанных выводов сканеров.

Проект предназначен для bug bounty и defensive research. Это не автономный
фреймворк эксплуатации уязвимостей.

## Что даёт Night Scout

- строгий YAML scope с exclusions, restrictions, budgets и общими rate limits;
- рекурсивный поиск через домены, DNS, HTTP, TLS, архивы, JavaScript и локальные mobile artifacts;
- durable SQLite workspaces с pause, resume и восстановлением после прерывания;
- provenance observations и дедуплицированный semantic surface graph;
- confidence, novelty, expected yield и convergence без обхода policy gates;
- ограниченный параллелизм с per-worker limits и backpressure записи событий;
- JSONL/TXT/CSV списки, graph JSON, tree JSON и автономный HTML explorer.

Граф следует привычному исследовательскому маршруту:

```text
корневой домен
└── подтверждённый поддомен или гипотеза
    ├── DNS-записи / IP-адреса
    └── HTTP-сервис
        ├── endpoints и вложенные пути
        ├── параметры и JavaScript
        ├── технологии и fingerprints
        ├── сертификат
        └── возможные или подтверждённые находки
```

## Модель безопасности

Night Scout воспринимает scope как разрешение, а не как подсказку обнаружения.
Hostname из сертификата, архива, ASN или CNAME заново классифицируется до
активной проверки. Confidence и novelty влияют на приоритет, но не обходят
scope, restrictions, review gates, budgets или rate limits. Неизвестные active
targets блокируются, а экспорт sensitive evidence требует двойного opt-in.

Запускайте Night Scout только для assets, на тестирование которых у вас есть
разрешение.

## Установка

Поддерживаемые release-платформы: Debian 13+ и актуальный Kali Linux на `amd64`
или `arm64`.

Скачайте подходящий `.deb` из GitHub Releases и установите его через APT:

```bash
sudo apt install ./nightscout_<version>_amd64.deb
nightscout --version
```

Локальная сборка:

```bash
git clone https://github.com/Breezeexe/Night-scout
cd Night-scout
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[release]'
python scripts/build_deb.py
```

## Первоначальная настройка

Выполняйте setup от имени обычного пользователя, который будет запускать
разведку:

```bash
nightscout setup
nightscout doctor
```

Не запускайте сам `nightscout setup` через `sudo`. При необходимости он сам
вызывает APT через `sudo` для явного allow-list пакетов. Изменяемые данные
размещаются по XDG-каталогам:

```text
~/.config/nightscout/       конфигурация и scopes
~/.local/share/nightscout/  workspaces, tools, wordlists и artifacts
~/.cache/nightscout/        удаляемые кэши
```

Полезные варианты:

```bash
nightscout setup --skip-tools --skip-wordlists
nightscout setup --optional-tools
nightscout setup --update-tools
```

## Первый авторизованный запуск

Создайте scope, буквально отражающий правила программы. Exact assets остаются
exact, wildcard — wildcard, а exclusions получают больший priority. Нельзя
выводить разрешение из ownership или общей инфраструктуры.

```yaml
schema_version: 1
target_id: example-program
display_name: Example Bug Bounty Program
gate:
  allow_unknown_passive: false
rules:
  - rule_id: main-wildcard
    kind: DOMAIN
    pattern: "*.example.com"
    state: IN_SCOPE
    priority: 100
    tier: L1
    reason: Explicitly listed by the program

  - rule_id: excluded-admin
    kind: DOMAIN
    pattern: admin.example.com
    state: OUT_OF_SCOPE
    priority: 300
    reason: Explicit program exclusion
```

Запустите frontier, полученный из scope:

```bash
nightscout doctor --scope ./program.yaml
nightscout run --scope ./program.yaml
```

Несколько разрешённых доменов могут находиться в одном workspace программы.
`target_id` — его стабильная идентичность. Для быстрого локального запуска
`nightscout run example.com` интерактивно запрашивает разрешение; в автоматизации
можно использовать `--authorize-exact` или `--authorize-subdomains`.

Полные шаблоны находятся в
[`configs/scope.example.yaml`](configs/scope.example.yaml) и
[`configs/pipeline.example.yaml`](configs/pipeline.example.yaml). Скопируйте и
проверьте их: файлы с `.example.` намеренно не принимаются как рабочая
конфигурация.

## Основные команды

```bash
# Запустить или продолжить durable frontier.
nightscout run --scope ./program.yaml --max-steps 100

# Посмотреть состояние и объяснить сохранённое observation.
nightscout status --scope ./program.yaml
nightscout explain <event-id-or-exact-value> --scope ./program.yaml

# Разрешить задачи, остановленные policy/review gates.
nightscout review list --scope ./program.yaml
nightscout review show <case-id> --scope ./program.yaml
nightscout review approve <case-id> --scope ./program.yaml --reason "authorized"
nightscout review reject <case-id> --scope ./program.yaml --reason "not authorized"

# Экспортировать поверхность атаки.
nightscout export --scope ./program.yaml --format graph-json
nightscout export --scope ./program.yaml --format tree-json --root example.com --max-depth 6
nightscout export --scope ./program.yaml --format html

# Восстановить semantic relationships в старом workspace.
nightscout graph rebuild --scope ./program.yaml --dry-run
nightscout graph rebuild --scope ./program.yaml
```

`nightscout export` без `--format` записывает все включённые SAFE exports.
Sensitive material дополнительно требует `--sensitive` и
`--confirm-sensitive`.

После каждого запуска `nightscout run` без `--json` итоговая сводка печатает
готовые команды: экспорт автономного HTML explorer, его открытие через
`xdg-open`, а также запись canonical graph и rooted tree в JSON. В командах
сохраняются именно те pipeline и scope, с которыми выполнялся запуск.

## Документация

- [Цель и архитектура](docs/ARCHITECTURE_RU.md)
- [Purpose and architecture — English](docs/ARCHITECTURE.md)
- [Шаблон pipeline](configs/pipeline.example.yaml)
- [Шаблон scope](configs/scope.example.yaml)
- [Manifest companion tools](scripts/tools_manifest.yaml)

Архитектурный документ объясняет event и surface graphs, lifecycle,
параллельный dispatcher, policy gates, intelligence-модели, persistence,
workers, exports и точки расширения.

## Разработка

Night Scout требует Python 3.12+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
mypy recon
```

Тесты используют adapters и fake subprocesses; обычные unit- и integration
tests не обращаются к целям разведки. Изменения базы должны оформляться через
Alembic migrations.

## Текущие границы

- admission одного workspace принадлежит одному процессу Night Scout;
- source of truth — SQLite, внешняя graph database не требуется;
- специализированные recon binaries управляются отдельно;
- GraphML и distributed dispatch возможны в будущем, но пока не являются контрактами.
