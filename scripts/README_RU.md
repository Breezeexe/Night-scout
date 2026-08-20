# Maintenance scripts Night Scout

Скрипты в этой директории — явные setup/release helpers и не входят в recursive
target-contact loop.

`wordlists_sync.py` синхронизирует публичные corpora в `wordlists/cache/`,
фиксирует SHA-256 lock и создаёт локальный runtime manifest. Сеть используется
только после явного запуска команды `sync`.


## `install_tools.py` / `tools_manifest.yaml`

Управление внешними утилитами только для Debian/Kali. Те же команды доступны
из будущего standalone binary, поэтому системный Python пользователю не нужен:

```bash
nightscout tools list
nightscout tools install
nightscout tools install --optional --install-prerequisites
nightscout tools verify
```

По умолчанию binaries живут в `~/.local/share/nightscout/tools/bin`; runtime сам
добавляет этот каталог в PATH workers. Установка APT-first для явно разрешённых
Debian/Kali пакетов; PDTM, pipx и официальные release assets используются только
как fallback, если distro-пакета нет или его binary не проходит проверку.

## `build_binary.py`

Собирает Linux standalone distribution через `PyInstaller --onedir` и `.tar.gz`.
Build host намеренно ограничен Debian/Kali.

## `verify_release.py`

Проверяет release bundle без любого reconnaissance-трафика к целям.

## `build_deb.py`

Собирает installable Debian/Kali пакет, который используется и локальной
сборкой, и tagged GitHub Releases. Если `release/dist/nightscout` отсутствует,
скрипт сначала вызывает `build_binary.py`.

```bash
python scripts/build_deb.py
sudo apt install ./release/nightscout_0.1.0_amd64.deb
nightscout setup
```

Пакет кладёт one-folder runtime в `/usr/lib/nightscout/` и создаёт команду
`/usr/bin/nightscout`. Изменяемые данные пользователя остаются в XDG-каталогах,
а не в `/usr`.
