# Словари Night Scout

Night Scout разделяет **загрузку локального corpus во время recon** и
**синхронизацию публичных словарей**.

Recon-loop читает только локальные файлы из `manifest.yaml` (или другого
локального manifest из pipeline). SecLists, Assetnote и Trickest никогда не
скачиваются автоматически во время работы по цели.

## Структура

```text
wordlists/
├── manifest.yaml          # маленький встроенный bootstrap corpus
├── sources.yaml           # каталог upstream-источников для sync-скрипта
├── builtins/              # небольшие списки Night Scout в репозитории
├── cache/                 # внешние corpora, gitignored
└── generated/             # lock + локальный runtime manifest, gitignored
```

Посмотреть источники:

```bash
python scripts/wordlists_sync.py list
```

Скачать консервативный набор по умолчанию:

```bash
python scripts/wordlists_sync.py sync
```

Большие источники не скачиваются автоматически. Например:

```bash
python scripts/wordlists_sync.py sync \
  --source assetnote.manual.2m-subdomains
```

Все источники:

```bash
python scripts/wordlists_sync.py sync --all
```

После sync появляются:

```text
wordlists/generated/sources.lock.yaml
wordlists/generated/manifest.local.yaml
```

`lock` фиксирует фактические SHA-256 исходных байтов и нормализованного локального
corpus. Чтобы использовать внешний corpus, укажи в pipeline:

```yaml
intelligence:
  wordlists:
    manifest: wordlists/generated/manifest.local.yaml
    corpus_root: wordlists
```

Проверка локальных файлов по lock:

```bash
python scripts/wordlists_sync.py verify
```

Upstream-списки не объединяются в один `sort -u`: runtime сохраняет source id,
категорию, вес, provenance и дальше смешивает public corpus с Target Genome и
historical yield, сохраняя отдельные TARGETED/EXPLORATION lanes.
