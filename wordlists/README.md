# Night Scout wordlists

Night Scout deliberately separates **runtime corpus loading** from **upstream
wordlist synchronization**.

The recon loop only reads local files from `manifest.yaml` (or another local
manifest you configure). It never downloads SecLists, Assetnote or Trickest
while scanning a target.

## Layout

```text
wordlists/
├── manifest.yaml          # bundled, small, always-local bootstrap corpus
├── sources.yaml           # upstream catalog used only by the sync script
├── builtins/              # small Night Scout lists kept in the repository
├── cache/                 # downloaded/normalized external corpora; gitignored
└── generated/             # local lock + generated runtime manifest; gitignored
```

The bundled corpus is intentionally small. It lets TARGETED/EXPLORATION logic
work on a clean checkout while target-specific vocabulary from JS, URLs,
certificates, mobile artifacts, parameters and naming patterns remains the
primary adaptive source.

## Synchronize public corpora

List available sources:

```bash
python scripts/wordlists_sync.py list
```

Download the conservative default set:

```bash
python scripts/wordlists_sync.py sync
```

Large optional sources are not downloaded by default. To request one:

```bash
python scripts/wordlists_sync.py sync \
  --source assetnote.manual.2m-subdomains
```

Or synchronize the entire catalog:

```bash
python scripts/wordlists_sync.py sync --all
```

The sync step creates:

```text
wordlists/generated/sources.lock.yaml
wordlists/generated/manifest.local.yaml
```

`sources.lock.yaml` records the actual raw and normalized SHA-256 values used on
this machine. `manifest.local.yaml` contains only local paths and can be loaded
by `ManifestGlobalCorpus`.

To use the synchronized corpus, point the pipeline at:

```yaml
intelligence:
  wordlists:
    manifest: wordlists/generated/manifest.local.yaml
    corpus_root: wordlists
```

Verify the local cache against the lock file:

```bash
python scripts/wordlists_sync.py verify
```

## Why normalization happens during sync

Upstream lists have different shapes. Night Scout's central corpus is token
oriented, so the supply step applies bounded, source-declared transforms:

- `dns_labels`: hostname/subdomain material -> candidate labels;
- `parameter_names`: strict parameter-name validation;
- `path_tokens`: route/path material -> individual path/API tokens;
- `words`: conservative generic token normalization.

The original upstream bytes are hashed before transformation. The resulting
local corpus is hashed again. Both digests are recorded in the lock file.

## Provenance and ranking

A downloaded source is not merged into a blind `sort -u` mega-list. The
runtime manifest preserves `source_id`, categories, weight, upstream URL,
license metadata and hashes. `wordlists.py` then combines public corpus evidence
with target-specific vocabulary and historical yield while keeping TARGETED and
EXPLORATION lanes separate.

## External sources

`sources.yaml` currently includes selected material from SecLists, Assetnote /
Commonspeak2 and Trickest. These projects are independent from Night Scout;
their licenses and upstream terms remain applicable. Large files are intentionally
kept out of the Night Scout repository.
