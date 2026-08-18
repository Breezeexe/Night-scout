# Night Scout

> **Рекурсивная, scope-aware система анализа поверхности атаки для авторизованной bug-bounty разведки.**

Night Scout — это движок оркестрации разведки, предназначенный для непрерывного обнаружения, корреляции, запоминания и приоритизации поверхности атаки авторизованной цели.

В отличие от традиционного линейного recon pipeline, Night Scout рассматривает каждую полезную находку как новый источник разведданных. Hostname может привести к certificate; certificate может раскрыть другой hostname; JavaScript bundle может показать API path; архивная версия приложения может раскрыть историческое название проекта; это название проекта может улучшить target-specific vocabulary и породить новую гипотезу с высокой уверенностью.

Система строится вокруг пяти основных идей:

- **рекурсивное обнаружение**
- **постоянная память**
- **полный provenance**
- **строгая осведомлённость о scope**
- **адаптация разведки под конкретную цель**

Night Scout не предназначен для автономной эксплуатации уязвимостей. Его задача — картографировать, обогащать, связывать, приоритизировать и объяснять находки поверхности атаки внутри явно разрешённого bug-bounty scope.

---

# 1. Основная концепция

Обычный recon pipeline часто выглядит так:

```text
subdomains
    ↓
resolve
    ↓
HTTP probe
    ↓
scan
    ↓
done
```

Night Scout намеренно устроен иначе:

```text
DISCOVERY
    ↓
NORMALIZATION
    ↓
SCOPE / POLICY GATE
    ↓
DEDUPLICATION
    ↓
ENRICHMENT
    ↓
KNOWLEDGE BASE
    ↓
SCORING
    ↓
SCHEDULER
    ↓
NEW TASKS
    ↓
DISCOVERY
```

Система образует контролируемый feedback loop.

Одна находка может создавать новые events, а эти events могут активировать другие модули:

```text
certificate SAN
    ↓
hostname
    ↓
DNS
    ↓
HTTP service
    ↓
JavaScript
    ↓
API endpoint
    ↓
target vocabulary
    ↓
naming pattern
    ↓
bounded hypothesis
    ↓
new hostname
```

Цель рекурсии — не создание бесконечного трафика.

Её задача — сделать так, чтобы каждый новый фрагмент знаний о цели улучшал следующее решение разведки.

---

# 2. Высокоуровневая архитектура

```mermaid
flowchart TD
    A[Seeds] --> B[Discovery Workers]
    B --> C[Normalizer]
    C --> D[Scope / Policy Gate]
    D --> E[Deduplication]
    E --> F[Event Store]
    F --> G[Knowledge Graph]
    G --> H[Confidence / Novelty]
    H --> I[Target Genome]
    I --> J[Scheduler]
    J --> K[Task Queue]
    K --> B

    F --> L[Snapshots]
    L --> M[Diff Engine]

    D --> N[Policy Block]
    G --> O[Human Review Queue]

    F --> P[JSONL Export]
    F --> Q[TXT / CSV Export]
```

Night Scout является **слоем оркестрации и разведывательной логики**.

Он не должен заново реализовывать зрелые низкоуровневые возможности, такие как:

```text
DNS resolution
HTTP probing
TLS parsing
web crawling
archive retrieval
mobile decompilation
```

Вместо этого внешние инструменты подключаются через adapters, а их результаты нормализуются в events Night Scout.

---

# 3. Структура репозитория

```text
night-scout/
├── README.md
├── pyproject.toml
├── .gitignore
│
├── recon/
│   ├── __init__.py
│   ├── cli.py
│   │
│   ├── core/
│   │   ├── events.py
│   │   ├── queue.py
│   │   ├── router.py
│   │   ├── scheduler.py
│   │   ├── budgets.py
│   │   └── lifecycle.py
│   │
│   ├── policy/
│   │   ├── scope.py
│   │   ├── rate_limit.py
│   │   ├── restrictions.py
│   │   └── review_gate.py
│   │
│   ├── storage/
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── provenance.py
│   │   └── snapshots.py
│   │
│   ├── workers/
│   │   ├── passive_domains.py
│   │   ├── dns.py
│   │   ├── permutations.py
│   │   ├── http.py
│   │   ├── tls.py
│   │   ├── asn.py
│   │   ├── archives.py
│   │   ├── crawler.py
│   │   ├── javascript.py
│   │   ├── vhost.py
│   │   ├── content.py
│   │   ├── parameters.py
│   │   ├── mobile.py
│   │   └── fingerprints.py
│   │
│   ├── intelligence/
│   │   ├── vocabulary.py
│   │   ├── patterns.py
│   │   ├── confidence.py
│   │   ├── novelty.py
│   │   ├── yield_model.py
│   │   ├── convergence.py
│   │   └── genome.py
│   │
│   └── exporters/
│       ├── jsonl.py
│       ├── text.py
│       └── csv.py
│
├── configs/
│   ├── scope.example.yaml
│   └── pipeline.example.yaml
│
├── migrations/
├── tests/
├── docs/
└── scripts/
```

---

# 4. Назначение файлов и модулей

## `recon/cli.py`

Точка входа command-line interface.

Отвечает за предоставление высокоуровневых операций, например:

```text
init target
load scope
seed assets
plan tasks
run pipeline
resume pipeline
show status
show changes
review blocked events
export results
explain an asset
```

Сам CLI не должен содержать recon-логику.

Он делегирует работу core-сервисам.

---

## `recon/core/events.py`

Определяет внутренний контракт events.

Всё, что обнаруживает Night Scout, представляется как event.

Примеры:

```text
DNS_NAME
IP_ADDRESS
URL
HTTP_SERVICE
CERTIFICATE
JAVASCRIPT
API_ENDPOINT
ARTIFACT
VOCAB_TOKEN
NAMING_PATTERN
```

Это один из центральных архитектурных файлов, поскольку все workers взаимодействуют через event model.

---

## `recon/core/queue.py`

Постоянная очередь задач.

Обязанности:

```text
enqueue tasks
deduplicate pending work
persist unfinished tasks
resume after interruption
track task state
```

Очередь должна безопасно переживать перезапуск процесса.

---

## `recon/core/router.py`

Определяет, какие действия могут последовать после появления нового event.

Пример:

```text
DNS_NAME
    ↓
DNS worker
TLS worker
HTTP worker
archive worker
```

или:

```text
JAVASCRIPT
    ↓
JS extraction
vocabulary extraction
endpoint extraction
hostname extraction
```

Router не решает, разрешено ли выполнение задачи.

Это обязанность policy layer.

---

## `recon/core/scheduler.py`

Выбирает следующую допустимую задачу для выполнения.

Scheduler учитывает:

```text
scope state
confidence
novelty
expected yield
worker cost
branch budget
previous failures
target-specific knowledge
```

Его цель — направлять recon-ресурсы туда, где ожидаемый прирост информации максимален.

---

## `recon/core/budgets.py`

Контролирует ограниченную рекурсию.

Типы budgets могут включать:

```text
requests per host
worker executions
candidate count
branch depth
time
concurrent hosts
historical retries
```

Budgets предотвращают комбинаторный взрыв.

---

## `recon/core/lifecycle.py`

Координирует жизненный цикл:

```text
run
round
branch
task
worker execution
shutdown
resume
```

Также определяет поведение convergence.

---

# 5. Policy Layer

Policy layer — обязательная граница между разведданными и активной разведкой.

```text
RELATIONSHIP
      ↓
SCOPE CHECK
      ↓
POLICY CHECK
      ↓
RATE LIMIT
      ↓
BUDGET CHECK
      ↓
WORKER
```

Обнаруженная связь **не означает автоматически наличие разрешения**.

Например:

```text
in-scope hostname
    ↓
IP
    ↓
ASN
    ↓
neighboring infrastructure
```

Соседняя инфраструктура может быть полезным разведданным, но должна оставаться passive-only, если выбранный bug-bounty scope явно не разрешает активное взаимодействие с ней.

---

## `recon/policy/scope.py`

Определяет состояние asset:

```text
IN_SCOPE
OUT_OF_SCOPE
PASSIVE_ONLY
AMBIGUOUS
```

Scope engine должен понимать:

```text
exact domains
wildcard domains
URLs
mobile applications
CIDRs where explicitly authorized
excluded assets
program-specific scope tiers
```

Ни один active worker не должен получить event до появления scope decision.

---

## `recon/policy/rate_limit.py`

Глобальный слой контроля частоты запросов.

Rate limiting должен быть централизованным, а не независимо реализованным каждым worker.

Возможные измерения:

```text
requests per host
requests per IP
global concurrency
worker-specific concurrency
program-specific limits
```

---

## `recon/policy/restrictions.py`

Представляет program-specific rules.

Примеры:

```text
active VHOST allowed / forbidden
content discovery allowed / restricted
authentication testing forbidden
high-volume automation forbidden
specific asset classes passive-only
```

---

## `recon/policy/review_gate.py`

Останавливает автоматизацию, если event требует ручного анализа.

Примеры:

```text
POSSIBLE_SECRET
POSSIBLE_PRIVATE_DATA
AUTH_BOUNDARY
POLICY_AMBIGUITY
OUT_OF_SCOPE_REFERENCE
POSSIBLE_HIGH_IMPACT_SURFACE
```

Ожидаемое поведение:

```text
interesting discovery
    ↓
review required
    ↓
automation stops for that branch
```

а не:

```text
interesting discovery
    ↓
automatic escalation
```

---

# 6. Event Model

Нормализованный event может выглядеть так:

```json
{
  "event_id": "evt_01...",
  "type": "URL",
  "value": "https://api.example.com/v2/orders",
  "source": "crawler",
  "parent_event_id": "evt_00...",
  "first_seen": "2026-08-18T18:00:00Z",
  "last_seen": "2026-08-18T18:00:00Z",
  "scope_state": "IN_SCOPE",
  "confidence": 0.96,
  "novelty": 0.71,
  "depth": 3,
  "metadata": {
    "http_status": 401,
    "content_length": 83,
    "content_type": "application/json"
  }
}
```

Основные типы events:

```text
ROOT_DOMAIN
DNS_NAME
DNS_RECORD
IP_ADDRESS
ASN
CIDR

URL
URL_PATH
HTTP_SERVICE
HTTP_RESPONSE

CERTIFICATE
CERT_SAN

FAVICON
TECHNOLOGY
FINGERPRINT

JAVASCRIPT
API_ENDPOINT
PARAMETER_NAME

ARTIFACT
MOBILE_ARTIFACT

PROJECT_NAME
VOCAB_TOKEN
NAMING_PATTERN

RELATIONSHIP

POLICY_BLOCK
HUMAN_REVIEW
```

---

# 7. Provenance

Каждый event обязан сохранять путь своего обнаружения.

Night Scout всегда должен уметь ответить:

```text
Where did this asset come from?
Why do we believe it exists?
Which previous event caused its discovery?
Which worker generated it?
What evidence supports it?
```

Пример цепочки:

```text
historical APK
    ↓
string
    ↓
project name
    ↓
target vocabulary
    ↓
naming pattern
    ↓
candidate hostname
    ↓
DNS resolution
    ↓
certificate
    ↓
HTTP service
    ↓
JavaScript
    ↓
API endpoint
```

Концептуально сохраняются:

```text
parent_event_id
source_worker
source_artifact
timestamp
evidence
scope_decision
```

Это делает находки объяснимыми и воспроизводимыми.

---

# 8. Knowledge Graph

Данные Night Scout естественным образом образуют граф.

Пример:

```text
DOMAIN
  │ resolves_to
  ▼
IP
  │ presents
  ▼
CERTIFICATE
  │ contains_SAN
  ▼
DOMAIN
```

Другой пример:

```text
APK
  │ contains
  ▼
HOSTNAME
  │ serves
  ▼
JAVASCRIPT
  │ references
  ▼
API_ENDPOINT
```

На первом этапе relationships можно хранить в SQLite:

```text
relationships(
    source_event_id,
    relation_type,
    target_event_id
)
```

Отдельная graph database для первой архитектуры не требуется.

Event model должен позволять добавить её позже без перепроектирования всей системы.

---

# 9. Target Genome

**Target Genome** — адаптивный слой знаний Night Scout.

На начальном этапе это не neural-network model.

Это объяснимый набор target-specific наблюдений, статистики, patterns и успешных гипотез.

Genome может содержать:

```text
naming conventions
environment names
region codes
service names
internal vocabulary
project names
application titles
technology combinations
URL structures
historical prefixes
historical suffixes
certificate relationships
API version patterns
artifact-derived terminology
```

Пример наблюдений:

```text
warehouse-api-prod-msk-01
warehouse-api-stage-msk-01
delivery-api-prod-spb-02
```

Возможная выведенная структура:

```text
{service}-api-{env}-{region}-{number}
```

Известные значения:

```text
service = warehouse | delivery
env     = prod | stage
region  = msk | spb
number  = 01 | 02
```

После этого Night Scout может генерировать **ограниченный набор гипотез**, а не бесконтрольно комбинировать огромные generic wordlists.

---

# 10. Adaptive Learning Loop

```mermaid
flowchart LR
    A[Observed Assets] --> B[Extract Vocabulary]
    B --> C[Detect Patterns]
    C --> D[Generate Bounded Hypotheses]
    D --> E[Scope / Policy Gate]
    E --> F[Observe Results]
    F --> G[Update Confidence]
    F --> H[Update Token Yield]
    F --> I[Negative Knowledge]
    G --> J[Scheduler]
    H --> J
    I --> J
    J --> D
```

Night Scout обучается на:

```text
confirmed hypotheses
failed hypotheses
source yield
worker yield
token performance
pattern performance
historical recurrence
independent evidence
```

Цель:

```text
more knowledge
    ↓
better hypotheses
    ↓
higher precision
    ↓
less wasted traffic
```

а не:

```text
more knowledge
    ↓
more requests
```

---

# 11. Vocabulary Engine

Generic wordlists полезны как стартовые данные, но со временем основным источником словаря должна становиться сама цель.

Vocabulary можно извлекать из:

```text
hostname labels
URL paths
parameter names
JavaScript identifiers
API names
page titles
certificate SANs
archived pages
archive filenames
mobile artifacts
project names
public documentation
technology identifiers
```

Пример:

```text
warehouse-api-preprod-msk-02.example.com
```

превращается в:

```text
warehouse
api
preprod
msk
02
```

Для каждого token можно хранить:

```text
frequency
source diversity
first_seen
last_seen
context
hostname position
path position
successful hypotheses
failed hypotheses
yield score
```

Так появляется target-specific language model без необходимости использовать непрозрачное machine learning.

---

# 12. Pattern Engine

Pattern engine преобразует наблюдения в структуры-кандидаты.

Пример:

```text
api-prod-msk-01
api-stage-msk-01
api-prod-spb-01
```

Возможный pattern:

```text
api-{env}-{region}-{number}
```

Confidence pattern должен расти, когда:

```text
multiple independent examples match
new generated candidates are confirmed
the same structure appears historically
different sources support the pattern
```

Confidence должен снижаться, когда:

```text
generated candidates consistently fail
the pattern only fits one example
evidence is derived from a single noisy source
```

Pattern engine должен отдавать приоритет точности, а не объёму.

---

# 13. Negative Knowledge

Неудачные гипотезы — тоже ценные данные.

Пример:

```text
candidate:
api-preprod-spb-03.example.com

result:
NXDOMAIN

checked_at:
2026-08-18
```

Без Negative Knowledge рекурсивные системы постоянно генерируют одни и те же мёртвые candidates.

Negative observations должны иметь TTL, поскольку инфраструктура может измениться.

Пример:

```text
recent NXDOMAIN
    ↓
suppress candidate

old NXDOMAIN
    ↓
eligible for future recheck
```

---

# 14. Confidence Model

Гипотеза и непосредственно наблюдаемый asset не должны иметь одинаковый вес.

Пример:

```text
api-preprod.example.com

evidence:
  old JavaScript reference

confidence:
  LOW
```

Позже:

```text
api-preprod.example.com

evidence:
  old JavaScript reference
  DNS resolution
  TLS certificate
  HTTP response

confidence:
  HIGH
```

Confidence должен учитывать:

```text
source quality
independent evidence count
direct observation
repeatability
historical recurrence
contradictions
```

Несколько инструментов, использующих один и тот же underlying data source, не должны считаться полностью независимыми подтверждениями.

---

# 15. Novelty Model

Novelty показывает, насколько asset необычен или ранее не наблюдался.

Возможные положительные сигналы:

```text
first seen in current snapshot
absent from common passive sources
historical-only origin
unusual naming pattern
unique favicon
unique title
new certificate relationship
new API surface
old / stage / preprod indication
newly changed service
```

Возможные отрицательные сигналы:

```text
duplicate content
generic CDN asset
static-only surface
known marketing application
very common fingerprint
```

Novelty не является оценкой критичности уязвимости.

Он управляет приоритетом разведки.

---

# 16. Yield Model

Night Scout отслеживает, насколько продуктивны конкретные sources и workers для текущей цели.

Пример:

```text
source                 candidates   confirmed   yield
CT                         1200         410      34%
generic permutations      45000          12     0.03%
target patterns             380          94      25%
historical JS               140          51      36%
```

Это позволяет scheduler постепенно отдавать приоритет target-specific методам с высоким yield.

Yield можно отслеживать для:

```text
workers
sources
tokens
patterns
artifact types
historical sources
fingerprints
```

---

# 17. Scheduler

Scheduler решает, какую задачу наиболее выгодно выполнить следующей.

Концептуально:

```text
priority =
    confidence
  × novelty
  × expected_yield
  × policy_multiplier
  ÷ estimated_cost
```

Возможные входные параметры задачи:

```text
scope certainty
confidence
novelty
expected information gain
worker cost
branch depth
previous failures
historical uniqueness
change recency
```

Policy denial всегда имеет приоритет над score.

```text
OUT_OF_SCOPE
    ↓
no active task
```

---

# 18. Cost Model

Каждый worker должен иметь приблизительную стоимость.

Пример условной шкалы:

```text
local parsing              0
passive lookup             0
DNS                        1
HTTP metadata              2
TLS                        2
archive lookup             2
crawl                      5
targeted content          15
VHOST                     20
broad active discovery    30
```

Точные значения являются деталями реализации.

Главная архитектурная идея: дорогие рекурсивные branches требуют более сильного обоснования.

---

# 19. Convergence

Night Scout должен уметь прекращать исследование непродуктивной branch.

Branch отслеживает:

```text
new domains
new live hosts
new URLs
new API endpoints
new vocabulary
new patterns
new relationships
```

Если marginal discovery rate приближается к нулю:

```text
branch
    ↓
converged
    ↓
closed
```

Если новая находка внезапно раскрывает продуктивный cluster:

```text
branch
    ↓
new evidence
    ↓
budget extension
```

Так создаётся **контролируемая рекурсия**, а не бесконечный loop.

---

# 20. Worker Model

Workers являются adapters для внешних инструментов или локальных processors.

```text
EVENT
  ↓
WORKER ADAPTER
  ↓
EXTERNAL TOOL / LOCAL PROCESSOR
  ↓
PARSER
  ↓
NORMALIZED EVENTS
```

Концептуальный interface:

```python
class Worker:
    accepts: set[str]
    emits: set[str]
    active: bool
    estimated_cost: int

    def eligible(self, event, context) -> bool:
        ...

    def run(self, event, context):
        ...
```

Event contract остаётся стабильным.

Конкретные инструменты можно заменять.

---

# 21. Классы Workers

## Passive Domain Discovery

Назначение:

```text
find hostnames
collect certificate names
collect public relationships
generate passive DNS evidence
```

Выходные events:

```text
DNS_NAME
CERTIFICATE
CERT_SAN
RELATIONSHIP
```

---

## DNS

Назначение:

```text
resolve candidates
collect DNS records
identify wildcard behavior
record negative observations
```

Возможные outputs:

```text
DNS_RECORD
IP_ADDRESS
RELATIONSHIP
```

---

## Permutations

Два основных режима:

```text
generic mutation
target-pattern mutation
```

По мере обогащения Target Genome генерация на основе target patterns должна получать всё больший вес.

---

## HTTP

Назначение:

```text
determine service presence
capture response metadata
fingerprint content
detect changes
```

Полезные metadata:

```text
status
length
title
content type
redirect
server hints
body hash
header hash
```

Компактный human-readable export:

```text
[200] [8321] [Portal] https://portal.example.com/
[401] [83]   [API]    https://api.example.com/
[403] [0]             https://admin-stage.example.com/
```

---

## TLS

Назначение:

```text
certificate collection
SAN extraction
certificate relationships
TLS metadata
```

Типичный pivot:

```text
hostname
    ↓
certificate
    ↓
SAN
    ↓
candidate hostname
    ↓
scope gate
```

---

## ASN / IP Context

Назначение:

```text
map known infrastructure relationships
associate known IPs with network context
identify passive neighboring evidence
```

Принадлежность ASN **не означает автоматически наличие разрешения**.

---

## Archives

Назначение:

```text
recover historical URLs
recover removed paths
recover historical hostnames
recover project names
recover old application references
```

Historical evidence передаётся в:

```text
vocabulary
patterns
artifact analysis
URL intelligence
```

---

## Crawler

Назначение:

```text
links
paths
JavaScript
API references
host references
application structure
```

Находки crawler возвращаются в центральную event bus.

---

## JavaScript

JavaScript рассматривается как первоклассный источник разведданных.

Возможные outputs:

```text
API paths
hostnames
parameter names
project vocabulary
configuration names
additional scripts
application fingerprints
```

---

## VHOST

VHOST discovery — активный worker, защищённый policy gate.

Требования:

```text
explicit authorization
scope approval
central rate limiting
candidate hostnames
bounded request budget
```

Он не должен превращать passive ASN relationships в неконтролируемое active scanning.

---

## Content

Назначение:

```text
targeted file/path discovery
historical file recovery
old application surface discovery
```

Content discovery должен отдавать приоритет:

```text
target vocabulary
historical paths
artifact-derived paths
application-specific candidates
```

вместо неконтролируемого generic enumeration.

---

## Parameters

Назначение:

```text
candidate parameter discovery
parameter-name intelligence
application surface enrichment
```

Поведенческое тестирование уязвимостей должно оставаться отдельным от reconnaissance этапом.

---

## Mobile / Artifacts

Offline-анализ artifacts может исследовать:

```text
APK
AAB
DEX
AAR
ZIP
application resources
historical builds
```

Возможные outputs:

```text
hostname
URL
API base path
project name
configuration name
candidate secret
```

Потенциальные secrets отправляются на human review, а не используются автоматически.

---

## Fingerprints

Возможные fingerprints:

```text
favicon
page title
headers
body hash
TLS properties
technology combination
unique application strings
```

Fingerprints полезны как generators связей.

Любой новый связанный asset перед active interaction снова проходит scope gate.

---

# 22. Storage Model

Night Scout использует три уровня хранения с разным назначением:

```text
SQLite
    ↓
persistent system state

JSONL
    ↓
append-friendly event trail

TXT / CSV
    ↓
human-readable exports
```

SQLite остаётся source of truth.

---

# 23. Рекомендуемые SQLite Entities

Логические таблицы:

```text
events
assets
relationships
evidence
tasks
worker_runs
scope_decisions
tokens
patterns
negative_observations
snapshots
changes
review_queue
budgets
```

Пример relationship:

```text
source_event_id
relation_type
target_event_id
```

Пример строки evidence:

```text
event_id
source
source_type
observed_at
confidence_delta
metadata
```

---

# 24. Snapshot Model

Night Scout хранит историческое состояние.

Концептуально:

```text
snapshot 001
snapshot 002
snapshot 003
...
```

Система сравнивает snapshots и создаёт change events, например:

```text
NEW_HOST
NEW_URL
NEW_ENDPOINT
NEW_CERT_SAN
IP_CHANGED
STATUS_CHANGED
TITLE_CHANGED
BODY_HASH_CHANGED
NEW_JAVASCRIPT
RESURRECTED_HOST
DISAPPEARED_HOST
SCOPE_CHANGED
```

Поверхность атаки рассматривается как изменяющаяся система, а не как статичная цель сканирования.

---

# 25. Differential Recon

Историческое сравнение само по себе является частью discovery.

Пример:

```text
yesterday:
admin-stage.example.com -> 403

today:
admin-stage.example.com -> 200
```

Night Scout сохраняет:

```text
STATUS_CHANGED
403 -> 200
```

Другой пример:

```text
new certificate
    ↓
new SAN
    ↓
new hostname
    ↓
new branch
```

Недавно изменившийся asset может получить более высокий priority, чем давно известный статичный host.

---

# 26. Human Review Queue

Чувствительные находки должны быть видимыми, но система не должна автоматически действовать на их основе.

Пример:

```text
[REVIEW]
type: POSSIBLE_SECRET
source: historical mobile artifact
event: evt_...
automation: paused
```

Возможные review classes:

```text
POSSIBLE_SECRET
POSSIBLE_PRIVATE_DATA
AUTH_REQUIRED
OUT_OF_SCOPE_REFERENCE
POLICY_AMBIGUITY
UNUSUAL_ADMIN_SURFACE
POSSIBLE_HIGH_IMPACT_SURFACE
```

---

# 27. Target Workspace

Реальные данные цели должны быть изолированы от кода движка.

Концептуальная структура:

```text
workspace/
└── target-id/
    ├── scope.yaml
    ├── policy.yaml
    ├── recon.db
    ├── events.jsonl
    │
    ├── artifacts/
    ├── snapshots/
    ├── exports/
    ├── logs/
    └── notes/
```

Repository содержит engine.

Workspace содержит знания о цели.

```text
ENGINE
    ≠
TARGET DATA
```

---

# 28. Пример Scope Model

```yaml
target_id: example-program

allowed:
  domains:
    - example.com
    - "*.example.com"

passive_only:
  related_domains: true
  certificate_neighbors: true
  asn_neighbors: true

active:
  enabled: true

limits:
  requests_per_second_per_host: 5
  max_concurrent_hosts: 10

stop_conditions:
  private_data: true
  possible_secret: true
  auth_boundary: true
```

Schema намеренно остаётся target-agnostic.

Разные bug-bounty programs могут быть представлены без изменения архитектуры engine.

---

# 29. Пример Event Flow

```text
ROOT_DOMAIN
    ↓
PASSIVE DOMAIN WORKER
    ↓
DNS_NAME
    ↓
SCOPE GATE
    ↓
DNS WORKER
    ↓
IP_ADDRESS
    ↓
HTTP + TLS
    ↓
HTTP_SERVICE + CERTIFICATE
    ↓
CRAWLER
    ↓
JAVASCRIPT
    ↓
API_ENDPOINT + VOCAB_TOKEN
    ↓
TARGET GENOME
    ↓
NAMING_PATTERN
    ↓
BOUNDED CANDIDATE
    ↓
SCOPE GATE
    ↓
DNS WORKER
```

Это фундаментальный рекурсивный механизм Night Scout.

---

# 30. Пример Historical Artifact Flow

```text
ARCHIVE
    ↓
OLD APPLICATION PACKAGE
    ↓
OFFLINE PARSER
    ↓
PROJECT NAME
    ↓
VOCABULARY ENGINE
    ↓
TARGET-SPECIFIC TOKEN
    ↓
PATTERN ENGINE
    ↓
HOSTNAME HYPOTHESIS
    ↓
SCOPE GATE
    ↓
OBSERVATION
```

---

# 31. Пример Fingerprint Pivot

```text
KNOWN APPLICATION
    ↓
FAVICON / TITLE / BODY HASH
    ↓
FINGERPRINT EVENT
    ↓
PASSIVE RELATIONSHIPS
    ↓
CANDIDATE ASSET
    ↓
SCOPE CHECK
```

Сходство fingerprint является свидетельством связи.

Оно не является свидетельством наличия разрешения.

---

# 32. Псевдокод Core Loop

```python
while scheduler.has_tasks():
    task = scheduler.next()

    if not policy.scope_allows(task):
        storage.record_block(task, reason="scope")
        continue

    if not budgets.allow(task):
        scheduler.defer(task)
        continue

    if policy.requires_human_review(task):
        review_queue.add(task)
        continue

    raw_result = workers[task.worker].run(task)

    for event in normalize(raw_result):
        event = storage.upsert(event)

        provenance.link(task, event)

        confidence.update(event)
        novelty.update(event)
        genome.learn(event)

        if policy.event_requires_review(event):
            review_queue.add(event)
            continue

        for next_task in router.expand(event):
            if feedback.accept(next_task):
                scheduler.enqueue(next_task)

    convergence.update(task.branch)
```

Критический порядок:

```text
scope
    ↓
policy
    ↓
budget
    ↓
review
    ↓
worker
```

Никогда:

```text
worker
    ↓
check authorization later
```

---

# 33. Контроль качества Feedback

Не каждая извлечённая строка должна создавать новую recon branch.

Слабый сигнал:

```text
production
```

Сильный сигнал:

```text
fulfillment-api-stage-msk-02.example.com
```

Feedback scoring может учитывать:

```text
source quality
context
frequency
structure
entropy
position
historical reuse
independent confirmations
target relevance
```

Только достаточно полезные сигналы должны создавать новые tasks.

Это критически важно для контроля рекурсивного роста.

---

# 34. Explainability

Каждое запланированное действие должно быть объяснимым.

Для любого asset Night Scout в конечном итоге должен уметь показать:

```text
asset
scope state
confidence
novelty
first seen
last seen

discovery path
evidence
related assets
workers executed
negative observations
patterns involved
changes over time
```

Концептуально:

```text
nightscout explain api-stage.example.com
```

Пример output:

```text
api-stage.example.com

scope:
  IN_SCOPE

first discovered:
  historical JavaScript

discovery path:
  archive
  -> old app.js
  -> hostname string
  -> DNS resolution
  -> TLS certificate
  -> HTTP service

confidence:
  0.97

novelty:
  0.88

related:
  certificate cert_...
  IP 203.0.113.15
  api-prod.example.com

changes:
  2026-08-18 NEW_HOST
```

Explainability — базовое требование, а не опциональная UI-функция.

---

# 35. Фундаментальные Invariants

Эти правила определяют архитектуру.

## Invariant 1

```text
No active request without a scope decision.
```

## Invariant 2

```text
Every finding has provenance.
```

## Invariant 3

```text
A relationship does not equal authorization.
```

## Invariant 4

```text
Every expensive recursive branch has a budget.
```

## Invariant 5

```text
Negative observations are remembered.
```

## Invariant 6

```text
Target knowledge remains isolated from engine code.
```

## Invariant 7

```text
Sensitive evidence pauses automation.
```

## Invariant 8

```text
Every scheduled task must be explainable.
```

## Invariant 9

```text
Recursive exploration must converge.
```

## Invariant 10

```text
Adaptation should improve precision, not simply increase traffic.
```

---

# 36. Night Scout на одной схеме

```mermaid
flowchart LR
    A[Discover] --> B[Remember]
    B --> C[Connect]
    C --> D[Learn]
    D --> E[Prioritize]
    E --> F[Recurse]
    F --> G[Diff]
    G --> H[Converge]

    H --> A
```

Операционно:

```text
discover
    ↓
remember
    ↓
connect
    ↓
learn
    ↓
prioritize
    ↓
recurse
    ↓
diff
    ↓
converge
```

---

# 37. Идентичность проекта

**Night Scout** — не wrapper вокруг набора scanners.

Это intelligence layer между reconnaissance tools и исследователем.

Его задача — превращать изолированные наблюдения в постоянную модель авторизованной цели:

```text
raw signals
    ↓
events
    ↓
relationships
    ↓
target knowledge
    ↓
better hypotheses
    ↓
higher-value reconnaissance
```

Центральная идея проста:

> **Следующий шаг разведки должен учитывать всё, что система уже узнала о цели.**

Поэтому Night Scout рассматривает reconnaissance как постоянно улучшаемую модель поверхности атаки, а не как одноразовый scan.
