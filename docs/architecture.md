# Architecture

How Proxycheck is put together: the Django ASGI backend, the Vue frontend, the MediaWiki gadget, the two cache layers, the intelligence providers and the scheduled Toolforge jobs. Diagrams are Mermaid and render on GitHub.

## System overview

```mermaid
flowchart LR
    subgraph Clients
        SPA["Vue 3 SPA (src/)<br/>Detector + RB Finder tabs"]
        Gadget["MediaWiki user gadget<br/>(scripts/user-gadget.js)"]
    end

    subgraph Toolforge["Toolforge webservice (gunicorn + uvicorn ASGI)"]
        Django["Django API<br/>/api/v1/* (detector/views.py)"]
        Detect["detection_service<br/>singleflight, SWR, SSE"]
        RB["rangeblock_service"]
        Arb["intelligence<br/>arbitration verdict"]
        Quota["quota_telemetry + dashboard<br/>quotas, rate limits, admin telemetry"]
    end

    Redis[("Toolforge Redis<br/>L1 snapshots, provider rows,<br/>sessions, locks, quotas")]
    ToolsDB[("ToolsDB (MariaDB)<br/>L2 snapshot cache,<br/>rangeblock aggregates")]
    Offline[("Offline DBs on NFS<br/>~/data or TOOL_DATA_DIR/data")]
    Replicas[("Wiki Replicas")]
    Upstream["Online providers<br/>HTTP APIs + DNSBL/rDNS"]
    Meta["Meta-Wiki<br/>OAuth 2.0 + CentralAuth"]
    Jobs["Toolforge jobs<br/>(jobs.yaml)"]

    SPA -- "session cookie" --> Django
    Gadget -- "Bearer gadget token (CORS)" --> Django
    Django --> Detect --> Arb
    Django --> RB
    Django --> Quota
    Detect <--> Redis
    Detect <--> ToolsDB
    Detect --> Offline
    Detect --> Upstream
    Quota <--> Redis
    RB --> ToolsDB
    RB --> Replicas
    Django <--> Meta
    Jobs --> Offline
    Jobs --> ToolsDB
    Replicas --> Jobs
```

* Django serves the API (`/api/v1/`, OAuth callbacks), `robots.txt` (disallow all) and the compiled SPA (`dist/index.html` for every other route).
* `proxycheck/access_log.py` wraps the ASGI app and writes the only access log, with IPs and the `ip`, `ips`, `code`, `state` and `token` query values redacted; the gunicorn worker (`proxycheck/worker.py`) turns uvicorn's own access log off.
* Sessions use Django's cache backend on Redis; `ResilientSessionMiddleware` keeps stateless API requests working when Redis is unavailable.
* Without ToolsDB credentials the app falls back to SQLite, and without Redis the L1 layer is skipped (a circuit breaker stops retrying for a cooldown).

## API endpoints

| Endpoint | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/v1/detect` | GET | session or gadget token | Full JSON detection result for one IP (`mode=full\|light`, `compact=1`, `wiki=`) |
| `/api/v1/detect/stream` | GET | session or gadget token | Same result as SSE: a first `snapshot`, one `provider` event per upstream result, then `done` |
| `/api/v1/detect/refresh` | POST | session (CSRF) or gadget token | Manual or stale-while-revalidate refresh |
| `/api/v1/detect/batch` | POST | session or gadget token | Bounded-concurrency detection for a list of IPs |
| `/api/v1/rangeblock` | GET | session or gadget token | Cross-wiki rangeblock summary for one IP |
| `/api/v1/auth/login`, `/auth/callback`, `/auth/logout`, `/auth/user` | GET/POST | — | Meta-Wiki OAuth 2.0 web login |
| `/api/v1/auth/gadget-token` | POST | CentralAuth token | Exchanges a CentralAuth token for a gadget Bearer token |
| `/api/v1/admin/provider-dashboard` | GET | admin session | Provider quota, cooldown and cache telemetry (`detector/dashboard.py`) |
| `/api/v1/status` | GET | admin session | Offline database file ages |

Every detection, batch, rangeblock and gadget-token call also passes a per-user and/or global endpoint rate limit (`check_and_consume_endpoint_rate_limit`).

## Detection flow and caching

`detect_single_canonical_ip` canonicalises the IP, short-circuits non-public addresses, then coalesces concurrent requests for the same IP and mode into one in-process task (singleflight). The rangeblock lookup runs in parallel with it.

```mermaid
flowchart TD
    Req["GET /api/v1/detect?ip=…"] --> Auth{"Authenticated?<br/>(session or gadget token)"}
    Auth -- no --> E401["401 / 403"]
    Auth -- yes --> RL{"Endpoint rate limit"}
    RL -- exceeded --> E429["429"]
    RL -- ok --> Canon["canonicalize_ip"]
    Canon --> NonPub{"Non-public IP?"}
    NonPub -- yes --> NP["Non-public payload<br/>(no provider calls)"]
    NonPub -- no --> SF["Join or start singleflight task<br/>(ip, mode)"]
    SF --> L1{"L1 snapshot in Redis?"}
    L1 -- hit --> Rehydrate["Rehydrate: re-run offline DBs,<br/>compute age, SWR flags"]
    L1 -- miss --> L2{"L2 snapshot in ToolsDB?"}
    L2 -- hit --> Rehydrate2["Rehydrate + backfill L1"]
    L2 -- miss --> PC{"All expected providers<br/>cached per-row in Redis?"}
    PC -- yes --> Exec
    PC -- no --> Lock{"Acquire per-IP<br/>updating lock (25 s)"}
    Lock -- "held by another worker" --> Poll["Poll for the other<br/>worker's snapshot"]
    Poll -- found --> Out
    Poll -- timeout --> Exec
    Lock -- acquired --> Exec["Execute detection"]
    Exec --> Plan["Plan providers: skip cached,<br/>deferred (light mode), cooled-down"]
    Plan --> QG["Quota guard: per-minute + daily<br/>windows per provider"]
    QG --> Fan["Fan out in parallel:<br/>HTTP APIs, DNSBL, offline DBs,<br/>rDNS PTR, Cymru BGP"]
    Fan --> Write["Write provider rows / cooldowns<br/>to Redis + telemetry"]
    Write --> Arb["aggregate_intelligence_metrics<br/>(arbitration verdict)"]
    Arb --> Persist{"Complete, full mode,<br/>no transient failures?"}
    Persist -- yes --> Snap["Store L1 snapshot +<br/>merge-upsert L2 snapshot"]
    Persist -- no --> Out
    Snap --> Out["Response + rangeblock summary"]
    Rehydrate --> Out
    Rehydrate2 --> Out
    NP --> Out
```

### Cache layers

| Layer | Store | Holds | Lifetime |
| --- | --- | --- | --- |
| Provider rows | Redis | One row per provider per IP, plus PTR and provider cooldowns | `PROVIDER_STATIC_CACHE_TTL_SECONDS` (24 h) or `PROVIDER_DYNAMIC_CACHE_TTL_SECONDS` (2 h); stable GetIPIntel results 72 h |
| L1 snapshot | Redis | Assembled result per IP and mode | Short-lived; backfilled from L2 on L2 hits |
| L2 snapshot | ToolsDB `detector_ip_cache` | Compressed, compliance-sanitised snapshot keyed by binary IP | Served until stale after `CACHE_SWR_STALE_DAYS` (90 days), then refreshed in the background |

Redis keys are namespaced and the IP is hashed with `REDIS_KEY_SECRET`. Compliance rules for L2:

* Offline sources (MaxMind, StopForumSpam, IPsum/DROP, OpenASN) are never stored; they are re-run on every rehydrate so results follow the latest database.
* IPHub, Spamhaus ZEN and SpamCop are L1-only.
* Shodan InternetDB rows are stripped of CVEs and raw data; per-provider retention windows (`PROVIDER_L2_MAX_RETENTION_DAYS`, default IP2Location 30 days) are enforced by the `purge-l2-restricted-cache` job.
* An incoming snapshot with fewer valid commercial rows than the stored one does not overwrite it (non-degrading merge).

### Stale-while-revalidate and refresh

```mermaid
sequenceDiagram
    participant C as SPA / gadget
    participant API as Django API
    participant R as Redis
    participant DB as ToolsDB (L2)
    participant P as Providers

    C->>API: GET /detect?ip=X
    API->>DB: read L2 snapshot (L1 miss)
    DB-->>API: snapshot older than stale threshold
    API->>R: check SWR backoff + quota pressure
    API-->>C: cached result, cacheMeta.shouldAutoRefresh = true
    C->>API: POST /detect/refresh (ip=X)
    API->>R: per-IP refresh cooldown (60 s)?
    alt on cooldown or lock held
        API-->>C: existing snapshot, refreshInProgress
    else allowed
        API->>R: per-user + global refresh rate limit, acquire lock
        API->>P: re-query providers (quota-guarded)
        API->>R: write L1 snapshot, set refresh cooldown
        API->>DB: non-degrading merge into L2
        API-->>C: fresh result (+ rangeblock summary)
    end
```

If upstreams are degraded or quota-limited, the refresh keeps the cached intelligence and sets an SWR backoff (30 min) so clients stop auto-refreshing.

### Streaming (SSE)

`detector/stream_service.py` streams one IP progressively. The SPA calls `/api/v1/detect/stream` first and falls back to `/api/v1/detect` if the stream does not finish.

```mermaid
sequenceDiagram
    participant SPA
    participant API as detect/stream
    participant Cache as Redis / ToolsDB
    participant OD as Offline DBs
    participant Up as Online providers

    SPA->>API: GET /detect/stream?ip=X (Accept: text/event-stream)
    API->>Cache: L1 / L2 snapshot?
    alt cached or non-public
        API-->>SPA: event: snapshot (complete)
        API-->>SPA: event: done
    else miss
        API->>Cache: per-provider rows + rangeblock summary
        API->>OD: run uncached offline sources immediately
        API-->>SPA: event: snapshot (cached + offline rows)
        par each remaining provider (quota + cooldown checked)
            API->>Up: query
            API->>Cache: write provider row + telemetry
            API-->>SPA: event: provider (row + updated verdict)
        end
        API->>Cache: L1 + L2 snapshot
        API-->>SPA: event: done (complete result)
    end
```

## Providers

Registered in `detector/provider_registry.py`; `PROVIDER_SPECS` in `detector/providers.py` maps each to its query function.

```mermaid
flowchart LR
    subgraph Commercial["Commercial HTTP APIs (arbitration votes, quota-guarded)"]
        direction TB
        abuseipdb["AbuseIPDB"]
        ipdata["ipdata"]
        ipregistry["ipregistry"]
        ip2location["IP2Location"]
        getipintel["GetIPIntel"]
        proxycheck["proxycheck.io"]
        iphub["IPHub"]
        iphunter["IPHunter (IPv4 only)"]
    end
    subgraph OSINT["Other HTTP sources"]
        direction TB
        cfradar["Cloudflare Radar"]
        tor["Tor Onionoo<br/>(offline summary first)"]
        dshield["DShield"]
        shodan["Shodan InternetDB"]
    end
    subgraph DNS["DNS lookups"]
        direction TB
        zen["Spamhaus ZEN"]
        spamcop["SpamCop"]
        ptr["rDNS PTR"]
        cymru["Team Cymru BGP<br/>(when bgp.tools has no match)"]
    end
    subgraph OfflineDB["Offline databases (local files)"]
        direction TB
        maxmind["MaxMind GeoLite2"]
        sfs["StopForumSpam"]
        ipsum["IPsum + Spamhaus DROP"]
        openasn["OpenASN"]
        hints["Hints: cloud/shared CIDRs,<br/>privacy relays, bgp.tools,<br/>PeeringDB mobile"]
    end
    Commercial --> Arb["Arbitration verdict<br/>(detector/intelligence.py)"]
    OSINT --> Arb
    DNS --> Arb
    OfflineDB --> Arb
```

* Light mode (`mode=light`, the gadget default) runs only the providers marked `active_in_light_mode` (Cloudflare Radar, DNSBLs, Tor, DShield and the offline databases); commercial APIs are deferred until a full query.
* Each online provider has per-minute and daily quota windows (`<PROVIDER>_RPM` / `<PROVIDER>_DAILY`). HTTP 429/5xx responses put it on a reactive cooldown, honouring `Retry-After`.
* `adapters.py` normalises each upstream response into a common row; `intelligence.py` weighs the rows into the verdict, Tor/shared/residential signals and CIDR hints.

## Authentication

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant API as Proxycheck
    participant Meta as Meta-Wiki
    participant G as Gadget on a wiki

    Note over U,Meta: Web app (OAuth 2.0)
    U->>API: GET /api/v1/auth/login?ip=…
    API->>U: redirect to Meta-Wiki /oauth2/authorize (state in session)
    U->>Meta: approve
    Meta->>API: /oauth/callback?code&state
    API->>Meta: exchange code, fetch profile + rights
    API->>API: evaluate IP-reveal rights / allowlist, store role in session
    API->>U: redirect to SPA (?ip=…)

    Note over G,Meta: Gadget (Bearer token)
    G->>Meta: mw.Api action=centralauthtoken
    Meta-->>G: one-time CentralAuth token
    G->>API: POST /api/v1/auth/gadget-token {centralauthtoken, domain}
    API->>Meta: verify token, resolve local + global rights
    API-->>G: signed Bearer token (GADGET_TOKEN_TTL_SECONDS, 15 min)
    G->>API: /api/v1/detect… with Authorization: Bearer
```

Without OAuth credentials, `DEBUG` + `ENABLE_TEST_AUTH` gives a local sysop test session. `RESTRICT_TO_ALLOWED_WIKI_USERS` limits access to an allowlist.

## Frontend

* `src/App.vue`: Codex UI with two tabs, **Detector** and **RB Finder**; tab, IP and wiki are kept in the URL.
* `src/utils/ip-detector-logic.ts`: IP validation and canonicalisation, the stream/JSON detection client, refresh coordination and risk presentation helpers.
* `src/components/`: `DetectorResultView` (verdict, provider table and cache controls for one IP), `RangeblockFinderView` (cross-wiki rangeblock table), `ProviderDashboardModal` (admin dashboard), `AboutNoteModal` (renders `docs/about.md`).

## MediaWiki gadget

```mermaid
flowchart TD
    Load["Gadget loads on a wiki<br/>(logged-in, non-temp user)"] --> Consent{"Policy consent given?"}
    Consent -- no --> Stop["Do nothing"]
    Consent -- yes --> Scan["Find targets: temp-account IP reveal<br/>anchors, IPInfo panel, IP Special:Contributions;<br/>MutationObserver for new reveals"]
    Scan --> Cache{"Fresh result in memory /<br/>localStorage?"}
    Cache -- yes --> Badge
    Cache -- no --> Token["ensureGadgetToken<br/>(CentralAuth exchange, cached in session storage;<br/>backs off on exchange failures)"]
    Token --> Queue["Request queue: 4 concurrent;<br/>batched up to 10 IPs (40 ms debounce)"]
    Queue -- one IP --> D["GET /detect?compact=1&mode=light&wiki=…"]
    Queue -- several --> B["POST /detect/batch?compact=1"]
    D --> Badge["Risk badge + rangeblock badge + details panel"]
    B --> Badge
    Badge --> SWR{"cacheMeta.shouldAutoRefresh?"}
    SWR -- yes --> R["POST /detect/refresh (once per IP, budgeted)"] --> Badge
```

## Rangeblock lookup

`query_rangeblocks_for_ips` builds the CIDR ladder for each IP (IPv4 /32–/16; IPv6 single IP and /64–/19) and queries two sources in parallel:

```mermaid
flowchart LR
    IP["Canonical IP(s)"] --> Ladder["CIDR candidate ladder"]
    Ladder --> T["ToolsDB detector_rangeblock_agg<br/>(all synced wikis)"]
    Ladder --> RT["Wiki Replicas real-time query<br/>metawiki (global blocks) +<br/>RANGEBLOCK_REALTIME_WIKIS (default enwiki)<br/>+ requested wiki"]
    T --> Merge["merge_rangeblock_records"]
    RT --> Merge
    Merge --> Sum["Summary: local/global totals,<br/>active blocks, expiry, block/log links,<br/>realtimeDegraded flag"]
```

If a replica query fails, the summary falls back to the ToolsDB aggregates and sets `realtimeDegraded`.

## Scheduled jobs

Defined in [`jobs.yaml`](../jobs.yaml) and loaded with `toolforge jobs load jobs.yaml`. All run the tool image with `--mount=all`.

```mermaid
flowchart LR
    subgraph Hourly
        sfs["update-sfs-db<br/>stopforumspam"]
        tor["update-tor-onionoo<br/>tor_onionoo"]
        sync["sync-world-block"]
    end
    subgraph Daily
        mm["update-maxmind-db<br/>maxmind"]
        shared["update-shared-cidrs-db<br/>shared_cidrs, privacy_relays"]
        threat["update-threat-feeds-db<br/>ipsum_drop"]
        asn["update-openasn-db<br/>openasn"]
        routing["update-routing-intel-db<br/>bgp_tools, peeringdb_mobile"]
        purge["purge-l2-restricted-cache"]
    end
    sfs & tor & mm & shared & threat & asn & routing --> Data[("Offline DBs<br/>~/data")]
    Replicas[("Wiki Replicas<br/>block + log tables")] --> sync
    sync --> Agg[("ToolsDB<br/>rangeblock aggregates<br/>+ sync state")]
    purge --> L2[("ToolsDB<br/>detector_ip_cache")]
```

* `update_offline_dbs` downloads each source with conditional requests, validates it and swaps files atomically; `--sources all` (the default) runs all nine sources.
* `sync_world_block` holds a Redis lock, then per wiki upserts active blocks and advances an incremental block-log watermark (`RangeblockSyncState.last_log_id`). Realtime wikis are excluded unless `--include-realtime-wikis` is passed, because they are queried live.

## Build and deploy

```mermaid
flowchart LR
    PR["Push / PR"] --> CI["CI: ruff, Django checks + tests,<br/>oxlint, typecheck, npm test,<br/>Vite build, collectstatic"]
    CI --> Dispatch["Manual workflow_dispatch:<br/>Deploy to Toolforge (main)<br/>or Toolforge Dev (dev)"]
    Dispatch --> SSH["SSH to Toolforge bastion:<br/>sync checkout to the verified SHA"]
    SSH --> Build["toolforge build start"]
    Build --> Migrate["migrate-db one-off job<br/>(manage.py migrate)"]
    Migrate --> Web["toolforge webservice buildservice<br/>restart --mount=all"]
    Web --> JobsLoad["toolforge jobs load jobs.yaml<br/>(pinned to the new image)"]
```

`main` deploys to `proxycheck`, `dev` to `proxycheck-dev`.
