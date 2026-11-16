# Proxy Detector

A tool that uses external APIs for proxy status of an IP

## Credits

* [ipcheck](https://github.com/SQL-enwiki/ipcheck)

## Environment Setup & Verification

Use the interactive setup command to inspect required and optional environment variables, persistent data directories, offline databases, and (on Toolforge Bastion) scheduled jobs:

```bash
# Interactive setup and diagnostic check (auto-detects Toolforge Bastion or local/container)
python manage.py check_setup

# Non-interactive audit (suitable for CI or read-only checks)
python manage.py check_setup --no-input

# Strict CI gate (exits non-zero if required variables, directories, or core offline DBs are missing)
python manage.py check_setup --no-input --strict

# Override auto-detection or inspect all low-level tuning and quota variables
python manage.py check_setup --env bastion
python manage.py check_setup --env local --all-options
```

Behaviour by environment:

* **Toolforge Bastion** (`become proxycheck` or `become proxycheck-dev`): reads runtime variables via `toolforge envvars list` / `show`, writes new or updated values safely via `toolforge envvars create <KEY>` over stdin, inspects `~/data` (or `*_DB_DIR`) permissions and NFS mounts, checks offline databases, and verifies scheduled jobs against [jobs.yaml](./jobs.yaml) via `toolforge jobs list`.
* **Local / Buildpack container**: reads process environment variables and `.env`, masks sensitive credentials on screen, writes updates to `.env` (ensuring `.gitignore` ignores `.env`), offers to create missing data directories, and prints copy-pasteable commands for missing offline databases.

## Local Development

```bash
uv sync
npm ci && npm run build
uv run python manage.py check_setup
uv run python manage.py update_offline_dbs
uv run python manage.py runserver
```

## Usage (Toolforge Build Service + ASGI)

Sessions and provider caches are stored in Toolforge Redis, and static frontend assets are compiled automatically during `toolforge build start`.

```bash
# 1. Build the container image and inspect/configure Toolforge envvars interactively
toolforge build start "link-to-.git"
python manage.py check_setup --env bastion

# 2. Populate persistent offline databases under ~/data (or custom *_DB_DIR)
toolforge jobs run update-offline-dbs-init \
  --image tool-proxycheck/tool-proxycheck:latest \
  --mount=all --wait \
  --command "python manage.py update_offline_dbs"

# 3. Register the hourly scheduled database update job (see jobs.yaml)
toolforge jobs load jobs.yaml

# 4. Start or restart the ASGI webservice with NFS mounts enabled
toolforge webservice buildservice start --mount=all
```

> Note for `proxycheck-dev`: replace `tool-proxycheck/tool-proxycheck:latest` with `tool-proxycheck-dev/tool-proxycheck-dev:latest` when running one-off jobs or loading [jobs.yaml](./jobs.yaml) (for example via `tmp_jobs=$(mktemp) && sed 's|tool-proxycheck/tool-proxycheck:latest|tool-proxycheck-dev/tool-proxycheck-dev:latest|g' jobs.yaml > "$tmp_jobs" && toolforge jobs load "$tmp_jobs" && rm -f "$tmp_jobs"`).
>
> For a full list of supported environment variables, see [example](./.env.example) and `python manage.py check_setup --all-options --no-input`.