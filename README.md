# Proxy Detector

A tool that uses external APIs for proxy status of an IP

## Credits

* [ipcheck](https://github.com/SQL-enwiki/ipcheck)

## Usage (Toolforge Build Service + ASGI)

Sessions and provider caches are stored in Toolforge Redis, and static frontend assets are compiled automatically during `toolforge build start`.

```bash
# Configure Toolforge runtime environment variables, see [example](./.env.example)
toolforge envvars create
toolforge build start "link-to-.git"
toolforge webservice buildservice start --mount=all
```