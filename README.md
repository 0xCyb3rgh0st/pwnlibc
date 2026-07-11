# pwnlibc

An all-in-one glibc version manager for CTF/pwn work: download, identify,
diff, patch, and build glibc versions — inspired by
[glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one), reimplemented
from scratch in Go, and fully Dockerized so **you never need a Go toolchain
installed locally**.

```
./pwnlibc.ps1 download 2.31-0ubuntu9.9_amd64
./pwnlibc.ps1 patch workdir/chall
./pwnlibc.ps1 identify workdir/libc.so.6
```

## Why a rewrite

The original tool is a great reference implementation, but it shells out to
`pyelftools`/`readelf`, downloads sequentially with no checksum verification,
and requires a local Python environment. This project is a clean-room
reimplementation of the same *idea* — not a port of its code — built around:

- **No local toolchain, ever.** Everything — build, test, lint, run — happens
  through Docker. `go build` never runs on your machine.
- **Reliability.** SHA256-verified downloads, path-traversal/zip-slip-safe
  extraction, decompression-bomb caps, retrying mirrors with a per-session
  circuit breaker, and a `PROVENANCE.json` audit trail per downloaded version.
- **Performance.** Native Go `debug/elf` parsing (no subprocess calls),
  concurrent mirror racing, and a local `bbolt` index for O(1) lookups.
- **A few extra tools** the original doesn't have: `patch` (pwninit-style
  auto-patch), `run` (disposable repro container with gdb), `bundle`
  (air-gapped export/import), `vuln` (known-CVE lookup), `doctor`
  (environment self-check).

## Quick start

Requires only Docker + Docker Compose.

```sh
git clone <this-repo>
cd pwnlibc
./pwnlibc.sh mirror update          # or ./pwnlibc.ps1 on Windows
./pwnlibc.sh download 2.31-0ubuntu9.9_amd64
./pwnlibc.sh identify libs/2.31-0ubuntu9.9/amd64/libc.so.6
```

The first run builds the `pwnlibc:latest` image; after that, every command is
just `docker compose run --rm cli <args>` under the hood. Downloaded glibc
versions land in `./libs`, persisted on the host. Drop challenge binaries
into `./workdir` before running `patch`/`run` against them — those two
commands launch *nested* containers via the host Docker socket, and can only
reach files under `./libs` or `./workdir` (see "How `build`/`run` work" below).

## Commands

| Command | What it does |
|---|---|
| `mirror list` / `mirror update` | List/refresh the apt mirrors (tuna, ustc, ubuntu-archive, old-releases, plus any custom ones from config). |
| `search <query>` | Fuzzy-search available versions. |
| `search --libc <path> --symbol <name\|glob>` | Local symbol offset lookup / glob match. |
| `search --libc <path> --ends-with <hex>` | Symbols whose offset ends in a given hex suffix (partial-overwrite gadget hunting). |
| `search --libc <path> --str <string>` | Scan `.rodata`/`.data` for a string. |
| `search --symbol name=addr [--symbol ...] [--tol N]` | Reverse lookup via libc.rip. |
| `search --buildid <hash>` | BuildID lookup (local index, then libc.rip). |
| `download <version>_<arch>` | Download + extract a glibc version, with checksum verification, provenance manifest, and automatic local indexing. |
| `identify <file> [--offline]` | Identify a glibc version via BuildID or anchor-symbol fingerprint. |
| `diff <a> <b>` | Symbol + security-attribute (RELRO/NX/Canary/PIE/RUNPATH) diff. |
| `patch <binary> [--version ...]` | pwninit-style: auto-detect, download, and patch interpreter+RPATH. |
| `run <binary> [--version ...]` | Patch (unless `--no-patch`) and drop into gdb inside a matching Ubuntu container. |
| `build <version> <arch>` | Compile glibc from source inside the period-correct Ubuntu image. |
| `vuln <version>` | Known CVEs affecting a version (curated, best-effort — cross-check NVD). |
| `bundle export/import` | Pack/unpack the whole `libs/` cache for air-gapped use. |
| `doctor` | Self-check: Docker reachability, disk space, mirror reachability, index health. |

Every command supports `--json` for scripting.

## How `build`/`run` work (Docker-in-Docker)

`build` and `run` launch *nested* containers by shelling out to `docker run`
against the host's Docker daemon. Two consequences:

1. They need the Docker socket, which is **opt-in** via the `build-src`
   compose profile (`pwnlibc.sh`/`pwnlibc.ps1` route these two subcommands
   there automatically). Socket access is equivalent to root on the host —
   only grant it if you're comfortable with that.
2. Bind-mount paths for the nested container are resolved by the *host*
   daemon, not pwnlibc's own container filesystem — so only paths under
   `./libs` and `./workdir` are reachable (the compose file exports
   `HOST_LIBS_DIR`/`HOST_WORKDIR_DIR` so pwnlibc can translate between the
   two). This is why challenge binaries need to live in `./workdir`.

## Configuration

Optional `config.yaml`, passed via `--config`:

```yaml
libs_dir: /data/libs
mirror_priority: ["ustc", "tuna"]
custom_mirrors:
  - name: corp-mirror
    base_url: https://mirror.corp.internal/ubuntu
max_retries: 5
```

## Development (still no local Go needed)

```sh
make test     # go vet + go test, in a container
make lint     # golangci-lint, in a container
make build    # build the pwnlibc:latest image
```

CI (`.github/workflows/ci.yml`) runs the same containerized test/lint steps,
then a Trivy vulnerability scan on the final image, and publishes multi-arch
(amd64/arm64) images to GHCR on tagged releases.

## Notes

- The `vuln` database is a small, hand-curated list of well-known CVEs, not
  an authoritative feed — always cross-check against the NVD before relying
  on it for anything beyond "does this ring a bell."
- This is an independent reimplementation for CTF/security-research use; it
  is not affiliated with the upstream `glibc-all-in-one` project.
