# Reproducible CTF worker images

PRESTIGE runs untrusted challenge programs only inside reviewed Docker images. The
definitions are in `docker/worker-core.Dockerfile` and `docker/worker-pwn.Dockerfile`.

## Build

```bash
docker pull python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
docker build -f docker/worker-core.Dockerfile -t prestige-worker-core:3.1 .
docker build --build-arg CORE_IMAGE=prestige-worker-core:3.1 \
  -f docker/worker-pwn.Dockerfile -t prestige-worker-pwn:3.1 .
```

The core image is built from the pinned Python 3.13 slim digest and contains Bash,
coreutils, GCC/G++, binutils, file, xxd, archive tools, curl, git, netcat, socat,
pwntools and Z3.

The pwn image adds GDB, gdbserver, strace and ltrace. Radare2/Rizin are optional
distribution packages and are not installed by the default Dockerfile; add a reviewed
package source if your distribution provides them.

## Local pinned digests

The images used for this development environment were:

| Image | Local image ID |
| --- | --- |
| core | `sha256:04b96abcade5b2ebd36a39daa41e734e75a298e52247e8fee5573b0de85b1a14` |
| pwn | `sha256:987cc389afc23e21fce00011bd094249e66c7d1a36f9d0c6e318fddfc63a65f1` |

These are local image IDs, not registry digests. Publish the image to your registry and
pin the resulting `repo@sha256:` digest for reproducibility across machines.

Configure the worker:

```bash
prestige --home ./.prestige config set sandbox.image \
  sha256:987cc389afc23e21fce00011bd094249e66c7d1a36f9d0c6e318fddfc63a65f1
prestige --home ./.prestige doctor
```

`prestige doctor` reports whether the configured image exists, its resolved image ID,
and which of the following tools are available: `python3`, `sh`, `gcc`, `gdb`, `r2`,
`curl`, `git`, `file`, `strings`, `xxd`.

## Isolation

All worker invocations use `--network=none`, `--read-only`, non-root UID 65534,
`--cap-drop=ALL`, `no-new-privileges`, no Docker socket, narrow input/output mounts,
CPU/memory/pids limits and bounded output. Persistent sessions run by `docker exec`
inside the same container and inherit its isolation.

Use the core image for offline tasks; use the pwn image for debugging and exploit
development. Missing tools should be added to a reviewed image, never installed or
executed on the Kali host.
