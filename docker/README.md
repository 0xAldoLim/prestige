# Reviewed worker images

## GDB-capable worker

`gdb-worker.Dockerfile` extends the pinned Python slim image with `gdb`, `binutils`
and `file`. Build it locally and pin the resulting image by ID/digest:

```bash
docker build -f docker/gdb-worker.Dockerfile -t prestige-gdb-worker:local .
docker image inspect prestige-gdb-worker:local --format '{{.Id}}'
```

The runner adds the isolation flags at run time: `--network=none`, read-only root,
non-root user `65534:65534`, capability drops, no-new-privileges, pids/memory/CPU
limits and only the run's input (read-only) and output (writable) mounts. Docker is
not a hardened VM guarantee; review the image and host before use.

Validate a real breakpoint session:

```bash
PRESTIGE_TEST_GDB_IMAGE=sha256:<image-id> python -m pytest tests/test_gdb_session.py -q
```

The session test copies the artifact to the writable output mount, makes it
executable, loads symbols, sets a breakpoint, runs, reads `rip`, prints a backtrace
and continues. The input artifact itself is never made writable.

Do not publish or pull this image automatically. The operator must review and pin it.
