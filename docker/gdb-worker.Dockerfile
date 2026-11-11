# Operator-reviewed GDB-capable worker for PRESTIGE persistent sessions.
# Build locally; the runner always adds --network=none, --read-only, non-root,
# capability drops and resource limits. Pin the resulting image by digest.
FROM python@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39

ENV DEBIAN_FRONTEND=noninteractive
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends gdb binutils file \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="prestige-gdb-worker"
LABEL org.opencontainers.image.description="Reviewed GDB/binutils worker for PRESTIGE isolated sessions"
USER 65534:65534
