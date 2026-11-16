# Reproducible core CTF worker. Build locally, then pin the resulting digest.
FROM python:3.13-slim@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash coreutils gcc g++ make binutils file xxd zip unzip tar git curl \
    netcat-openbsd socat procps less ca-certificates python3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
    pwntools==4.15.0 z3-solver==4.15.3.0 requests==2.32.5
RUN useradd -u 65534 -M -s /usr/sbin/nologin sandbox 2>/dev/null || true
USER 65534:65534
WORKDIR /work/output
