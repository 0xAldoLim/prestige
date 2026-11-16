# Reproducible pwn/reverse worker. Build from the core image and pin the digest.
ARG CORE_IMAGE
FROM ${CORE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb gdbserver strace ltrace \
    && rm -rf /var/lib/apt/lists/*
USER 65534:65534
WORKDIR /work/output
