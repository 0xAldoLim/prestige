# Kali / Linux

Use `python3 -m venv .venv`, activate it, and install `.[dev,codex]` inside the environment.
Do not use sudo pip or modify Kali's system Python. The built-in offline tools need no native
CTF packages. Existing GDB/Ghidra/file/strings commands are reported by doctor but are not
automatically installed or granted execution privileges.

For offline isolation, use a reviewed local Linux image containing python3 and obtain its
immutable digest with `docker image inspect IMAGE --format '{{.Id}}'`. Run
`prestige security sandbox-test --image sha256:DIGEST`. The runner never pulls images,
mounts host directories or provider credentials, or enables a network interface.
Docker daemon access is a trusted prerequisite; do not grant it to the model.

Only the explicitly documented Docker environment was validated here. This does not certify
native Kali VM package availability, GDB/PTY behavior, GPU pass-through or live CTF success.
