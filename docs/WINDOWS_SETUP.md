# Windows

Use Python 3.11+ and a virtual environment. PowerShell activation is unnecessary:
`.\.venv\Scripts\python.exe -m prestige --help` works directly. Quote paths with spaces.
No Git Bash, WSL or Node runtime is required for the offline CLI.

Native Windows does not provide a validated arbitrary-code runner in this release.
Docker Desktop's Linux backend can run the offline isolation audit when available.
If Docker is absent or inaccessible, the bounded in-process artifact analysis still works.
Remote execution and live Codex solving remain disabled even when Docker is present.

In a restricted development host, Python asyncio/subprocess and pytest's default temporary
directory may be blocked. Run the offline suite in an ordinary permitted terminal and use
`pytest --basetemp=./private/pytest-temp` if a workspace-local temporary directory is needed.
Do not weaken PRESTIGE runtime rules to address development-host restrictions.
