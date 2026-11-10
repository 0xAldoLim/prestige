"""Portable argparse CLI: JSON is a stable primary interface, never terminal control text."""

import argparse
import asyncio
import json
import shutil
import sqlite3
import sys
from pathlib import Path

from prestige import __version__
from prestige.artifacts import redact
from prestige.config import data_home, load_config, set_config
from prestige.engine import new_run, report, solve
from prestige.knowledge import Knowledge, SkillsBridge
from prestige.security import Rules, require_remote
from prestige.store import Store, encoded
from prestige.types import PolicyDenied, PrestigeError


def parser():
    cli = argparse.ArgumentParser(
        prog="prestige", description="Experimental evidence-driven offline CTF investigations"
    )
    cli.add_argument(
        "--home", type=Path, help="Local state directory (default: OS user data directory)"
    )
    cli.add_argument("--json", action="store_true", help="JSON output (also the default)")
    cli.add_argument(
        "--no-color", action="store_true", help="Output never contains ANSI formatting"
    )
    cli.add_argument("--quiet", action="store_true", help="Suppress successful command output")
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("version")
    commands.add_parser("about")
    commands.add_parser("doctor")
    commands.add_parser("init")
    commands.add_parser("agent")
    config = commands.add_parser("config").add_subparsers(dest="operation", required=True)
    config.add_parser("show")
    setting = config.add_parser("set")
    setting.add_argument("key")
    setting.add_argument("value")
    rules = (
        commands.add_parser("rules")
        .add_subparsers(dest="operation", required=True)
        .add_parser("import")
    )
    rules.add_argument("path", type=Path)
    solving = commands.add_parser("solve")
    solving.add_argument("path", type=Path)
    solving.add_argument("--mode", choices=("fast", "expert", "auto"), default="auto")
    solving.add_argument("--backend", choices=("codex", "fake", "openai"), default="fake")
    solving.add_argument("--rules", type=Path)
    solving.add_argument(
        "--offline",
        action="store_true",
        help="No challenge network (always enforced in this release)",
    )
    solving.add_argument("--instance", help="Reserved; remote mode fails closed")
    solving.add_argument(
        "--expected-sha256",
        help="Trusted independent verifier commitment; never read from challenge instructions",
    )
    solving.add_argument("--max-turns", type=int, default=12)
    solving.add_argument("--max-seconds", type=float, default=120)
    solving.add_argument("--max-tokens", type=int)
    solving.add_argument(
        "--max-artifact-mib",
        type=int,
        default=1,
        help="Maximum artifact size in MiB (1-256); default 1",
    )
    solving.add_argument(
        "--live",
        action="store_true",
        help="Enable real model inference through the inspected Codex SDK",
    )
    solving.add_argument(
        "--runner-image",
        help="Immutable Docker image digest (sha256:...) for isolated python/command tools",
    )
    solving.add_argument(
        "--openai-base-url",
        help="OpenAI-compatible endpoint base URL (e.g. https://api.openai.com/v1)",
    )
    solving.add_argument(
        "--openai-api-key",
        help="API key for the OpenAI-compatible endpoint; prefer PRESTIGE_OPENAI_API_KEY env",
    )
    solving.add_argument("--openai-model", help="Model name for the OpenAI-compatible endpoint")
    solving.add_argument(
        "--operating-mode",
        choices=("supervised", "autonomous"),
        default="supervised",
        help="Both use identical hard limits; available tools are harmless local analysis",
    )
    for name in ("status", "report", "logs", "pause", "stop", "resume"):
        command = commands.add_parser(name)
        command.add_argument("run_id", nargs="?" if name == "status" else None)
        if name == "resume":
            command.add_argument("--instance")
        if name == "report":
            command.add_argument(
                "--reveal", action="store_true", help="Reveal local candidate values explicitly"
            )
    knowledge = commands.add_parser("knowledge").add_subparsers(dest="operation", required=True)
    knowledge.add_parser("list")
    search = knowledge.add_parser("search")
    search.add_argument("query")
    inspect = knowledge.add_parser("inspect")
    inspect.add_argument("id")
    delete = knowledge.add_parser("delete")
    delete.add_argument("id")
    models = commands.add_parser("models").add_subparsers(dest="operation", required=True)
    models.add_parser("list")
    models.add_parser("doctor")
    register = models.add_parser("register")
    register.add_argument("manifest", type=Path)
    inspect = models.add_parser("inspect")
    inspect.add_argument("id")
    advisory = models.add_parser("advise")
    advisory.add_argument("id")
    advisory.add_argument("text", type=Path)
    bench = commands.add_parser("benchmark").add_subparsers(dest="operation", required=True)
    run = bench.add_parser("run")
    run.add_argument("--suite", type=Path, required=True)
    run.add_argument("--repetitions", type=int, default=1)
    run.add_argument("--output", type=Path, required=True)
    compare = bench.add_parser("compare")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    security = commands.add_parser("security").add_subparsers(dest="operation", required=True)
    audit = security.add_parser("audit")
    audit.add_argument("run_id")
    sandbox = security.add_parser("sandbox-test")
    sandbox.add_argument("--image", required=True)
    competition = commands.add_parser("competition").add_subparsers(dest="operation", required=True)
    create = competition.add_parser("create")
    create.add_argument("name")
    add = competition.add_parser("add")
    add.add_argument("name")
    add.add_argument("path", type=Path)
    add.add_argument("--points", type=int, required=True)
    add.add_argument("--priority", type=int, default=0)
    add.add_argument("--expected-sha256")
    run = competition.add_parser("run")
    run.add_argument("name")
    run.add_argument("--workers", type=int, default=1)
    return cli


def dispatch(args, store: Store, config: dict):
    skills = SkillsBridge(Path(config["skills.path"]) if config.get("skills.path") else None)
    if args.command == "version":
        return {"version": __version__}
    if args.command == "about":
        return {
            "name": "PRESTIGE",
            "status": "experimental offline release; P0 incomplete",
            "credits": "OpenCode-for-CTF, D-CIPHER, EnIGMA, CTFAgent, PentestGPT, CTFusion, AgentLSD, Arditi et al., owner skills, OpenAI, Ollama, Hugging Face, OWASP",
            "provenance": "docs/ATTRIBUTION.md",
            "affiliation": "Independent project; no upstream endorsement",
        }
    if args.command == "doctor":
        from prestige.codex_sdk import capabilities
        from prestige.local_models import hardware

        return {
            "version": __version__,
            "python": sys.version.split()[0],
            "hardware": hardware(),
            "codex": capabilities(),
            "skills": str(skills.root) if skills.root else "not configured",
            "tools": {
                tool: shutil.which(tool)
                for tool in ("docker", "gdb", "ghidra", "file", "strings", "wsl")
            },
            "sandbox": "not validated by doctor; run security sandbox-test explicitly",
            "remote": "disabled",
            "state": str(store.home),
            "telemetry": False,
        }
    if args.command == "init":
        return {"state": str(store.home), "settings": config, "remote": "disabled"}
    if args.command == "agent":
        from prestige.mcp_server import serve_stdio

        asyncio.run(serve_stdio())
        return {"agent": "stopped"}
    if args.command == "config":
        if args.operation == "set":
            set_config(store.home, args.key, args.value)
        return load_config(store.home)
    if args.command == "rules":
        rules = Rules.load(args.path)
        directory = store.home / "rules"
        directory.mkdir(exist_ok=True)
        (directory / (rules.source_hash + ".json")).write_text(
            encoded({k: v for k, v in rules.snapshot().items() if k != "source_hash"}),
            encoding="utf-8",
        )
        return rules.snapshot()
    if args.command == "solve":
        import os

        api_key = args.openai_api_key or os.environ.get("PRESTIGE_OPENAI_API_KEY")
        if args.backend == "openai" and api_key:
            os.environ["PRESTIGE_OPENAI_API_KEY"] = api_key
        run_id = new_run(
            store,
            args.path,
            mode=args.mode,
            backend=args.backend,
            rules=Rules.load(args.rules),
            expected=args.expected_sha256,
            max_turns=args.max_turns,
            max_seconds=args.max_seconds,
            max_tokens=args.max_tokens,
            instance=args.instance,
            live=args.live,
            runner_image=args.runner_image,
            max_artifact_mib=args.max_artifact_mib,
            openai_base_url=args.openai_base_url,
            openai_api_key=api_key,
            openai_model=args.openai_model,
        )
        return asyncio.run(solve(store, run_id, skills=skills))
    if args.command == "status" and args.run_id is None:
        return store.rows(
            "SELECT id,status,lane,backend,turns FROM runs ORDER BY created DESC LIMIT 30"
        )
    if args.command in {"status", "report"}:
        return report(store, args.run_id, getattr(args, "reveal", False))
    if args.command == "logs":
        return store.events(args.run_id)
    if args.command in {"pause", "stop"}:
        run = store.run(args.run_id)
        if run["status"] in {"solved", "stopped", "input_rejected"}:
            raise PrestigeError("Terminal runs cannot be paused or stopped again")
        store.update(args.run_id, status="paused" if args.command == "pause" else "stopped")
        return report(store, args.run_id)
    if args.command == "resume":
        if args.instance:
            require_remote()
        return asyncio.run(solve(store, args.run_id, skills=skills))
    if args.command == "knowledge":
        knowledge = Knowledge(store, skills)
        if args.operation == "search":
            return {"local": knowledge.search(args.query), "skills": skills.search(args.query)}
        if args.operation == "list":
            return store.rows("SELECT id,status FROM knowledge")
        if args.operation == "delete":
            with store.transaction() as db:
                count = db.execute("DELETE FROM knowledge WHERE id=?", (args.id,)).rowcount
            return {"deleted": count}
        rows = store.rows("SELECT record,status FROM knowledge WHERE id=?", (args.id,))
        return [{"record": json.loads(x["record"]), "status": x["status"]} for x in rows]
    if args.command == "models":
        from prestige.local_models import advise, hardware, register

        if args.operation == "doctor":
            return hardware()
        if args.operation == "register":
            return register(store, json.loads(args.manifest.read_text(encoding="utf-8")))
        if args.operation == "list":
            return store.rows("SELECT id FROM models")
        rows = store.rows("SELECT manifest FROM models WHERE id=?", (args.id,))
        if not rows:
            raise PrestigeError("Unknown model")
        manifest = json.loads(rows[0]["manifest"])
        if args.operation == "inspect":
            return {**manifest, "role": "advisory-only"}
        return advise(manifest, args.text.read_text(encoding="utf-8"))
    if args.command == "benchmark":
        from prestige.evaluation import benchmark, compare

        if args.operation == "compare":
            return compare(json.loads(args.left.read_text()), json.loads(args.right.read_text()))
        result = asyncio.run(benchmark(store, args.suite, args.repetitions))
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return {"output": str(args.output), "metrics": result["metrics"], "model_evaluation": False}
    if args.command == "security":
        if args.operation == "sandbox-test":
            from prestige.sandbox import DockerRunner

            return DockerRunner(args.image).audit()
        events = store.events(args.run_id)
        return {
            "run_id": args.run_id,
            "remote": "disabled",
            "host_shell_tools": False,
            "denials": sum(x["kind"] == "policy_denied" for x in events),
            "injection_immunity": "not claimed",
            "event_count": len(events),
        }
    if args.command == "competition":
        from prestige.evaluation import run_queue

        if args.operation == "create":
            with store.transaction() as db:
                db.execute("INSERT INTO competitions VALUES(?,?)", (args.name, "[]"))
            return {"name": args.name, "scheduler": "manual priority, deadline, points baseline"}
        rows = store.rows("SELECT data FROM competitions WHERE name=?", (args.name,))
        if not rows:
            raise PrestigeError("Unknown competition")
        jobs = json.loads(rows[0]["data"])
        if args.operation == "add":
            if args.points < 0:
                raise PrestigeError("Points must be nonnegative")
            run_id = new_run(store, args.path, expected=args.expected_sha256)
            jobs.append({"run_id": run_id, "points": args.points, "priority": args.priority})
            with store.transaction() as db:
                db.execute(
                    "UPDATE competitions SET data=? WHERE name=?", (encoded(jobs), args.name)
                )
            return {"name": args.name, "run_id": run_id}
        return asyncio.run(run_queue(store, jobs, args.workers))
    raise PrestigeError("Unsupported command")


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    store = None
    try:
        home = (args.home or data_home()).resolve()
        config = load_config(home)
        store = Store(home)
        result = dispatch(args, store, config)
        if not args.quiet:

            def scrub(value):
                if isinstance(value, str):
                    return redact(value)
                if isinstance(value, list):
                    return [scrub(item) for item in value]
                if isinstance(value, dict):
                    return {key: scrub(item) for key, item in value.items()}
                return value

            output = json.dumps(
                result if getattr(args, "reveal", False) else scrub(result),
                indent=2,
                ensure_ascii=True,
            )
            # JSON escaping prevents terminal control sequences. Routine output strips candidate values.
            print(output)
        if isinstance(result, dict) and result.get("status") in {
            "blocked",
            "failed",
            "input_rejected",
        }:
            return 3
        return 0
    except (PrestigeError, OSError, ValueError, KeyError, sqlite3.Error) as error:
        print(
            json.dumps({"error": redact(str(error)), "type": type(error).__name__}), file=sys.stderr
        )
        return 3 if isinstance(error, PolicyDenied) else 2
    except KeyboardInterrupt:
        return 130
    finally:
        if store:
            store.close()
