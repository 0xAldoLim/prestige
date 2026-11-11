"""Portable argparse CLI: JSON is a stable primary interface, never terminal control text."""

import argparse
import asyncio
import hashlib
import json
import re
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
    answer = commands.add_parser("answer")
    answer.add_argument("run_id")
    answer.add_argument("answer_text", nargs="?")
    answer.add_argument("--request-id")
    verify = commands.add_parser("verify-candidate")
    verify.add_argument("--expected-sha256", required=True)
    verify.add_argument("--candidate-file", type=Path)
    commitment = commands.add_parser("commitment").add_subparsers(
        dest="operation", required=True
    )
    commitment.add_parser("list")
    commitment_add = commitment.add_parser("add")
    commitment_add.add_argument("artifact_sha256")
    commitment_add.add_argument("expected_sha256")
    commitment_remove = commitment.add_parser("remove")
    commitment_remove.add_argument("artifact_sha256")
    target = commands.add_parser("target").add_subparsers(dest="operation", required=True)
    target.add_parser("list")
    target_register = target.add_parser("register")
    target_register.add_argument("file", type=Path)
    for name in ("show", "enable", "disable", "revoke"):
        item = target.add_parser(name)
        item.add_argument("registration_id")
    target_bind = target.add_parser("bind")
    target_bind.add_argument("run_id")
    target_bind.add_argument("registration_id")
    target_unbind = target.add_parser("unbind")
    target_unbind.add_argument("run_id")
    target_unbind.add_argument("registration_id")
    target_bindings = target.add_parser("bindings")
    target_bindings.add_argument("run_id")
    research = commands.add_parser("research").add_subparsers(
        dest="operation", required=True
    )
    research.add_parser("sources")
    research_fetch = research.add_parser("fetch")
    research_fetch.add_argument("url")
    research_search = research.add_parser("search")
    research_search.add_argument("query")
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
    knowledge.add_parser("inbox")
    propose = knowledge.add_parser("propose")
    propose.add_argument("file", type=Path)
    propose.add_argument("--run", required=True)
    promote = knowledge.add_parser("promote")
    promote.add_argument("id")
    promote.add_argument("--verified", action="store_true")
    reject = knowledge.add_parser("reject")
    reject.add_argument("id")
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
    conditions = bench.add_parser("conditions")
    conditions.add_argument("--suite", type=Path, required=True)
    conditions.add_argument("--conditions", default="P1,P2,P3")
    conditions.add_argument("--repetitions", type=int, default=1)
    conditions.add_argument("--seed", type=int, default=2026)
    conditions.add_argument("--output", type=Path)
    conditions.add_argument("--adapter-command", help="Operator-approved B0/B1 baseline command")
    conditions.add_argument("--adapter-model", default="operator-baseline")
    conditions.add_argument("--adapter-turns", type=int, default=12)
    conditions.add_argument("--adapter-seconds", type=int, default=120)
    security = commands.add_parser("security").add_subparsers(dest="operation", required=True)
    audit = security.add_parser("audit")
    audit.add_argument("run_id")
    sandbox = security.add_parser("sandbox-test")
    sandbox.add_argument("--image", required=True)
    adversarial = security.add_parser("adversarial")
    adversarial.add_argument("--corpus", type=Path, required=True)
    adversarial.add_argument(
        "--format",
        choices=("auto", "prestige", "agentdojo", "agentlsd", "gray-swan", "paired"),
        default="auto",
    )
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
    if args.command == "answer":
        from prestige.human import answer_operator, pending_request

        pending = pending_request(store, args.run_id)
        if not pending:
            raise PrestigeError("No pending operator request")
        request_id = args.request_id or pending["request_id"]
        text = args.answer_text if args.answer_text is not None else sys.stdin.read().strip()
        payload = answer_operator(
            store, args.run_id, request_id, text, trust="operator_direct"
        )
        return {"status": "ready", **payload}
    if args.command == "verify-candidate":
        # Stateless known-answer check: accept an operator-supplied commitment and
        # report only digests, never the candidate value.
        if args.candidate_file:
            data = args.candidate_file.read_bytes()
        else:
            data = sys.stdin.buffer.read(65537)
        if len(data) > 65536:
            raise PolicyDenied("Candidate input exceeds 64 KiB")
        expected = args.expected_sha256.strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise PolicyDenied("Expected digest must be 64 lowercase hex characters")
        digest = hashlib.sha256(data).hexdigest()
        return {
            "match": digest == expected,
            "candidate_sha256": digest,
            "expected_sha256": expected,
        }
    if args.command == "commitment":
        from prestige.commitments import (
            add_commitment,
            list_commitments,
            remove_commitment,
        )

        if args.operation == "add":
            return add_commitment(store.home, args.artifact_sha256, args.expected_sha256)
        if args.operation == "remove":
            return remove_commitment(store.home, args.artifact_sha256)
        return list_commitments(store.home)
    if args.command == "target":
        from dataclasses import replace

        from prestige.remote import (
            Registration,
            load_registrations,
            remote_enabled,
            save_registrations,
        )

        registrations = load_registrations(store.home)
        if args.operation == "list":
            return {
                "remote_enabled": remote_enabled(store.home),
                "registrations": [
                    registration.to_dict()
                    for registration in sorted(
                        registrations.values(), key=lambda item: item.id
                    )
                ],
            }
        if args.operation == "bind":
            from prestige.remote import bind_target

            if args.registration_id not in registrations:
                raise PrestigeError("Unknown registration id")
            return bind_target(store.home, args.run_id, args.registration_id)
        if args.operation == "unbind":
            from prestige.remote import unbind_target

            return unbind_target(store.home, args.run_id, args.registration_id)
        if args.operation == "bindings":
            from prestige.remote import list_bindings

            return list_bindings(store.home, args.run_id)
        if args.operation == "register":
            if not args.file.is_file() or args.file.stat().st_size > 262144:
                raise PrestigeError("Registration file is missing or too large")
            data = json.loads(args.file.read_text(encoding="utf-8"))
            items = (
                data["registrations"]
                if isinstance(data, dict) and "registrations" in data
                else [data]
            )
            if not isinstance(items, list):
                raise PrestigeError("registrations must be a list")
            registered = []
            for item in items:
                registration = Registration.from_dict(item)
                registrations[registration.id] = registration
                registered.append(registration.id)
            save_registrations(store.home, registrations)
            return {"registered": registered}
        registration_id = args.registration_id
        if registration_id not in registrations:
            raise PrestigeError("Unknown registration id")
        if args.operation == "revoke":
            registrations.pop(registration_id)
            save_registrations(store.home, registrations)
            return {"registration_id": registration_id, "revoked": True}
        if args.operation in {"enable", "disable"}:
            registrations[registration_id] = replace(
                registrations[registration_id], enabled=args.operation == "enable"
            )
            save_registrations(store.home, registrations)
            return {
                "registration_id": registration_id,
                "enabled": args.operation == "enable",
            }
        return registrations[registration_id].to_dict()
    if args.command == "research":
        from prestige.research import ResearchBroker

        broker = ResearchBroker(store.home)
        if args.operation == "sources":
            return broker.status()
        if args.operation == "fetch":
            return broker.fetch(args.url)
        return broker.search(args.query)
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
        from prestige.strategy import rules_for_mode

        rules = (
            Rules.load(args.rules)
            if args.rules
            else rules_for_mode(args.mode, args.max_turns, args.max_seconds)
        )
        run_id = new_run(
            store,
            args.path,
            mode=args.mode,
            backend=args.backend,
            rules=rules,
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
        from prestige.human import pending_request

        body = report(store, args.run_id, getattr(args, "reveal", False))
        body["pending_operator_request"] = pending_request(store, args.run_id)
        return body
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
        if args.operation == "inbox":
            return knowledge.review("inbox")
        if args.operation == "propose":
            if not args.file.is_file() or args.file.stat().st_size > 262144:
                raise PrestigeError("Learning proposal file is missing or too large")
            return knowledge.propose(
                json.loads(args.file.read_text(encoding="utf-8")), args.run
            )
        if args.operation == "promote":
            return knowledge.promote(args.id, verified=args.verified)
        if args.operation == "reject":
            return knowledge.reject(args.id)
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
        if args.operation == "bind":
            from prestige.remote import bind_target

            if args.registration_id not in registrations:
                raise PrestigeError("Unknown registration id")
            return bind_target(store.home, args.run_id, args.registration_id)
        if args.operation == "unbind":
            from prestige.remote import unbind_target

            return unbind_target(store.home, args.run_id, args.registration_id)
        if args.operation == "bindings":
            from prestige.remote import list_bindings

            return list_bindings(store.home, args.run_id)
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
        from prestige.evaluation import benchmark, compare, run_conditions

        if args.operation == "compare":
            return compare(json.loads(args.left.read_text()), json.loads(args.right.read_text()))
        if args.operation == "conditions":
            import shlex

            names = tuple(item.strip() for item in args.conditions.split(",") if item.strip())
            adapter_factory = None
            if args.adapter_command:
                from prestige.benchmark_adapter import CommandConditionAdapter

                command = shlex.split(args.adapter_command)
                def adapter_factory(condition):
                    return CommandConditionAdapter(
                        command,
                        condition,
                        args.adapter_model,
                        args.adapter_turns,
                        args.adapter_seconds,
                    )
            result = asyncio.run(
                run_conditions(
                    store,
                    args.suite,
                    names,
                    args.repetitions,
                    args.seed,
                    adapter_factory=adapter_factory,
                )
            )
            if args.output:
                args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return result
        result = asyncio.run(benchmark(store, args.suite, args.repetitions))
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return {"output": str(args.output), "metrics": result["metrics"], "model_evaluation": False}
    if args.command == "security":
        if args.operation == "sandbox-test":
            from prestige.sandbox import DockerRunner

            return DockerRunner(args.image).audit()
        if args.operation == "adversarial":
            from prestige.adversarial import run_corpus, run_pairs
            from prestige.adversarial_adapters import adapt

            if args.format == "paired":
                if args.corpus.is_dir():
                    from prestige.adversarial_adapters import adapt_pairs

                    pairs = adapt_pairs(args.corpus, "agentlsd")
                else:
                    pairs = json.loads(args.corpus.read_text(encoding="utf-8"))
                return asyncio.run(run_pairs(store, pairs))
            scenarios = adapt(args.corpus, args.format)
            return asyncio.run(run_corpus(store, scenarios))
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
