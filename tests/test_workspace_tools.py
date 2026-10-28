"""Coverage for the unfinished workspace-tool increment, without paid inference."""

import os

import pytest

from prestige.artifacts import Artifacts, ToolRegistry
from prestige.engine import new_run
from prestige.sandbox import WorkspaceRunner
from prestige.store import encoded
from prestige.types import Action, PolicyDenied


def test_bounded_views_and_explicit_large_limit(store, tmp_path):
    source = tmp_path / "small.bin"
    source.write_bytes(b"0123456789")
    run = new_run(store, source)
    artifacts = Artifacts(store, run)
    artifact = artifacts.list()[0]["id"]
    assert artifacts.view(artifact, 2, 4) == b"2345"
    for offset, length in ((-1, 2), (0, 32769), (11, 2)):
        with pytest.raises(PolicyDenied):
            artifacts.view(artifact, offset, length)
    # No CLI option is shipped yet. Exercise only the stored policy input.
    settings = store.run(run)["settings"]
    settings["max_artifact_mib"] = 2
    with store.transaction() as db:
        db.execute("UPDATE runs SET settings=? WHERE id=?", (encoded(settings), run))
    large = Artifacts(store, run)
    digest = large.add(b"x" * (1024 * 1024 + 1), "large.bin")
    assert large.view(digest, 1024 * 1024, 1) == b"x"
    with pytest.raises(PolicyDenied):
        artifacts.add(b"x" * (1024 * 1024 + 1), "too-large.bin")


def test_workspace_arguments_and_tool_allowlist(store, challenge):
    run = new_run(store, challenge[0])
    artifacts = Artifacts(store, run)
    runner = WorkspaceRunner("sha256:" + "a" * 64, artifacts)
    args = runner.argv("test")
    assert "--network=none" in args and "--read-only" in args
    assert args.count("--mount") == 2
    assert str(artifacts.root.resolve()) in args[args.index("--mount") + 1]
    assert "readonly" in args[args.index("--mount") + 1]
    for action in (
        Action("command", "", {"argv": ["curl", "https://ctfd.example"]}),
        Action("python", "", {"code": "pass", "timeout": 31}),
        Action("python", "", {"code": "pass", "override": True}),
    ):
        with pytest.raises(PolicyDenied):
            runner.execute(action)


@pytest.mark.container
@pytest.mark.skipif(
    not os.environ.get("PRESTIGE_TEST_IMAGE"), reason="Explicit local immutable image required"
)
def test_real_workspace_persistence_read_only_inputs_and_no_network(store, challenge):
    run = new_run(store, challenge[0])
    artifacts = Artifacts(store, run)
    artifact = artifacts.list()[0]["id"]
    runner = WorkspaceRunner(os.environ["PRESTIGE_TEST_IMAGE"], artifacts)
    assert runner.audit()["isolated"]
    registry = ToolRegistry(artifacts, ("python",), runner)
    result = registry.execute(
        Action(
            "python",
            artifact,
            {
                "code": "from pathlib import Path\n"
                f"p=Path('/work/input/{artifact}')\n"
                "assert p.read_bytes()\n"
                "try: p.write_bytes(b'changed')\n"
                "except OSError: pass\n"
                "else: raise AssertionError('input was writable')\n"
                "Path('/work/output/result.txt').write_text('persistent observation')\n"
                "print('done')\n"
            },
        )
    )
    assert result["returncode"] == 0
    assert any(item["path"].endswith("result.txt") for item in result["outputs"])
    result = runner.execute(
        Action(
            "python",
            artifact,
            {
                "code": "from pathlib import Path\n"
                "assert Path('/work/output/result.txt').read_text()=='persistent observation'\n"
                "print('retained')\n"
            },
        )
    )
    assert result["stdout"].strip() == "retained"
    assert artifacts.read(artifact) == challenge[0].read_bytes()
