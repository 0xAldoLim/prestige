"""Real GDB breakpoint session in the reviewed GDB-capable worker."""

import os
import shutil
import subprocess

import pytest

from prestige.artifacts import Artifacts
from prestige.engine import new_run
from prestige.sessions import send_session, start_session, stop_session
from prestige.store import Store

IMAGE = os.environ.get("PRESTIGE_TEST_GDB_IMAGE")

pytestmark = pytest.mark.skipif(
    not IMAGE or not shutil.which("gcc"),
    reason="Set PRESTIGE_TEST_GDB_IMAGE to a reviewed GDB worker and install gcc",
)


def test_real_gdb_breakpoint_registers_and_backtrace(tmp_path):
    source = tmp_path / "test.c"
    source.write_text(
        "int helper(int x) { return x + 1; }\n"
        "int main(void) { return helper(41); }\n"
    )
    binary = tmp_path / "testbin"
    subprocess.run(
        ["gcc", "-g", "-O0", "-o", str(binary), str(source)], check=True
    )

    home = tmp_path / "state"
    store = Store(home)
    try:
        run_id = new_run(store, binary, mode="expert", max_seconds=300)
        artifacts = Artifacts(store, run_id)
        artifact_id = artifacts.list()[0]["id"]
        session = start_session(home, run_id, IMAGE, artifacts, "gdb")
        try:
            commands = f"""set pagination off
set confirm off
shell cp /work/input/{artifact_id} /work/output/testbin && chmod +x /work/output/testbin
file /work/output/testbin
break helper
run
info registers rip
bt
continue
quit"""
            output = send_session(
                home, run_id, session["session_id"], commands, wait=4.0
            )["output"]
        finally:
            stop_session(home, run_id, session["session_id"])
    finally:
        store.close()

    assert "Breakpoint 1" in output
    assert "helper" in output
    assert "main" in output
    assert "rip" in output.lower()
    assert "exited" in output.lower()
