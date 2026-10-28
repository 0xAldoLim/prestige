"""Offline reference worker; explicit registry prevents arbitrary provider imports."""

import re

from prestige.types import Action, Proposal


class FakeBackend:
    """Deterministic fixture worker, not a model or benchmark baseline."""

    name = "fake"
    session_id = None

    async def propose(self, context: dict) -> Proposal:
        used = {(a["tool"], a["artifact"]) for a in context["actions"]}
        for item in reversed(context["artifacts"]):
            text = item["preview"].strip()
            for tool, applicable in (
                ("zip", item["magic_hex"].startswith("504b0304")),
                ("hex", bool(re.fullmatch(r"[0-9a-fA-F\s]+", text)) and len(text) >= 2),
                ("base64", bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", text)) and len(text) >= 8),
                ("strings", context["lane"] == "expert"),
                ("inspect", True),
            ):
                if (
                    applicable
                    and (tool, item["id"]) not in used
                    and tool in context["allowed_tools"]
                ):
                    return Proposal(Action(tool, item["id"]), f"Test {tool} against observed bytes")
        return Proposal(None, "No untested bounded fixture discriminator remains")

    async def interrupt(self):
        return None

    async def close(self):
        return None
