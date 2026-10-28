"""Offline, evidence-matched advisory cache. Live research transport is not enabled."""

import re
from urllib.parse import urlsplit

from prestige.types import PolicyDenied

SOURCES = {"nvd.nist.gov", "www.cisa.gov", "www.cve.org", "cwe.mitre.org"}


def version(value: str):
    if not re.fullmatch(r"\d+(?:\.\d+){0,3}", value):
        raise PolicyDenied("Unrecognized version syntax; applicability unknown")
    parts = tuple(int(x) for x in value.split("."))
    return parts + (0,) * (4 - len(parts))


def match_advisory(record: dict, *, component: str, observed_version: str) -> dict:
    parts = urlsplit(record["source_url"])
    if parts.scheme != "https" or parts.hostname not in SOURCES or parts.username or parts.password:
        raise PolicyDenied("Advisory source is not allowlisted")
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", record["id"]):
        raise PolicyDenied("Invalid CVE identifier")
    applicable = record["component"].casefold() == component.casefold() and version(
        record["introduced"]
    ) <= version(observed_version) < version(record["fixed"])
    return {
        "id": record["id"],
        "source_url": record["source_url"],
        "retrieved_at": record["retrieved_at"],
        "version_range_matches": applicable,
        "confidence": "hypothesis_only",
        "trust": "external_untrusted",
        "note": "Version match requires local reproduction; retrieved instructions carry no authority",
    }
