"""Agent manifests: the parts of an AI agent that decide its behaviour.

A SPIFFE ID from the unix attestor tells you *which binary* is running. For an
agent, behaviour is decided by the code, the model, the system prompt, and the tools
it can call. The manifest hash binds all four together, and the trusted launcher
embeds it in the agent's SPIFFE ID.
"""
from __future__ import annotations

import hashlib
import json
import os
import re

RUN = "/lab/run"
APPROVED = os.path.join(RUN, "approved_manifests.json")
AGENT_ID_RE = re.compile(r"^spiffe://lab\.local/agent/(?P<name>[a-z0-9-]+)/m-(?P<hash>[0-9a-f]{16})$")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def compute(script_bytes: bytes, config: dict, interpreter_sha256: str) -> tuple[dict, str]:
    manifest = {
        "agent": config["name"],
        "script_sha256": _sha(script_bytes),
        "model": config["model"],
        "system_prompt_sha256": _sha(config["system_prompt"].encode()),
        "tools": sorted(config["tools"]),
        "interpreter_sha256": interpreter_sha256,
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return manifest, _sha(canonical)[:16]


def load_approved() -> dict:
    try:
        with open(APPROVED) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def parse_agent_id(spiffe_id: str):
    m = AGENT_ID_RE.match(spiffe_id or "")
    return (m.group("name"), m.group("hash")) if m else (None, None)
