"""Trusted agent launcher: the mitigation for 'interpreter collapse'.

SPIRE's unix attestor can only see the uid and the binary of a process. For a
Python or Node agent, that binary is the interpreter, so every agent looks the same.
The launcher closes the gap from outside the agent:

  1. Copies the agent's code and config into a root-owned instance dir, so they
     can't be changed between hashing and exec (no TOCTOU).
  2. Hashes code + model + system prompt + tool list into a manifest hash.
  3. Gives the instance a fresh, unique uid, and registers a SPIRE entry
         spiffe://lab.local/agent/<name>/m-<manifest-hash>
     with selectors unix:uid:<that uid> + unix:sha256:<interpreter>.
  4. Execs the agent as that uid, and deletes the entry when it exits. The identity
     lives exactly as long as the instance does.

Change any of the four inputs and the agent gets a different SPIFFE ID, which no
policy has approved.

  python launcher.py approve --script agents/research_agent.py --config agents/research.json --max-scope records:read
  python launcher.py launch  --script agents/research_agent.py --config agents/research.json -- --task "..."
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys

from common import manifest as mf
from common.spiffe_util import sha256_hex

SERVER_SOCK = "/tmp/spire-server/private/api.sock"
PARENT = "spiffe://lab.local/node"
INSTANCES = "/lab/run/instances"
UID_FILE = "/lab/run/next_uid"


def interpreter() -> tuple[str, str]:
    path = os.path.realpath(sys.executable)
    with open(path, "rb") as f:
        return path, sha256_hex(f.read())


def compute(script: str, config: str):
    with open(script, "rb") as f:
        code = f.read()
    with open(config) as f:
        cfg = json.load(f)
    return cfg, *mf.compute(code, cfg, interpreter()[1])


def approve(script: str, config: str, max_scopes: list[str]):
    cfg, manifest, mhash = compute(script, config)
    approved = mf.load_approved()
    approved[mhash] = {"agent": cfg["name"], "max_scopes": max_scopes, "manifest": manifest}
    with open(mf.APPROVED, "w") as f:
        json.dump(approved, f, indent=2)
    os.chmod(mf.APPROVED, 0o644)
    return mhash


def _next_uid() -> int:
    with open(UID_FILE, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        uid = int(f.read().strip() or 20000)
        f.seek(0)
        f.truncate()
        f.write(str(uid + 1))
    return uid


def spire(*args) -> str:
    p = subprocess.run(["spire-server", *args, "-socketPath", SERVER_SOCK], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"spire-server {' '.join(args)} failed: {p.stderr or p.stdout}")
    return p.stdout


def launch(script: str, config: str, agent_args: list[str], extra_env: dict | None = None,
           timeout: int = 180) -> dict:
    uid = _next_uid()
    inst = os.path.join(INSTANCES, str(uid))
    os.makedirs(inst, mode=0o755, exist_ok=True)
    s_copy, c_copy = os.path.join(inst, "agent.py"), os.path.join(inst, "config.json")
    shutil.copyfile(script, s_copy)
    shutil.copyfile(config, c_copy)
    for p in (s_copy, c_copy):
        os.chmod(p, 0o444)  # root-owned and read-only. The agent can't rewrite its own manifest inputs.

    cfg, manifest, mhash = compute(s_copy, c_copy)
    spiffe_id = f"spiffe://lab.local/agent/{cfg['name']}/m-{mhash}"
    _, interp_sha = interpreter()
    out = spire("entry", "create", "-parentID", PARENT, "-spiffeID", spiffe_id,
                "-selector", f"unix:uid:{uid}", "-selector", f"unix:sha256:{interp_sha}",
                "-x509SVIDTTL", "300", "-jwtSVIDTTL", "60")
    m = re.search(r"Entry ID\s*:\s*(\S+)", out)
    entry_id = m.group(1) if m else None
    try:
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONPATH": "/lab",
               "PYTHONDONTWRITEBYTECODE": "1", "AGENT_CONFIG": c_copy,
               "SPIFFE_ENDPOINT_SOCKET": os.environ["SPIFFE_ENDPOINT_SOCKET"], **(extra_env or {})}
        p = subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                            sys.executable, s_copy, *agent_args],
                           capture_output=True, text=True, env=env, timeout=timeout, cwd="/tmp")
    finally:
        if entry_id:
            spire("entry", "delete", "-entryID", entry_id)
    try:
        result = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        result = {"error": "agent produced no JSON", "stdout": p.stdout[-1500:], "stderr": p.stderr[-1500:]}
    result.update({"launcher": {"uid": uid, "assigned_spiffe_id": spiffe_id, "manifest_hash": mhash,
                                "manifest": manifest, "approved": mhash in mf.load_approved()}})
    return result


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("approve")
    a.add_argument("--script", required=True)
    a.add_argument("--config", required=True)
    a.add_argument("--max-scope", action="append", default=[])
    l = sub.add_parser("launch")
    l.add_argument("--script", required=True)
    l.add_argument("--config", required=True)
    l.add_argument("rest", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    if args.cmd == "approve":
        print(approve(args.script, args.config, args.max_scope))
    else:
        rest = args.rest[1:] if args.rest[:1] == ["--"] else args.rest
        passthrough = {"USER_TOKEN": os.environ["USER_TOKEN"]} if os.environ.get("USER_TOKEN") else None
        print(json.dumps(launch(args.script, args.config, rest, passthrough), indent=2))


if __name__ == "__main__":
    main()
