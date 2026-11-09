"""Code-execution sandbox service. Runs as uid 1999, which has no SPIRE registration entry.

The hardened agent sends model-generated code here instead of running it as a
subprocess of itself. The Workload API identifies callers by uid, so code here gets no SVID.
(This is the identity half of sandboxing. Pair it with seccomp, Landlock, or gVisor for the rest.)
"""
from __future__ import annotations

import subprocess
import sys

from common.http import serve


def execute(_h, body):
    proc = subprocess.run([sys.executable, "-c", body.get("code", "")], capture_output=True, text=True,
                          timeout=60, cwd="/tmp", env={"PYTHONPATH": "/lab", "HOME": "/tmp",
                                                         "SPIFFE_ENDPOINT_SOCKET": "unix:///run/spire/sockets/agent.sock"})
    return 200, {"rc": proc.returncode, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-2000:]}


if __name__ == "__main__":
    serve(7000, {("POST", "/exec"): execute}, "sandbox").serve_forever()
