"""'Research assistant': an HR helper agent with four tools.

  get_record(user)   read an HR record from the records API
  read_doc(name)     read a document from the knowledge base (untrusted content)
  run_python(code)   code-interpreter tool
  summarize(text)    third-party summarisation tool

--mode naive     how agents are commonly wired today: the agent's own SVID is its
                 credential, code runs as a subprocess, and auth headers are forwarded to tools.
--mode hardened  Agent Passport via broker, code sent to the uid-isolated sandbox, and
                 the credential forwarded to tools is sender-constrained.

Prints one JSON object on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from agents.mock_llm import MockLLM
from common.http import request
from common.spiffe_util import (BROKER_ID, DATA_API_ID, NoIdentity, client_context, fetch_jwt_svid,
                                whoami, write_tls_files)

DOCS = "/lab/docs"


class Agent:
    def __init__(self, mode: str, config: dict, user_token: str | None):
        self.mode, self.cfg, self.user_token = mode, config, user_token
        self.llm = MockLLM(config["model"], config["system_prompt"], config["tools"])
        self.trace: list = []
        self._tls = None
        self._passport = None

    # ---- credentials ------------------------------------------------------
    def tls(self):
        if self._tls is None:
            self._tls = write_tls_files()
        return self._tls

    def passport(self, task: str) -> str:
        if self._passport is None:
            status, body, _ = request("POST", "127.0.0.1", 8444, "/passport",
                                      body={"user_token": self.user_token, "scope": "records:read records:export",
                                            "task": task},
                                      ssl_ctx=client_context(self.tls()), expect_peer=BROKER_ID)
            self.trace.append({"step": "broker", "status": status, "body": body if status != 200 else
                               {"granted_scope": body["granted_scope"], "expires_in": body["expires_in"]}})
            if status != 200:
                raise PermissionError(body.get("error"))
            self._passport = body["passport"]
        return self._passport

    def auth_header(self, task: str) -> str:
        if self.mode == "naive":
            return "Bearer " + fetch_jwt_svid(DATA_API_ID)
        return "Passport " + self.passport(task)

    # ---- tools ------------------------------------------------------------
    def get_record(self, user: str, task: str):
        if self.mode == "naive":
            s, b, _ = request("GET", "127.0.0.1", 8000, f"/records/{user}",
                              headers={"Authorization": self.auth_header(task)})
        else:
            s, b, _ = request("GET", "127.0.0.1", 8443, f"/records/{user}",
                              headers={"Authorization": self.auth_header(task)},
                              ssl_ctx=client_context(self.tls()), expect_peer=DATA_API_ID)
        return {"status": s, **b}

    def read_doc(self, name: str, task: str):
        path = os.path.join(DOCS, os.path.basename(name))
        with open(path) as f:
            return {"text": f.read()}

    def run_python(self, code: str, task: str):
        if self.mode == "naive":
            # Typical code-interpreter tool: a child process of the agent, same uid, so same SPIFFE identity.
            p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
            return {"where": f"subprocess uid={os.getuid()}", "rc": p.returncode, "stdout": p.stdout,
                    "stderr": p.stderr[-800:]}
        s, b, _ = request("POST", "127.0.0.1", 7000, "/exec", body={"code": code}, timeout=90)
        return {"where": "sandbox service uid=1999", **b}

    def summarize(self, text: str, task: str):
        # The framework forwards the agent's auth header to the tool ("token passthrough").
        s, b, _ = request("POST", "127.0.0.1", 7001, "/summarize", body={"text": text},
                          headers={"Authorization": self.auth_header(task)})
        return {"status": s, **b}

    # ---- loop -------------------------------------------------------------
    def run(self, task: str):
        step = self.llm.plan(task)
        for _ in range(5):
            if "final" in step:
                return step["final"]
            tool, args = step["tool"], step["args"]
            try:
                result = getattr(self, tool)(**args, task=task)
            except Exception as e:  # noqa: BLE001
                result = {"error": f"{type(e).__name__}: {e}"}
            self.trace.append({"tool": tool, "args": {k: (v[:60] + "...") if isinstance(v, str) and len(v) > 60
                                                      else v for k, v in args.items()}, "result": result})
            step = self.llm.observe(tool, result)
        return step.get("final")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["naive", "hardened"], default="naive")
    ap.add_argument("--task", default="")
    ap.add_argument("--whoami", action="store_true")
    a = ap.parse_args()
    with open(os.environ.get("AGENT_CONFIG", "/lab/agents/research.json")) as f:
        cfg = json.load(f)
    out = {"agent_script": os.path.abspath(__file__), "uid": os.getuid(), "model": cfg["model"]}
    try:
        out["spiffe_id"] = whoami()
    except NoIdentity as e:
        out["spiffe_id"], out["error"] = None, str(e)
    if not a.whoami and out["spiffe_id"]:
        agent = Agent(a.mode, cfg, os.environ.get("USER_TOKEN"))
        out["final"] = agent.run(a.task)
        out["trace"] = agent.trace
    print(json.dumps(out))


if __name__ == "__main__":
    main()
