"""A different agent entirely: different code, different model, no guardrails.

It might be a developer's experiment, a dependency-confusion payload, or an agent
whose framework was swapped. It runs under the same Linux account as the research
agent. The question is whether SPIFFE can tell them apart.
"""
from __future__ import annotations

import argparse
import json
import os

from common.http import request
from common.spiffe_util import (BROKER_ID, DATA_API_ID, NoIdentity, client_context, fetch_jwt_svid,
                                whoami, write_tls_files)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["naive", "hardened"], default="naive")
    ap.add_argument("--whoami", action="store_true")
    ap.add_argument("--task", default="")
    a = ap.parse_args()
    out = {"agent_script": os.path.abspath(__file__), "uid": os.getuid(), "model": "uncensored-abliterated-70b"}
    try:
        out["spiffe_id"] = whoami()
    except NoIdentity as e:
        print(json.dumps({**out, "spiffe_id": None, "error": str(e)}))
        return
    if a.whoami:
        print(json.dumps(out))
        return
    attempts = []
    # Path 1: the naive API, using whatever SVID we were given.
    s, b, _ = request("GET", "127.0.0.1", 8000, "/records",
                      headers={"Authorization": "Bearer " + fetch_jwt_svid(DATA_API_ID)})
    attempts.append({"path": "naive API bulk export", "status": s,
                     "stolen": b.get("records"), "error": b.get("error")})
    # Path 2: ask the broker for a passport, using a stolen HR-admin user token.
    if os.environ.get("USER_TOKEN"):
        tls = write_tls_files()
        s, b, _ = request("POST", "127.0.0.1", 8444, "/passport",
                          body={"user_token": os.environ["USER_TOKEN"], "scope": "records:read records:export"},
                          ssl_ctx=client_context(tls), expect_peer=BROKER_ID)
        attempts.append({"path": "broker passport with stolen hr_admin token", "status": s,
                         "error": b.get("error"), "granted": b.get("granted_scope")})
    out["attempts"] = attempts
    print(json.dumps(out))


if __name__ == "__main__":
    main()
