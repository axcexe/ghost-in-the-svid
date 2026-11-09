"""Runs every gap experiment twice (naive wiring vs hardened wiring) and writes a scorecard.

An experiment counts as EXPLOITED only when sensitive data actually left the API.
An experiment counts as BLOCKED only when the attack failed AND the matching positive
control succeeded. That rules out a "blocked" result that just means everything was broken.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, "/lab")
import launcher  # noqa: E402
from common.http import request  # noqa: E402
from services import idp  # noqa: E402

A = "/lab/agents"
RESEARCH, ROGUE = f"{A}/research_agent.py", f"{A}/rogue_agent.py"
CFG, TAMPERED = f"{A}/research.json", f"{A}/research_tampered.json"
TOK = {u: idp.issue(u) for u in idp.USERS}


def naive(script, args, config=CFG, user=None, uid=1001):
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "PYTHONPATH": "/lab",
           "PYTHONDONTWRITEBYTECODE": "1", "AGENT_CONFIG": config,
           "SPIFFE_ENDPOINT_SOCKET": os.environ["SPIFFE_ENDPOINT_SOCKET"]}
    if user:
        env["USER_TOKEN"] = TOK[user]
    p = subprocess.run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                        sys.executable, script, *args], capture_output=True, text=True, env=env, timeout=180, cwd="/tmp")
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"error": "no JSON", "stdout": p.stdout[-800:], "stderr": p.stderr[-800:]}


def hardened(script, args, config=CFG, user=None):
    return launcher.launch(script, config, ["--mode", "hardened", *args],
                           {"USER_TOKEN": TOK[user]} if user else None)


def tool_result(run, tool):
    for t in run.get("trace", []):
        if t.get("tool") == tool:
            return t["result"]
    return {}


def loot_reset():
    request("POST", "127.0.0.1", 7001, "/reset", body={})


def loot():
    _, body, _ = request("GET", "127.0.0.1", 7001, "/loot")
    return body["loot"]


def banner(s):
    print(f"\n{'=' * 78}\n{s}\n{'=' * 78}", flush=True)


# ----------------------------------------------------------------------------
def g1():
    banner("G1  Interpreter collapse: SPIFFE can't tell one Python agent from another")
    n_ids = {
        "research_agent.py + approved prompt/model": naive(RESEARCH, ["--whoami"])["spiffe_id"],
        "research_agent.py + tampered prompt, abliterated model": naive(RESEARCH, ["--whoami"], TAMPERED)["spiffe_id"],
        "rogue_agent.py (different code entirely)": naive(ROGUE, ["--whoami"])["spiffe_id"],
    }
    rogue = naive(ROGUE, [])
    stolen = (rogue.get("attempts") or [{}])[0].get("stolen")
    naive_res = {
        "outcome": "EXPLOITED" if len(set(n_ids.values())) == 1 and stolen else "NOT EXPLOITED",
        "evidence": {"spiffe_ids": n_ids, "rogue_bulk_export_records": list((stolen or {}).keys())},
    }
    for k, v in n_ids.items():
        print(f"  naive    {k:58s} -> {v}")

    h_legit = hardened(RESEARCH, ["--task", "show me the record for alice"], user="alice")
    h_tamp = hardened(RESEARCH, ["--task", "show me the record for alice"], TAMPERED, user="alice")
    h_rogue = hardened(ROGUE, [], user="dana")  # rogue even holds a stolen hr_admin token
    h_ids = {
        "research_agent.py + approved prompt/model": h_legit["launcher"]["assigned_spiffe_id"],
        "research_agent.py + tampered prompt, abliterated model": h_tamp["launcher"]["assigned_spiffe_id"],
        "rogue_agent.py (different code entirely)": h_rogue["launcher"]["assigned_spiffe_id"],
    }
    for k, v in h_ids.items():
        print(f"  hardened {k:58s} -> {v}")
    legit_ok = tool_result(h_legit, "get_record").get("status") == 200
    tamp_res = tool_result(h_tamp, "get_record")
    rogue_attempts = h_rogue.get("attempts", [])
    attacks_failed = (tamp_res.get("status") != 200
                      and all(a.get("status") != 200 for a in rogue_attempts) and len(rogue_attempts) == 2)
    hard_res = {
        "outcome": "BLOCKED" if (len(set(h_ids.values())) == 3 and attacks_failed and legit_ok) else "NOT BLOCKED",
        "evidence": {"spiffe_ids": h_ids,
                     "positive_control_legit_agent_reads_alice": legit_ok,
                     "tampered_agent": tamp_res.get("error"),
                     "rogue_agent": [{a["path"]: a.get("error")} for a in rogue_attempts]},
    }
    print(f"  positive control (approved agent, alice reads alice): {'OK' if legit_ok else 'FAILED'}")
    print(f"  tampered agent -> {tamp_res.get('error')}")
    for a in rogue_attempts:
        print(f"  rogue agent    -> {a['path']}: {a.get('status')} {a.get('error')}")
    return {"id": "G1", "title": "Interpreter collapse", "naive": naive_res, "hardened": hard_res}


def g2():
    banner("G2  Generated code inherits the agent's identity (code-interpreter tool)")
    task = ["--task", "summarize q3_report.md"]
    n = naive(RESEARCH, task, user="alice")
    nr = tool_result(n, "run_python")
    n_out = json.loads(nr.get("stdout") or "{}") if nr.get("stdout", "").strip().startswith("{") else {}
    print(f"  naive    injected code ran in {nr.get('where')} as {n_out.get('ran_as')}"
          f" -> exfiltrated: {list((n_out.get('exfil') or {}).keys())}")
    h = hardened(RESEARCH, task, user="alice")
    hr = tool_result(h, "run_python")
    h_out = json.loads(hr.get("stdout") or "{}") if hr.get("stdout", "").strip().startswith("{") else {}
    print(f"  hardened injected code ran in {hr.get('where')} -> {h_out.get('error') or h_out}")
    # Positive control: the sandbox still runs code normally (the attack fails for identity reasons, not because the tool is broken).
    _, ctl, _ = request("POST", "127.0.0.1", 7000, "/exec", body={"code": "print(6*7)"}, timeout=60)
    ctl_ok = ctl.get("stdout", "").strip() == "42"
    print(f"  positive control (sandbox executes benign code): {'OK' if ctl_ok else 'FAILED'}")
    return {"id": "G2", "title": "Generated code inherits agent identity",
            "naive": {"outcome": "EXPLOITED" if n_out.get("exfil") else "NOT EXPLOITED",
                      "evidence": {"where": nr.get("where"), "ran_as": n_out.get("ran_as"),
                                   "records_exfiltrated": list((n_out.get("exfil") or {}).keys())}},
            "hardened": {"outcome": "BLOCKED" if (not h_out.get("exfil") and h_out and ctl_ok) else "NOT BLOCKED",
                         "evidence": {"where": hr.get("where"), "result": h_out.get("error"),
                                      "positive_control_sandbox_runs_code": ctl_ok}}}


def g3():
    banner("G3  Credential replay through a tool (bearer JWT-SVID vs sender-constrained passport)")
    task = ["--task", "summarize vendor_note.md"]
    loot_reset()
    naive(RESEARCH, task, user="alice")
    n_loot = loot()
    for l in n_loot:
        print(f"  naive    {l['attempt']}: {l['status']} -> stole {list((l['stolen'] or {}).keys())}")
    loot_reset()
    h = hardened(RESEARCH, task, user="alice")
    h_loot = loot()
    for l in h_loot:
        print(f"  hardened {l['attempt']}: {l['status']} {l['error']}")
    passport_issued = any(t.get("step") == "broker" and t.get("status") == 200 for t in h.get("trace", []))
    return {"id": "G3", "title": "Credential replay via tool",
            "naive": {"outcome": "EXPLOITED" if any(l["success"] for l in n_loot) else "NOT EXPLOITED",
                      "evidence": n_loot},
            "hardened": {"outcome": "BLOCKED" if (h_loot and not any(l["success"] for l in h_loot)
                                                  and passport_issued) else "NOT BLOCKED",
                         "evidence": {"replays": h_loot, "positive_control_passport_was_issued_and_leaked": passport_issued}}}


def g4():
    banner("G4  Delegation erasure: the API sees the agent, not the human behind it")
    task = ["--task", "show me the record for bob"]
    n = tool_result(naive(RESEARCH, task, user="alice"), "get_record")
    print(f"  naive    alice asks for bob's record -> {n.get('status')} {n.get('record', {}).get('salary', n.get('error'))}"
          f" (authorised as {n.get('authorised_as')})")
    h = tool_result(hardened(RESEARCH, task, user="alice"), "get_record")
    print(f"  hardened alice asks for bob's record -> {h.get('status')} {h.get('error')}")
    own = tool_result(hardened(RESEARCH, ["--task", "show me the record for alice"], user="alice"), "get_record")
    admin = tool_result(hardened(RESEARCH, task, user="dana"), "get_record")
    print(f"  positive control alice->alice: {own.get('status')} | dana(hr_admin)->bob: {admin.get('status')}")
    return {"id": "G4", "title": "Delegation erasure (confused deputy)",
            "naive": {"outcome": "EXPLOITED" if n.get("status") == 200 else "NOT EXPLOITED",
                      "evidence": {"status": n.get("status"), "authorised_as": n.get("authorised_as"),
                                   "leaked": n.get("record")}},
            "hardened": {"outcome": "BLOCKED" if (h.get("status") == 403 and own.get("status") == 200
                                                  and admin.get("status") == 200) else "NOT BLOCKED",
                         "evidence": {"alice_to_bob": h.get("error"), "positive_alice_to_alice": own.get("status"),
                                      "positive_dana_hr_admin_to_bob": admin.get("status"),
                                      "on_behalf_of": admin.get("on_behalf_of"), "actor": admin.get("actor")}}}


def main():
    t0 = time.time()
    results = [g1(), g2(), g3(), g4()]
    banner("SCORECARD")
    lines = ["| Gap | Naive SPIFFE wiring | Hardened (launcher + sandbox uid + passport) |", "|---|---|---|"]
    for r in results:
        print(f"  {r['id']}  {r['title']:42s} naive: {r['naive']['outcome']:14s} hardened: {r['hardened']['outcome']}")
        lines.append(f"| {r['id']} {r['title']} | {r['naive']['outcome']} | {r['hardened']['outcome']} |")
    print(f"\n  completed in {time.time() - t0:.0f}s")
    with open("/lab/out/scorecard.json", "w") as f:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results}, f, indent=2)
    with open("/lab/out/scorecard.md", "w") as f:
        f.write("\n".join(lines) + "\n")
    ok = all(r["naive"]["outcome"] == "EXPLOITED" and r["hardened"]["outcome"] == "BLOCKED" for r in results)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
