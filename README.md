# Ghost in the SVID

**SPIFFE proves which process is running. For an AI agent, you need to know what is acting, and for whom.**

This lab runs real SPIRE and shows four ways that standard SPIFFE workload identity
goes wrong when the workload is an LLM agent. It then implements and verifies a
mitigation for each, all in one `docker compose up`.

Every experiment runs twice, once against the "naive" wiring (the way Python agents
are typically attested today) and once against the hardened wiring. Results only count
when data actually leaves the API (for EXPLOITED) or when the attack fails *and* a
positive control passes (for BLOCKED).

## Quick start

```bash
docker compose up --build
```

It boots SPIRE server and agent, registers the workloads, starts five services, runs every
experiment, and writes `results/scorecard.md` and `results/scorecard.json`.

### Poke around yourself

```bash
# PowerShell: keep the stack running, skip the automatic experiments
$env:STAY_UP="1"; $env:RUN_SCENARIOS="0"; docker compose up -d --build
docker compose exec lab bash      # you are now root inside the lab
bash explore.sh                   # 7-step guided tour; every command is printed so you can copy it
python3 scenarios/run_all.py      # run the full experiment suite by hand
exit
docker compose down               # stop everything
```

No API keys and no cloud accounts. Cost: $0. A full run takes about 45 seconds once the image is built.

## Results (SPIRE 1.13.3, reproduced on consecutive clean runs)

| Gap | Naive SPIFFE wiring | Hardened (launcher + sandbox uid + passport) |
|---|---|---|
| G1 Interpreter collapse | EXPLOITED | BLOCKED |
| G2 Generated code inherits agent identity | EXPLOITED | BLOCKED |
| G3 Credential replay via tool | EXPLOITED | BLOCKED |
| G4 Delegation erasure (confused deputy) | EXPLOITED | BLOCKED |

Excerpt from the run log:

```
naive    research_agent.py + approved prompt/model              -> spiffe://lab.local/agent/research
naive    research_agent.py + tampered prompt, abliterated model -> spiffe://lab.local/agent/research
naive    rogue_agent.py (different code entirely)               -> spiffe://lab.local/agent/research
hardened research_agent.py + approved prompt/model              -> spiffe://lab.local/agent/research/m-4063a147463d862d
hardened research_agent.py + tampered prompt, abliterated model -> spiffe://lab.local/agent/research/m-6b1e3b6522251723
hardened rogue_agent.py (different code entirely)               -> spiffe://lab.local/agent/research/m-2cc5dc2efd4be2e8

naive    injected code ran in subprocess uid=1001 as spiffe://lab.local/agent/research -> exfiltrated: ['alice','bob','carol']
hardened injected code ran in sandbox service uid=1999 -> no identity issued (PERMISSION_DENIED)

naive    replay bearer JWT-SVID -> naive API /records: 200 -> stole ['alice','bob','carol']
hardened replay passport, no client cert             -> TLSV13_ALERT_CERTIFICATE_REQUIRED
hardened replay passport over mTLS with tool's SVID  -> 401 passport is bound to a different key (replay?)

naive    alice asks for bob's record -> 200 $182,000 (authorised as spiffe://lab.local/agent/research)
hardened alice asks for bob's record -> 403 user alice may not read bob's record
positive control alice->alice: 200 | dana(hr_admin)->bob: 200
```

## The four gaps

### G1: Interpreter collapse
SPIRE's unix workload attestor identifies a process by uid, gid, binary path, and
`sha256` of `/proc/<pid>/exe`. Almost every agent is Python or Node, so **that binary is the
interpreter**. Three very different things all get the *same* SPIFFE ID:

* the approved agent,
* the same agent with its system prompt rewritten and its model swapped for an "abliterated" (refusal-removed) one,
* a completely different script running under the same service account.

The Kubernetes attestor has the same problem one level up: it attests pod, namespace,
service account, and image. It can't see the prompt, the model weights the pod loads at runtime, or the tool list.

**Mitigation: manifest-bound identity via a trusted launcher** (`lab/launcher.py`).
The launcher copies the code and config to a root-owned, read-only instance dir. It hashes
*code + model + system-prompt + tool list* and gives the instance a fresh uid. It registers
`spiffe://lab.local/agent/<name>/m-<manifest-hash>` for that uid only, execs the agent, and
deletes the entry on exit. Any change to the agent produces a new SPIFFE ID that no
policy has approved.

### G2: Generated code inherits the agent's identity
Code-interpreter tools usually run model-written code as a **child process of the agent**.
The child has the same uid and the same interpreter, so the Workload API hands it the
agent's SVID. In the lab, a prompt injection hidden in a document makes the agent
run code that fetches a JWT-SVID and bulk-exports every HR record.

**Mitigation:** model-written code runs in a separate sandbox service under uid 1999, which
has *no registration entry*. The Workload API refuses to issue it an identity.
Nothing in the agent needs to cooperate.

### G3: Bearer SVID replay through a tool
JWT-SVIDs are bearer tokens. When a framework forwards the agent's `Authorization`
header to a tool ("token passthrough"), a malicious tool can replay it. In the lab, the
third-party summariser replays the agent's JWT-SVID and exports every record.

**Mitigation: Agent Passport** (`lab/services/broker.py`). This is a 60-second token with
`cnf.x5t#S256` bound to the agent's X509-SVID key (RFC 8705 style). The hardened API
requires mTLS, and the client certificate's thumbprint must match. In the lab the passport
*is* leaked to the tool on purpose, and both replays fail: without a client cert, and over
mTLS with the tool's own valid SVID.

### G4: Delegation erasure (confused deputy)
An SVID says "this is the research agent". It doesn't say "acting for Alice". The API
authorises the agent's own broad privilege, so Alice asks the agent for Bob's salary and gets it.

**Mitigation:** the passport carries `sub` (the human, taken from the IdP token) and `act`
(the agent's SPIFFE ID + manifest hash), as in RFC 8693 token exchange. The API decides
on the human. The agent's ceiling can only narrow access, never widen it. Positive controls:
Alice can read her own record, and Dana (`hr_admin`) can read Bob's through the same agent.

## Architecture

```
                 ┌───────────────── one Linux container ─────────────────┐
 user token ──►  │  launcher (root) ──entry create──► SPIRE server        │
 (mock IdP)      │     │ exec as fresh uid                 ▲              │
                 │     ▼                                   │ join_token   │
                 │  agent  ──Workload API (unix attestor)──► SPIRE agent  │
                 │   │  │ mTLS(X509-SVID)+user token                      │
                 │   │  └──────────────► broker ──► Agent Passport        │
                 │   │ mTLS + Passport (cnf-bound)                        │
                 │   ├──────────────────────► data-api :8443 (hardened)   │
                 │   ├── code ──► sandbox (uid 1999, no SVID)            │
                 │   └── text ──► evil summariser :7001 (replays creds)  │
                 │                         data-api :8000 (naive)          │
                 └────────────────────────────────────────────────────────┘
```

| uid | workload | SPIFFE ID |
|---|---|---|
| 1001 | agent host account (naive) | `spiffe://lab.local/agent/research` |
| 20000+ | launcher-assigned agent instance | `spiffe://lab.local/agent/research/m-<hash>` |
| 1002 | records API | `spiffe://lab.local/svc/data-api` |
| 1003 | passport broker | `spiffe://lab.local/svc/broker` |
| 1004 | third-party tool | `spiffe://lab.local/tool/summarizer` |
| 1999 | code sandbox | *(none, on purpose)* |

## Mapping to enterprise IAM (PingOne AIC / Keycloak)

The broker is an RFC 8693 token exchange: `subject_token` = the user's IdP token,
actor = the agent authenticated by its X509-SVID over mTLS. In production you'd host
that exchange in your IdP:

* **Keycloak**: the token-exchange feature plus a client-policy or script mapper that adds `act` and `cnf`, with X.509 client authentication against the SPIRE trust bundle.
* **PingOne AIC**: an OAuth2 token-exchange flow with a scripted token modification that adds `act`, `cnf`, and the manifest check. Workload authentication would be mTLS client auth (RFC 8705) against the SPIRE bundle.

The lab inlines the broker, so it runs offline with no tenant.

## Honest limitations

* **The LLM is a deterministic mock** (`lab/agents/mock_llm.py`) that obeys injected
  instructions. These gaps are in the identity layer, and any model that can be talked into a tool call reproduces them. A mock keeps the results reproducible.
* The manifest covers the agent's entry script, not its imported modules. A real launcher should hash the whole package, or run from a signed, read-only image.
* The launcher must itself be trusted and tamper-proof. It is the new root of trust for "what is the agent".
* uid isolation is only the *identity* half of sandboxing. Use seccomp, Landlock, or gVisor for the rest.
* Server, agent, and workloads share one container for simplicity. In production the server is separate, and node attestation would use something stronger than `join_token`.

## Layout

```
spire/                 SPIRE server + agent config
lab/entrypoint.sh      boot, register, start services, run experiments
lab/launcher.py        manifest-bound identity (G1 fix)
lab/services/          data_api (naive+hardened), broker, idp, evil_tool, sandbox_exec
lab/agents/            research agent, rogue agent, configs, mock LLM
lab/docs/              documents carrying indirect prompt injections
lab/scenarios/run_all.py   experiments + scorecard
```
