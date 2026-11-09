"""Protected HR records API, served two ways.

:8000  NAIVE    - the common pattern today. Bearer JWT-SVID, authorise on the caller's
                  SPIFFE ID. If the ID is the agent's, the agent can read anything.
:8443  HARDENED - mTLS with X509-SVIDs plus an Agent Passport (sender-constrained,
                  delegated, manifest-bound). Authorisation is decided by the
                  human the agent acts for, capped by what the approved agent may do.
"""
from __future__ import annotations

import sys
import threading

import jwt

from common import manifest as mf
from common.http import serve
from common.spiffe_util import (DATA_API_ID, server_context, spiffe_id_from_der, thumbprint,
                                validate_jwt_svid, write_tls_files)

RECORDS = {
    "alice": {"owner": "alice", "title": "Engineer II", "salary": "$128,000", "note": "Q3: meets expectations"},
    "bob": {"owner": "bob", "title": "Staff Engineer", "salary": "$182,000", "note": "Q3: PIP under discussion"},
    "carol": {"owner": "carol", "title": "Director", "salary": "$240,000", "note": "Q3: retention risk"},
}

# Naive policy: what most teams write. "The research agent may read records."
NAIVE_POLICY = {"spiffe://lab.local/agent/research": {"records:read:any"}}

BROKER_PUB = "/lab/run/broker_pub.pem"
PASSPORT_ISS = "spiffe://lab.local/svc/broker"


# ------------------------------------------------------------------ naive ---

def naive_auth(h):
    authz = h.headers.get("Authorization", "")
    if not authz.startswith("Bearer "):
        return None, (401, {"error": "missing bearer JWT-SVID"})
    try:
        caller = validate_jwt_svid(authz[7:], DATA_API_ID)
    except Exception as e:  # noqa: BLE001
        return None, (401, {"error": f"invalid JWT-SVID: {e}"})
    if "records:read:any" not in NAIVE_POLICY.get(caller, set()):
        return None, (403, {"error": f"{caller} not authorised", "caller": caller})
    return caller, None


def naive_get_one(h, _body):
    caller, err = naive_auth(h)
    if err:
        return err
    user = h.path.rsplit("/", 1)[-1]
    if user not in RECORDS:
        return 404, {"error": "no such record"}
    return 200, {"authorised_as": caller, "record": RECORDS[user]}


def naive_get_all(h, _body):
    caller, err = naive_auth(h)
    if err:
        return err
    return 200, {"authorised_as": caller, "records": RECORDS}


# --------------------------------------------------------------- hardened ---

def hardened_auth(h, needed_scope: str):
    der = h.peer_der()
    if not der:
        return None, (401, {"error": "mTLS client certificate required"})
    peer_id = spiffe_id_from_der(der)
    authz = h.headers.get("Authorization", "")
    if not authz.startswith("Passport "):
        return None, (401, {"error": "Agent Passport required", "peer": peer_id})
    try:
        with open(BROKER_PUB, "rb") as f:
            claims = jwt.decode(authz[9:], f.read(), algorithms=["ES256"], audience=DATA_API_ID,
                                issuer=PASSPORT_ISS)
    except Exception as e:  # noqa: BLE001
        return None, (401, {"error": f"invalid passport: {e}"})

    # 1. Sender constraint (RFC 8705-style). A stolen passport is useless without the agent's private key.
    if claims.get("cnf", {}).get("x5t#S256") != thumbprint(der):
        return None, (401, {"error": "passport is bound to a different key (replay?)", "presented_by": peer_id})
    # 2. The actor in the passport must be the peer on this connection.
    act = claims.get("act", {})
    if act.get("sub") != peer_id:
        return None, (401, {"error": "actor mismatch", "act": act.get("sub"), "peer": peer_id})
    # 3. Check the manifest again on every call, so revoking an approval takes effect at once.
    if act.get("manifest") not in mf.load_approved():
        return None, (403, {"error": "agent manifest no longer approved"})
    # 4. Scope.
    if needed_scope not in claims.get("scope", "").split():
        return None, (403, {"error": f"scope {needed_scope} not granted", "scope": claims.get("scope")})
    return claims, None


def hardened_get_one(h, _body):
    claims, err = hardened_auth(h, "records:read")
    if err:
        return err
    target = h.path.rsplit("/", 1)[-1]
    if target not in RECORDS:
        return 404, {"error": "no such record"}
    user, roles = claims["sub"], claims.get("roles", [])
    # Decide on the human the agent acts for. The agent's own power is not used.
    if target != user and "hr_admin" not in roles:
        return 403, {"error": f"user {user} may not read {target}'s record", "on_behalf_of": user,
                     "actor": claims["act"]["sub"]}
    return 200, {"on_behalf_of": user, "actor": claims["act"]["sub"], "task": claims.get("task"),
                 "record": RECORDS[target]}


def hardened_get_all(h, _body):
    claims, err = hardened_auth(h, "records:export")
    if err:
        return err
    return 200, {"records": RECORDS}


def main():
    tls = write_tls_files()
    print(f"[data-api] identity {tls.spiffe_id}", file=sys.stderr)
    naive = serve(8000, {("GET", "/records/"): naive_get_one, ("GET", "/records"): naive_get_all}, "data-api:naive")
    hard = serve(8443, {("GET", "/records/"): hardened_get_one, ("GET", "/records"): hardened_get_all},
                 "data-api:hardened", ssl_ctx=server_context(tls, require_client_cert=True))
    threading.Thread(target=naive.serve_forever, daemon=True).start()
    hard.serve_forever()


if __name__ == "__main__":
    main()
