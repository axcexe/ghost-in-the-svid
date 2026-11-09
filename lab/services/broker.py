"""Agent Passport broker: the mitigation.

Mints a short-lived token answering three questions that an SVID alone can't:
  WHO is the human being acted for?        sub, roles      (from the user's IdP token)
  WHAT exactly is acting?                  act.sub + act.manifest (manifest-bound SPIFFE ID)
  WHO may present this token?              cnf.x5t#S256    (the agent's X509-SVID key)

Conceptually this is an RFC 8693 token exchange:
  subject_token = user's IdP token, actor = agent's X509-SVID over mTLS.
Keycloak or PingOne AIC could host the same policy. This lab inlines it so it can run fully offline.
"""
from __future__ import annotations

import sys
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from common import manifest as mf
from common.http import serve
from common.spiffe_util import DATA_API_ID, server_context, spiffe_id_from_der, thumbprint, write_tls_files
from services import idp

PASSPORT_TTL = 60  # seconds. Matches a task, not a deployment.
KEY = ec.generate_private_key(ec.SECP256R1())


def mint(h, body):
    der = h.peer_der()
    peer_id = spiffe_id_from_der(der) if der else ""
    name, mhash = mf.parse_agent_id(peer_id)
    if not mhash:
        return 403, {"error": "unbound agent identity: SPIFFE ID carries no manifest", "peer": peer_id}
    approved = mf.load_approved()
    if mhash not in approved or approved[mhash]["agent"] != name:
        return 403, {"error": "agent manifest not approved", "peer": peer_id, "manifest": mhash}

    try:
        user = idp.verify(body.get("user_token", ""))
    except Exception as e:  # noqa: BLE001
        return 401, {"error": f"invalid user token: {e}"}

    ceiling = set(approved[mhash]["max_scopes"])
    requested = set(body.get("scope", "").split())
    granted = sorted(requested & ceiling)
    if not granted:
        return 403, {"error": "no requested scope is within the agent's ceiling",
                     "requested": sorted(requested), "ceiling": sorted(ceiling)}

    now = int(time.time())
    claims = {
        "iss": "spiffe://lab.local/svc/broker",
        "aud": DATA_API_ID,
        "sub": user["sub"],
        "roles": user.get("roles", []),
        "scope": " ".join(granted),
        "act": {"sub": peer_id, "manifest": mhash},
        "cnf": {"x5t#S256": thumbprint(der)},
        "task": body.get("task", "")[:200],
        "iat": now,
        "exp": now + PASSPORT_TTL,
        "jti": str(uuid.uuid4()),
    }
    return 200, {"passport": jwt.encode(claims, KEY, algorithm="ES256"), "expires_in": PASSPORT_TTL,
                 "granted_scope": claims["scope"]}


def main():
    with open("/lab/run/broker_pub.pem", "wb") as f:
        f.write(KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo))
    tls = write_tls_files()
    print(f"[broker] identity {tls.spiffe_id}", file=sys.stderr)
    serve(8444, {("POST", "/passport"): mint}, "broker",
          ssl_ctx=server_context(tls, require_client_cert=True)).serve_forever()


if __name__ == "__main__":
    main()
