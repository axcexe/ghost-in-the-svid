#!/usr/bin/env bash
# Guided tour of the lab. Run inside the container:  bash explore.sh
# Each step prints the command it runs, so you can copy it and modify it.
set -u
cd /lab
SRV=/tmp/spire-server/private/api.sock
AGT=/run/spire/sockets/agent.sock
step() { echo; echo "────────────────────────────────────────────────────────────"; echo "STEP $1"; echo "────────────────────────────────────────────────────────────"; }
show() { echo "\$ $*"; eval "$@"; }

step "1. What has SPIRE been told to trust? (registration entries)"
show "spire-server entry show -socketPath $SRV | grep -E 'SPIFFE ID|Selector'"

step "2. Ask the Workload API 'who am I?' as uid 1001 (the agent account)"
show "setpriv --reuid=1001 --regid=1001 --clear-groups python3 -c 'from common.spiffe_util import whoami; print(whoami())'"

step "3. Same uid, but a different binary (the spire-agent CLI instead of python3)"
echo "   -> refused: the entry also pins unix:sha256 of the python3 interpreter"
show "setpriv --reuid=1001 --regid=1001 --clear-groups spire-agent api fetch x509 -socketPath $AGT 2>&1 | tail -1"

step "4. Same python3, but uid 1999 (the sandbox, which has no entry)"
show "setpriv --reuid=1999 --regid=1999 --clear-groups python3 -c 'from common.spiffe_util import whoami; print(whoami(retries=2))' 2>&1 | tail -1"

step "5. NAIVE: Alice asks the agent for Bob's record"
export USER_TOKEN=$(python3 -m services.idp issue alice)
show "setpriv --reuid=1001 --regid=1001 --clear-groups python3 agents/research_agent.py --task 'show me the record for bob' | python3 -m json.tool"

step "6. HARDENED: the same request through the trusted launcher + passport"
show "python3 launcher.py launch --script agents/research_agent.py --config agents/research.json -- --mode hardened --task 'show me the record for bob'"

step "7. Look inside Alice's IdP token: the 'who is the human' half of the passport"
show "python3 - <<'EOF'
import json, jwt
from services import idp
print('user token claims:', json.dumps(jwt.decode(idp.issue('alice'), options={'verify_signature': False}), indent=2))
EOF"
echo "   (passport claims sub/act/cnf/scope are printed by the broker trace in step 6)"

echo; echo "Done. Edit agents/research.json (e.g. change the system prompt) and re-run step 6 to watch the SPIFFE ID change."
