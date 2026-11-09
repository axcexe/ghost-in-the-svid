#!/usr/bin/env bash
# Boots SPIRE server + agent, registers the baseline ("naive") workloads, starts the
# services under their own uids, then (optionally) runs every experiment.
set -euo pipefail

SRV_SOCK=/tmp/spire-server/private/api.sock
AGT_SOCK=/run/spire/sockets/agent.sock
LOG=/lab/run/logs
# The lab is ephemeral: a restarted container must not reuse stale SPIRE state
# (an already-attested agent + a new join token would never become healthy).
rm -rf /opt/spire/data /lab/run /tmp/spire-server /run/spire/sockets
mkdir -p /run/spire/sockets /opt/spire/data/server /opt/spire/data/agent "$LOG" /lab/run/instances /lab/out
chmod 1777 /lab/run   # services drop small public files here (e.g. broker_pub.pem)
chmod 755 /run/spire/sockets

echo "==> starting SPIRE server"
spire-server run -config /lab/spire/server.conf >"$LOG/spire-server.log" 2>&1 &
until spire-server healthcheck -socketPath "$SRV_SOCK" >/dev/null 2>&1; do sleep 1; done

TOKEN=$(spire-server token generate -socketPath "$SRV_SOCK" -spiffeID spiffe://lab.local/node | awk '{print $2}')
echo "==> starting SPIRE agent (join token attestation)"
spire-agent run -config /lab/spire/agent.conf -joinToken "$TOKEN" >"$LOG/spire-agent.log" 2>&1 &
until spire-agent healthcheck -socketPath "$AGT_SOCK" >/dev/null 2>&1; do sleep 1; done

PY=$(readlink -f "$(command -v python3)")
PY_SHA=$(sha256sum "$PY" | awk '{print $1}')
echo "==> interpreter $PY sha256=$PY_SHA"

reg() { # reg <spiffe-id> <uid>
  spire-server entry create -socketPath "$SRV_SOCK" -parentID spiffe://lab.local/node \
    -spiffeID "$1" -selector "unix:uid:$2" -selector "unix:sha256:$PY_SHA" >/dev/null
  echo "    registered $1  <=  unix:uid:$2 + unix:sha256:<python3>"
}
echo "==> registering workloads (the way most Python agents get attested today)"
reg spiffe://lab.local/agent/research 1001
reg spiffe://lab.local/svc/data-api 1002
reg spiffe://lab.local/svc/broker 1003
reg spiffe://lab.local/tool/summarizer 1004
echo "    (uid 1999 'sandbox' intentionally has no entry)"

python3 -m services.idp init

run_as() { # run_as <uid> <name> <module>
  setpriv --reuid="$1" --regid="$1" --clear-groups env HOME=/tmp python3 -m "$3" >"$LOG/$2.log" 2>&1 &
}
echo "==> starting services"
run_as 1002 data-api services.data_api
run_as 1003 broker services.broker
run_as 1004 evil-tool services.evil_tool
run_as 1999 sandbox services.sandbox_exec

wait_port() { for _ in $(seq 1 60); do (echo >/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 1; done; echo "port $1 never opened"; cat "$LOG"/*.log; exit 1; }
for p in 8000 8443 8444 7001 7000; do wait_port "$p"; done
echo "    data-api :8000 (naive) :8443 (hardened) | broker :8444 | evil-tool :7001 | sandbox :7000"

echo "==> approving the legitimate research agent manifest"
MH=$(python3 /lab/launcher.py approve --script /lab/agents/research_agent.py --config /lab/agents/research.json --max-scope records:read)
echo "    approved m-$MH (max scope: records:read)"

if [[ "${RUN_SCENARIOS:-1}" == "1" ]]; then
  python3 /lab/scenarios/run_all.py
fi

if [[ "${STAY_UP:-0}" == "1" ]]; then
  echo "==> stack is up. Try: docker compose exec lab bash"
  tail -f /dev/null
fi
