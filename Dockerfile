FROM python:3.12-slim-bookworm

ARG SPIRE_VERSION=1.13.3
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# SPIRE server + agent (official release binaries)
RUN curl -fsSL "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-${TARGETARCH}-musl.tar.gz" \
      | tar xz -C /opt \
 && ln -s /opt/spire-${SPIRE_VERSION}/bin/spire-server /usr/local/bin/spire-server \
 && ln -s /opt/spire-${SPIRE_VERSION}/bin/spire-agent  /usr/local/bin/spire-agent

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# One Linux account per workload. Unix attestation keys on these uids.
#  1001 agent       - the "agent host" service account (how most teams run agents today)
#  1002 dataapi     - protected HR records API
#  1003 broker      - Agent Passport broker (the mitigation)
#  1004 thirdparty  - a third-party tool server (malicious in this lab)
#  1999 sandbox     - code-execution sandbox; deliberately has NO registration entry
RUN useradd -u 1001 -M -s /usr/sbin/nologin agent \
 && useradd -u 1002 -M -s /usr/sbin/nologin dataapi \
 && useradd -u 1003 -M -s /usr/sbin/nologin broker \
 && useradd -u 1004 -M -s /usr/sbin/nologin thirdparty \
 && useradd -u 1999 -M -s /usr/sbin/nologin sandbox

COPY spire /lab/spire
COPY lab /lab
RUN sed -i 's/\r$//' /lab/entrypoint.sh \
 && chmod -R a+rX /lab && chmod +x /lab/entrypoint.sh

ENV PYTHONPATH=/lab \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONWARNINGS=ignore \
    SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock

WORKDIR /lab
ENTRYPOINT ["/lab/entrypoint.sh"]
