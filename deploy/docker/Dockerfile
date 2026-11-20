# syntax=docker/dockerfile:1.7
# cctl control plane: the HTTP API (cctl serve) with the tools the policy gate
# shells out to. Build from the repository root:
#
#   docker build -f deploy/docker/Dockerfile \
#     --build-arg BASE_IMAGE=python:3.13-slim-bookworm@sha256:<digest> \
#     --build-arg TERRAFORM_SHA256=<sha256 of terraform_1.10.5_linux_amd64.zip> \
#     --build-arg KUBECTL_SHA256=<sha256 of kubectl v1.31.4 linux/amd64> \
#     --build-arg EXTRAS=service \
#     -t cctl-control-plane:dev .
#
# Every downloaded binary is checked against a SHA256 you pass in; the build
# fails without one. Take the sums from HashiCorp's SHA256SUMS file (verify its
# signature) and from dl.k8s.io/<version>/bin/linux/amd64/kubectl.sha256.
# EXTRAS: service (AWS), service-azure, or service-gcp; "service,service-azure,service-gcp" for all.

ARG BASE_IMAGE=python:3.13-slim-bookworm

# ── tools: terraform, kubectl, checkov (pinned, checksummed) ─────────────────
FROM ${BASE_IMAGE} AS tools
ARG TERRAFORM_VERSION=1.10.5
ARG TERRAFORM_SHA256
ARG KUBECTL_VERSION=1.31.4
ARG KUBECTL_SHA256
ARG CHECKOV_VERSION=3.2.334
ARG TARGETARCH=amd64
RUN if [ -z "$TERRAFORM_SHA256" ] || [ -z "$KUBECTL_SHA256" ]; then \
      echo "TERRAFORM_SHA256 and KUBECTL_SHA256 build args are required" >&2; exit 1; fi
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN mkdir -p /out/bin
RUN curl -fsSLo tf.zip "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" \
 && echo "${TERRAFORM_SHA256}  tf.zip" | sha256sum -c - \
 && unzip tf.zip terraform && install -m 0755 terraform /out/bin/terraform
RUN curl -fsSLo kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
 && echo "${KUBECTL_SHA256}  kubectl" | sha256sum -c - \
 && install -m 0755 kubectl /out/bin/kubectl
# checkov in its own virtualenv so its pins never meet cctl's
RUN python -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}"

# ── build: cctl wheel and its runtime dependencies ───────────────────────────
FROM ${BASE_IMAGE} AS build
ARG EXTRAS=service
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY cloudctl ./cloudctl
RUN python -m venv /opt/cctl \
 && /opt/cctl/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/cctl/bin/pip install --no-cache-dir ".[${EXTRAS}]"

# ── runtime ──────────────────────────────────────────────────────────────────
FROM ${BASE_IMAGE} AS runtime
LABEL org.opencontainers.image.source="https://github.com/cloudctlio/cloudctl" \
      org.opencontainers.image.title="cctl control plane" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 cctl && useradd --uid 10001 --gid 10001 --home-dir /home/cctl --create-home --shell /usr/sbin/nologin cctl
COPY --from=tools /out/bin/ /usr/local/bin/
COPY --from=tools /opt/checkov /opt/checkov
COPY --from=build /opt/cctl /opt/cctl
RUN ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov
ENV PATH=/opt/cctl/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/cctl \
    TF_IN_AUTOMATION=1 \
    TF_INPUT=0 \
    TF_PLUGIN_CACHE_DIR=/home/cctl/.terraform.d/plugin-cache \
    CHECKPOINT_DISABLE=1 \
    CLOUDCTL_SERVICE_CONFIG=/etc/cctl/service.yaml
USER 10001:10001
WORKDIR /home/cctl
EXPOSE 8080
# The pod runs with a read-only root filesystem; /tmp and /home/cctl are emptyDir volumes.
HEALTHCHECK NONE
ENTRYPOINT ["/usr/bin/tini", "--", "cloudctl", "serve"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
