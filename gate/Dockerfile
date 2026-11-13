# artifact-gate image: the single stdlib-only file gate/gate.py on a digest-pinned Python base.
# No pip install, no added package, no tests. Same code, same command and same path
# (/app/gate.py) as the ConfigMap mode of the Helm chart, so both modes run identical code.
#
# Build from the repository root (the root .dockerignore lets only gate/gate.py into the context):
#   docker build -f gate/Dockerfile --build-arg REVISION="$(git rev-parse HEAD)" -t artifacts-gate:dev .
# Run as the numeric non-root user below with a read-only root filesystem (the gate writes no file):
#   docker run --read-only --user 1000:1000 --cap-drop ALL -e ... artifacts-gate:dev
# Published images: .github/workflows/publish.yml (README, "Gate image").
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# REVISION is the 40-hex commit the image is built from; the publish workflow sets it.
ARG REVISION=""
ARG SOURCE="https://github.com/pocharlies-org/artifacts"
LABEL org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="artifacts-gate" \
      org.opencontainers.image.description="artifact-gate: per-artifact authorization for an artifacts host" \
      org.opencontainers.image.licenses="Apache-2.0"

# No bytecode cache (the root filesystem is read-only), unbuffered logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Debian updates published after the base digest was cut (upgrade only: no package is added
# or removed). A re-run of the publish workflow at the same commit picks up new fixes.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Root-owned and read-only for everyone: the runtime user can read the code, never change it.
# WORKDIR creates /app as 0755 first: COPY --chmod would otherwise create it 0444 (not traversable).
WORKDIR /app
COPY --chown=0:0 --chmod=0444 gate/gate.py /app/gate.py

# Numeric uid/gid (Kubernetes runAsNonRoot can verify it); the chart runs the pod as 1000:1000.
USER 1000:1000

# 8080 public request-access surface, 8081 decision listener (GATE_PORT / GATE_AUTH_PORT).
EXPOSE 8080 8081
CMD ["python3", "/app/gate.py"]
