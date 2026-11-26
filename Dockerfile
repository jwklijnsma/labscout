# syntax=docker/dockerfile:1
#
# labscout: scan a homelab, identify the software with a local Ollama model, plan monitoring.
#
#   docker run -d --name labscout --network host --cap-add NET_RAW --cap-add NET_ADMIN \
#     -v ~/.config/labscout:/config -v labscout-data:/data \
#     -e LABSCOUT_WEB_TOKEN="$(openssl rand -hex 24)" --env-file ~/.config/labscout/secrets.env \
#     ghcr.io/jwklijnsma/labscout
#
# --network host + NET_RAW: nmap can only see MAC addresses and do ARP discovery on the
# networks the container is really attached to. Ollama is not in this image.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# hadolint ignore=DL3013
RUN pip install . && labscout --version

FROM python:${PYTHON_VERSION}-slim
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="labscout" \
      org.opencontainers.image.description="Discover a homelab with a local Ollama model: scan, identify, plan monitoring, fill NetBox" \
      org.opencontainers.image.source="https://github.com/jwklijnsma/labscout" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# nmap: discovery + service versions; git: `apply --infra` commits on a branch; tini: PID 1.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap git tini ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*' \
 && mkdir -p /config /data && chmod 0777 /data

COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    LABSCOUT_STATE_DIR=/data \
    OLLAMA_HOST=http://127.0.0.1:11434

WORKDIR /data
EXPOSE 8766
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8766/app.css', timeout=4); sys.exit(0)"]
STOPSIGNAL SIGINT
ENTRYPOINT ["tini", "--", "labscout"]
CMD ["serve", "-c", "/config/labscout.yml", "--bind", "0.0.0.0", "--port", "8766"]
