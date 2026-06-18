FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libffi-dev libssl-dev \
    && python -m venv "$VIRTUAL_ENV" \
    && "$VIRTUAL_ENV/bin/pip" install --upgrade pip setuptools wheel \
    && "$VIRTUAL_ENV/bin/pip" install cryptography==46.0.5

FROM python:3.12-slim AS runtime
ENV PATH=/opt/venv/bin:$PATH \
    TG_RE_PROXY_HOST=0.0.0.0 \
    TG_RE_PROXY_PORT=1444 \
    TG_RE_PROXY_CF_WORKER=""
RUN apt-get update && apt-get install -y --no-install-recommends tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY transparent.py ./
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/venv/bin/python", "-u", "transparent.py"]
