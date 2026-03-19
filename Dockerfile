FROM python:3.12-slim

LABEL maintainer="Smail Haroun"
LABEL description="SentinelAudit — Professional Linux security audit tool"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY sentinel_audit/ sentinel_audit/

RUN pip install --no-cache-dir ".[pdf]"

RUN useradd --create-home --shell /bin/bash auditor
USER auditor
WORKDIR /home/auditor

ENTRYPOINT ["sentinel-audit"]
CMD ["--help"]
