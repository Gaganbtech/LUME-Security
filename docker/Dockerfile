# Multi-stage Dockerfile for LUME Security Toolkit
# Compatible with Kali Linux, Debian, Ubuntu, and Container Runtimes

FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip wheel setuptools
RUN pip wheel --no-cache-dir --wheel-dir /build/wheels -e .

# Final stage
FROM python:3.12-slim

LABEL maintainer="LUME Security Team <security@lume.dev>"
LABEL description="Enterprise AI Security & Prompt Injection CLI Toolkit"

# Create unprivileged application user
RUN groupadd -g 1000 lume && \
    useradd -u 1000 -g lume -m -s /bin/bash lume

WORKDIR /app

# Install runtime dependencies from wheels
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application source, configs, and fixtures
COPY --chown=lume:lume . /app

# Install package in editable/live mode for user
RUN pip install --no-cache-dir -e .

# Ensure report output directory has proper permissions
RUN mkdir -p /app/reports && chown -R lume:lume /app/reports

USER lume

# Ensure reports directory is persisted
VOLUME ["/app/reports"]

ENTRYPOINT ["lume"]
CMD ["--help"]
