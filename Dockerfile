FROM python:3.11-slim as builder

# Optimization: Use specialized build-time environment
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

# OPSEC: Isolation via non-privileged user
RUN useradd -m nexus -s /bin/bash
WORKDIR /home/nexus/app

# Import dependencies from builder
COPY --from=builder /root/.local /home/nexus/.local
ENV PATH=/home/nexus/.local/bin:$PATH

# Deploy application and fix permissions
COPY . .
RUN chown -R nexus:nexus /home/nexus/app

USER nexus

# Configuration defaults
ENV NEXUS_TIMEOUT=15
ENV NEXUS_THREADS=8
ENV NEXUS_OUTPUT_DIR=reports

ENTRYPOINT ["python", "-m", "nexus_intelligence"]
CMD ["--help"]
