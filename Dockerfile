FROM python:3.11-alpine

WORKDIR /app

# Install network utilities and build dependencies for cryptography/lxml
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    libxml2-dev \
    libxslt-dev \
    bind-tools \
    tcpdump

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-privileged user for OPSEC
RUN adduser -D nexususer
USER nexususer

ENTRYPOINT ["python", "-m", "nexus_intelligence"]
