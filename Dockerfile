FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias de sistema minimas para red y criptografia
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Seguridad Operativa: Usuario no privilegiado
RUN useradd -m nexususer
USER nexususer

ENTRYPOINT ["python", "-m", "nexus_intelligence"]
