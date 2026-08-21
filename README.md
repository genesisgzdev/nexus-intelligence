# Nexus Intelligence

Nexus es una herramienta local para reunir señales de OSINT y análisis forense en un mismo informe. Ejecuta consultas asíncronas de DNS, inspecciones TLS, revisión HTTP y lectura de banners de correo. Guarda los hallazgos en SQLite para que cada ejecución pueda revisarse después.

Está pensada para investigar dominios y activos propios o aquellos para los que tengas autorización. No es un servicio de reputación externo ni pretende convertir una señal aislada en una conclusión definitiva.

## Flujo de trabajo

```text
objetivo o archivo de objetivos
          |
          v
workers asyncio -> DNS | TLS | web | mail
          |
          v
SQLite + hallazgos JSON
          |
          v
TF-IDF local -> similitud coseno -> informe Markdown
```

Los módulos actuales cubren:

- registros DNS como A, AAAA, MX, TXT, SOA y CAA
- certificado X.509, fechas, emisor, SAN y huella SHA-256
- cabeceras de seguridad HTTP y metadatos de la respuesta
- banners SMTP cuando el servicio responde
- correlación local con TF-IDF y `scikit-learn`
- ingesta opcional de eventos JSONL de [Threat Detection Suite](https://github.com/genesisgzdev/threat-detection-suite)

La correlación es una matriz TF-IDF reproducible. No depende de FAISS, de embeddings remotos ni de una API de inteligencia externa.

## Instalación

Requiere Python 3.11 o superior. Con `uv`:

```bash
uv sync
uv run nexus-intel example.com
```

Con pip:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
nexus-intel example.com
```

También puedes pasar objetivos desde un archivo y ajustar el número de workers:

```bash
nexus-intel --file targets.txt --concurrency 8
```

El modo bulk ejecuta los cinco módulos por objetivo, guarda cada hallazgo en SQLite y genera un informe por objetivo. La correlación con el histórico y con TDS se ejecuta en el flujo de objetivo único, no al terminar un archivo completo. Usa `nexus-intel --help` para ver las opciones disponibles.

## Datos y resultados

Los hallazgos se conservan en SQLite junto con sus datos JSON. Los informes Markdown se generan a partir de esos resultados y la auditoría de integridad comprueba que la matriz activa tenga el tamaño y la normalización esperados.

Las consultas de red dependen del objetivo, del DNS y de los servicios que estén disponibles en ese momento. Un timeout o un banner ausente es un resultado incompleto, no una prueba de que el activo sea seguro.

## Desarrollo

```bash
uv sync --extra dev
uv run pytest
```

La entrada de consola es `nexus-intel` y apunta a `nexus_intelligence.__main__:main`. El proyecto mantiene locks de dependencias para que las instalaciones y los tests sean repetibles.

El mapa de ejecución real está en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Uso responsable

Ejecuta Nexus solo sobre infraestructura propia o con permiso explícito. Respeta los límites de la red, evita cargas innecesarias y trata los informes como material sensible.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
