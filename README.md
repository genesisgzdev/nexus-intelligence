# Nexus Intelligence

Nexus reúne señales observables de DNS, TLS, HTTP, correo y subdominios en informes locales revisables. No convierte una señal aislada en una sentencia de reputación.

En 30 segundos: entrega un dominio o un archivo de objetivos, los módulos consultan la red con límites propios, SQLite conserva los hallazgos y el informe Markdown explica lo observado. El flujo de objetivo único puede añadir correlación TF-IDF local y eventos JSONL de TDS. No depende de una API de reputación ni de un índice vectorial remoto.

Está pensada para investigar dominios y activos propios o aquellos para los que tengas autorización. No es un servicio de reputación externo ni pretende convertir una señal aislada en una conclusión definitiva.

## Flujo que explica el producto

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

La vista corta separa observación, persistencia y análisis. El diagrama completo de workers, timeouts, errores, bulk y auditoría está en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Los módulos actuales cubren:

- registros DNS como A, AAAA, MX, TXT, SOA y CAA
- certificado X.509, fechas, emisor, SAN y huella SHA-256
- cabeceras de seguridad HTTP y metadatos de la respuesta
- banners SMTP cuando el servicio responde
- correlación local con TF-IDF y `scikit-learn`
- ingesta opcional de eventos JSONL de [Threat Detection Suite](https://github.com/genesisgzdev/threat-detection-suite)

La validación de objetivos y de los subdominios descubiertos comprueba todas las respuestas DNS y bloquea rangos privados, loopback, link-local, multicast, reservados y no especificados. El módulo web no sigue redirects a ciegas: cada salto HTTP(S) vuelve a validarse y hay un máximo de cinco.

La conexión TLS vuelve a resolver el host y abre el socket contra la IP pública validada, manteniendo el hostname como SNI. Los banners SMTP aplican la misma validación a cada servidor MX. HTTP también fija cada solicitud a una IP validada y conserva el `Host` original para el virtual host; cada redirect vuelve a pasar por la misma frontera.

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
nexus-intel --file targets.txt --concurrency 8 --correlate
```

El modo bulk ejecuta los cinco módulos por objetivo, guarda cada hallazgo en SQLite y genera un informe por objetivo. `--correlate` añade un resumen global con similitudes TF-IDF entre objetivos distintos; no convierte esas similitudes en una reputación ni en una clasificación automática. SQLite usa WAL y una cola de escritura por proceso para evitar que los workers compitan por el mismo commit. Usa `nexus-intel --help` para ver las opciones disponibles.

## Datos y resultados

Los hallazgos se conservan en SQLite junto con sus datos JSON. Los informes Markdown se generan a partir de esos resultados, escapan los datos observados y se guardan con nombre seguro y permisos `0600`. La auditoría de integridad comprueba que la matriz activa tenga el tamaño y la normalización esperados. Eso respalda una observación reproducible del momento, no una garantía sobre el activo.

Las consultas de red dependen del objetivo, del DNS y de los servicios que estén disponibles en ese momento. Un timeout o un banner ausente es un resultado incompleto, no una prueba de que el activo sea seguro. Las consultas salen hacia el objetivo autorizado: “local-first” no significa “sin tráfico de red”.

## Desarrollo

```bash
uv sync --extra dev
uv run pytest
```

La entrada de consola es `nexus-intel` y apunta a `nexus_intelligence.__main__:main`. El proyecto mantiene locks de dependencias para que las instalaciones y los tests sean repetibles.

El mapa de ejecución real, la diferencia entre objetivo único y bulk y la forma de interpretar los resultados están en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Para cambios de comportamiento, revisa primero [`tests/test_runtime.py`](tests/test_runtime.py).

## Uso responsable

Ejecuta Nexus solo sobre infraestructura propia o con permiso explícito. Respeta los límites de la red, evita cargas innecesarias y trata los informes como material sensible.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
