# Nexus Intelligence architecture

Nexus no es una API remota: es un proceso CLI que ejecuta módulos de red, guarda observaciones locales y construye correlación TF-IDF en memoria.

## Cómo leerlo

La primera figura muestra los componentes conectados. Las dos secuencias separan objetivo único y archivo bulk porque terminan con análisis distintos. La sección final explica cómo interpretar un hallazgo.

## 1. Componentes reales

~~~mermaid
flowchart LR
    CMD[nexus-intel] --> ARG[argparse]
    ARG -->|target| ONE[execute_forensic_pipeline]
    ARG -->|file| Q[asyncio Queue]
    Q --> W[worker tasks]
    W --> BT[engine per dequeued target]
    ONE --> E[IntelligenceEngine]
    BT --> E
    E --> SAFE[SecurityValidator]
    E --> MOD[DNS / Web / SSL / Mail / Subdomains]
    MOD --> DB[(PersistenceManager SQLite intelligence)]
    MOD --> REP[ReportingEngine Markdown]
    DB --> V[VectorCorrelator scikit-learn TF-IDF]
    TDS[TDS_LOG_PATH JSONL optional] --> V
    V --> AUD[VectorIntegrityAuditor]
~~~

Configuración que existe pero no forma parte del camino actual: `redis_url`, `mongodb_url` y `milvus_url` se cargan como settings opcionales, pero ningún runtime module los usa. No son dependencias ocultas ni backends activos.

## 2. Objetivo único

~~~mermaid
sequenceDiagram
    participant CLI as entrypoint
    participant E as IntelligenceEngine target
    participant M as five modules
    participant DB as SQLite
    participant R as ReportingEngine
    participant V as TF-IDF correlator
    CLI->>E: create target + config
    E->>E: SecurityValidator.is_safe_target
    E->>M: asyncio.gather(wait_for timeout)
    M-->>E: results or module_fault
    loop each module result
      CLI->>DB: save_finding target module data
    end
    CLI->>R: generate_markdown target results
    CLI->>V: ingest optional TDS JSONL
    CLI->>DB: get_all_findings
    CLI->>V: ingest Nexus rows
    V->>V: cosine similarity for target
    V->>V: integrity audit
~~~

## 3. Archivo bulk

~~~mermaid
sequenceDiagram
    participant CLI as --file
    participant Q as asyncio Queue
    participant W as worker
    participant E as IntelligenceEngine target
    participant DB as SQLite
    participant R as report file
    CLI->>Q: enqueue non-empty lines
    par worker 1..N
      W->>Q: dequeue target
      W->>E: construct with dequeued target
      E->>E: run same five modules
      E-->>W: module results
      W->>DB: save every module result
      W->>R: report for that target
    end
    CLI-->>CLI: finish after queue.join
~~~

El bulk ejecuta y persiste cada objetivo, pero no ejecuta la correlación histórica/TDS al finalizar todo el archivo. `--concurrency` se limita a `NEXUS_MAX_CONCURRENT`; los fallos de un módulo quedan como `module_fault` y no cancelan los otros módulos.

## 4. Datos y evidencia

- SQLite almacena `target`, `module`, JSON serializado y timestamp mediante queries parametrizadas.
- Los reportes escapan el target en el encabezado, pero los bloques JSON representan observaciones del scan y deben tratarse como material sensible.
- DNS, TLS, HTTP, SMTP y subdominios dependen de respuestas de red en ese momento. Una ausencia o timeout es una observación incompleta, no una conclusión de seguridad.
- `tests/test_runtime.py` cubre mail SPF/DMARC, wildcard, persistencia, correlación, JSONL malformado, integridad TF-IDF y el target correcto en bulk.
