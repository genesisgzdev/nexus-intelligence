# Nexus Intelligence architecture

~~~mermaid
flowchart LR
    CLI[console script nexus-intel] -->|single target| Single[IntelligenceEngine target]
    CLI -->|file mode| Queue[asyncio Queue]
    Queue --> Workers[bounded worker tasks]
    Workers --> PerTarget[IntelligenceEngine queued target]
    Single --> Mods[DNS web TLS mail subdomains]
    PerTarget --> Mods
    Mods --> SQLite[(SQLite intelligence table)]
    Mods --> MD[Markdown report]
    SQLite --> Corr[local TF-IDF correlator]
    EDR[optional TDS JSONL] --> Corr
    Corr --> Audit[vector integrity audit]
~~~

## Runtime facts

- A single-target run executes five modules concurrently with NEXUS_TIMEOUT per module, persists every result, generates a report and then runs local correlation.
- A bulk run uses an asyncio Queue. Each worker constructs an engine with the target it dequeued, executes the same five modules, persists each module result and writes that target's report. Bulk mode does not yet run the cross-project correlation stage after the batch.
- PersistenceManager writes parameterized rows to nexus_forensics.db. Reports go to the default reports directory in the current CLI.
- The correlator uses scikit-learn TF-IDF and cosine similarity. It does not use FAISS, a remote embedding service, Redis, MongoDB or Milvus; those settings are currently configuration placeholders and are not runtime dependencies.

## Validation boundary

Network answers, TLS handshakes, SMTP banners and HTTP responses are observations from the target at scan time. They are not proof of ownership, safety or absence of compromise. Unit tests mock network resolvers and cover persistence, mail policy separation, wildcard probing, malformed JSONL handling and TF-IDF integrity.
