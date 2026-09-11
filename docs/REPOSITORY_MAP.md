# Mapa del repositorio

Revisión de estructura y flujos: 2026-09-11. Este inventario cubre los archivos versionados y las incorporaciones de esta revisión; excluye dependencias instaladas y artefactos de build. Los límites de validación aparecen por área.

## Flujos y fronteras

| Área | Recorrido real | Verificación / límite |
| --- | --- | --- |
| Entrada | CLI simple/bulk → engine/orchestrator → módulos | Devuelve error por módulos u objetivos fallidos |
| Red | security.py valida DNS público → HTTP fija IP conservando SNI, SMTP/TLS usan timeout | Revalidación de redirects; sin barrido externo durante las pruebas |
| Análisis | DNS, correo, certificado, subdominios, web → diccionarios de hallazgos | Un certificado recolectado sin autenticación se etiqueta como tal |
| Persistencia | persistence.py → SQLite WAL → correlación TF-IDF | DB configurable; integridad del índice y corpus vacío cubiertos |
| Correlación | Nexus/JSONL TDS → vectores → top-k acotado | Comparaciones limitadas; resultado puede declarar truncamiento; no prueba causalidad |
| Informes | Markdown saneado → archivo único privado | No sobrescribe dos informes generados en el mismo segundo |

## Inventario de archivos

| Archivo | Responsabilidad |
| --- | --- |
| [.dockerignore](../.dockerignore) | Configuración/metadata: .dockerignore |
| [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Automatización de ci |
| [.github/workflows/release.yml](../.github/workflows/release.yml) | Automatización de release |
| [.gitignore](../.gitignore) | Configuración/metadata: .gitignore |
| [CHANGELOG.md](../CHANGELOG.md) | Documentación: CHANGELOG |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Documentación: CONTRIBUTING |
| [Dockerfile](../Dockerfile) | Build y ejecución en contenedores |
| [LICENSE](../LICENSE) | Licencia del proyecto |
| [README.md](../README.md) | Documentación: README |
| [SECURITY.md](../SECURITY.md) | Documentación: SECURITY |
| [docker-compose.yml](../docker-compose.yml) | Build y ejecución en contenedores |
| [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Documentación: ARCHITECTURE |
| [docs/REPOSITORY_MAP.md](../docs/REPOSITORY_MAP.md) | Documentación: REPOSITORY_MAP |
| [nexus_intelligence/__main__.py](../nexus_intelligence/__main__.py) | Módulo: __main__ |
| [nexus_intelligence/analysis/base.py](../nexus_intelligence/analysis/base.py) | Módulo: base |
| [nexus_intelligence/analysis/dns.py](../nexus_intelligence/analysis/dns.py) | Módulo: dns |
| [nexus_intelligence/analysis/intelligence/correlation.py](../nexus_intelligence/analysis/intelligence/correlation.py) | Módulo: correlation |
| [nexus_intelligence/analysis/intelligence/entropy.py](../nexus_intelligence/analysis/intelligence/entropy.py) | Módulo: entropy |
| [nexus_intelligence/analysis/intelligence/integrity.py](../nexus_intelligence/analysis/intelligence/integrity.py) | Módulo: integrity |
| [nexus_intelligence/analysis/intelligence/math_forensics.py](../nexus_intelligence/analysis/intelligence/math_forensics.py) | Módulo: math_forensics |
| [nexus_intelligence/analysis/mail.py](../nexus_intelligence/analysis/mail.py) | Módulo: mail |
| [nexus_intelligence/analysis/ssl.py](../nexus_intelligence/analysis/ssl.py) | Módulo: ssl |
| [nexus_intelligence/analysis/subdomains.py](../nexus_intelligence/analysis/subdomains.py) | Módulo: subdomains |
| [nexus_intelligence/analysis/web.py](../nexus_intelligence/analysis/web.py) | Módulo: web |
| [nexus_intelligence/core/config.py](../nexus_intelligence/core/config.py) | Módulo: config |
| [nexus_intelligence/core/engine.py](../nexus_intelligence/core/engine.py) | Módulo: engine |
| [nexus_intelligence/core/logger.py](../nexus_intelligence/core/logger.py) | Módulo: logger |
| [nexus_intelligence/core/orchestrator.py](../nexus_intelligence/core/orchestrator.py) | Módulo: orchestrator |
| [nexus_intelligence/core/persistence.py](../nexus_intelligence/core/persistence.py) | Módulo: persistence |
| [nexus_intelligence/core/reporting.py](../nexus_intelligence/core/reporting.py) | Módulo: reporting |
| [nexus_intelligence/core/security.py](../nexus_intelligence/core/security.py) | Módulo: security |
| [nexus_intelligence/nexus_correlator.py](../nexus_intelligence/nexus_correlator.py) | Módulo: nexus_correlator |
| [pyproject.toml](../pyproject.toml) | Dependencias y comandos del componente |
| [requirements.lock](../requirements.lock) | Dependencias y comandos del componente |
| [requirements.txt](../requirements.txt) | Dependencias y comandos del componente |
| [tests/test_cli_contract.py](../tests/test_cli_contract.py) | Validación: test_cli_contract |
| [tests/test_regressions.py](../tests/test_regressions.py) | Validación: test_regressions |
| [tests/test_runtime.py](../tests/test_runtime.py) | Validación: test_runtime |
| [uv.lock](../uv.lock) | Resolución exacta del entorno uv |
