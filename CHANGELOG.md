# Changelog

All notable changes to this project will be documented in this file.

## [3.3.2] - 2026-08-22

### Fixed

- Valida cada salto de redirect HTTP(S) y limita la cadena a cinco destinos.
- Fija las conexiones TLS y SMTP a una IP pública validada antes de abrir el socket y limita la concurrencia de subdominios a `NEXUS_MAX_CONCURRENT`.
- Usa SQLite WAL, timeout de espera y una única cola de escritura por proceso.
- Escapa observaciones en los informes y restringe sus archivos a permisos `0600`.
- Retira settings de Redis, MongoDB y Milvus que no pertenecían al runtime.
- Añade `--correlate` para resumir similitudes TF-IDF entre objetivos distintos después de un bulk.
- Conserva una ingesta sin vocabulario útil como resultado incompleto en vez de abortar el escaneo.
- Rechaza rangos no globales como CGNAT antes de abrir conexiones de red.

### Riesgo y actualización

- No cambia la configuración ni el esquema de SQLite.
- Los objetivos que resuelvan a direcciones no globales dejan de ser aceptados.

## [Unreleased]

## [3.3.1] - 2026-08-20

### Changed

- Rewrote the public README around the current DNS, TLS, web, mail and local TF-IDF pipeline.
- Added the repository MIT license and removed stale claims about external services and vector backends.
- Aligned the package version with the release tag.
