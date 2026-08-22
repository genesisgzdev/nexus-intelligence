# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- Valida cada salto de redirect HTTP(S) y limita la cadena a cinco destinos.
- Usa SQLite WAL, timeout de espera y una única cola de escritura por proceso.
- Escapa observaciones en los informes y restringe sus archivos a permisos `0600`.
- Retira settings de Redis, MongoDB y Milvus que no pertenecían al runtime.

## [3.3.1] - 2026-08-20

### Changed

- Rewrote the public README around the current DNS, TLS, web, mail and local TF-IDF pipeline.
- Added the repository MIT license and removed stale claims about external services and vector backends.
- Aligned the package version with the release tag.
