# Changelog

All notable changes to RoyalBit Poster.

## [0.3.0] - 2026-01-01

### Changed
- Rebranded from "daneel-poster" to "RoyalBit Poster"
- CLI command changed from `daneel-poster` to `poster`
- Config directory changed from `~/.config/daneel-poster/` to `~/.config/poster/`

### Migration
- Users with existing tokens need to move `~/.config/daneel-poster/` to `~/.config/poster/` or re-authenticate

## [0.2.0] - 2025-12-19

### Added
- Comprehensive unit tests (55 tests)
- Test coverage for config, posts, linkedin, x modules
- Testable pure functions extracted from side-effectful code
- Makefile with test, build, install targets

## [0.1.0] - 2025-12-19

### Added
- LinkedIn OAuth 2.0 authentication
- LinkedIn posting via Marketing API
- X/Twitter OAuth 1.0a posting
- YAML-based post definitions
- Dry-run mode for preview
- Pedantic clippy lints, zero warnings
