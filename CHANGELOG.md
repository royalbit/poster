# Changelog

All notable changes to RoyalBit Poster.

## [0.4.0] - 2026-01-01

### Added
- JSON schema for posts.yaml (`posts.schema.json`)
- IDE validation and autocomplete support via yaml-language-server directive

## [0.3.0] - 2026-01-01

### Changed
- Rebranded from "daneel-poster" to "RoyalBit Poster"
- CLI command changed from `daneel-poster` to `poster`
- Config directory changed from `~/.config/daneel-poster/` to `~/.config/poster/`

### Migration
- Users with existing tokens need to move `~/.config/daneel-poster/` to `~/.config/poster/` or re-authenticate

## [0.2.0] - 2025-12-19

### Added
- `posted` field tracking in posts.yaml (timestamps for x/linkedin)
- `--posts-path` CLI argument and `DANEEL_POSTS_PATH` env var
- YAML validation on load (X posts ≤280 chars, URL format, required fields)
- Automatic timestamp update after successful posting
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
