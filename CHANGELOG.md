# Changelog

All notable changes to RoyalBit Poster.

## [0.6.0] - 2026-01-01

### Added
- Image attachment support for LinkedIn and X posts
- `image` field in posts.yaml for specifying image paths
- LinkedIn Images API integration (initializeUpload + binary upload)
- X media upload API integration (base64 media_data)
- 10 new unit tests for media serialization

## [0.5.0] - 2026-01-01

### Changed
- `post-all` now skips already-posted entries by default
- Shows count of skipped items and exits early if nothing to post

### Added
- `is_posted()` and `filter_unposted()` helper functions
- 7 unit tests for skip-posted logic

## [0.4.1] - 2026-01-01

### Added
- Unit tests for JSON schema validation (9 tests)

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
