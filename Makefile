.PHONY: all test build install clean check

PREFIX ?= $(HOME)/bin
BINARY = daneel-poster

all: check test build

check:
	cargo fmt --check
	cargo clippy -- -D warnings

test:
	cargo test

build:
	cargo build --release

install: build
	@mkdir -p $(PREFIX)
	cp target/release/$(BINARY) $(PREFIX)/
	@echo "Installed $(BINARY) to $(PREFIX)"

clean:
	cargo clean

# Development helpers
dev:
	cargo build

watch:
	cargo watch -x test

coverage:
	cargo tarpaulin --out Stdout --skip-clean
