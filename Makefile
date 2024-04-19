.PHONY: bench build lint test

bench:
	cargo bench

build:
	cargo build

clean:
	cargo clean

fmt:
	cargo fmt

lint:
	cargo fmt --all -- --check
	cargo check --all-features
	cargo clippy --release -- -D warnings

test:
	cargo test --release --all
