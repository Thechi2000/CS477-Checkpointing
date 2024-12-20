all: target/debug/app

.PHONY: clean

target/debug/app: $(wildcard **/*.rs) Cargo.lock Cargo.toml
	@cargo build

clean:
	@cargo clean
