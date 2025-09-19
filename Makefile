all: lint test test-cli

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test

test-cli:
	cargo build	
	mkdir -p tmp
	./target/debug/ark_cwc_setup example/multiply.r1cs tmp/pkey tmp/vk tmp/vk.json
	./target/debug/ark_cwc_prove example/multiply.input.json example/multiply.graph example/multiply.r1cs tmp/pkey tmp/proof.json tmp/proof.bin
	./target/debug/ark_cwc_verify tmp/proof.bin tmp/vk 110 11
	./target/debug/ark_cwc_verify tmp/proof.bin tmp/vk 10 110 || true # This will fail 
	./target/debug/ark_cwc_verify_json tmp/proof.json tmp/vk.json
