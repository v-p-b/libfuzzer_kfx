FUZZER_NAME="fuzzer_libkfx_dummy"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

all: fuzzer

fuzzer: 
	# Build the libpng libfuzzer library
	cargo build --release

	clang \
		$(PROJECT_DIR)/harness.cc \
		-L target/release -llibfuzzer_libkfx_dummy \
		-fsanitize=fuzzer \
		-o $(FUZZER_NAME) \
		-v -lm -lz

clean:
	rm ./$(FUZZER_NAME)

