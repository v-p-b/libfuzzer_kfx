FUZZER_NAME="fuzzer_libkfx_dummy"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

all: afl fuzzer
	clang \
		-o $(FUZZER_NAME) \
		-fsanitize=fuzzer \
		-lm -lz \
		-L target/release -llibfuzzer_libkfx_dummy \
		$(FUZZER_NAME).o afl.o

afl: 
	clang \
		$(PROJECT_DIR)/afl.c \
		-o afl.o \
		-c

fuzzer: 
	# Build the libpng libfuzzer library
	cargo build --release

	clang \
		$(PROJECT_DIR)/harness.cc \
		-fsanitize=fuzzer \
		-o $(FUZZER_NAME).o \
		-v  -c

clean:
	rm ./$(FUZZER_NAME)
	rm *.o

