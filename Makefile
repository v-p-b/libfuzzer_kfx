FUZZER_NAME="fuzzer_libkfx_dummy"
PROJECT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
UNAME := $(shell uname)

all: afl fuzzer
	clang \
        $(PROJECT_DIR)/harness.c \
		-o $(FUZZER_NAME) \
		-lm -lz -g -O3 \
        -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1 \
        -lrt \
		-Wl,--whole-archive target/release/liblibfuzzer_libkfx_dummy.a \
		-Wl,-no-whole-archive -pthread -ldl afl.o

afl: 
	clang \
		$(PROJECT_DIR)/afl.c \
		-o afl.o \
		-c

fuzzer: 
	# Build the libpng libfuzzer library
	cargo build --release

	clang \
		$(PROJECT_DIR)/harness.c \
		-o $(FUZZER_NAME).o \
		-v -c 

clean:
	rm ./$(FUZZER_NAME)
	rm *.o
	rm -r target

