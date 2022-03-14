KF/x integration notes
======================

Repo Status
-----------

This branch currently implements a minimal, dummy implementation (based on LibAFL's libpng fuzzers) to try out things before bringing in KF/x code.

Roadmap for the dummy stage:

- [x] Replace libpng harness with dummy
- [x] Remove LibFuzzer instrumentation, while maintaining functional fuzzing entry point 
- [ ] Implement coverage reporting
- [x] Support standalone harness? (something is fucky with libfuzzer: https://groups.google.com/g/libfuzzer/c/oV3Hp4IGx7Y )

Usage
-----

Clone this to the `fuzzers` directory of LibAFL!

Research notes
--------------

The goal is to make the C implementation of KF/x to run under LibAFL.

Based on the [RC3 talk](https://media.ccc.de/v/rc3-channels-2020-87-fuzzers-like-lego) a similar implementation is available for libpng under `fuzzers/` in LibAFL. These implementations use LLVM's LibFuzzer to instrument the target. For our immediate purpose LibFuzzer does two important things:

- Defines an API/entry point for a single fuzzing iteration that LibAFL can loop via its [LibFuzzer target](https://github.com/AFLplusplus/LibAFL/blob/main/libafl_targets/src/libfuzzer.rs)
- Performs compile-time edge instrumentation on the target, and implements an AFL compatible interface to report back results

The whole thing is glued together by exposing the TestOne entry point of the C implementation to LibAFL's Rust implementation (see [A little C with your Rust](https://docs.rust-embedded.org/book/interoperability/c-with-rust.html)).

The `forkserver_simple` example [shows](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/forkserver_simple/src/main.rs#L83) how to initialize a shared memory region, notify the harness about it, and use it with an Observer.

The current version uses LibAFL's `libfuzzer_target` for compatibility reasons, otherwise LLVM instrumentation is not in use. The executable entry point is defined by LibAFL's `libfuzzer_target` instead of the one provided by the LLVM fuzzer sanitizer - this needed some serious hacking with the Makefile - we'll probably want something more robust for building. 

The original libpng fuzzer code is slowly going away:
* There is code for am `ShMem` based `HitcountsMapObserver`, and the AFL area seems to set up correctly, but reporting on objectives is buggy.
* We are using a SimpleEventManager instead of the `setup restarting_mgr_std()` helper.

To be continued...
 
