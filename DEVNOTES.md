KF/x integration notes
======================

Repo Status
-----------

This branch currently implements a minimal, dummy implementation (based on LibAFL's libpng fuzzers) to try out things before bringing in KF/x code.

Roadmap for the dummy stage:

- [x] Replace libpng harness with dummy
- [x] Remove LibFuzzer instrumentation, while maintaining functional fuzzing entry point 
- [ ] Implement coverage reporting
- [ ] Support standalone harness? (something is fucky with libfuzzer: https://groups.google.com/g/libfuzzer/c/oV3Hp4IGx7Y )

Research notes
--------------

The goal is to make the C implementation of KF/x to run under LibAFL.

Based on the [RC3 talk](https://media.ccc.de/v/rc3-channels-2020-87-fuzzers-like-lego) a similar implementation is available for libpng under `fuzzers/` in LibAFL. These implementations use LLVM's LibFuzzer to instrument the target. For our immediate purpose LibFuzzer does two important things:

- Defines an API/entry point for a single fuzzing iteration that LibAFL can loop via its [LibFuzzer target](https://github.com/AFLplusplus/LibAFL/blob/main/libafl_targets/src/libfuzzer.rs)
- Performs compile-time edge instrumentation on the target, and implements an AFL compatible interface to report back results

The whole thing is glued together by exposing the TestOne entry point of the C implementation to LibAFL's Rust implementation (see [A little C with your Rust](https://docs.rust-embedded.org/book/interoperability/c-with-rust.html)).

Creating a LibFuzzer compatible harness is easy, as we only need to:
- implement the appropriate interface 
- use Clang with the `fuzzer` sanitizer (TODO does KF/x have issues with Clang?)
- link everything together with the LibAFL based fuzzer implementation (see the Makefile)

By removing other santizers, we can get rid of LLVM's instrumentation, that will be useless with KF/x. The next task is to create a replacement for coverage tracking - this will hopefully be achievable by using the existing code from KF/x. 

To be continued...
