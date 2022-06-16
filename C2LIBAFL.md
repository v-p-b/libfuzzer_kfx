C Harness to LibAFL
===================

This project was a good exercise in integrating existing C code with LibAFL.

Here's the base setting:
* KF/x is a relatively complex C project with its own build toolchain. We don't want to rewrite either the existing code or the toolchain.
* KF/x is capable of executing fuzz iterations, measure code coverage and detect objectives (crashes). We want to make these capabilities available for LibAFL.
* We want to use the modular input generation (and potentially other) features of LibAFL.

Integration Using the LibFuzzer Target
--------------------------------------

LibAFL comes with a _target_ for [LibFuzzer](https://llvm.org/docs/LibFuzzer.html). According to its documentation:

> [The LibFuzzer target] makes LibAFL interoperable with harnesses written for other fuzzers like Libfuzzer and AFLplusplus

This seems ideal for our goal. As we will see, we could easily reimplement a similar API independently from the libfuzzer target, but I saw no point in that. For our immediate purpose LibFuzzer does two important things:

- Defines an API for a fuzzer initialization and executing a single fuzzing iteration. The API is exposed to LibAFL with a simple Rust wrapper (see [A little C with your Rust](https://docs.rust-embedded.org/book/interoperability/c-with-rust.html)).
- Performs compile-time edge instrumentation on the target. LibAFL has a clang wrapper that [is used to compile](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/libfuzzer_libpng_accounting/src/bin/libafl_cc.rs) LibFuzzer compatible C/C++ harnesses. 

### Exposing a LibFuzzer compatible API

On the C side, we can easily conform the LibFuzzer target, exposing the `LLVMFuzzerTestOneInput` and `LLVMFuzzerInitialize` function symbols from our C/C++ code. The executable entry point is implemented by the LibFuzzer target of LibAFL, so the original entry point in the C harness needs to be removed (or renamed, to be called from Rust). The Rust entry point simply calls the `libafl_main` function, that is supposed to be implemented by the fuzzer (see `src/lib.rs` sources in LibAFL). The command line arguments can be passed from `libafl_main` to the exposed `LLVMFuzzerInitialize` of the C harness. `LLVMFuzzerTestOneInput` accepts the test input as usual. 

At LibAFL, we have to create a Rust library, that implements `libafl_main`, and uses `libfuzzer_initialize` and `libfuzzer_test_one_input` wrappers of the `libfuzzer_target` crate for fuzzing. This library will connect together the "LEGO bricks" provided by LibAFL to create something useful.  

### Replacing the Build Toolchain

The LibAFL-based Rust library is compiled into a library archive (.a file) with Cargo. We can modify the build configuration of the C harness to link against this library.

At this point an important problem arises: if you link against the Rust library with your usual configuration, you'll find, that the body of `libafl_main()` is empty in the resulting executable. Inspecting the code of the LibFuzzer target, you'll also find, that it does indeed declare a version of `libafl_main()` with an empty body. I asked [Dominik](https://twitter.com/domenuk) about this, and it turns out, that the definition in the LibFuzzer target is marked as a [weak symbol](https://witekio.com/blog/gcc-weak-symbols/), meaning that if a "strong" symbol with the same name is found, it will override it. 

But `libafl_main()` __is__ declared by the fuzzer, why do we see the empty body in the compiled code, when using our original toolchain? As it turns out [ld does not care about weak/strong symbols by default when linking static libraries](https://stackoverflow.com/a/37191811), so we have to use the `--whole-archive` option for proper linking ([here is how to do that with autotools](https://stackoverflow.com/questions/22210903/autotools-and-wl-whole-archive)). You can see this option emitted by `libafl_cc` when you disable [silence](https://docs.rs/libafl_cc/0.4.0/libafl_cc/trait.CompilerWrapper.html#tymethod.silence).

With `libafl_cc`, we also get a bunch of common libs (pthread, math, ...) linked - when using a different toolchain, we have to include these explicitly.

Feedback
--------

LibAFL supports communication with the target using shared memory via the `StdShMemProvider` type. This can be used to implement an AFL-compatible interface, so coverage data from our harness can be communicated back from C code to LibAFL, where it can be tracked with `HitcountsMapObserver` for example. 

For coverage tracking, no modification was needed in the C code, but in AFL world signals about reaching a "solution" are not communicated via shared memory but with pipes. Fortunately in case of LibAFL the solution is even simpler: the _InProcessExecutor_ uses a [closure](https://doc.rust-lang.org/book/ch13-01-closures.html) to call our wrapped `LLVMFuzzerTestOneInput` function. We can simply check the return value of `LLVMFuzzerTestOneInput` inside the closure, and return `ErrorKind:Crash` in case of a solution, that can be detected by `CrashFeedback`.

Cleanup
-------

LibFuzzer doesn't define an API for cleaning up, but we can just declare an `extern "C"` symbol in our Rust library, and implement it in C to perform any teardown actions - in our case removing Xen domains. 

TODO
----

- Ctrl+C handling
- Parallelization

