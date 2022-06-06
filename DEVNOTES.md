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

### Back to square1

The thing is, that the original way of using libafl as the main program module and link to our harness as a library won't  work that well when we have to convert a complex harness (kfx) to a library (esp. if you don't know toolchain...). So the other way is to keep libafl as God intended, remove the original entry point of the harness, create the LLVM API's and link against libafl. 

The trick is that Rust's `cc` crate does some magic in the background, that took a couple of days for me to figure out.

The libfuzzer target defines the entry point of the executable, that simply calls `libafl_main`, that is supposed to be implemented by the fuzzer (see `src/lib.rs` sources). Now if you build the fuzzer and try to link against it, you'll find, that teh body of `libafl_main()` is empty. Inspecting the code of the libfuzzer target, you'll also find, that it does indeed declare a version of `libafl_main()` with an empty body. I asked Dominik about this, and it turns out, that the definition in the libfuzzer target is marked as a _weak_ symbol, meaning that if a "strong" symbol with the same name is found, it will override it. 

Then why do we see the empty body in the compiled code? As it turns out [ld does not care about weak/strong symbols by default when linking static libraries](https://stackoverflow.com/a/37191811), so we have to use the `--whole-archive` option for proper linking. ( [Here is how to do that with autotools](https://stackoverflow.com/questions/22210903/autotools-and-wl-whole-archive) ) I stumbled upon this quirk before while inspecting the verbose command lines emitted by `cc`, but until this point I couldn't figure out the purpose of it. Now I understand. 

With `cc`, we also get a bunch of common libs (pthread, math, ...) linked - when using a different toolchain, we have to include these explicitly.

### Feedback

Feedack traits are used in two ways: 
- to mark _interesting inputs_
- to inform the fuzzer about reached _objectives_

The first function is covered by the HitcountsMapobserver that is capable of monitoring the shared memory region for changes. To test this with IPT I had to modify the testmodule, so that closing in on the desired buffer state would be apparent in the generated corpus, something like:

```
if (test1[0] == test2[0]){
  if (test1[1] == test2[1]){
    // etc... crash inside
  }
}
```

This proved that shmem based coverage works:

```
% for f in `ls -1t kfx/gencorp/*`; do hd $f;done # trigger pseudocode: memcmp(input+"beef", "nottbeef")
00000000  6e 6f 74 74 92 74 00 20  74 74 74 74 74 74 0e     |nott.t. tttttt.|
0000000f
00000000  6e 6f 74 0e                                       |not.|
00000004
00000000  6e 6f 0e                                          |no.|
00000003
00000000  6e 0a                                             |n.|
00000002
00000000  79 0a                                             |y.|
00000002
```

Unfortunately existing observers can't handle when LLVMTestOneInput just returns with a status code indicating a crash, so this will probably need a new Feedback class.

The question is how the (unsafe) function return value can be propagated back through `ExitKind` to the Feedback, so it can register it as a _solution_.



```
Executor.run_target() -> Result (Ok(return value))
StdFuzzer.execute_input() -> exit_kind


Feedback.is_interesting(state, manager, &input, observers, exit_kind)
ExitKind is just an enum! 
```
