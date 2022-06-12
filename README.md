libfuzzer\_kfx
==============

[LibAFL](https://github.com/AFLplusplus/LibAFL) wrapper for [KF/x](https://github.com/intel/kernel-fuzzer-for-xen-project) based on the libfuzzer target.

Building and Usage
------------------

Clone this to the `fuzzers` directory of LibAFL!

Download the appropriate KF/x branch as submodule:

```
git submodule init
git submodule update
```

Build the wrapper with Cargo: 

```
cd libfuzzer_kfx/
cargo build --release
```

Build kfx, linking it to the wrapper: 

```
cd kfx/
autoreconf -vif
./configure
make -j4
```

`./kfx -h` and the [KF/x](https://github.com/intel/kernel-fuzzer-for-xen-project) repo provides further information about running.

