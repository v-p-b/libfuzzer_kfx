libfuzzer\_kfx
==============

[LibAFL](https://github.com/AFLplusplus/LibAFL) wrapper for [KF/x](https://github.com/intel/kernel-fuzzer-for-xen-project) based on the libfuzzer target.

Code in this repo is in large part based on LibAFL's [libfuzzer_libpng](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/libfuzzer_libpng) fuzzer.

Building and Usage
------------------

Clone this to the `fuzzers` directory of LibAFL!

Download the appropriate KF/x branch as submodule:

```
cd libfuzzer_kfx/

git submodule init
git submodule update
```

Build the wrapper with Cargo: 

```
cargo build --release
```

Build kfx, linking it to the wrapper: 

```
cd kfx/
autoreconf -vif
./configure
make -j4
```

Execute:

`./kfx --domain debian --json /path/to/debian.json --address 0xffffffffdeadbeef --input-limit 9 -A -t`

`./kfx -h` and the [KF/x](https://github.com/intel/kernel-fuzzer-for-xen-project) repo provides further information about running.

