#include <stdint.h>
#include <cstdio>
#include <stdbool.h>

#include "afl.h"

bool afl;


static int LLVMTestOneInput(const uint8_t* data, size_t size) {
  //afl_rewind();
  //afl_wait();
  if (size < 4) {
    afl_report(false);
    return 0;
  }

  if (data[0] == 'l'){
    afl_instrument_location(0x11223344);
    if (data[1] == 'K'){
      afl_instrument_location(0x22334455);
      if (data[2] == 'F'){
        afl_instrument_location(0x33445566);
        if (data[3] == 'x'){
            afl_instrument_location(0x44556677);
            afl_report(true);
        }
      }
    }
  }

  afl_report(false);
  return 0;
}

static void LLVMFuzzerInitialize(){
    afl_setup();
}
