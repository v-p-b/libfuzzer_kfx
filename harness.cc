#include <stdint.h>
#include <cstdio>


static int LLVMTestOneInput(const uint8_t* data, size_t size) {
  if (size < 4) {
    return 0;
  }

  if (data[0] == 'l'){
    if (data[1] == 'K'){
      if (data[2] == 'F'){
        if (data[3] == 'x'){
            asm("ud2");
        }
      }
    }
  }

  return 0;
}

