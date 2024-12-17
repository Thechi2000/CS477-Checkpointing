#include <stdio.h>

int main() {
  for (int i = 0; i < 10000000; i++) {
    unsigned long rsp_value;

    // Inline assembly to read the value of rsp
    __asm__ __volatile__(
        "mov %%rsp, %0"   // Move the value of rsp into the output variable
        : "=r"(rsp_value) // Output operand: store the value in rsp_value
    );
    printf("0x%lx: Hello world!\n", i);
  }
}
