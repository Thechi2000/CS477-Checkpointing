#include <stdio.h>

int __attribute__ ((noinline)) time_2(int n) {
  asm ("");
  return 2 * n;
}

int main() {
  for (int i = 0; i < 10000000; i++) {
    int i_mult = time_2(i);
    printf("%d: Hello world!\n", i_mult);
  }
}
