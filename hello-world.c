#include <signal.h>
#include <stdio.h>

int main() {
  for (int i = 0; i < 10; i++) {
    printf("Hello world!\n");

    if(i == 4) {
      raise(SIGSTOP);
    }
  }
}
