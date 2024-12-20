#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  int *ptr = malloc(20 * sizeof(int));
  for (int i = 0; i < 20; i++) {
    ptr[i] = i;
  }

  for (int i = 0; i < 20; ++i) {
    printf("%p: %d\n", &ptr[i], ptr[i]);
    sleep(1);
  }

  free(ptr);
}