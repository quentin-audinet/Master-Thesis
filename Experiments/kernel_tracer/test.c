#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main (void) {
    printf("Hello, world ! PID: %d\n", getpid());
    printf("Executing as %d\n", getuid());
    return 0;
}