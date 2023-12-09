#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

void main (int argc, char* argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        execl(argv[1], argv[1], NULL);
    }
}