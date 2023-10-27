#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main (void) {
    printf("Hello, world ! PID: %d\n", getpid());
    printf("Executing as %d\n", getuid());
    pid_t pid = fork();
    if(pid == 0) {
        printf("child");
        sleep(5);
    }

    return 0;
}