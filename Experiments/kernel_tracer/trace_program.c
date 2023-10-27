#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#define tracing "/sys/kernel/tracing/"

uid_t euid, ruid, suid;

// Write value at file located at path
int set_tracing(char *path, char *value) {
    setreuid(geteuid(), getuid());
    // printf("1 - ruid: %d\teuid: %d\n", getuid(), geteuid());
    
    FILE *fd = fopen(path, "w+");

    if (fd == NULL) {
        printf("ERROR: Unable to open %s\n", path);
        return -1;
    }

    if (fwrite(value, strlen(value), 1, fd) == -1) {
        printf("ERROR: Unable to write %s in %s\n", value, path);
        return -1;
    }

    if (fclose(fd) == -1) {
        printf("ERROR: Unable to close %s\n", path);
        return -1;
    }
    setreuid(geteuid(), getuid());
    // printf("2 - ruid: %d\teuid: %d\n", getuid(), geteuid());
    
    return 0;
}

// Set tracing on (1) or off (0)
int set_tracing_status(int status) {

    if (status >> 1 != 0) {
        printf("[*] tracing_on value must be 0 or 1\n");
        return -1;
    }

    char status_buffer[4];
    sprintf(status_buffer, "%d", status);

    if (set_tracing(tracing "tracing_on", status_buffer) == -1) {
        return -1;
    }
    return 0;
}

// Set the tracer to follow the program with PID pid
int set_tracing_pid(pid_t pid) {

    char pid_buffer[8];
    sprintf(pid_buffer, "%d", pid);

    if (set_tracing(tracing "set_ftrace_pid", pid_buffer) == -1) {
        return -1;
    }
    return 0;
}

// Set the current tracer
int set_current_tracer(char* tracer) {
    if (set_tracing(tracing "current_tracer", tracer) == -1) {
        return -1;
    }
    return 0;
}

// Run the traced program
int run_traced_program(char* path) {
    pid_t child_pid = fork();

    if (child_pid == -1) {
        perror("Fork failed");
        return -1;
    }
    // Child process
    else if (child_pid == 0) {
        // Pause to get the PID and set the ftrace parameters
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        setreuid(ruid, ruid);
        // Execute the program
        execl(path, path, NULL);
        perror("exec");
        exit(EXIT_FAILURE);
    }
    // Parent process
    else {

        printf("child pid is %d\n", child_pid);
        
        waitpid(child_pid, NULL, 0);
        
        //if (set_tracing_pid(child_pid) == -1) return -1;
        //if (set_tracing_status(1) == -1) return -1;

        // Resume child process
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        int status;
        waitpid(child_pid, &status, 0);
        printf("Finish %d\n", status);

        //if (set_tracing_status(0) == -1) return -1;
    }

    return 0;
}

int save_trace(char * dest) {
    
    setreuid(geteuid(), getuid());
    FILE * trace_fd = fopen(tracing "trace", "r");
    if (trace_fd == NULL) {
        printf("Error opening %s\n", tracing "trace");
        return -1;
    }
    setreuid(geteuid(), getuid());

    FILE * output_fd = fopen(dest, "w");
    if (output_fd == NULL) {
        printf("Error opening %s\n", dest);
        return -1;
    }
    
    size_t buffer_size = 1024, char_read;
    char buffer[buffer_size];
    while ((char_read = fread(buffer, 1, buffer_size, trace_fd)) > 0) {
        fwrite(buffer, 1, char_read, output_fd);
    }
    
    fclose(trace_fd);
    fclose(output_fd);
    printf("Trace saved in %s\n", dest);
}

int main(int argc, char* argv[]) {
    
    if (argc != 2) {
        printf("Usage: %s <program to execute> [output]\n", argv[0]);
    }

    char *output;
    if (argc == 3) {
        output = argv[2];
    } else {
        output = "output";
    }

    getresuid(&ruid, &euid, &suid);
    setreuid(geteuid(), getuid());
    
    //if (set_tracing_status(0) == -1) return -1;

    // Reset log
    //if (set_current_tracer("nop") == -1) return -1;
    //if (set_current_tracer("function") == -1) return -1;
    
    if (run_traced_program(argv[1]) == -1) return -1;

    // save_trace(output);


    
    return 0;
}