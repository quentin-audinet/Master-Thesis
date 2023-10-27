#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>

int main(int argc, char *argv[]) {
    DIR *dir;
    struct dirent *entry;
    
    dir = opendir("/tmp");

    if (dir == NULL) {
        perror("Error opening directory");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        
        for(int i=0; i < strlen(entry->d_name); i++) {
            if (entry->d_name[i] == '\n') {
                printf("%ld\n", entry->d_ino);
                char command[256];
                sprintf(command, "sudo find /tmp -inum %ld -exec rm -r {} \\;", entry->d_ino); 
                system(command);
                break;
            }
        }
    }

    closedir(dir);
    
    return 0;
}