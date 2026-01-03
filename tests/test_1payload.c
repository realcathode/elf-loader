// gcc -static test_1payload.c -o payload

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[], char *envp[]) {
    printf("[*] Hello payload!\n");
    printf("[*] Received %d arguments.\n", argc);

    for(int i = 0; i < argc; i++) {
        printf("    argv[%d]: %s\n", i, argv[i]);
    }

    if (envp[0]) {
        printf("[*] First environment variable: %s\n", envp[0]);
    }

    return 69;
}
