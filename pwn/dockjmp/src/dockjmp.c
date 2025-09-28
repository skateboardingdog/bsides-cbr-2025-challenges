#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <unistd.h>

#define dockjmp longjmp

void win() {
    system("/bin/sh");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    jmp_buf env;
    setjmp(env);

    printf("My jmp_buf: ");
    for (int i = 0; i < sizeof(jmp_buf); i++) {
        printf("%02x", ((unsigned char*)env)[i]);
    }
    printf("\n");

    puts("Now, give me your jmp_buf:");
    ssize_t n = read(0, env, sizeof(jmp_buf));

    dockjmp(env, 0);

    return 0;
}
