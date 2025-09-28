// xcrun -sdk iphoneos -r clang target_practice.c -o target_practice

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define MIN_ADDR 0x280000000
#define MAX_ADDR 0x300000000
#define COOKIE_OFFSET 0x7010


extern uint64_t *malloc_zones;

char secret[50] = {0};


void setup(void) {
    for (int i = 0; i < sizeof(secret); i++) {
        secret[i] = 0x41 + (arc4random() % 26);
    }

    srand(arc4random());

    void *pointers[50] = {0};

    for (int size = 8; size < 256; size += 16) {
        for (int i = 0; i < 50; i++) {
            pointers[i] = malloc(size);
        }

        for (int i = 0; i < 5; i++) {
            int idx = rand() % 50;
            if (pointers[idx] != NULL) {
                free(pointers[idx]);
                pointers[idx] = NULL;
            }
        }
    }

}

uintptr_t read_pointer(void) {
    uintptr_t ptr = 0;
    char buf[32] = {0};
    fgets(buf, 32, stdin);
    sscanf(buf, "%lx", &ptr);
    return ptr;
}

void run(void) {
    uint64_t zone = *malloc_zones;

    // libmalloc/src/nanov2_zone.h
    uint32_t aslr_cookie = *(uint32_t *)(zone + COOKIE_OFFSET);
    printf("cookie: %#x\n", aslr_cookie);

    srand(aslr_cookie);

    for (int i = 0; i < 100; i++) {
        size_t pad = rand() % 200;
        char *ptr = malloc(pad + sizeof(secret));
        memcpy(&ptr[pad], secret, sizeof(secret));

        printf("target: ");
        uintptr_t target = read_pointer();

        if (target < MIN_ADDR || target > MAX_ADDR) {
            puts("miss");
        } else {
            printf("hit: %u\n", *(uint8_t *)target);
        }

        memset(ptr, 0, pad + sizeof(secret));
        free(ptr);
    }

    puts("that's enough practice.");
}

int main(int argc, char *argv[]) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char *env = getenv("MallocNanoMaxMagazines");
    if (env == NULL || strcmp(env, "1")) {
        puts("run with MallocNanoMaxMagazines=1");
        return 0;
    }

    env = getenv("MallocNanoZone");
    if (env == NULL || strcmp(env, "1")) {
        puts("run with MallocNanoZone=1");
        return 0;
    }

    setup();
    run();

    char secret_guess[sizeof(secret) + 1];
    printf("what's the secret? ");
    read(STDIN_FILENO, secret_guess, sizeof(secret) + 1);
    if (memcmp(secret, secret_guess, sizeof(secret))) {
        puts("incorrect.");

        return 1;
    } else {
        puts("correct!");

        FILE* f = fopen("flag.txt", "r");
        char flag[50] = {0};
        fread(flag, 50, 1, f);

        puts(flag);

        return 0;
    }
}
