// clang lucky_visitor.m -fno-stack-protector -O0 -fobjc-arc -fmodules -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -o lucky_visitor
#include <stdio.h>

@import Foundation;

void win() {
    char flag[0x100] = {0};
    FILE* f = fopen("flag.txt", "r");
    fread(flag, 0x100, 1, f);
    printf("%s\n", flag);
}

char address[0x40] = {0};

int main(int argc, char *argv[], char *envp[]) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    NSItemProvider* iphone;
    char fruit[20];

    printf("Congratulations, you've won a FREE iPhone 17 for being visitor number %ld! Please answer a short survey to claim your prize.\n", (unsigned long)&win);

    printf("What is your favourite fruit? ");
    [[[NSFileHandle fileHandleWithStandardInput] availableData] getBytes:fruit length:0x20];

    printf("Where should we send your prize? ");
    [[[NSFileHandle fileHandleWithStandardInput] availableData] getBytes:address length:0x40];

    puts("Thank you for your information. Enjoy your prize :)");
}
