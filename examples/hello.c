/* Build on macOS Apple Silicon: clang -arch arm64 -mmacosx-version-min=11.0 hello.c -o hello */
#include <stdio.h>
int main(void) { puts("Hello from ARM64 macOS"); return 0; }
