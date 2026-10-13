// Freestanding fixture, intentionally independent of libc/NDK headers.
extern "C" unsigned long long add_seven(unsigned long long x) {
    return x + 7ULL;
}
