// Tiny check framework for the HF14 out-of-tree harness. Deliberately no
// gtest: these binaries build against the normal tree and run anywhere.
#pragma once

#include <cstdio>
#include <cstdlib>

static int hf14checks_failures = 0;
static int hf14checks_checks = 0;

#define CHECK_TRUE(expr) \
    do { \
        ++hf14checks_checks; \
        if (!(expr)) { \
            ++hf14checks_failures; \
            std::fprintf(stderr, "FAIL %s:%d: expected true: %s\n", __FILE__, __LINE__, #expr); \
        } \
    } while (0)

#define CHECK_FALSE(expr) \
    do { \
        ++hf14checks_checks; \
        if (expr) { \
            ++hf14checks_failures; \
            std::fprintf(stderr, "FAIL %s:%d: expected false: %s\n", __FILE__, __LINE__, #expr); \
        } \
    } while (0)

#define RUN(fn) \
    do { \
        std::printf("-- %s\n", #fn); \
        fn(); \
    } while (0)

static int check_summary(const char *name)
{
    if (hf14checks_failures == 0)
        std::printf("%s: %d checks, all passed\n", name, hf14checks_checks);
    else
        std::printf("%s: %d of %d checks FAILED\n", name, hf14checks_failures, hf14checks_checks);
    return hf14checks_failures == 0 ? 0 : 1;
}
