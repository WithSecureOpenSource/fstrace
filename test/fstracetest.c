#include "fstracetest.h"

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <fsdyn/charstr.h>
#include <fsdyn/fsalloc.h>
#include <fstrace.h>

static int failures = 0;

static void timestamp(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time_t t = tv.tv_sec;
    struct tm tm;
    gmtime_r(&t, &tm);
    char s[50];
    strftime(s, sizeof s, "%F %T", &tm);
    fprintf(stderr, "%s.%03d: ", s, (int) (tv.tv_usec / 1000));
}

void tlog(const char *format, ...)
{
    timestamp();
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static int outstanding_object_count = 0;
static bool log_allocation = false; /* set in debugger */

static fs_realloc_t reallocator;

static void *test_realloc(void *ptr, size_t size)
{
    void *obj = (*reallocator)(ptr, size);
    if (obj == NULL && size != 0)
        assert(0);
    if (ptr != NULL) {
        outstanding_object_count--;
        if (log_allocation)
            tlog("free %p", ptr);
    }
    if (obj != NULL) {
        outstanding_object_count++;
        if (log_allocation)
            tlog("alloc %p", obj);
    }
    return obj;
}

int posttest_check(int tentative_verdict)
{
    if (tentative_verdict != PASS)
        return tentative_verdict;
    if (outstanding_object_count != 0) {
        tlog("Garbage generated");
        return FAIL;
    }
    return PASS;
}

static void verify(const char *name, VERDICT (*testcase)(void))
{
    tlog("Begin %s", name);
    switch (testcase()) {
        case PASS:
            tlog("PASS");
            break;
        case FAIL:
            tlog("FAIL");
            failures++;
            break;
        default:
            assert(0);
    }
    tlog("End %s", name);
}

#define VERIFY(tc) verify(#tc, tc)

static char *prefix;

static int enable_all(void *data, const char *id)
{
    return 1;
}

static int disable_all(void *data, const char *id)
{
    return -1;
}

VERDICT test_fstrace_basic(void)
{
    fstrace_t *trace = fstrace_open(prefix, 10);
    fstrace_set_common_format(trace, "P=%P");
    fstrace_event_t *TEST_BASIC =
        fstrace_declare(trace, "TEST-BASIC", "A=%d B=%s");
    FSTRACE(TEST_BASIC, 7, "hello world");
    fstrace_select_safe(trace, enable_all, NULL);
    FSTRACE(TEST_BASIC, 8, "hello world");
    FSTRACE(TEST_BASIC, 9, "a+b");
    fstrace_select_safe(trace, disable_all, NULL);
    fstrace_close(trace);
    return posttest_check(PASS);
}

static const char *trace_sign(const void *arg)
{
    int value = *(int *) arg;
    if (value < 0)
        return "negative";
    if (value > 0)
        return "positive";
    return "zero";
}

static const char *trace_rhyme(const void *arg)
{
    switch ((*(int *) arg)++) {
        case 0:
            return "eeny";
        case 1:
            return "meeny";
        case 2:
            return "miny";
        case 3:
            return "moe";
        default:
            return NULL;
    }
}

VERDICT test_fstrace_iterated(void)
{
    fstrace_t *trace = fstrace_open(prefix, 10);
    fstrace_event_t *TEST_ITER =
        fstrace_declare(trace, "TEST-ITER", "A=%I B=%J");
    int n = -2, rhyme = 0;
    fstrace_select_safe(trace, enable_all, NULL);
    FSTRACE(TEST_ITER, trace_sign, &n, trace_rhyme, &rhyme);
    fstrace_close(trace);
    return posttest_check(PASS);
}

VERDICT test_fstrace_perf(void)
{
    fstrace_t *trace = fstrace_open(prefix, 1000000);
    fstrace_limit_rotation_byte_count(trace, 2500000);
    fstrace_event_t *TEST_PERF =
        fstrace_declare(trace, "TEST-PERF",
                        "A=%d B=%s C=%64u D=%64x F=%F L=%L");
    fstrace_select_safe(trace, enable_all, NULL);
    int i;
    for (i = 0; i < 100000; i++)
        FSTRACE(TEST_PERF, 7, "hello world", (uint64_t) 9999999999999999LL,
                (uint64_t) -1);
    fstrace_close(trace);
    return posttest_check(PASS);
}

VERDICT test_fstrace_robustness(void)
{
    fstrace_t *trace = fstrace_open(prefix, 1000000);
    fstrace_limit_rotation_byte_count(trace, 2500000);
    fstrace_event_t *TEST_ROBUST = fstrace_declare(trace, "TEST-ROBUST", "%s");
    fstrace_select_safe(trace, enable_all, NULL);
    pid_t child_pid = fork();
    assert(child_pid >= 0);
    if (child_pid == 0) {
        /* Child: crash intentionally */
        FSTRACE(TEST_ROBUST, (const char *) 7);
        assert(false);
    }
    pid_t pid = waitpid(child_pid, NULL, 0);
    assert(pid == child_pid);
    FSTRACE(TEST_ROBUST, "hello world");
    fstrace_close(trace);
    return posttest_check(PASS);
}

int main(int argc, char *const argv[])
{
    char *lock_path = charstr_printf("%s/lock", argv[1]);
    fstrace_set_lock_path(lock_path);
    fsfree(lock_path);
    char *log_path = charstr_printf("%s/log", argv[1]);
    mkdir(log_path, 0777);
    struct stat statbuf;
    stat(log_path, &statbuf);
    assert(S_ISDIR(statbuf.st_mode));
    prefix = charstr_printf("%s/trace", log_path);
    fsfree(log_path);
    reallocator = fs_get_reallocator();
    fs_set_reallocator(test_realloc);
    VERIFY(test_fstrace_perf);
    VERIFY(test_fstrace_basic);
    VERIFY(test_fstrace_iterated);
    VERIFY(test_fstrace_robustness);
    fsfree(prefix);
    return failures;
}
