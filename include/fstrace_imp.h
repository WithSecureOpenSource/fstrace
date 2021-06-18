/* Copyright (C) 2013, F-Secure Corporation */

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>

#include <fsdyn/list.h>
#include <rotatable/rotatable.h>

enum {
    BLOCK_SIZE = 1 << 13,
    ALIGNMENT = 1 << 6,
    ALIGNMENT_MASK = ALIGNMENT - 1
};

typedef struct {
    uint8_t *start;
    uint8_t *free;
} fstrace_memblock_t;

struct fstrace {
    list_t *mempool; /* of fstracce_memblock_t */
    char *pathname_prefix;
    ssize_t rotate_size;
    list_t *events;    /* of struct fstrace_event_impl */
    sigset_t old_mask; /* for signal handling */
    int mutex;         /* for processes */
    /* Whenever ordinal != *shared_orginal (inside a critical section),
     * the trace file needs to be reopened. */
    unsigned ordinal;         /* this process's view */
    unsigned *shared_ordinal; /* all processes' global view */
    /* If the fstrace object is opened with fstrace_direct(),
     * rotatable is NULL and outf is an unchanging output destination.
     * If the fstrace object is opened with fstrace_open(), rotatable
     * is non-NULL and outf is assigned to rotatable_file() before
     * producing output. */
    rotatable_t *rotatable;
    FILE *outf;
    rotatable_params_t *params;
    const char *file;      /* source file; valid during logging */
    unsigned lineno;       /* line number; valid during logging */
    int err;               /* errno; valid during logging */
    list_t *common_fields; /* of struct fstrace_field */
};

struct fstrace_field {
    char *leader;
    void (*processor)(fstrace_t *trace, va_list *pap);
};

struct fstrace_event_impl {
    fstrace_t *trace;
    fstrace_event_t *shared;
    char *id;
    list_t *fields; /* of struct fstrace_field */
};
