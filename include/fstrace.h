/* Copyright (C) 2013, F-Secure Corporation */

#ifndef __FSTRACE__
#define __FSTRACE__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fstrace fstrace_t;
typedef struct {
    struct fstrace_event_impl *impl;
    volatile int enabled;
} fstrace_event_t;

/* Get a globally unique identifier. (There is a nonzero probability
 * for non-uniqueness.) */
uint64_t fstrace_get_unique_id(void);

/*
 * Open a trace log. At the generation of the first trace log entry, a
 * new trace log file is created. The pathname of the file is composed
 * from the given pathname prefix and the UTC ISO 8601 timestamp as
 * follows:
 *
 *    ${prefix}YYYY-MM-DDThh:mm:ss.dddddd.log
 *
 * The directory must pre-exist.
 *
 * If rotate_size is nonnegative, a new log file is opened whenever the
 * current trace log size exceeds it. A negative value suppresses log
 * rotation.
 *
 * Sets errno and returns NULL in case of error.
 */
fstrace_t *fstrace_open(const char *pathname_prefix, ssize_t rotate_size);

/*
 * Output the trace log to the given file.
 *
 * Sets errno and returns NULL in case of error.
 */
fstrace_t *fstrace_direct(FILE *outf);

/*
 * Sets errno and returns a negative number in case of error.
 */
int fstrace_close(fstrace_t *trace);

/*
 * Sets errno and returns NULL in case of error.
 *
 * Supported format directives:
 *
 * %%    The percent character. No argument.
 * %d    An int argument.
 * %u    An unsigned argument.
 * %x    An unsigned argument.
 * %64d  An int64_t argument.
 * %64u  An uint64_t argument.
 * %64x  An uint64_t argument.
 * %z    An ssize_t (or size_t) argument.
 * %f    A double argument.
 * %b    A boolean (or int) argument.
 * %s    A NUL-terminated string argument. A null pointer argument is
 *       allowed and mapped onto the empty string.
 * %S    A NUL-terminated string argument with size limit.
 *       Two arguments: <const char *, size_t>.
 * %I    Indirect string. Two arguments: <const char *(*f)(void *), void *>.
 *       Handy for mapping enumerated values. As tracing calls are
 *       made inside critical sections, the function may also return a
 *       pointer to a static buffer. A null pointer second argument is
 *       allowed and mapped onto the empty string, without invoking the
 *       trace function.
 * %J    Iterated indirect string. Two arguments:
 *       <const char *(*f)(void *), void *>. The function is called
 *       repeatedly until it returns NULL, and all returned strings
 *       are joined in the trace output with comma as separator.
 * %A    An octet string. Two arguments: <const void *, ssize_t>. A negative
 *       size is taken as 0.
 * %B    An octet string. Two arguments: <const void *, ssize_t>. A negative
 *       size is taken as 0.
 * %P    Record the process ID. No argument.
 * %T    Record the thread ID (pthread_self()). No argument.
 * %F    Record __FILE__ (string). No argument.
 * %L    Record __LINE__ (decimal integer). No argument.
 * %e    An errno symbol. No argument.
 * %E    An errno symbol. An int argument.
 * %p    A pointer argument.
 * %a    A network address. Two arguments:
 *       <const struct sockaddr *, socklen_t>.
 */
fstrace_event_t *fstrace_declare(fstrace_t *trace, const char *id,
                                 const char *format);

/*
 * Add a format string that is prepended to every trace event. The
 * format directives in the format string must not expect any
 * arguments. For example, "TID=%T" causes the current thread ID to be
 * inserted after the event id properly surrounded by whitespace.
 */
void fstrace_set_common_format(fstrace_t *trace, const char *format);

/*
 * Sets errno and returns a negative number in case of error. Don't call
 * fstrace_log...() directly. Instead, use the FSTRACE_... macros below.
 */
void fstrace_log(fstrace_event_t *event, ...);
void fstrace_log_2(fstrace_event_t *event, const char *file, unsigned lineno,
                   ...);

/*
 * FSTRACE_ENABLED() is true if the trace event is enabled. Use the
 * function in the exceptional case where you have to compute the
 * arguments to the FSTRACE() macro.
 */
static inline bool FSTRACE_ENABLED(fstrace_event_t *event)
{
    return event && event->enabled;
}

/*
 * Conditionally record a trace event using the FSTRACE() macro. The
 * event must have been declared with fstrace_declare() before and the
 * argument list must match the format expression of the declaration.
 *
 * Note, FSTRACE() can be used inside a signal handler. Exception: do
 * not call FSTRACE() when handling SIGSEGV or SIGBUS.
 */
#if defined(__GNUC__)
#define FSTRACE(event, ...)                                          \
    do {                                                             \
        if (FSTRACE_ENABLED(event))                                  \
            fstrace_log_2(event, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define FSTRACE(event, ...)                                        \
    do {                                                           \
        if (FSTRACE_ENABLED(event))                                \
            fstrace_log_2(event, __FILE__, __LINE__, __VA_ARGS__); \
    } while (0)
#endif

/*
 * Standard C doesn't allow you to invoke FSTRACE() unless you have at
 * least one optional argument. You can use FSTRACE_NO_ARGS() in such
 * case. However, GCC is more flexible and allows you to use FSTRACE()
 * even in that case.
 */
#define FSTRACE_NO_ARGS(event)                        \
    do {                                              \
        if (FSTRACE_ENABLED(event))                   \
            fstrace_log_2(event, __FILE__, __LINE__); \
    } while (0)

/*
 * Initially all trace events are disabled. You can selectively enable
 * and disable them with fstrace_select() or fstrace_select_safe().
 *
 * The supplied select callback should return a negative value for
 * disabled event id's, a positive value for enabled event id's and zero
 * for unchanged event id's.
 *
 * Use fstrace_select() from a signal handler, but make sure you don't
 * declare new events simultenously. Using fstrace_select_safe() is
 * robust and should be called outside signal handlers.
 */
void fstrace_select(fstrace_t *trace, int (*select)(void *data, const char *id),
                    void *data);
void fstrace_select_safe(fstrace_t *trace,
                         int (*select)(void *data, const char *id), void *data);

/*
 * A convenience function to select/deselect based on regular
 * expressions. If include_re is NULL, nothing is selected. If
 * exclude_re is NULL, nothing is excluded. Returns false, if one of the
 * regular expressions is bad.
 */
bool fstrace_select_regex(fstrace_t *trace, const char *include_re,
                          const char *exclude_re);

/*
 * You can enable or disable an indivual event using
 * fstrace_select_event, which is not available to a signal handler.
 *
 * If 'selection' is positive, the event is enabled. If 'selection' is
 * negative, the event is disabled. A zero value leaves the event
 * unchanged.
 */
void fstrace_select_event(fstrace_event_t *event, int selection);

/* For inter-process synchronization, the fstrace implementation may
 * use a lock file. By default the lock file is placed in a suitable,
 * unspecified location. The application should specify the location
 * explicitly using this function, which must be called at most once
 * before the first call to fstrace_open() or fstrace_direct().
 *
 * The application must make sure the pathname can be opened with the
 * O_CREAT | O_WRONLY flags.
 *
 * A future implementation of fstrace may make this function
 * redundant, in which case the function will do nothing.
 */
void fstrace_set_lock_path(const char *pathname);

/*
 * The fstrace library needs to initialize at startup time, which
 * leads to some global resources being owned by the owner of the
 * process. If the process is started privileged and wants to change
 * its effective or real user, you need to call fstrace_chown().
 *
 * Sets errno and returns a negative number in case of error.
 */
int fstrace_chown(uid_t owner, gid_t group);

/*
 * Call fstrace_reinit() if there is a chance you might have closed
 * the global underlying file descriptor of the fstrace library. That
 * could happen after you categorically close all open file
 * descriptors after a call to fork(), for example.
 *
 * Note that fstrace_reinit() is called by fstrace_reopen() (q.v.).
 *
 * Always returns 0.
 */
int fstrace_reinit(void);

/*
 * Call fstrace_reopen() if there is a chance you might have closed the
 * underlying file descriptor of the trace object. That could happen
 * after you categorically close all open file descriptors after a call
 * to fork(), for example.
 *
 * Note that fstrace_reopen() may reclaim old file descriptors it used
 * to own. Do not allow other code to "steal" that file descriptor.
 * fstrace_reopen() itself guarantees it does not claim any new file
 * descriptors. Thus, it is safe and advisable to place
 * fstrace_reopen() right after the child process closes file
 * descriptors.
 *
 * Always returns 0.
 *
 * See also fstrace_reinit().
 */
int fstrace_reopen(fstrace_t *trace);

/*
 * Over time, rotation file build up on the target system. By default,
 * there are no limits. The following functions cause the rotation
 * process enforce some limits to the buildup by removing oldest
 * rotation files.
 *
 * The main trace log file is never removed. The oldest rotation file
 * that violates a limit is kept, but anything older is removed.
 *
 * A negative argument can be given to specify "no limit."
 *
 * The limit enforcement only takes place at rotation (file rename) time
 * and not immediately when a limit is set.
 *
 * Don't call these functions from a signal handler.
 */
void fstrace_limit_rotation_file_count(fstrace_t *trace, int max_files);
void fstrace_limit_rotation_file_age(fstrace_t *trace, int max_seconds);
void fstrace_limit_rotation_byte_count(fstrace_t *trace, int64_t max_bytes);

typedef struct fstrace_event_spec {
    struct fstrace_event_spec *next;
    fstrace_event_t **variable;
    const char *id, *format;
} fstrace_event_spec_t;

/* Record a global trace event specification. Global trace events can be
 * declared en masse using fstrace_declare_globals(). */
#define FSTRACE_DECL(id, format)                                    \
    static fstrace_event_t *id;                                     \
    static __attribute__((constructor)) void __construct_##id(void) \
    {                                                               \
        static fstrace_event_spec_t spec;                           \
        static char name[] = #id;                                   \
        fstrace_specify(&spec, &id, name, format);                  \
    }

/* Record a global trace event specification. Meant to be used with the
 * FSTRACE_SPEC macro. Any underscores in the given variable name are
 * converted to hyphens for traditional reasons. */
void fstrace_specify(fstrace_event_spec_t *spec,
                     fstrace_event_t **event_variable,
                     char event_variable_name[], const char *format);

/* Call fstrace_declare() for every event that has been declared using
 * the FSTRACE_DECL macro. Please forbid calling the function for more
 * than one trace object at a time. */
void fstrace_declare_globals(fstrace_t *trace);

/* The %I and %J formatting directives usually need a way to return a
 * string for unexpected input. These convenience functions can be
 * used to convert integers to corresponding strings. They use static
 * storage so the return value is only good until one of the functions
 * is called again. */
const char *fstrace_signed_repr(int64_t n);
const char *fstrace_unsigned_repr(uint64_t n);
const char *fstrace_hex_repr(uint64_t n);

#ifdef __cplusplus
}

#if __cplusplus >= 201103L

#include <cassert>
#include <string>
#include <type_traits>

namespace fsecure {
namespace fstrace {

// This UniqueId class should be inherited by classes which desire to have a
// unique identier to use in fstrace entries.
class UniqueId {
public:
    UniqueId() : id_(fstrace_get_unique_id()) {}

    UniqueId(UniqueId&&) = default;
    UniqueId &operator=(UniqueId &&) = default;
    virtual ~UniqueId() = default;

    UniqueId(const UniqueId &)
        : id_(fstrace_get_unique_id())
    {}

    UniqueId &operator=(const UniqueId &)
    {
        // Let both keep their ids.
        return *this;
    }

    uint64_t id() const { return id_; }

private:
    uint64_t id_;
};

#if __cplusplus >= 201703L

// This TraceIterator class should be used with %J formatter to trace contents
// of C++ containers.
//
// Usage examples:
//
// FSTRACE_DECL(STRINGS, "STRINGS=%J");
// FSTRACE_DECL(ULL_NUMBERS, "ULL-NUMBERS=%J");
//
// void main()
// {
//   std::vector<std::string> strings{"aa", "bb", "cc"};
//   std::set<unsigned long long> ull_numbers{1,2,3,4};
//
//   // Trace all values in strings
//   auto string_iter = TraceIterator { strings };
//   FSTRACE(STRINGS, string_iter.trace, &string_iter);
//
//   // Trace all but last number in ull_numbers
//   auto ull_iter = TraceIterator<decltype(ull_numbers)>{
//       ull_numbers.cbegin(), ull_numbers.cend() - 1};
//   FSTRACE(ULL_NUMBERS, ull_iter.trace, &ull_iter);
// }
//
// Output:
// STRINGS=[aa,bb,cc]
// ULL-NUMBERS=[1,2,3]
template <typename TContainer>
struct TraceIterator {

    using const_iterator = typename TContainer::const_iterator;
    using value_type = typename const_iterator::value_type;

    TraceIterator(const TContainer &container)
        : TraceIterator(container.cbegin(), container.cend())
    {}

    TraceIterator(const_iterator current, const const_iterator end)
        : current_ { std::move(current) }
        , end_ { std::move(end) }
    {}

    // helper type for the static_assert in trace()
    template <class T>
    struct always_false : std::false_type {};

    static const char *trace(TraceIterator<TContainer> *tracer)
    {
        assert(tracer != nullptr);

        if (tracer->current_ == tracer->end_) {
            return nullptr;
        }

        const char *value = nullptr;
        if constexpr (std::is_same<value_type, std::string>::value) {
            value = static_cast<const std::string &>(*tracer->current_).c_str();
        } else if constexpr (std::is_same<value_type, uint64_t>::value) {
            value = fstrace_unsigned_repr(
                static_cast<std::uint64_t>(*tracer->current_));
        } else {
            static_assert(always_false<TContainer>::value, "Unsupported type");
        }
        tracer->current_++;
        return value;
    }

    const_iterator current_;
    const const_iterator end_;
};

#endif // #if __cplusplus >= 201703L

} // namespace fstrace
} // namespace fsecure

#endif // #if __cplusplus >= 201103L

#endif

#endif
