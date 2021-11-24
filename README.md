## Overview

fstrace is a C library for Linux and macOS that provides a framework
to trace a program execution.

## Building

fstrace uses [SCons][] and `pkg-config` for building and depends on
the following libraries:
- [fsdyn][]
- [rotatable][]

Before building fsdyn for the first time, run
```
git submodule update --init
```

To build fstrace, run
```
scons [ prefix=<prefix> ]
```
from the top-level fstrace directory. The prefix argument is a directory,
`/usr/local` by default, where the build system searches for `fstrace`
dependencies and installs fstrace.

To install fstrace, run
```
sudo scons [ prefix=<prefix> ] install
```

## Trace File Format

The trace file is a sequence of ASCII records. Each record has this
format:
```
YYYY-MM-DD hh:mm:ss.dddddd <id> <format>\n
```
that is, the UTC timestamp followed by the id and expanded format as
given in `fstrace_declare()` by user code.


## Trace Event Format

Trace events are declared in user code with the `fstrace_declare()`
function. The function has a format argument similar to (but not
identical with) that in the standard printf(3) function:


Format directive|Output format Regex|Explanation
----------------|-------------------|-----------
%%|%|percent
%d|`-?[0-9]+`|signed integer
%u|`[0-9]+`|unsigned integer
%x|`[0-9a-f]+`|unsigned hexadecimal
%64d|`-?[0-9]+`|signed integer
%64u|`[0-9]+`|unsigned integer
%64x|`[0-9a-f]+`|unsigned hexadecimal
%z|`-?[0-9]+`|signed integer
%f|`-?[0-9]+(\.[0-9]+)?(e[-+][0-9]+)+`|floating-point
%b|`true\|false`|boolean
%s|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|URL-encoded string<sup>1</sup>
%S|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|URL-encoded string<sup>1</sup>
%A|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|URL-encoded string<sup>2</sup>
%B|`([0-9a-f][0-9a-f])*`|octet string
%P|`[0-9]+`|getpid()
%T|`[0-9]+`|pthread_self()
%F|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|`__FILE__`
%L|`[0-9]+`|`__LINE__`
%e|`[0-9A-Z]+`|errno (symbol or number)
%E|`[0-9A-Z]+`|errno (symbol or number)
%p|`[0-9a-f]+`|pointer
%a|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|network address<sup>3</sup>
%I|``[-0-9A-Za-z"%./<>\^_`{\|}~]*``|URL-encoded string<sup>1</sup>
%J|``\[([-0-9A-Za-z"%./<>\^_`{\|}~]*)(,\1)*\]``|list of URL-encoded strings<sup>4</sup>

1. The NUL character is illegal inside a string. The percent encoding
%00 is reserved for the encoding of an omitted string (NULL pointer).

2. The NUL character is allowed inside the string.

3. Examples:
```
 AF_INET`127.0.0.1`12345
 AF_INET6`fe80::62b7:7d4a:ed95:922a`12345
 AF_UNIX`/var/run/syslog
 OTHER`ffeea1
```

4. Examples:
```
[]
[hello]
[hello,world]
```

## Convention

The user code is advised to stick to format strings like this:

```
ICAP-ACCEPT RHOST=%s RPORT=%d CONN-ID=%d
```
where "ICAP-ACCEPT" is the id of the event. In particular, the format
string must only contain printable, non-control ASCII characters
(regular expression: `[ -~]*`).

The event id's of a single tracing component should have a common prefix
to facilitate event filtering.

[SCons]: https://scons.org/
[fsdyn]: https://github.com/F-Secure/fsdyn
[rotatable]: https://github.com/F-Secure/rotatable
