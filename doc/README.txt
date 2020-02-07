Trace File Format
=================

 * The trace file is a sequence of ASCII records.

 * Each record has this format:

   "YYYY-MM-DD hh:mm:ss.dddddd <id> <format>\n"

   that is, the UTC timestamp followed by the id and expanded format as
   given in fstrace_declare() by user code.


Trace Event Format
==================

Trace events are declared in user code with the fstrace_declare()
function. The function has a format argument similar to (but not
identical with) that in the standard printf(3) function:


   ====================================================================
    Format     Output
   Directive   Format                              Explanation
               RegEx
   ====================================================================
      %%       %                                   percent
      %d       -?[0-9]+                            signed integer
      %u       [0-9]+                              unsigned integer
      %x       [0-9a-f]+                           unsigned hexadecimal
      %64d     -?[0-9]+                            signed integer
      %64u     [0-9]+                              unsigned integer
      %64x     [0-9a-f]+                           unsigned hexadecimal
      %z       -?[0-9]+                            signed integer
      %f       -?[0-9]+(\.[0-9]+)?(e[-+][0-9]+)+   floating-point
      %b       true|false                          boolean
      %s       [-0-9A-Za-z"%./<>\^_`{|}~]*         URL-encoded string(*)
      %S       [-0-9A-Za-z"%./<>\^_`{|}~]*         URL-encoded string(*)
      %I       [-0-9A-Za-z"%./<>\^_`{|}~]*         URL-encoded string(*)
      %A       [-0-9A-Za-z"%./<>\^_`{|}~]*         URL-encoded string(**)
      %B       ([0-9a-f][0-9a-f])*                 octet string
      %P       [0-9]+                              getpid()
      %T       [0-9]+                              pthread_self()
      %F       [-0-9A-Za-z"%./<>\^_`{|}~]*             __FILE__
      %L       [0-9]+                              __LINE__
      %e       [0-9A-Z]+                           errno (symbol or number)
      %E       [0-9A-Z]+                           errno (symbol or number)
      %p       [0-9a-f]+                           pointer
      %a       [-0-9A-Za-z"%./<>\^_`{|}~]*         network address(***)
      %J       \[([-0-9A-Za-z"%./<>\^_`{|}~]*(,[-0-9A-Za-z"%./<>\^_`{|}~]*)*)?\]
                                                   list of URL-encoded
                                                   strings(****)
   ====================================================================

(*) The NUL character is illegal inside a string. The percent encoding
%00 is reserved for the encoding of an omitted string (NULL pointer).

(**) The NUL character is allowed inside the string.

(***) Examples:
      AF_INET`127.0.0.1`12345
      AF_INET6`fe80::62b7:7d4a:ed95:922a`12345
      AF_UNIX`/etc/opt/f-secure/baseguard/aadfkfj
      OTHER`ffeea1
      -

(****) Examples:
       []
       [hello]
       [hello,world]


Convention
==========

The user code is advised to stick to format strings like this:

   "ICAP-ACCEPT RHOST=%s RPORT=%d CONN-ID=%d"

where "ICAP-ACCEPT" is the id of the event. In particular, the format
string must only contain printable, non-control ASCII characters
(regular expression: /[ -~]*/).

The event id's of a single tracing component should have a common prefix
to facilitate event filtering.
