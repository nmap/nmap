#define PCRE_EXPORT
#define HAVE_STRERROR 1
#define HAVE_MEMMOVE  1

/* The value of NEWLINE determines the newline character. The default is to
leave it up to the compiler, but some sites want to force a particular value.
On Unix systems, "configure" can be used to override this default. */

#ifndef NEWLINE
#define NEWLINE '\n'
#endif

/* The value of LINK_SIZE determines the number of bytes used to store
links as offsets within the compiled regex. The default is 2, which allows for
compiled patterns up to 64K long. This covers the vast majority of cases.
However, PCRE can also be compiled to use 3 or 4 bytes instead. This allows for
longer patterns in extreme cases. On Unix systems, "configure" can be used to
override this default. */

#ifndef LINK_SIZE
#define LINK_SIZE   2
#endif

/* The value of MATCH_LIMIT determines the default number of times the match()
function can be called during a single execution of pcre_exec(). (There is a
runtime method of setting a different limit.) The limit exists in order to
catch runaway regular expressions that take for ever to determine that they do
not match. The default is set very large so that it does not accidentally catch
legitimate cases. On Unix systems, "configure" can be used to override this
default default. */

#ifndef MATCH_LIMIT
#define MATCH_LIMIT 10000000
#endif

/* The above limit applies to all calls of match(), whether or not they
increase the recursion depth. In some environments it is desirable to limit the
depth of recursive calls of match() more strictly, in order to restrict the
maximum amount of stack (or heap, if NO_RECURSE is defined) that is used. The
value of MATCH_LIMIT_RECURSION applies only to recursive calls of match(). To
have any useful effect, it must be less than the value of MATCH_LIMIT. There is
a runtime method for setting a different limit. On systems that support it,
"configure" can be used to override this default default. */

#ifndef MATCH_LIMIT_RECURSION
#define MATCH_LIMIT_RECURSION MATCH_LIMIT
#endif

/* These three limits are parameterized just in case anybody ever wants to
change them. Care must be taken if they are increased, because they guard
against integer overflow caused by enormously large patterns. */

#ifndef MAX_NAME_SIZE
#define MAX_NAME_SIZE 32
#endif

#ifndef MAX_NAME_COUNT
#define MAX_NAME_COUNT 10000
#endif

#ifndef MAX_DUPLENGTH
#define MAX_DUPLENGTH 30000
#endif

// This is set by configure on other platforms -Fyodor
#define POSIX_MALLOC_THRESHOLD 10

/* Without this, Windows will give us all sorts of crap about using functions
   like strcpy() even if they are done safely */
#define _CRT_SECURE_NO_DEPRECATE 1
/* End */
