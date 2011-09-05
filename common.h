#include <netdb.h>

/* Client side */
extern int
client(int, char * const [],
       int (*)(char *, char *, int, int, int));
extern int
connect_socket(struct addrinfo *, char *, char *);
extern struct addrinfo*
solve(char *, char*);

/* Display functions */
extern void
start(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
end(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
fail(const char *, ...)
__attribute__ ((format (printf, 1, 2)));

extern void
warn(const char *, ...)
__attribute__ ((format (printf, 1, 2)));
