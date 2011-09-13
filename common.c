#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>

static char current[2048];
static int running = 0;

#define BEGIN "\r\033[2K"
#define CHECK "\033[1;32m✔\033[0m"
#define BALLOT "\033[1;31m✘\033[0m"
#define WARN "\033[1;33m‼\033[0m"

static void
display(const char *sign, const char *format, va_list ap) {
  if (running) {
    running = 0;
    fprintf(stderr, BEGIN "[%s] %s%c\n", sign, current, format?':':'.');
    fflush(stderr);
  }

  if (format) {
    /* We indent the message */
    int   n = 0;
    int   size    = 0;
    char *message = NULL;
    char *cur;
    while (n >= size) {
      if ((message = realloc(message, size + 2048)) == NULL) return;
      size = size + 2048;
      if ((n = vsnprintf(message, size, format, ap)) == -1) return;
    }
    cur = message;
    fprintf(stderr, "    │ ");
    while (*cur) {
      if (*cur == '\n')
	fprintf(stderr, "\n    │ ");
      else
	fprintf(stderr, "%c", *cur);
      cur++;
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    free(message);
  }
}

void
start(const char *format, ...) {
  va_list ap;
  int     n;
  if (running) end(NULL);

  /* Save the current message */
  va_start(ap, format);
  n = vsnprintf(current, sizeof(current), format, ap);
  va_end(ap);
  if (n == -1 || n >= sizeof(current))
    exit(EXIT_FAILURE);

  /* Display */
  fprintf(stderr, "[ ] %s ...", current);
  fflush(stderr);
  running = 1;
}

void
end(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  display(CHECK, format, ap);
  va_end(ap);
}

void
fail(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  display(BALLOT, format, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

void
warn(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  display(WARN, format, ap);
  va_end(ap);
}
