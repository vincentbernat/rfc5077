/* RFC 5077 client test */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "common.h"

#define PORT "https"
#define TRY  5
#define UA   "Mozilla/5.0 (compatible; RFC5077-Checker/0.1; +https://github.com/vincentbernat/rfc5077)"

/* Display usage and exit */
static void
usage(char * const name) {
  fail("Usage: %s host [host ...]\n"
       "\n"
       " Check if a host or a pool of hosts support RFC 5077.", name);
}

/* Solve hostname to IPs */
static void
resolve(const char *host, struct addrinfo **result) {
  int              err, count;
  char             name[INET6_ADDRSTRLEN*4];
  char            *p;
  struct addrinfo  hints;
  struct addrinfo *next;

  start("Solve %s", host);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = 0;
  hints.ai_protocol = 0;
  if ((err = getaddrinfo(host, PORT, &hints, result)) != 0)
    fail("Unable to solve ‘%s:%s’:\n%s", host, PORT, gai_strerror(err));

  count = 0;
  name[0] = '\0';
  for (next = *result, p = name; next; next = next->ai_next, count++) {
    strcat(p, "\n"); p++;
    err = getnameinfo(next->ai_addr, next->ai_addrlen,
		      p, sizeof(name) - (p - name), NULL, 0,
		      NI_NUMERICHOST);
    if ((err == EAI_OVERFLOW) ||
	(err == EAI_SYSTEM && errno == ENOSPC) || /* Odd... Bug #13166 */
	(sizeof(name) - strlen(name)) < 2) {
      p--; *p = '\0';
      while (sizeof(name) - strlen(name) < strlen("\n[...]") + 1) {
	p = strrchr(name, '\n');
	*p = '\0';
      }
      strncat(name, "\n[...]", sizeof(name));
      name[sizeof(name)] = '\0';
      while ((next = next->ai_next)) count++;
      break;
    }
    if (err != 0)
      fail("Unable to format ‘%s:%s’:\n%s\n%m", host, PORT, gai_strerror(err));
    p = p + strlen(p);
  }
  end("Got %d result%s:%s", count, (count > 1)?"s":"", name);
}

struct resultinfo {
  char              *host;	     /* Tested host */
  int                try;	     /* Try number (0, 1, 2, ...) */
  int                session_reused; /* Is session reused? */
  SSL_SESSION       *session;	     /* SSL session */
  char	            *answer;	     /* HTTP answer */
  struct resultinfo *next;	     /* Next result */
};

static void
resultinfo_free(struct resultinfo *result) {
  struct resultinfo *r, *n;
  for (r = n = result; r; r = n = n->next) {
    if (r->host) free(r->host);
    if (r->session) SSL_SESSION_free(r->session);
    if (r->answer)  free(r->answer);
    free(r);
  }
}

/* Display results as a table (best-effort) */
static void
resultinfo_display(struct resultinfo *result) {
  int          i, n;
  char        *buf;
  BIO         *mem = BIO_new(BIO_s_mem());
  SSL_SESSION *x;

  start("Display result set");
  if (!result) fail("No memory");
  if (BIO_printf(mem,
		 "         IP address            │ Try │         Cipher        │ Reuse │ "
		 "   SSL Session ID   │      Master key     │ Ticket │ Answer \n"
		 "───────────────────────────────┼─────┼───────────────────────┼───────┼─"
		 "────────────────────┼─────────────────────┼────────┼───────────────────") <= 0)
    goto err;

  for(; result; result = result->next) {
    x = result->session;
    if (BIO_printf(mem, "\n%-30s │ %3d │ %-21s │   %s   │ ",
		   result->host,
		   result->try,
		   x->cipher?x->cipher->name:"unknown",
		   result->session_reused?"✔":"✘") <= 0) goto err;

    if (x->session_id_length == 0) {
      if (BIO_printf(mem, "%19s", "") <= 0)
	goto err;
    } else {
      for (i = 0; (i < x->session_id_length) && (i < 9); i++) {
	if (BIO_printf(mem, "%02X", x->session_id[i]) <= 0) goto err;
      }
      if ((i != x->session_id_length) &&
	  (BIO_puts(mem, "…") <= 0)) goto err;
    }
    if (BIO_puts(mem, " │ ") <=0) goto err;
    if (x->master_key_length == 0) {
      if (BIO_printf(mem, "%19s", "") <= 0)
	goto err;
    } else {
      for (i = 0; (i < x->master_key_length) && (i < 9); i++) {
	if (BIO_printf(mem, "%02X", x->master_key[i]) <= 0) goto err;
      }
      if ((i != x->master_key_length) &&
	  (BIO_puts(mem, "…") <= 0)) goto err;
    }
    if (BIO_printf(mem, " │   %s    │ %s ",
		   x->tlsext_ticklen?"✔":"✘",
		   result->answer?result->answer:"") <= 0) goto err;
  }

  n = BIO_get_mem_data(mem, &buf);
  buf[n-1] = '\0';
  end(buf);
  BIO_free(mem);
  return;

 err:
  fail("BIO failure");
}

/* Dump results in a CSV file */
static void
resultinfo_write(const char *comment, struct resultinfo *result,
		 FILE *output, int write_header) {
  SSL_SESSION  *x;
  int           i;

  start("Dump results to file");
  if (write_header)
    fprintf(output,
	    "test;IP;try;version;cipher;compression;"
	    "reuse;session id;master key;ticket;answer\n");
  for(; result; result = result->next) {
    x = result->session;

    /* Comment, host and try number */
    fprintf(output, "%s;%s;%d;",
	    comment,
	    result->host,
	    result->try);

    /* Display version */
    if (x->ssl_version == SSL2_VERSION)
      fprintf(output, "SSLv2");
    else if (x->ssl_version == SSL3_VERSION)
      fprintf(output, "SSLv3");
    else if (x->ssl_version == TLS1_VERSION)
      fprintf(output, "TLSv1");
    else
      fprintf(output, "%d", x->ssl_version);

    /* Cipher, compression method */
    fprintf(output, ";%s;%d",
	    x->cipher?x->cipher->name:"",
	    x->compress_meth);

    /* Session stuff */
    fprintf(output, ";%d;", result->session_reused?1:0);
    for (i = 0; i < x->session_id_length; i++)
      fprintf(output, "%02X", x->session_id[i]);
    fprintf(output, ";");
    for (i = 0; i < x->master_key_length; i++)
      fprintf(output, "%02X", x->master_key[i]);
    fprintf(output, ";%d;%s\n", x->tlsext_ticklen?1:0,
	    result->answer?result->answer:"");
  }
  return;
}

static struct resultinfo*
tests(SSL_CTX *ctx, struct addrinfo *hosts, int tickets) {
  SSL*                ssl;
  SSL_SESSION*        ssl_session = NULL;
  int                 s, err, n;
  char                name[INET6_ADDRSTRLEN];
  char                buffer[256];
  struct resultinfo  *results = NULL, *r;
  struct resultinfo **p;

  p = &results;

  if (tickets)
    start("Run tests with use of tickets");
  else
    start("Run tests without use of tickets");

  for (struct addrinfo *current = hosts;
       current;
       current = current->ai_next) {

    /* For diagnostic purpose, we want to keep the IP address we test */
    if ((err = getnameinfo(current->ai_addr, current->ai_addrlen,
			   name, sizeof(name), NULL, 0,
			   NI_NUMERICHOST)))
      fail("Unable to format IP address:\n%s\n%m", gai_strerror(err));
    name[sizeof(name)] = '\0';

    for (int try = 0; try < TRY; try++) {

      /* Create socket and connect. */
      if ((s = socket(current->ai_family,
		      current->ai_socktype,
		      current->ai_protocol)) == -1)
	fail("Unable to create socket for ‘%s’:\n%m", name);
      if ((err = connect(s, current->ai_addr,
			 current->ai_addrlen)) == -1)
	fail("Unable to connect to ‘%s:%s’:\n%m", name, PORT);

      /* SSL handshake */
      if ((ssl = SSL_new(ctx)) == NULL)
	fail("Unable to create new SSL struct:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
      SSL_set_fd(ssl, s);
      if (!tickets) SSL_set_options(ssl, SSL_OP_NO_TICKET);
      if (ssl_session) {
	if (!SSL_set_session(ssl, ssl_session)) {
	  fail("Unable to set session to previous one:\n%s",
	       ERR_error_string(ERR_get_error(), NULL));
	}
      }
      if (SSL_connect(ssl) != 1)
	fail("Unable to start TLS negociation with ‘%s’:\n%s",
	     name,
	     ERR_error_string(ERR_get_error(), NULL));

      /* Grab session to store it */
      if (!(ssl_session = SSL_get1_session(ssl)))
	fail("No session available");
      r = malloc(sizeof(struct resultinfo));
      if (r == NULL) fail("Unable to allocate memory");
      r->host = strdup(name);
      r->try = try;
      r->session_reused = SSL_session_reused(ssl);
      r->session = ssl_session;
      r->answer = NULL;
      r->next = NULL;
      *p = r;
      p = &r->next;

      /* Send HTTP request */
      n = snprintf(buffer, sizeof(buffer),
		   "HEAD / HTTP/1.0\r\n"
		   "User-Agent: " UA "\r\n"
		   "\r\n");
      if (n == -1 || n >= sizeof(buffer))
	fail("Unable to build request to send to ‘%s’", name);
      if (SSL_write(ssl, buffer, strlen(buffer)) != strlen(buffer))
	fail("SSL write request to ‘%s’ failed:\n%s",
	     name,
	     ERR_error_string(ERR_get_error(), NULL));

      /* Read answer */
      if ((n = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0)
	fail("SSL read request failed:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
      buffer[n] = '\0';
      if (strchr(buffer, '\r'))
	*strchr(buffer, '\r') = '\0';
      r->answer = strdup(buffer);

      SSL_shutdown(ssl);
      close(s);
      SSL_free(ssl);
    }
  }
  return results;
}

int
main(int argc, char * const argv[]) {
  /* We need at least one host */
  start("Check arguments");
  if (argc < 2) usage(argv[0]);

  /* Solve all hosts given on the command line */
  int              i;
  struct addrinfo *hosts, **next;
  next = &hosts;
  for (i = 1; i < argc; i++) {
    resolve(argv[i], next);
    next = &((*next)->ai_next);
  }

  start("Prepare tests");

  /* Initialize OpenSSL library */
  SSL_CTX *ctx;
  SSL_load_error_strings();
  SSL_library_init();
  if ((ctx = SSL_CTX_new(TLSv1_client_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  /* Run tests without and with tickets and store them to a file */
  struct resultinfo *results;
  FILE              *output;
  char               name[1024];
  time_t             now = time(NULL);
  int                n;

  /* Build file name */
  n = snprintf(name, sizeof(name),
	       "rfc5077-output-%lu", (unsigned long)now);
  if (n == -1 || n >= sizeof(name))
    fail("Not possible...");
  for (i = 1; i < argc; i++) {
    strncat(name, "-", sizeof(name) - 1);
    strncat(name, argv[i], sizeof(name) - 1);
  }
  strncat(name, ".csv", sizeof(name) - 1);
  if ((output = fopen(name, "w+")) == NULL)
    fail("Unable to create output file ‘%s’:\n%m", name);

  /* Run tests */
  results = tests(ctx, hosts, 0);
  resultinfo_display(results);
  resultinfo_write("Without tickets", results, output, 1);
  resultinfo_free(results);

  results = tests(ctx, hosts, 1);
  resultinfo_display(results);
  resultinfo_write("With tickets", results, output, 0);
  resultinfo_free(results);

  fclose(output);
  SSL_CTX_free(ctx);
  freeaddrinfo(hosts);
  end(NULL);
  return 0;
}
