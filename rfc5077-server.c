/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* RFC 5077 server test */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <ev.h>

#include "common.h"
#include "http-parser/http_parser.h"

#define PEM_CERTIFICATE "cert.pem"
#define PEM_KEY         "key.pem"
#define PEM_DH          "dh.pem"

#define NONBLOCKING(s) do {				\
  int val = 1;						\
  if (ioctl(s, FIONBIO, &val) == -1)			\
    fail("unable to set non blocking socket:\n%m");	\
  } while(0);

/* One server */
struct server {
  /* Configuration */
  int session_cache;	       /* Setup a session cache? */
  int accept_tickets;	       /* Accept tickets? */
  /* State */
  struct server *servers;      /* List of available servers */
  char    *port;	       /* Port we should listen to */
  int      socket;	       /* Socket the server is listening to */
  SSL_CTX *ctx;		       /* SSL context */
  ev_io    listener;
};

/* Buffer size. You can extend it, but don't shrink it. We use a large
   buffer because this app does not know how to split a response
   message. The buffer should be able to fit the largest response
   message (including headers). With a value of 16 kbytes, we won't be
   able to send messages larger than 8 kbytes. */
#define BUFSIZE 1024*8		/* 8 kbytes of buffer */

/* One connection. */
struct connection {
  ev_tstamp      start;  /* Timestamp for the start of the request */
  int            client; /* Client socket */
  struct server *server;
  ev_io          ev_read;	    /* Reading from the client */
  ev_io          ev_write;	    /* Writing to the client */
  ev_io          ev_read_handshake; /* SSL handshake with the client (read) */
  ev_io          ev_write_handshake;/* SSL handshake with the client (write) */
  ev_timer       ev_timeout;	    /* Basic timeout */
  char           buffer[BUFSIZE];   /* Read/write buffer */
  int            buffer_size;
  /* HTTP */
  int            response;	/* We are currently sending HTTP response */
  int            uastate;	/* State for parsing User-Agent header */
  http_parser    parser;   /* HTTP parser */
  int            method;   /* Action requested */
  char          *path;	   /* Path requested */
  char          *callback; /* Callback param (other params are discarded) */
  char          *ua;	   /* User agent */
  char          *protocol; /* Protocol */
  int            code;	   /* Code for response */
  int            size;	   /* Size of response */
  /* SSL */
  SSL  *ssl;	     /* SSL state */
  /* IP */
  char  ip[INET6_ADDRSTRLEN];	/* IP address of the client */
  /* Loop */
  struct ev_loop *loop;
};

/* Make a listening socket. */
static void
setup_socket(struct server *server) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;	/* IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

  /* Solve port name and get the binding address */
  int              s, sfd;
  struct addrinfo *result, *rp;
  if ((s = getaddrinfo(NULL, server->port, &hints, &result)) != 0)
    fail("Unable to solve ‘%s‘:\n%s", server->port, gai_strerror(s));

  /* Try to bind */
  for (rp = result; rp; rp = rp->ai_next) {
    if ((sfd = socket(rp->ai_family, rp->ai_socktype,
		      rp->ai_protocol)) == -1)
      continue;			/* Cannot bind. */

    int val = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
		   &val,sizeof(val)) == -1)
      fail("Unable to set socket options:\n%m");

    NONBLOCKING(sfd);

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1)
      fail("Unable to bind to ‘%s‘:\n%m", server->port);

#if TCP_DEFER_ACCEPT
    setsockopt(sfd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val) );
#endif

    break;
  }

  /* Then, listen */
  if (listen(sfd, 100) == -1)
    fail("Unable to listen to ‘%s‘:\n%m", server->port);

  server->socket = sfd;
  freeaddrinfo(result);
}

/* Setup SSL context for each server */
static void
setup_ssl(struct server *server) {
  SSL_CTX *ctx;

  /* Create context */
  if ((ctx = server->ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
    fail("Unable to create SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* Load certificate and key */
  if (SSL_CTX_use_certificate_file(ctx,
				   PEM_CERTIFICATE,
				   SSL_FILETYPE_PEM) != 1)
    fail("Unable to load certificate from ‘%s‘:\n%s",
	 PEM_CERTIFICATE,
	 ERR_error_string(ERR_get_error(), NULL));
  if (SSL_CTX_use_PrivateKey_file(ctx,
				  PEM_KEY,
				  SSL_FILETYPE_PEM) != 1)
    fail("Unable to load key from ‘%s‘:\n%s",
	 PEM_KEY,
	 ERR_error_string(ERR_get_error(), NULL));

  /* Load DH param */
  DH  *dh;
  BIO *bio = BIO_new_file(PEM_DH, "r");
  if (!bio)
    fail("Unable to load DH params from ‘%s‘:\n%s",
	 PEM_DH,
	 ERR_error_string(ERR_get_error(), NULL));
  dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!dh)
    fail("Unable to find DH params in ‘%s‘",
	 PEM_DH);
  SSL_CTX_set_tmp_dh(ctx, dh);
  DH_free(dh);

  /* Disable tickets */
  if (!server->accept_tickets)
    SSL_CTX_set_options(server->ctx, SSL_OP_NO_TICKET);

  /* Enable/disable session cache */
  SSL_CTX_set_session_cache_mode(server->ctx,
				 (server->session_cache)?
				 SSL_SESS_CACHE_SERVER:SSL_SESS_CACHE_OFF);
}

/* Handle shutdown of the connection */
static void
shutdown_connection(struct ev_loop *loop, struct connection *conn) {
  ev_io_stop(loop, &conn->ev_read);
  ev_io_stop(loop, &conn->ev_write);
  ev_io_stop(loop, &conn->ev_read_handshake);
  ev_io_stop(loop, &conn->ev_write_handshake);
  ev_timer_stop(loop, &conn->ev_timeout);
  close(conn->client);
  SSL_set_shutdown(conn->ssl, SSL_SENT_SHUTDOWN);
  SSL_free(conn->ssl);
  free(conn->path);
  free(conn->callback);
  free(conn->ua);
  free(conn->protocol);
  free(conn);
}
/* Handle shutdown in case of an SSL error */
static void
shutdown_connection_with_err(struct ev_loop *loop, struct connection *conn,
			     int err) {
  if (err == SSL_ERROR_ZERO_RETURN)
    warn("Connection with %s closed while receiving data (0)", conn->ip);
  else if (err == SSL_ERROR_SYSCALL) {
    if (errno == 0)
      warn("Connection with %s closed while receiving data (1)", conn->ip);
    else
      warn("Got an error with %s, closing:\n%m", conn->ip);
  } else
    warn("Unexpected SSL error with %s: %d", conn->ip, err);
  shutdown_connection(loop, conn);
  start("Ready for the next connection");
}

/* Return the requested HTTP answer */
static void
http_answer(struct ev_loop *loop, struct connection *conn,
	    int code, const char *reason, const char *content_type,
	    const char *body) {
  int n;
  int jsonp = 0;
  int len;
  conn->response = 1;
  ev_io_stop(loop, &conn->ev_read);
  ev_io_start(loop, &conn->ev_write);

  jsonp = (!strcmp(content_type, "application/json") && conn->callback);
  len = jsonp?(strlen(conn->callback) + 3 + strlen(body)):strlen(body);
  n = snprintf(conn->buffer, sizeof(conn->buffer),
	       "HTTP/1.0 %d %s\r\n"
	       "Cache-Control: no-cache\r\n"
	       "Content-Type: %s\r\n"
	       "Content-Length: %d\r\n"
	       "Connection: close\r\n"
	       "\r\n"
	       "%s%s%s%s",
	       code, reason,
	       jsonp?"application/javascript":content_type,
	       len,
	       jsonp?conn->callback:"",
	       jsonp?"(":"",
	       body,
	       jsonp?");":"");
  if (n == -1 || n >= sizeof(conn->buffer)) {
    warn("Answer too large");	/* Should not happen */
    shutdown_connection(loop, conn);
    return;
  }
  conn->buffer_size = n;
  conn->code = code;
  conn->size = len;
}

struct handler {
  char *path;			/* Requested path */
  int (*handle)(struct ev_loop *, struct connection *, void *);
  void *data;
};

/* Serve a static file */
static int
http_handle_file(struct ev_loop *loop, struct connection *conn, void *data) {
  char *path = (char *)data;
  char *buf = malloc(BUFSIZE);
  int   n, m = 0, buflen = BUFSIZE;
  int   fd = open(path, O_RDONLY);
  char *type = "text/html";
  char *ext;

  if (!buf) fail("Out of memory");
  if (!fd) {
    warn("Unable to open %s:\n%m", path);
    return 1;
  }

  /* Set content-type */
  ext = strrchr(path, '.');
  if (ext) {
    ext++;
    if (!strcmp(ext, "js")) type = "application/javascript";
  }

  /* Read file content (we may truncate) */
  while ((n = read(fd, buf + m, buflen - 1 - m))) m += n;
  buf[m] = '\0';

  /* Answer */
  http_answer(loop, conn, 200, "OK", type, buf);
  return 0;
}

/* Grab current session parameters */
static int
http_handle_session(struct ev_loop *loop, struct connection *conn, void *_) {
  SSL_SESSION *x = SSL_get_session(conn->ssl);
  char        *answer;

  char *version = "unknown";
  switch (x->ssl_version) {
  case SSL2_VERSION:
    version = "SSLv2"; break;
  case SSL3_VERSION:
    version = "SSLv3"; break;
  case TLS1_VERSION:
   version = "TLSv1"; break;
  }

  char *sessionid = malloc(2*x->session_id_length + 1);
  if (!sessionid) fail("Out of memory");
  for (int i = 0; i < x->session_id_length; i++)
    snprintf(sessionid + 2*i, 3, "%02X", x->session_id[i]);
  sessionid[2*x->session_id_length] = '\0';

  char *masterkey = malloc(2*x->master_key_length + 1);
  if (!masterkey) fail("Out of memory");
  for (int i = 0; i < x->master_key_length; i++)
    snprintf(masterkey + 2*i, 3, "%02X", x->master_key[i]);
  masterkey[2*x->master_key_length] = '\0';

  char *ticket = malloc(2*x->tlsext_ticklen + 1);
  if (!ticket) fail("Out of memory");
  for (int i = 0; i < x->tlsext_ticklen; i++)
    snprintf(ticket + 2*i, 3, "%02X", x->tlsext_tick[i]);
  ticket[2*x->tlsext_ticklen] = '\0';

  int n = asprintf(&answer,
		   "{ version: '%s', \r\n"
		   "  cipher: '%s', \r\n"
		   "  sessionid: '%s', \r\n"
		   "  masterkey: '%s', \r\n"
		   "  ticket: '%s' \r\n"
		   "}",
		   version,
		   x->cipher?x->cipher->name:"unknown",
		   sessionid,
		   masterkey,
		   ticket);
  free(sessionid);
  free(masterkey);
  free(ticket);
  if (n == -1) return 1;

  http_answer(loop, conn, 200, "OK",
	      "application/json",
	      answer);
  free(answer);
  return 0;
}

/* Return params for current server */
static int
http_handle_params(struct ev_loop *loop, struct connection *conn, void *_) {
  char *answer;
  int   n = asprintf(&answer,
		     "{ cache: %d,\r\n"
		     "  tickets: %d\r\n"
		     "}",
		     conn->server->session_cache,
		     conn->server->accept_tickets);
  if (n == -1) return 1;
  http_answer(loop, conn, 200, "OK", "application/json", answer);
  free(answer);
  return 0;
}

/* Return list of available servers */
static int
http_handle_servers(struct ev_loop *loop, struct connection *conn, void *_) {
  char *answer = NULL;
  struct server *server;
  for (server = conn->server->servers;
       server->session_cache != -1; server++) {
    char *old = answer;
    int   n = asprintf(&answer, "%s%s%s%s",
		       (old)?old:"",
		       (!old)?"{ servers: [ ":", ",
		       server->port,
		       ((server+1)->session_cache == -1)?" ] }":"");
    free(old);
    if (n == -1) return 1;
  }
  http_answer(loop, conn, 200, "OK", "application/json", answer);
  free(answer);
  return 0;
}

static struct handler http_handlers[] = {
  { "/",                  http_handle_file, "rfc5077-server.html" },
  { "/rfc5077-server.js", http_handle_file, "rfc5077-server.js" },
  { "/session",           http_handle_session },
  { "/params" ,           http_handle_params },
  { "/servers",           http_handle_servers },
  { NULL }
};

/* HTTP request received is complete */
static int
http_cb_message_complete(http_parser *p) {
  struct connection *conn = (struct connection*)p->data;
  struct handler    *h;

  for (h = http_handlers; h->path; h++) {
    if (strcmp(h->path, conn->path)) continue;
    if (h->handle(conn->loop, conn, h->data))
      http_answer(conn->loop, conn, 500, "Internal Error", "text/html",
		  "<html><body>\r\n"
		  "<h1>Internal error</h1>\r\n"
		  "An internal error occurred while serving the request\r\n"
		  "</body></html>\r\n");
    break;
  }
  if (!h->path) {
    http_answer(conn->loop, conn, 404, "Page not found", "text/html",
		"<html><body>\r\n"
		"<h1>Not found</h1>\r\n"
		"The requested page was not found\r\n"
		"</body></html>\r\n");
    return 0;
  }
  return 0;
}

/* Headers are complete, grab HTTP method and version */
static int
http_cb_headers_complete(http_parser *p) {
  struct connection *conn = (struct connection*)p->data;
  conn->method = p->method;
  asprintf(&conn->protocol, "HTTP/%d.%d", p->http_major, p->http_minor);

  /* Strip params and extract callback */
  char *q = strchr(conn->path, '?');
  if (q) {
    *q = '\0'; q++;
    /* We keep callback only if this is the first param */
    if (!strncmp(q, "callback=", 9)) {
      char *q2 = strchr(q, '&'); /* We hope this is not an entity */
      if (q2) *q2 = '\0';
      conn->callback = strdup(q + 9);
      if (!conn->callback) fail("Out of memory");
    }
  }
  
  return 0;
}

/* Received some bytes of the URL */
static int
http_cb_url(http_parser *p, const char *buf, size_t len) {
  struct connection *conn = (struct connection*)p->data;

  char *url;
  int   newlen = conn->path?strlen(conn->path):0 + len;
  url = realloc(conn->path, newlen + 1);
  if (!url) fail("Out of memory");
  if (!conn->path) strncpy(url, buf, len);
  else strncat(url, buf, len);
  url[newlen] = '\0';		/* strncpy */
  conn->path = url;
  return 0;
}

/* Received some bytes for a header field */
static int
http_cb_header_field(http_parser *p, const char *buf, size_t len) {
  struct connection *conn = (struct connection*)p->data;

  switch (conn->uastate) {
  case -2:
    /* We were reading user agent value. */
  case 0:
    /* We were not reading an header field. Check if we have
       user-agent field. */
    if (strncasecmp("user-agent", buf, len)) {
      conn->uastate = -1;	/* No */
      break;
    }
    conn->uastate = len;	/* Yes */
    break;
  case -1:
    /* We were reading an header field and it does not match
       user-agent. We are not interested in the remaining value of
       this header field. */
    break;
  default:
    /* We were reading an header field and it matches user-agent. */
    if (strncasecmp("user-agent" + conn->uastate, buf, len)) {
      conn->uastate = -1;	/* No */
      break;
    }
    conn->uastate += len;	/* Yes */
    break;
  }
  if (conn->uastate > 0 && conn->uastate > strlen("user-agent"))
    conn->uastate = -1;		/* Too long */

  return 0;
}

/* Received some bytes for a header value */
static int
http_cb_header_value(http_parser *p, const char *buf, size_t len) {
  struct connection *conn = (struct connection*)p->data;
  switch (conn->uastate) {
  case -2:
    /* Continuation of a previous user-agent */
    conn->ua = realloc(conn->ua, strlen(conn->ua) + len + 1);
    if (!conn->ua) fail("Out of memory");
    strncat(conn->ua, buf, len);
    break;
  case 10:			/* strlen("user-agent") */
    /* New user-agent value */
    conn->uastate = -2;
    if (conn->ua) {
      /* This is odd for a user agent, but HTTP requires to
	 concatenate fields with the same name */
      conn->ua = realloc(conn->ua, strlen(conn->ua) + 2 + len + 1);
      if (!conn->ua) fail("Out of memory");
      strcat(conn->ua, ", ");
      strncat(conn->ua, buf, len);
    } else {
      /* We don't have user-agent yet */
      conn->ua = strndup(buf, len);
      if (!conn->ua) fail("Out of memory");
    }
    break;
  default:
    /* Not a user-agent value */
    conn->uastate = 0;
  }
  return 0;
}

/* HTTP Parser settings */
static http_parser_settings parser_settings = {
  .on_header_field = http_cb_header_field,
  .on_header_value = http_cb_header_value,
  .on_headers_complete = http_cb_headers_complete,
  .on_url = http_cb_url,
  .on_message_complete = http_cb_message_complete
};

/* Be ready for an handshake */
static void
start_handshake(struct ev_loop *loop, struct connection *conn, int err) {
  /* Stop normal reading */
  ev_io_stop(loop, &conn->ev_read);
  ev_io_stop(loop, &conn->ev_write);
  /* Start handshake loop */
  if (err == SSL_ERROR_WANT_READ)
    ev_io_start(loop, &conn->ev_read_handshake);
  else if (err == SSL_ERROR_WANT_WRITE)
    ev_io_start(loop, &conn->ev_write_handshake);
}

/* Do the SSL handshake */
static void
handle_client_handshake(struct ev_loop *loop, ev_io *w, int revents) {
  struct connection *conn = (struct connection *)w->data;
  ev_timer_again(loop, &conn->ev_timeout); /* Reinit timeout */

  int err;
  err = SSL_do_handshake(conn->ssl);
  if (err == 1) {
    /* Handshake is successful */
    ev_io_stop(loop, &conn->ev_read_handshake);
    ev_io_stop(loop, &conn->ev_write_handshake);
    if (conn->response)
      ev_io_start(loop, &conn->ev_write); /* Keep sending HTTP response */
    else
      ev_io_start(loop, &conn->ev_read); /* Continue reading request */
  } else {
    err = SSL_get_error(conn->ssl, err);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      ev_io_stop(loop, &conn->ev_write_handshake);
      ev_io_start(loop, &conn->ev_read_handshake);
      break;
    case SSL_ERROR_WANT_WRITE:
      ev_io_stop(loop, &conn->ev_read_handshake);
      ev_io_start(loop, &conn->ev_write_handshake);
      break;
    case SSL_ERROR_ZERO_RETURN:
      warn("Connection close from %s (in handshake)", conn->ip);
      shutdown_connection(loop, conn);
      break;
    case SSL_ERROR_SSL:
      warn("Unable to do SSL handshake with %s:\n %s", conn->ip,
	   ERR_error_string(ERR_get_error(), NULL));
      shutdown_connection(loop, conn);
      break;
    case SSL_ERROR_SYSCALL:
      warn("Unable to do SSL handshake with %s:\n %m", conn->ip);
      shutdown_connection(loop, conn);
      break;
    default:
      warn("Unable to do SSL handshake with %s (%d)", conn->ip, err);
      shutdown_connection(loop, conn);
    }
  }
}

/* Handle read from the client (request) */
static void
handle_client_read(struct ev_loop *loop, ev_io *w, int revents) {
  struct connection *conn = (struct connection *)w->data;
  ev_timer_again(loop, &conn->ev_timeout); /* Reinit timeout */

  int n;
  n = SSL_read(conn->ssl, conn->buffer,
	       sizeof(conn->buffer));
  if (n > 0) {
    /* Feed the buffer to the HTTP parser */
    size_t nparsed = http_parser_execute(&conn->parser,
					 &parser_settings,
					 conn->buffer,
					 n);
    if (conn->parser.upgrade || nparsed != n)
      /* Issue a 400 bad request */
      http_answer(loop, conn,
		  400, "Bad request", "text/html",
		  "<html><body><h1>400 Bad request</h1>\r\n"
		  "Your browser sent an invalid request.\r\n"
		  "</body></html>\r\n");
  } else {
    n = SSL_get_error(conn->ssl, n);
    switch (n) {
    case SSL_ERROR_WANT_WRITE:
      /* Handshake wanted */
      start_handshake(loop, conn, n);
      break;
    case SSL_ERROR_WANT_READ:
      /* Not enough data */
      break;
    default:
      /* Fatal error */
      shutdown_connection_with_err(loop, conn, n);
      break;
    }
  }
}

/* Write data to the client (response) */
static void
handle_client_write(struct ev_loop *loop, ev_io *w, int revents) {
  struct connection *conn = (struct connection *)w->data;
  ev_timer_again(loop, &conn->ev_timeout); /* Reinit timeout */

  int n;
  n = SSL_write(conn->ssl, conn->buffer, conn->buffer_size);
  if (n > 0) {
    if (n != conn->buffer_size) {
      memmove(conn->buffer, conn->buffer + n,
	      conn->buffer_size - n);
      conn->buffer_size -= n;
    } else {
      /* No more to write. Display log line */
      char ctime[100];
      time_t now = conn->start;
      struct tm *tmp = gmtime(&now);
      strftime(ctime, sizeof(ctime), "%FT%TZ", tmp);
      end("%s - - [%s] \"%s %s %s\" %d %d \"%s\"",
	  conn->ip, ctime,
	  http_method_str(conn->method), /* GET */
	  conn->path,		  /* /foobar */
	  conn->protocol,	  /* HTTP/1.0 */
	  conn->code,		  /* 200 */
	  conn->size,		  /* 4874 */
	  conn->ua?conn->ua:"");  /* Mozilla/5.0 ... */
      shutdown_connection(loop, conn);
    }
  } else {
    n = SSL_get_error(conn->ssl, n);
    switch (n) {
    case SSL_ERROR_WANT_READ:
      /* Handshake wanted */
      start_handshake(loop, conn, n);
      break;
    case SSL_ERROR_WANT_WRITE:
      /* Not enough data */
      break;
    default:
      /* Fatal error */
      shutdown_connection_with_err(loop, conn, n);
      break;
    }
  }
}

/* Timeout for a client */
static void
handle_client_timeout(struct ev_loop *loop, ev_timer *w, int revents) {
  struct connection *conn = (struct connection *)w->data;
  warn("Timeout occurred with %s. Aborting connection", conn->ip);
  shutdown_connection(loop, conn);
}

/* Handle accept */
static void
handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);

  struct connection *conn = malloc(sizeof(struct connection));
  if (!conn) fail("Out of memory.");
  memset(conn, 0, sizeof(struct connection));
  conn->loop = loop;
  conn->start = ev_now(loop);
  conn->server = (struct server *)w->data;

  /* Accept the client */
  if ((conn->client = accept(w->fd,
		       (struct sockaddr *)&addr,
		       &addrlen)) == -1) {
    if (errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)
      return;
    fail("Unable to accept():\n%m");
  }

  /* Setup TCP_NODELAY, ignore any error */
  int flag = 1;
  setsockopt(conn->client, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

  NONBLOCKING(conn->client);
  
  /* Grab IP address of the client */
  int err;
  if ((err = getnameinfo((struct sockaddr *)&addr, addrlen,
			 conn->ip, sizeof(conn->ip), NULL, 0,
			 NI_NUMERICHOST)) != 0)
    fail("Unable to get format client address:\n%s",
	 gai_strerror(err));

  /* SSL setup */
  long mode = SSL_MODE_ENABLE_PARTIAL_WRITE;
#if SSL_MODE_RELEASE_BUFFERS
  mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
  conn->ssl = SSL_new(conn->server->ctx);
  SSL_set_mode(conn->ssl, mode);
  SSL_set_accept_state(conn->ssl);
  SSL_set_fd(conn->ssl, conn->client);

  /* Setup libev */
  ev_io_init(&conn->ev_read, handle_client_read, conn->client, EV_READ);
  conn->ev_read.data = conn;
  ev_io_init(&conn->ev_write, handle_client_write, conn->client, EV_WRITE);
  conn->ev_write.data = conn;
  ev_io_init(&conn->ev_read_handshake, handle_client_handshake, conn->client, EV_READ);
  conn->ev_read_handshake.data = conn;
  ev_io_init(&conn->ev_write_handshake, handle_client_handshake, conn->client, EV_WRITE);
  conn->ev_write_handshake.data = conn;
  ev_init(&conn->ev_timeout, handle_client_timeout);
  conn->ev_timeout.repeat = 10.;
  conn->ev_timeout.data = conn;
  ev_timer_again(loop, &conn->ev_timeout);

  /* Initialize the HTTP parser */
  http_parser_init(&conn->parser, HTTP_REQUEST);
  conn->parser.data = conn;

  /* Let's start the handshake */
  start_handshake(loop, conn, SSL_ERROR_WANT_READ);
}

int
main(int argc, char * const argv[]) {

  /* Servers configuration */
  struct server servers[] = {
    {  0,  0 },
    {  1,  0 },
    {  1,  1 },
    {  0,  1 },
    { -1, -1 }
  };

  int nb = sizeof(servers)/sizeof(struct server) - 1;

  start("Check arguments");
  if (argc != nb + 1)
    fail("Usage: %s ports\n"
	 "\n"
	 " Start a small web server listening on %d ports with\n"
	 " different SSL parameters on each port.", argv[0], nb);

  /* Initialize OpenSSL library */
  start("Initialize OpenSSL");
  signal(SIGPIPE, SIG_IGN);
  SSL_load_error_strings();
  SSL_library_init();

  /* Check libev version */
  start("Setup libev");
  if (ev_version_major() != EV_VERSION_MAJOR ||
      ev_version_minor() < EV_VERSION_MINOR)
    fail("libev version mismatch:\n%d.%d vs %d.%d",
	 ev_version_major(), ev_version_minor(),
	 EV_VERSION_MAJOR, EV_VERSION_MINOR);

  struct ev_loop *loop;
  loop = EV_DEFAULT;
  if (!loop)
    fail("Unable to setup the default event loop!");

  for (int i = 0; i < nb; i++) {
    servers[i].port = argv[i+1];
    servers[i].servers = servers;
    start("Setup server listening on %s %s cache and %s tickets",
	  servers[i].port,
	  servers[i].session_cache?"with":"without",
	  servers[i].accept_tickets?"with":"without");
    setup_socket(&servers[i]);
    setup_ssl(&servers[i]);
    ev_io_init(&servers[i].listener, handle_accept,
	       servers[i].socket, EV_READ);
    servers[i].listener.data = &servers[i];
    ev_io_start(loop, &servers[i].listener);
  }
  
  start("Start main loop and serve requests");
  ev_run(loop, 0);

  /* Free some stuff */
  for (int i = 0; i < nb; i++)
    SSL_CTX_free(servers[i].ctx);

  end(NULL);
  return 0;
}
