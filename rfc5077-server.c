/* RFC 5077 server test */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <curl/curl.h>

#include "common.h"

#define PEM_CERTIFICATE "cert.pem"
#define PEM_KEY         "key.pem"
#define PEM_DH          "dh.pem"

/* Params for AWS. User with append-only rights. */
#define AWS_KEY "AKIAIDFV7UUQKJBXU6CQ"
#define AWS_SAK "dJpFoH4QzU9Slhw9nZHiYBYTcgkVs7RicIdI+WZB"
#define AWS_SDB "rfc5077"

/* Server state */
struct server {
  int session_cache;		/* Setup a session cache? */
  int accept_tickets;		/* Accept tickets? */
  /* State */
  char    *port;	       /* Port we should listen to */
  int      socket;	       /* Socket the server is listening to */
  SSL_CTX *ctx;		       /* SSL context */
};

/* Make a listening socket */
void
setup_socket(struct server *server) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;	/* IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;	/* For wildcard IP address */

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
    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == -1)
      fail("Unable to bind to ‘%s‘:\n%m", server->port);

    break;
  }

  /* Then, listen */
  if (listen(sfd, 5) == -1)
    fail("Unable to listen to ‘%s‘:\n%m", server->port);

  server->socket = sfd;
  freeaddrinfo(result);
}

/* Setup SSL context for each server */
void
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

struct request {
  char *method;			/* Action requested */
  char *path;			/* Path requested */
  char *callback;		/* Callback param (other params are discarded) */
  char *ua;			/* User agent */
  char *protocol;		/* Protocol */
};

/* Parse HTTP request and return the queried path.  That's not really
   a full featured HTTP parser. We try to keep the number of lines
   minimal. The request is statically returned. */
struct request *
parse_http(BIO *bio) {
  static struct request request = { NULL, NULL, NULL };
  static char *methods[] = { "OPTIONS",
			     "GET",
			     "HEAD",
			     "POST",
			     "PUT",
			     "DELETE",
			     "TRACE",
			     "CONNECT",
			     NULL };
  char **method;
  int    p;
  char  *p2, *p3;

  if (request.path) free(request.path);
  if (request.callback) free(request.callback);
  if (request.ua) free(request.ua);
  if (request.protocol) free(request.protocol);
  memset(&request, 0, sizeof(request));

  char line[1024];
  int  n;

  /* Grab a line */
  n = BIO_gets(bio, line, sizeof(line));
  if (n <= 0 || n >= sizeof(line)) return NULL;
  while ((line[n-1] == '\n') || (line[n-1] == '\r')) {
    line[--n] = '\0';
    if (n <= 0) return NULL;
  }

  /* Parse method */
  for (method = methods; *method; method++)
    if (!strncmp(line, *method, strlen(*method))) break;
  if (!*method) return NULL;
  request.method = *method;

  /* Spaces */
  p = strlen(request.method);
  while (line[p] == ' ' && p++ < n);
  if (line[p] == ' ' ||
      p == strlen(request.method)) return NULL; /* No space */

  /* Parse path */
  if ((p2 = strchr(line + p, ' ')) == NULL) return NULL; /* No protocol */
  request.path = strdup(line + p);
  request.path[p2 - line - p] = '\0';
  p = p2 - line;

  /* Now, we need to remove arguments from path. */
  p2 = strchr(request.path, '?');
  if (p2) {
    *p2 = '\0';
    p2++;
    /* And we want to keep callback. We assume it is just here */
    if (!strncmp(p2, "callback=", 9)) {
      request.callback = strdup(p2 + 9);
      p3 = strchr(request.callback, '&');	/* Hope this is not &amp; */
      if (p3) *p3 = '\0';
    }
  }

  /* Spaces */
  p2 = p + line;
  while (line[p] == ' ' && p++ < n);
  if (line[p] == ' ' ||
      p == p2 - line) return NULL; /* No space */

  /* Protocol */
  if (strcmp(line + p, "HTTP/1.0") &&
      strcmp(line + p, "HTTP/1.1")) return NULL;
  request.protocol = strdup(line + p);
  
  /* Headers, just grab user-agent */
  while (1) {
    n = BIO_gets(bio, line, sizeof(line));
    if (n <= 0 || n >= sizeof(line)) return NULL;
    while ((line[n-1] == '\n') || (line[n-1] == '\r')) {
      line[--n] = '\0';
      if (n < 0) return NULL;
      if (n == 0) return &request;
    }
    if (strncasecmp("user-agent: ", line, 12)) continue;
    if (!request.ua)
      request.ua = strdup(line + 12);
  }

  return &request;		/* Should not be there */
}

/* Serve a static file */
int hserve(BIO *bio, char *file, char* mime) {
  int   n;
  char  buffer[1024];
  BIO  *ibio = BIO_new(BIO_s_file());
  if (BIO_read_filename(ibio, file) != 1) {
    BIO_puts(bio, "HTTP/1.0 404 Resource not found\r\n");
    BIO_puts(bio, "Content-Type: text/html\r\n");
    BIO_puts(bio, "\r\n");
    BIO_printf(bio, "<h1>Index file \"%s\" was not found.</h1>\r\n",
	       file);
    BIO_free(ibio);
    return 404;
  }
  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  BIO_printf(bio, "Content-Type: %s\r\n", mime);
  BIO_puts(bio, "\r\n");
  while ((n = BIO_read(ibio, buffer, sizeof(buffer))) > 0)
    BIO_write(bio, buffer, n);
  /* Don't handle n < 0 */
  return 200;
}

/* Handler: return index page */
int
hindex(struct server servers[], struct server *server,
       struct request *request,
       BIO *bio, SSL *ssl) {
  return hserve(bio, "rfc5077-server.html", "text/html");
}

/* Handler: return JS */
int
hjs(struct server servers[], struct server *server,
    struct request *request,
    BIO *bio, SSL *ssl) {
  return hserve(bio, "rfc5077-server.js", "application/javascript");
}

/* handler: flush sessions */
int
hflush(struct server servers[], struct server *server,
       struct request *request,
       BIO *bio, SSL *ssl) {
  /* This handler does not really seems to work... */
  SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
  SSL_CTX_flush_sessions(ctx, -1);
  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  if (request->callback)
    BIO_puts(bio, "Content-Type: application/javascript\r\n");
  else
    BIO_puts(bio, "Content-Type: application/json\r\n");
  BIO_puts(bio, "\r\n");
  BIO_printf(bio, "%s%s{ status: 1, message: 'Cache flushed' }%s",
	     request->callback?request->callback:"",
	     request->callback?"(":"",
	     request->callback?");":"");
  return 200;
}

/* handler: return params */
int
hparams(struct server servers[], struct server *server,
	struct request *request,
	BIO *bio, SSL *ssl) {
  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  if (request->callback)
    BIO_puts(bio, "Content-Type: application/javascript\r\n");
  else
    BIO_puts(bio, "Content-Type: application/json\r\n");
  BIO_puts(bio, "\r\n");
  BIO_printf(bio, "%s%s{ status: 1, cache: %s, tickets: %s }%s\r\n",
	     request->callback?request->callback:"",
	     request->callback?"(":"",
	     server->session_cache?"true":"false",
	     server->accept_tickets?"true":"false",
	     request->callback?");":"");
  return 200;
}

/* handler: return servers */
int
hservers(struct server servers[], struct server *server,
	 struct request *request,
	 BIO *bio, SSL *ssl) {
  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  if (request->callback)
    BIO_puts(bio, "Content-Type: application/javascript\r\n");
  else
    BIO_puts(bio, "Content-Type: application/json\r\n");
  BIO_puts(bio, "\r\n");
  BIO_printf(bio, "%s%s{ status: 1, servers: [",
	     request->callback?request->callback:"",
	     request->callback?"(":"");
  for (server = servers; server->session_cache != -1;) {
    BIO_printf(bio, "'%s'", server->port);
    server++;
    if (server->session_cache != -1)
      BIO_puts(bio, ", ");
  }
  BIO_puts(bio, "] }");
  if (request->callback) BIO_puts(bio, ");");
  BIO_puts(bio, "\r\n");
  return 200;
}

/* handler: grab current session parameters */
int
hsession(struct server servers[], struct server *server,
	 struct request *request,
	 BIO *bio, SSL *ssl) {
  int          i;
  SSL_SESSION *x = SSL_get_session(ssl);

  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  if (request->callback)
    BIO_puts(bio, "Content-Type: application/javascript\r\n");
  else
    BIO_puts(bio, "Content-Type: application/json\r\n");
  BIO_puts(bio, "\r\n");
  BIO_printf(bio, "%s%s{ status: 1,\r\n",
	     request->callback?request->callback:"",
	     request->callback?"(":"");

  /* Display version */
  BIO_puts(bio, "  version: '");
  if (x->ssl_version == SSL2_VERSION)
    BIO_puts(bio, "SSLv2");	/* Should not be possible */
  else if (x->ssl_version == SSL3_VERSION)
    BIO_puts(bio, "SSLv3");
  else if (x->ssl_version == TLS1_VERSION)
    BIO_puts(bio, "TLSv1");
  else
    BIO_puts(bio, "unknown");
  BIO_puts(bio, "',\r\n");

  /* Cipher */
  BIO_puts(bio, "  cipher: '");
  BIO_puts(bio, x->cipher?x->cipher->name:"unknown");
  BIO_puts(bio, "',\r\n");

  /* Session stuff */
  BIO_puts(bio, "  sessionid: '");
  for (i = 0; i < x->session_id_length; i++)
    BIO_printf(bio, "%02X", x->session_id[i]);
  BIO_puts(bio, "',\r\n");
  BIO_puts(bio, "  masterkey: '");
  for (i = 0; i < x->master_key_length; i++)
    BIO_printf(bio, "%02X", x->master_key[i]);
  BIO_puts(bio, "',\r\n");
  BIO_puts(bio, "  ticket: '");
  for (i = 0; i < x->tlsext_ticklen; i++)
    BIO_printf(bio, "%02X", x->tlsext_tick[i]);
  BIO_puts(bio, "' }");
  if (request->callback) BIO_puts(bio, ");");
  BIO_puts(bio, "\r\n");

  return 200;
}

/* Save to AWS */
static size_t
trash(void *contents, size_t size, size_t nmemb, void *userp) {
  return size * nmemb;
}

int
hsave(struct request *request, BIO *bio, SSL *ssl,
      int wotickets, int wtickets) {
  char         req[2048];
  char         url[2048];
  int          n;
  SSL_SESSION *x = SSL_get_session(ssl);

  CURL        *curl = NULL;
  char        *ua = NULL;
  char        *cipher = NULL;
  char        *sig = NULL;
  char        *ts = NULL;

  start("Try to send data to Amazon SimpleDB");

  /* Initialize cURL */
  curl_version_info_data *cversion = curl_version_info(CURLVERSION_NOW);
  if (!(cversion->features & CURL_VERSION_SSL)) {
    warn("cURL is not compiled with SSL support. Can't do more.");
    goto cleanup;
  }
  if (!(curl = curl_easy_init())) {
    warn("Not able to initialize cURL.");
    goto cleanup;
  }

  /* Encode some params (assume that this can't fail) */
  ua     = curl_easy_escape(curl, request->ua, 0);
  cipher = curl_easy_escape(curl,
			    x->cipher?x->cipher->name:"unknown",
			    0);

  /* Build request that should be signed */
  char       timestamp[100];
  time_t     now = time(NULL);
  struct tm *tmp = gmtime(&now);
  strftime(timestamp, sizeof(timestamp),
	   "%FT%TZ", tmp);
  ts = curl_easy_escape(curl, timestamp, 0);
  n = snprintf(req, sizeof(req),
	       "AWSAccessKeyId=" AWS_KEY
	       "&Action=PutAttributes"
	       "&Attribute.1.Name=UserAgent"
	       "&Attribute.1.Value=%s"
	       "&Attribute.2.Name=Cipher"
	       "&Attribute.2.Value=%s"
	       "&Attribute.3.Name=WithoutTickets"
	       "&Attribute.3.Value=%d"
	       "&Attribute.4.Name=WithTickets"
	       "&Attribute.4.Value=%d"
	       "&DomainName=" AWS_SDB
	       "&ItemName=%lu"
	       "&SignatureMethod=HmacSHA256"
	       "&SignatureVersion=2"
	       "&Timestamp=%s"
	       "&Version=2009-04-15",
	       ua,
	       cipher,
	       wotickets, wtickets,
	       now,  /* We may get a collision, but we don't bother */
	       ts);
  if (n == -1 || n >= sizeof(req)) {
    warn("Not able to build AWS request (too long).");
    goto cleanup;
  }

  /* I would have loved to use BIO_f_md() and BIO_f_base64() but I did
   * not find how to plug everything together to do HMAC with
   * BIO_f_md(). Mail me if you know something about this. */

  /* TODO: do we need error checking here? */

  /* Let's sign the request */
  HMAC_CTX  hmac_ctx;
  HMAC_CTX_init(&hmac_ctx);
  HMAC_Init(&hmac_ctx, AWS_SAK, strlen(AWS_SAK), EVP_sha256());
  HMAC_Update(&hmac_ctx,
	      (const unsigned char *)"GET\nsdb.amazonaws.com\n/\n",
	      strlen("GET\nsdb.amazonaws.com\n/\n"));
  HMAC_Update(&hmac_ctx, (const unsigned char *)req,
	      strlen(req));
  unsigned char hresult[HMAC_MAX_MD_CBLOCK];
  unsigned int len = sizeof(hresult);
  HMAC_Final(&hmac_ctx, hresult, &len);
  HMAC_CTX_cleanup(&hmac_ctx);

  /* Encode it using base64 */
  unsigned char signature[HMAC_MAX_MD_CBLOCK*2];
  int  olen, tlen = 0;
  EVP_ENCODE_CTX ectx;
  EVP_EncodeInit(&ectx);
  EVP_EncodeUpdate(&ectx, signature, &olen, hresult, len);
  tlen = olen;
  EVP_EncodeFinal(&ectx, signature + tlen, &olen);
  tlen += olen;
  signature[tlen-1] = '\0';	/* It is ended by a new line. Why? */

  /* OK, let's build the HTTP request */
  sig = curl_easy_escape(curl, (char *)signature, 0);
  n = snprintf(url, sizeof(url),
	       "https://sdb.amazonaws.com/?%s"
	       "&Signature=%s", req, sig);
  if (n == -1 || n >= sizeof(url)) {
    warn("Not able to build AWS request (too long).");
    goto cleanup;
  }
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, trash);
  if (curl_easy_perform(curl) != 0)
    warn("There was a problem with AWS request to SimpleDB.\n"
	 "Good luck to find why. ;-)");

 cleanup:
  if (ts) curl_free(ts);
  if (sig) curl_free(sig);
  if (ua) curl_free(ua);
  if (cipher) curl_free(cipher);
  if (curl) curl_easy_cleanup(curl);

  /* Even if it fails, build a success answer. */
  BIO_puts(bio, "HTTP/1.0 200 OK\r\n");
  if (request->callback)
    BIO_puts(bio, "Content-Type: application/javascript\r\n");
  else
    BIO_puts(bio, "Content-Type: application/json\r\n");
  BIO_puts(bio, "\r\n");
  BIO_printf(bio, "%s%s{ status: 1, message: 'Thanks for your support' }%s\r\n",
	     request->callback?request->callback:"",
	     request->callback?"(":"",
	     request->callback?");":"");
  return 200;
}

#define HSAVE(x,y)							\
  int									\
  hsave ## x ## y (struct server servers[], struct server *server,	\
		   struct request *request, BIO *bio, SSL *ssl) {	\
    return hsave(request, bio, ssl, x, y);				\
  }
HSAVE(0, 0)
HSAVE(0, 1)
HSAVE(1, 1)
HSAVE(1, 0)

struct handler {
  char *path;			/* Path handled */
  int (*h)(struct server [], struct server *,
	   struct request *,
	   BIO *, SSL *);	/* Handler return error code */
};

void
handle(struct server *server, struct server servers[]) {
  int s, err;
  struct sockaddr_storage addr;
  socklen_t               addrlen = sizeof(struct sockaddr_storage);
  char                    client[INET6_ADDRSTRLEN];
  SSL*                    ssl = NULL;
  BIO                    *bbio = NULL, *sbio = NULL;
  int                     code = 0;

  /* Accept the connection */
  if ((s = accept(server->socket,
		  (struct sockaddr *)&addr, &addrlen)) == -1) {
    warn("Unable to accept():\n%m");
    return;
  }
  
  /* Grab IP address of the client */
  if ((err = getnameinfo((struct sockaddr *)&addr, addrlen,
			 client, sizeof(client), NULL, 0,
			 NI_NUMERICHOST)) != 0) {
    warn("Unable to get format client address:\n%s",
	 gai_strerror(err));
    goto err;
  }

  /* SSL handshake */
  if (!(ssl = SSL_new(server->ctx))) {
    warn("Unable to setup SSL structure:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  SSL_set_fd(ssl, s);
  if ((err = SSL_accept(ssl)) <= 0) {
    if (SSL_get_error(ssl, err) == SSL_ERROR_SYSCALL) {
      /* TODO: There is something here with False Start. Just ignore
       * the problem. */
      if (!errno) goto err;
      warn("Unable to perform handshake with %s:\n%m",
	   client);
    } else
      warn("Unable to perform handshake with %s:\n%s",
	   client, ERR_error_string(ERR_get_error(), NULL));
    goto err;
  }

  /* Turn the connection into a BIO */
  bbio = BIO_new(BIO_f_buffer());
  sbio = BIO_new(BIO_f_ssl());
  BIO_set_ssl(sbio, ssl, BIO_CLOSE);
  sbio = BIO_push(bbio, sbio);

  /* OK, read the request. */
  struct request *request = parse_http(sbio);
  if (!request) {
    warn("Invalid HTTP request received from %s", client);
    goto err;
  }
  if (strcmp(request->method, "GET")) {
    code = 405;
    BIO_puts(sbio, "HTTP/1.0 405 Action not allowed\r\n\r\n");
    goto err;
  }

  /* Find the appropriate handler */
  struct handler *h;
  struct handler          handlers[] = {
    { "/", hindex },
    { "/rfc5077-server.js", hjs },
    { "/flush", hflush },
    { "/session", hsession },
    { "/params", hparams },
    { "/servers", hservers },
    /* Save to AWS SimpleDB */
    { "/save-0-0", hsave00 },
    { "/save-1-0", hsave10 },
    { "/save-1-1", hsave11 },
    { "/save-0-1", hsave01 },
    { NULL }
  };

  for (h = handlers; h->path; h++) {
    if (!strcmp(h->path, request->path)) {
      code = h->h(servers, server, request, sbio, ssl);
      break;
    }
  }
  if (!h->path) {
    code = 404;
    BIO_puts(sbio, "HTTP/1.0 404 Not found\r\n");
    BIO_puts(sbio, "Content-Type: text/html\r\n");
    BIO_puts(sbio, "\r\n");
    BIO_puts(sbio, "<h1>404: Resource not found</h1>\r\n");
  }
  
 err:
  if (code) {
    if (code != 200) 
      warn("%s %lu \"%s %s %s\" %d \"%s\"",
	   client, time(NULL),
	   request->method, request->path, request->protocol,
	   code, request->ua?request->ua:"");
    else
      end("%s %lu \"%s %s%s%s %s\" %d \"%s\"",
	  client, time(NULL),
	  request->method, request->path,
	  request->callback?"?callback=":"",
	  request->callback?request->callback:"",
	  request->protocol,
	  code, request->ua?request->ua:"");
  }
  if (sbio) {
    (void)BIO_flush(sbio);
    BIO_free_all(sbio);
  } else if(ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  close(s);
}

int
main(int argc, char * const argv[]) {

  struct server servers[] = {
    { 0, 0 },
    { 1, 0 },
    { 1, 1 },
    { 0, 1 },
    { -1, -1 }
  };

  int nb = sizeof(servers)/sizeof(struct server) - 1;

  start("Check arguments");
  if (argc != nb + 1)
    fail("Usage: %s ports\n"
	 "\n"
	 " Start a small web server listening on %d ports with\n"
	 " different session parameters on each port.", argv[0], nb);

  /* Initialize OpenSSL library */
  SSL_load_error_strings();
  SSL_library_init();
  /* And cURL */
  if (curl_global_init(CURL_GLOBAL_NOTHING) != 0)
    fail("Unable to initialize cURL");

  /* Setup each configuration */
  for (int i = 0; i < nb; i++) {
    servers[i].port = argv[i+1];
    start("Setup server listening on %s %s cache and %s tickets",
	  servers[i].port,
	  servers[i].session_cache?"with":"without",
	  servers[i].accept_tickets?"with":"without");
    setup_socket(&servers[i]);
    setup_ssl(&servers[i]);
  }

  /* Wait for a connection on one of the socket */
  fd_set rfds;
  int    n, max;
  while (1) {
    start("Wait for a connection");
    max = 0;
    FD_ZERO(&rfds);
    for (int i = 0; i < nb; i++) {
      FD_SET(servers[i].socket, &rfds);
      max = (servers[i].socket > max)?servers[i].socket:max;
    }
    n = select(max+1, &rfds, NULL, NULL, NULL);
    if (n <= 0) {
      warn("Error in select():\n%m");
      sleep(1);
      continue;
    }
    for (int i = 0; i < nb; i++) {
      if (!FD_ISSET(servers[i].socket, &rfds)) continue;
      handle(&servers[i], servers);
    }
  }

  /* Free some stuff */
  for (int i = 0; i < nb; i++)
    SSL_CTX_free(servers[i].ctx);

  end(NULL);
  curl_global_cleanup();
  return 0;
}
