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

/* Simple client using OpenSSL as backend. */

#include "common.h"

#include <unistd.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int
connect_ssl(char *host, char *port,
	    int reconnect,
	    int use_sessionid, int use_ticket,
      int delay,
      const char *client_cert, const char *client_key,
      const char *opt_uri, const char *opt_method) {
  SSL_CTX*         ctx;
  SSL*             ssl;
  SSL_SESSION*     ssl_session = NULL;
  int              s, n;
  char             buffer[256];
  struct addrinfo* addr;
  int stat_reused=0;
  int stat_notreused=0;

  start("Initialize OpenSSL library");
  SSL_load_error_strings();
  SSL_library_init();
  if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  if (client_cert || client_key) {
    if (SSL_CTX_use_certificate_chain_file(ctx,client_cert)==0) {
      fail("failed to read X509 certificate from file %s into PEM format",client_key);
    }
  }
  if (client_key) {
    if (SSL_CTX_use_PrivateKey_file(ctx,client_key,SSL_FILETYPE_PEM)==0) {
      fail("failed to read private key from file %s into PEM format",client_key);
    }
  }
  if (!use_ticket) {
    start("Disable use of session tickets (RFC 5077)");
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
  }

  addr = solve(host, port);
  do {
    s = connect_socket(addr, host, port);
    start("Start TLS renegotiation");
    if ((ssl = SSL_new(ctx)) == NULL)
      fail("Unable to create new SSL struct:\n%s",
	   ERR_error_string(ERR_get_error(), NULL));
    SSL_set_fd(ssl, s);
    if (ssl_session) {
      if (!SSL_set_session(ssl, ssl_session)) {
	fail("Unable to set session to previous one:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
      }
    }
    if (SSL_connect(ssl) != 1)
      fail("Unable to start TLS renegotiation:\n%s",
	   ERR_error_string(ERR_get_error(), NULL));

    start("Check if session was reused");
    if (!SSL_session_reused(ssl) && ssl_session)
      warn("No session was reused.");
    else if (SSL_session_reused(ssl) && !ssl_session) {
      warn("Session was reused.");
      stat_notreused++;
    }
    else if (SSL_session_reused(ssl)) {
      end("SSL session correctly reused");
      stat_reused++;
    }
    else
      end("SSL session was not used");
    start("Get current session");
    if (ssl_session) {
      SSL_SESSION_free(ssl_session);
      ssl_session = NULL;
    }
    if (!(ssl_session = SSL_get1_session(ssl)))
      warn("No session available");
    else {
      BIO *mem = BIO_new(BIO_s_mem());
      char *buf;
      if (SSL_SESSION_print(mem, ssl_session) != 1)
	fail("Unable to print session:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
      n = BIO_get_mem_data(mem, &buf);
      buf[n-1] = '\0';
      end("Session content:\n%s", buf);
      BIO_free(mem);
    }
    if ((!use_sessionid && !use_ticket) ||
	(!use_sessionid && !SSL_SESSION_has_ticket(ssl_session))) {
      SSL_SESSION_free(ssl_session);
      ssl_session = NULL;
    }

    start("Send HTTP %s for %s",opt_method, opt_uri);
    n = snprintf(buffer, sizeof(buffer),
		 "%s %s HTTP/1.0\r\n"
		 "Host: %s:%s\r\n"
		 "\r\n", opt_method, opt_uri,host, port);
    if (n == -1 || n >= sizeof(buffer))
      fail("Unable to build request to send");
    if (SSL_write(ssl, buffer, strlen(buffer)) != strlen(buffer))
      fail("SSL write request failed:\n%s",
	   ERR_error_string(ERR_get_error(), NULL));

    start("Get HTTP answer");
    if ((n = SSL_read(ssl, buffer, sizeof(buffer) - 1)) <= 0)
      fail("SSL read request failed:\n%s",
	   ERR_error_string(ERR_get_error(), NULL));
    buffer[n] = '\0';
    if (strchr(buffer, '\r'))
      *strchr(buffer, '\r') = '\0';
    end("%s", buffer);

    start("End TLS connection");
    SSL_shutdown(ssl);
    close(s);
    SSL_free(ssl);
    --reconnect;
    if (reconnect < 0) break;
    else {         
      start("waiting %d seconds",delay);
      sleep(delay);
    }
  } while (1);

  start("STAT: reused: %d notreused: %d", stat_reused, stat_notreused);
  SSL_CTX_free(ctx);
  if ( stat_notreused > 0 ) 
	return 1;
  return 0;
}

int
main(int argc, char * const argv[]) {
  return client(argc, argv, connect_ssl);
}
