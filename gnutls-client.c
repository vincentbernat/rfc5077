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

/* Simple client using GNU TLS as backend. */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <gnutls/gnutls.h>

#ifdef DEBUG
void
debug(int level, const char *s) {
  printf(s);
}
#endif

int
connect_ssl(char *host, char *port,
	    int reconnect,
	    int use_sessionid, int use_ticket) {
  struct addrinfo* addr;
  int err, s;
  char buffer[256];
  gnutls_anon_client_credentials_t anoncred;
  gnutls_certificate_credentials_t xcred;
  gnutls_session_t                 session;
  char                            *session_data = NULL;
  size_t                           session_data_size = 0;

  start("Initialize GNU TLS library");
  if ((err = gnutls_global_init()))
    fail("Unable to initialize GNU TLS:\n%s",
	 gnutls_strerror(err));
  if ((err = gnutls_anon_allocate_client_credentials(&anoncred)))
    fail("Unable to allocate anonymous client credentials:\n%s",
	 gnutls_strerror(err));
  if ((err = gnutls_certificate_allocate_credentials(&xcred)))
    fail("Unable to allocate X509 credentials:\n%s",
	 gnutls_strerror(err));

#ifdef DEBUG
  gnutls_global_set_log_function(debug);
  gnutls_global_set_log_level(10);
#endif

  addr = solve(host, port);
  do {
    start("Initialize TLS session");
    if ((err = gnutls_init(&session, GNUTLS_CLIENT)))
      fail("Unable to initialize the current session:\n%s",
	   gnutls_strerror(err));
    if ((err = gnutls_priority_set_direct(session, "PERFORMANCE:NORMAL:EXPORT", NULL)))
      fail("Unable to initialize cipher suites:\n%s",
	   gnutls_strerror(err));
    gnutls_dh_set_prime_bits(session, 512);
    if ((err = gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred)))
      fail("Unable to set anonymous credentials for session:\n%s",
	   gnutls_strerror(err));
    if ((err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred)))
      fail("Unable to set X509 credentials for session:\n%s",
	   gnutls_strerror(err));
    
    if (use_ticket) {
      start("Enable use of session tickets (RFC 5077)");
      if (gnutls_session_ticket_enable_client(session))
	fail("Unable to enable session tickets:\n%s",
	     gnutls_strerror(err));
    }

    if (session_data) {
      start("Copy old session");
      if ((err = gnutls_session_set_data(session, session_data, session_data_size)))
	fail("Unable to set session to previous one:\n%s",
	     gnutls_strerror(err));
    }

    s = connect_socket(addr, host, port);
    start("Start TLS negociation");
    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(uintptr_t)s);
    if ((err = gnutls_handshake(session))) {
      fail("Unable to start TLS negociation:\n%s",
	   gnutls_strerror(err));
    }

    start("Check if session was reused");
    if (!gnutls_session_is_resumed(session) && session_data)
      warn("No session was reused.");
    else if (gnutls_session_is_resumed(session) && !session_data)
      warn("Session was reused.");
    else if (gnutls_session_is_resumed(session))
      end("SSL session correctly reused");
    else
      end("SSL session was not used");

    start("Get current session");
    if (session_data) {
      free(session_data); session_data = NULL;
    }
    session_data_size = 8192;
    if ((err = gnutls_session_get_data(session, NULL, &session_data_size)))
      warn("No session available:\n%s",
	   gnutls_strerror(err));
    else {
      session_data = malloc(session_data_size);
      if (!session_data) fail("No memory available");
      gnutls_session_get_data(session, session_data, &session_data_size);
      /* TODO: display some details about session */
    }
    if (!use_sessionid && !use_ticket) {
      free(session_data); session_data = NULL;
    }

    start("Send HTTP GET");
    err = snprintf(buffer, sizeof(buffer),
		   "GET / HTTP/1.0\r\n"
		   "Host: %s\r\n"
		   "\r\n", host);
    if (err == -1 || err >= sizeof(buffer))
      fail("Unable to build request to send");
    if (gnutls_record_send(session, buffer, strlen(buffer)) < 0)
      fail("SSL write request failed:\n%s",
	   gnutls_strerror(err));

    start("Get HTTP answer");
    if ((err = gnutls_record_recv(session, buffer, sizeof(buffer) - 1)) <= 0)
      fail("SSL read request failed:\n%s",
	   gnutls_strerror(err));
    buffer[err] = '\0';
    if (strchr(buffer, '\r'))
      *strchr(buffer, '\r') = '\0';
    end("%s", buffer);

    start("End TLS connection");
    gnutls_bye(session, GNUTLS_SHUT_RDWR);
    close(s);
    gnutls_deinit (session);
  } while (reconnect--);

  if (session_data) free(session_data);
  gnutls_anon_free_client_credentials(anoncred);
  gnutls_global_deinit();
  return 0;
}

int
main(int argc, char * const argv[]) {
  return client(argc, argv, connect_ssl);
}
