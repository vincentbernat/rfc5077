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
#include <stdint.h>
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
	    int use_sessionid, int use_ticket,
      int delay,
      const char *client_cert,
      const char *client_key,
      const char *opt_uri, const char *opt_method) {
  struct addrinfo* addr;
  int err, s;
  char buffer[256];
  gnutls_anon_client_credentials_t anoncred;
  gnutls_certificate_credentials_t xcred;
  gnutls_session_t                 session;
  char                            *session_data = NULL;
  size_t                           session_data_size = 0;
  char                            *session_id = NULL;
  size_t                           session_id_size = 0;
  char                            *session_id_hex = NULL;
  char                            *session_id_p = NULL;
  unsigned                         session_id_idx;
  const char                      *hex = "0123456789ABCDEF";

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
    if (client_cert == NULL) {
      if ((err = gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred)))
        fail("Unable to set anonymous credentials for session:\n%s",
	     gnutls_strerror(err));
    } else {
      if ((err = gnutls_certificate_set_x509_key_file(xcred, client_cert, client_key, GNUTLS_X509_FMT_PEM))) {
        fail("failed to load x509 certificate from file %s or key from %s: %s",client_cert,client_key,gnutls_strerror(err));
      }
    }
    if ((err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred)))
      fail("Unable to set credentials for session:\n%s",
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
    start("Start TLS renegotiation");
    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(uintptr_t)s);
    if ((err = gnutls_handshake(session))) {
      fail("Unable to start TLS renegotiation:\n%s",
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

      if ((err = gnutls_session_get_id( session, NULL, &session_id_size)))
         warn("No session id available:\n%s",
             gnutls_strerror(err));
      session_id = malloc(session_id_size);
      if (!session_id) fail("No memory available");
      else {
        if ((err = gnutls_session_get_id( session, session_id, &session_id_size)))
          warn("No session id available:\n%s",
            gnutls_strerror(err));
        session_id_hex = malloc(session_id_size * 2 + 1);
        if (!session_id_hex) fail("No memory available");
        else {
          for (session_id_p = session_id_hex, session_id_idx = 0;
               session_id_idx < session_id_size;
               ++session_id_idx) {
            *session_id_p++ = hex[ (session_id[session_id_idx] >> 4) & 0xf];
            *session_id_p++ = hex[ session_id[session_id_idx] & 0xf];
          }
          *session_id_p = '\0';

          end("Session context:\nProtocol : %s\nCipher : %s\nKx : %s\nPSK : %s\nID : %s",
            gnutls_protocol_get_name( gnutls_protocol_get_version(session) ),
            gnutls_cipher_get_name( gnutls_cipher_get(session) ),
            gnutls_kx_get_name( gnutls_kx_get(session) ),
            gnutls_psk_server_get_username(session),
            session_id_hex
            );
          free(session_id_hex);
        }
        free(session_id);
      }
        
    }
    if (!use_sessionid && !use_ticket) {
      free(session_data); session_data = NULL;
    }

    start("Send HTTP %s for %s",opt_method, opt_uri);
    err = snprintf(buffer, sizeof(buffer),
		   "%s %s HTTP/1.0\r\n"
		   "Host: %s:%s\r\n"
		   "\r\n", opt_method, opt_uri, host, port);
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
    --reconnect;
    if (reconnect < 0) break;
    else {
      start("waiting %d seconds",delay);
      sleep(delay);
    }
  } while (1);

  if (session_data) free(session_data);
  gnutls_anon_free_client_credentials(anoncred);
  gnutls_global_deinit();
  return 0;
}

int
main(int argc, char * const argv[]) {
  return client(argc, argv, connect_ssl);
}
