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

/* Common client functions */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Display usage for clients and exit */
static void
usage(char * const name) {
  fail("Usage: %s [-r] [-R {number}] [-d {secs}] [-S] [-T] [-C {client_cert}] [-K {client_key}] [-U URI ] [-M METHOD] host port\n"
       "\n"
       " Connect to an SSL HTTP server and requests `/'\n"
       "\n"
       "Options:\n"
       "\t-r: reconnect (may be repeated)\n"
       "\t-R: number of reconnects\n"
       "\t-d: delay between each renegotiation in seconds\n"
       "\t-S: disable support for session identifier\n"
       "\t-T: disable support for tickets\n"
       "\t-C: use a client certificate for the connection and this specifies a certificate as a file in PEM format. Optionally the key can be here too\n"
       "\t-K: use the key {client_key}, a PEM formated key file, in the connection\n"
       "\t-U: use a different URI\n"
       "\t-M: use a different method\n"
       , name);
}

/* Parse arguments and call back connect function */
int client(int argc, char * const argv[],
	   int (*connect)(char *, char *, int, int, int, int,
                    const char *, const char *, const char *,const char *)) {
  int   opt, status;
  int   reconnect     = 0;
  int   use_sessionid = 1;
  int   use_ticket    = 1;
  int   delay         = 0;
  char *host          = NULL;
  char *port          = NULL;
  const char *client_cert   = NULL;
  const char *client_key    = NULL;
  const char *opt_uri    = "/";
  const char *opt_method    = "GET";

  /* Parse arguments */
  opterr = 0;
  start("Parse arguments");
  while ((opt = getopt(argc, argv, "rR:d:STC:K:U:M:")) != -1) {
    switch (opt) {
    case 'r':
      reconnect++;
      break;
    case 'R':
      reconnect = atoi(optarg);
      break;
    case 'S':
      use_sessionid = 0;
      break;
    case 'T':
      use_ticket = 0;
      break;
    case 'd':
      delay = atoi(optarg);
      break;
    case 'C':
      client_cert = optarg;
      break;
    case 'K':
      client_key = optarg;
      break;
    case 'U':
      opt_uri = optarg;
      break;
    case 'M':
      opt_method = optarg;
      break;
    default:
      usage(argv[0]);
    }
  }
  if (client_key && !client_cert) {
    fail("a client key_file is specified without a client_certificate file. If both are in the same file use -C");
  }
  if (client_cert && !client_key) {
    client_key = client_cert;
  }
  if (optind != argc - 2)
    usage(argv[0]);

  host = argv[optind];
  port = argv[optind + 1];

  /* Callback */
  status = connect(host, port, reconnect, use_sessionid, use_ticket, delay, client_cert, client_key, opt_uri, opt_method);
  end(NULL);
  return status;
}

struct addrinfo *
solve(char *host, char *port) {
  int              err;
  char             name[INET6_ADDRSTRLEN];
  struct addrinfo  hints;
  struct addrinfo *result;

  start("Solve %s:%s", host, port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = 0;
  hints.ai_protocol = 0;
  if ((err = getaddrinfo(host, port, &hints, &result)) != 0)
    fail("Unable to solve ‘%s:%s’:\n%s", host, port, gai_strerror(err));

  if ((err = getnameinfo(result->ai_addr, result->ai_addrlen,
			 name, sizeof(name), NULL, 0,
			 NI_NUMERICHOST)) != 0)
    fail("Unable to format ‘%s:%s’:\n%s", host, port, gai_strerror(err));
  end("Will connect to %s", name);  
  return result;
}

int
connect_socket(struct addrinfo *result, char *host, char *port) {
  int s, err;
  start("Connect to %s:%s", host, port);
  if ((s = socket(result->ai_family,
		  result->ai_socktype,
		  result->ai_protocol)) == -1)
    fail("Unable to create socket:\n%m");

  if ((err = connect(s, result->ai_addr, result->ai_addrlen)) == -1)
    fail("Unable to connect to ‘%s:%s’:\n%m", host, port);

  return s;
}
