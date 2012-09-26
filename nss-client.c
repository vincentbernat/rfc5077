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

/* Simple client using NSS as backend. */

#include "common.h"

#include <unistd.h>
#include <prinit.h>
#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <secerr.h>
#include <sslerr.h>

/* For PR_ImportTCPSocket() */
#include <private/pprio.h>

/* See also:
   http://www.mail-archive.com/dev-tech-crypto@lists.mozilla.org/msg01208.html */

/* Convert error number to string. Copy from nss/cmd/lib/secutil.c */
static char *
SECU_ErrorString(int16 err) {
 switch (err) {
 case 0: return "No error";
 case SEC_ERROR_BAD_DATA: return "Bad data";
 case SEC_ERROR_BAD_DATABASE: return "Problem with database";
 case SEC_ERROR_BAD_DER: return "Problem with DER";
 case SEC_ERROR_BAD_KEY: return "Problem with key";
 case SEC_ERROR_BAD_PASSWORD: return "Incorrect password";
 case SEC_ERROR_BAD_SIGNATURE: return "Bad signature";
 case SEC_ERROR_EXPIRED_CERTIFICATE: return "Expired certificate";
 case SEC_ERROR_INPUT_LEN: return "Problem with input length";
 case SEC_ERROR_INVALID_ALGORITHM: return "Invalid algorithm";
 case SEC_ERROR_INVALID_ARGS: return "Invalid arguments";
 case SEC_ERROR_INVALID_AVA: return "Invalid AVA";
 case SEC_ERROR_INVALID_TIME: return "Invalid time";
 case SEC_ERROR_IO: return "Security I/O error";
 case SEC_ERROR_LIBRARY_FAILURE: return "Library failure";
 case SEC_ERROR_NO_MEMORY: return "Out of memory";
 case SEC_ERROR_OLD_CRL: return "CRL is older than the current one";
 case SEC_ERROR_OUTPUT_LEN: return "Problem with output length";
 case SEC_ERROR_UNKNOWN_ISSUER: return "Unknown issuer";
 case SEC_ERROR_UNTRUSTED_CERT: return "Untrusted certificate";
 case SEC_ERROR_UNTRUSTED_ISSUER: return "Untrusted issuer";
 case SSL_ERROR_BAD_CERTIFICATE: return "Bad certificate";
 case SSL_ERROR_BAD_CLIENT: return "Bad client";
 case SSL_ERROR_BAD_SERVER: return "Bad server";
 case SSL_ERROR_EXPORT_ONLY_SERVER: return "Export only server";
 case SSL_ERROR_NO_CERTIFICATE: return "No certificate";
 case SSL_ERROR_NO_CYPHER_OVERLAP: return "No cypher overlap";
 case SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE: return "Unsupported certificate type";
 case SSL_ERROR_UNSUPPORTED_VERSION: return "Unsupported version";
 case SSL_ERROR_US_ONLY_SERVER: return "U.S. only server";
 case PR_IO_ERROR: return "I/O error";
 case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE: return "Expired Issuer Certificate";
 case SEC_ERROR_REVOKED_CERTIFICATE: return "Revoked certificate";
 case SEC_ERROR_NO_KEY: return "No private key in database for this cert";
 case SEC_ERROR_CERT_NOT_VALID: return "Certificate is not valid";
 case SEC_ERROR_EXTENSION_NOT_FOUND: return "Certificate extension was not found";
 case SEC_ERROR_EXTENSION_VALUE_INVALID: return "Certificate extension value invalid";
 case SEC_ERROR_CA_CERT_INVALID: return "Issuer certificate is invalid";
 case SEC_ERROR_CERT_USAGES_INVALID: return "Certificate usages is invalid";
 case SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION: return "Certificate has unknown critical extension";
 case SEC_ERROR_PKCS7_BAD_SIGNATURE: return "Bad PKCS7 signature";
 case SEC_ERROR_INADEQUATE_KEY_USAGE: return "Certificate not approved for this operation";
 case SEC_ERROR_INADEQUATE_CERT_TYPE: return "Certificate not approved for this operation";
 default: return "Unknown error";
 }
}

static SECStatus
nss_auth_cert_hook(void *arg, PRFileDesc *fd, PRBool checksig,
		   PRBool isServer)
{
  /* Bypass */
  return SECSuccess;
}

int
connect_ssl(char *host, char *port,
	    int reconnect,
	    int use_sessionid, int use_ticket) {
  SECStatus        err;
  PRFileDesc      *tcpSocket, *sslSocket;
  int              s, n;
  char             buffer[256];
  struct addrinfo* addr;

  start("Initialize NSS library");
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
  if ((err = NSS_NoDB_Init(NULL)) != SECSuccess)
    fail("Unable to initialize NSS:\n%s", SECU_ErrorString(PR_GetError()));

  if (!use_ticket && !use_sessionid) {
    start("Disable tickets and session ID");
    if ((err = SSL_OptionSetDefault(SSL_NO_CACHE, PR_TRUE)) != SECSuccess)
      fail("Unable to disable cache mechanism:\n%s", SECU_ErrorString(PR_GetError()));
  }

  if (use_ticket) {
    start("Enable session tickets (RFC 5077)");
    if ((err = SSL_OptionSetDefault(SSL_ENABLE_SESSION_TICKETS, PR_TRUE)) != SECSuccess)
      fail("Unable to enable session tickets:\n%s", SECU_ErrorString(PR_GetError()));
  }

  start("Ask for US Domestic policy");
  if ((err = NSS_SetDomesticPolicy()) != SECSuccess)
    fail("Unable to configure US domestic policy:\n%s", SECU_ErrorString(PR_GetError()));

  addr = solve(host, port);
  do {
    s = connect_socket(addr, host, port);

    start("Setup sockets");
    if (!(tcpSocket = PR_ImportTCPSocket(s)))
      fail("Unable to convert socket:\n%s", SECU_ErrorString(PR_GetError()));
    if (!(sslSocket = SSL_ImportFD(NULL, tcpSocket)))
      fail("unable to enable SSL socket:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_OptionSet(sslSocket, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE)) != SECSuccess)
      fail("Unable to setup handshake mode:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_OptionSet(sslSocket, SSL_ENABLE_FDX, PR_TRUE)) != SECSuccess)
      fail("Unable to setup full duplex mode:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_SetURL(sslSocket, host)) != SECSuccess)
      fail("Unable to register target host:\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_AuthCertificateHook(sslSocket, nss_auth_cert_hook, NULL)) != SECSuccess)
      fail("Unable to register certificate check hook:\n%s", SECU_ErrorString(PR_GetError()));

    start("Start TLS renegotiation");
    if ((err = SSL_ResetHandshake(sslSocket, PR_FALSE)) != SECSuccess)
      fail("Unable to negociate TLS (1/2):\n%s", SECU_ErrorString(PR_GetError()));
    if ((err = SSL_ForceHandshake(sslSocket)) != SECSuccess)
      fail("Unable to negociate TLS (2/2):\n%s", SECU_ErrorString(PR_GetError()));

    /* TODO: session resume check */

    start("Send HTTP GET");
    n = snprintf(buffer, sizeof(buffer),
		 "GET / HTTP/1.0\r\n"
		 "Host: %s\r\n"
		 "\r\n", host);
    if (n == -1 || n >= sizeof(buffer))
      fail("Unable to build request to send");
    if ((err = PR_Write(sslSocket, buffer, n)) != n)
      fail("SSL write request failed:\n%s", SECU_ErrorString(PR_GetError()));

    start("Get HTTP answer");
    if ((n = PR_Read(sslSocket, buffer, sizeof(buffer) - 1)) <= 0)
      fail("SSL read request failed:\n%s", SECU_ErrorString(PR_GetError()));
    buffer[n] = '\0';
    if (strchr(buffer, '\r'))
      *strchr(buffer, '\r') = '\0';
    end("%s", buffer);

    start("End TLS connection");
    PR_Close(sslSocket);
  } while (reconnect--);
  SSL_ClearSessionCache();
  NSS_Shutdown();
  PR_Cleanup();
  return 0;
}

int
main(int argc, char * const argv[]) {
  return client(argc, argv, connect_ssl);
}
