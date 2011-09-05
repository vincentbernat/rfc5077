Various tools for testing RFC 5077
----------------------------------

[RFC 5077](http://tools.ietf.org/html/rfc5077) is a session resumption
mechanism for TLS without server-side state. You'll find here various
tools related to testing availability of RFC 5077.

The following clients are implemented:

- `openssl-client`
- `gnutls-client`
- `nss-client`

They all take an host and a port as argument. You need to use `-r`
flag to really test reconnection. You can also add `-T` to disable
ticket supports (RFC 5077) and `-S` to disable session ID
support. However, disabling session ID may be difficult, therefore, it
may not really have the expected effect.

Only OpenSSL client is complete enough. GNU TLS does not allow easy
display of session contents and NSS does not allow to check if a
session was resumed.
