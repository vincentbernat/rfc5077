CFLAGS=-g -Werror -Wall -ansi -std=c99 -D_POSIX_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE $(shell pkg-config --cflags libev)
LDFLAGS=
OPENSSL_LIBS=$(shell pkg-config --libs openssl)
EXEC=rfc5077-client rfc5077-server rfc5077-pcap openssl-client gnutls-client nss-client 

all:
	for e in $(EXEC); do \
		echo "******* Build $$e" ; \
		$(MAKE) $$e || echo "!!!!!!!! Build of $$e failed" ; \
	done

openssl-client.o: openssl-client.c
	$(CC) $(CFLAGS) $(shell pkg-config --cflags openssl) -c -o $@ $^

openssl-client: openssl-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(OPENSSL_LIBS)

gnutls-client: gnutls-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lgnutls

nss-client: nss-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell nss-config --libs) $(shell nspr-config --libs)
nss-client.o: nss-client.c
	$(CC) $(CFLAGS) $(shell nss-config --cflags) $(shell nspr-config --cflags) -c -o $@ $^

rfc5077-client: rfc5077-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(OPENSSL_LIBS)
rfc5077-server: rfc5077-server.o common.o http-parser/libhttp_parser.a
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pkg-config --libs libev) $(OPENSSL_LIBS)
http-parser/libhttp_parser.a: http-parser/http_parser.c
	$(MAKE) -C http-parser package

rfc5077-pcap: rfc5077-pcap.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pcap-config --libs)

certificate: key.pem cert.pem dh.pem
key.pem:
	certtool --bits 1024 --generate-privkey --outfile $@
cert.pem: key.pem
	certtool --generate-self-signed --load-privkey $^ --outfile $@
dh.pem:
	certtool --bits 1024 --generate-dh-params --outfile $@

clean:
	rm -f *.pem *.o $(EXEC)
	$(MAKE) -C http-parser clean

.PHONY: clean certificates all
