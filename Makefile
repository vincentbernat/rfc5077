CFLAGS = -g -Werror -Wall -ansi -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS=
EVCFLAGS=$(shell pkg-config --silence-errors --cflags libev)
OPENSSL_LIBS=$(shell pkg-config --libs "openssl >= 1.1")
EXEC=rfc5077-client rfc5077-server rfc5077-pcap openssl-client gnutls-client nss-client 

all: $(EXEC)

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

rfc5077-server.o: rfc5077-server.c
	$(CC) $(CFLAGS) $(EVCFLAGS) -c -o $@ $^

rfc5077-client: rfc5077-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(OPENSSL_LIBS)
rfc5077-server: rfc5077-server.o common.o http-parser/libhttp_parser.a
	$(CC) -o $@ $^ $(LDFLAGS) -lev $(OPENSSL_LIBS)
http-parser/libhttp_parser.a: http-parser/http_parser.c
	$(MAKE) -C http-parser package

rfc5077-pcap: rfc5077-pcap.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell pcap-config --libs)

certificate: key.pem cert.pem dh.pem
key.pem:
	certtool --bits 2048 --generate-privkey --outfile $@
cert.pem: key.pem
	certtool --generate-self-signed --load-privkey $^ --outfile $@
dh.pem:
	certtool --bits 2048 --generate-dh-params --outfile $@
# for later gnutls utils
#	certtool --sec-param normal --generate-privkey --outfile $@
#	certtool --sec-param normal --generate-dh-params --outfile $@

clean:
	rm -f *.pem *.o $(EXEC)
	$(MAKE) -C http-parser clean

.PHONY: clean certificates all
