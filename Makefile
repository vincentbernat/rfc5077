CFLAGS=-g -Werror -Wall -ansi -std=c99 -D_POSIX_SOURCE -D_BSD_SOURCE
LDFLAGS=
EXEC=$(patsubst %.c,%,$(filter-out common-%,$(filter %-client.c %-server.c,$(wildcard *.c))))

all: $(EXEC)

openssl-client: openssl-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

gnutls-client: gnutls-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lgnutls

nss-client: nss-client.o common-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) $(shell nss-config --libs) $(shell nspr-config --libs)
nss-client.o: nss-client.c
	$(CC) $(CFLAGS) $(shell nss-config --cflags) $(shell nspr-config --cflags) -c -o $@ $^

rfc5077-client: rfc5077-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto
rfc5077-server: rfc5077-server.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

certificate: key.pem cert.pem dh.pem
key.pem:
	certtool --bits 1024 --generate-privkey --outfile $@
cert.pem: key.pem
	certtool --generate-self-signed --load-privkey $^ --outfile $@
dh.pem:
	certtool --bits 1024 --generate-dh-params --outfile $@

clean:
	rm -f *.pem *.o $(EXEC)

.PHONY: clean certificates all
