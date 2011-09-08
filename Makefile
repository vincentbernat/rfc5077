CFLAGS=-g -Werror -Wall -ansi -std=c99 -D_POSIX_SOURCE -D_BSD_SOURCE
LDFLAGS=
EXEC=openssl-client gnutls-client nss-client rfc5077-client

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

clean:
	rm -f *.o $(EXEC)

