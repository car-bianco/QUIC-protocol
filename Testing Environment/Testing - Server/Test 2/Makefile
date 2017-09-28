CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic tcp

quic: quicServer_new.c
	$(CC) $(CFLAGS) quicServer_new.c -o quicServer

tcp: TCPServer.c
	$(CC) $(CFLAGS) TCPServer.c -o TCPServer

clean:
	rm -rf quicServer TCPServer
