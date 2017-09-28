CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic tcp

quic: quicClient_new.c
	$(CC) $(CFLAGS) quicClient_new.c -o quicClient

tcp: TCPClient.c
	$(CC) $(CFLAGS) TCPClient.c -o TCPClient

clean:
	rm -rf quicClient TCPClient
