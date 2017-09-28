CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic tcp tcp2

quic: quicServer_new.c
	$(CC) $(CFLAGS) quicServer_new.c -o quicServer

tcp: TCPServer.c
	$(CC) $(CFLAGS) TCPServer.c -o TCPServer
	
tcp2: TCPServer2.c
	$(CC) $(CFLAGS) TCPServer2.c -o TCPServer2

clean:
	rm -rf quicServer TCPServer TCPServer2
