CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic quic2 tcp udp

quic: quicServer_new.c
	$(CC) $(CFLAGS) quicServer_new.c -o quicServer
	
quic2: quicServer2_new.c
	$(CC) $(CFLAGS) quicServer2_new.c -o quicServer2

tcp: TCPServer.c
	$(CC) $(CFLAGS) TCPServer.c -o TCPServer
	
udp: UDPServer.c
	$(CC) $(CFLAGS) UDPServer.c -o UDPServer

clean:
	rm -rf quicServer quicServer2 TCPServer UDPServer
