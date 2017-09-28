CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic tcp tcp2

client1: quic

client2: tcp tcp2

quic: quicClient_new.c
	$(CC) $(CFLAGS) quicClient_new.c -o quicClient

tcp: TCPClient.c
	$(CC) $(CFLAGS) TCPClient.c -o TCPClient
	
tcp2: TCPClient2.c
    $(CC) $(CFLAGS) TCPClient2.c -o TCPClient2

clean:
	rm -rf quicClient TCPClient TCPClient2
