CC=gcc
CFLAGS=-Wall
.PHONY=clean

all: quic quic2 tcp udp

client1: quic

client2: quic2 tcp udp

quic: quicClient_new.c
	$(CC) $(CFLAGS) quicClient_new.c -o quicClient
	
quic2: quicClient2_new.c
	$(CC) $(CFLAGS) quicClient2_new.c -o quicClient2

tcp: TCPClient.c
	$(CC) $(CFLAGS) TCPClient.c -o TCPClient
	
udp: UDPClient.c
    $(CC) $(CFLAGS) UDPClient.c -o UDPClient

clean:
	rm -rf quicClient quicClient2 TCPClient UDPClient
