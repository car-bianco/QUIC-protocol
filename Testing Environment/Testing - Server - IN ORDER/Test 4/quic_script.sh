#!/bin/bash
i=0
while [ $i -lt 20 ]
do
#only capture first 50 bytes of each packet - fully enough for calculating throughput
#and it isn't too demanding for the server memory
    let i=i+1
    echo "Test number $i"
	dumpcap -i ifb0 -f "ip && !udp && !stp && not broadcast and not multicast && host 192.168.1.20" -s 50 -w test1.pcapng & ./quicServer
#only way to end capture
	kill $!
	sleep 1
	capinfos test1.pcapng -BT | cut -f 14 | cut -d ' ' -f 5 >> std.txt
	rm test1.pcapng
	rm New.pdf
	#cat std.txt
done
sleep 5
