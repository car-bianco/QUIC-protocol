#!/bin/bash
i=0
while [ $i -lt 20 ]
do
	dumpcap -i ifb0 -f "ip && !udp && !stp && not broadcast and not multicast && host 192.168.1.8 &&" -s 50 -w test2.pcapng & ./TCPServer
#only way to end capture
	sleep 10	
	kill $!
	sleep 1
	capinfos test2.pcapng -BT | cut -f 14 | cut -d ' ' -f 5 >> std2.txt
	rm test2.pcapng
	rm New2.pdf
	let i=i+1
	cat std2.txt
done
sleep 5
