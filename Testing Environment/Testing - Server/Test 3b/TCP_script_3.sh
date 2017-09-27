#!/bin/bash
i=0
while [ $i -lt 20 ]
do
	dumpcap -i ifb0 -f "ip && !udp && !stp && not broadcast and not multicast && host 192.168.1.8 && tcp port 5421" -s 50 -w test3.pcapng & ./TCPServer2
#only way to end capture
	sleep 10	
	kill $!
	sleep 1
	capinfos test3.pcapng -BT | cut -f 14 | cut -d ' ' -f 5 >> std3.txt
	rm test3.pcapng
	rm New3.pdf
	let i=i+1
	cat std3.txt
done
sleep 5
