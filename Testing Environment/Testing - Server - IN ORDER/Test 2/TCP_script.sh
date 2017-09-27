#!/bin/bash
i=0
while [ $i -lt 20 ]
do
    let i=i+1
    echo "Test number $i"
	dumpcap -i ifb0 -f "ip && !udp && !stp && not broadcast and not multicast" -s 50 -w test1.pcapng & ./TCPServer
#only way to end capture
	sleep 10	
	kill $!
	sleep 1
	capinfos test1.pcapng -BT | cut -f 14 | cut -d ' ' -f 5 >> std1.txt
	rm test1.pcapng
	rm New.pdf
done
sleep 5
