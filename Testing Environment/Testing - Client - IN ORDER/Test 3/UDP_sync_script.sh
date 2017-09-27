#!/bin/bash
i=0
while [ $i -lt 1 ]
do
SEC=$(date +%M%S | cut -c 2-)
	while [ $SEC -ne "000" -a $SEC -ne "500" ]
	do
		sleep 0.001
		SEC=$(date +%M%S | cut -c 2-)
	done
	#sleep 3
	./UDPClient
	let i=i+1
done
sleep 15

