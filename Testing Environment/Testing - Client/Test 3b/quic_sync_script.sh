#!/bin/bash
i=0
while [ $i -lt 20 ]
do
    let i=i+1
    echo "Test number $i. Wait for synchronization..."
	#SEC=$(date +%S)
	SEC=$(date +%M%S | cut -c 2-)
	while [ $SEC -ne "000" -a $SEC -ne "500" ] 
	do
		sleep 0.001
		#SEC=$(date +%S)
		SEC=$(date +%M%S | cut -c 2-)
	done
	./quicClient
done
sleep 15
