# QUIC kernel implementation

Code from Gaurav Suman's Master's thesis *Implementation and Performance Analysis of QUIC Protocol in Wireless Networks* (2016). 
Based on the Internet Draft draft-ietf-quic-transport-00 by IETF, only implemented for IPv4. Following files are changed/added to the Linux 3.13.11 kernel from Ubuntu 14.04 LTS:

## /net/ipv4/af_inet.c

The following lines are added to this file. They call a function in the */net/ipv4/quic.c* file which registers the QUIC protocol into the kernel. 

/* Add QUIC  */

*quic4_register();*
  
## /net/ipv4/quic.c

The bulk of the protocol implementation, encompassing
* Core send and receive functions
* Flow control
* Congestion control (taken from the TCP CUBIC implementation in the Linux kernel)

## /include/net/quic.h

Header file for the *quic.c* function, containing

* Definition of constants according to QUIC protocol drafts
* Definition of socket and socket buffer structure for QUIC
* Definition of some short help functions
* Declaration of kernel functions
