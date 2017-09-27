# QUIC-protocol
This repository contains an implementation of the QUIC protocol in the Linux kernel by Gaurav Suman, as well as shell scripts for testing in a wireless setup.


# Kernel Files

The following files are added to the Linux 3.13.11 kernel used in Ubuntu 14.04 LTS:
* /net/ipv4/quic.c
* /net/ipv4/af_inet.c (modified to recognize the QUIC protocol)
* /include/net/quic.h

# Testing environment

The folder containes the following subfolders:

* *Kernel Installation Files*: Already compiled version of the kernel with all the modules needed for testing
* *Testing - Client*: Client files for each test
* *Testing - Server*: Server files for each test
as well as the *install_wireshark.sh* script to install and activate Wireshark.
