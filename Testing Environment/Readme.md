# HOW TO INSTALL THE KERNEL

The kernel build in the *Kernel installation files* folder is a modified version of the 14.04 Ubuntu kernel already complete with the modules needed for QUIC testing in our environment. It can be installed with the instruction:

sudo dpkg -i *.deb

After installing the kernel on both clients and server, the machines must be rebooted. While rebooting, hold the SHIFT key to open the GRUB bootloader. Once there, open the *Advanced options* window. There, select the *quicifb2* kernel.

# PRELIMINARY CONFIGURATION

Before testing, please make sure that the protocol number is defined in the kernel by checking whether the /usr/include/netinet/in.h file containes the lines

IPPROTO_QUIC = 18,  /* QUIC Protocol */ */

#define IPPROTO_QUIC IPPROTO_QUIC

If not, add these lines and save the file. 
In order to capture incoming packets, Wireshark must be installed and configured on the server machine. To do this, please execute the 

./install_wireshark.sh

shell script, which you will find in the Testing-Server folder. Then, reboot the machine and choose again the "quicifb2" kernel from GRUB.

# HOW TO TEST

For both server and client, you will find a folder for each test (1, 2, 3, 3b, 4). These are structured as follows:
* Test 1: Single connection setup (QUIC and TCP)
* Test 2: Single connection setup (QUIC and TCP) + spectral interference
* Test 3: Concurrent streams setup (QUIC/QUIC, QUIC/TCP)
* Test 3b: Concurrent streams setup (QUIC against 2 TCP streams)
* Test 4: Concurrent streams setup (QUIC/TCP) + spectral interference.
Further details on each test may be found in the thesis. For tests 2 and 4, please bear in mind that spectral interference must be manually set up in the second router's settings.
For tests 3, 3b and 4, the file names also give an indication on whether the function must be run on the first on on the second client.
Before testing, on both server and client(s), all C functions involved must be edited. In the lines

serv_addr.sin_addr.s_addr= inet_addr("...");
client_addr.sin_addr.s_addr= inet_addr("...");

replace the placeholder addresses with the current server and client addresses in your local network. Then, save and compile again with gcc. 

# VIRTUAL MACHINE SETUP

If you're using this environment in a VM setup, please refer to the *VM_testing_instructions.pdf* file.

Carmine Bianco - 26.09.2017
