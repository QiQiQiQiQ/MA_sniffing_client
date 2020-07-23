# MA_sniffing_client

This repository is part of my master thesis, which runs on the linux virtual machine to sniff the wireless traffic and enable the transfer of the captured wireless traffic  to windows host over TCP/IP socket

WLAN adapter: TL-WN722N

driver: https://github.com/aircrack-ng/rtl8188eus

libpcap library should be installed previously

compile the source code: g++ -o <object name> sniffer.cpp -lpcap

run sudo bash sniff.sh to start sniffing, and please pay attention to the configuration in it.
