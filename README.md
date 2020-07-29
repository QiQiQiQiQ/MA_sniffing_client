# MA_sniffing_client

This repository is part of my master thesis, which runs on the linux virtual machine to sniff the wireless traffic and enable the transfer of the captured wireless traffic  to windows host over TCP/IP socket

The host programm: https://github.com/QiQiQiQiQ/MA_sniffing_host


WLAN adapter: TL-WN722N v3
driver: https://github.com/aircrack-ng/rtl8188eus

The libpcap library should be installed previously

compile the source code: g++ -o <object name> sniffer.cpp -lpcap

run "sudo bash sniff.sh" in terminal to start sniffing, and please pay attention to the configuration in it.
