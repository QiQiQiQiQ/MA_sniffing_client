#!/bin/bash

### usage: sudo $program $iface $number $host_ip $host_port
# $program is the compiled file of the sniffer
# $iface is the wireless interface name which is set to monitor mode
# $number is the number of packets to be captured, 0 for non-stop capturing
# $filter_expression is the filter according to the libpcap syntax

# command to compile the program: g++ -o <exe file> <source code> -lpcap
# example: g++ -o sniffer sniffer.cpp -lpcap

### setting sniffing arguments
program=./sniffer
iface=wlx503eaae75354
#filter_expression="wlan addr2 b8:27:eb:68:e5:eb || wlan addr2 b8:27:eb:47:19:12"
number=0
host_ip=192.168.71.1
#port between 49152 and 65535
host_port=60000

if [ -e $program ]; then
    sleep 0.1
else
    echo error: program not found
    exit 1
fi

### scan for SECC, put adapter in the communication channel of the AP
sudo ip link set $iface down
sudo iw dev $iface set type managed
sudo ip link set $iface up
iw dev $iface scan -u > scan_result.txt
apinfo=`echo $(gawk -f set_channel.awk scan_result.txt) `

ssidVal="$(cut -d' ' -f1 <<<"$apinfo")"
freqVal="$(cut -d' ' -f2 <<<"$apinfo")"
if [ $ssidVal == "NOT_FOUND" ]; then
    echo "SECC not found..."
else
    echo "AP SSID:" $ssidVal
    echo "AP freq:" $freqVal "MHz"
fi
# search for device
FOUND=`grep "$iface" /proc/net/dev`
if [ -n "$FOUND" ]; then
    echo setting $iface in monitor mode
    sudo ip link set $iface down
    sudo iw $iface set type monitor
    sudo ip link set $iface up
    echo "setting adapter channel to ${freqVal} MHz"
    sudo iw dev $iface set freq $freqVal
else
    echo error: interface $iface not found
    #exit 1
fi
sleep 0.1

if [ $number -gt 0 ]; then
    echo $number packets will be captured
elif [ $number -eq 0 ]; then
    echo capturing will keep running until user interrupts
else
    echo error: number invalid
    exit 1
fi

#echo data will be storaged to $outfile
sleep 0.1
trap "echo process terminated by user; exit 0" SIGINT
sudo $program $iface $number $host_ip $host_port
sleep 0.1
