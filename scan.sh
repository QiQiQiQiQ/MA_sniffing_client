dev=wlx503eaae75354
#oui=00 0c 43


sudo ip link set $dev down
sudo iw dev $dev set type managed
sudo ip link set $dev up
iw dev $dev scan -u > scan_result.txt
