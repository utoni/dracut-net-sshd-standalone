#!/bin/sh

killall dhclient

for iface in `ls /sys/class/net`; do
	if [ "x$iface" != "xlo" ]; then
		ip link set $iface down
	fi
done
