#!/bin/sh

( sleep 180; poweroff ) &

for iface in `ls /sys/class/net`; do
	if [ "x$iface" != "xlo" ]; then
		ip link set $iface up
	fi
done

mkdir -p /var/lib/dhcp
dhclient -nw
