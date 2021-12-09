#!/bin/sh /etc/rc.common
#License: GPL-2.0-or-later

START=99
USE_PROCD=1

DIVBLOCK_HOSTS="https://divested.dev/hosts-dnsmasq";
DIVBLOCK_OUTPUT="/tmp/dnsmasq.d/divblock.conf";

reload_service()
{
	stop "$@"
	start "$@"
}

start_service()
{
	#Tasks
	# - Download the list if dnsmasq is enabled
	# - Sanitize it to only allow comments and domain overrides to the invalid (#) address
	# - TODO: add basic exclusion list support
	# - Restart dnsmasq
	if /etc/init.d/dnsmasq enabled; then
		sleep 15; #wait for network and system to settle after boot XXX: ugly
		if wget $DIVBLOCK_HOSTS -O - | grep -i -e '^#' -e '^address=/.*/#' > $DIVBLOCK_OUTPUT; then
			logger -t divblock "downloaded";
			/etc/init.d/dnsmasq restart;
			logger -t divblock "restarted dnsmasq";
		else
			logger -t divblock "failed to download";
		fi;
	else
		logger -t divblock "dnsmasq is disabled, not starting";
	fi;
}

stop_service()
{
	#Tasks
	# - Delete the list if available
	# - Restart dnsmasq if running
	if rm $DIVBLOCK_OUTPUT &>/dev/null; then logger -t divblock "deleted"; fi;
	if /etc/init.d/dnsmasq running; then
		/etc/init.d/dnsmasq restart;
		logger -t divblock "restarted dnsmasq";
	else
		logger -t divblock "dnsmasq stopped, not restarting";
	fi;
}
