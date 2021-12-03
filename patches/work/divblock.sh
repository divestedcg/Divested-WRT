#!/bin/sh /etc/rc.common

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
	if /etc/init.d/dnsmasq enabled; then
		if wget $DIVBLOCK_HOSTS -O $DIVBLOCK_OUTPUT; then
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
	if rm $DIVBLOCK_OUTPUT &>/dev/null; then logger -t divblock "deleted"; fi;
	if /etc/init.d/dnsmasq running; then
		/etc/init.d/dnsmasq restart;
		logger -t divblock "restarted dnsmasq";
	else
		logger -t divblock "dnsmasq stopped, not restarting";
	fi;
}
