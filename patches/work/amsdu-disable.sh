#!/bin/sh /etc/rc.common

USE_PROCD=0

START=18
STOP=30

echo "0" >> /sys/kernel/debug/ieee80211/phy0/mwlwifi/tx_amsdu
echo "0" >> /sys/kernel/debug/ieee80211/phy1/mwlwifi/tx_amsdu
logger "AMSDU Disabled"
