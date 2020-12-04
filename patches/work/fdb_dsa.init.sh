#!/bin/sh /etc/rc.common

USE_PROCD=1
START=99
PIDFILE=/var/run/fdb_dsa.pid

start_service() {
    procd_open_instance "fdb_dsa"
    procd_set_param command /bin/sh /etc/fdb_dsa.sh
    procd_set_param pidfile $PIDFILE
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

stop_service() {
    killall bridge;
    #kill $(cat $PIDFILE)
}

status_service() {
    return 0;
}
