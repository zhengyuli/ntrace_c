#!/bin/bash

#---------------------------------------------------------------------------------
# Name: ntraced.sh
# Purpose:
#
# Time-stamp: <2015-04-30 18:11:13 Thursday by zhengyuli>
#
# Author: zhengyu li
# Created: 2015-04-30
#
# Copyright (c) 2015 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

SERVICE_NAME=ntrace
PID_FILE=/var/run/ntrace/ntrace.pid

start () {
    if [ -f $PID_FILE ]
    then
        echo "${SERVICE_NAME} is running"
    else
        echo -n "Start ${SERVICE_NAME}: "
        ${SERVICE_NAME} -D
        loop=10
        while [ $loop -gt 0 ]
        do
            sleep 1
            if [ -f $PID_FILE ]
            then
                echo "[OK]"
                exit 0
            else
                loop=$(($loop - 1))
            fi
        done
        echo "[Failed]"
    fi
}

stop () {
    if [ ! -f $PID_FILE ]
    then
        echo "${SERVICE_NAME} is not running"
    else
		echo -n "Stop ${SERVICE_NAME}: "
        PID=$(cat $PID_FILE)
        kill -2 $PID
        while [ -x /proc/$PID ]
        do
            sleep 1
        done

        if [ -f $PID_FILE ]
        then
            rm $PID_FILE
        fi
        echo "[Done]"
    fi
}

restart () {
    stop
    start
}

status () {
    echo -n "${SERVICE_NAME} status: "
    if [ ! -f $PID_FILE ]
    then
        echo "[Stopped]"
    else
        echo "[Runing]"
    fi
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        ;;
esac
