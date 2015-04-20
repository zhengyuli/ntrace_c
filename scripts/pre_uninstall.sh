#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-04-20 20:03:16 Monday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

PROJECT_NAME="WDA"

toLower() {
    echo "$(echo ${1}|tr '[:upper:]' '[:lower:]')"
}

toUpper() {
    echo "$(echo ${1}|tr '[:lower:]' '[:upper:]')"
}

rm -rf /var/run/$(toLower ${PROJECT_NAME})
rm -rf /var/log/$(toLower ${PROJECT_NAME})
rm -rf /etc/$(toLower ${PROJECT_NAME})
rm -rf /usr/share/$(toLower ${PROJECT_NAME})
