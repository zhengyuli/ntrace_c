#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-04-28 07:19:32 Tuesday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

PROJECT_NAME="ntrace"

toLower() {
    echo "$(echo ${1}|tr '[:upper:]' '[:lower:]')"
}

toUpper() {
    echo "$(echo ${1}|tr '[:lower:]' '[:upper:]')"
}

rm -rf /etc/$(toLower ${PROJECT_NAME})
rm -rf /usr/share/$(toLower ${PROJECT_NAME})
rm -rf /var/run/$(toLower ${PROJECT_NAME})
rm -rf /var/log/$(toLower ${PROJECT_NAME})
