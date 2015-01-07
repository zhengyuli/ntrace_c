#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-01-07 20:19:53 Wednesday by lzy>
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

mkdir /var/run/$(toLower ${PROJECT_NAME})

chkconfig --level 2345 $(toLower ${PROJECT_NAME})_logger on