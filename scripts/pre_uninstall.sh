#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-01-07 18:28:28 Wednesday by lzy>
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

chkconfig --del $(toLower ${PROJECT_NAME})_logger
