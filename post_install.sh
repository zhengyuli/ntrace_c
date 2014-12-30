#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2014-12-29 11:11:54 Monday by lzy>
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

sed -i "s/PROJECT_NAME_LOWER/$(toLower ${PROJECT_NAME})/g" /etc/init.d/wda_logd
sed -i "s/PROJECT_NAME/${PROJECT_NAME}/g" /etc/init.d/wda_logd

chkconfig --level 2345 wda_logd on
