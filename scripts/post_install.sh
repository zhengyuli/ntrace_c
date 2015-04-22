#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-04-22 19:53:09 Wednesday by lzy>
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

mkdir -p /var/run/$(toLower ${PROJECT_NAME})
mkdir -p /var/log/$(toLower ${PROJECT_NAME})
mkdir -p /usr/share/$(toLower ${PROJECT_NAME})/analyzers
mkdir -p /usr/share/$(toLower ${PROJECT_NAME})/detectors
