#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-01-07 14:41:27 Wednesday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

rm /etc/init.d/wda_logd
rm -rf /var/run/wda/
