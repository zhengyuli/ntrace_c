#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2014-12-27 16:54:58 Saturday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

sed -i "s/PROJECT_NAME/wda/g" /etc/init.d/wda_logd

chkconfig --level 2345 wda_logd on
