#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2015-01-07 14:35:58 Wednesday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

chkconfig --del wda_logd
