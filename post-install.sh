#!/bin/bash

#---------------------------------------------------------------------------------
# Name: post_install.sh
# Purpose:
#
# Time-stamp: <2014-08-21 19:30:19 Thursday by lzy>
#
# Author: zhengyu li
# Created: 2014-03-27
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

source /etc/profile
export LC_ALL=C

chkconfig --level 2345 logd on
