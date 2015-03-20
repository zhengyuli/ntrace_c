#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: breakdown_display.py
# Purpose:
#
# Time-stamp: <2015-03-20 15:36:28 Friday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import zmq

context = zmq.Context ()
resp = context.socket (zmq.PULL)
resp.bind ("tcp://127.0.0.1:59009")

breakdownCount = 0

while 1:
    breakdown = resp.recv ()
    print "Breakdown count: %d" % breakdownCount
    breakdownCount = breakdownCount + 1
    print breakdown
