#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: miningEngine.py
# Purpose:
#
# Time-stamp: <2014-12-31 18:42:46 Wednesday by lzy>
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
    sessionBreakdown = resp.recv ()
    print "Breakdown count: %d" % breakdownCount
    breakdownCount = breakdownCount + 1
    print breakdown
