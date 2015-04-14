#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: breakdown_receiver.py
# Purpose:
#
# Time-stamp: <2015-04-15 00:50:52 Wednesday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import os
import sys
import zmq

context = zmq.Context()
bkdRecvSock = context.socket(zmq.PULL)
bkdRecvSock.bind("tcp://127.0.0.1:60002")

while True:
    try:
        data = bkdRecvSock.recv()
        print data
    except KeyboardInterrupt:
        print "program is interrupted."
        exit(0)
    except BaseException:
        print "program encounter fatal error."
        exit(-1)
