#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: heartbeat.py
# Purpose:
#
# Time-stamp: <2015-03-28 21:54:12 Saturday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

heartbeatBody = {}

heartbeatDict = {}
heartbeatDict['command'] = 'heartbeat'
heartbeatDict['body'] = heartbeatBody
heartbeatJson = json.dumps(heartbeatDict)
print heartbeatJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:58000")
request.send_json(heartbeatDict)
print request.recv_json()
