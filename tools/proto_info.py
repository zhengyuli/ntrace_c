#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: proto_info.py
# Purpose:
#
# Time-stamp: <2015-04-15 18:23:36 Wednesday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

protoInfoBody = {}

protoInfoDict = {}
protoInfoDict['command'] = 'proto_info'
protoInfoDict['body'] = protoInfoBody
protoInfoJson = json.dumps(protoInfoDict)
print protoInfoJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:53001")
request.send_json(protoInfoDict)
print request.recv_json()
