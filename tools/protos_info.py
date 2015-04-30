#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: protos_info.py
# Purpose:
#
# Time-stamp: <2015-04-30 08:04:14 Thursday by zhengyuli>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

protoInfosBody = {}

protoInfosDict = {}
protoInfosDict['command'] = 'protos_info'
protoInfosDict['body'] = protoInfosBody
protoInfosJson = json.dumps(protoInfosDict)
print protoInfosJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:53001")
request.send_json(protoInfosDict)
print request.recv_json()
