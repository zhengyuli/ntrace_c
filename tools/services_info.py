#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: services_info.py
# Purpose:
#
# Time-stamp: <2015-04-30 08:14:05 Thursday by zhengyuli>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

servicesInfoBody = {}

servicesInfoDict = {}
servicesInfoDict['command'] = 'services_info'
servicesInfoDict['body'] = servicesInfoBody
servicesInfoJson = json.dumps(servicesInfoDict)
print servicesInfoJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:53001")
request.send_json(servicesInfoDict)
print request.recv_json()
