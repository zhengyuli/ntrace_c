#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: packets_statistic_info.py
# Purpose:
#
# Time-stamp: <2015-04-30 08:04:07 Thursday by zhengyuli>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

pktsStatisticInfoBody = {}

pktsStatisticInfoDict = {}
pktsStatisticInfoDict['command'] = 'packets_statistic_info'
pktsStatisticInfoDict['body'] = pktsStatisticInfoBody
pktsStatisticInfoJson = json.dumps(pktsStatisticInfoDict)
print pktsStatisticInfoJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:53001")
request.send_json(pktsStatisticInfoDict)
print request.recv_json()
