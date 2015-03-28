#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: packets_statistic.py
# Purpose:
#
# Time-stamp: <2015-03-28 21:54:39 Saturday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

pktsStatisticBody = {}

pktsStatisticDict = {}
pktsStatisticDict['command'] = 'packets_statistic'
pktsStatisticDict['body'] = pktsStatisticBody
pktsStatisticJson = json.dumps(pktsStatisticDict)
print pktsStatisticJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:58000")
request.send_json(pktsStatisticDict)
print request.recv_json()
