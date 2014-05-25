#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: push-profile.py
# Purpose:
#
# Time-stamp: <2014-05-25 00:37:11 Sunday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import json
import zmq


service1 = {}
service1 ['service_id'] = 1
service1 ['service_proto'] = 'HTTP'
service1 ['service_ip'] = '210.28.129.4'
service1 ['service_port'] = 80
serviceList = [service1]
pushProfileBody = {}
pushProfileBody ['agent-id'] = '12345'
pushProfileBody ['services'] = serviceList
pushProfileDict = {}
pushProfileDict ['command'] = 'push-profile'
pushProfileDict ['body'] = pushProfileBody
pushProfileJson = json.dumps (pushProfileDict)
print pushProfileJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (pushProfileDict)
print request.recv_json ()
