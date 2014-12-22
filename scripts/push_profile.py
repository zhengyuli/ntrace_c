#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: push_profile.py
# Purpose:
#
# Time-stamp: <2014-12-23 13:43:32 Tuesday by lzy>
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
pushProfileBody ['agent_id'] = '12345'
pushProfileBody ['services'] = serviceList
pushProfileDict = {}
pushProfileDict ['command'] = 'push_profile'
pushProfileDict ['body'] = pushProfileBody
pushProfileJson = json.dumps (pushProfileDict)
print pushProfileJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (pushProfileDict)
print request.recv_json ()
