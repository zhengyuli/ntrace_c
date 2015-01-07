#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: push_profile.py
# Purpose:
#
# Time-stamp: <2014-12-25 08:13:46 Thursday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import json
import zmq

appService1 = {}
appService1 ['id'] = 1
appService1 ['proto'] = 'HTTP'
appService1 ['ip'] = '210.28.129.4'
appService1 ['port'] = 80

pushProfileBody = {}
pushProfileBody ['agent_id'] = '12345'
appServiceList = [appService1]
pushProfileBody ['app_services'] = appServiceList

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
