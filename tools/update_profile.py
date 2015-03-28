#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: update_profile.py
# Purpose:
#
# Time-stamp: <2015-03-28 21:56:04 Saturday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

appService1 = {}
appService1['id'] = 1
appService1['proto'] = 'HTTP'
appService1['ip'] = '210.28.129.4'
appService1['port'] = 80

appService2 = {}
appService2['id'] = 2
appService2['proto'] = 'MYSQL'
appService2['ip'] = '10.211.55.3'
appService2['port'] = 3306

appServiceList = [appService1, appService2]

updateProfileBody = {}
updateProfileBody['application_services'] = appServiceList

updateProfileDict = {}
updateProfileDict['command'] = 'update_profile'
updateProfileDict['body'] = updateProfileBody

updateProfileJson = json.dumps(updateProfileDict)
print updateProfileJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:58000")
request.send_json(updateProfileDict)
print request.recv_json()
