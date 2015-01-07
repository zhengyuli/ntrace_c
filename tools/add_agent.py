#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: add_agent.py
# Purpose:
#
# Time-stamp: <2014-12-31 19:04:44 Wednesday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import json
import zmq

addAgentBody = {}
addAgentBody ['agent_id'] = '12345'
addAgentBody ['breakdown_sink_ip'] = '127.0.0.1'
addAgentBody ['breakdown_sink_port'] = 59009
addAgentDict = {}
addAgentDict ['command'] = 'add_agent'
addAgentDict ['body'] = addAgentBody
addAgentJson = json.dumps (addAgentDict)
print addAgentJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (addAgentDict)
print request.recv_json ()
