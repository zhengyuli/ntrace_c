#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: stop-agent.py
# Purpose:
#
# Time-stamp: <2014-05-25 00:28:02 Sunday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import json
import zmq

stopAgentBody = {}
stopAgentBody ['agent-id'] = '12345'
stopAgentDict = {}
stopAgentDict ['command'] = 'stop-agent'
stopAgentDict ['body'] = stopAgentBody
stopAgentJson = json.dumps (stopAgentDict)
print stopAgentJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (stopAgentDict)
print request.recv_json ()
