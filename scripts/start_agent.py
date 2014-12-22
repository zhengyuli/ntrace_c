#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: start_agent.py
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

startAgentBody = {}
startAgentBody ['agent_id'] = '12345'
startAgentDict = {}
startAgentDict ['command'] = 'start_agent'
startAgentDict ['body'] = startAgentBody
startAgentJson = json.dumps (startAgentDict)
print startAgentJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (startAgentDict)
print request.recv_json ()
