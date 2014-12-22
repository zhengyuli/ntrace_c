#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: remove_agent.py
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

removeAgentBody = {}
removeAgentBody ['agent_id'] = '12345'
removeAgentDict = {}
removeAgentDict ['command'] = 'remove_agent'
removeAgentDict ['body'] = removeAgentBody
removeAgentJson = json.dumps (removeAgentDict)
print removeAgentJson

context = zmq.Context ()
request = context.socket (zmq.REQ)
request.connect ("tcp://127.0.0.1:59000")
request.send_json (removeAgentDict)
print request.recv_json ()
