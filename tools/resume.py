#!/usr/bin/env python

# ---------------------------------------------------------------------------------
# Name: resume.py
# Purpose:
#
# Time-stamp: <2015-04-10 19:29:16 Friday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
# ---------------------------------------------------------------------------------

import json
import zmq

resumeBody = {}

resumeDict = {}
resumeDict['command'] = 'resume'
resumeDict['body'] = resumeBody
resumeJson = json.dumps(resumeDict)
print resumeJson

context = zmq.Context()
request = context.socket(zmq.REQ)
request.connect("tcp://127.0.0.1:53001")
request.send_json(resumeDict)
print request.recv_json()
