#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: breakdown_publish.py
# Purpose:
#
# Time-stamp: <2015-03-20 23:55:50 Friday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import zmq
import httplib
import json

context = zmq.Context ()
resp = context.socket (zmq.PULL)
resp.bind ("tcp://127.0.0.1:59009")

httpConn = httplib.HTTPConnection ("192.168.1.10", 9200)
headers = {"Connection" : "keep-alive"}

httpConn.request ("GET", "/_cat/indices/breakdown", None, headers)
httpResp = httpConn.getresponse ()
page = httpResp.read ()

if httpResp.status != 200:
    httpConn.request ("PUT", "/breakdown")
    httpResp = httpConn.getresponse ()
    page = httpResp.read ()



while 1:
    breakdown = resp.recv ()
    jobj = json.loads (breakdown)

    if (jobj ['protocol'] == "ICMP"):
        httpConn.request ("POST", "breakdown/icmp", breakdown, headers)
    elif (jobj ['protocol'] == "DEFAULT"):
        httpConn.request ("POST", "/breakdown/default/", breakdown, headers)
    elif (jobj ['protocol'] == "HTTP"):
        httpConn.request ("POST", "/breakdown/http/", breakdown, headers)
    elif (jobj ['protocol'] == "MYSQL"):
        httpConn.request ("POST", "/breakdown/mysql/", breakdown, headers)

    httpResp = httpConn.getresponse ()
    print httpResp.status, httpResp.reason
    page = httpResp.read ()
