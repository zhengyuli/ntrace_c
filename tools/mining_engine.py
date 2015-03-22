#!/usr/bin/env python

#---------------------------------------------------------------------------------
# Name: mining_engine.py
# Purpose:
#
# Time-stamp: <2015-03-22 22:24:35 Sunday by lzy>
#
# Author: zhengyu li
# Created: 24 May 2014
#
# Copyright (c) 2014 zhengyu li <lizhengyu419@gmail.com>
#---------------------------------------------------------------------------------

import os, sys
import argparse
import zmq
import httplib
import json

def createIndex (ip):
    "Created elastic search index if index doesn't exists"
    httpConn = httplib.HTTPConnection (ip, 9200)
    httpConn.request ("GET", "_cat/indices/breakdown")

    httpResp = httpConn.getresponse ()
    page = httpResp.read ()
    if httpResp.status != 200:
        httpConn.request ("PUT", "/breakdown")
        httpResp = httpConn.getresponse ()
        page = httpResp.read ()

    httpConn.close ()

if __name__ == '__main__':
    interrupted = False;
    
    parser = argparse.ArgumentParser ()
    parser.add_argument ("ip", type = str, help = "ElasticSearch ip")
    args = parser.parse_args ()

    context = zmq.Context ()
    bkdRecvSock = context.socket (zmq.PULL)
    bkdRecvSock.bind ("tcp://127.0.0.1:59009")

    createIndex (args.ip)

    httpConn = httplib.HTTPConnection (args.ip, 9200)
    headers = {"Connection" : "keep-alive"}
    while interrupted == False:
        try:
            data = bkdRecvSock.recv ()
            breakdown = json.loads (data)

            if (breakdown ['protocol'] == "ICMP"):
                httpConn.request ("POST", "breakdown/icmp", data, headers)
            elif (breakdown ['protocol'] == "DEFAULT"):
                httpConn.request ("POST", "/breakdown/default/", data, headers)
            elif (breakdown ['protocol'] == "HTTP"):
                httpConn.request ("POST", "/breakdown/http/", data, headers)
            elif (breakdown ['protocol'] == "MYSQL"):
                httpConn.request ("POST", "/breakdown/mysql/", data, headers)

            httpResp = httpConn.getresponse ()
            print httpResp.status, httpResp.reason
            page = httpResp.read ()
        except KeyboardInterrupt:
            print "program is interrupted"
            interrupted = True

    httpConn.close ()
    print "exit... .. ."
