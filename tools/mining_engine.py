#! /usr/bin/env python
# Time-stamp: <2015-05-03 09:13:03 Sunday by zhengyuli>
#
# Author: zhengyu li
# Created: 2015-05-02
#
# Copyright (c) 2015 zhengyu li <lizhengyu419@gmail.com>

"""
Mining engine
"""

import argparse
import zmq
import httplib
import json


def createIndex(conn, headers):
    "Created elastic search index if index doesn't exists"
    conn.request("GET", "_cat/indices/breakdown", headers=headers)
    resp = conn.getresponse()
    page = resp.read()
    if resp.status != 200:
        conn.request("PUT", "/breakdown", headers=headers)
        resp = conn.getresponse()
        page = resp.read()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", nargs=1, help="ElasticSearch ip")
    args = parser.parse_args()
    doES = True


    if args.ip:
        try:
            httpConn = httplib.HTTPConnection(args.ip[0], 9200)
            headers = {"Connection": "keep-alive"}
            createIndex(httpConn, headers)
        except BaseException:
            print "except"
            doES = False
    else:
        doES = False

    context = zmq.Context.instance()
    bkdRecvSock = context.socket(zmq.PULL)
    bkdRecvSock.bind("tcp://127.0.0.1:60002")

    while True:
        try:
            data = bkdRecvSock.recv_string()
            if doES:
                breakdown = json.loads(data)
                if breakdown['protocol'] == "ICMP":
                    httpConn.request("POST", "breakdown/icmp", body=data, headers=headers)
                elif breakdown['protocol'] == "DEFAULT":
                    httpConn.request("POST", "/breakdown/default/", body=data, headers=headers)
                elif breakdown['protocol'] == "HTTP":
                    httpConn.request("POST", "/breakdown/http/", body=data, headers=headers)
                elif breakdown['protocol'] == "MYSQL":
                    httpConn.request("POST", "/breakdown/mysql/", body=data, headers=headers)

                httpResp = httpConn.getresponse()
                page = httpResp.read()
                print httpResp.status, httpResp.reason
            else:
                print data
        except KeyboardInterrupt:
            exit(0)
        except BaseException:
            print "program encounter fatal error."
            exit(-1)
        finally:
            if doES:
                httpConn.close()
