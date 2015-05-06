#! /usr/bin/env python
# Time-stamp: <2015-05-06 17:48:49 Wednesday by zhengyuli>
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
    conn.request("GET", "_cat/indices/analysis_records", headers=headers)
    resp = conn.getresponse()
    page = resp.read()
    if resp.status != 200:
        conn.request("PUT", "/analysis_records", headers=headers)
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
                record = json.loads(data)
                if record['type'] == "TOPOLOGY_ENTRY":
                    httpConn.request("POST", "/analysis_records/topology_entries", body=data, headers=headers)
                elif record['type'] == "APP_SERVICE":
                    httpConn.request("POST", "/analysis_records/app_services", body=data, headers=headers)
                elif record['type'] == "ICMP_BREAKDOWN":
                    httpConn.request("POST", "/analysis_records/icmp_breakdowns", body=data, headers=headers)
                elif record['type'] == "TCP_BREAKDOWN":
                    if record['proto'] == "DEFAULT":
                        httpConn.request("POST", "/analysis_records/default_breakdowns/", body=data, headers=headers)
                    elif record['proto'] == "HTTP":
                        httpConn.request("POST", "/analysis_records/http_breakdowns/", body=data, headers=headers)
                    elif record['protocol'] == "MYSQL":
                        httpConn.request("POST", "/analysis_records/mysql_breakdowns/", body=data, headers=headers)

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
