#! /usr/bin/env python
# Time-stamp: <2015-05-05 21:43:47 Tuesday by zhengyuli>
#
# Author: zhengyu li
# Created: 2015-05-02
#
# Copyright (c) 2015 zhengyu li <lizhengyu419@gmail.com>

"""
nTrace client
"""

import os
import argparse
import json
import zmq


def cmdResume(sock):
    req = {'command':'resume'}
    sock.send_json(req)
    print sock.recv_string()

def cmdPause(sock):
    req = {'command':'pause'}
    sock.send_json(req)
    print sock.recv_string()

def cmdHeartbeat(sock):
    req = {'command':'heartbeat'}
    sock.send_json(req)
    print sock.recv_string()

def cmdPktsStatInfo(sock):
    req = {'command':'packets_statistic_info'}
    sock.send_json(req)
    print sock.recv_string()

def cmdProtosInfo(sock):
    req = {'command':'protos_info'}
    sock.send_json(req)
    print sock.recv_string()

def cmdServicesInfo(sock):
    req = {'command':'services_info'}
    sock.send_json(req)
    print sock.recv_string()

def cmdDetectedServicesInfo(sock):
    req = {'command':'detected_services_info'}
    sock.send_json(req)
    print sock.recv_string()

def cmdTopologyEntriesInfo(sock):
    req = {'command':'topology_entries_info'}
    sock.send_json(req)
    print sock.recv_string()

def cmdUpdateServices(sock):
    service1 = {'ip':'210.28.129.4',
               'port':80,
               'proto':'HTTP'}
    serviceList = [service1]

    req = {'command':'update_services',
           'body':{
               'services':serviceList
           }}
    sock.send_json(req)
    print sock.recv_string()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", nargs=1, help="nTrace host ip")
    parser.add_argument("-p", "--port", nargs=1, type=int, help="nTrace host port")
    parser.add_argument("cmd",
                        choices=["resume",
                                 "pause",
                                 "heartbeat",
                                 "pktsStatInfo",
                                 "protosInfo",
                                 "servicesInfo",
                                 "detectedServicesInfo",
                                 "topologyEntriesInfo",
                                 "updateServices"],
                        help="nTrace request command")
    args = parser.parse_args()

    ip = "127.0.0.1" if not args.ip else args.ip[0]
    port = 53001 if not args.port else args.port[0]
    cmd = args.cmd

    try:
        zmqCtxt = zmq.Context.instance()
        zmqSock = zmqCtxt.socket(zmq.REQ)
        zmqSock.connect("tcp://" + ip + ":" + str(port))

        if cmd == 'resume':
            cmdResume(zmqSock)
        elif cmd == 'pause':
            cmdPause(zmqSock)
        elif cmd == 'heartbeat':
            cmdHeartbeat(zmqSock)
        elif cmd == 'pktsStatInfo':
            cmdPktsStatInfo(zmqSock)
        elif cmd == 'protosInfo':
            cmdProtosInfo(zmqSock)
        elif cmd == 'servicesInfo':
            cmdServicesInfo(zmqSock)
        elif cmd == 'detectedServicesInfo':
            cmdDetectedServicesInfo(zmqSock)
        elif cmd == 'topologyEntriesInfo':
            cmdTopologyEntriesInfo(zmqSock)
        elif cmd == 'updateServices':
            cmdUpdateServices(zmqSock)

        zmqCtxt.destroy()
    except KeyboardInterrupt:
        exit(0)
    except BaseException:
        print "program encounter fatal error."
        exit(-1)
