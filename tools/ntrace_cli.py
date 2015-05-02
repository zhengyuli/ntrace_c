#! /usr/bin/env python
# Time-stamp: <2015-05-02 18:29:24 Saturday by zhengyuli>
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
import zmq

def cmdResume(sock):
    req = {'command':'resume'}
    sock.send_json(req)
    print sock.recv_json()

def cmdPause(sock):
    req = {'command':'pause'}
    sock.send_json(req)
    print sock.recv_json()

def cmdHeartbeat(sock):
    req = {'command':'heartbeat'}
    sock.send_json(req)
    print sock.recv_json()

def cmdPktsStatInfo(sock):
    req = {'command':'packets_statistic_info'}
    sock.send_json(req)
    print sock.recv_json()

def cmdProtosInfo(sock):
    req = {'command':'protos_info'}
    sock.send_json(req)
    print sock.recv_json()

def cmdServicesInfo(sock):
    req = {'command':'services_info'}
    sock.send_json(req)
    print sock.recv_json()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", nargs=1, help="nTrace host ip")
    parser.add_argument("-p", "--port", nargs=1, type=int, help="nTrace host port")
    parser.add_argument("-c", "--cmd", nargs=1, required=True,
                        choices=["resume",
                                 "pause",
                                 "heartbeat",
                                 "pktsStatInfo",
                                 "protosInfo",
                                 "servicesInfo"],
                        help="nTrace request command")
    args = parser.parse_args()

    ip = "127.0.0.1" if not args.ip else args.ip[0]
    port = 53001 if not args.port else args.port[0]
    cmd = args.cmd[0]

    try:
        zmqCtxt = zmq.Context()
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
    except BaseException:
        print "program encounter fatal error."
        exit(-1)
