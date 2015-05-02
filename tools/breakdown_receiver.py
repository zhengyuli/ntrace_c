#! /usr/bin/env python
# Time-stamp: <2015-05-02 16:25:05 Saturday by zhengyuli>
#
# Author: zhengyu li
# Created: 2015-05-02
#
# Copyright (c) 2015 zhengyu li <lizhengyu419@gmail.com>

"""

"""

import os
import argparse
import zmq


def recvBreakdown(ip, port):
    "Receive session breakdown"
    ctxt = zmq.Context ()
    sock = ctxt.sock(zmq.PULL)
    sock.bind("tcp://" + ip + ":" + port)

    while True:
        breakdown = sock.recv()
        print breakdown


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", nargs=1, help="nTrace host ip")
    parser.add_argument("-p", "--port", nargs=1, help="nTrace host port")
    parser.add_argument("-c", "--cmd", nargs=1, choices=["recvBreakdown"], required=True)
    args = parser.parse_args()

    if args.
