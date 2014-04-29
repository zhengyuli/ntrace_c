#!/usr/bin/env python2

from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

service_dict = {}
service_dict['service_id'] = 3
service_dict['service_ip'] = '192.168.203.3'
service_dict['service_port'] = 80
service_dict['service_proto'] = 'HTTP'

rdsobj.publishAddService(1, service_dict)

