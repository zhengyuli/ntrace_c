#!/usr/bin/env python2

from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

service_dict = {}
service_dict['service_id'] = 1
service_dict['service_ip'] = '210.28.129.4'
service_dict['service_port'] = '80'
service_dict['service_proto'] = 'HTTP'

rdsobj.publishUpdateService(1, service_dict)
