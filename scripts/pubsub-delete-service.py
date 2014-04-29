#!/usr/bin/env python2

from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

service_dict = {}
service_dict['service_id'] = 2
service_dict['service_ip'] = '10.64.40.26'
service_dict['service_port'] = 3306
service_dict['service_proto'] = 'MYSQL'

rdsobj.publishDeleteService(1, service_dict)

