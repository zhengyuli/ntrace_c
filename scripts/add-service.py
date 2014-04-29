#!/usr/bin/env python2

from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

service_dict = {}
service_dict['service_id'] = 1
service_dict['service_ip'] = '58.215.133.28'
service_dict['service_port'] = 80
service_dict['service_proto'] = 'HTTP'

rdsobj.setServiceInfo(1, service_dict)
print "get service_info: %s" % rdsobj.getServiceInfo(1, 1)

service_dict['service_id'] = 2
service_dict['service_ip'] = '10.64.40.150'
service_dict['service_port'] = 3306
service_dict['service_proto'] = 'MYSQL'

rdsobj.setServiceInfo(1, service_dict)
print "get service_info: %s" % rdsobj.getServiceInfo(1, 1)
