#!/usr/bin/env python2

from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

rdsobj.deleteAgentInfo(2)

print "get agent_list: %s" % rdsobj.getAgentInfo()


