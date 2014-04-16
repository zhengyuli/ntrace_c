#!/usr/bin/env python2
from RedisClient import RedisClient

rdsobj = RedisClient('127.0.0.1')

agent_info = {}
agent_info['agent_id'] = 1
agent_info['agent_name'] = 'agent1'
agent_info['agent_ip'] = '192.168.1.100'

rdsobj.setAgentInfo(agent_info)

print "get agent_list: %s" % rdsobj.getAgentInfo()

