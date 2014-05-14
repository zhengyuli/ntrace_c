#!/usr/bin/env python2

import redis
import json
import logging

class RedisClient:
    def __init__(self, server_ip = "127.0.0.1", server_port = 6379, logger=logging ):
        self.errmsg = ""
	self.logger = logger

        try:
            #rds = redis.Redis(server_ip, server_port)
            #rds = redis.StrictRedis(server_ip, server_port, db=0)
            #self.subObj = rds.pubsub()

            self.pool = redis.ConnectionPool(host=server_ip, port=server_port, db=0)
            self.logger.info("success to connect to redis server")

        except Exception, e:
            self.logger.error("failed connect to redis server with ip=%s and port = %d" %(server_ip,server_port))
            self.errmsg = str(e)
            self.logger.error("with reason: %s" % self.errmsg)
            return None

    def getErrMsg(self) :
        return self.errmsg
######

    def pubSub(self) :
        try :
            rds = redis.Redis(connection_pool=self.pool)
            pubsub = rds.pubsub()
        except Exception, e :
            self.logger.error("Redis failed to create pubsub object")
            self.errmsg = str(e)
            self.logger.error("with reason = %s" % self.errmsg)

        return pubsub
######

    def getAgentInfo(self, agent_id = None):
        agentList = []
        try:
            rds = redis.Redis(connection_pool=self.pool)
            if agent_id == None :
                output = rds.hgetall('wda:agent_map')
                for key in output:
                    agentList.append(json.loads(output[key]))

                return agentList

            else:
                output = rds.hget('wda:agent_map', agent_id)
                return json.loads(output)

        except Exception, e:
            self.errmsg = "failed to get agent list from key='wda:agent_map'"
            if agent_id != None :
                self.errmsg = self.errmsg + " with agent_id=%d" % agent_id

            self.logger.warning(self.errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return None
######

    def setAgentInfo(self, agent_info):
        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.hset('wda:agent_map', agent_info['agent_id'], json.dumps(agent_info))
            return True

        except Exception, e:
            self.errmsg = "failed to set agent info:\n %s" % str(agent_info)
            self.logger.warning(self.errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return False
######

    def deleteAgentInfo(self, agent_id):
        try:
            rds = redis.Redis(connection_pool=self.pool)
            #TODO: publish the delete action to agent, agent will close then
            rds.hdel('wda:agent_map', agent_id)
            return True

        except Exception, e:
            self.errmsg = "failed to delete agent info with agent_id = %d" % agent_id
            self.logger.warning(self.errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)
            return False
######

    def getServiceInfo(self, agent_id, service_id = None):
        service_dict = {}
        try:
            rds = redis.Redis(connection_pool=self.pool)
            if service_id == None :
                output = rds.hgetall('wda:service_map:agent_%d' % agent_id)
                for key in output:
                    #serviceList.append(json.loads(output[key]))
                    service_dict[int(key)] = (json.loads(output[key]))

                #return serviceList
            else:
                output = rds.hget('wda:service_map:agent_%d' % agent_id, service_id)
                service_dict = json.loads(output)
                #return json.loads(output)

            return service_dict

        except Exception, e:
            self.errmsg = "failed to get service info list "
            if service_id != None :
                self.errmsg = self.errmsg + "with agent_id=%d, service_id=%d" % (agent_id, service_id)
            else :
                self.errmsg = self.errmsg + "with agent_id=%d" % agent_id
            self.logger.warning(self.errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return None
######

    def setServiceInfo(self, agent_id, service_info):
        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.hset('wda:service_map:agent_%d' % agent_id, service_info['service_id'], json.dumps(service_info))
            return True

        except Exception, e:
            self.errmsg = "failed to set service info with agent_id = %d and service_info = \n%s" % (agent_id, str(service_info))
            self.logger.warning(self.errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return False
######

    def deleteServiceInfo(self, agent_id, service_id):
        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.hdel('wda:service_map:agent_%d' % agent_id, service_id)
            return True

        except Exception, e:
            errmsg = "failed to delete service info"
            errmsg = errmsg + " with agent_id = %d, service_id = %d" % (agent_id,service_id)
            self.logger.warning(errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)
            return False
######

    def publishAddService(self, agent_id, service_info):

        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.publish('wda:pubsub_service_add:agent_%d' % agent_id, json.dumps(service_info))

            return True

        except Exception, e:
            errmsg = "failed to pulish add service with agent_id=%d:" % agent_id
            errmsg = errmsg + " and service_info=\n%s" % str(service_info)
            self.logger.warning(errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return False
######

    def publishDeleteService(self, agent_id, service_info):

        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.publish('wda:pubsub_service_delete:agent_%d' % agent_id, json.dumps(service_info))
            return True

        except Exception, e:
            errmsg = "failed to pulish delete service, agent_id=%d" % agent_id
            errmsg = errmsg + " and service_info=\n\t%s" % str(service_info)
            self.logger.warning(errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return False
######

    def publishUpdateService(self, agent_id, service_info):

        try:
            rds = redis.Redis(connection_pool=self.pool)
            rds.publish('wda:pubsub_service_update:agent_%d' % agent_id, json.dumps(service_info))
            return True

        except Exception, e:
            errmsg = "failed to pulish update service, agent_id=%d" % agent_id
            errmsg = errmsg + " and service_info=\n\t%s" % str(service_info)
            self.logger.warning(errmsg)

            self.errmsg = str(e)
            self.logger.warning("with reason = %s" % self.errmsg)

            return False
######

    def __del__(self) :
        self.pool.disconnect()
        self.logger.info("close redisclient object")
